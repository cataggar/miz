const std = @import("std");
const Io = std.Io;

const azure = @import("azure.zig");
const bootconfig = @import("bootconfig.zig");
const cosi = @import("cosi.zig");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const Format = @import("formats.zig").Format;
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const layout = @import("layout.zig");
const mbr = @import("mbr.zig");
const oci = @import("oci.zig");
const os_customization = @import("os_customization.zig");
const output = @import("output.zig");
const iso9660 = @import("iso9660.zig");
const qcow2 = @import("qcow2.zig");
const limits_mod = @import("limits.zig");
const root_tree_mod = @import("root_tree.zig");
const vhdx = @import("vhdx.zig");
const squashfs = @import("squashfs.zig");
const verity = @import("verity.zig");
const initramfs = @import("initramfs.zig");

const mib: u64 = azure.one_mib;
pub const default_esp_size: u64 = 96 * mib;
/// Building a filesystem is inherently random-access, so even an image that
/// is delivered on stdout is assembled in a scratch file first. When there
/// is no output path to hang the scratch names off, they hang off this name
/// in the current directory instead, and are removed when the build ends.
pub const stdout_scratch_base = "zvmi-build-image-stdout";
const scratch_copy_chunk_size: usize = 1024 * 1024;
const nested_filesystem_probe_len: usize = 2048;
const ext4_magic_offset: usize = 1024 + 56;
const ext4_magic: u16 = 0xEF53;
const max_nested_filesystem_depth: u8 = 3;

pub const BuildImageOptions = struct {
    iso_path: []const u8,
    container_path: []const u8,
    /// Bounded OCI input limits. The defaults remain conservative; callers
    /// that deliberately create larger layers must opt into matching limits.
    oci_load_options: oci.LoadOptions = .{},
    output_path: []const u8,
    size: u64,
    generation: azure.Generation = .gen2,
    output_format: ?Format = null,
    /// How the finished image is encoded. Null infers it from
    /// `output_path`'s extensions (`image.raw.gz`), like `output_format`
    /// does. Only `raw` can be compressed: compression happens while the
    /// artifact is written, and every other format amends metadata it
    /// already wrote.
    output_compression: ?output.Compression = null,
    /// gzip level for compressed output. Null means "not requested", which
    /// is distinct from asking for the default: the zstd encoder has no
    /// level to set, so an explicit level with `-O raw.zst` is an error
    /// rather than something quietly dropped.
    compression_level: ?output.Level = null,
    /// Deliver the finished image on stdout instead of writing
    /// `output_path`, which is then unused. Scratch files are still written
    /// to disk (see `stdout_scratch_base`).
    stream_to_stdout: bool = false,
    rootfs_path_in_iso: ?[]const u8 = null,
    /// When set, the container image becomes the effective root filesystem and
    /// the ISO/squashfs contribute only the minimum boot-critical assets
    /// (kernel, initramfs, EFI binaries, Secure Boot helpers, BIOS GRUB
    /// stage images, and the installed rootfs's `/lib/modules/<kernel-version>`
    /// tree so loadable drivers that aren't statically built into the kernel,
    /// e.g. Azure's `hv_netvsc`/`mlx5` NIC drivers, still load on real
    /// hardware). This keeps live/installer-only OS payload out of the
    /// final root partition.
    skip_iso_rootfs: bool = false,
    os: os_customization.OsCustomization = .{},
    generalization: os_customization.GeneralizationPolicy = .none,
    esp_size: u64 = default_esp_size,
    ext4_label: []const u8 = "rootfs",
    /// Whether the root filesystem carries a JBD2 journal, and how large.
    /// Off by default, matching every build that predates the option. Turn
    /// it on for an image that boots into a mutable root filesystem, where
    /// an unclean shutdown otherwise leaves nothing to replay.
    ext4_journal: ext4.JournalOptions = .{},
    /// Optional SELinux context for the implicit ext4 root inode. The stored
    /// xattr includes the NUL terminator expected by SELinux tooling.
    root_selinux_label: ?[]const u8 = null,
    verity: bool = false,
    /// Extra kernel command-line arguments appended after
    /// `root=PARTUUID=<...>` (or `root=/dev/mapper/root ...` when `verity`
    /// is set). Useful for e.g. `console=ttyS0,115200n8` for cloud/serial
    /// console access, matching real Azure Linux VHD conventions.
    extra_kernel_options: []const u8 = "",
    /// Selects whether the Gen2/UEFI ESP gets the shim/GRUB/BLS chain, a
    /// generated Unified Kernel Image (UKI), or both. No effect on Gen1
    /// (BIOS) builds, which don't use `bootconfig.populateEsp()`.
    boot_mode: bootconfig.BootMode = .bls_only,
    /// Additional UKI discovery/output controls forwarded to
    /// `bootconfig.populateEsp()`.
    uki: bootconfig.UkiOptions = .{},
    architecture: ?bootconfig.Architecture = null,
    /// Limits on the owned root tree the merged ISO/squashfs/container
    /// sources are materialized into. The defaults suit a purpose-built
    /// image; a full installed root filesystem needs them raised.
    limits: root_tree_mod.Limits = .{},
    /// Optional sink for the peak measurements and the first limit breach.
    /// The report is returned by value, so a build that fails on a limit can
    /// only name the flag that raises it through a sink the caller owns.
    limit_diagnostic: ?*limits_mod.Diagnostic = null,
    deterministic: ?BuildImageDeterminism = null,
    event_sink: ?EventSink = null,
    stage_sink: ?StageSink = null,
    dry_run: bool = false,
    verbose: bool = false,
};

pub const BuildImageDeterminism = struct {
    disk_guid: guid.Guid,
    esp_partition_guid: guid.Guid,
    root_partition_guid: guid.Guid,
    mbr_disk_signature: u32,
    root_filesystem_uuid: [16]u8,
    verity_salt: [verity.salt_size]u8,
    filesystem_timestamp: u32,
    output_create_options: image_mod.CreateOptions,
};

pub const Event = union(enum) {
    progress: []const u8,
    warning: Warning,
};

pub const Warning = struct {
    code: []const u8,
    message: []const u8,
};

pub const EventSink = struct {
    context: ?*anyopaque = null,
    emitFn: *const fn (context: ?*anyopaque, event: Event) void,

    fn emit(self: EventSink, event: Event) void {
        self.emitFn(self.context, event);
    }
};

pub const Stage = enum {
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
};

pub const StageSink = struct {
    context: ?*anyopaque = null,
    advanceFn: *const fn (context: ?*anyopaque, stage: Stage) bool,

    pub fn advance(self: StageSink, stage: Stage) bool {
        return self.advanceFn(self.context, stage);
    }
};

pub const VhdxMetadataReport = struct {
    header_sequence_number: u64,
    file_write_guid: guid.Guid,
    data_write_guid: guid.Guid,
    page83_guid: guid.Guid,
};

pub const BuildImageReport = struct {
    output_format: Format,
    output_compression: output.Compression = .none,
    generation: azure.Generation,
    architecture: bootconfig.Architecture,
    disk_size: u64,
    dry_run: bool,
    rootfs_path_in_iso: []u8,
    planned_partitions: []bootconfig.PlannedPartitionIdentity,
    verity: ?verity.Info = null,
    vhd_alignment: ?azure.FixupResult = null,
    partition_style: ?azure.PartitionStyleReport = null,
    vhdx_metadata: ?VhdxMetadataReport = null,
    root_tree_digest: ?[32]u8 = null,
    /// The largest value each limit reached while the root tree was built.
    limit_peaks: limits_mod.Peaks = .{},

    pub fn deinit(self: *BuildImageReport, allocator: std.mem.Allocator) void {
        allocator.free(self.rootfs_path_in_iso);
        allocator.free(self.planned_partitions);
        self.* = undefined;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    io: Io,
    options: BuildImageOptions,
) !BuildImageReport {
    try enterStage(options, .load_sources);
    const spec = resolveOutputSpec(options);
    const output_format = spec.format;
    const destination = outputDestination(options);
    // Every scratch file is named after where the artifact lands, so that
    // two concurrent builds in one directory cannot collide.
    const scratch_base = scratchBase(options);
    try output.validate(spec, destination, options.compression_level);
    const disk_size = if (output_format == .vhd) azure.alignSizeToMib(options.size) else options.size;

    if (output_format == .vhd and disk_size != options.size) {
        if (options.event_sink) |sink| {
            sink.emit(.{ .progress = "align requested VHD size for Azure compatibility" });
        } else if (options.verbose) {
            std.debug.print("build-image: aligned requested VHD size from {d} to {d} bytes for Azure compatibility\n", .{ options.size, disk_size });
        }
    }
    try validateBuildPathIsolation(allocator, io, options);

    logStep(options, "load container image");
    var container_image = try oci.load(io, allocator, options.container_path, options.oci_load_options);
    var container_image_open = true;
    defer if (container_image_open) container_image.deinit();

    const inferred_architecture = parseArchitecture(container_image.config.architecture);
    if (options.architecture != null and inferred_architecture == null) {
        return error.UnsupportedContainerArchitecture;
    }

    const architecture = options.architecture orelse inferred_architecture orelse .x86_64;
    if (options.architecture != null and inferred_architecture != null and options.architecture.? != inferred_architecture.?) {
        return error.ContainerArchitectureMismatch;
    }
    const planned_partitions = try planPartitionIdentities(
        allocator,
        io,
        disk_size,
        options.generation,
        architecture,
        options.esp_size,
        if (options.deterministic) |*deterministic| deterministic else null,
    );
    var planned_partitions_owned = false;
    errdefer if (!planned_partitions_owned) allocator.free(planned_partitions);

    logStep(options, "open ISO");
    var iso_reader = try iso9660.Reader.openPath(allocator, io, options.iso_path);
    var iso_reader_open = true;
    defer if (iso_reader_open) iso_reader.close(io);

    const rootfs_path_in_iso = try discoverRootfsPathInIso(allocator, &iso_reader, options.rootfs_path_in_iso);
    var rootfs_path_in_iso_owned = false;
    errdefer if (!rootfs_path_in_iso_owned) allocator.free(rootfs_path_in_iso);

    var report = BuildImageReport{
        .output_format = output_format,
        .output_compression = spec.compression,
        .generation = options.generation,
        .architecture = architecture,
        .disk_size = disk_size,
        .dry_run = options.dry_run,
        .rootfs_path_in_iso = rootfs_path_in_iso,
        .planned_partitions = planned_partitions,
    };
    // `report` now owns both allocations; disarm the standalone errdefers above
    // so `report.deinit` below is the single owner responsible for freeing them.
    planned_partitions_owned = true;
    rootfs_path_in_iso_owned = true;
    errdefer report.deinit(allocator);

    if (options.dry_run) return report;

    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.build-image-rootfs.sqsh", .{scratch_base});
    defer allocator.free(rootfs_scratch_path);
    var extracted_rootfs = false;
    defer if (extracted_rootfs) Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};

    logStep(options, "extract squashfs payload from ISO");
    try extractIsoEntryToPath(allocator, io, &iso_reader, rootfs_path_in_iso, rootfs_scratch_path);
    extracted_rootfs = true;

    logStep(options, "open squashfs rootfs");
    var squash_reader = try squashfs.Reader.openPath(allocator, io, rootfs_scratch_path);
    var squash_reader_open = true;
    defer if (squash_reader_open) squash_reader.close(io);

    const nested_scratch_prefix = try std.fmt.allocPrint(allocator, "{s}.build-image-nested", .{scratch_base});
    defer allocator.free(nested_scratch_prefix);

    logStep(options, "merge ISO, squashfs, and OCI trees");
    var source_tree = try MergedSourceTree.init(allocator, io, &iso_reader, rootfs_path_in_iso, &squash_reader, &container_image, nested_scratch_prefix);
    source_tree.bind();
    var source_tree_open = true;
    defer if (source_tree_open) source_tree.deinit(allocator);

    try enterStage(options, .apply_filesystem_changes);
    if (options.skip_iso_rootfs) {
        logStep(options, "prune merged tree to container rootfs + boot assets");
        try source_tree.pruneToContainerRootfsAndBootAssets(
            allocator,
            &container_image,
            architecture,
            options.boot_mode != .bls_only,
        );
    }

    if (!options.skip_iso_rootfs) {
        // Only for the full-rootfs path: the merged tree there always
        // brings its own systemd (from the distro ISO/squashfs), so a
        // systemd unit is guaranteed to actually be usable. A
        // --skip-iso-rootfs image's rootfs *is* the given container --
        // there's no guarantee it has systemd at all (its PID 1 is
        // whatever /sbin/init the container provides, e.g. zvminit),
        // so wiring in a systemd unit there wouldn't do anything; it's
        // that from-scratch init's own job to invoke azagent if it wants
        // to (see zvminit/README.md).
        logStep(options, "install azagent systemd unit if present in the source tree");
        try installAzagentSystemdUnitIfPresent(allocator, &source_tree);
    }

    const root_tree_spool_path = try std.fmt.allocPrint(
        allocator,
        "{s}.build-image-root-tree.spool",
        .{scratch_base},
    );
    defer allocator.free(root_tree_spool_path);
    logStep(options, "materialize merged sources into owned root tree");
    var root_tree = try root_tree_mod.RootTree.init(
        allocator,
        io,
        root_tree_spool_path,
        options.limits,
    );
    root_tree.diagnostic = options.limit_diagnostic;
    defer root_tree.deinit();
    try root_tree.importExt4View(&source_tree.view);

    // RootTree owns every path, xattr, and content byte from this point on.
    // Release all format readers and their scratch files before customization.
    source_tree.deinit(allocator);
    source_tree_open = false;
    squash_reader.close(io);
    squash_reader_open = false;
    Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch |err| return err;
    extracted_rootfs = false;
    iso_reader.close(io);
    iso_reader_open = false;
    container_image.deinit();
    container_image_open = false;

    const customization_epoch: u64 = if (options.deterministic) |deterministic|
        deterministic.filesystem_timestamp
    else blk: {
        const now: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
        if (now < 0) return error.InvalidSystemTime;
        break :blk @intCast(now);
    };
    try os_customization.apply(allocator, &root_tree, options.os, customization_epoch);
    try enterStage(options, .generalize_and_cleanup);
    try os_customization.generalize(allocator, &root_tree, options.generalization);
    try enterStage(options, .prepare_initramfs);
    if (options.verity) {
        logStep(options, "check initramfs for dm-verity tooling");
        switch (try checkInitramfsVerityTooling(allocator, try root_tree.ext4View())) {
            .present => {},
            .absent => return error.InitramfsMissingVerityTooling,
            .inconclusive => emitWarning(
                options,
                "initramfs_verity_tooling_inconclusive",
                "could not conclusively verify that the source initramfs includes dm-verity userspace tooling (systemd-veritysetup-generator/systemd-veritysetup/veritysetup); --verity images built from an initramfs lacking this tooling will hang at boot waiting on /dev/mapper/root (see https://github.com/cataggar/zvmi/issues/77)",
            ),
        }
    }
    if (options.generation == .gen1 and !options.verity) {
        try enterStage(options, .prepare_boot_configuration);
    }

    // An uncompressed raw artifact written to a real path *is* the build
    // image, so it is assembled in place. Everything else -- another
    // format, a compressed artifact, or a pipe -- is produced from a raw
    // scratch file that is removed afterwards.
    const builds_output_in_place = buildsOutputInPlace(options);
    const raw_build_path = if (builds_output_in_place)
        options.output_path
    else
        try std.fmt.allocPrint(allocator, "{s}.build-image.raw", .{scratch_base});
    defer if (!builds_output_in_place) allocator.free(raw_build_path);
    defer if (!builds_output_in_place) Io.Dir.cwd().deleteFile(io, raw_build_path) catch {};

    logStep(options, "create build image");
    var raw_img = try Image.create(io, raw_build_path, .raw, disk_size, .{});
    var raw_img_open = true;
    defer if (raw_img_open) raw_img.close(io);

    const disk_guid = if (options.deterministic) |deterministic| deterministic.disk_guid else randomGuid(io);
    switch (options.generation) {
        .gen2 => {
            logStep(options, "write GPT partition tables");
            try writeGptLayout(allocator, &raw_img, io, disk_guid, planned_partitions);
        },
        .gen1 => {
            logStep(options, "write MBR partition table");
            try writeMbrLayout(&raw_img, io, planned_partitions);
        },
    }

    if (findPartitionByRole(planned_partitions, .esp)) |esp_partition| {
        logStep(options, "format ESP as FAT32");
        try fat32.format(&raw_img, io, .{
            .partition_offset = esp_partition.planned.offset_bytes,
            .partition_len = esp_partition.planned.length_bytes,
            .volume_label = "ZVMI ESP   ".*,
        });
    }

    const root_partition = findRootPartition(planned_partitions, architecture) orelse return error.MissingRootPartition;
    // A dm-verity root is mounted read-only over a hash tree computed from
    // its exact bytes, so it is never written to and has nothing to journal.
    // Accepting the combination would cost real space and imply a durability
    // property the image does not have.
    if (options.verity and options.ext4_journal.enabled) return error.JournalWithVerityRoot;
    const verity_layout = if (options.verity)
        try verity.splitPartition(root_partition.planned.length_bytes, ext4.default_block_size, ext4.default_block_size)
    else
        null;
    const rootfs_length = if (verity_layout) |layout_for_verity| layout_for_verity.data_size else root_partition.planned.length_bytes;

    // Generate a real, random ext4 filesystem UUID and thread it into the
    // generated GRUB configs' `search --fs-uuid` lines -- GRUB's `search`
    // command has no `--partuuid` search type, so without this the generated
    // boot chain fails to locate the root filesystem at all (see issue #72,
    // confirmed via real QEMU + OVMF boot testing against the real Azure
    // Linux 4.0 ISO).
    const root_filesystem_uuid = if (options.deterministic) |deterministic|
        deterministic.root_filesystem_uuid
    else blk: {
        var uuid: [16]u8 = undefined;
        Io.random(io, &uuid);
        break :blk uuid;
    };
    if (options.generation == .gen1 and !options.verity) {
        // Non-verity Gen1 can safely overlay a generated BIOS grub.cfg into
        // the source tree before `ext4.populate()`. Gen1+verity remains a
        // follow-up: once grub.cfg lives inside the verified root filesystem,
        // embedding the final `roothash=` there becomes self-referential.
        logStep(options, "generate BIOS GRUB configuration");
        var bios_grub_cfg = try bootconfig.generateBiosGrubCfg(allocator, try root_tree.ext4View(), .{
            .planned_partitions = planned_partitions,
            .architecture = architecture,
            .root_filesystem_uuid = root_filesystem_uuid,
            .extra_kernel_options = options.extra_kernel_options,
        });
        defer bios_grub_cfg.deinit(allocator);
        const existing = root_tree.findNode(bios_grub_cfg.path);
        try root_tree.putFileBytes(
            bios_grub_cfg.path,
            bios_grub_cfg.bytes,
            if (existing) |node| node.metadata else .{ .mode = 0o644 },
        );
    }
    try enterStage(options, .populate_filesystem);
    report.root_tree_digest = try root_tree.manifestDigest();
    if (options.limit_diagnostic) |sink| report.limit_peaks = sink.peaks;
    logStep(options, "populate root ext4 filesystem");
    var root_xattr_buffer: [1]ext4.Xattr = undefined;
    var root_selinux_value: ?[]u8 = null;
    defer if (root_selinux_value) |value| allocator.free(value);
    const root_xattrs: []const ext4.Xattr = if (options.root_selinux_label) |label| blk: {
        if (label.len == 0 or std.mem.indexOfScalar(u8, label, 0) != null) {
            return error.InvalidRootSelinuxLabel;
        }
        const value = try allocator.alloc(u8, label.len + 1);
        std.mem.copyForwards(u8, value[0..label.len], label);
        value[label.len] = 0;
        root_selinux_value = value;
        root_xattr_buffer[0] = .{
            .name = "security.selinux",
            .value = value,
        };
        break :blk &root_xattr_buffer;
    } else &.{};
    _ = try ext4.populate(io, raw_img.file, allocator, try root_tree.ext4View(), .{
        .offset = root_partition.planned.offset_bytes,
        .length = rootfs_length,
        .label = options.ext4_label,
        .root_xattrs = root_xattrs,
        .uuid = root_filesystem_uuid,
        .timestamp = if (options.deterministic) |deterministic| deterministic.filesystem_timestamp else 0,
        .journal = options.ext4_journal,
    });

    if (verity_layout) |layout_for_verity| {
        try enterStage(options, .seal_verity);
        logStep(options, "generate dm-verity hash tree");
        const salt = if (options.deterministic) |deterministic|
            deterministic.verity_salt
        else blk: {
            var random_salt: [verity.salt_size]u8 = undefined;
            Io.random(io, &random_salt);
            break :blk random_salt;
        };
        report.verity = try verity.generateAndWrite(io, raw_img.file, allocator, .{
            .device_offset = root_partition.planned.offset_bytes,
            .data_size = layout_for_verity.data_size,
            .hash_offset = layout_for_verity.hash_offset,
            .data_block_size = ext4.default_block_size,
            .hash_block_size = ext4.default_block_size,
            .salt = salt,
        });
    }

    if (options.generation == .gen1) {
        try enterStage(options, .install_bootloader);
        logStep(options, "install BIOS GRUB boot chain");
        try bootconfig.installBiosBoot(allocator, io, &raw_img, try root_tree.ext4View(), .{
            .planned_partitions = planned_partitions,
            .architecture = architecture,
            .verity = report.verity,
        });
    }

    if (findPartitionByRole(planned_partitions, .esp)) |esp_partition| {
        logStep(options, "populate ESP boot files");
        var esp_fs = try fat32.open(&raw_img, io, .{
            .offset = esp_partition.planned.offset_bytes,
            .length = esp_partition.planned.length_bytes,
        });
        var populate_stage_bridge = PopulateStageBridge{ .sink = options.stage_sink };
        _ = bootconfig.populateEsp(allocator, io, &esp_fs, try root_tree.ext4View(), .{
            .planned_partitions = planned_partitions,
            .architecture = architecture,
            .verity = report.verity,
            .root_filesystem_uuid = root_filesystem_uuid,
            .boot_mode = options.boot_mode,
            .extra_kernel_options = options.extra_kernel_options,
            .uki = options.uki,
            .stage_sink = if (options.stage_sink != null)
                .{ .context = &populate_stage_bridge, .advanceFn = PopulateStageBridge.advance }
            else
                null,
        }) catch |err| switch (err) {
            error.NoSpaceLeft => if (options.boot_mode != .bls_only)
                return error.EspTooSmallForBootArtifacts
            else
                return err,
            else => return err,
        };
    }

    try enterStage(options, .check_and_close_filesystems);
    raw_img.close(io);
    raw_img_open = false;

    try enterStage(options, .convert_output);
    if (!builds_output_in_place and spec.compression == .none and destination == .path) {
        logStep(options, "convert raw build image to requested output format");
        try convertRawToOutput(
            allocator,
            io,
            raw_build_path,
            destination.path,
            output_format,
            disk_size,
            if (options.deterministic) |deterministic| deterministic.output_create_options else .{},
        );
    }

    // A compressed or piped artifact is not a file the checks below can
    // open, so they run against the raw build image instead. It holds
    // exactly the guest-visible bytes that are about to be streamed out,
    // and validating before publishing means a rejected image is never
    // emitted at all.
    const validate_in_place = builds_output_in_place or (spec.compression == .none and destination == .path);
    var final_img = if (validate_in_place)
        try Image.openPath(io, destination.path)
    else
        try Image.openPathReadOnly(io, raw_build_path);
    defer final_img.close(io);

    if (output_format == .vhdx) {
        const metadata = try vhdx.open(io, final_img.file);
        report.vhdx_metadata = .{
            .header_sequence_number = metadata.header_sequence_number,
            .file_write_guid = metadata.file_write_guid,
            .data_write_guid = metadata.data_write_guid,
            .page83_guid = metadata.page83_guid,
        };
    }

    if (output_format == .vhd) {
        logStep(options, "validate Azure VHD alignment");
        report.vhd_alignment = try azure.alignFixedVhd(&final_img, io);
    }

    if (output_format != .qcow2) {
        logStep(options, "validate partition style");
        const partition_style = try azure.checkPartitionStyle(final_img, io, allocator, options.generation);
        report.partition_style = partition_style;
        if (!partition_style.ok) return error.PartitionStyleCheckFailed;
    }

    if (!validate_in_place) {
        logStep(options, "stream build image to compressed output");
        try output.writeImageTo(allocator, io, final_img, destination, .{
            .compression = spec.compression,
            .level = options.compression_level orelse output.default_level,
        });
    }

    return report;
}

fn validateBuildPathIsolation(
    allocator: std.mem.Allocator,
    io: Io,
    options: BuildImageOptions,
) !void {
    const output_path = try std.fs.path.resolve(allocator, &.{scratchBase(options)});
    defer allocator.free(output_path);
    const rootfs_scratch = try std.fmt.allocPrint(allocator, "{s}.build-image-rootfs.sqsh", .{output_path});
    defer allocator.free(rootfs_scratch);
    const root_tree_spool = try std.fmt.allocPrint(allocator, "{s}.build-image-root-tree.spool", .{output_path});
    defer allocator.free(root_tree_spool);
    const nested_prefix = try std.fmt.allocPrint(allocator, "{s}.build-image-nested", .{output_path});
    defer allocator.free(nested_prefix);
    const in_place = buildsOutputInPlace(options);
    const raw_build = if (in_place)
        output_path
    else
        try std.fmt.allocPrint(allocator, "{s}.build-image.raw", .{output_path});
    defer if (!in_place) allocator.free(raw_build);

    for ([_][]const u8{ options.iso_path, options.container_path }) |source| {
        if (try buildSourceConflicts(
            io,
            source,
            &.{ output_path, rootfs_scratch, root_tree_spool, raw_build },
            nested_prefix,
        )) return error.SourcePathConflict;
    }
    for (options.os.filesystem) |operation| switch (operation) {
        .put_file => |file| switch (file.source) {
            .inline_bytes => {},
            .host_path => |path| {
                if (try buildSourceConflicts(
                    io,
                    path,
                    &.{ output_path, rootfs_scratch, root_tree_spool, raw_build },
                    nested_prefix,
                )) return error.SourcePathConflict;
                const source_file = try Io.Dir.cwd().openFile(io, path, .{});
                defer source_file.close(io);
                if ((try source_file.stat(io)).kind != .file) return error.SourceNotRegularFile;
            },
        },
        else => {},
    };
}

fn buildSourceConflicts(
    io: Io,
    source_path: []const u8,
    reserved_paths: []const []const u8,
    nested_prefix_path: []const u8,
) !bool {
    const cwd = Io.Dir.cwd();
    var source_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const source = source_buffer[0..try canonicalBuildPath(cwd, io, source_path, &source_buffer)];
    for (reserved_paths) |reserved_path| {
        var reserved_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
        const reserved = reserved_buffer[0..try canonicalBuildPath(cwd, io, reserved_path, &reserved_buffer)];
        if (std.mem.eql(u8, source, reserved) or buildPathContains(source, reserved)) return true;
    }

    var nested_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const nested_prefix = nested_buffer[0..try canonicalBuildPath(cwd, io, nested_prefix_path, &nested_buffer)];
    return buildPathContains(source, nested_prefix) or
        (std.mem.startsWith(u8, source, nested_prefix) and
            source.len > nested_prefix.len and source[nested_prefix.len] == '-');
}

fn canonicalBuildPath(
    dir: Io.Dir,
    io: Io,
    path: []const u8,
    buffer: *[Io.Dir.max_path_bytes]u8,
) !usize {
    var absolute_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const absolute_path = if (std.fs.path.isAbsolute(path))
        path
    else blk: {
        const cwd_len = try dir.realPathFile(io, ".", &absolute_buffer);
        const separator_len: usize = @intFromBool(cwd_len != 0 and !std.fs.path.isSep(absolute_buffer[cwd_len - 1]));
        if (cwd_len + separator_len + path.len > absolute_buffer.len) return error.NameTooLong;
        if (separator_len != 0) absolute_buffer[cwd_len] = std.fs.path.sep;
        @memcpy(absolute_buffer[cwd_len + separator_len ..][0..path.len], path);
        break :blk absolute_buffer[0 .. cwd_len + separator_len + path.len];
    };
    var candidate = absolute_path;
    while (true) {
        if (dir.realPathFile(io, candidate, buffer)) |len| {
            const suffix = absolute_path[candidate.len..];
            if (len + suffix.len > buffer.len) return error.NameTooLong;
            @memcpy(buffer[len..][0..suffix.len], suffix);
            return len + suffix.len;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        const parent = std.fs.path.dirname(candidate) orelse return error.InvalidPath;
        if (std.mem.eql(u8, parent, candidate)) return error.InvalidPath;
        candidate = parent;
    }
}

fn buildPathContains(parent: []const u8, candidate: []const u8) bool {
    if (parent.len >= candidate.len or !std.mem.startsWith(u8, candidate, parent)) return false;
    return std.fs.path.isSep(candidate[parent.len]) or
        (std.fs.path.isSep(parent[parent.len - 1]) and parent.len == 1);
}

/// Resolves what the artifact is and how it is encoded. Anything stated
/// explicitly wins; the rest is inferred from the output filename's
/// extensions (`image.vhd`, `image.raw.gz`), and what is left over is raw
/// and uncompressed. Streaming to stdout leaves no filename to infer from,
/// so it relies entirely on `-O`.
fn resolveOutputSpec(options: BuildImageOptions) output.Spec {
    const inferred: ?output.Spec = if (options.stream_to_stdout)
        null
    else
        output.Spec.inferFromPath(options.output_path);
    return .{
        .format = options.output_format orelse
            if (inferred) |value| value.format else .raw,
        .compression = options.output_compression orelse
            if (inferred) |value| value.compression else .none,
    };
}

fn outputDestination(options: BuildImageOptions) output.Destination {
    return if (options.stream_to_stdout) .stdout else .{ .path = options.output_path };
}

fn scratchBase(options: BuildImageOptions) []const u8 {
    return if (options.stream_to_stdout) stdout_scratch_base else options.output_path;
}

fn buildsOutputInPlace(options: BuildImageOptions) bool {
    const spec = resolveOutputSpec(options);
    return !options.stream_to_stdout and spec.format == .raw and spec.compression == .none;
}

fn parseArchitecture(raw_arch: ?[]const u8) ?bootconfig.Architecture {
    const arch = raw_arch orelse return null;
    if (std.ascii.eqlIgnoreCase(arch, "amd64") or std.ascii.eqlIgnoreCase(arch, "x86_64")) return .x86_64;
    if (std.ascii.eqlIgnoreCase(arch, "arm64") or std.ascii.eqlIgnoreCase(arch, "aarch64")) return .aarch64;
    return null;
}

fn planPartitionIdentities(
    allocator: std.mem.Allocator,
    io: Io,
    disk_size: u64,
    generation: azure.Generation,
    architecture: bootconfig.Architecture,
    esp_size: u64,
    deterministic: ?*const BuildImageDeterminism,
) ![]bootconfig.PlannedPartitionIdentity {
    return switch (generation) {
        .gen2 => try planGen2PartitionIdentities(allocator, io, disk_size, architecture, esp_size, deterministic),
        .gen1 => try planGen1PartitionIdentities(allocator, io, disk_size, architecture, deterministic),
    };
}

fn planGen2PartitionIdentities(
    allocator: std.mem.Allocator,
    io: Io,
    disk_size: u64,
    architecture: bootconfig.Architecture,
    esp_size: u64,
    deterministic: ?*const BuildImageDeterminism,
) ![]bootconfig.PlannedPartitionIdentity {
    const root_role: layout.PartitionRole = switch (architecture) {
        .x86_64 => .root_x86_64,
        .aarch64 => .root_aarch64,
    };
    const requests = [_]layout.PartitionRequest{
        .{ .name = "ESP", .role = .esp, .size = .{ .fixed = esp_size } },
        .{ .name = "root", .role = root_role, .size = .{ .percent = 100.0 } },
    };
    const planned = try layout.planLayout(allocator, disk_size, &requests, null);
    errdefer allocator.free(planned);
    const identities = try allocator.alloc(bootconfig.PlannedPartitionIdentity, planned.len);
    for (planned, 0..) |part, index| {
        const unique_guid = if (deterministic) |values|
            if (part.role == .esp) values.esp_partition_guid else values.root_partition_guid
        else
            randomGuid(io);
        identities[index] = .{ .planned = part, .unique_guid = unique_guid };
    }
    allocator.free(planned);
    return identities;
}

fn planGen1PartitionIdentities(
    allocator: std.mem.Allocator,
    io: Io,
    disk_size: u64,
    architecture: bootconfig.Architecture,
    deterministic: ?*const BuildImageDeterminism,
) ![]bootconfig.PlannedPartitionIdentity {
    if (disk_size % gpt.sector_size != 0) return error.InvalidDiskSize;
    const root_role: layout.PartitionRole = switch (architecture) {
        .x86_64 => .root_x86_64,
        .aarch64 => .root_aarch64,
    };
    // Reserve the classic post-MBR embedding gap (sector 1 up to the first
    // 1 MiB-aligned partition) so BIOS GRUB can place `core.img` there.
    const offset_bytes = mib;
    if (disk_size <= offset_bytes + mib) return error.DiskTooSmall;
    const usable_bytes = alignDown(disk_size - offset_bytes, mib);
    if (usable_bytes == 0) return error.DiskTooSmall;
    const disk_signature = if (deterministic) |values| values.mbr_disk_signature else randomDiskSignature(io);

    const identities = try allocator.alloc(bootconfig.PlannedPartitionIdentity, 1);
    identities[0] = .{ .planned = .{
        .name = "root",
        .role = root_role,
        .type_guid = root_role.defaultTypeGuid(),
        .offset_bytes = offset_bytes,
        .length_bytes = usable_bytes,
    }, .unique_guid = if (deterministic) |values| values.root_partition_guid else randomGuid(io), .mbr_disk_signature = disk_signature };
    return identities;
}

fn alignDown(value: u64, alignment: u64) u64 {
    return value / alignment * alignment;
}

fn randomGuid(io: Io) guid.Guid {
    var bytes: guid.Guid = undefined;
    Io.random(io, &bytes);
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    return bytes;
}

fn randomDiskSignature(io: Io) u32 {
    var disk_signature: u32 = 0;
    while (disk_signature == 0) Io.random(io, std.mem.asBytes(&disk_signature));
    return disk_signature;
}

fn writeGptLayout(
    allocator: std.mem.Allocator,
    img: *Image,
    io: Io,
    disk_guid: guid.Guid,
    planned: []const bootconfig.PlannedPartitionIdentity,
) !void {
    const specs = try allocator.alloc(gpt.PlacedPartitionSpec, planned.len);
    defer allocator.free(specs);

    for (planned, 0..) |partition, index| {
        specs[index] = .{
            .type_guid = partition.planned.type_guid,
            .unique_guid = partition.unique_guid,
            .placement = .{
                .first_lba = partition.planned.firstLba(),
                .last_lba = partition.planned.lastLba(),
            },
            .name_utf16le = gpt.asciiName(partition.planned.name),
        };
    }
    try gpt.writeGptPlaced(img, io, disk_guid, specs);
}

fn writeMbrLayout(
    img: *Image,
    io: Io,
    planned: []const bootconfig.PlannedPartitionIdentity,
) !void {
    const root_partition = findAnyRootPartition(planned) orelse return error.MissingRootPartition;
    const first_lba = std.math.cast(u32, root_partition.planned.firstLba()) orelse return error.PartitionTooLargeForMbr;
    const sector_count = std.math.cast(u32, root_partition.planned.sizeSectors()) orelse return error.PartitionTooLargeForMbr;
    var table = mbr.singleLinuxPartitionMbr(first_lba, sector_count);
    table.disk_signature = root_partition.mbr_disk_signature orelse 0;
    const encoded = table.encode();
    try img.pwrite(io, &encoded, 0);
}

fn convertRawToOutput(
    allocator: std.mem.Allocator,
    io: Io,
    raw_path: []const u8,
    output_path: []const u8,
    output_format: Format,
    disk_size: u64,
    create_options: image_mod.CreateOptions,
) !void {
    var src = try Image.openPath(io, raw_path);
    defer src.close(io);

    var effective_create_options = create_options;
    if (output_format == .vhd) {
        effective_create_options.vhd_subformat = .fixed;
    }

    var dst = try Image.create(io, output_path, output_format, disk_size, effective_create_options);
    defer dst.close(io);

    try image_mod.copyAll(io, src, &dst, allocator);
}

fn logStep(options: BuildImageOptions, message: []const u8) void {
    if (options.event_sink) |sink| {
        sink.emit(.{ .progress = message });
    } else if (options.verbose) {
        std.debug.print("build-image: {s}\n", .{message});
    }
}

fn enterStage(options: BuildImageOptions, stage: Stage) !void {
    if (options.stage_sink) |sink| {
        if (!sink.advance(stage)) return error.InvalidOperationOrder;
    }
}

const PopulateStageBridge = struct {
    sink: ?StageSink,

    fn advance(context: ?*anyopaque, stage: bootconfig.PopulateStage) bool {
        const self: *PopulateStageBridge = @ptrCast(@alignCast(context.?));
        const sink = self.sink orelse return true;
        return sink.advance(switch (stage) {
            .prepare => .prepare_boot_configuration,
            .bootloader => .install_bootloader,
            .uki => .generate_uki,
        });
    }
};

fn emitWarning(options: BuildImageOptions, code: []const u8, message: []const u8) void {
    if (options.event_sink) |sink| {
        sink.emit(.{ .warning = .{ .code = code, .message = message } });
    } else {
        std.debug.print("build-image: warning: {s}\n", .{message});
    }
}

fn discoverRootfsPathInIso(
    allocator: std.mem.Allocator,
    reader: *iso9660.Reader,
    override_path: ?[]const u8,
) ![]u8 {
    if (override_path) |path| {
        const lookup_path = if (std.mem.startsWith(u8, path, "/")) path else try std.fmt.allocPrint(allocator, "/{s}", .{path});
        defer if (lookup_path.ptr != path.ptr) allocator.free(lookup_path);
        const index = try reader.lookup(lookup_path);
        if (reader.getEntry(index).kind != .file) return error.InvalidRootfsPath;
        return allocator.dupe(u8, trimLeadingSlash(path));
    }

    var best: ?[]u8 = null;
    errdefer if (best) |path| allocator.free(path);

    var queue = std.array_list.Managed(struct { index: usize, path: []u8 }).init(allocator);
    defer {
        for (queue.items) |item| allocator.free(item.path);
        queue.deinit();
    }

    const root_entries = try reader.listDirAlloc(allocator, reader.root_index);
    defer allocator.free(root_entries);
    for (root_entries) |entry| {
        try queue.append(.{ .index = entry.index, .path = try allocator.dupe(u8, entry.name) });
    }

    var cursor: usize = 0;
    while (cursor < queue.items.len) : (cursor += 1) {
        const item = queue.items[cursor];
        const node = reader.getEntry(item.index);
        if (node.kind == .directory) {
            const children = try reader.listDirAlloc(allocator, item.index);
            defer allocator.free(children);
            for (children) |child| {
                const child_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ item.path, child.name });
                try queue.append(.{ .index = child.index, .path = child_path });
            }
            continue;
        }
        if (!isRootfsCandidate(item.path)) continue;
        if (best == null or candidateScore(item.path) > candidateScore(best.?)) {
            if (best) |previous| allocator.free(previous);
            best = try allocator.dupe(u8, item.path);
        }
    }

    return best orelse error.RootfsNotFound;
}

fn isRootfsCandidate(path: []const u8) bool {
    const base = baseName(path);
    return std.ascii.endsWithIgnoreCase(base, ".squashfs") or
        std.ascii.endsWithIgnoreCase(base, ".sqsh") or
        std.ascii.indexOfIgnoreCase(base, "squashfs") != null or
        std.ascii.indexOfIgnoreCase(base, "rootfs") != null or
        std.ascii.endsWithIgnoreCase(base, ".img");
}

fn candidateScore(path: []const u8) u8 {
    const base = baseName(path);
    if (std.ascii.endsWithIgnoreCase(base, ".squashfs") or std.ascii.endsWithIgnoreCase(base, ".sqsh")) return 4;
    if (std.ascii.indexOfIgnoreCase(base, "squashfs") != null) return 3;
    if (std.ascii.indexOfIgnoreCase(base, "rootfs") != null) return 2;
    if (std.ascii.endsWithIgnoreCase(base, ".img")) return 1;
    return 0;
}

fn extractIsoEntryToPath(
    allocator: std.mem.Allocator,
    io: Io,
    reader: *iso9660.Reader,
    path_in_iso: []const u8,
    output_path: []const u8,
) !void {
    const lookup_path = if (std.mem.startsWith(u8, path_in_iso, "/")) path_in_iso else try std.fmt.allocPrint(allocator, "/{s}", .{path_in_iso});
    defer if (lookup_path.ptr != path_in_iso.ptr) allocator.free(lookup_path);

    const index = try reader.lookup(lookup_path);
    if (reader.getEntry(index).kind != .file) return error.InvalidRootfsPath;

    const file = try Io.Dir.cwd().createFile(io, output_path, .{
        .read = true,
        .truncate = true,
        .exclusive = true,
    });
    errdefer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer file.close(io);

    const buffer = try allocator.alloc(u8, scratch_copy_chunk_size);
    defer allocator.free(buffer);

    const entry = reader.getEntry(index);
    var offset: u64 = 0;
    while (offset < entry.size) {
        const want: usize = @intCast(@min(@as(u64, buffer.len), entry.size - offset));
        const got = try readIsoFileAt(io, reader, index, buffer[0..want], offset);
        if (got == 0) return error.UnexpectedEndOfStream;
        try file.writePositionalAll(io, buffer[0..got], offset);
        offset += got;
    }
}

fn trimLeadingSlash(path: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, path, "/")) path[1..] else path;
}

fn baseName(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[slash + 1 ..];
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

/// Loadable kernel modules (e.g. `hv_netvsc`/`mlx5` NIC drivers, `overlay`)
/// live under `/lib/modules/<kernel-version>/` (or `/usr/lib/modules/...` on
/// distros that merge `/usr`), alongside the `modules.dep`/`modules.alias`/
/// `modules.builtin` metadata modprobe/udev need to resolve them. Drivers
/// that happen to be statically built into the kernel (e.g. QEMU's
/// `virtio_net`) work without this, which is why the gap this covers is
/// invisible under local QEMU testing but breaks real hardware whose drivers
/// are modules (see issue #88). Retain the whole per-kernel-version tree
/// rather than a curated subset: there is no reliable way here to know which
/// specific `.ko` files a given piece of hardware will need at boot.
fn isKernelModulesPath(path: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(path, "lib/modules/") or
        std.ascii.startsWithIgnoreCase(path, "usr/lib/modules/");
}

fn isRequiredBootAssetPath(
    path: []const u8,
    architecture: bootconfig.Architecture,
    retain_uki_assets: bool,
) bool {
    if (shouldPreferInstalledBootPayload(path)) return true;
    if (isKernelModulesPath(path)) return true;
    if (retain_uki_assets and bootconfig.isUkiStubPath(path, architecture)) return true;
    if (std.ascii.eqlIgnoreCase(path, "boot/grub2/grub.cfg") or
        std.ascii.eqlIgnoreCase(path, "boot/grub/grub.cfg"))
    {
        return true;
    }
    if (std.ascii.endsWithIgnoreCase(path, "/i386-pc/boot.img") or
        std.ascii.endsWithIgnoreCase(path, "/i386-pc/core.img"))
    {
        return true;
    }
    if (!containsPathSegmentIgnoreCase(path, "EFI")) return false;

    const basename = baseName(path);
    return std.ascii.eqlIgnoreCase(basename, "BOOTX64.EFI") or
        std.ascii.eqlIgnoreCase(basename, "shimx64.efi") or
        std.ascii.eqlIgnoreCase(basename, "grubx64.efi") or
        std.ascii.eqlIgnoreCase(basename, "mmx64.efi") or
        std.ascii.eqlIgnoreCase(basename, "BOOTAA64.EFI") or
        std.ascii.eqlIgnoreCase(basename, "shimaa64.efi") or
        std.ascii.eqlIgnoreCase(basename, "grubaa64.efi") or
        std.ascii.eqlIgnoreCase(basename, "mmaa64.efi") or
        std.ascii.eqlIgnoreCase(basename, "MokManager.efi") or
        std.ascii.eqlIgnoreCase(basename, "MokManagerX64.efi") or
        std.ascii.eqlIgnoreCase(basename, "MokManagerAA64.efi") or
        std.ascii.eqlIgnoreCase(basename, "fbx64.efi") or
        std.ascii.eqlIgnoreCase(basename, "fbaa64.efi") or
        std.ascii.eqlIgnoreCase(basename, "fallback.efi") or
        std.ascii.endsWithIgnoreCase(basename, ".csv") or
        std.ascii.endsWithIgnoreCase(basename, ".cer") or
        std.ascii.endsWithIgnoreCase(basename, ".crt") or
        std.ascii.endsWithIgnoreCase(basename, ".der") or
        std.ascii.endsWithIgnoreCase(basename, ".esl") or
        std.ascii.endsWithIgnoreCase(basename, ".auth") or
        std.ascii.endsWithIgnoreCase(basename, ".conf");
}

fn findPartitionByRole(
    planned: []const bootconfig.PlannedPartitionIdentity,
    role: layout.PartitionRole,
) ?bootconfig.PlannedPartitionIdentity {
    for (planned) |partition| {
        if (partition.planned.role == role) return partition;
    }
    return null;
}

fn findRootPartition(
    planned: []const bootconfig.PlannedPartitionIdentity,
    architecture: bootconfig.Architecture,
) ?bootconfig.PlannedPartitionIdentity {
    const preferred_role: layout.PartitionRole = switch (architecture) {
        .x86_64 => .root_x86_64,
        .aarch64 => .root_aarch64,
    };
    if (findPartitionByRole(planned, preferred_role)) |partition| return partition;
    return findAnyRootPartition(planned);
}

fn findAnyRootPartition(planned: []const bootconfig.PlannedPartitionIdentity) ?bootconfig.PlannedPartitionIdentity {
    for (planned) |partition| switch (partition.planned.role) {
        .root_x86_64, .root_aarch64, .linux_filesystem_data => return partition,
        else => {},
    };
    return null;
}

const NestedSource = union(enum) {
    ext4: struct {
        scratch_path: []u8,
        file: Io.File,
        reader: ext4.Reader,
    },
    squashfs: struct {
        scratch_path: []u8,
        reader: squashfs.Reader,
    },
};

const MergedSourceTree = struct {
    io: Io,
    entries: []MergedEntry,
    nested_sources: []*NestedSource,
    index: usize = 0,
    view: ext4.FileTreeView,

    const MergedEntry = struct {
        path: []u8,
        kind: ext4.Kind,
        mode: u16,
        uid: u32,
        gid: u32,
        size: u64,
        content: ContentSource = .none,
        xattrs: ?[]ext4.OwnedXattr = null,
    };

    const PendingEntry = struct {
        path: []u8,
        kind: ext4.Kind,
        mode: u16,
        uid: u32,
        gid: u32,
        size: u64,
        content: ContentSource = .none,
        xattrs: ?[]ext4.OwnedXattr = null,
        alive: bool = true,
    };

    const ContentSource = union(enum) {
        none,
        bytes: []const u8,
        owned_bytes: []u8,
        iso_file: struct { io: Io, reader: *iso9660.Reader, index: usize },
        squashfs_file: struct { io: Io, reader: *squashfs.Reader, index: usize },
        nested_ext4_file: struct { io: Io, reader: *ext4.Reader, path: []const u8 },
    };

    fn init(
        allocator: std.mem.Allocator,
        io: Io,
        iso_reader: *iso9660.Reader,
        rootfs_path_in_iso: []const u8,
        squash_reader: *squashfs.Reader,
        container_image: *oci.Image,
        nested_scratch_prefix: []const u8,
    ) !MergedSourceTree {
        var pending = std.array_list.Managed(PendingEntry).init(allocator);
        defer pending.deinit();
        errdefer deinitPendingEntries(allocator, pending.items);

        var path_index = std.StringHashMap(usize).init(allocator);
        defer path_index.deinit();

        var nested_sources = std.array_list.Managed(*NestedSource).init(allocator);
        errdefer {
            deinitNestedSourcePointers(io, allocator, nested_sources.items);
            nested_sources.deinit();
        }
        var next_nested_scratch_id: usize = 0;

        try collectSquashfsEntries(
            allocator,
            io,
            &pending,
            &path_index,
            &nested_sources,
            nested_scratch_prefix,
            &next_nested_scratch_id,
            squash_reader,
            squash_reader.root_index,
            "",
            0,
        );
        try collectIsoEntries(allocator, io, &pending, &path_index, iso_reader, iso_reader.root_index, "", rootfs_path_in_iso);
        pruneEmptyAncestorDirectories(&pending, &path_index, rootfs_path_in_iso);
        try collectOciEntries(allocator, &pending, &path_index, container_image);
        try synthesizeMissingParents(allocator, &pending, &path_index);

        var live_count: usize = 0;
        for (pending.items) |*entry| {
            if (entry.alive) live_count += 1;
        }

        const entries = try allocator.alloc(MergedEntry, live_count);
        errdefer allocator.free(entries);

        var out_index: usize = 0;
        for (pending.items) |*entry| {
            if (!entry.alive) continue;
            entries[out_index] = .{
                .path = entry.path,
                .kind = entry.kind,
                .mode = entry.mode,
                .uid = entry.uid,
                .gid = entry.gid,
                .size = entry.size,
                .content = entry.content,
                .xattrs = entry.xattrs,
            };
            out_index += 1;
        }

        sortMergedEntries(entries);

        const owned_nested_sources = try nested_sources.toOwnedSlice();
        for (pending.items) |*entry| {
            if (!entry.alive) deinitPendingEntry(allocator, entry);
        }

        return .{
            .io = io,
            .entries = entries,
            .nested_sources = owned_nested_sources,
            .view = .{ .ctx = undefined, .next_fn = next, .reset_fn = reset },
        };
    }

    fn deinit(self: *MergedSourceTree, allocator: std.mem.Allocator) void {
        for (self.entries) |*entry| deinitMergedEntry(allocator, entry);
        allocator.free(self.entries);
        deinitNestedSourcePointers(self.io, allocator, self.nested_sources);
        allocator.free(self.nested_sources);
        self.* = undefined;
    }

    fn bind(self: *MergedSourceTree) void {
        self.view = .{
            .ctx = self,
            .next_fn = next,
            .reset_fn = reset,
        };
    }

    fn reset(ctx: *anyopaque) void {
        const self: *MergedSourceTree = @ptrCast(@alignCast(ctx));
        self.index = 0;
    }

    fn next(ctx: *anyopaque) ext4.FileTreeView.IteratorError!?ext4.FileTreeView.Entry {
        const self: *MergedSourceTree = @ptrCast(@alignCast(ctx));
        if (self.index >= self.entries.len) return null;
        const entry = &self.entries[self.index];
        self.index += 1;
        return .{
            .path = entry.path,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = if (entry.kind == .directory)
                null
            else
                .{ .ctx = &entry.content, .read_at_fn = readContent },
            .xattrs = ownedXattrsAsView(entry.xattrs),
        };
    }

    fn readContent(
        ctx: *const anyopaque,
        buffer: []u8,
        offset: u64,
    ) ext4.FileTreeView.ContentError!usize {
        const source: *const ContentSource = @ptrCast(@alignCast(ctx));
        return switch (source.*) {
            .none => 0,
            .bytes => |bytes| readBytes(bytes, buffer, offset),
            .owned_bytes => |bytes| readBytes(bytes, buffer, offset),
            .iso_file => |file| readIsoFileAt(file.io, file.reader, file.index, buffer, offset) catch error.ReadFailed,
            .squashfs_file => |file| readSquashfsFileAt(file.io, file.reader, file.index, buffer, offset) catch error.ReadFailed,
            .nested_ext4_file => |file| file.reader.preadPath(file.io, file.path, buffer, offset) catch error.ReadFailed,
        };
    }

    fn findEntryIndex(self: *const MergedSourceTree, path: []const u8) ?usize {
        for (self.entries, 0..) |entry, index| {
            if (std.mem.eql(u8, entry.path, path)) return index;
        }
        return null;
    }

    fn ensureParentDirectories(self: *MergedSourceTree, allocator: std.mem.Allocator, path: []const u8) !void {
        var missing = std.array_list.Managed([]u8).init(allocator);
        defer {
            for (missing.items) |parent| allocator.free(parent);
            missing.deinit();
        }

        var end_opt = std.mem.lastIndexOfScalar(u8, path, '/');
        while (end_opt) |end| {
            const parent = path[0..end];
            if (self.findEntryIndex(parent)) |index| {
                var entry = &self.entries[index];
                if (entry.kind != .directory) {
                    deinitContentSource(allocator, &entry.content);
                    if (entry.xattrs) |xattrs| {
                        ext4.freeXattrs(allocator, xattrs);
                        entry.xattrs = null;
                    }
                    entry.kind = .directory;
                    entry.mode = 0o755;
                    entry.uid = 0;
                    entry.gid = 0;
                    entry.size = 0;
                }
            } else {
                try missing.append(try allocator.dupe(u8, parent));
            }
            end_opt = std.mem.lastIndexOfScalar(u8, parent, '/');
        }

        if (missing.items.len == 0) return;

        const old_len = self.entries.len;
        self.entries = try allocator.realloc(self.entries, old_len + missing.items.len);
        var write_index = old_len;
        while (missing.pop()) |owned_parent| {
            self.entries[write_index] = .{
                .path = owned_parent,
                .kind = .directory,
                .mode = 0o755,
                .uid = 0,
                .gid = 0,
                .size = 0,
            };
            write_index += 1;
        }
        sortMergedEntries(self.entries);
    }

    fn upsertOwnedFile(self: *MergedSourceTree, allocator: std.mem.Allocator, path: []u8, bytes: []u8) !void {
        errdefer allocator.free(path);
        errdefer allocator.free(bytes);

        try self.ensureParentDirectories(allocator, path);

        if (self.findEntryIndex(path)) |index| {
            var entry = &self.entries[index];
            const existing_mode = if (entry.kind == .file) entry.mode else 0o644;
            const existing_uid = entry.uid;
            const existing_gid = entry.gid;
            deinitContentSource(allocator, &entry.content);
            if (entry.xattrs) |xattrs| {
                ext4.freeXattrs(allocator, xattrs);
                entry.xattrs = null;
            }
            entry.kind = .file;
            entry.mode = normalizeMode(.file, existing_mode);
            entry.uid = existing_uid;
            entry.gid = existing_gid;
            entry.size = bytes.len;
            entry.content = .{ .owned_bytes = bytes };
            allocator.free(path);
            return;
        }

        const old_len = self.entries.len;
        self.entries = try allocator.realloc(self.entries, old_len + 1);
        self.entries[old_len] = .{
            .path = path,
            .kind = .file,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .size = bytes.len,
            .content = .{ .owned_bytes = bytes },
        };
        sortMergedEntries(self.entries);
    }

    fn pruneToContainerRootfsAndBootAssets(
        self: *MergedSourceTree,
        allocator: std.mem.Allocator,
        container_image: *const oci.Image,
        architecture: bootconfig.Architecture,
        retain_uki_assets: bool,
    ) !void {
        var write_index: usize = 0;
        for (self.entries, 0..) |entry, read_index| {
            const keep = container_image.get(entry.path) != null or
                isRequiredBootAssetPath(entry.path, architecture, retain_uki_assets);
            if (keep) {
                if (write_index != read_index) self.entries[write_index] = entry;
                write_index += 1;
            } else {
                deinitMergedEntry(allocator, &self.entries[read_index]);
            }
        }

        self.entries = try allocator.realloc(self.entries, write_index);
        self.index = 0;

        var ensure_index: usize = 0;
        while (ensure_index < self.entries.len) : (ensure_index += 1) {
            try self.ensureParentDirectories(allocator, self.entries[ensure_index].path);
        }
    }
};

fn sortMergedEntries(entries: []MergedSourceTree.MergedEntry) void {
    std.mem.sort(MergedSourceTree.MergedEntry, entries, {}, struct {
        fn lessThan(_: void, a: MergedSourceTree.MergedEntry, b: MergedSourceTree.MergedEntry) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lessThan);
}

/// Well-known path (within the merged source tree, no leading `/`) where
/// `azagent` is expected if the caller wants it wired up -- add it via an
/// extra container layer, matching how `--stub-source-path` already
/// expects the UKI systemd EFI stub to already be present in the merged
/// tree rather than being injected by `zvmi` itself.
pub const azagent_binary_path = "usr/sbin/azagent";

const azagent_unit_path = "usr/lib/systemd/system/azagent.service";
const azagent_unit_enable_path = "usr/lib/systemd/system/multi-user.target.wants/azagent.service";

const azagent_unit_content =
    \\[Unit]
    \\Description=azagent Azure VM provisioning and disk maintenance
    \\After=network-online.target
    \\Wants=network-online.target
    \\
    \\[Service]
    \\Type=oneshot
    \\ExecStart=/usr/sbin/azagent
    \\RemainAfterExit=yes
    \\StandardOutput=journal+console
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\
;

/// If `azagent_binary_path` is present in `source_tree` (added by the
/// caller via an extra container layer -- see the doc comment on
/// `azagent_binary_path`), installs and enables a oneshot systemd unit
/// that runs on every boot. Provisioning remains sentinel-gated inside
/// `azagent`, while resource-disk and root-resize maintenance still runs.
/// A no-op if the binary isn't present -- most `build-image` output
/// doesn't set out to be an Azure-provisioned VM at all, so this must
/// never be a hard requirement.
///
/// The `[Install]` "enablement" is done by writing the *same* unit
/// content directly into `<target>.wants/`, rather than a symlink:
/// functionally equivalent for systemd's unit-loading purposes (it scans
/// each unit directory for files by name; a real file works exactly like
/// a symlink there), and `MergedSourceTree` has no symlink-upsert
/// primitive today.
fn installAzagentSystemdUnitIfPresent(allocator: std.mem.Allocator, source_tree: *MergedSourceTree) !void {
    if (source_tree.findEntryIndex(azagent_binary_path) == null) return;

    const unit_path = try allocator.dupe(u8, azagent_unit_path);
    const unit_bytes = try allocator.dupe(u8, azagent_unit_content);
    try source_tree.upsertOwnedFile(allocator, unit_path, unit_bytes);

    const enable_path = try allocator.dupe(u8, azagent_unit_enable_path);
    const enable_bytes = try allocator.dupe(u8, azagent_unit_content);
    try source_tree.upsertOwnedFile(allocator, enable_path, enable_bytes);
}

const NestedFilesystemKind = enum {
    ext4,
    squashfs,
};

fn deinitPendingEntry(allocator: std.mem.Allocator, entry: *MergedSourceTree.PendingEntry) void {
    deinitContentSource(allocator, &entry.content);
    if (entry.xattrs) |xattrs| ext4.freeXattrs(allocator, xattrs);
    allocator.free(entry.path);
    entry.* = undefined;
}

fn deinitPendingEntries(allocator: std.mem.Allocator, entries: []MergedSourceTree.PendingEntry) void {
    for (entries) |*entry| deinitPendingEntry(allocator, entry);
}

fn deinitMergedEntry(allocator: std.mem.Allocator, entry: *MergedSourceTree.MergedEntry) void {
    deinitContentSource(allocator, &entry.content);
    if (entry.xattrs) |xattrs| ext4.freeXattrs(allocator, xattrs);
    allocator.free(entry.path);
    entry.* = undefined;
}

fn deinitContentSource(allocator: std.mem.Allocator, source: *MergedSourceTree.ContentSource) void {
    switch (source.*) {
        .owned_bytes => |bytes| allocator.free(bytes),
        else => {},
    }
    source.* = .none;
}

fn ownedXattrsAsView(xattrs: ?[]ext4.OwnedXattr) []const ext4.Xattr {
    const owned = xattrs orelse return &.{};
    return @as([*]const ext4.Xattr, @ptrCast(owned.ptr))[0..owned.len];
}

fn isValidOwnedXattrName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    inline for (.{
        "user.",
        "trusted.",
        "security.",
        "system.",
    }) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) {
            const short_name = name[prefix.len..];
            return short_name.len > 0 and short_name.len <= 255;
        }
    }
    return true;
}

/// Consumes `xattrs`. On success, the caller owns the returned slice; on
/// error, this function frees the complete input.
fn dedupeOwnedXattrs(allocator: std.mem.Allocator, xattrs: []ext4.OwnedXattr) ![]ext4.OwnedXattr {
    if (xattrs.len == 0) return xattrs;
    errdefer ext4.freeXattrs(allocator, xattrs);

    const keep = try allocator.alloc(bool, xattrs.len);
    defer allocator.free(keep);
    @memset(keep, true);

    var unique_count = xattrs.len;
    for (xattrs, 0..) |xattr, index| {
        if (!isValidOwnedXattrName(xattr.name)) {
            keep[index] = false;
            unique_count -= 1;
            continue;
        }
        var other: usize = 0;
        while (other < index) : (other += 1) {
            if (keep[other] and std.mem.eql(u8, xattrs[other].name, xattr.name)) {
                keep[index] = false;
                unique_count -= 1;
                break;
            }
        }
    }
    if (unique_count == xattrs.len) return xattrs;

    const deduped = try allocator.alloc(ext4.OwnedXattr, unique_count);
    var out_index: usize = 0;
    for (xattrs, keep) |xattr, should_keep| {
        if (should_keep) {
            deduped[out_index] = xattr;
            out_index += 1;
        } else {
            allocator.free(xattr.name);
            allocator.free(xattr.value);
        }
    }
    allocator.free(xattrs);
    return deduped;
}

fn deinitNestedSourcePointers(io: Io, allocator: std.mem.Allocator, nested_sources: []const *NestedSource) void {
    for (nested_sources) |source| {
        switch (source.*) {
            .ext4 => |*nested| {
                nested.reader.deinit();
                nested.file.close(io);
                Io.Dir.cwd().deleteFile(io, nested.scratch_path) catch {};
                allocator.free(nested.scratch_path);
            },
            .squashfs => |*nested| {
                nested.reader.close(io);
                Io.Dir.cwd().deleteFile(io, nested.scratch_path) catch {};
                allocator.free(nested.scratch_path);
            },
        }
        allocator.destroy(source);
    }
}

fn collectSquashfsEntries(
    allocator: std.mem.Allocator,
    io: Io,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    nested_sources: *std.array_list.Managed(*NestedSource),
    nested_scratch_prefix: []const u8,
    next_nested_scratch_id: *usize,
    reader: *squashfs.Reader,
    parent_index: usize,
    prefix: []const u8,
    nesting_depth: u8,
) anyerror!void {
    const children = try reader.listDirAlloc(allocator, parent_index);
    defer allocator.free(children);

    for (children) |child| {
        const full_path = if (prefix.len == 0)
            try allocator.dupe(u8, child.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, child.name });
        var full_path_owned = true;
        errdefer if (full_path_owned) allocator.free(full_path);

        const entry = reader.getEntry(child.index);
        const mode = normalizeMode(switch (entry.kind) {
            .directory => .directory,
            .file => .file,
            .symlink => .symlink,
        }, entry.mode);
        switch (entry.kind) {
            .directory => {
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .directory,
                    .mode = mode,
                    .uid = entry.uid,
                    .gid = entry.gid,
                    .size = 0,
                });
                full_path_owned = false;
                try collectSquashfsEntries(
                    allocator,
                    io,
                    pending,
                    path_index,
                    nested_sources,
                    nested_scratch_prefix,
                    next_nested_scratch_id,
                    reader,
                    child.index,
                    full_path,
                    nesting_depth,
                );
            },
            .file => {
                if (try collectNestedFilesystemFromSquashfsFile(
                    allocator,
                    io,
                    pending,
                    path_index,
                    nested_sources,
                    nested_scratch_prefix,
                    next_nested_scratch_id,
                    reader,
                    child.index,
                    full_path,
                    nesting_depth,
                )) {
                    allocator.free(full_path);
                    continue;
                }
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .file,
                    .mode = mode,
                    .uid = entry.uid,
                    .gid = entry.gid,
                    .size = entry.size,
                    .content = .{ .squashfs_file = .{ .io = io, .reader = reader, .index = child.index } },
                });
                full_path_owned = false;
            },
            .symlink => {
                const target = try reader.readLink(child.index);
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .symlink,
                    .mode = mode,
                    .uid = entry.uid,
                    .gid = entry.gid,
                    .size = target.len,
                    .content = .{ .bytes = target },
                });
                full_path_owned = false;
            },
        }
    }
}

fn collectNestedFilesystemFromSquashfsFile(
    allocator: std.mem.Allocator,
    io: Io,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    nested_sources: *std.array_list.Managed(*NestedSource),
    nested_scratch_prefix: []const u8,
    next_nested_scratch_id: *usize,
    reader: *squashfs.Reader,
    index: usize,
    path: []const u8,
    nesting_depth: u8,
) anyerror!bool {
    if (nesting_depth >= max_nested_filesystem_depth) return false;

    var probe: [nested_filesystem_probe_len]u8 = undefined;
    const got = try readSquashfsFileAt(io, reader, index, &probe, 0);
    const nested_kind = detectNestedFilesystem(probe[0..got]) orelse return false;

    switch (nested_kind) {
        .ext4 => {
            const nested_source = try openNestedExt4FromSquashfsFile(
                allocator,
                io,
                nested_sources,
                nested_scratch_prefix,
                next_nested_scratch_id,
                reader,
                index,
            );
            // LiveOS-style media use nested filesystem image files as a
            // transport wrapper. Flatten the nested image's own root into the
            // merged tree root instead of preserving the wrapper file path.
            try collectExt4Entries(allocator, io, pending, path_index, &nested_source.ext4.reader, "");
            pruneEmptyAncestorDirectories(pending, path_index, path);
        },
        .squashfs => {
            const nested_source = try openNestedSquashfsFromSquashfsFile(
                allocator,
                io,
                nested_sources,
                nested_scratch_prefix,
                next_nested_scratch_id,
                reader,
                index,
            );
            // Flatten nested squashfs roots for the same reason as ext4
            // wrappers above: callers want the effective rootfs contents.
            try collectSquashfsEntries(
                allocator,
                io,
                pending,
                path_index,
                nested_sources,
                nested_scratch_prefix,
                next_nested_scratch_id,
                &nested_source.squashfs.reader,
                nested_source.squashfs.reader.root_index,
                "",
                nesting_depth + 1,
            );
            pruneEmptyAncestorDirectories(pending, path_index, path);
        },
    }
    return true;
}

fn pruneEmptyAncestorDirectories(
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    path: []const u8,
) void {
    var end_opt = std.mem.lastIndexOfScalar(u8, path, '/');
    while (end_opt) |end| {
        const parent = path[0..end];
        if (path_index.get(parent)) |existing_index| {
            if (pending.items[existing_index].kind == .directory and !hasLiveDescendants(pending.items, parent)) {
                deactivateEntry(pending, path_index, existing_index);
            }
        }
        end_opt = std.mem.lastIndexOfScalar(u8, parent, '/');
    }
}

fn hasLiveDescendants(entries: []const MergedSourceTree.PendingEntry, prefix: []const u8) bool {
    for (entries) |entry| {
        if (!entry.alive) continue;
        if (isDescendantPath(entry.path, prefix)) return true;
    }
    return false;
}

fn detectNestedFilesystem(bytes: []const u8) ?NestedFilesystemKind {
    if (bytes.len >= 4 and std.mem.readInt(u32, bytes[0..4], .little) == squashfs.magic) {
        return .squashfs;
    }
    if (bytes.len >= ext4_magic_offset + 2 and std.mem.readInt(u16, bytes[ext4_magic_offset..][0..2], .little) == ext4_magic) {
        return .ext4;
    }
    return null;
}

fn openNestedExt4FromSquashfsFile(
    allocator: std.mem.Allocator,
    io: Io,
    nested_sources: *std.array_list.Managed(*NestedSource),
    nested_scratch_prefix: []const u8,
    next_nested_scratch_id: *usize,
    reader: *squashfs.Reader,
    index: usize,
) !*NestedSource {
    const scratch_path = try nextNestedScratchPath(allocator, nested_scratch_prefix, next_nested_scratch_id, "ext4");
    errdefer allocator.free(scratch_path);
    errdefer Io.Dir.cwd().deleteFile(io, scratch_path) catch {};

    try extractSquashfsEntryToPath(allocator, io, reader, index, scratch_path);

    const file = try Io.Dir.cwd().openFile(io, scratch_path, .{});
    errdefer file.close(io);

    var nested_reader = try ext4.Reader.open(io, file, allocator, .{});
    errdefer nested_reader.deinit();

    const source = try allocator.create(NestedSource);
    errdefer allocator.destroy(source);
    source.* = .{
        .ext4 = .{
            .scratch_path = scratch_path,
            .file = file,
            .reader = nested_reader,
        },
    };
    try nested_sources.append(source);
    return source;
}

fn openNestedSquashfsFromSquashfsFile(
    allocator: std.mem.Allocator,
    io: Io,
    nested_sources: *std.array_list.Managed(*NestedSource),
    nested_scratch_prefix: []const u8,
    next_nested_scratch_id: *usize,
    reader: *squashfs.Reader,
    index: usize,
) !*NestedSource {
    const scratch_path = try nextNestedScratchPath(allocator, nested_scratch_prefix, next_nested_scratch_id, "sqsh");
    errdefer allocator.free(scratch_path);
    errdefer Io.Dir.cwd().deleteFile(io, scratch_path) catch {};

    try extractSquashfsEntryToPath(allocator, io, reader, index, scratch_path);

    var nested_reader = try squashfs.Reader.openPath(allocator, io, scratch_path);
    errdefer nested_reader.close(io);

    const source = try allocator.create(NestedSource);
    errdefer allocator.destroy(source);
    source.* = .{
        .squashfs = .{
            .scratch_path = scratch_path,
            .reader = nested_reader,
        },
    };
    try nested_sources.append(source);
    return source;
}

fn nextNestedScratchPath(
    allocator: std.mem.Allocator,
    nested_scratch_prefix: []const u8,
    next_nested_scratch_id: *usize,
    extension: []const u8,
) ![]u8 {
    const path = try std.fmt.allocPrint(
        allocator,
        "{s}-{d}.{s}",
        .{ nested_scratch_prefix, next_nested_scratch_id.*, extension },
    );
    next_nested_scratch_id.* += 1;
    return path;
}

fn collectExt4Entries(
    allocator: std.mem.Allocator,
    io: Io,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    reader: *ext4.Reader,
    prefix: []const u8,
) !void {
    const children = try reader.listDir(io, allocator, prefix);
    defer ext4.freeDirEntries(allocator, children);

    for (children) |child| {
        const full_path = if (prefix.len == 0)
            try allocator.dupe(u8, child.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, child.name });
        var full_path_owned = true;
        errdefer if (full_path_owned) allocator.free(full_path);

        const stat = try reader.statPath(io, full_path);
        const xattrs = try dedupeOwnedXattrs(allocator, try reader.readXattrsAlloc(io, allocator, full_path));
        var xattrs_owned = true;
        errdefer if (xattrs_owned) ext4.freeXattrs(allocator, xattrs);

        switch (child.kind) {
            .directory => {
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .directory,
                    .mode = normalizeMode(.directory, stat.mode),
                    .uid = stat.uid,
                    .gid = stat.gid,
                    .size = 0,
                    .xattrs = xattrs,
                });
                full_path_owned = false;
                xattrs_owned = false;
                try collectExt4Entries(allocator, io, pending, path_index, reader, full_path);
            },
            .file => {
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .file,
                    .mode = normalizeMode(.file, stat.mode),
                    .uid = stat.uid,
                    .gid = stat.gid,
                    .size = stat.size,
                    .content = .{ .nested_ext4_file = .{ .io = io, .reader = reader, .path = full_path } },
                    .xattrs = xattrs,
                });
                full_path_owned = false;
                xattrs_owned = false;
            },
            .symlink => {
                const target = try reader.readLinkAlloc(io, allocator, full_path);
                var target_owned = true;
                errdefer if (target_owned) allocator.free(target);
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .symlink,
                    .mode = normalizeMode(.symlink, stat.mode),
                    .uid = stat.uid,
                    .gid = stat.gid,
                    .size = target.len,
                    .content = .{ .owned_bytes = target },
                    .xattrs = xattrs,
                });
                full_path_owned = false;
                xattrs_owned = false;
                target_owned = false;
            },
            // `ext4.Reader` classifies only these three kinds, so a nested
            // ext4 source cannot present anything else here.
            .hardlink, .block_device, .char_device, .fifo => return error.UnsupportedNestedEntryKind,
        }
    }
}

fn extractSquashfsEntryToPath(
    allocator: std.mem.Allocator,
    io: Io,
    reader: *squashfs.Reader,
    index: usize,
    output_path: []const u8,
) !void {
    const entry = reader.getEntry(index);
    if (entry.kind != .file) return error.NotAFile;

    const file = try Io.Dir.cwd().createFile(io, output_path, .{
        .read = true,
        .truncate = true,
        .exclusive = true,
    });
    defer file.close(io);

    const buffer = try allocator.alloc(u8, scratch_copy_chunk_size);
    defer allocator.free(buffer);

    var offset: u64 = 0;
    while (offset < entry.size) {
        const want: usize = @intCast(@min(@as(u64, buffer.len), entry.size - offset));
        const got = try readSquashfsFileAt(io, reader, index, buffer[0..want], offset);
        if (got == 0) return error.UnexpectedEndOfStream;
        try file.writePositionalAll(io, buffer[0..got], offset);
        offset += got;
    }
}

fn collectIsoEntries(
    allocator: std.mem.Allocator,
    io: Io,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    reader: *iso9660.Reader,
    parent_index: usize,
    prefix: []const u8,
    rootfs_path_in_iso: []const u8,
) !void {
    const children = try reader.listDirAlloc(allocator, parent_index);
    defer allocator.free(children);

    for (children) |child| {
        const full_path = if (prefix.len == 0)
            try allocator.dupe(u8, child.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, child.name });
        var full_path_owned = true;
        errdefer if (full_path_owned) allocator.free(full_path);

        if (std.ascii.eqlIgnoreCase(full_path, rootfs_path_in_iso)) {
            allocator.free(full_path);
            continue;
        }

        const entry = reader.getEntry(child.index);
        const kind: ext4.Kind = switch (entry.kind) {
            .directory => .directory,
            .file => .file,
            .symlink => .symlink,
        };
        const mode = normalizeMode(kind, entry.mode);

        switch (entry.kind) {
            .directory => {
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .directory,
                    .mode = mode,
                    .uid = entry.uid,
                    .gid = entry.gid,
                    .size = 0,
                });
                full_path_owned = false;
                try collectIsoEntries(allocator, io, pending, path_index, reader, child.index, full_path, rootfs_path_in_iso);
            },
            .file => {
                // Prefer the installed rootfs's own /boot kernel+initramfs (and
                // /lib/modules) over duplicate copies shipped on the
                // installation media. Live ISO boot payloads can legitimately
                // differ from the installed system's own contents (e.g.
                // missing dm-verity support in the initramfs, or a different
                // kernel/module version used only to run the installer), so
                // the built image should keep the squashfs rootfs version
                // when both provide the same path.
                if (path_index.contains(full_path) and
                    (shouldPreferInstalledBootPayload(full_path) or isKernelModulesPath(full_path)))
                {
                    allocator.free(full_path);
                    continue;
                }
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .file,
                    .mode = mode,
                    .uid = entry.uid,
                    .gid = entry.gid,
                    .size = entry.size,
                    .content = .{ .iso_file = .{ .io = io, .reader = reader, .index = child.index } },
                });
                full_path_owned = false;
            },
            .symlink => {
                if (path_index.contains(full_path) and
                    (shouldPreferInstalledBootPayload(full_path) or isKernelModulesPath(full_path)))
                {
                    allocator.free(full_path);
                    continue;
                }
                const target = try reader.readLink(child.index);
                try overlayEntry(allocator, pending, path_index, .{
                    .path = full_path,
                    .kind = .symlink,
                    .mode = mode,
                    .uid = entry.uid,
                    .gid = entry.gid,
                    .size = target.len,
                    .content = .{ .bytes = target },
                });
                full_path_owned = false;
            },
        }
    }
}

fn shouldPreferInstalledBootPayload(path: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, path, '/') orelse return false;
    if (!std.ascii.eqlIgnoreCase(path[0..slash], "boot")) return false;

    const basename = path[slash + 1 ..];
    return std.ascii.startsWithIgnoreCase(basename, "vmlinuz") or
        std.ascii.eqlIgnoreCase(basename, "Image") or
        std.ascii.startsWithIgnoreCase(basename, "Image-") or
        std.ascii.eqlIgnoreCase(basename, "bzImage") or
        std.ascii.eqlIgnoreCase(basename, "zImage") or
        std.ascii.startsWithIgnoreCase(basename, "initrd") or
        std.ascii.startsWithIgnoreCase(basename, "initramfs");
}

fn isInitramfsSourcePath(path: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, path, '/') orelse return false;
    if (!std.ascii.eqlIgnoreCase(path[0..slash], "boot")) return false;

    const basename = path[slash + 1 ..];
    return std.ascii.startsWithIgnoreCase(basename, "initrd") or
        std.ascii.startsWithIgnoreCase(basename, "initramfs");
}

/// Reads every `boot/initrd*`/`boot/initramfs*` file in the merged source
/// tree and checks each for dm-verity userspace tooling (see
/// `initramfs.zig`), returning the most conservative combined status: any
/// match anywhere is `.present`; otherwise `.absent` only if every candidate
/// was fully and conclusively parsed with no match, and `.inconclusive`
/// (including when no initramfs candidate was found at all) whenever any
/// candidate couldn't be fully verified, since a false "absent" would fail a
/// build that might actually boot fine.
fn checkInitramfsVerityTooling(
    allocator: std.mem.Allocator,
    view: *ext4.FileTreeView,
) !initramfs.VerityToolingStatus {
    view.reset();

    var found_any_candidate = false;
    var saw_inconclusive = false;
    var saw_absent = false;

    while (try view.next()) |entry| {
        if (entry.kind != .file or !isInitramfsSourcePath(entry.path)) continue;
        const content = entry.content orelse continue;
        found_any_candidate = true;

        const bytes = try readViewFileAlloc(allocator, content, entry.size);
        defer allocator.free(bytes);

        switch (try initramfs.checkVerityTooling(allocator, bytes)) {
            .present => return .present,
            .absent => saw_absent = true,
            .inconclusive => saw_inconclusive = true,
        }
    }

    if (!found_any_candidate or saw_inconclusive) return .inconclusive;
    return if (saw_absent) .absent else .inconclusive;
}

fn readViewFileAlloc(
    allocator: std.mem.Allocator,
    content: ext4.FileTreeView.ContentReader,
    size: u64,
) ![]u8 {
    const len = std.math.cast(usize, size) orelse return error.FileTooLarge;
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);

    var done: usize = 0;
    while (done < out.len) {
        const got = try content.readAt(out[done..], done);
        if (got == 0) return error.UnexpectedSourceLength;
        done += got;
    }
    return out;
}

fn collectOciEntries(
    allocator: std.mem.Allocator,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    image: *oci.Image,
) !void {
    var iter = image.iterator();
    while (iter.next()) |entry| {
        const kind: ext4.Kind = switch (entry.kind) {
            .directory => .directory,
            .file, .hardlink => .file,
            .symlink => .symlink,
        };
        const bytes: []const u8 = switch (entry.kind) {
            .file => entry.content,
            .symlink => entry.link_name.?,
            .hardlink => try resolveOciHardlinkContent(image, entry),
            .directory => "",
        };
        const xattrs = try dedupeOwnedXattrs(allocator, try dupeOciXattrs(allocator, entry.xattrs));
        var xattrs_owned = true;
        errdefer if (xattrs_owned) ext4.freeXattrs(allocator, xattrs);
        const path = try allocator.dupe(u8, entry.path);
        var path_owned = true;
        errdefer if (path_owned) allocator.free(path);
        try overlayEntry(allocator, pending, path_index, .{
            .path = path,
            .kind = kind,
            .mode = normalizeMode(kind, entry.mode),
            .uid = entry.uid,
            .gid = entry.gid,
            .size = switch (kind) {
                .file, .symlink => bytes.len,
                else => 0,
            },
            .content = switch (kind) {
                .file, .symlink => .{ .bytes = bytes },
                else => .none,
            },
            .xattrs = xattrs,
        });
        path_owned = false;
        xattrs_owned = false;
    }
}

fn dupeOciXattrs(allocator: std.mem.Allocator, xattrs: []const oci.Xattr) ![]ext4.OwnedXattr {
    if (xattrs.len == 0) return allocator.alloc(ext4.OwnedXattr, 0);
    const owned = try allocator.alloc(ext4.OwnedXattr, xattrs.len);
    var completed: usize = 0;
    errdefer {
        for (owned[0..completed]) |xattr| {
            allocator.free(xattr.name);
            allocator.free(xattr.value);
        }
        allocator.free(owned);
    }
    for (xattrs, 0..) |xattr, index| {
        const name = try allocator.dupe(u8, xattr.name);
        const value = allocator.dupe(u8, xattr.value) catch |err| {
            allocator.free(name);
            return err;
        };
        owned[index] = .{
            .name = name,
            .value = value,
        };
        completed += 1;
    }
    return owned;
}

fn resolveOciHardlinkContent(image: *const oci.Image, initial: oci.FileTree.Entry) ![]const u8 {
    var entry = initial;
    var depth: usize = 0;
    while (entry.kind == .hardlink) : (depth += 1) {
        if (depth == 32) return error.HardlinkDepthExceeded;
        entry = image.get(entry.link_name orelse return error.MissingHardlinkTarget) orelse
            return error.MissingHardlinkTarget;
    }
    if (entry.kind != .file) return error.UnsupportedHardlinkTarget;
    return entry.content;
}

fn overlayEntry(
    allocator: std.mem.Allocator,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    entry: MergedSourceTree.PendingEntry,
) !void {
    // Reserve every fallible insertion before changing the overlay state.
    // On error, the caller still owns the complete entry; on success, pending
    // owns it and releases it through deinitPendingEntry.
    try pending.ensureUnusedCapacity(1);
    try path_index.ensureUnusedCapacity(1);

    removeAncestorConflicts(pending, path_index, entry.path);
    if (entry.kind != .directory) removeDescendants(pending, path_index, entry.path);
    if (path_index.get(entry.path)) |existing_index| deactivateEntry(pending, path_index, existing_index);

    const entry_index = pending.items.len;
    pending.appendAssumeCapacity(entry);
    path_index.putAssumeCapacity(pending.items[entry_index].path, entry_index);
    _ = allocator;
}

fn overlaySyntheticDirectory(
    allocator: std.mem.Allocator,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    path: []const u8,
) !void {
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    try overlayEntry(allocator, pending, path_index, .{
        .path = owned_path,
        .kind = .directory,
        .mode = 0o755,
        .uid = 0,
        .gid = 0,
        .size = 0,
    });
}

fn synthesizeMissingParents(
    allocator: std.mem.Allocator,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
) !void {
    var cursor: usize = 0;
    while (cursor < pending.items.len) : (cursor += 1) {
        if (!pending.items[cursor].alive) continue;
        const path = pending.items[cursor].path;
        var end = std.mem.lastIndexOfScalar(u8, path, '/') orelse continue;
        while (true) {
            const parent = path[0..end];
            if (path_index.get(parent)) |existing_index| {
                if (pending.items[existing_index].kind != .directory) {
                    try overlaySyntheticDirectory(allocator, pending, path_index, parent);
                }
            } else {
                try overlaySyntheticDirectory(allocator, pending, path_index, parent);
            }
            end = std.mem.lastIndexOfScalar(u8, parent, '/') orelse break;
        }
    }
}

fn removeAncestorConflicts(
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    path: []const u8,
) void {
    var end_opt = std.mem.lastIndexOfScalar(u8, path, '/');
    while (end_opt) |end| {
        const parent = path[0..end];
        if (path_index.get(parent)) |existing_index| {
            if (pending.items[existing_index].kind != .directory) {
                deactivateEntry(pending, path_index, existing_index);
            }
        }
        end_opt = std.mem.lastIndexOfScalar(u8, parent, '/');
    }
}

fn removeDescendants(
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    prefix: []const u8,
) void {
    for (pending.items, 0..) |entry, index| {
        if (!entry.alive) continue;
        if (isDescendantPath(entry.path, prefix)) deactivateEntry(pending, path_index, index);
    }
}

fn deactivateEntry(
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    index: usize,
) void {
    if (!pending.items[index].alive) return;
    pending.items[index].alive = false;
    if (path_index.get(pending.items[index].path)) |mapped_index| {
        if (mapped_index == index) _ = path_index.remove(pending.items[index].path);
    }
}

fn isDescendantPath(candidate: []const u8, prefix: []const u8) bool {
    return candidate.len > prefix.len and
        std.mem.startsWith(u8, candidate, prefix) and
        candidate[prefix.len] == '/';
}

fn normalizeMode(kind: ext4.Kind, raw_mode: u32) u16 {
    const mode = @as(u16, @intCast(raw_mode & 0o7777));
    if ((mode & 0o7777) != 0) return mode & 0o7777;
    return switch (kind) {
        .directory => 0o755,
        .file, .hardlink => 0o644,
        .symlink => 0o777,
        .block_device, .char_device, .fifo => 0o600,
    };
}

fn readBytes(bytes: []const u8, buffer: []u8, offset: u64) ext4.FileTreeView.ContentError!usize {
    const start = std.math.cast(usize, offset) orelse return error.UnexpectedEndOfStream;
    if (start > bytes.len) return error.UnexpectedEndOfStream;
    const count = @min(buffer.len, bytes.len - start);
    std.mem.copyForwards(u8, buffer[0..count], bytes[start .. start + count]);
    return count;
}

fn readIsoFileAt(io: Io, reader: *iso9660.Reader, index: usize, buffer: []u8, offset: u64) !usize {
    const entry = reader.getEntry(index);
    if (entry.kind != .file) return error.NotAFile;
    if (offset > entry.size) return error.UnexpectedEndOfStream;
    if (offset == entry.size or buffer.len == 0) return 0;

    const remaining_total = entry.size - offset;
    const target_len: usize = @intCast(@min(@as(u64, buffer.len), remaining_total));
    var produced: usize = 0;
    var file_offset_within_entry = offset;

    for (entry.extents) |extent| {
        if (file_offset_within_entry >= extent.size) {
            file_offset_within_entry -= extent.size;
            continue;
        }

        const extent_offset = file_offset_within_entry;
        const extent_remaining = extent.size - extent_offset;
        const take: usize = @intCast(@min(@as(u64, target_len - produced), extent_remaining));
        const absolute_offset = @as(u64, extent.lba) * reader.logical_block_size + extent_offset;
        const got = try reader.file.readPositionalAll(io, buffer[produced .. produced + take], absolute_offset);
        if (got < take) @memset(buffer[produced + got .. produced + take], 0);
        produced += take;
        file_offset_within_entry = 0;
        if (produced == target_len) break;
    }

    return produced;
}

fn readSquashfsFileAt(io: Io, reader: *squashfs.Reader, index: usize, buffer: []u8, offset: u64) !usize {
    const entry = reader.getEntry(index);
    if (entry.kind != .file) return error.NotAFile;
    if (offset > entry.size) return error.UnexpectedEndOfStream;
    return reader.readFileAt(reader.allocator, io, index, buffer, offset);
}

fn expectGen2BuiltImageContents(
    allocator: std.mem.Allocator,
    io: Io,
    img: *Image,
    report: BuildImageReport,
    image_path: []const u8,
) !void {
    const parsed = try gpt.readGpt(img.*, io, allocator);
    defer allocator.free(parsed.partitions);
    try std.testing.expectEqual(@as(usize, 2), parsed.partitions.len);
    try std.testing.expectEqualSlices(u8, &guid.esp, &parsed.partitions[0].partition_type_guid);
    try std.testing.expectEqualSlices(u8, &report.planned_partitions[1].unique_guid, &parsed.partitions[1].unique_partition_guid);

    const esp_partition = report.planned_partitions[0].planned;
    var esp = try fat32.open(img, io, .{ .offset = esp_partition.offset_bytes, .length = esp_partition.length_bytes });

    const bootx64 = try esp.readFileAlloc(io, allocator, "EFI/BOOT/BOOTX64.EFI");
    defer allocator.free(bootx64);
    try std.testing.expectEqualStrings("bootx64-from-oci", bootx64);

    const vendor_grub = try esp.readFileAlloc(io, allocator, "EFI/Acme/grub.cfg");
    defer allocator.free(vendor_grub);
    try std.testing.expect(std.mem.indexOf(u8, vendor_grub, "menuentry") != null);

    const bls_entry = try esp.readFileAlloc(io, allocator, "loader/entries/vmlinuz-test.conf");
    defer allocator.free(bls_entry);
    try std.testing.expect(std.mem.indexOf(u8, bls_entry, "root=PARTUUID=") != null);
    try std.testing.expect(std.mem.indexOf(u8, bls_entry, "/boot/vmlinuz-test") != null);

    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{image_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const root_entries = try root_reader.listDir(io, allocator, "");
    defer {
        for (root_entries) |entry| allocator.free(entry.name);
        allocator.free(root_entries);
    }
    try std.testing.expect(root_entries.len >= 3);

    const squashfs_file = try root_reader.readFileAlloc(io, allocator, "etc/message.txt");
    defer allocator.free(squashfs_file);
    try std.testing.expectEqual(@as(usize, 1500), squashfs_file.len);
    try std.testing.expectEqual(@as(u8, 'A'), squashfs_file[0]);
    try std.testing.expectEqual(@as(u8, 'B'), squashfs_file[squashfs_file.len - 1]);

    const overlay_file = try root_reader.readFileAlloc(io, allocator, "app/hello.txt");
    defer allocator.free(overlay_file);
    try std.testing.expectEqualStrings("hello from layer2\n", overlay_file);

    const boot_kernel = try root_reader.readFileAlloc(io, allocator, "boot/vmlinuz-test");
    defer allocator.free(boot_kernel);
    try std.testing.expectEqualStrings("kernel-from-oci", boot_kernel);
}

fn syntheticSquashfsBlockByte(block_index: usize) u8 {
    return @as(u8, 'A') + @as(u8, @intCast(block_index % 26));
}

fn syntheticSquashfsFragmentByte(full_data_block_count: usize) u8 {
    return @as(u8, 'A') + @as(u8, @intCast(full_data_block_count % 26));
}

fn buildExpectedSyntheticSquashfsFileAlloc(allocator: std.mem.Allocator, options: squashfs.SyntheticImageOptions) ![]u8 {
    if (options.file_bytes) |bytes| return allocator.dupe(u8, bytes);

    const block_size: usize = @intCast(options.block_size);
    const full_data_block_count: usize = @intCast(options.full_data_blocks);
    const fragment_tail_size: usize = @intCast(options.fragment_tail_size);
    const total_len = full_data_block_count * block_size + fragment_tail_size;
    const bytes = try allocator.alloc(u8, total_len);

    var offset: usize = 0;
    for (0..full_data_block_count) |block_index| {
        @memset(bytes[offset..][0..block_size], syntheticSquashfsBlockByte(block_index));
        offset += block_size;
    }
    if (fragment_tail_size > 0) {
        @memset(bytes[offset..][0..fragment_tail_size], syntheticSquashfsFragmentByte(full_data_block_count));
    }
    return bytes;
}

const SyntheticNestedExt4Entry = struct {
    path: []const u8,
    kind: ext4.Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64 = 0,
    bytes: []const u8 = "",
};

const SyntheticNestedExt4Tree = struct {
    entries: []const SyntheticNestedExt4Entry,
    index: usize = 0,
    view: ext4.FileTreeView,

    fn init(entries: []const SyntheticNestedExt4Entry) SyntheticNestedExt4Tree {
        return .{
            .entries = entries,
            .view = .{
                .ctx = undefined,
                .next_fn = next,
                .reset_fn = reset,
            },
        };
    }

    fn bind(self: *SyntheticNestedExt4Tree) void {
        self.view = .{
            .ctx = self,
            .next_fn = next,
            .reset_fn = reset,
        };
    }

    fn reset(ctx: *anyopaque) void {
        const self: *SyntheticNestedExt4Tree = @ptrCast(@alignCast(ctx));
        self.index = 0;
    }

    fn next(ctx: *anyopaque) ext4.FileTreeView.IteratorError!?ext4.FileTreeView.Entry {
        const self: *SyntheticNestedExt4Tree = @ptrCast(@alignCast(ctx));
        if (self.index >= self.entries.len) return null;
        const entry = self.entries[self.index];
        self.index += 1;
        return .{
            .path = entry.path,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = if (entry.kind == .directory)
                null
            else
                .{ .ctx = &self.entries[self.index - 1], .read_at_fn = readContent },
        };
    }

    fn readContent(ctx: *const anyopaque, buffer: []u8, offset: u64) ext4.FileTreeView.ContentError!usize {
        const entry: *const SyntheticNestedExt4Entry = @ptrCast(@alignCast(ctx));
        return readBytes(entry.bytes, buffer, offset);
    }
};

fn buildSyntheticNestedExt4ImageAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
) ![]u8 {
    return buildNestedExt4ImageAlloc(allocator, io, path, &[_]SyntheticNestedExt4Entry{
        .{ .path = "bin", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 7, .bytes = "usr/bin" },
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 12, .bytes = "nested-host\n" },
        .{ .path = "usr", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "usr/bin", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "usr/bin/true", .kind = .file, .mode = 0o755, .uid = 0, .gid = 0, .size = 17, .bytes = "#!/bin/sh\nexit 0\n" },
    });
}

fn buildNestedExt4ImageAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    entries: []const SyntheticNestedExt4Entry,
) ![]u8 {
    var tree = SyntheticNestedExt4Tree.init(entries);
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    _ = try ext4.populate(io, file, allocator, &tree.view, .{
        .length = 8 * 1024 * 1024,
        .label = "nested-root",
    });

    const image_size = (try file.stat(io)).size;
    const bytes = try allocator.alloc(u8, image_size);
    _ = try file.readPositionalAll(io, bytes, 0);
    return bytes;
}

fn extractImageRegionToPath(
    allocator: std.mem.Allocator,
    io: Io,
    img: *Image,
    offset: u64,
    length: u64,
    output_path: []const u8,
) !void {
    const file = try Io.Dir.cwd().createFile(io, output_path, .{ .read = true, .truncate = true });
    defer file.close(io);

    const buffer = try allocator.alloc(u8, scratch_copy_chunk_size);
    defer allocator.free(buffer);

    var copied: u64 = 0;
    while (copied < length) {
        const want: usize = @intCast(@min(@as(u64, buffer.len), length - copied));
        const got = try img.pread(io, buffer[0..want], offset + copied);
        if (got != want) return error.UnexpectedEndOfStream;
        try file.writePositionalAll(io, buffer[0..want], copied);
        copied += got;
    }
}

test "dedupeOwnedXattrs frees owned input on allocation failures" {
    const source = [_]oci.Xattr{
        .{ .name = "user.duplicate", .value = "first" },
        .{ .name = "user.duplicate", .value = "second" },
        .{ .name = "user.unique", .value = "third" },
    };

    for (0..3) |failure_offset| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const allocator = failing.allocator();
        const input = try dupeOciXattrs(allocator, &source);
        failing.fail_index = failing.alloc_index + failure_offset;

        const deduped = dedupeOwnedXattrs(allocator, input) catch |err| {
            try std.testing.expect(failure_offset < 2);
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            continue;
        };
        try std.testing.expectEqual(@as(usize, 2), failure_offset);
        try std.testing.expectEqual(@as(usize, 2), deduped.len);
        ext4.freeXattrs(allocator, deduped);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}

fn overlayEntryForAllocationTest(
    allocator: std.mem.Allocator,
    failing: *std.testing.FailingAllocator,
    failure_offset: usize,
) !void {
    var pending = std.array_list.Managed(MergedSourceTree.PendingEntry).init(allocator);
    defer {
        deinitPendingEntries(allocator, pending.items);
        pending.deinit();
    }
    var path_index = std.StringHashMap(usize).init(allocator);
    defer path_index.deinit();

    const path = try allocator.dupe(u8, "parent/child");
    errdefer allocator.free(path);
    const source = [_]oci.Xattr{.{ .name = "user.overlay", .value = "metadata" }};
    const xattrs = try dupeOciXattrs(allocator, &source);
    errdefer ext4.freeXattrs(allocator, xattrs);

    failing.fail_index = failing.alloc_index + failure_offset;
    overlayEntry(allocator, &pending, &path_index, .{
        .path = path,
        .kind = .file,
        .mode = 0o640,
        .uid = 42,
        .gid = 43,
        .size = 7,
        .content = .{ .bytes = "payload" },
        .xattrs = xattrs,
    }) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), pending.items.len);
        try std.testing.expectEqual(@as(usize, 0), path_index.count());
        return err;
    };
}

test "overlayEntry is transactional across allocation failures" {
    var saw_success = false;
    var induced_failures: usize = 0;
    var failure_offset: usize = 0;
    while (failure_offset < 8 and !saw_success) : (failure_offset += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        overlayEntryForAllocationTest(failing.allocator(), &failing, failure_offset) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            induced_failures += 1;
            continue;
        };
        saw_success = true;
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
    try std.testing.expect(saw_success);
    try std.testing.expect(induced_failures >= 2);
}

fn appendPendingEntryForAllocationTest(
    allocator: std.mem.Allocator,
    pending: *std.array_list.Managed(MergedSourceTree.PendingEntry),
    path_index: *std.StringHashMap(usize),
    path: []const u8,
) !void {
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    const source = [_]oci.Xattr{.{ .name = "user.pending", .value = "metadata" }};
    const xattrs = try dupeOciXattrs(allocator, &source);
    errdefer ext4.freeXattrs(allocator, xattrs);
    try overlayEntry(allocator, pending, path_index, .{
        .path = owned_path,
        .kind = .file,
        .mode = 0o600,
        .uid = 42,
        .gid = 43,
        .size = 0,
        .xattrs = xattrs,
    });
}

fn failAfterAccumulatingPendingEntries(
    allocator: std.mem.Allocator,
    failing: *std.testing.FailingAllocator,
) !void {
    var pending = std.array_list.Managed(MergedSourceTree.PendingEntry).init(allocator);
    defer pending.deinit();
    errdefer deinitPendingEntries(allocator, pending.items);
    var path_index = std.StringHashMap(usize).init(allocator);
    defer path_index.deinit();

    try appendPendingEntryForAllocationTest(allocator, &pending, &path_index, "first");
    try appendPendingEntryForAllocationTest(allocator, &pending, &path_index, "second");

    failing.fail_index = failing.alloc_index;
    _ = try allocator.alloc(MergedSourceTree.MergedEntry, pending.items.len);
}

test "merged source initialization frees accumulated pending entries on allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    try std.testing.expectError(
        error.OutOfMemory,
        failAfterAccumulatingPendingEntries(failing.allocator(), &failing),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "customization sources cannot alias output or internal scratch paths" {
    var operations = [_]os_customization.FilesystemOperation{
        .{ .put_file = .{
            .path = "/etc/example",
            .source = .{ .host_path = "output.qcow2.build-image-root-tree.spool" },
        } },
    };
    var options = BuildImageOptions{
        .iso_path = "input.iso",
        .container_path = "container",
        .output_path = "output.qcow2",
        .size = 128 * mib,
        .output_format = .qcow2,
        .os = .{ .filesystem = &operations },
    };
    try std.testing.expectError(
        error.SourcePathConflict,
        validateBuildPathIsolation(std.testing.allocator, std.testing.io, options),
    );

    operations[0].put_file.source = .{ .host_path = "output.qcow2.build-image.raw" };
    try std.testing.expectError(
        error.SourcePathConflict,
        validateBuildPathIsolation(std.testing.allocator, std.testing.io, options),
    );

    operations[0].put_file.source = .{ .host_path = "output.qcow2.build-image-nested-1.img" };
    try std.testing.expectError(
        error.SourcePathConflict,
        validateBuildPathIsolation(std.testing.allocator, std.testing.io, options),
    );

    operations[0].put_file.source = .{ .host_path = "output.qcow2" };
    try std.testing.expectError(
        error.SourcePathConflict,
        validateBuildPathIsolation(std.testing.allocator, std.testing.io, options),
    );

    const independent = try Io.Dir.cwd().createFile(std.testing.io, "independent-input", .{});
    independent.close(std.testing.io);
    defer Io.Dir.cwd().deleteFile(std.testing.io, "independent-input") catch {};
    operations[0].put_file.source = .{ .host_path = "independent-input" };
    try validateBuildPathIsolation(std.testing.allocator, std.testing.io, options);

    options.iso_path = "output.qcow2.build-image-root-tree.spool";
    try std.testing.expectError(
        error.SourcePathConflict,
        validateBuildPathIsolation(std.testing.allocator, std.testing.io, options),
    );
}

test "build-image honors caller OCI load limits" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const oci_root = "test-build-image-oci-limit";
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    try createEfiOnlyBuildImageOciLayout(allocator, io, oci_root);

    try std.testing.expectError(error.BlobTooLarge, build(allocator, io, .{
        .iso_path = "unreached.iso",
        .container_path = oci_root,
        .oci_load_options = .{ .max_blob_size = 1 },
        .output_path = "unreached.raw",
        .output_format = .raw,
        .size = 256 * mib,
        .dry_run = true,
    }));
}

test "build-image builds Gen2 VHD, VHDX, and qcow2 outputs from XZ squashfs + OCI layout" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image.iso";
    const oci_root = "test-build-image-oci";
    const vhd_output_path = "test-build-image.vhd";
    const vhdx_output_path = "test-build-image.vhdx";
    const qcow2_output_path = "test-build-image.qcow2";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, vhd_output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, vhdx_output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, qcow2_output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    const StageRecorder = struct {
        stages: [11]Stage = undefined,
        len: usize = 0,

        fn advance(context: ?*anyopaque, stage: Stage) bool {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.stages[self.len] = stage;
            self.len += 1;
            return true;
        }
    };
    var stage_recorder = StageRecorder{};
    var vhd_report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = vhd_output_path,
        .output_format = .vhd,
        .generation = .gen2,
        .size = 256 * mib,
        .stage_sink = .{ .context = &stage_recorder, .advanceFn = StageRecorder.advance },
    });
    defer vhd_report.deinit(allocator);

    const expected_stages = [_]Stage{
        .load_sources,
        .apply_filesystem_changes,
        .generalize_and_cleanup,
        .prepare_initramfs,
        .populate_filesystem,
        .prepare_boot_configuration,
        .install_bootloader,
        .check_and_close_filesystems,
        .convert_output,
    };
    try std.testing.expectEqualSlices(Stage, &expected_stages, stage_recorder.stages[0..stage_recorder.len]);
    try std.testing.expectEqual(Format.vhd, vhd_report.output_format);
    try std.testing.expect(vhd_report.partition_style.?.ok);
    try std.testing.expectEqual(@as(usize, 2), vhd_report.planned_partitions.len);

    var vhd_img = try Image.openPath(io, vhd_output_path);
    defer vhd_img.close(io);
    try expectGen2BuiltImageContents(allocator, io, &vhd_img, vhd_report, vhd_output_path);

    var vhdx_report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = vhdx_output_path,
        .output_format = .vhdx,
        .generation = .gen2,
        .size = 256 * mib,
    });
    defer vhdx_report.deinit(allocator);

    try std.testing.expectEqual(Format.vhdx, vhdx_report.output_format);
    try std.testing.expect(vhdx_report.partition_style.?.ok);
    try std.testing.expectEqual(@as(usize, 2), vhdx_report.planned_partitions.len);

    const vhdx_file = try Io.Dir.cwd().openFile(io, vhdx_output_path, .{});
    defer vhdx_file.close(io);
    const vhdx_info = try vhdx.open(io, vhdx_file);
    try std.testing.expectEqual(vhdx_report.disk_size, vhdx_info.virtual_size);
    try std.testing.expectEqual(vhdx_info.header_sequence_number, vhdx_report.vhdx_metadata.?.header_sequence_number);
    try std.testing.expectEqualSlices(u8, &vhdx_info.file_write_guid, &vhdx_report.vhdx_metadata.?.file_write_guid);
    try std.testing.expectEqualSlices(u8, &vhdx_info.data_write_guid, &vhdx_report.vhdx_metadata.?.data_write_guid);
    try std.testing.expectEqualSlices(u8, &vhdx_info.page83_guid, &vhdx_report.vhdx_metadata.?.page83_guid);

    var vhdx_img = try Image.openPath(io, vhdx_output_path);
    defer vhdx_img.close(io);
    try std.testing.expectEqual(Format.vhdx, vhdx_img.format);
    try expectGen2BuiltImageContents(allocator, io, &vhdx_img, vhdx_report, vhdx_output_path);

    var qcow2_report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = qcow2_output_path,
        .output_format = .qcow2,
        .generation = .gen2,
        .size = 256 * mib,
    });
    defer qcow2_report.deinit(allocator);

    try std.testing.expectEqual(Format.qcow2, qcow2_report.output_format);
    try std.testing.expect(qcow2_report.partition_style == null);
    try std.testing.expectEqual(@as(usize, 2), qcow2_report.planned_partitions.len);

    const qcow2_file = try Io.Dir.cwd().openFile(io, qcow2_output_path, .{});
    defer qcow2_file.close(io);
    const qcow2_info = try qcow2.open(io, qcow2_file);
    try std.testing.expectEqual(qcow2_report.disk_size, qcow2_info.virtual_size);

    var qcow2_img = try Image.openPath(io, qcow2_output_path);
    defer qcow2_img.close(io);
    try std.testing.expectEqual(Format.qcow2, qcow2_img.format);
    try expectGen2BuiltImageContents(allocator, io, &qcow2_img, qcow2_report, qcow2_output_path);
}

test "build-image populates multi-block squashfs files into ext4 for small sequential reads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-large-squashfs.iso";
    const oci_root = "test-build-image-large-squashfs-oci";
    const output_path = "test-build-image-large-squashfs.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_options = squashfs.SyntheticImageOptions{
        .compression = .xz,
        .block_size = 64 * 1024,
        .full_data_blocks = 48,
        .fragment_tail_size = 8192,
    };
    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, squashfs_options);
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
    });
    defer report.deinit(allocator);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const contents = try root_reader.readFileAlloc(io, allocator, "etc/message.txt");
    defer allocator.free(contents);
    const expected = try buildExpectedSyntheticSquashfsFileAlloc(allocator, squashfs_options);
    defer allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, contents);
}

test "build-image unwraps nested ext4 filesystem images inside squashfs files" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-nested-ext4.iso";
    const oci_root = "test-build-image-nested-ext4-oci";
    const output_path = "test-build-image-nested-ext4.raw";
    const nested_ext4_path = "test-build-image-nested-rootfs.img";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, nested_ext4_path) catch {};

    const nested_ext4_bytes = try buildSyntheticNestedExt4ImageAlloc(allocator, io, nested_ext4_path);
    defer allocator.free(nested_ext4_bytes);

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{
        .compression = .none,
        .block_size = 1024 * 1024,
        .file_bytes = nested_ext4_bytes,
    });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
    });
    defer report.deinit(allocator);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const hostname = try root_reader.readFileAlloc(io, allocator, "etc/hostname");
    defer allocator.free(hostname);
    try std.testing.expectEqualStrings("nested-host\n", hostname);

    const true_payload = try root_reader.readFileAlloc(io, allocator, "usr/bin/true");
    defer allocator.free(true_payload);
    try std.testing.expectEqualStrings("#!/bin/sh\nexit 0\n", true_payload);
}

test "build-image prefers squashfs kernel and initramfs over duplicate ISO boot payloads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-boot-payload-precedence.iso";
    const oci_root = "test-build-image-boot-payload-precedence-oci";
    const output_path = "test-build-image-boot-payload-precedence.raw";
    const nested_ext4_path = "test-build-image-boot-payload-precedence-rootfs.img";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, nested_ext4_path) catch {};

    const nested_ext4_bytes = try buildNestedExt4ImageAlloc(allocator, io, nested_ext4_path, &[_]SyntheticNestedExt4Entry{
        .{ .path = "boot", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "kernel-from-squashfs".len, .bytes = "kernel-from-squashfs" },
        .{ .path = "boot/initramfs-test.img", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "initrd-from-squashfs".len, .bytes = "initrd-from-squashfs" },
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "precedence-test\n".len, .bytes = "precedence-test\n" },
    });
    defer allocator.free(nested_ext4_bytes);

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{
        .compression = .none,
        .block_size = 1024 * 1024,
        .file_bytes = nested_ext4_bytes,
    });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithBootPayloads(
        allocator,
        io,
        iso_path,
        "root.squashfs",
        squashfs_bytes,
        "vmlinuz-test",
        "kernel-from-iso",
        "initramfs-test.img",
        "initrd-from-iso",
    );

    try createEfiOnlyBuildImageOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
    });
    defer report.deinit(allocator);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    const esp_partition = report.planned_partitions[0].planned;
    var esp = try fat32.open(&img, io, .{ .offset = esp_partition.offset_bytes, .length = esp_partition.length_bytes });
    const bls_entry = try esp.readFileAlloc(io, allocator, "loader/entries/vmlinuz-test.conf");
    defer allocator.free(bls_entry);
    try std.testing.expect(std.mem.indexOf(u8, bls_entry, "/boot/vmlinuz-test") != null);
    try std.testing.expect(std.mem.indexOf(u8, bls_entry, "/boot/initramfs-test.img") != null);

    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const kernel = try root_reader.readFileAlloc(io, allocator, "boot/vmlinuz-test");
    defer allocator.free(kernel);
    try std.testing.expectEqualStrings("kernel-from-squashfs", kernel);

    const initrd = try root_reader.readFileAlloc(io, allocator, "boot/initramfs-test.img");
    defer allocator.free(initrd);
    try std.testing.expectEqualStrings("initrd-from-squashfs", initrd);
}

test "build-image can skip the ISO rootfs while retaining boot assets" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-skip-iso-rootfs.iso";
    const oci_root = "test-build-image-skip-iso-rootfs-oci";
    const output_path = "test-build-image-skip-iso-rootfs.raw";
    const nested_ext4_path = "test-build-image-skip-iso-rootfs-rootfs.img";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, nested_ext4_path) catch {};

    const nested_ext4_bytes = try buildNestedExt4ImageAlloc(allocator, io, nested_ext4_path, &[_]SyntheticNestedExt4Entry{
        .{ .path = "boot", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "kernel-from-squashfs".len, .bytes = "kernel-from-squashfs" },
        .{ .path = "boot/initramfs-test.img", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "initrd-from-squashfs".len, .bytes = "initrd-from-squashfs" },
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "live-rootfs-only\n".len, .bytes = "live-rootfs-only\n" },
    });
    defer allocator.free(nested_ext4_bytes);

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{
        .compression = .none,
        .block_size = 1024 * 1024,
        .file_bytes = nested_ext4_bytes,
    });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithBootPayloads(
        allocator,
        io,
        iso_path,
        "root.squashfs",
        squashfs_bytes,
        "vmlinuz-test",
        "kernel-from-iso",
        "initramfs-test.img",
        "initrd-from-iso",
    );

    try createContainerRootfsOnlyBuildImageOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
        .skip_iso_rootfs = true,
        .root_selinux_label = "system_u:object_r:root_t:s0",
    });
    defer report.deinit(allocator);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const kernel = try root_reader.readFileAlloc(io, allocator, "boot/vmlinuz-test");
    defer allocator.free(kernel);
    try std.testing.expectEqualStrings("kernel-from-squashfs", kernel);

    const initrd = try root_reader.readFileAlloc(io, allocator, "boot/initramfs-test.img");
    defer allocator.free(initrd);
    try std.testing.expectEqualStrings("initrd-from-squashfs", initrd);

    const app_file = try root_reader.readFileAlloc(io, allocator, "app/hello.txt");
    defer allocator.free(app_file);
    try std.testing.expectEqualStrings("hello from minimal container rootfs\n", app_file);

    const chronyd = try root_reader.statPath(io, "usr/bin/chronyd");
    try std.testing.expectEqual(@as(u32, 991), chronyd.uid);
    try std.testing.expectEqual(@as(u32, 991), chronyd.gid);
    const capability = try root_reader.readXattrAlloc(io, allocator, "usr/bin/chronyd", "security.capability");
    defer allocator.free(capability);
    try std.testing.expectEqualStrings("chronyd-capability", capability);
    const root_selinux = try root_reader.readXattrAlloc(io, allocator, "/", "security.selinux");
    defer allocator.free(root_selinux);
    try std.testing.expectEqualSlices(u8, "system_u:object_r:root_t:s0\x00", root_selinux);

    try std.testing.expectError(error.NotFound, root_reader.readFileAlloc(io, allocator, "etc/hostname"));
}

test "build-image retains installed kernel modules during skip-iso-rootfs pruning" {
    // Regression test for issue #88: --skip-iso-rootfs used to discard
    // /lib/modules entirely, so any NIC/storage driver that isn't statically
    // built into the kernel (e.g. Azure's hv_netvsc/mlx5, unlike QEMU's
    // statically-built-in virtio_net) could never load on the built image.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-skip-iso-rootfs-modules.iso";
    const oci_root = "test-build-image-skip-iso-rootfs-modules-oci";
    const output_path = "test-build-image-skip-iso-rootfs-modules.raw";
    const nested_ext4_path = "test-build-image-skip-iso-rootfs-modules-rootfs.img";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, nested_ext4_path) catch {};

    const nested_ext4_bytes = try buildNestedExt4ImageAlloc(allocator, io, nested_ext4_path, &[_]SyntheticNestedExt4Entry{
        .{ .path = "boot", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "kernel-from-squashfs".len, .bytes = "kernel-from-squashfs" },
        .{ .path = "boot/initramfs-test.img", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "initrd-from-squashfs".len, .bytes = "initrd-from-squashfs" },
        .{ .path = "lib", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "lib/modules", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "lib/modules/6.6.0", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "lib/modules/6.6.0/modules.dep", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "hv_netvsc.ko:".len, .bytes = "hv_netvsc.ko:" },
        .{ .path = "lib/modules/6.6.0/kernel", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "lib/modules/6.6.0/kernel/drivers", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "lib/modules/6.6.0/kernel/drivers/net", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "lib/modules/6.6.0/kernel/drivers/net/hyperv", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "lib/modules/6.6.0/kernel/drivers/net/hyperv/hv_netvsc.ko", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "hv-netvsc-module-bytes".len, .bytes = "hv-netvsc-module-bytes" },
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "live-rootfs-only\n".len, .bytes = "live-rootfs-only\n" },
    });
    defer allocator.free(nested_ext4_bytes);

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{
        .compression = .none,
        .block_size = 1024 * 1024,
        .file_bytes = nested_ext4_bytes,
    });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithBootPayloads(
        allocator,
        io,
        iso_path,
        "root.squashfs",
        squashfs_bytes,
        "vmlinuz-test",
        "kernel-from-iso",
        "initramfs-test.img",
        "initrd-from-iso",
    );

    try createContainerRootfsOnlyBuildImageOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
        .skip_iso_rootfs = true,
    });
    defer report.deinit(allocator);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const module = try root_reader.readFileAlloc(io, allocator, "lib/modules/6.6.0/kernel/drivers/net/hyperv/hv_netvsc.ko");
    defer allocator.free(module);
    try std.testing.expectEqualStrings("hv-netvsc-module-bytes", module);

    const modules_dep = try root_reader.readFileAlloc(io, allocator, "lib/modules/6.6.0/modules.dep");
    defer allocator.free(modules_dep);
    try std.testing.expectEqualStrings("hv_netvsc.ko:", modules_dep);

    // Unrelated live-only paths are still pruned.
    try std.testing.expectError(error.NotFound, root_reader.readFileAlloc(io, allocator, "etc/hostname"));
}

test "build-image retains kernel modules paths during skip-iso-rootfs pruning" {
    // Loadable NIC/storage drivers (e.g. hv_netvsc, mlx5) and modprobe/udev
    // metadata (modules.dep, modules.alias, modules.builtin) live under
    // /lib/modules/<kernel-version>/ and must survive pruning even though
    // they aren't in the EFI/GRUB/kernel/initramfs allowlist -- see issue #88.
    try std.testing.expect(isRequiredBootAssetPath(
        "lib/modules/6.6.0/kernel/drivers/net/hyperv/hv_netvsc.ko",
        .x86_64,
        false,
    ));
    try std.testing.expect(isRequiredBootAssetPath("lib/modules/6.6.0/modules.dep", .x86_64, false));
    try std.testing.expect(isRequiredBootAssetPath("lib/modules/6.6.0/modules.alias", .x86_64, false));
    try std.testing.expect(isRequiredBootAssetPath(
        "usr/lib/modules/6.6.0-aarch64/kernel/fs/overlayfs/overlay.ko",
        .aarch64,
        false,
    ));

    try std.testing.expect(!isRequiredBootAssetPath("usr/lib/modules-load.d/virtio.conf", .x86_64, false));
    try std.testing.expect(!isRequiredBootAssetPath("etc/modules-load.d/virtio.conf", .x86_64, false));
    try std.testing.expect(!isRequiredBootAssetPath("var/lib/modules/state", .x86_64, false));
}

test "build-image retains architecture-matching UKI stub paths during skip-iso-rootfs pruning" {
    try std.testing.expect(isRequiredBootAssetPath("boot/linuxx64.efi.stub", .x86_64, true));
    try std.testing.expect(isRequiredBootAssetPath("usr/lib/systemd/boot/efi/systemd-stubx64.efi", .x86_64, true));
    try std.testing.expect(isRequiredBootAssetPath("custom/stubx64.efi", .x86_64, true));

    try std.testing.expect(isRequiredBootAssetPath("boot/linuxaa64.efi.stub", .aarch64, true));
    try std.testing.expect(isRequiredBootAssetPath("usr/lib/systemd/boot/efi/systemd-stubaa64.efi", .aarch64, true));
    try std.testing.expect(isRequiredBootAssetPath("custom/stubaa64.efi", .aarch64, true));

    try std.testing.expect(!isRequiredBootAssetPath("boot/linuxx64.efi.stub", .x86_64, false));
    try std.testing.expect(!isRequiredBootAssetPath("boot/linuxaa64.efi.stub", .x86_64, true));
    try std.testing.expect(!isRequiredBootAssetPath("boot/linuxx64.efi.stub", .aarch64, true));
}

test "build-image can skip the ISO rootfs and still build a UKI from ISO-only stub assets" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-skip-iso-rootfs-uki.iso";
    const oci_root = "test-build-image-skip-iso-rootfs-uki-oci";
    const output_path = "test-build-image-skip-iso-rootfs-uki.raw";
    const nested_ext4_path = "test-build-image-skip-iso-rootfs-uki-rootfs.img";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, nested_ext4_path) catch {};

    const nested_ext4_bytes = try buildNestedExt4ImageAlloc(allocator, io, nested_ext4_path, &[_]SyntheticNestedExt4Entry{
        .{ .path = "boot", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "kernel-from-squashfs".len, .bytes = "kernel-from-squashfs" },
        .{ .path = "boot/initramfs-test.img", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "initrd-from-squashfs".len, .bytes = "initrd-from-squashfs" },
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "live-rootfs-only\n".len, .bytes = "live-rootfs-only\n" },
    });
    defer allocator.free(nested_ext4_bytes);

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{
        .compression = .none,
        .block_size = 1024 * 1024,
        .file_bytes = nested_ext4_bytes,
    });
    defer allocator.free(squashfs_bytes);

    const stub_bytes = try makeTestStubPe(allocator, 0x8664);
    defer allocator.free(stub_bytes);

    try writeMinimalIsoWithBootPayloads(
        allocator,
        io,
        iso_path,
        "root.squashfs",
        squashfs_bytes,
        "linuxx64.efi.stub",
        stub_bytes,
        "README.TXT",
        "ignored\n",
    );

    try createContainerRootfsOnlyBuildImageOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 512 * mib,
        .skip_iso_rootfs = true,
        .boot_mode = .uki_only,
    });
    defer report.deinit(allocator);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    const esp_partition = report.planned_partitions[0].planned;
    var esp = try fat32.open(&img, io, .{ .offset = esp_partition.offset_bytes, .length = esp_partition.length_bytes });

    const fallback_uki = try esp.readFileAlloc(io, allocator, "EFI/BOOT/BOOTX64.EFI");
    defer allocator.free(fallback_uki);
    try std.testing.expectEqualStrings("MZ", fallback_uki[0..2]);

    const named_uki = try esp.readFileAlloc(io, allocator, "EFI/Linux/vmlinuz-test.efi");
    defer allocator.free(named_uki);
    try std.testing.expectEqualStrings("MZ", named_uki[0..2]);

    try std.testing.expectError(error.PathNotFound, esp.readFileAlloc(io, allocator, "loader/loader.conf"));

    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const app_file = try root_reader.readFileAlloc(io, allocator, "app/hello.txt");
    defer allocator.free(app_file);
    try std.testing.expectEqualStrings("hello from minimal container rootfs\n", app_file);

    try std.testing.expectError(error.NotFound, root_reader.readFileAlloc(io, allocator, "etc/hostname"));
}

test "build-image installs a Gen1 BIOS GRUB chain into the post-MBR gap" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-gen1.iso";
    const oci_root = "test-build-image-gen1-oci";
    const output_path = "test-build-image-gen1.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixtureWithOptions(allocator, io, oci_root, .{
        .bios_asset_layout = .usr_lib_grub,
    });
    defer fixture.deinit(allocator);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen1,
        .size = 256 * mib,
    });
    defer report.deinit(allocator);

    try std.testing.expectEqual(Format.raw, report.output_format);
    try std.testing.expect(report.partition_style.?.ok);
    try std.testing.expectEqual(@as(usize, 1), report.planned_partitions.len);
    try std.testing.expectEqual(@as(u64, mib), report.planned_partitions[0].planned.offset_bytes);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    var sector0: [mbr.sector_size]u8 = undefined;
    _ = try img.pread(io, &sector0, 0);
    const parsed_mbr = try mbr.Mbr.decode(&sector0);
    try std.testing.expect(parsed_mbr.entries[0].bootable);
    try std.testing.expectEqual(mbr.PartitionType.linux, parsed_mbr.entries[0].partition_type);
    try std.testing.expectEqual(@as(u32, @intCast(report.planned_partitions[0].planned.firstLba())), parsed_mbr.entries[0].first_lba);
    try std.testing.expectEqual(@as(u32, @intCast(report.planned_partitions[0].planned.sizeSectors())), parsed_mbr.entries[0].sector_count);

    var expected_boot = try allocator.dupe(u8, fixture.bios_boot_img);
    defer allocator.free(expected_boot);
    std.mem.writeInt(u64, expected_boot[0x5C..][0..8], 1, .little);
    try std.testing.expectEqualSlices(u8, expected_boot[0..0x1B8], sector0[0..0x1B8]);

    var expected_mbr = mbr.singleLinuxPartitionMbr(
        @intCast(report.planned_partitions[0].planned.firstLba()),
        @intCast(report.planned_partitions[0].planned.sizeSectors()),
    );
    expected_mbr.disk_signature = report.planned_partitions[0].mbr_disk_signature.?;
    const expected_table_tail = expected_mbr.encode();
    try std.testing.expectEqualSlices(u8, expected_table_tail[0x1B8..], sector0[0x1B8..]);

    const core_sector_count = std.math.divCeil(usize, fixture.bios_core_img.len, mbr.sector_size) catch unreachable;
    const embedded_core = try allocator.alloc(u8, core_sector_count * mbr.sector_size);
    defer allocator.free(embedded_core);
    _ = try img.pread(io, embedded_core, mbr.sector_size);

    var expected_core = try allocator.alloc(u8, embedded_core.len);
    defer allocator.free(expected_core);
    @memset(expected_core, 0);
    std.mem.copyForwards(u8, expected_core[0..fixture.bios_core_img.len], fixture.bios_core_img);
    std.mem.writeInt(u64, expected_core[500..][0..8], 2, .little);
    std.mem.writeInt(u16, expected_core[508..][0..2], @intCast(core_sector_count - 1), .little);
    std.mem.writeInt(u16, expected_core[510..][0..2], 0x820, .little);
    try std.testing.expectEqualSlices(u8, expected_core, embedded_core);

    const root_partition = report.planned_partitions[0].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const grub_cfg = try root_reader.readFileAlloc(io, allocator, "boot/grub2/grub.cfg");
    defer allocator.free(grub_cfg);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "insmod part_msdos") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "search --no-floppy --fs-uuid --set=kernel_root ") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "linux ($kernel_root)/boot/vmlinuz-test root=PARTUUID=") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "initrd ($kernel_root)/boot/initramfs-test.img") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "boot/x86_64/loader/linux") == null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "root=live:CDLABEL=CDROM") == null);
}

test "build-image can append a dm-verity tree and pass metadata through COSI output" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-verity.iso";
    const oci_root = "test-build-image-verity-oci";
    const output_path = "test-build-image-verity.raw";
    const cosi_path = "test-build-image-verity.cosi";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, cosi_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
        .verity = true,
    });
    defer report.deinit(allocator);

    try std.testing.expect(report.verity != null);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    const esp_partition = report.planned_partitions[0].planned;
    var esp = try fat32.open(&img, io, .{ .offset = esp_partition.offset_bytes, .length = esp_partition.length_bytes });

    const bls_entry = try esp.readFileAlloc(io, allocator, "loader/entries/vmlinuz-test.conf");
    defer allocator.free(bls_entry);

    var root_hash_buf: [verity.digest_size * 2]u8 = undefined;
    const root_hash_text = report.verity.?.formatRootHash(&root_hash_buf);
    try std.testing.expect(std.mem.indexOf(u8, bls_entry, "root=/dev/mapper/root") != null);
    try std.testing.expect(std.mem.indexOf(u8, bls_entry, root_hash_text) != null);
    try std.testing.expect(std.mem.indexOf(u8, bls_entry, "systemd.verity_root_options=superblock=0,format=1") != null);

    _ = try cosi.writeWithOptions(img, io, allocator, cosi_path, .{
        .root_verity = report.verity,
    });

    const cosi_file = try Io.Dir.cwd().openFile(io, cosi_path, .{});
    defer cosi_file.close(io);
    const cosi_size = (try cosi_file.stat(io)).size;
    const cosi_bytes = try allocator.alloc(u8, cosi_size);
    defer allocator.free(cosi_bytes);
    _ = try cosi_file.readPositionalAll(io, cosi_bytes, 0);

    try std.testing.expect(std.mem.indexOf(u8, cosi_bytes, "\"roothash\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cosi_bytes, root_hash_text) != null);
    try std.testing.expect(std.mem.indexOf(u8, cosi_bytes, "\"hashAlgorithm\":\"sha256\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cosi_bytes, "\"hashOffset\":") != null);
}

test "build-image can append a dm-verity tree for Gen1 builds and synthesize an MBR PARTUUID cmdline" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-verity-gen1.iso";
    const oci_root = "test-build-image-verity-gen1-oci";
    const output_path = "test-build-image-verity-gen1.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen1,
        .size = 256 * mib,
        .verity = true,
    });
    defer report.deinit(allocator);

    try std.testing.expect(report.verity != null);
    try std.testing.expectEqual(@as(usize, 1), report.planned_partitions.len);
    try std.testing.expect(report.planned_partitions[0].mbr_disk_signature != null);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);

    var sector0: [mbr.sector_size]u8 = undefined;
    _ = try img.pread(io, &sector0, 0);
    const parsed_mbr = try mbr.Mbr.decode(&sector0);
    try std.testing.expectEqual(report.planned_partitions[0].mbr_disk_signature.?, parsed_mbr.disk_signature);

    var partuuid_buf: [mbr.partuuid_len]u8 = undefined;
    const root_partuuid_text = mbr.formatPartuuid(&partuuid_buf, parsed_mbr.disk_signature, 1);
    const kernel_options = try bootconfig.renderKernelOptions(allocator, root_partuuid_text, "", report.verity);
    defer allocator.free(kernel_options);

    var root_hash_buf: [verity.digest_size * 2]u8 = undefined;
    const root_hash_text = report.verity.?.formatRootHash(&root_hash_buf);
    try std.testing.expect(std.mem.indexOf(u8, kernel_options, "root=/dev/mapper/root ro") != null);
    try std.testing.expect(std.mem.indexOf(u8, kernel_options, root_hash_text) != null);
    try std.testing.expect(std.mem.indexOf(u8, kernel_options, "systemd.verity_root_data=PARTUUID=") != null);
    try std.testing.expect(std.mem.indexOf(u8, kernel_options, "systemd.verity_root_hash=PARTUUID=") != null);
    try std.testing.expect(std.mem.indexOf(u8, kernel_options, root_partuuid_text) != null);
}

test "build-image --verity fails fast when the initramfs lacks dm-verity tooling" {
    // Regression test for issue #77: a `--verity` build must not silently
    // produce an image that hangs at boot waiting on /dev/mapper/root just
    // because the source initramfs never had systemd-veritysetup-generator/
    // systemd-veritysetup/veritysetup in it. When the initramfs is a real,
    // fully-parseable cpio archive containing none of those tools, `build()`
    // should fail fast instead.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-verity-missing-tooling.iso";
    const oci_root = "test-build-image-verity-missing-tooling-oci";
    const output_path = "test-build-image-verity-missing-tooling.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    const initrd_bytes = try makeSyntheticInitramfsCpio(allocator, "usr/bin/bash");
    defer allocator.free(initrd_bytes);

    var fixture = try createBuildImageOciFixtureWithOptions(allocator, io, oci_root, .{
        .initrd_bytes = initrd_bytes,
    });
    defer fixture.deinit(allocator);

    try std.testing.expectError(error.InitramfsMissingVerityTooling, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
        .verity = true,
    }));
}

test "build-image --verity succeeds when the initramfs includes dm-verity tooling" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-verity-with-tooling.iso";
    const oci_root = "test-build-image-verity-with-tooling-oci";
    const output_path = "test-build-image-verity-with-tooling.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    const initrd_bytes = try makeSyntheticInitramfsCpio(allocator, "usr/lib/systemd/systemd-veritysetup-generator");
    defer allocator.free(initrd_bytes);

    var fixture = try createBuildImageOciFixtureWithOptions(allocator, io, oci_root, .{
        .initrd_bytes = initrd_bytes,
    });
    defer fixture.deinit(allocator);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
        .verity = true,
    });
    defer report.deinit(allocator);

    try std.testing.expect(report.verity != null);
}

test "build-image reports errors cleanly (no double-free) when squashfs open fails after partition planning" {
    // Regression test for a bug found via real-world testing against the real
    // Azure Linux 4.0 ISO (https://aka.ms/azurelinux-4.0-x86_64.iso), whose
    // embedded /LiveOS/squashfs.img uses XZ-compressed metadata blocks.
    // `build()` used to register an `errdefer allocator.free(planned_partitions)`
    // / `errdefer allocator.free(rootfs_path_in_iso)` *and* a later
    // `errdefer report.deinit(allocator)` that also frees the same two slices;
    // any error past that point (like squashfs.Reader.openFile returning
    // InvalidMetadataBlock for malformed compressed metadata) triggered all of
    // them during unwinding and
    // double-freed both allocations. `std.testing.allocator` below will fail
    // this test if that regresses.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-compressed.iso";
    const oci_root = "test-build-image-compressed-oci";
    const output_path = "test-build-image-compressed.vhd";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .none });
    defer allocator.free(squashfs_bytes);

    // Clear the inode table's metadata-block "uncompressed" bit and relabel
    // the filesystem as XZ-compressed so squashfs.Reader attempts to
    // decompress raw metadata bytes and fails after partition planning.
    std.mem.writeInt(u16, squashfs_bytes[20..22], @intFromEnum(squashfs.Compression.xz), .little);
    const inode_table_start = std.mem.readInt(u64, squashfs_bytes[64..72], .little);
    const header_offset: usize = @intCast(inode_table_start);
    var header = std.mem.readInt(u16, squashfs_bytes[header_offset..][0..2], .little);
    header &= ~squashfs.metadata_uncompressed_bit;
    std.mem.writeInt(u16, squashfs_bytes[header_offset..][0..2], header, .little);

    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    try std.testing.expectError(error.InvalidMetadataBlock, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .vhd,
        .generation = .gen2,
        .size = 256 * mib,
    }));
}

test "build-image reports MissingUkiStub for UKI mode without a stub" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-missing-uki-stub.iso";
    const oci_root = "test-build-image-missing-uki-stub-oci";
    const output_path = "test-build-image-missing-uki-stub.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    try std.testing.expectError(error.MissingUkiStub, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
        .boot_mode = .uki_only,
    }));
}

test "build-image wraps ESP NoSpaceLeft as EspTooSmallForBootArtifacts for UKI mode" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-uki-esp-too-small.iso";
    const oci_root = "test-build-image-uki-esp-too-small-oci";
    const output_path = "test-build-image-uki-esp-too-small.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    const stub_bytes = try makeTestStubPe(allocator, 0x8664);
    defer allocator.free(stub_bytes);

    const kernel_bytes = try allocator.alloc(u8, @intCast(20 * mib));
    defer allocator.free(kernel_bytes);
    @memset(kernel_bytes, 'K');

    const initrd_bytes = try allocator.alloc(u8, @intCast(20 * mib));
    defer allocator.free(initrd_bytes);
    @memset(initrd_bytes, 'I');

    var fixture = try createBuildImageOciFixtureWithOptions(allocator, io, oci_root, .{
        .kernel_bytes = kernel_bytes,
        .initrd_bytes = initrd_bytes,
        .uki_stub_path = "custom/linuxx64.efi.stub",
        .uki_stub_bytes = stub_bytes,
    });
    defer fixture.deinit(allocator);

    try std.testing.expectError(error.EspTooSmallForBootArtifacts, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 512 * mib,
        .esp_size = 64 * mib,
        .boot_mode = .uki_only,
        .uki = .{
            .stub_source_path = "custom/linuxx64.efi.stub",
        },
    }));
}

test "build-image installs and enables an azagent systemd unit when azagent is present in the source tree" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-azagent-unit.iso";
    const oci_root = "test-build-image-azagent-unit-oci";
    const output_path = "test-build-image-azagent-unit.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixtureWithOptions(allocator, io, oci_root, .{ .include_azagent = true });
    defer fixture.deinit(allocator);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
    });
    defer report.deinit(allocator);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);
    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    const azagent_bytes = try root_reader.readFileAlloc(io, allocator, azagent_binary_path);
    defer allocator.free(azagent_bytes);
    try std.testing.expectEqualStrings("azagent-binary-bytes", azagent_bytes);

    const unit = try root_reader.readFileAlloc(io, allocator, azagent_unit_path);
    defer allocator.free(unit);
    try std.testing.expectEqualStrings(azagent_unit_content, unit);
    try std.testing.expect(std.mem.indexOf(u8, unit, "ConditionPathExists") == null);

    const enabled_unit = try root_reader.readFileAlloc(io, allocator, azagent_unit_enable_path);
    defer allocator.free(enabled_unit);
    try std.testing.expectEqualStrings(azagent_unit_content, enabled_unit);
}

test "build-image does not install an azagent systemd unit when azagent is absent" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-no-azagent-unit.iso";
    const oci_root = "test-build-image-no-azagent-unit-oci";
    const output_path = "test-build-image-no-azagent-unit.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);

    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
    });
    defer report.deinit(allocator);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);
    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();

    try std.testing.expectError(error.NotFound, root_reader.readFileAlloc(io, allocator, azagent_unit_path));
}

test "build-image applies typed OS customization before generalization and ext4 population" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const iso_path = "test-build-image-customization.iso";
    const oci_root = "test-build-image-customization-oci";
    const output_path = "test-build-image-customization.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .xz });
    defer allocator.free(squashfs_bytes);
    try writeMinimalIsoWithFile(allocator, io, iso_path, "ROOT.SQUASHFS;1", squashfs_bytes);
    var fixture = try createBuildImageOciFixture(allocator, io, oci_root);
    defer fixture.deinit(allocator);

    const filesystem = [_]os_customization.FilesystemOperation{
        .{ .put_file = .{ .path = "/etc/passwd", .source = .{ .inline_bytes = "root:x:0:0::/root:/bin/bash\n" } } },
        .{ .put_file = .{ .path = "/etc/shadow", .source = .{ .inline_bytes = "root:!:19000:0:99999:7:::\n" }, .metadata = .{ .mode = 0o600 } } },
        .{ .put_file = .{ .path = "/etc/group", .source = .{ .inline_bytes = "root:x:0:\n" } } },
        .{ .put_file = .{ .path = "/etc/machine-id", .source = .{ .inline_bytes = "captured-machine-id\n" }, .metadata = .{ .mode = 0o444 } } },
        .{ .put_file = .{ .path = "/etc/ssh/ssh_host_rsa_key", .source = .{ .inline_bytes = "captured-host-key" }, .metadata = .{ .mode = 0o600 } } },
    };
    const users = [_]os_customization.User{.{
        .name = "alice",
        .uid = 1000,
        .ssh_authorized_keys = &.{"ssh-ed25519 AAAATEST alice@example"},
    }};
    const services = [_]os_customization.Service{.{ .name = "example.service", .state = .enabled }};
    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = 256 * mib,
        .os = .{
            .filesystem = &filesystem,
            .hostname = "custom-vm",
            .users = &users,
            .services = &services,
        },
        .generalization = .{ .azure = .{ .reset_hostname = false } },
    });
    defer report.deinit(allocator);
    try std.testing.expect(report.root_tree_digest != null);

    var img = try Image.openPath(io, output_path);
    defer img.close(io);
    const root_partition = report.planned_partitions[1].planned;
    const rootfs_scratch_path = try std.fmt.allocPrint(allocator, "{s}.test-rootfs.raw", .{output_path});
    defer allocator.free(rootfs_scratch_path);
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch_path) catch {};
    try extractImageRegionToPath(allocator, io, &img, root_partition.offset_bytes, root_partition.length_bytes, rootfs_scratch_path);

    const rootfs_scratch = try Io.Dir.cwd().openFile(io, rootfs_scratch_path, .{});
    defer rootfs_scratch.close(io);
    var root_reader = try ext4.open(io, rootfs_scratch, allocator, .{});
    defer root_reader.deinit();
    const hostname = try root_reader.readFileAlloc(io, allocator, "etc/hostname");
    defer allocator.free(hostname);
    try std.testing.expectEqualStrings("custom-vm\n", hostname);
    const authorized_keys = try root_reader.readFileAlloc(io, allocator, "home/alice/.ssh/authorized_keys");
    defer allocator.free(authorized_keys);
    try std.testing.expectEqualStrings("ssh-ed25519 AAAATEST alice@example\n", authorized_keys);
    const service_target = try root_reader.readLinkAlloc(
        io,
        allocator,
        "etc/systemd/system/multi-user.target.wants/example.service",
    );
    defer allocator.free(service_target);
    try std.testing.expectEqualStrings("/usr/lib/systemd/system/example.service", service_target);
    try std.testing.expectError(error.NotFound, root_reader.readFileAlloc(io, allocator, "etc/ssh/ssh_host_rsa_key"));
    const machine_id = try root_reader.readFileAlloc(io, allocator, "etc/machine-id");
    defer allocator.free(machine_id);
    try std.testing.expectEqual(@as(usize, 0), machine_id.len);
}

fn makeTestStubPe(allocator: std.mem.Allocator, machine: u16) ![]u8 {
    const file_alignment: u32 = 0x200;
    const section_alignment: u32 = 0x1000;
    const pe_offset: usize = 0x80;
    const optional_header_size: usize = 240;
    const section_count: usize = 1;
    const file_header_size = 20;
    const section_header_size = 40;
    const size_of_headers = std.mem.alignForward(
        u32,
        pe_offset + 4 + file_header_size + optional_header_size + section_count * section_header_size,
        file_alignment,
    );
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

const BuildImageOciFixtureBiosAssetLayout = enum {
    boot_grub2,
    usr_lib_grub,
};

const BuildImageOciFixtureOptions = struct {
    bios_asset_layout: BuildImageOciFixtureBiosAssetLayout = .boot_grub2,
    kernel_bytes: []const u8 = "kernel-from-oci",
    initrd_bytes: []const u8 = "initrd-from-oci",
    uki_stub_path: ?[]const u8 = null,
    uki_stub_bytes: []const u8 = "",
    /// If set, adds a `usr/sbin/azagent` entry to the container so tests
    /// can exercise `installAzagentSystemdUnitIfPresent`'s detection path.
    include_azagent: bool = false,
};

const BuildImageOciFixture = struct {
    bios_boot_img: []u8,
    bios_core_img: []u8,
    layer1_tar: []u8,
    layer2_tar: []u8,
    layer1_gzip: []u8,
    layer2_gzip: []u8,
    config_json: []u8,
    config_digest: []u8,
    layer1_digest: []u8,
    layer2_digest: []u8,
    manifest_json: []u8,
    manifest_digest: []u8,
    index_json: []u8,

    fn deinit(self: *BuildImageOciFixture, allocator: std.mem.Allocator) void {
        allocator.free(self.bios_boot_img);
        allocator.free(self.bios_core_img);
        allocator.free(self.layer1_tar);
        allocator.free(self.layer2_tar);
        allocator.free(self.layer1_gzip);
        allocator.free(self.layer2_gzip);
        allocator.free(self.config_json);
        allocator.free(self.config_digest);
        allocator.free(self.layer1_digest);
        allocator.free(self.layer2_digest);
        allocator.free(self.manifest_json);
        allocator.free(self.manifest_digest);
        allocator.free(self.index_json);
        self.* = undefined;
    }
};

fn createBuildImageOciFixture(
    allocator: std.mem.Allocator,
    io: Io,
    root: []const u8,
) !BuildImageOciFixture {
    return createBuildImageOciFixtureWithOptions(allocator, io, root, .{});
}

fn createBuildImageOciFixtureWithOptions(
    allocator: std.mem.Allocator,
    io: Io,
    root: []const u8,
    options: BuildImageOciFixtureOptions,
) !BuildImageOciFixture {
    try Io.Dir.cwd().createDirPath(io, root);
    var dir = try Io.Dir.cwd().openDir(io, root, .{});
    defer dir.close(io);
    try dir.createDirPath(io, "blobs/sha256");

    const bios_boot_img = try makeSyntheticBiosBootImg(allocator);
    errdefer allocator.free(bios_boot_img);
    const bios_core_img = try makeSyntheticBiosCoreImg(allocator);
    errdefer allocator.free(bios_core_img);
    std.debug.assert(options.uki_stub_path == null or options.uki_stub_bytes.len != 0);

    var layer1_specs = std.array_list.Managed(TarSpec).init(allocator);
    defer layer1_specs.deinit();
    try layer1_specs.appendSlice(&.{
        .{ .path = "boot/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "boot/vmlinuz-test", .mode = 0o644, .typeflag = '0', .content = options.kernel_bytes, .link_name = null },
        .{ .path = "boot/initramfs-test.img", .mode = 0o644, .typeflag = '0', .content = options.initrd_bytes, .link_name = null },
        .{ .path = "boot/grub2/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{
            .path = "boot/grub2/grub.cfg",
            .mode = 0o644,
            .typeflag = '0',
            .content = "set default=0\nlinux /boot/x86_64/loader/linux root=live:CDLABEL=CDROM rd.live.image\ninitrd /boot/x86_64/loader/initrd\n",
            .link_name = null,
        },
        .{ .path = "EFI/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/BOOT/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/BOOT/BOOTX64.EFI", .mode = 0o644, .typeflag = '0', .content = "bootx64-from-oci", .link_name = null },
        .{ .path = "EFI/Acme/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/Acme/grubx64.efi", .mode = 0o644, .typeflag = '0', .content = "grubx64-from-oci", .link_name = null },
        .{ .path = "app/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "app/hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from layer1\n", .link_name = null },
        .{ .path = "etc/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "etc/remove.txt", .mode = 0o644, .typeflag = '0', .content = "remove me\n", .link_name = null },
    });
    switch (options.bios_asset_layout) {
        .boot_grub2 => try layer1_specs.appendSlice(&.{
            .{ .path = "boot/grub2/i386-pc/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
            .{ .path = "boot/grub2/i386-pc/boot.img", .mode = 0o644, .typeflag = '0', .content = bios_boot_img, .link_name = null },
            .{ .path = "boot/grub2/i386-pc/core.img", .mode = 0o644, .typeflag = '0', .content = bios_core_img, .link_name = null },
        }),
        .usr_lib_grub => try layer1_specs.appendSlice(&.{
            .{ .path = "usr/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
            .{ .path = "usr/lib/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
            .{ .path = "usr/lib/grub/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
            .{ .path = "usr/lib/grub/i386-pc/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
            .{ .path = "usr/lib/grub/i386-pc/boot.img", .mode = 0o644, .typeflag = '0', .content = bios_boot_img, .link_name = null },
            .{ .path = "usr/lib/grub/i386-pc/core.img", .mode = 0o644, .typeflag = '0', .content = bios_core_img, .link_name = null },
        }),
    }
    if (options.uki_stub_path) |uki_stub_path| {
        try layer1_specs.append(.{
            .path = uki_stub_path,
            .mode = 0o644,
            .typeflag = '0',
            .content = options.uki_stub_bytes,
            .link_name = null,
        });
    }
    if (options.include_azagent) {
        try layer1_specs.appendSlice(&.{
            .{ .path = "usr/sbin/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
            .{ .path = "usr/sbin/azagent", .mode = 0o755, .typeflag = '0', .content = "azagent-binary-bytes", .link_name = null },
        });
    }
    const layer1_tar = try buildTarArchive(allocator, layer1_specs.items);
    const layer2_tar = try buildTarArchive(allocator, &.{
        .{ .path = "etc/.wh.remove.txt", .mode = 0o000, .typeflag = '0', .content = "", .link_name = null },
        .{ .path = "app/hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from layer2\n", .link_name = null },
        .{ .path = "usr/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "usr/bin/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "usr/bin/tool", .mode = 0o755, .typeflag = '0', .content = "#!/bin/sh\n", .link_name = null },
    });

    const layer1_gzip = try gzipBytes(allocator, layer1_tar);
    const layer2_gzip = try gzipBytes(allocator, layer2_tar);
    const config_json = try std.fmt.allocPrint(
        allocator,
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[]}}}}",
        .{},
    );
    const config_digest = try writeBlobAndDigest(allocator, io, dir, config_json);
    const layer1_digest = try writeBlobAndDigest(allocator, io, dir, layer1_gzip);
    const layer2_digest = try writeBlobAndDigest(allocator, io, dir, layer2_gzip);
    const manifest_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{s}\",\"size\":{d}}},{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ config_digest, config_json.len, layer1_digest, layer1_gzip.len, layer2_digest, layer2_gzip.len },
    );
    const manifest_digest = try writeBlobAndDigest(allocator, io, dir, manifest_json);
    const index_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ manifest_digest, manifest_json.len },
    );

    try dir.writeFile(io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}" });
    try dir.writeFile(io, .{ .sub_path = "index.json", .data = index_json });

    return .{
        .bios_boot_img = bios_boot_img,
        .bios_core_img = bios_core_img,
        .layer1_tar = layer1_tar,
        .layer2_tar = layer2_tar,
        .layer1_gzip = layer1_gzip,
        .layer2_gzip = layer2_gzip,
        .config_json = config_json,
        .config_digest = config_digest,
        .layer1_digest = layer1_digest,
        .layer2_digest = layer2_digest,
        .manifest_json = manifest_json,
        .manifest_digest = manifest_digest,
        .index_json = index_json,
    };
}

fn createEfiOnlyBuildImageOciLayout(
    allocator: std.mem.Allocator,
    io: Io,
    root: []const u8,
) !void {
    try Io.Dir.cwd().createDirPath(io, root);
    var dir = try Io.Dir.cwd().openDir(io, root, .{});
    defer dir.close(io);
    try dir.createDirPath(io, "blobs/sha256");

    const layer_tar = try buildTarArchive(allocator, &.{
        .{ .path = "EFI/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/BOOT/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/BOOT/BOOTX64.EFI", .mode = 0o644, .typeflag = '0', .content = "bootx64-from-oci", .link_name = null },
        .{ .path = "EFI/Acme/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/Acme/grubx64.efi", .mode = 0o644, .typeflag = '0', .content = "grubx64-from-oci", .link_name = null },
    });
    defer allocator.free(layer_tar);
    const layer_gzip = try gzipBytes(allocator, layer_tar);
    defer allocator.free(layer_gzip);

    const config_json = try std.fmt.allocPrint(
        allocator,
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[]}}}}",
        .{},
    );
    defer allocator.free(config_json);
    const config_digest = try writeBlobAndDigest(allocator, io, dir, config_json);
    defer allocator.free(config_digest);
    const layer_digest = try writeBlobAndDigest(allocator, io, dir, layer_gzip);
    defer allocator.free(layer_digest);
    const manifest_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ config_digest, config_json.len, layer_digest, layer_gzip.len },
    );
    defer allocator.free(manifest_json);
    const manifest_digest = try writeBlobAndDigest(allocator, io, dir, manifest_json);
    defer allocator.free(manifest_digest);
    const index_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ manifest_digest, manifest_json.len },
    );
    defer allocator.free(index_json);

    try dir.writeFile(io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}" });
    try dir.writeFile(io, .{ .sub_path = "index.json", .data = index_json });
}

fn createContainerRootfsOnlyBuildImageOciLayout(
    allocator: std.mem.Allocator,
    io: Io,
    root: []const u8,
) !void {
    try Io.Dir.cwd().createDirPath(io, root);
    var dir = try Io.Dir.cwd().openDir(io, root, .{});
    defer dir.close(io);
    try dir.createDirPath(io, "blobs/sha256");

    const capability = try buildPaxRecord(allocator, "SCHILY.xattr.security.capability", "chronyd-capability");
    defer allocator.free(capability);
    const layer_tar = try buildTarArchive(allocator, &.{
        .{ .path = "app/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "app/hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from minimal container rootfs\n", .link_name = null },
        .{ .path = "usr/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "usr/bin/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "PaxHeaders/chronyd", .mode = 0o644, .typeflag = 'x', .content = capability, .link_name = null },
        .{ .path = "usr/bin/chronyd", .mode = 0o755, .uid = 991, .gid = 991, .typeflag = '0', .content = "chronyd", .link_name = null },
        .{ .path = "EFI/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/BOOT/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/BOOT/BOOTX64.EFI", .mode = 0o644, .typeflag = '0', .content = "bootx64-from-oci", .link_name = null },
        .{ .path = "EFI/Acme/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "EFI/Acme/grubx64.efi", .mode = 0o644, .typeflag = '0', .content = "grubx64-from-oci", .link_name = null },
    });
    defer allocator.free(layer_tar);
    const layer_gzip = try gzipBytes(allocator, layer_tar);
    defer allocator.free(layer_gzip);

    const config_json = try std.fmt.allocPrint(
        allocator,
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[]}}}}",
        .{},
    );
    defer allocator.free(config_json);
    const config_digest = try writeBlobAndDigest(allocator, io, dir, config_json);
    defer allocator.free(config_digest);
    const layer_digest = try writeBlobAndDigest(allocator, io, dir, layer_gzip);
    defer allocator.free(layer_digest);
    const manifest_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ config_digest, config_json.len, layer_digest, layer_gzip.len },
    );
    defer allocator.free(manifest_json);
    const manifest_digest = try writeBlobAndDigest(allocator, io, dir, manifest_json);
    defer allocator.free(manifest_digest);
    const index_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ manifest_digest, manifest_json.len },
    );
    defer allocator.free(index_json);

    try dir.writeFile(io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}" });
    try dir.writeFile(io, .{ .sub_path = "index.json", .data = index_json });
}

const TarSpec = struct {
    path: []const u8,
    mode: u32,
    uid: u32 = 0,
    gid: u32 = 0,
    typeflag: u8,
    content: []const u8,
    link_name: ?[]const u8,
};

fn buildTarArchive(allocator: std.mem.Allocator, specs: []const TarSpec) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, 4096);
    errdefer out.deinit();

    for (specs) |spec| try appendTarSpec(&out, spec);
    try out.writer.splatByteAll(0, 1024);
    return out.toOwnedSlice();
}

fn appendTarSpec(out: *std.Io.Writer.Allocating, spec: TarSpec) !void {
    var header: [512]u8 = [_]u8{0} ** 512;
    if (spec.path.len > 100) return error.InvalidHeader;
    @memcpy(header[0..spec.path.len], spec.path);
    try writeOctalField(header[100..108], spec.mode);
    try writeOctalField(header[108..116], spec.uid);
    try writeOctalField(header[116..124], spec.gid);
    try writeOctalField(header[124..136], spec.content.len);
    try writeOctalField(header[136..148], 0);
    @memset(header[148..156], ' ');
    header[156] = spec.typeflag;
    if (spec.link_name) |link_name| {
        if (link_name.len > 100) return error.InvalidHeader;
        @memcpy(header[157..][0..link_name.len], link_name);
    }
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");

    var checksum: u32 = 0;
    for (header) |byte| checksum += byte;
    try writeChecksumField(header[148..156], checksum);

    try out.writer.writeAll(&header);
    try out.writer.writeAll(spec.content);
    const padding = std.mem.alignForward(usize, spec.content.len, 512) - spec.content.len;
    if (padding > 0) try out.writer.splatByteAll(0, padding);
}

fn buildPaxRecord(allocator: std.mem.Allocator, key: []const u8, value: []const u8) ![]u8 {
    var record_len: usize = 0;
    while (true) {
        const record = try std.fmt.allocPrint(allocator, "{d} {s}={s}\n", .{ record_len, key, value });
        if (record.len == record_len) return record;
        record_len = record.len;
        allocator.free(record);
    }
}

fn gzipBytes(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), data.len));
    errdefer out.deinit();

    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&out.writer, &history, .gzip, .default);
    try compressor.writer.writeAll(data);
    try compressor.finish();
    return out.toOwnedSlice();
}

fn writeBlobAndDigest(allocator: std.mem.Allocator, io: Io, dir: Io.Dir, data: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const digest_string = try std.fmt.allocPrint(allocator, "sha256:{s}", .{hex});
    const blob_path = try std.fmt.allocPrint(allocator, "blobs/sha256/{s}", .{hex});
    defer allocator.free(blob_path);
    try dir.writeFile(io, .{ .sub_path = blob_path, .data = data });
    return digest_string;
}

fn writeOctalField(field: []u8, value: u64) !void {
    if (field.len == 0) return;
    @memset(field, 0);
    var buf: [32]u8 = undefined;
    const octal = try std.fmt.bufPrint(&buf, "{o}", .{value});
    if (octal.len + 1 > field.len) return error.InvalidHeader;
    const digits = field.len - 1;
    @memset(field[0..digits], '0');
    const start = digits - octal.len;
    @memcpy(field[start .. start + octal.len], octal);
}

fn writeChecksumField(field: []u8, value: u32) !void {
    @memset(field, ' ');
    var buf: [16]u8 = undefined;
    const octal = try std.fmt.bufPrint(&buf, "{o}", .{value});
    if (octal.len + 2 > field.len) return error.InvalidHeader;
    const start = field.len - octal.len - 2;
    @memcpy(field[start .. start + octal.len], octal);
    field[field.len - 2] = 0;
    field[field.len - 1] = ' ';
}

fn makeSyntheticBiosBootImg(allocator: std.mem.Allocator) ![]u8 {
    const bytes = try allocator.alloc(u8, mbr.sector_size);
    for (bytes, 0..) |*byte, index| byte.* = @intCast((index * 17 + 11) % 251);
    return bytes;
}

fn makeSyntheticBiosCoreImg(allocator: std.mem.Allocator) ![]u8 {
    const bytes = try allocator.alloc(u8, 900);
    for (bytes, 0..) |*byte, index| byte.* = @intCast((index * 29 + 7) % 253);
    return bytes;
}

/// Builds a minimal newc-format cpio archive (see `cpio.zig`) containing a
/// single entry followed by a `TRAILER!!!`, for exercising
/// `initramfs.checkVerityTooling` end-to-end through `build()`'s
/// `--verity` initramfs check (see issue #77).
fn makeSyntheticInitramfsCpio(allocator: std.mem.Allocator, entry_path: []const u8) ![]u8 {
    var list = std.array_list.Managed(u8).init(allocator);
    errdefer list.deinit();
    try appendCpioTestEntry(&list, entry_path, "elf-bytes");
    try appendCpioTestEntry(&list, "TRAILER!!!", "");
    return list.toOwnedSlice();
}

fn appendCpioTestEntry(list: *std.array_list.Managed(u8), name: []const u8, content: []const u8) !void {
    var header: [110]u8 = undefined;
    _ = try std.fmt.bufPrint(&header, "070701{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}", .{
        0, @as(u32, 0o100644), 0, 0, 1, 0, content.len, 0, 0, 0, 0, name.len + 1, 0,
    });
    try list.appendSlice(&header);
    try list.appendSlice(name);
    try list.append(0);
    while (list.items.len % 4 != 0) try list.append(0);
    try list.appendSlice(content);
    while (list.items.len % 4 != 0) try list.append(0);
}

fn appendU16Le(list: *std.array_list.Managed(u8), value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn appendU32Le(list: *std.array_list.Managed(u8), value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn appendU64Le(list: *std.array_list.Managed(u8), value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn writeMinimalIsoWithFile(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    iso_file_name: []const u8,
    bytes: []const u8,
) !void {
    const root_lba: u32 = 20;
    const file_lba: u32 = 21;

    var image = std.array_list.Managed(u8).init(allocator);
    defer image.deinit();
    try image.resize((file_lba + @as(u32, @intCast(std.math.divCeil(u64, bytes.len, iso9660.descriptor_size) catch unreachable))) * iso9660.descriptor_size);
    @memset(image.items, 0);

    var pvd: [iso9660.descriptor_size]u8 = [_]u8{0} ** iso9660.descriptor_size;
    pvd[0] = 1;
    pvd[1..6].* = iso9660.standard_id;
    pvd[6] = 1;
    write733(pvd[80..88], @intCast(image.items.len / iso9660.descriptor_size));
    write723(pvd[128..132], iso9660.descriptor_size);
    write733(pvd[132..140], 0);
    std.mem.writeInt(u32, pvd[140..144], 19, .little);
    const root_record = makeDirectoryRecord(&.{0}, root_lba, iso9660.descriptor_size, 0x02, &.{});
    @memcpy(pvd[156 .. 156 + root_record[0]], root_record[0..root_record[0]]);
    image.items[iso9660.volume_descriptor_lba * iso9660.descriptor_size .. (iso9660.volume_descriptor_lba + 1) * iso9660.descriptor_size].* = pvd;

    var terminator: [iso9660.descriptor_size]u8 = [_]u8{0} ** iso9660.descriptor_size;
    terminator[0] = 255;
    terminator[1..6].* = iso9660.standard_id;
    terminator[6] = 1;
    image.items[(iso9660.volume_descriptor_lba + 1) * iso9660.descriptor_size .. (iso9660.volume_descriptor_lba + 2) * iso9660.descriptor_size].* = terminator;

    var path_table = std.array_list.Managed(u8).init(allocator);
    defer path_table.deinit();
    try path_table.append(1);
    try path_table.append(0);
    try appendU32Le(&path_table, root_lba);
    try appendU16Le(&path_table, 1);
    try path_table.append(0);
    try path_table.append(0);
    write733(image.items[16 * iso9660.descriptor_size + 132 .. 16 * iso9660.descriptor_size + 140], @intCast(path_table.items.len));
    @memcpy(image.items[19 * iso9660.descriptor_size ..][0..path_table.items.len], path_table.items);

    var root_dir = std.array_list.Managed(u8).init(allocator);
    defer root_dir.deinit();
    const dot = makeDirectoryRecord(&.{0}, root_lba, iso9660.descriptor_size, 0x02, &.{});
    try root_dir.appendSlice(dot[0..dot[0]]);
    const dotdot = makeDirectoryRecord(&.{1}, root_lba, iso9660.descriptor_size, 0x02, &.{});
    try root_dir.appendSlice(dotdot[0..dotdot[0]]);
    const file_record = makeDirectoryRecord(iso_file_name, file_lba, bytes.len, 0, &.{});
    try root_dir.appendSlice(file_record[0..file_record[0]]);
    @memcpy(image.items[root_lba * iso9660.descriptor_size ..][0..root_dir.items.len], root_dir.items);

    @memcpy(image.items[file_lba * iso9660.descriptor_size ..][0..bytes.len], bytes);

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, image.items, 0);
}

fn writeMinimalIsoWithBootPayloads(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    rootfs_name: []const u8,
    rootfs_bytes: []const u8,
    kernel_name: []const u8,
    kernel_bytes: []const u8,
    initrd_name: []const u8,
    initrd_bytes: []const u8,
) !void {
    const root_lba: u32 = 20;
    const boot_dir_lba: u32 = 21;
    const rootfs_lba: u32 = 22;
    const rootfs_blocks: u32 = @intCast(std.math.divCeil(u64, rootfs_bytes.len, iso9660.descriptor_size) catch unreachable);
    const kernel_lba = rootfs_lba + rootfs_blocks;
    const kernel_blocks: u32 = @intCast(std.math.divCeil(u64, kernel_bytes.len, iso9660.descriptor_size) catch unreachable);
    const initrd_lba = kernel_lba + kernel_blocks;
    const initrd_blocks: u32 = @intCast(std.math.divCeil(u64, initrd_bytes.len, iso9660.descriptor_size) catch unreachable);
    const image_blocks = initrd_lba + initrd_blocks;

    var image = std.array_list.Managed(u8).init(allocator);
    defer image.deinit();
    try image.resize(image_blocks * iso9660.descriptor_size);
    @memset(image.items, 0);

    var pvd: [iso9660.descriptor_size]u8 = [_]u8{0} ** iso9660.descriptor_size;
    pvd[0] = 1;
    pvd[1..6].* = iso9660.standard_id;
    pvd[6] = 1;
    write733(pvd[80..88], @intCast(image.items.len / iso9660.descriptor_size));
    write723(pvd[128..132], iso9660.descriptor_size);
    write733(pvd[132..140], 0);
    std.mem.writeInt(u32, pvd[140..144], 19, .little);
    const root_record = makeDirectoryRecord(&.{0}, root_lba, iso9660.descriptor_size, 0x02, &.{});
    @memcpy(pvd[156 .. 156 + root_record[0]], root_record[0..root_record[0]]);
    image.items[iso9660.volume_descriptor_lba * iso9660.descriptor_size .. (iso9660.volume_descriptor_lba + 1) * iso9660.descriptor_size].* = pvd;

    var terminator: [iso9660.descriptor_size]u8 = [_]u8{0} ** iso9660.descriptor_size;
    terminator[0] = 255;
    terminator[1..6].* = iso9660.standard_id;
    terminator[6] = 1;
    image.items[(iso9660.volume_descriptor_lba + 1) * iso9660.descriptor_size .. (iso9660.volume_descriptor_lba + 2) * iso9660.descriptor_size].* = terminator;

    var path_table = std.array_list.Managed(u8).init(allocator);
    defer path_table.deinit();
    try path_table.append(1);
    try path_table.append(0);
    try appendU32Le(&path_table, root_lba);
    try appendU16Le(&path_table, 1);
    try path_table.append(0);
    try path_table.append(0);
    try path_table.append(bootPathSegment.len);
    try path_table.append(0);
    try appendU32Le(&path_table, boot_dir_lba);
    try appendU16Le(&path_table, 1);
    try path_table.appendSlice(bootPathSegment);
    if (bootPathSegment.len % 2 != 0) try path_table.append(0);
    write733(image.items[16 * iso9660.descriptor_size + 132 .. 16 * iso9660.descriptor_size + 140], @intCast(path_table.items.len));
    @memcpy(image.items[19 * iso9660.descriptor_size ..][0..path_table.items.len], path_table.items);

    var root_dir = std.array_list.Managed(u8).init(allocator);
    defer root_dir.deinit();
    const dot = makeDirectoryRecord(&.{0}, root_lba, iso9660.descriptor_size, 0x02, &.{});
    try root_dir.appendSlice(dot[0..dot[0]]);
    const dotdot = makeDirectoryRecord(&.{1}, root_lba, iso9660.descriptor_size, 0x02, &.{});
    try root_dir.appendSlice(dotdot[0..dotdot[0]]);
    const rootfs_record = makeDirectoryRecord(rootfs_name, rootfs_lba, rootfs_bytes.len, 0, &.{});
    try root_dir.appendSlice(rootfs_record[0..rootfs_record[0]]);
    const boot_record = makeDirectoryRecord(bootPathSegment, boot_dir_lba, iso9660.descriptor_size, 0x02, &.{});
    try root_dir.appendSlice(boot_record[0..boot_record[0]]);
    @memcpy(image.items[root_lba * iso9660.descriptor_size ..][0..root_dir.items.len], root_dir.items);

    var boot_dir = std.array_list.Managed(u8).init(allocator);
    defer boot_dir.deinit();
    const boot_dot = makeDirectoryRecord(&.{0}, boot_dir_lba, iso9660.descriptor_size, 0x02, &.{});
    try boot_dir.appendSlice(boot_dot[0..boot_dot[0]]);
    const boot_dotdot = makeDirectoryRecord(&.{1}, root_lba, iso9660.descriptor_size, 0x02, &.{});
    try boot_dir.appendSlice(boot_dotdot[0..boot_dotdot[0]]);
    const kernel_record = makeDirectoryRecord(kernel_name, kernel_lba, kernel_bytes.len, 0, &.{});
    try boot_dir.appendSlice(kernel_record[0..kernel_record[0]]);
    const initrd_record = makeDirectoryRecord(initrd_name, initrd_lba, initrd_bytes.len, 0, &.{});
    try boot_dir.appendSlice(initrd_record[0..initrd_record[0]]);
    @memcpy(image.items[boot_dir_lba * iso9660.descriptor_size ..][0..boot_dir.items.len], boot_dir.items);

    @memcpy(image.items[rootfs_lba * iso9660.descriptor_size ..][0..rootfs_bytes.len], rootfs_bytes);
    @memcpy(image.items[kernel_lba * iso9660.descriptor_size ..][0..kernel_bytes.len], kernel_bytes);
    @memcpy(image.items[initrd_lba * iso9660.descriptor_size ..][0..initrd_bytes.len], initrd_bytes);

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, image.items, 0);
}

const bootPathSegment = "boot";

fn makeDirectoryRecord(
    file_identifier: []const u8,
    extent_lba: u32,
    data_length: usize,
    flags: u8,
    system_use: []const u8,
) [256]u8 {
    var record: [256]u8 = [_]u8{0} ** 256;
    const identifier_len = file_identifier.len;
    const padding: usize = if (identifier_len % 2 == 0) 1 else 0;
    const record_len = 33 + identifier_len + padding + system_use.len;
    record[0] = @intCast(record_len);
    record[1] = 0;
    write733(record[2..10], extent_lba);
    write733(record[10..18], @intCast(data_length));
    record[25] = flags;
    record[28] = 1;
    record[29] = 0;
    record[30] = 1;
    record[31] = 0;
    record[32] = @intCast(identifier_len);
    @memcpy(record[33 .. 33 + identifier_len], file_identifier);
    if (padding == 1) record[33 + identifier_len] = 0;
    @memcpy(record[33 + identifier_len + padding .. 33 + identifier_len + padding + system_use.len], system_use);
    return record;
}

fn write723(bytes: []u8, value: u16) void {
    std.mem.writeInt(u16, bytes[0..2], value, .little);
    std.mem.writeInt(u16, bytes[2..4], value, .big);
}

fn write733(bytes: []u8, value: u32) void {
    std.mem.writeInt(u32, bytes[0..4], value, .little);
    std.mem.writeInt(u32, bytes[4..8], value, .big);
}
