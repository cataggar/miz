//! `vmiz write --allow-device-write [--yes] [--grow-root] [--new-uuids] [--allow-duplicate-identifiers] <source> <block-device>`

const std = @import("std");
const builtin = @import("builtin");
const vmiz = @import("vmiz");

const help_text =
    \\usage: vmiz write --allow-device-write [--yes] [--grow-root] [--new-uuids] [--allow-duplicate-identifiers] <source> <block-device>
    \\
    \\Writes a raw, VHD, VHDX, or qcow2 image directly to an existing Linux
    \\block device. The source format is detected automatically.
    \\
    \\  --allow-device-write  Required acknowledgement that the destination
    \\                        device will be overwritten.
    \\  --yes                 Skip the final interactive confirmation.
    \\  --grow-root           Offline-grow the single supported GPT ext4 root
    \\                        in a raw source to fill the destination.
    \\  --new-uuids           Generate fresh GPT/FAT/ext4/XFS identifiers and
    \\                        rewrite supported boot references before publish.
    \\  --allow-duplicate-identifiers
    \\                        Allow collisions with identifiers already visible
    \\                        on other disks. --yes does not bypass this check.
    \\
    \\The command checks the target while it is read-only, refuses a target
    \\that is too small or in use, writes zero regions explicitly, flushes the
    \\device, and asks the kernel to re-read its partition table. A stale
    \\kernel partition view is reported as partial success with exit status 2.
    \\By default it also refuses duplicate visible GPT or filesystem
    \\identifiers before confirmation or mutation.
    \\Root growth is native and offline; it does not require resize2fs or
    \\cloud-init in the guest. Fresh-identity rewrites are strict:
    \\unsupported filesystems, stale boot references, and immutable/signed
    \\artifacts are refused before any destination bytes change.
    \\The separate `vmiz convert` command remains unable to write devices.
    \\
;

const RootGrowthPlan = struct {
    root: vmiz.root_resize.RootSelection,
    final_last_lba: u64,
    final_partition_length: u64,
    final_filesystem_length: u64,
    grow_partition: bool,
    grow_filesystem: bool,
};

const WriteIdentityOptions = struct {
    new_uuids: bool = false,
    allow_duplicate_identifiers: bool = false,
};

const PreparedIdentity = struct {
    context: ?*anyopaque = null,
    report_text: []u8 = &.{},
    refusal_message: ?[]u8 = null,
    collision_count: usize = 0,
    apply_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
        std.Io,
        *vmiz.Image,
    ) anyerror!void = preparedIdentityApplyNoop,
    deinit_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
    ) void = preparedIdentityDeinitNoop,
};

const Operations = struct {
    context: ?*anyopaque = null,
    open_destination_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
        std.Io,
        []const u8,
        u64,
        bool,
    ) anyerror!vmiz.Image = openDestination,
    preflight_report_fn: *const fn (
        ?*anyopaque,
        *const vmiz.Image,
    ) ?*const vmiz.DevicePreflightReport = preflightReport,
    prepare_identity_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
        std.Io,
        *const vmiz.Image,
        *const vmiz.DevicePreflightReport,
        vmiz.gpt.DetectedGpt,
        ?RootGrowthPlan,
        WriteIdentityOptions,
    ) anyerror!PreparedIdentity = prepareIdentity,
    confirm_fn: *const fn (
        ?*anyopaque,
        std.Io,
        []const u8,
    ) anyerror!bool = confirm,
    detect_gpt_fn: *const fn (
        ?*anyopaque,
        vmiz.Image,
        std.Io,
        std.mem.Allocator,
    ) anyerror!vmiz.gpt.DetectedGpt = detectGpt,
    invalidate_fn: *const fn (
        ?*anyopaque,
        *vmiz.Image,
        std.Io,
    ) anyerror!void = invalidateDestination,
    copy_fn: *const fn (
        ?*anyopaque,
        std.Io,
        vmiz.Image,
        *vmiz.Image,
        std.mem.Allocator,
    ) anyerror!void = copyBytes,
    relocate_fn: *const fn (
        ?*anyopaque,
        *vmiz.Image,
        std.Io,
        std.mem.Allocator,
        vmiz.gpt.VerifiedGpt,
    ) anyerror!vmiz.gpt.RelocationResult = relocateBackup,
    plan_root_growth_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
        std.Io,
        *const vmiz.Image,
        u64,
        vmiz.gpt.VerifiedGpt,
    ) anyerror!RootGrowthPlan = planRootGrowth,
    grow_partition_fn: *const fn (
        ?*anyopaque,
        *vmiz.Image,
        std.Io,
        std.mem.Allocator,
        vmiz.gpt.VerifiedGpt,
        u32,
    ) anyerror!vmiz.gpt.GrowPartitionResult = growPartition,
    resize_ext4_fn: *const fn (
        ?*anyopaque,
        std.Io,
        std.Io.File,
        std.mem.Allocator,
        vmiz.ext4.ResizeOptions,
    ) anyerror!vmiz.ext4.FilesystemInfo = resizeExt4,
    verify_fn: *const fn (
        ?*anyopaque,
        vmiz.Image,
        std.Io,
        std.mem.Allocator,
    ) anyerror!vmiz.gpt.VerifiedGpt = verifyGpt,
    verify_root_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
        std.Io,
        *const vmiz.Image,
        vmiz.gpt.VerifiedGpt,
    ) anyerror!vmiz.root_resize.RootSelection = verifyRoot,
    durable_fn: *const fn (
        ?*anyopaque,
        *vmiz.Image,
        std.Io,
    ) anyerror!bool = makeDurable,
    finish_fn: *const fn (
        ?*anyopaque,
        *vmiz.Image,
        std.Io,
    ) anyerror!?vmiz.DeviceWriteOutcome = finishDeviceWrite,
};

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    return runWithOperations(gpa, io, args, .{});
}

fn runWithOperations(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    operations: Operations,
) u8 {
    var allow_device_write = false;
    var yes = false;
    var grow_root = false;
    var new_uuids = false;
    var allow_duplicate_identifiers = false;
    var positional: [2][]const u8 = undefined;
    var positional_count: usize = 0;

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--allow-device-write")) {
            allow_device_write = true;
        } else if (std.mem.eql(u8, arg, "--yes")) {
            yes = true;
        } else if (std.mem.eql(u8, arg, "--grow-root")) {
            grow_root = true;
        } else if (std.mem.eql(u8, arg, "--new-uuids")) {
            new_uuids = true;
        } else if (std.mem.eql(u8, arg, "--allow-duplicate-identifiers")) {
            allow_duplicate_identifiers = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("{s}", .{help_text});
            return 0;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return fail("write: unknown option '{s}'\n\n{s}", .{ arg, help_text });
        } else if (positional_count < positional.len) {
            positional[positional_count] = arg;
            positional_count += 1;
        } else {
            return fail("write: unexpected argument '{s}'\n\n{s}", .{ arg, help_text });
        }
    }

    if (positional_count != positional.len) return fail("{s}", .{help_text});
    if (!allow_device_write) {
        return fail(
            "write: refusing to open a device for writing without --allow-device-write",
            .{},
        );
    }
    if (builtin.os.tag != .linux) {
        return fail("write: direct block-device writes are supported only on Linux", .{});
    }

    const source_path = positional[0];
    const destination_path = positional[1];
    var source = vmiz.Image.openPathReadOnly(io, source_path) catch |err| {
        return fail("write: failed to open source '{s}': {s}", .{ source_path, @errorName(err) });
    };
    defer source.close(io);

    var destination = operations.open_destination_fn(
        operations.context,
        gpa,
        io,
        destination_path,
        source.virtual_size,
        allow_device_write,
    ) catch |err| {
        if (describeWriteFailure(err)) |message| {
            return fail("write: refused destination '{s}': {s}", .{ destination_path, message });
        }
        return fail(
            "write: failed to open destination '{s}': {s}",
            .{ destination_path, @errorName(err) },
        );
    };
    defer destination.close(io);

    const report = operations.preflight_report_fn(
        operations.context,
        &destination,
    ) orelse return fail(
        "write: destination preflight report is unavailable; no data was written",
        .{},
    );
    const report_text = formatPreflightReport(gpa, destination_path, report) catch |err| {
        return fail(
            "write: failed to format destination preflight: {s}; no data was written",
            .{@errorName(err)},
        );
    };
    defer gpa.free(report_text);
    std.debug.print("{s}", .{report_text});

    var detected = operations.detect_gpt_fn(
        operations.context,
        source,
        io,
        gpa,
    ) catch |err| {
        return fail(
            "write: source GPT validation failed: {s}; no data was written",
            .{@errorName(err)},
        );
    };
    defer detected.deinit(gpa);

    var growth_plan: ?RootGrowthPlan = null;
    if (grow_root) {
        const verified = switch (detected) {
            .not_gpt => return fail(
                "write: --grow-root requires a verified GPT source; no data was written",
                .{},
            ),
            .verified => |verified| verified,
        };
        growth_plan = operations.plan_root_growth_fn(
            operations.context,
            gpa,
            io,
            &source,
            destination.virtual_size,
            verified,
        ) catch |err| {
            return fail(
                "write: root growth preflight failed: {s}; no data was written",
                .{@errorName(err)},
            );
        };
        const plan = growth_plan.?;
        std.debug.print(
            "write: root GPT table index {d}, partition LBA {d} -> {d}, filesystem {d} -> {d} bytes\n",
            .{
                plan.root.table_index,
                plan.root.last_lba,
                plan.final_last_lba,
                plan.root.filesystem_length,
                plan.final_filesystem_length,
            },
        );
    }

    const prepared_identity = operations.prepare_identity_fn(
        operations.context,
        gpa,
        io,
        &source,
        report,
        detected,
        growth_plan,
        .{
            .new_uuids = new_uuids,
            .allow_duplicate_identifiers = allow_duplicate_identifiers,
        },
    ) catch |err| {
        return fail(
            "write: source identity inspection failed: {s}; no data was written",
            .{@errorName(err)},
        );
    };
    defer prepared_identity.deinit_fn(prepared_identity.context, gpa);
    defer gpa.free(prepared_identity.report_text);
    if (prepared_identity.refusal_message) |message| {
        defer gpa.free(message);
        if (prepared_identity.report_text.len != 0) std.debug.print("{s}", .{prepared_identity.report_text});
        return fail("write: {s}; no data was written", .{message});
    }
    if (prepared_identity.report_text.len != 0) std.debug.print("{s}", .{prepared_identity.report_text});
    if (prepared_identity.collision_count != 0 and !allow_duplicate_identifiers) {
        return fail(
            "write: refusing duplicate identifiers without --allow-duplicate-identifiers; no data was written",
            .{},
        );
    }

    if (!yes) {
        const approved = operations.confirm_fn(
            operations.context,
            io,
            destination_path,
        ) catch |err| {
            return fail("write: confirmation failed: {s}; no data was written", .{@errorName(err)});
        };
        if (!approved) return fail("write: cancelled; no data was written", .{});
    }

    operations.invalidate_fn(
        operations.context,
        &destination,
        io,
    ) catch |err| {
        return failAfterMutation(
            operations,
            &destination,
            io,
            "write: failed to invalidate stale destination partition metadata: {s}; the device may be partially modified",
            .{@errorName(err)},
        );
    };

    std.debug.print(
        "write: writing {d} bytes from '{s}' to '{s}'\n",
        .{ source.virtual_size, source_path, destination_path },
    );
    operations.copy_fn(
        operations.context,
        io,
        source,
        &destination,
        gpa,
    ) catch |err| {
        return failAfterMutation(
            operations,
            &destination,
            io,
            "write: data copy failed: {s}; the device may be partially written",
            .{@errorName(err)},
        );
    };

    switch (detected) {
        .not_gpt => {},
        .verified => |verified| {
            const plan = growth_plan;
            var grow_result: ?vmiz.gpt.GrowPartitionResult = null;
            const relocation = if (plan) |root_plan| blk: {
                if (root_plan.grow_partition) {
                    grow_result = operations.grow_partition_fn(
                        operations.context,
                        &destination,
                        io,
                        gpa,
                        verified,
                        root_plan.root.table_index,
                    ) catch |err| {
                        return failAfterMutation(
                            operations,
                            &destination,
                            io,
                            "write: root partition growth failed: {s}; the device was modified",
                            .{@errorName(err)},
                        );
                    };
                    break :blk grow_result.?.relocation;
                }
                break :blk operations.relocate_fn(
                    operations.context,
                    &destination,
                    io,
                    gpa,
                    verified,
                ) catch |err| {
                    return failAfterMutation(
                        operations,
                        &destination,
                        io,
                        "write: backup GPT relocation failed: {s}; the device was modified",
                        .{@errorName(err)},
                    );
                };
            } else operations.relocate_fn(
                operations.context,
                &destination,
                io,
                gpa,
                verified,
            ) catch |err| {
                return failAfterMutation(
                    operations,
                    &destination,
                    io,
                    "write: backup GPT relocation failed: {s}; the device was modified",
                    .{@errorName(err)},
                );
            };
            std.debug.print(
                "write: backup GPT LBA {d} -> {d}{s}\n",
                .{
                    relocation.old_backup_lba,
                    relocation.new_backup_lba,
                    if (relocation.was_relocated) "" else " (already at destination end)",
                },
            );

            if (plan) |root_plan| {
                if (root_plan.grow_filesystem) {
                    _ = operations.resize_ext4_fn(
                        operations.context,
                        io,
                        destination.file,
                        gpa,
                        .{
                            .offset = root_plan.root.byte_offset,
                            .length = root_plan.final_filesystem_length,
                        },
                    ) catch |err| {
                        return failAfterMutation(
                            operations,
                            &destination,
                            io,
                            "write: offline ext4 root resize failed: {s}; the device was modified",
                            .{@errorName(err)},
                        );
                    };
                } else {
                    std.debug.print("write: root filesystem already fills its final block-aligned extent\n", .{});
                }
            }

            var destination_gpt = operations.verify_fn(
                operations.context,
                destination,
                io,
                gpa,
            ) catch |err| {
                return failAfterMutation(
                    operations,
                    &destination,
                    io,
                    "write: destination GPT verification failed after copy: {s}; the device was modified",
                    .{@errorName(err)},
                );
            };
            defer destination_gpt.deinit(gpa);
            if (plan) |root_plan| {
                verifyGrownGptInvariant(
                    verified,
                    destination_gpt,
                    root_plan,
                ) catch |err| {
                    return failAfterMutation(
                        operations,
                        &destination,
                        io,
                        "write: grown GPT invariant verification failed: {s}; the device was modified",
                        .{@errorName(err)},
                    );
                };
                const destination_root = operations.verify_root_fn(
                    operations.context,
                    gpa,
                    io,
                    &destination,
                    destination_gpt,
                ) catch |err| {
                    return failAfterMutation(
                        operations,
                        &destination,
                        io,
                        "write: grown ext4 root verification failed: {s}; the device was modified",
                        .{@errorName(err)},
                    );
                };
                verifyGrownRoot(root_plan, destination_root) catch |err| {
                    return failAfterMutation(
                        operations,
                        &destination,
                        io,
                        "write: grown root identity verification failed: {s}; the device was modified",
                        .{@errorName(err)},
                    );
                };
            } else if (!std.mem.eql(
                u8,
                verified.partition_array,
                destination_gpt.partition_array,
            )) {
                return failAfterMutation(
                    operations,
                    &destination,
                    io,
                    "write: destination GPT verification failed after copy: opaque partition array changed; the device was modified",
                    .{},
                );
            }
        },
    }

    prepared_identity.apply_fn(
        prepared_identity.context,
        gpa,
        io,
        &destination,
    ) catch |err| {
        return failAfterMutation(
            operations,
            &destination,
            io,
            "write: fresh-identity rewrite failed: {s}; the device was modified",
            .{@errorName(err)},
        );
    };

    const outcome = (operations.finish_fn(
        operations.context,
        &destination,
        io,
    ) catch |err| {
        return failAfterMutation(
            operations,
            &destination,
            io,
            "write: device finalization failed: {s}; the device was modified",
            .{@errorName(err)},
        );
    }) orelse return failAfterMutation(
        operations,
        &destination,
        io,
        "write: device finalization did not report an outcome; the device may be partially written",
        .{},
    );

    if (outcome.warning()) |warning| {
        std.debug.print("write: partial success: {s}\n", .{warning});
        return 2;
    }
    if (growth_plan) |plan| {
        std.debug.print(
            "write: wrote {d} source bytes, finalized a {d}-byte root partition with a {d}-byte ext4 filesystem, and flushed the device. {s}\n",
            .{
                source.virtual_size,
                plan.final_partition_length,
                plan.final_filesystem_length,
                outcome.message(),
            },
        );
    } else {
        std.debug.print(
            "write: wrote and flushed {d} bytes. {s}\n",
            .{ source.virtual_size, outcome.message() },
        );
    }
    return 0;
}

fn openDestination(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    source_virtual_size: u64,
    allow_device_write: bool,
) anyerror!vmiz.Image {
    return vmiz.Image.openDeviceForWrite(io, path, source_virtual_size, .{
        .allow_device_write = allow_device_write,
        .allocator = allocator,
    });
}

fn preflightReport(
    _: ?*anyopaque,
    image: *const vmiz.Image,
) ?*const vmiz.DevicePreflightReport {
    return image.devicePreflight();
}

fn sourceImageReadAt(
    ctx: *const anyopaque,
    io: std.Io,
    buffer: []u8,
    offset: u64,
) anyerror!usize {
    const image: *const vmiz.Image = @ptrCast(@alignCast(ctx));
    return image.pread(io, buffer, offset);
}

fn preparedIdentityApplyNoop(
    _: ?*anyopaque,
    _: std.mem.Allocator,
    _: std.Io,
    _: *vmiz.Image,
) anyerror!void {}

fn preparedIdentityDeinitNoop(_: ?*anyopaque, _: std.mem.Allocator) void {}

fn prepareIdentity(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    destination_report: *const vmiz.DevicePreflightReport,
    detected: vmiz.gpt.DetectedGpt,
    growth_plan: ?RootGrowthPlan,
    options: WriteIdentityOptions,
) anyerror!PreparedIdentity {
    if (options.new_uuids) {
        return prepareFreshIdentity(
            allocator,
            io,
            source,
            destination_report,
            detected,
            growth_plan,
        );
    }
    return prepareExistingIdentityReport(
        allocator,
        io,
        source,
        destination_report,
    );
}

fn prepareExistingIdentityReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    destination_report: *const vmiz.DevicePreflightReport,
) anyerror!PreparedIdentity {
    var inventory = try vmiz.block_device.inspectIdentityInventory(allocator, io, .{
        .ctx = source,
        .read_at_fn = sourceImageReadAt,
    }, source.virtual_size);
    defer inventory.deinit(allocator);

    var collisions = try vmiz.block_device.findLinuxVisibleIdentityCollisions(
        allocator,
        io,
        &inventory,
        destination_report.whole_disk_name,
    );
    defer collisions.deinit(allocator);

    return .{
        .report_text = try formatSourceIdentityReport(allocator, &inventory, &collisions),
        .collision_count = collisions.collisions.len,
    };
}

fn prepareFreshIdentity(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    destination_report: *const vmiz.DevicePreflightReport,
    detected: vmiz.gpt.DetectedGpt,
    growth_plan: ?RootGrowthPlan,
) anyerror!PreparedIdentity {
    var inventory = try vmiz.block_device.inspectIdentityInventory(allocator, io, .{
        .ctx = source,
        .read_at_fn = sourceImageReadAt,
    }, source.virtual_size);
    defer inventory.deinit(allocator);

    switch (detected) {
        .not_gpt => return .{
            .report_text = try formatSourceInventoryOnly(allocator, &inventory),
            .refusal_message = try allocator.dupe(
                u8,
                "--new-uuids requires a verified GPT source",
            ),
        },
        .verified => |verified| {
            var state = try allocator.create(IdentityRewriteState);
            errdefer allocator.destroy(state);
            state.* = .{
                .io = io,
                .arena = std.heap.ArenaAllocator.init(allocator),
                .gpt_replacements = null,
                .partitions = &.{},
                .filesystems = &.{},
                .esp_roots = &.{},
                .plan = .{},
                .root_partition_index = 0,
                .boot_partition_index = null,
                .esp_partition_index = null,
                .grown_root_table_index = if (growth_plan) |plan| plan.root.table_index else null,
                .grown_root_filesystem_length = if (growth_plan) |plan| plan.final_filesystem_length else null,
            };
            errdefer {
                state.deinit(allocator);
                allocator.destroy(state);
            }

            const setup = try initializeFreshIdentityState(
                allocator,
                io,
                source,
                destination_report,
                &inventory,
                verified,
                growth_plan,
                state,
            );
            if (setup.refusal_message != null) {
                state.deinit(allocator);
                allocator.destroy(state);
                return .{
                    .report_text = setup.report_text,
                    .refusal_message = setup.refusal_message,
                    .collision_count = setup.collision_count,
                };
            }
            return .{
                .context = state,
                .report_text = setup.report_text,
                .collision_count = setup.collision_count,
                .apply_fn = applyPreparedFreshIdentity,
                .deinit_fn = deinitPreparedFreshIdentity,
            };
        },
    }
}

const PartitionRole = enum { other, root, boot, esp };

const PartitionRewriteMode = enum {
    none,
    ext4_uuid_only,
    xfs_uuid_only,
    fat_uuid_only,
    ext4_tree,
    xfs_tree,
    fat_tree,
};

const FatFormatSnapshot = struct {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    fat_count: u8,
    hidden_sectors: u32,
    media_descriptor: u8,
    sectors_per_track: u16,
    head_count: u16,
    volume_label: [11]u8,

    fn formatOptions(
        self: FatFormatSnapshot,
        partition_offset: u64,
        partition_length: u64,
        volume_id: u32,
    ) vmiz.fat32.FormatOptions {
        return .{
            .partition_offset = partition_offset,
            .partition_len = partition_length,
            .bytes_per_sector = self.bytes_per_sector,
            .sectors_per_cluster = self.sectors_per_cluster,
            .fat_count = self.fat_count,
            .reserved_sector_count = self.reserved_sector_count,
            .media_descriptor = self.media_descriptor,
            .sectors_per_track = self.sectors_per_track,
            .head_count = self.head_count,
            .hidden_sectors = self.hidden_sectors,
            .volume_id = volume_id,
            .volume_label = self.volume_label,
        };
    }
};

const Ext4RewriteSource = struct {
    reader: vmiz.ext4.Reader,
    tree: vmiz.ext4.GeneralTree,
    mutable_tree: vmiz.root_tree.RootTree,

    fn deinit(self: *Ext4RewriteSource) void {
        self.mutable_tree.deinit();
        self.tree.deinit();
        self.reader.deinit();
        self.* = undefined;
    }
};

const XfsRewriteSource = struct {
    reader: vmiz.xfs.Reader,
    tree: vmiz.xfs.Tree,
    mutable_tree: vmiz.root_tree.RootTree,

    fn deinit(self: *XfsRewriteSource, io: std.Io) void {
        self.mutable_tree.deinit();
        self.tree.deinit();
        self.reader.close(io);
        self.* = undefined;
    }
};

const FatRewriteSource = struct {
    filesystem: vmiz.fat32.FileSystem,
    tree: vmiz.fat32.Tree,
    mutable_tree: vmiz.root_tree.RootTree,
    format: FatFormatSnapshot,

    fn deinit(self: *FatRewriteSource) void {
        self.mutable_tree.deinit();
        self.tree.deinit();
        self.* = undefined;
    }
};

const PartitionSource = union(enum) {
    none,
    ext4: Ext4RewriteSource,
    xfs: XfsRewriteSource,
    fat: FatRewriteSource,

    fn deinit(self: *PartitionSource, io: std.Io) void {
        switch (self.*) {
            .none => {},
            .ext4 => |*ext4| ext4.deinit(),
            .xfs => |*xfs| xfs.deinit(io),
            .fat => |*fat| fat.deinit(),
        }
        self.* = .none;
    }

    fn mutableTree(self: *PartitionSource) ?*vmiz.root_tree.RootTree {
        return switch (self.*) {
            .ext4 => |*ext4| &ext4.mutable_tree,
            .xfs => |*xfs| &xfs.mutable_tree,
            .fat => |*fat| &fat.mutable_tree,
            .none => null,
        };
    }
};

const PartitionRewrite = struct {
    table_index: u32,
    partition_type_guid: vmiz.guid.Guid,
    partition_offset: u64,
    partition_length: u64,
    source_partition_guid: vmiz.guid.Guid,
    new_partition_guid: vmiz.guid.Guid,
    old_partition_guid_text: []const u8,
    new_partition_guid_text: []const u8,
    partition_label: ?[]const u8 = null,
    filesystem_kind: vmiz.block_device.FilesystemIdentityKind = .none,
    old_filesystem_identifier: ?[]const u8 = null,
    new_filesystem_identifier: ?[]const u8 = null,
    filesystem_label: ?[]const u8 = null,
    role: PartitionRole = .other,
    mount_point: ?[]const u8 = null,
    mode: PartitionRewriteMode = .none,
    new_uuid: [16]u8 = [_]u8{0} ** 16,
    new_fat_volume_id: u32 = 0,
    source: PartitionSource = .none,
};

const IdentityRewriteState = struct {
    io: std.Io,
    arena: std.heap.ArenaAllocator,
    gpt_replacements: ?vmiz.gpt.OwnedReplacementGuids = null,
    partitions: []PartitionRewrite = &.{},
    filesystems: []vmiz.identity_rewrite.Filesystem = &.{},
    esp_roots: []const []const u8,
    plan: vmiz.identity_rewrite.Plan,
    root_partition_index: usize,
    boot_partition_index: ?usize,
    esp_partition_index: ?usize,
    grown_root_table_index: ?u32,
    grown_root_filesystem_length: ?u64,

    fn deinit(self: *IdentityRewriteState, allocator: std.mem.Allocator) void {
        for (self.partitions) |*partition| partition.source.deinit(self.io);
        if (self.gpt_replacements) |*replacement| replacement.deinit(allocator);
        self.arena.deinit();
        self.* = undefined;
    }
};

const FstabTaggedSpec = struct {
    kind: vmiz.identity_rewrite.Kind,
    value: []const u8,
};

fn makeFilesystemUuidV4(io: std.Io) [16]u8 {
    var bytes: [16]u8 = undefined;
    std.Io.random(io, &bytes);
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    return bytes;
}

fn duplicateGuidText(allocator: std.mem.Allocator, value: vmiz.guid.Guid) ![]const u8 {
    var buffer: [36]u8 = undefined;
    return allocator.dupe(u8, vmiz.guid.formatLower(&buffer, value));
}

fn duplicateFilesystemUuidText(
    allocator: std.mem.Allocator,
    value: *const [16]u8,
) ![]const u8 {
    var buffer: [vmiz.identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    return allocator.dupe(u8, vmiz.identity_rewrite.formatFilesystemUuid(&buffer, value));
}

fn duplicateFatSerialText(
    allocator: std.mem.Allocator,
    volume_id: u32,
) ![]const u8 {
    var buffer: [vmiz.identity_rewrite.fat_serial_bytes]u8 = undefined;
    return allocator.dupe(u8, vmiz.identity_rewrite.formatFatVolumeSerial(&buffer, volume_id));
}

fn partitionLengthBytes(partition: vmiz.gpt.PartitionEntry) !u64 {
    return std.math.mul(
        u64,
        partition.last_lba - partition.first_lba + 1,
        vmiz.gpt.sector_size,
    );
}

fn partitionOffsetBytes(partition: vmiz.gpt.PartitionEntry) !u64 {
    return std.math.mul(u64, partition.first_lba, vmiz.gpt.sector_size);
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index .. index + needle.len], needle)) return true;
    }
    return false;
}

fn isEspTypeGuid(guid_value: vmiz.guid.Guid) bool {
    return std.mem.eql(u8, &guid_value, &vmiz.guid.esp);
}

fn isLinuxRootTypeGuid(guid_value: vmiz.guid.Guid) bool {
    return std.mem.eql(u8, &guid_value, &vmiz.guid.linux_root_x86_64) or
        std.mem.eql(u8, &guid_value, &vmiz.guid.linux_root_aarch64);
}

fn isBootTypeGuid(guid_value: vmiz.guid.Guid) bool {
    return std.mem.eql(u8, &guid_value, &vmiz.guid.linux_xbootldr);
}

fn rootFilesystemType(kind: vmiz.block_device.FilesystemIdentityKind) ?vmiz.identity_rewrite.FilesystemType {
    return switch (kind) {
        .ext4 => .ext4,
        .xfs => .xfs,
        else => null,
    };
}

fn pathExists(tree: *const vmiz.root_tree.RootTree, path: []const u8) bool {
    return tree.findNode(path) != null;
}

fn topLevelPathExists(tree: *const vmiz.root_tree.RootTree, path: []const u8) bool {
    return pathExists(tree, path);
}

fn treeLooksLikeRoot(tree: *const vmiz.root_tree.RootTree) bool {
    return pathExists(tree, "etc/fstab") or
        pathExists(tree, "etc/os-release") or
        pathExists(tree, "usr/lib/os-release");
}

fn treeLooksLikeBoot(tree: *const vmiz.root_tree.RootTree) bool {
    return topLevelPathExists(tree, "grub") or
        topLevelPathExists(tree, "grub2") or
        topLevelPathExists(tree, "loader");
}

fn treeLooksLikeEsp(tree: *const vmiz.root_tree.RootTree) bool {
    return topLevelPathExists(tree, "EFI") or
        topLevelPathExists(tree, "loader");
}

fn partitionLooksLikeEsp(partition_label: ?[]const u8) bool {
    if (partition_label) |label| {
        return containsIgnoreCase(label, "efi") or containsIgnoreCase(label, "esp");
    }
    return false;
}

fn partitionLooksLikeBoot(partition_label: ?[]const u8) bool {
    if (partition_label) |label| {
        return containsIgnoreCase(label, "boot");
    }
    return false;
}

fn signaturesContainUnsupportedFilesystem(signatures: vmiz.block_device.Signatures) bool {
    return signatures.btrfs or
        signatures.swap or
        signatures.luks or
        signatures.lvm2;
}

fn duplicateTrimmedLabel(
    allocator: std.mem.Allocator,
    field: []const u8,
) !?[]const u8 {
    const label = vmiz.identity_rewrite.trimLabel(field) orelse return null;
    return allocator.dupe(u8, label);
}

fn copyLabelText(
    allocator: std.mem.Allocator,
    label: ?[]const u8,
) !?[]const u8 {
    const value = label orelse return null;
    return allocator.dupe(u8, value);
}

fn parseTaggedSpecLocal(spec: []const u8) ?FstabTaggedSpec {
    inline for (comptime std.enums.values(vmiz.identity_rewrite.Kind)) |kind| {
        const prefix = comptime kind.tag() ++ "=";
        if (std.mem.startsWith(u8, spec, prefix) and spec.len > prefix.len) {
            return .{
                .kind = kind,
                .value = spec[prefix.len..],
            };
        }
    }
    return null;
}

fn unescapeFstabFieldLocal(
    allocator: std.mem.Allocator,
    field: []const u8,
) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var index: usize = 0;
    while (index < field.len) {
        if (field[index] == '\\' and index + 3 < field.len) {
            if (std.fmt.parseInt(u8, field[index + 1 ..][0..3], 8)) |byte| {
                try out.append(byte);
                index += 4;
                continue;
            } else |_| {}
        }
        try out.append(field[index]);
        index += 1;
    }
    return out.toOwnedSlice();
}

fn declaresSeparateBootFilesystem(contents: []const u8) bool {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        const body = std.mem.trim(u8, line, " \t\r");
        if (body.len == 0 or body[0] == '#') continue;
        var fields = std.mem.tokenizeAny(u8, body, " \t");
        _ = fields.next() orelse continue;
        const target = fields.next() orelse continue;
        const trimmed = if (target.len > 1 and target[target.len - 1] == '/')
            target[0 .. target.len - 1]
        else
            target;
        if (std.mem.eql(u8, trimmed, "/boot")) return true;
    }
    return false;
}

fn initBorrowedMemoryTree(allocator: std.mem.Allocator, io: std.Io) vmiz.root_tree.RootTree {
    return vmiz.root_tree.RootTree.initMemory(allocator, io, .{});
}

fn scanExt4Partition(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    partition: *PartitionRewrite,
) !void {
    var reader = try vmiz.ext4.openGeneralReadOnlySource(
        io,
        source.file,
        .{
            .ctx = source,
            .read_at_fn = sourceImageReadAt,
        },
        allocator,
        .{ .offset = partition.partition_offset },
    );
    errdefer reader.deinit();
    var tree = try vmiz.ext4.scanReadable(
        &reader,
        io,
        allocator,
        .{ .available_length = partition.partition_length },
    );
    errdefer tree.deinit();
    var mutable_tree = initBorrowedMemoryTree(allocator, io);
    errdefer mutable_tree.deinit();
    try mutable_tree.importExt4GeneralBorrowed(&tree);
    partition.source = .{
        .ext4 = .{
            .reader = reader,
            .tree = tree,
            .mutable_tree = mutable_tree,
        },
    };
}

fn scanXfsPartition(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    partition: *PartitionRewrite,
) !void {
    var reader = try vmiz.xfs.Reader.openReadOnlySource(
        allocator,
        io,
        source.file,
        .{
            .ctx = source,
            .read_at_fn = sourceImageReadAt,
        },
        partition.partition_offset,
    );
    errdefer reader.close(io);
    var tree = try vmiz.xfs.scanReadable(
        &reader,
        io,
        allocator,
        .{ .available_length = partition.partition_length },
    );
    errdefer tree.deinit();
    var mutable_tree = initBorrowedMemoryTree(allocator, io);
    errdefer mutable_tree.deinit();
    try mutable_tree.importXfsBorrowed(&tree);
    partition.source = .{
        .xfs = .{
            .reader = reader,
            .tree = tree,
            .mutable_tree = mutable_tree,
        },
    };
}

fn scanFatPartition(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    partition: *PartitionRewrite,
) !void {
    var filesystem = try vmiz.fat32.open(@constCast(source), io, .{
        .offset = partition.partition_offset,
        .length = partition.partition_length,
    });
    var tree = try vmiz.fat32.scanTree(&filesystem, io, allocator, .{});
    errdefer tree.deinit();
    var mutable_tree = initBorrowedMemoryTree(allocator, io);
    errdefer mutable_tree.deinit();
    mutable_tree.setRootMetadata(.{
        .mode = tree.metadata.directory_mode,
        .uid = tree.metadata.uid,
        .gid = tree.metadata.gid,
    });
    try mutable_tree.importExt4ViewBorrowed(tree.fileTreeView());
    partition.source = .{
        .fat = .{
            .filesystem = filesystem,
            .tree = tree,
            .mutable_tree = mutable_tree,
            .format = .{
                .bytes_per_sector = filesystem.info.bytes_per_sector,
                .sectors_per_cluster = filesystem.info.sectors_per_cluster,
                .reserved_sector_count = filesystem.info.reserved_sector_count,
                .fat_count = filesystem.info.fat_count,
                .hidden_sectors = filesystem.info.hidden_sectors,
                .media_descriptor = filesystem.info.media_descriptor,
                .sectors_per_track = filesystem.info.sectors_per_track,
                .head_count = filesystem.info.head_count,
                .volume_label = filesystem.info.volume_label,
            },
        },
    };
}

fn ensurePartitionScanned(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    partition: *PartitionRewrite,
) !void {
    switch (partition.source) {
        .none => switch (partition.filesystem_kind) {
            .ext4 => try scanExt4Partition(allocator, io, source, partition),
            .xfs => try scanXfsPartition(allocator, io, source, partition),
            .fat => try scanFatPartition(allocator, io, source, partition),
            else => return error.UnsupportedFilesystem,
        },
        else => {},
    }
}

fn rootMutableTree(partition: *PartitionRewrite) ?*vmiz.root_tree.RootTree {
    return partition.source.mutableTree();
}

fn captureScannedPartitionMetadata(
    allocator: std.mem.Allocator,
    partition: *PartitionRewrite,
) !void {
    switch (partition.source) {
        .ext4 => |*ext4| {
            partition.filesystem_label = try duplicateTrimmedLabel(
                allocator,
                &ext4.tree.identity.label,
            );
        },
        .xfs => |*xfs| {
            partition.filesystem_label = try duplicateTrimmedLabel(
                allocator,
                &xfs.tree.identity.label,
            );
        },
        .fat => |*fat| {
            partition.filesystem_label = try duplicateTrimmedLabel(
                allocator,
                &fat.tree.label,
            );
        },
        .none => {},
    }
}

fn selectRootPartitionIndex(
    partitions: []PartitionRewrite,
) !usize {
    var match: ?usize = null;
    for (partitions, 0..) |*partition, index| {
        switch (partition.source) {
            .ext4, .xfs => {
                const tree = rootMutableTree(partition).?;
                if (!treeLooksLikeRoot(tree)) continue;
                if (match == null) {
                    match = index;
                    continue;
                }
                const existing = match.?;
                const prefer_current = isLinuxRootTypeGuid(partition.partition_type_guid) and
                    !isLinuxRootTypeGuid(partitions[existing].partition_type_guid);
                const prefer_existing = !isLinuxRootTypeGuid(partition.partition_type_guid) and
                    isLinuxRootTypeGuid(partitions[existing].partition_type_guid);
                if (prefer_current) {
                    match = index;
                    continue;
                }
                if (!prefer_existing) return error.AmbiguousRootFilesystem;
            },
            else => {},
        }
    }
    return match orelse error.RootFilesystemNotFound;
}

fn chooseFallbackEspMountPoint(root_tree: *const vmiz.root_tree.RootTree) []const u8 {
    if (pathExists(root_tree, "boot/efi")) return "/boot/efi";
    if (pathExists(root_tree, "efi")) return "/efi";
    return "/boot/efi";
}

fn selectFallbackEspPartition(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    partitions: []PartitionRewrite,
) !?usize {
    var match: ?usize = null;
    for (partitions, 0..) |*partition, index| {
        if (partition.filesystem_kind != .fat) continue;
        const candidate = isEspTypeGuid(partition.partition_type_guid) or
            partitionLooksLikeEsp(partition.partition_label);
        if (!candidate) continue;
        try ensurePartitionScanned(allocator, io, source, partition);
        try captureScannedPartitionMetadata(allocator, partition);
        const tree = rootMutableTree(partition).?;
        if (!treeLooksLikeEsp(tree) and !isEspTypeGuid(partition.partition_type_guid)) continue;
        if (match != null) return error.AmbiguousEspMount;
        match = index;
    }
    return match;
}

fn hasUnsupportedSeparateBootCandidate(partitions: []PartitionRewrite, root_index: usize, esp_index: ?usize) bool {
    for (partitions, 0..) |*partition, index| {
        if (index == root_index or (esp_index != null and index == esp_index.?)) continue;
        if (partition.filesystem_kind != .ext4 and partition.filesystem_kind != .xfs and
            partition.filesystem_kind != .fat)
        {
            continue;
        }
        if (isBootTypeGuid(partition.partition_type_guid) or partitionLooksLikeBoot(partition.partition_label)) {
            return true;
        }
        switch (partition.source) {
            .ext4, .xfs, .fat => if (rootMutableTree(partition)) |tree| {
                if (treeLooksLikeBoot(tree)) return true;
            },
            .none => {},
        }
    }
    return false;
}

fn partitionMatchesTaggedSpec(partition: *const PartitionRewrite, tagged: FstabTaggedSpec) bool {
    return switch (tagged.kind) {
        .filesystem_uuid => if (partition.old_filesystem_identifier) |value|
            std.ascii.eqlIgnoreCase(value, tagged.value)
        else
            false,
        .partition_uuid => std.ascii.eqlIgnoreCase(partition.old_partition_guid_text, tagged.value),
        .filesystem_label => if (partition.filesystem_label) |value|
            std.mem.eql(u8, value, tagged.value)
        else
            false,
        .partition_label => if (partition.partition_label) |value|
            std.mem.eql(u8, value, tagged.value)
        else
            false,
    };
}

fn findPartitionForTaggedSpec(
    partitions: []PartitionRewrite,
    tagged: FstabTaggedSpec,
) !?usize {
    var match: ?usize = null;
    for (partitions, 0..) |*partition, index| {
        if (!partitionMatchesTaggedSpec(partition, tagged)) continue;
        if (match != null) return error.AmbiguousMountReference;
        match = index;
    }
    return match;
}

const EspMount = struct {
    partition_index: usize,
    mount_point: []const u8,
};

fn resolveEspMountFromFstab(
    allocator: std.mem.Allocator,
    contents: []const u8,
    partitions: []PartitionRewrite,
) !struct { declared: bool, mount: ?EspMount } {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    var declared = false;
    var match: ?EspMount = null;
    while (lines.next()) |line| {
        const body = std.mem.trim(u8, line, " \t\r");
        if (body.len == 0 or body[0] == '#') continue;
        var fields = std.mem.tokenizeAny(u8, body, " \t");
        const spec = fields.next() orelse continue;
        const mount_field = fields.next() orelse continue;
        const decoded_mount = try unescapeFstabFieldLocal(allocator, mount_field);
        defer allocator.free(decoded_mount);
        if (!std.mem.eql(u8, decoded_mount, "/boot/efi") and !std.mem.eql(u8, decoded_mount, "/efi")) {
            continue;
        }
        declared = true;
        const tagged = parseTaggedSpecLocal(spec) orelse return error.UnsupportedEspMountSpecifier;
        const index = (try findPartitionForTaggedSpec(partitions, tagged)) orelse
            return error.EspMountNotFound;
        if (partitions[index].filesystem_kind != .fat) return error.EspMountNotFat;
        if (match != null) return error.AmbiguousEspMount;
        match = .{
            .partition_index = index,
            .mount_point = if (std.mem.eql(u8, decoded_mount, "/boot/efi"))
                "/boot/efi"
            else
                "/efi",
        };
    }
    return .{ .declared = declared, .mount = match };
}

fn formatSignaturesText(
    allocator: std.mem.Allocator,
    signatures: vmiz.block_device.Signatures,
) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var first = true;
    inline for (std.meta.fields(vmiz.block_device.Signatures)) |field| {
        if (@field(signatures, field.name)) {
            if (!first) try out.appendSlice(",");
            try out.appendSlice(field.name);
            first = false;
        }
    }
    if (first) try out.appendSlice("none");
    return out.toOwnedSlice();
}

fn freshRefusal(
    report_text: []u8,
    message: []u8,
    collision_count: usize,
) FreshPreparedSetup {
    return .{
        .report_text = report_text,
        .collision_count = collision_count,
        .refusal_message = message,
    };
}

fn identifierTextAlreadyUsed(partitions: []const PartitionRewrite, candidate: []const u8) bool {
    for (partitions) |partition| {
        if (partition.new_filesystem_identifier) |existing| {
            if (std.ascii.eqlIgnoreCase(existing, candidate)) return true;
        }
    }
    return false;
}

fn assignFreshFilesystemIdentifier(
    allocator: std.mem.Allocator,
    io: std.Io,
    partitions: []PartitionRewrite,
    partition_index: usize,
) !void {
    const partition = &partitions[partition_index];
    switch (partition.filesystem_kind) {
        .ext4, .xfs => {
            while (true) {
                const uuid = makeFilesystemUuidV4(io);
                const text = try duplicateFilesystemUuidText(allocator, &uuid);
                if (partition.old_filesystem_identifier) |old| {
                    if (std.ascii.eqlIgnoreCase(old, text)) {
                        allocator.free(text);
                        continue;
                    }
                }
                if (identifierTextAlreadyUsed(partitions, text)) {
                    allocator.free(text);
                    continue;
                }
                partition.new_uuid = uuid;
                partition.new_filesystem_identifier = text;
                return;
            }
        },
        .fat => {
            while (true) {
                var candidate_bytes: [4]u8 = undefined;
                std.Io.random(io, &candidate_bytes);
                const value = std.mem.readInt(u32, &candidate_bytes, .little);
                if (value == 0) continue;
                const text = try duplicateFatSerialText(allocator, value);
                if (partition.old_filesystem_identifier) |old| {
                    if (std.ascii.eqlIgnoreCase(old, text)) {
                        allocator.free(text);
                        continue;
                    }
                }
                if (identifierTextAlreadyUsed(partitions, text)) {
                    allocator.free(text);
                    continue;
                }
                partition.new_fat_volume_id = value;
                partition.new_filesystem_identifier = text;
                return;
            }
        },
        else => return,
    }
}

fn buildPlannedIdentityInventory(
    allocator: std.mem.Allocator,
    source: *const vmiz.block_device.IdentityInventory,
    new_disk_guid_text: []const u8,
    partitions: []const PartitionRewrite,
) !vmiz.block_device.IdentityInventory {
    const copied = try allocator.alloc(vmiz.block_device.PartitionReport, source.partitions.len);
    errdefer allocator.free(copied);
    for (source.partitions, copied, 0..) |original, *slot, index| {
        slot.* = original;
        const partition = &partitions[index];
        slot.gpt_unique_guid_len = @intCast(partition.new_partition_guid_text.len);
        @memcpy(
            slot.gpt_unique_guid[0..partition.new_partition_guid_text.len],
            partition.new_partition_guid_text,
        );
        if (partition.new_filesystem_identifier) |identifier| {
            slot.filesystem.identifier_len = @intCast(identifier.len);
            @memset(slot.filesystem.identifier[0..], 0);
            @memcpy(slot.filesystem.identifier[0..identifier.len], identifier);
        }
    }
    var inventory = source.*;
    inventory.partitions = copied;
    inventory.gpt_disk_guid_len = @intCast(new_disk_guid_text.len);
    @memset(inventory.gpt_disk_guid[0..], 0);
    @memcpy(inventory.gpt_disk_guid[0..new_disk_guid_text.len], new_disk_guid_text);
    return inventory;
}

fn buildIdentityRewritePlan(state: *IdentityRewriteState) !void {
    const arena = state.arena.allocator();
    state.filesystems = try arena.alloc(vmiz.identity_rewrite.Filesystem, state.partitions.len);
    for (state.partitions, state.filesystems, 0..) |partition, *slot, index| {
        slot.* = .{
            .before = .{
                .filesystem_uuid = partition.old_filesystem_identifier,
                .partition_uuid = partition.old_partition_guid_text,
                .filesystem_label = partition.filesystem_label,
                .partition_label = partition.partition_label,
            },
            .after = .{
                .filesystem_uuid = partition.new_filesystem_identifier,
                .partition_uuid = partition.new_partition_guid_text,
                .filesystem_label = partition.filesystem_label,
                .partition_label = partition.partition_label,
            },
            .root_filesystem_type = if (index == state.root_partition_index)
                rootFilesystemType(partition.filesystem_kind)
            else
                null,
        };
    }
    if (state.esp_partition_index) |esp_index| {
        const mount_point = state.partitions[esp_index].mount_point orelse return error.InvalidIdentityPlan;
        state.esp_roots = try arena.alloc([]const u8, 1);
        state.esp_roots[0] = mount_point;
    } else {
        state.esp_roots = &.{};
    }
    state.plan = .{
        .filesystems = state.filesystems,
        .esp_roots = state.esp_roots,
    };
    try state.plan.validate();
}

fn describeStaleReferenceRefusal(
    allocator: std.mem.Allocator,
    diagnostic: vmiz.identity_rewrite.Diagnostic,
) ![]u8 {
    const stale = diagnostic.stale orelse return allocator.dupe(
        u8,
        "--new-uuids left an unrewriteable stale boot reference",
    );
    var detail: [vmiz.identity_rewrite.Stale.max_message_bytes]u8 = undefined;
    const description = stale.describe(&detail) catch "stale boot reference";
    const path = stale.path();
    const immutable = std.mem.endsWith(u8, path, ".efi") or
        std.mem.endsWith(u8, path, "core.img") or
        std.mem.endsWith(u8, path, "grubenv");
    return if (immutable)
        std.fmt.allocPrint(
            allocator,
            "{s}; safe in-place rewriting of signed or immutable boot artifacts is unsupported",
            .{description},
        )
    else
        std.fmt.allocPrint(
            allocator,
            "{s}; correct the source or omit --new-uuids",
            .{description},
        );
}

fn ext4PopulateLength(partition: *const PartitionRewrite, state: *const IdentityRewriteState) u64 {
    if (state.grown_root_table_index) |table_index| {
        if (partition.table_index == table_index) return state.grown_root_filesystem_length.?;
    }
    return switch (partition.source) {
        .ext4 => |ext4| ext4.tree.identity.filesystem_length,
        else => partition.partition_length,
    };
}

fn ext4PopulateOptions(
    partition: *PartitionRewrite,
    state: *const IdentityRewriteState,
) vmiz.ext4.PopulateOptions {
    const ext4 = partition.source.ext4;
    const root = ext4.mutable_tree.rootMetadata();
    return .{
        .offset = partition.partition_offset,
        .length = ext4PopulateLength(partition, state),
        .block_size = ext4.tree.identity.block_size,
        .label = &ext4.tree.identity.label,
        .uuid = partition.new_uuid,
        .timestamp = std.math.cast(u32, root.mtime orelse 0) orelse 0,
        .journal = .{ .enabled = ext4.tree.identity.has_journal },
        .root_mode = root.mode,
        .root_uid = root.uid,
        .root_gid = root.gid,
        .root_atime = root.atime,
        .root_mtime = root.mtime,
        .root_ctime = root.ctime,
        .root_atime_nsec = root.atime_nsec,
        .root_mtime_nsec = root.mtime_nsec,
        .root_ctime_nsec = root.ctime_nsec,
        .root_crtime = root.crtime,
        .root_crtime_nsec = root.crtime_nsec,
        .root_xattrs = root.xattrs,
        .descriptor_size = ext4.tree.identity.descriptor_size,
        .preserve_feature_ro_compat = ext4.tree.identity.feature_ro_compat,
        .preserve_feature_compat = if (ext4.tree.identity.descriptor_size == 64)
            ext4.tree.identity.feature_compat
        else
            null,
        .preserve_feature_incompat = if (ext4.tree.identity.descriptor_size == 64)
            ext4.tree.identity.feature_incompat
        else
            null,
        .preserve_checksum_seed = if (ext4.tree.identity.descriptor_size == 64)
            ext4.tree.identity.checksum_seed
        else
            null,
        .preserve_orphan_file_inode = ext4.tree.identity.orphan_file_inode,
    };
}

fn xfsPopulateOptions(partition: *PartitionRewrite) vmiz.xfs_writer.PopulateOptions {
    const xfs = partition.source.xfs;
    const root = xfs.mutable_tree.rootMetadata();
    return .{
        .format = .{
            .offset = partition.partition_offset,
            .length = xfs.tree.identity.filesystem_length,
            .uuid = partition.new_uuid,
            .label = &xfs.tree.identity.label,
            .timestamp = .{
                .sec = root.mtime orelse 0,
                .nsec = root.mtime_nsec,
            },
        },
        .root = .{
            .mode = root.mode,
            .uid = root.uid,
            .gid = root.gid,
            .atime = root.atime,
            .mtime = root.mtime,
            .ctime = root.ctime,
            .crtime = root.crtime,
            .atime_nsec = root.atime_nsec,
            .mtime_nsec = root.mtime_nsec,
            .ctime_nsec = root.ctime_nsec,
            .crtime_nsec = root.crtime_nsec,
            .xattrs = root.xattrs,
        },
    };
}

fn preflightPreparedTrees(
    allocator: std.mem.Allocator,
    state: *IdentityRewriteState,
) !void {
    for (state.partitions) |*partition| {
        switch (partition.mode) {
            .ext4_tree => {
                const ext4 = partition.source.ext4;
                _ = try vmiz.ext4.preflightPopulate(
                    allocator,
                    try ext4.mutable_tree.cursor(),
                    ext4PopulateOptions(partition, state),
                );
            },
            .xfs_tree => {
                const minimum = try vmiz.xfs_writer.minimumSize(
                    allocator,
                    try partition.source.xfs.mutable_tree.cursor(),
                    xfsPopulateOptions(partition),
                );
                if (minimum > partition.source.xfs.tree.identity.filesystem_length) {
                    return error.DestinationTooSmall;
                }
            },
            .fat_tree => {
                const minimum = try partition.source.fat.mutable_tree.minimumFat32VolumeLength(
                    .{},
                    .{
                        .bytes_per_sector = partition.source.fat.format.bytes_per_sector,
                        .fat_count = partition.source.fat.format.fat_count,
                        .reserved_sector_count = partition.source.fat.format.reserved_sector_count,
                        .alignment = partition.source.fat.format.bytes_per_sector,
                        .max_length = partition.partition_length,
                    },
                );
                if (minimum > partition.partition_length) return error.DestinationTooSmall;
            },
            else => {},
        }
    }
}

fn applyIdentityRewritePreflight(
    allocator: std.mem.Allocator,
    state: *IdentityRewriteState,
) !?[]u8 {
    var diagnostic = vmiz.identity_rewrite.Diagnostic{};
    const root_tree = rootMutableTree(&state.partitions[state.root_partition_index]).?;
    vmiz.identity_rewrite.apply(
        allocator,
        root_tree,
        state.plan,
        .rewrite_and_verify,
        &diagnostic,
    ) catch |err| switch (err) {
        error.StaleFilesystemIdentifier => return try describeStaleReferenceRefusal(allocator, diagnostic),
        else => return err,
    };

    if (state.esp_partition_index) |esp_index| {
        var esp_plan = state.plan;
        esp_plan.tree_is_esp = true;
        esp_plan.esp_roots = &.{};
        diagnostic = .{};
        const esp_tree = rootMutableTree(&state.partitions[esp_index]).?;
        vmiz.identity_rewrite.apply(
            allocator,
            esp_tree,
            esp_plan,
            .rewrite_and_verify,
            &diagnostic,
        ) catch |err| switch (err) {
            error.StaleFilesystemIdentifier => return try describeStaleReferenceRefusal(allocator, diagnostic),
            else => return err,
        };
    }
    return null;
}

fn verifyFreshIdentityDestination(
    allocator: std.mem.Allocator,
    io: std.Io,
    destination: *vmiz.Image,
    state: *IdentityRewriteState,
) !void {
    var inventory = try vmiz.block_device.inspectIdentityInventory(
        allocator,
        io,
        destination.*,
        vmiz.gpt.default_max_partition_array_bytes,
    );
    defer inventory.deinit(allocator);
    if (inventory.partition_table != .gpt) return error.IdentityRewriteVerificationFailed;

    const expected_disk_guid = try duplicateGuidText(allocator, state.gpt_replacements.?.disk_guid);
    defer allocator.free(expected_disk_guid);
    const actual_disk_guid = inventory.gptDiskGuid() orelse return error.IdentityRewriteVerificationFailed;
    if (!std.ascii.eqlIgnoreCase(actual_disk_guid, expected_disk_guid)) {
        return error.IdentityRewriteVerificationFailed;
    }

    if (inventory.partitions.len != state.partitions.len) return error.IdentityRewriteVerificationFailed;
    for (inventory.partitions, state.partitions) |actual, expected| {
        if (actual.table_index != expected.table_index) return error.IdentityRewriteVerificationFailed;
        if (!std.ascii.eqlIgnoreCase(actual.gptUniqueGuid(), expected.new_partition_guid_text)) {
            return error.IdentityRewriteVerificationFailed;
        }
        if (expected.new_filesystem_identifier) |identifier| {
            const actual_identifier = actual.filesystem.identifierText() orelse
                return error.IdentityRewriteVerificationFailed;
            if (!std.ascii.eqlIgnoreCase(actual_identifier, identifier)) {
                return error.IdentityRewriteVerificationFailed;
            }
        }
    }

    var diagnostic = vmiz.identity_rewrite.Diagnostic{};
    const root_partition = &state.partitions[state.root_partition_index];
    switch (root_partition.filesystem_kind) {
        .ext4 => {
            var readable = try vmiz.ext4.openGeneralReadOnlySource(destination.*, io, .{
                .offset = root_partition.partition_offset,
                .length = ext4PopulateLength(root_partition, state),
            });
            const tree = try readable.scanReadable(io, allocator);
            var root_tree = vmiz.root_tree.RootTree{};
            defer root_tree.deinit(allocator);
            try root_tree.importExt4GeneralBorrowed(allocator, tree);
            vmiz.identity_rewrite.apply(
                allocator,
                &root_tree,
                state.plan,
                .verify_only,
                &diagnostic,
            ) catch |err| switch (err) {
                error.StaleFilesystemIdentifier => return error.IdentityRewriteVerificationFailed,
                else => return err,
            };
        },
        .xfs => {
            var reader = try vmiz.xfs.Reader.openReadOnlySource(destination.file, .{
                .offset = root_partition.partition_offset,
                .available_length = root_partition.partition_length,
            });
            const tree = try reader.scanReadable(io, allocator);
            var root_tree = vmiz.root_tree.RootTree{};
            defer root_tree.deinit(allocator);
            try root_tree.importXfsBorrowed(allocator, tree);
            vmiz.identity_rewrite.apply(
                allocator,
                &root_tree,
                state.plan,
                .verify_only,
                &diagnostic,
            ) catch |err| switch (err) {
                error.StaleFilesystemIdentifier => return error.IdentityRewriteVerificationFailed,
                else => return err,
            };
        },
        else => return error.IdentityRewriteVerificationFailed,
    }

    if (state.esp_partition_index) |esp_index| {
        var root_tree = vmiz.root_tree.RootTree{};
        defer root_tree.deinit(allocator);
        var filesystem = try vmiz.fat32.open(destination, io, .{
            .offset = state.partitions[esp_index].partition_offset,
            .length = state.partitions[esp_index].partition_length,
        });
        const tree = try filesystem.scanTree(allocator, .{});
        root_tree.setRootMetadata(.{
            .mode = tree.metadata.directory_mode,
            .uid = tree.metadata.uid,
            .gid = tree.metadata.gid,
        });
        try root_tree.importExt4ViewBorrowed(
            allocator,
            tree.fileTreeView(),
        );
        var esp_plan = state.plan;
        esp_plan.tree_is_esp = true;
        esp_plan.esp_roots = &.{};
        diagnostic = .{};
        vmiz.identity_rewrite.apply(
            allocator,
            &root_tree,
            esp_plan,
            .verify_only,
            &diagnostic,
        ) catch |err| switch (err) {
            error.StaleFilesystemIdentifier => return error.IdentityRewriteVerificationFailed,
            else => return err,
        };
    }
}

const FreshPreparedSetup = struct {
    report_text: []u8,
    collision_count: usize,
    refusal_message: ?[]u8 = null,
};

fn initializeFreshIdentityState(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    destination_report: *const vmiz.DevicePreflightReport,
    inventory: *const vmiz.block_device.IdentityInventory,
    verified: vmiz.gpt.VerifiedGpt,
    growth_plan: ?RootGrowthPlan,
    state: *IdentityRewriteState,
) !FreshPreparedSetup {
    if (inventory.partition_table != .gpt or inventory.partitions.len != verified.partitions.len) {
        return freshRefusal(
            try formatSourceInventoryOnly(allocator, inventory),
            try allocator.dupe(u8, "--new-uuids requires a strict GPT-partitioned source"),
            0,
        );
    }

    var source_report_text = try formatSourceInventoryOnly(allocator, inventory);
    errdefer allocator.free(source_report_text);

    const arena = state.arena.allocator();
    state.gpt_replacements = try vmiz.gpt.generateReplacementGuids(allocator, io, verified);
    state.partitions = try arena.alloc(PartitionRewrite, verified.partitions.len);

    for (verified.partitions, inventory.partitions, state.partitions, 0..) |verified_partition, inventory_partition, *slot, index| {
        if (verified_partition.table_index != inventory_partition.table_index) {
            return freshRefusal(
                source_report_text,
                try allocator.dupe(u8, "source GPT inventory changed unexpectedly"),
                0,
            );
        }
        const partition_label = if (inventory_partition.partitionName().len == 0)
            null
        else
            try arena.dupe(u8, inventory_partition.partitionName());
        slot.* = .{
            .table_index = verified_partition.table_index,
            .partition_type_guid = verified_partition.partition_type_guid,
            .partition_offset = try partitionOffsetBytes(verified_partition),
            .partition_length = try partitionLengthBytes(verified_partition),
            .source_partition_guid = verified_partition.unique_partition_guid,
            .new_partition_guid = state.gpt_replacements.?.partition_guids[index],
            .old_partition_guid_text = try duplicateGuidText(arena, verified_partition.unique_partition_guid),
            .new_partition_guid_text = try duplicateGuidText(
                arena,
                state.gpt_replacements.?.partition_guids[index],
            ),
            .partition_label = partition_label,
            .filesystem_kind = inventory_partition.filesystem.kind,
            .old_filesystem_identifier = if (inventory_partition.filesystem.identifierText()) |value|
                try arena.dupe(u8, value)
            else
                null,
        };
        if (inventory_partition.filesystem.kind == .ambiguous or
            signaturesContainUnsupportedFilesystem(inventory_partition.signatures))
        {
            const signatures = try formatSignaturesText(allocator, inventory_partition.signatures);
            defer allocator.free(signatures);
            return freshRefusal(
                source_report_text,
                try std.fmt.allocPrint(
                    allocator,
                    "partition {d} carries unsupported signatures ({s}); --new-uuids supports only GPT plus FAT/ext4/XFS filesystem identities",
                    .{ inventory_partition.table_index + 1, signatures },
                ),
                0,
            );
        }
    }

    for (state.partitions) |*partition| {
        if (partition.filesystem_kind != .ext4 and partition.filesystem_kind != .xfs) continue;
        ensurePartitionScanned(allocator, io, source, partition) catch |err| {
            return freshRefusal(
                source_report_text,
                try std.fmt.allocPrint(
                    allocator,
                    "partition {d} could not be scanned safely for --new-uuids: {s}",
                    .{ partition.table_index + 1, @errorName(err) },
                ),
                0,
            );
        };
        try captureScannedPartitionMetadata(arena, partition);
    }

    state.root_partition_index = selectRootPartitionIndex(state.partitions) catch |err| {
        return freshRefusal(
            source_report_text,
            try std.fmt.allocPrint(
                allocator,
                "--new-uuids could not locate a unique ext4/XFS root filesystem: {s}",
                .{@errorName(err)},
            ),
            0,
        );
    };
    state.partitions[state.root_partition_index].role = .root;
    state.partitions[state.root_partition_index].mode = switch (state.partitions[state.root_partition_index].filesystem_kind) {
        .ext4 => .ext4_tree,
        .xfs => .xfs_tree,
        else => .none,
    };

    if (growth_plan != null and state.partitions[state.root_partition_index].filesystem_kind != .ext4) {
        return freshRefusal(
            source_report_text,
            try allocator.dupe(
                u8,
                "--grow-root with --new-uuids requires the detected root filesystem to be ext4",
            ),
            0,
        );
    }
    if (growth_plan) |plan| {
        if (state.partitions[state.root_partition_index].table_index != plan.root.table_index) {
            return freshRefusal(
                source_report_text,
                try allocator.dupe(
                    u8,
                    "--new-uuids could not reconcile the detected root filesystem with --grow-root",
                ),
                0,
            );
        }
    }

    const root_tree = rootMutableTree(&state.partitions[state.root_partition_index]).?;
    const root_fstab = root_tree.readFileAlloc(
        allocator,
        "etc/fstab",
        vmiz.identity_rewrite.max_config_bytes,
    ) catch |err| switch (err) {
        error.MissingNode => null,
        else => {
            return freshRefusal(
                source_report_text,
                try std.fmt.allocPrint(
                    allocator,
                    "failed to read /etc/fstab from the source root: {s}",
                    .{@errorName(err)},
                ),
                0,
            );
        },
    };
    defer if (root_fstab) |bytes| allocator.free(bytes);

    if (root_fstab) |bytes| {
        if (declaresSeparateBootFilesystem(bytes)) {
            return freshRefusal(
                source_report_text,
                try allocator.dupe(
                    u8,
                    "layouts with a separate /boot filesystem are refused by --new-uuids",
                ),
                0,
            );
        }
    }

    var esp_mount: ?EspMount = null;
    var esp_declared = false;
    if (root_fstab) |bytes| {
        const resolved = resolveEspMountFromFstab(allocator, bytes, state.partitions) catch |err| {
            return freshRefusal(
                source_report_text,
                try std.fmt.allocPrint(
                    allocator,
                    "failed to resolve the ESP mount from /etc/fstab: {s}",
                    .{@errorName(err)},
                ),
                0,
            );
        };
        esp_declared = resolved.declared;
        esp_mount = resolved.mount;
    }
    if (esp_mount == null) {
        const fallback = selectFallbackEspPartition(
            allocator,
            io,
            source,
            state.partitions,
        ) catch |err| {
            return freshRefusal(
                source_report_text,
                try std.fmt.allocPrint(
                    allocator,
                    "failed to inspect a candidate EFI system partition: {s}",
                    .{@errorName(err)},
                ),
                0,
            );
        };
        if (fallback) |esp_index| {
            esp_mount = .{
                .partition_index = esp_index,
                .mount_point = chooseFallbackEspMountPoint(root_tree),
            };
        } else if (esp_declared) {
            return freshRefusal(
                source_report_text,
                try allocator.dupe(
                    u8,
                    "the source declares an EFI system partition but vmiz could not resolve it safely",
                ),
                0,
            );
        }
    }
    if (esp_mount) |mount| {
        state.esp_partition_index = mount.partition_index;
        state.partitions[mount.partition_index].role = .esp;
        state.partitions[mount.partition_index].mode = .fat_tree;
        state.partitions[mount.partition_index].mount_point = try arena.dupe(u8, mount.mount_point);
        if (state.partitions[mount.partition_index].source == .none) {
            scanFatPartition(allocator, io, source, &state.partitions[mount.partition_index]) catch |err| {
                return freshRefusal(
                    source_report_text,
                    try std.fmt.allocPrint(
                        allocator,
                        "the EFI system partition could not be scanned safely: {s}",
                        .{@errorName(err)},
                    ),
                    0,
                );
            };
        }
        try captureScannedPartitionMetadata(arena, &state.partitions[mount.partition_index]);
    }

    if (hasUnsupportedSeparateBootCandidate(
        state.partitions,
        state.root_partition_index,
        state.esp_partition_index,
    )) {
        return freshRefusal(
            source_report_text,
            try allocator.dupe(
                u8,
                "layouts with a separate boot filesystem are refused by --new-uuids",
            ),
            0,
        );
    }

    for (state.partitions, 0..) |*partition, index| {
        switch (partition.role) {
            .root, .esp => {},
            .other => partition.mode = switch (partition.filesystem_kind) {
                .ext4 => .ext4_uuid_only,
                .xfs => .xfs_uuid_only,
                .fat => .fat_uuid_only,
                else => .none,
            },
            .boot => unreachable,
        }
        try assignFreshFilesystemIdentifier(arena, io, state.partitions, index);
    }

    try buildIdentityRewritePlan(state);

    const new_disk_guid_text = try duplicateGuidText(arena, state.gpt_replacements.?.disk_guid);
    var planned_inventory = try buildPlannedIdentityInventory(
        allocator,
        inventory,
        new_disk_guid_text,
        state.partitions,
    );
    defer planned_inventory.deinit(allocator);
    var collisions = try vmiz.block_device.findLinuxVisibleIdentityCollisions(
        allocator,
        io,
        &planned_inventory,
        destination_report.whole_disk_name,
    );
    defer collisions.deinit(allocator);
    const report_text = try formatFreshIdentityReport(
        allocator,
        inventory,
        &planned_inventory,
        &collisions,
    );
    allocator.free(source_report_text);
    source_report_text = &.{};

    if (try applyIdentityRewritePreflight(allocator, state)) |message| {
        return freshRefusal(report_text, message, collisions.collisions.len);
    }
    preflightPreparedTrees(allocator, state) catch |err| {
        return freshRefusal(
            report_text,
            try std.fmt.allocPrint(
                allocator,
                "the rewritten filesystems could not be validated before mutation: {s}",
                .{@errorName(err)},
            ),
            collisions.collisions.len,
        );
    };
    return .{
        .report_text = report_text,
        .collision_count = collisions.collisions.len,
    };
}

fn applyPreparedFreshIdentity(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    destination: *vmiz.Image,
) anyerror!void {
    const state: *IdentityRewriteState = @ptrCast(@alignCast(ctx.?));
    var verified = try vmiz.gpt.readVerifiedGpt(
        destination.*,
        io,
        allocator,
        vmiz.gpt.default_max_partition_array_bytes,
    );
    defer verified.deinit(allocator);
    var gpt_report = try vmiz.gpt.rewriteIdentity(
        destination,
        io,
        allocator,
        verified,
        state.gpt_replacements.?.borrowed(),
    );
    defer gpt_report.deinit(allocator);

    for (state.partitions) |*partition| {
        switch (partition.mode) {
            .none => {},
            .ext4_uuid_only => {
                _ = try vmiz.ext4.rewriteUuidImage(
                    io,
                    destination,
                    allocator,
                    .{
                        .offset = partition.partition_offset,
                        .length = partition.partition_length,
                        .uuid = partition.new_uuid,
                    },
                );
            },
            .xfs_uuid_only => {
                _ = try vmiz.xfs.rewriteFilesystemUuid(
                    io,
                    destination.file,
                    allocator,
                    .{
                        .offset = partition.partition_offset,
                        .available_length = partition.partition_length,
                        .new_uuid = partition.new_uuid,
                    },
                );
            },
            .fat_uuid_only => {
                _ = try vmiz.fat.rewriteIdentity(
                    destination,
                    io,
                    .{
                        .offset = partition.partition_offset,
                        .length = partition.partition_length,
                    },
                    partition.new_fat_volume_id,
                );
            },
            .ext4_tree => {
                _ = try vmiz.ext4.populate(
                    io,
                    destination.file,
                    allocator,
                    try partition.source.ext4.mutable_tree.cursor(),
                    ext4PopulateOptions(partition, state),
                );
            },
            .xfs_tree => {
                _ = try vmiz.filesystem_writer.formatAndPopulate(
                    io,
                    allocator,
                    destination,
                    &partition.source.xfs.mutable_tree,
                    .xfs,
                    .{ .xfs = xfsPopulateOptions(partition) },
                );
            },
            .fat_tree => {
                try vmiz.fat32.format(
                    destination,
                    io,
                    partition.source.fat.format.formatOptions(
                        partition.partition_offset,
                        partition.partition_length,
                        partition.new_fat_volume_id,
                    ),
                );
                var filesystem = try vmiz.fat32.open(destination, io, .{
                    .offset = partition.partition_offset,
                    .length = partition.partition_length,
                });
                try partition.source.fat.mutable_tree.populateFat32(&filesystem, .{});
            },
        }
    }
    try verifyFreshIdentityDestination(allocator, io, destination, state);
}

fn deinitPreparedFreshIdentity(
    ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
) void {
    const state: *IdentityRewriteState = @ptrCast(@alignCast(ctx.?));
    state.deinit(allocator);
    allocator.destroy(state);
}

fn formatSourceInventoryOnly(
    allocator: std.mem.Allocator,
    inventory: *const vmiz.block_device.IdentityInventory,
) ![]u8 {
    const empty = vmiz.block_device.CollisionReport{
        .collisions = &.{},
        .scanned_visible_disks = 0,
    };
    return formatSourceIdentityReport(allocator, inventory, &empty);
}

fn confirm(_: ?*anyopaque, io: std.Io, destination_path: []const u8) anyerror!bool {
    std.debug.print(
        "write: overwrite all existing data on '{s}'? [y/N] ",
        .{destination_path},
    );
    var buffer: [64]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    const inclusive = reader.interface.takeDelimiterInclusive('\n') catch return false;
    const response = std.mem.trim(u8, inclusive[0 .. inclusive.len - 1], " \t\r");
    return std.ascii.eqlIgnoreCase(response, "y") or
        std.ascii.eqlIgnoreCase(response, "yes");
}

fn detectGpt(
    _: ?*anyopaque,
    source: vmiz.Image,
    io: std.Io,
    allocator: std.mem.Allocator,
) anyerror!vmiz.gpt.DetectedGpt {
    return vmiz.gpt.detectVerifiedGpt(
        source,
        io,
        allocator,
        vmiz.gpt.default_max_partition_array_bytes,
    );
}

fn invalidateDestination(
    _: ?*anyopaque,
    destination: *vmiz.Image,
    io: std.Io,
) anyerror!void {
    return vmiz.gpt.invalidateDestinationPartitionStructures(
        destination,
        io,
        vmiz.gpt.default_max_partition_array_bytes,
    );
}

fn copyBytes(
    _: ?*anyopaque,
    io: std.Io,
    source: vmiz.Image,
    destination: *vmiz.Image,
    allocator: std.mem.Allocator,
) anyerror!void {
    return vmiz.copyAllBytes(io, source, destination, allocator);
}

fn relocateBackup(
    _: ?*anyopaque,
    destination: *vmiz.Image,
    io: std.Io,
    allocator: std.mem.Allocator,
    verified: vmiz.gpt.VerifiedGpt,
) anyerror!vmiz.gpt.RelocationResult {
    return vmiz.gpt.relocateBackup(destination, io, allocator, verified);
}

fn planRootGrowth(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    destination_size: u64,
    verified: vmiz.gpt.VerifiedGpt,
) anyerror!RootGrowthPlan {
    if (source.format != .raw) return error.RootGrowthPreflightRequiresRawSource;
    if (destination_size == 0 or destination_size % vmiz.gpt.sector_size != 0) {
        return error.ImageNotSectorAligned;
    }
    const root = try vmiz.root_resize.selectRoot(
        allocator,
        io,
        source,
        verified,
        .{ .require_last_partition = true },
    );
    const array_sectors = try std.math.divCeil(
        u64,
        @intCast(verified.partition_array.len),
        vmiz.gpt.sector_size,
    );
    const destination_sectors = destination_size / vmiz.gpt.sector_size;
    if (destination_sectors <= array_sectors + 1) return error.InvalidPartitionArrayBounds;
    const backup_lba = destination_sectors - 1;
    const backup_array_lba = backup_lba - array_sectors;
    if (backup_array_lba == 0) return error.InvalidPartitionArrayBounds;
    const final_last_lba = backup_array_lba - 1;
    if (final_last_lba < root.last_lba or final_last_lba < root.first_lba) {
        return error.DestinationTooSmall;
    }
    const partition_sectors = std.math.add(
        u64,
        final_last_lba - root.first_lba,
        1,
    ) catch return error.InvalidPartitionBounds;
    const final_partition_length = std.math.mul(
        u64,
        partition_sectors,
        vmiz.gpt.sector_size,
    ) catch return error.InvalidPartitionBounds;
    const final_filesystem_length =
        final_partition_length / vmiz.ext4.default_block_size *
        vmiz.ext4.default_block_size;
    if (final_filesystem_length == 0 or
        final_filesystem_length > final_partition_length or
        final_filesystem_length < root.filesystem_length)
    {
        return error.InvalidRange;
    }

    const preflight = vmiz.ext4.preflightResize(
        io,
        source.file,
        allocator,
        .{
            .offset = root.byte_offset,
            .length = final_filesystem_length,
        },
    ) catch |err| switch (err) {
        error.GrowthNotRequested => {
            return .{
                .root = root,
                .final_last_lba = final_last_lba,
                .final_partition_length = final_partition_length,
                .final_filesystem_length = final_filesystem_length,
                .grow_partition = final_last_lba != root.last_lba,
                .grow_filesystem = false,
            };
        },
        else => return err,
    };
    if (preflight.existing_length != root.filesystem_length or
        !std.mem.eql(u8, &preflight.uuid, &root.filesystem_uuid) or
        preflight.filesystem.feature_compat != root.filesystem_feature_compat or
        preflight.filesystem.feature_incompat != root.filesystem_feature_incompat or
        preflight.filesystem.feature_ro_compat != root.filesystem_feature_ro_compat)
    {
        return error.FilesystemIdentityChanged;
    }
    return .{
        .root = root,
        .final_last_lba = final_last_lba,
        .final_partition_length = final_partition_length,
        .final_filesystem_length = final_filesystem_length,
        .grow_partition = final_last_lba != root.last_lba,
        .grow_filesystem = true,
    };
}

fn growPartition(
    _: ?*anyopaque,
    destination: *vmiz.Image,
    io: std.Io,
    allocator: std.mem.Allocator,
    verified: vmiz.gpt.VerifiedGpt,
    table_index: u32,
) anyerror!vmiz.gpt.GrowPartitionResult {
    return vmiz.gpt.growPartitionToEnd(
        destination,
        io,
        allocator,
        verified,
        table_index,
    );
}

fn resizeExt4(
    _: ?*anyopaque,
    io: std.Io,
    file: std.Io.File,
    allocator: std.mem.Allocator,
    options: vmiz.ext4.ResizeOptions,
) anyerror!vmiz.ext4.FilesystemInfo {
    return vmiz.ext4.resize(io, file, allocator, options);
}

fn verifyGpt(
    _: ?*anyopaque,
    destination: vmiz.Image,
    io: std.Io,
    allocator: std.mem.Allocator,
) anyerror!vmiz.gpt.VerifiedGpt {
    return vmiz.gpt.readVerifiedGpt(
        destination,
        io,
        allocator,
        vmiz.gpt.default_max_partition_array_bytes,
    );
}

fn verifyRoot(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    destination: *const vmiz.Image,
    verified: vmiz.gpt.VerifiedGpt,
) anyerror!vmiz.root_resize.RootSelection {
    return vmiz.root_resize.selectRoot(
        allocator,
        io,
        destination,
        verified,
        .{ .require_last_partition = true },
    );
}

fn makeDurable(
    _: ?*anyopaque,
    destination: *vmiz.Image,
    io: std.Io,
) anyerror!bool {
    return destination.flushDeviceWrite(io);
}

fn finishDeviceWrite(
    _: ?*anyopaque,
    destination: *vmiz.Image,
    io: std.Io,
) anyerror!?vmiz.DeviceWriteOutcome {
    return destination.finishDeviceWrite(io);
}

fn failAfterMutation(
    operations: Operations,
    destination: *vmiz.Image,
    io: std.Io,
    comptime format: []const u8,
    args: anytype,
) u8 {
    _ = operations.durable_fn(
        operations.context,
        destination,
        io,
    ) catch |durability_err| {
        std.debug.print(
            "write: failed to make partial device writes durable: {s}\n",
            .{@errorName(durability_err)},
        );
        return fail(format, args);
    };
    return fail(format, args);
}

fn bytesEqualExcept(
    before: []const u8,
    after: []const u8,
    allowed_ranges: []const [2]usize,
) bool {
    if (before.len != after.len) return false;
    for (before, after, 0..) |before_byte, after_byte, index| {
        var allowed = false;
        for (allowed_ranges) |range| {
            if (index >= range[0] and index < range[1]) {
                allowed = true;
                break;
            }
        }
        if (!allowed and before_byte != after_byte) return false;
    }
    return true;
}

fn verifyGrownGptInvariant(
    source: vmiz.gpt.VerifiedGpt,
    destination: vmiz.gpt.VerifiedGpt,
    plan: RootGrowthPlan,
) !void {
    const entry_size: usize = source.primary_header.partition_entry_size;
    const entry_offset = std.math.mul(
        usize,
        plan.root.table_index,
        entry_size,
    ) catch return error.InvalidPartitionArrayBounds;
    const last_lba_start = std.math.add(
        usize,
        entry_offset,
        40,
    ) catch return error.InvalidPartitionArrayBounds;
    const last_lba_end = std.math.add(
        usize,
        last_lba_start,
        8,
    ) catch return error.InvalidPartitionArrayBounds;
    if (last_lba_end > source.partition_array.len) return error.InvalidPartitionArrayBounds;
    const partition_allowed = [_][2]usize{.{ last_lba_start, last_lba_end }};
    if (!bytesEqualExcept(
        source.partition_array,
        destination.partition_array,
        &partition_allowed,
    )) return error.UnexpectedPartitionArrayChange;
    if (std.mem.readInt(
        u64,
        destination.partition_array[last_lba_start..][0..8],
        .little,
    ) != plan.final_last_lba) return error.PartitionLengthMismatch;

    const primary_allowed = [_][2]usize{
        .{ 16, 20 },
        .{ 32, 40 },
        .{ 48, 56 },
        .{ 88, 92 },
    };
    const backup_allowed = [_][2]usize{
        .{ 16, 20 },
        .{ 24, 40 },
        .{ 48, 56 },
        .{ 72, 80 },
        .{ 88, 92 },
    };
    const protective_offset = vmiz.mbr.partition_table_offset +
        @as(usize, source.protective_entry_index) * vmiz.mbr.entry_size;
    const mbr_allowed = [_][2]usize{
        .{ protective_offset + 5, protective_offset + 8 },
        .{ protective_offset + 12, protective_offset + 16 },
    };
    if (!bytesEqualExcept(
        &source.primary_header_sector,
        &destination.primary_header_sector,
        &primary_allowed,
    ) or !bytesEqualExcept(
        &source.backup_header_sector,
        &destination.backup_header_sector,
        &backup_allowed,
    ) or !bytesEqualExcept(
        &source.protective_mbr_sector,
        &destination.protective_mbr_sector,
        &mbr_allowed,
    )) return error.UnexpectedGptMetadataChange;

    const array_sectors = std.math.divCeil(
        u64,
        @intCast(source.partition_array.len),
        vmiz.gpt.sector_size,
    ) catch return error.InvalidPartitionArrayBounds;
    const expected_backup_lba = std.math.add(
        u64,
        plan.final_last_lba,
        array_sectors + 1,
    ) catch return error.InvalidPartitionArrayBounds;
    if (!std.mem.eql(
        u8,
        &source.primary_header.disk_guid,
        &destination.primary_header.disk_guid,
    ) or destination.primary_header.last_usable_lba != plan.final_last_lba or
        destination.primary_header.backup_lba != expected_backup_lba or
        destination.primary_header.backup_lba !=
            destination.backup_header.current_lba or
        destination.backup_header.backup_lba !=
            destination.primary_header.current_lba)
    {
        return error.GptGeometryMismatch;
    }
}

fn verifyGrownRoot(
    plan: RootGrowthPlan,
    actual: vmiz.root_resize.RootSelection,
) !void {
    if (actual.table_index != plan.root.table_index or
        actual.first_lba != plan.root.first_lba or
        actual.last_lba != plan.final_last_lba or
        actual.partition_length != plan.final_partition_length)
    {
        return error.PartitionGeometryMismatch;
    }
    if (!std.mem.eql(
        u8,
        &actual.partition_type_guid,
        &plan.root.partition_type_guid,
    ) or !std.mem.eql(
        u8,
        &actual.unique_partition_guid,
        &plan.root.unique_partition_guid,
    ) or !std.mem.eql(
        u8,
        &actual.filesystem_uuid,
        &plan.root.filesystem_uuid,
    ) or !std.mem.eql(
        u8,
        &actual.filesystem_label,
        &plan.root.filesystem_label,
    ) or actual.filesystem_feature_compat != plan.root.filesystem_feature_compat or
        actual.filesystem_feature_incompat != plan.root.filesystem_feature_incompat or
        actual.filesystem_feature_ro_compat != plan.root.filesystem_feature_ro_compat or
        actual.filesystem_length != plan.final_filesystem_length)
    {
        return error.FilesystemIdentityChanged;
    }
}

fn describeWriteFailure(err: anyerror) ?[]const u8 {
    if (vmiz.block_device.describePreflightFailure(err)) |message| return message;
    return switch (err) {
        error.BlockDeviceWriteNotPermitted => "--allow-device-write is required",
        error.NotBlockDevice => "the destination is not an existing block device",
        error.UnsupportedBlockDevice, error.UnsupportedBlockDevicePreflight => "direct block-device writes are supported only on Linux",
        error.AccessDenied, error.PermissionDenied => "opening a block device for writing requires sufficient privileges",
        else => null,
    };
}

fn formatPreflightReport(
    allocator: std.mem.Allocator,
    destination_path: []const u8,
    report: *const vmiz.DevicePreflightReport,
) ![]u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.print(
        "write: destination preflight for '{s}':\n" ++
            "  kernel device: {s} (whole disk: {s})\n" ++
            "  size: {d} bytes; logical sector: {d} bytes\n" ++
            "  removable: {s}; transport: {s}\n",
        .{
            destination_path,
            report.target_name,
            report.whole_disk_name,
            report.geometry.size_bytes,
            report.geometry.logical_sector_size,
            if (report.removable) "yes" else "no",
            @tagName(report.transport),
        },
    );
    try writeIdentityInventory(
        writer,
        report.partition_table,
        report.gptDiskGuid(),
        report.device_signatures,
        report.device_filesystem,
        report.partitions,
    );
    return out.toOwnedSlice();
}

fn formatSourceIdentityReport(
    allocator: std.mem.Allocator,
    inventory: *const vmiz.block_device.IdentityInventory,
    collisions: *const vmiz.block_device.CollisionReport,
) ![]u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.writeAll("write: source identity inventory:\n");
    try writeIdentityInventory(
        writer,
        inventory.partition_table,
        inventory.gptDiskGuid(),
        inventory.device_signatures,
        inventory.device_filesystem,
        inventory.partitions,
    );

    try writer.print(
        "write: visible-device identifier collisions ({d} whole disk{s} scanned):\n",
        .{
            collisions.scanned_visible_disks,
            if (collisions.scanned_visible_disks == 1) "" else "s",
        },
    );
    if (collisions.collisions.len == 0) {
        try writer.writeAll("  none\n");
    } else {
        for (collisions.collisions) |collision| {
            try writeCollisionWithSubject(writer, collision, "source");
        }
    }
    return out.toOwnedSlice();
}

fn formatFreshIdentityReport(
    allocator: std.mem.Allocator,
    source_inventory: *const vmiz.block_device.IdentityInventory,
    planned_inventory: *const vmiz.block_device.IdentityInventory,
    collisions: *const vmiz.block_device.CollisionReport,
) ![]u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.writeAll("write: source identity inventory:\n");
    try writeIdentityInventory(
        writer,
        source_inventory.partition_table,
        source_inventory.gptDiskGuid(),
        source_inventory.device_signatures,
        source_inventory.device_filesystem,
        source_inventory.partitions,
    );
    try writer.writeAll("write: planned fresh-installation identities:\n");
    try writeIdentityInventory(
        writer,
        planned_inventory.partition_table,
        planned_inventory.gptDiskGuid(),
        planned_inventory.device_signatures,
        planned_inventory.device_filesystem,
        planned_inventory.partitions,
    );
    try writer.print(
        "write: visible-device identifier collisions ({d} whole disk{s} scanned):\n",
        .{
            collisions.scanned_visible_disks,
            if (collisions.scanned_visible_disks == 1) "" else "s",
        },
    );
    if (collisions.collisions.len == 0) {
        try writer.writeAll("  none\n");
    } else {
        for (collisions.collisions) |collision| {
            try writeCollisionWithSubject(writer, collision, "planned");
        }
    }
    return out.toOwnedSlice();
}

fn writeIdentityInventory(
    writer: *std.Io.Writer,
    partition_table: vmiz.block_device.PartitionTable,
    gpt_disk_guid: ?[]const u8,
    device_signatures: vmiz.block_device.Signatures,
    device_filesystem: vmiz.block_device.FilesystemIdentity,
    partitions: []const vmiz.block_device.PartitionReport,
) !void {
    try writer.print("  partition table: {s}", .{@tagName(partition_table)});
    if (gpt_disk_guid) |disk_guid| try writer.print("; disk GUID: {s}", .{disk_guid});
    try writer.writeAll("; device signatures: ");
    try writeSignatures(writer, device_signatures);
    if (device_filesystem.kind != .none) {
        try writer.writeAll("; device filesystem: ");
        try writeFilesystemIdentity(writer, device_filesystem);
    }
    try writer.writeByte('\n');

    if (partitions.len == 0) {
        try writer.writeAll("  partitions: none\n");
        return;
    }

    for (partitions) |partition| {
        try writer.print(
            "  partition {d}: LBA {d}-{d}",
            .{ partition.table_index + 1, partition.first_lba, partition.last_lba },
        );
        if (partition.gptUniqueGuid()) |unique_guid| {
            try writer.print(" guid={s}", .{unique_guid});
        }
        if (partition.partitionName().len != 0) {
            try writer.print(" name=\"{s}\"", .{partition.partitionName()});
        }
        try writer.writeAll("; signatures: ");
        try writeSignatures(writer, partition.signatures);
        if (partition.filesystem.kind != .none) {
            try writer.writeAll("; filesystem: ");
            try writeFilesystemIdentity(writer, partition.filesystem);
        }
        try writer.writeByte('\n');
    }
}

fn writeFilesystemIdentity(
    writer: *std.Io.Writer,
    identity: vmiz.block_device.FilesystemIdentity,
) !void {
    switch (identity.kind) {
        .none => try writer.writeAll("none"),
        .ambiguous => try writer.writeAll("ambiguous"),
        .fat, .ext4, .xfs => if (identity.identifierText()) |identifier|
            try writer.print(
                "{s} {s}",
                .{ @tagName(identity.kind), identifier },
            )
        else
            try writer.print("{s} (no identifier)", .{@tagName(identity.kind)}),
    }
}

fn writeSignatures(writer: *std.Io.Writer, signatures: vmiz.block_device.Signatures) !void {
    var first = true;
    inline for (std.meta.fields(vmiz.block_device.Signatures)) |field| {
        if (@field(signatures, field.name)) {
            if (!first) try writer.writeByte(',');
            try writer.writeAll(field.name);
            first = false;
        }
    }
    if (first) try writer.writeAll("none");
}

fn writeCollision(writer: *std.Io.Writer, collision: vmiz.block_device.Collision) !void {
    return writeCollisionWithSubject(writer, collision, "source");
}

fn writeCollisionWithSubject(
    writer: *std.Io.Writer,
    collision: vmiz.block_device.Collision,
    subject: []const u8,
) !void {
    try writer.writeAll("  ");
    switch (collision.kind) {
        .gpt_disk_guid => try writer.print(
            "{s} disk GUID {s} already exists on {s}\n",
            .{ subject, collision.identifierText(), collision.visible_device_name },
        ),
        .gpt_partition_guid => try writer.print(
            "{s} partition {d} GUID {s} already exists on {s} partition {d}\n",
            .{
                subject,
                collision.source_partition_table_index.? + 1,
                collision.identifierText(),
                collision.visible_device_name,
                collision.visible_partition_table_index.? + 1,
            },
        ),
        .filesystem_identifier => {
            if (collision.source_partition_table_index) |source_partition| {
                try writer.print(
                    "{s} partition {d} {s} identifier {s} already exists on {s}",
                    .{
                        subject,
                        source_partition + 1,
                        @tagName(collision.source_filesystem),
                        collision.identifierText(),
                        collision.visible_device_name,
                    },
                );
            } else {
                try writer.print(
                    "{s} device {s} identifier {s} already exists on {s}",
                    .{
                        subject,
                        @tagName(collision.source_filesystem),
                        collision.identifierText(),
                        collision.visible_device_name,
                    },
                );
            }
            if (collision.visible_partition_table_index) |visible_partition| {
                try writer.print(
                    " partition {d}",
                    .{visible_partition + 1},
                );
            }
            if (collision.visible_filesystem != .none) {
                try writer.print(" ({s})", .{@tagName(collision.visible_filesystem)});
            }
            try writer.writeByte('\n');
        },
    }
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

const FakeOperations = struct {
    open_error: ?anyerror = null,
    detect_error: ?anyerror = null,
    invalidate_error: ?anyerror = null,
    copy_error: ?anyerror = null,
    relocate_error: ?anyerror = null,
    plan_root_error: ?anyerror = null,
    grow_partition_error: ?anyerror = null,
    resize_error: ?anyerror = null,
    verify_error: ?anyerror = null,
    verify_root_error: ?anyerror = null,
    durable_error: ?anyerror = null,
    finish_error: ?anyerror = null,
    outcome: ?vmiz.DeviceWriteOutcome = .partition_table_refreshed,
    report: ?*const vmiz.DevicePreflightReport = null,
    source_identity_report_text: []const u8 = "",
    prepared_refusal_message: ?[]const u8 = null,
    prepared_collision_count: usize = 0,
    confirm_result: bool = true,
    expected_format: ?vmiz.Format = null,
    open_calls: usize = 0,
    confirm_calls: usize = 0,
    detect_calls: usize = 0,
    invalidate_calls: usize = 0,
    copy_calls: usize = 0,
    plan_root_calls: usize = 0,
    grow_partition_calls: usize = 0,
    resize_calls: usize = 0,
    verify_root_calls: usize = 0,
    durable_calls: usize = 0,
    finish_calls: usize = 0,
    allow_device_write_seen: bool = false,
    new_uuids_seen: bool = false,
    allow_duplicate_identifiers_seen: bool = false,
    real_pipeline: bool = false,
    real_prepare_identity: bool = false,
    events: [16]u8 = undefined,
    event_count: usize = 0,

    fn record(self: *FakeOperations, event: u8) void {
        self.events[self.event_count] = event;
        self.event_count += 1;
    }

    fn eventSlice(self: *const FakeOperations) []const u8 {
        return self.events[0..self.event_count];
    }

    fn openDestinationFake(
        context: ?*anyopaque,
        _: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
        _: u64,
        allow_device_write: bool,
    ) anyerror!vmiz.Image {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.open_calls += 1;
        self.allow_device_write_seen = allow_device_write;
        if (self.open_error) |err| return err;
        return vmiz.Image.openPath(io, path);
    }

    fn preflightReportFake(
        context: ?*anyopaque,
        _: *const vmiz.Image,
    ) ?*const vmiz.DevicePreflightReport {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        return self.report;
    }

    fn prepareIdentityFake(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        source: *const vmiz.Image,
        report: *const vmiz.DevicePreflightReport,
        detected_gpt: vmiz.gpt.DetectedGpt,
        growth_plan: ?RootGrowthPlan,
        identity_options: WriteIdentityOptions,
    ) anyerror!PreparedIdentity {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.new_uuids_seen = identity_options.new_uuids;
        self.allow_duplicate_identifiers_seen = identity_options.allow_duplicate_identifiers;
        if (self.real_prepare_identity) {
            return prepareIdentity(
                null,
                allocator,
                io,
                source,
                report,
                detected_gpt,
                growth_plan,
                identity_options,
            );
        }
        return .{
            .report_text = try allocator.dupe(u8, self.source_identity_report_text),
            .refusal_message = if (self.prepared_refusal_message) |message|
                try allocator.dupe(u8, message)
            else
                null,
            .collision_count = self.prepared_collision_count,
        };
    }

    fn confirmFake(
        context: ?*anyopaque,
        _: std.Io,
        _: []const u8,
    ) anyerror!bool {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.confirm_calls += 1;
        self.record('c');
        return self.confirm_result;
    }

    fn detectGptFake(
        context: ?*anyopaque,
        source: vmiz.Image,
        io: std.Io,
        allocator: std.mem.Allocator,
    ) anyerror!vmiz.gpt.DetectedGpt {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.detect_calls += 1;
        self.record('d');
        if (self.detect_error) |err| return err;
        if (self.real_pipeline) {
            return detectGpt(null, source, io, allocator);
        }
        return .not_gpt;
    }

    fn invalidateFake(
        context: ?*anyopaque,
        destination: *vmiz.Image,
        io: std.Io,
    ) anyerror!void {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.invalidate_calls += 1;
        self.record('i');
        if (self.invalidate_error) |err| return err;
        if (self.real_pipeline) {
            return invalidateDestination(null, destination, io);
        }
    }

    fn copyFake(
        context: ?*anyopaque,
        io: std.Io,
        source: vmiz.Image,
        destination: *vmiz.Image,
        allocator: std.mem.Allocator,
    ) anyerror!void {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.copy_calls += 1;
        self.record('x');
        if (self.expected_format) |format| {
            try std.testing.expectEqual(format, source.format);
        }
        if (self.copy_error) |err| return err;
        if (self.real_pipeline) {
            return copyBytes(null, io, source, destination, allocator);
        }
    }

    fn relocateFake(
        context: ?*anyopaque,
        destination: *vmiz.Image,
        io: std.Io,
        allocator: std.mem.Allocator,
        verified: vmiz.gpt.VerifiedGpt,
    ) anyerror!vmiz.gpt.RelocationResult {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.record('r');
        if (self.relocate_error) |err| return err;
        return relocateBackup(null, destination, io, allocator, verified);
    }

    fn planRootGrowthFake(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        source: *const vmiz.Image,
        destination_size: u64,
        verified: vmiz.gpt.VerifiedGpt,
    ) anyerror!RootGrowthPlan {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.plan_root_calls += 1;
        self.record('p');
        if (self.plan_root_error) |err| return err;
        return planRootGrowth(
            null,
            allocator,
            io,
            source,
            destination_size,
            verified,
        );
    }

    fn growPartitionFake(
        context: ?*anyopaque,
        destination: *vmiz.Image,
        io: std.Io,
        allocator: std.mem.Allocator,
        verified: vmiz.gpt.VerifiedGpt,
        table_index: u32,
    ) anyerror!vmiz.gpt.GrowPartitionResult {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.grow_partition_calls += 1;
        self.record('g');
        if (self.grow_partition_error) |err| return err;
        return growPartition(
            null,
            destination,
            io,
            allocator,
            verified,
            table_index,
        );
    }

    fn resizeExt4Fake(
        context: ?*anyopaque,
        io: std.Io,
        file: std.Io.File,
        allocator: std.mem.Allocator,
        options: vmiz.ext4.ResizeOptions,
    ) anyerror!vmiz.ext4.FilesystemInfo {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.resize_calls += 1;
        self.record('e');
        if (self.resize_error) |err| return err;
        return resizeExt4(null, io, file, allocator, options);
    }

    fn verifyFake(
        context: ?*anyopaque,
        destination: vmiz.Image,
        io: std.Io,
        allocator: std.mem.Allocator,
    ) anyerror!vmiz.gpt.VerifiedGpt {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.record('v');
        if (self.verify_error) |err| return err;
        return verifyGpt(null, destination, io, allocator);
    }

    fn verifyRootFake(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        destination: *const vmiz.Image,
        verified: vmiz.gpt.VerifiedGpt,
    ) anyerror!vmiz.root_resize.RootSelection {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.verify_root_calls += 1;
        self.record('q');
        if (self.verify_root_error) |err| return err;
        return verifyRoot(null, allocator, io, destination, verified);
    }

    fn durableFake(
        context: ?*anyopaque,
        destination: *vmiz.Image,
        io: std.Io,
    ) anyerror!bool {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.durable_calls += 1;
        self.record('u');
        if (self.durable_error) |err| return err;
        if (self.real_pipeline) return makeDurable(null, destination, io);
        return true;
    }

    fn finishFake(
        context: ?*anyopaque,
        _: *vmiz.Image,
        _: std.Io,
    ) anyerror!?vmiz.DeviceWriteOutcome {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        self.finish_calls += 1;
        self.record('f');
        if (self.finish_error) |err| return err;
        return self.outcome;
    }

    fn operations(self: *FakeOperations) Operations {
        return .{
            .context = self,
            .open_destination_fn = openDestinationFake,
            .preflight_report_fn = preflightReportFake,
            .prepare_identity_fn = prepareIdentityFake,
            .confirm_fn = confirmFake,
            .detect_gpt_fn = detectGptFake,
            .invalidate_fn = invalidateFake,
            .copy_fn = copyFake,
            .relocate_fn = relocateFake,
            .plan_root_growth_fn = planRootGrowthFake,
            .grow_partition_fn = growPartitionFake,
            .resize_ext4_fn = resizeExt4Fake,
            .verify_fn = verifyFake,
            .verify_root_fn = verifyRootFake,
            .durable_fn = durableFake,
            .finish_fn = finishFake,
        };
    }
};

fn testReport() vmiz.DevicePreflightReport {
    return .{
        .target_name = @constCast("test-target"),
        .whole_disk_name = @constCast("test-disk"),
        .geometry = .{ .size_bytes = 16 * 1024 * 1024, .logical_sector_size = 512 },
        .removable = true,
        .transport = .usb,
        .partition_table = .none,
        .partitions = @constCast(&[_]vmiz.block_device.PartitionReport{}),
        .device_signatures = .{},
    };
}

fn createRawTestImage(io: std.Io, path: []const u8) !void {
    return createRawTestImageWithSize(io, path, 16 * 1024 * 1024);
}

fn createRawTestImageWithSize(io: std.Io, path: []const u8, size: u64) !void {
    var image = try vmiz.Image.create(io, path, .raw, size, .{});
    image.close(io);
}

fn createGptTestImage(io: std.Io, path: []const u8, size: u64) !void {
    var image = try vmiz.Image.create(io, path, .raw, size, .{});
    defer image.close(io);
    const specs = [_]vmiz.gpt.PartitionSpec{.{
        .type_guid = vmiz.guid.linux_filesystem_data,
        .unique_guid = vmiz.guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        .size_sectors = 2048,
    }};
    var placements: [specs.len]vmiz.gpt.Placement = undefined;
    try vmiz.gpt.writeGpt(
        &image,
        io,
        vmiz.guid.parse("99999999-8888-7777-6666-555555555555"),
        &specs,
        &placements,
    );
}

fn createRootGptTestImage(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    size: u64,
) !void {
    return createRootGptTestImageWithFilesystemLength(
        allocator,
        io,
        path,
        size,
        null,
    );
}

fn createRootGptTestImageWithFilesystemLength(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    size: u64,
    requested_filesystem_length: ?u64,
) !void {
    var image = try vmiz.Image.create(io, path, .raw, size, .{});
    defer image.close(io);
    const first_lba: u64 = 2048;
    const last_lba = size / vmiz.gpt.sector_size -
        2 - vmiz.gpt.partition_array_sectors;
    const specs = [_]vmiz.gpt.PlacedPartitionSpec{.{
        .type_guid = vmiz.guid.linux_root_x86_64,
        .unique_guid = vmiz.guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        .placement = .{
            .first_lba = first_lba,
            .last_lba = last_lba,
        },
        .name_utf16le = vmiz.gpt.asciiName("root"),
    }};
    try vmiz.gpt.writeGptPlaced(
        &image,
        io,
        vmiz.guid.parse("99999999-8888-7777-6666-555555555555"),
        &specs,
    );
    var tree = vmiz.root_tree.RootTree.initMemory(allocator, io, .{});
    defer tree.deinit();
    try tree.putFileBytes("marker", "preserve me", .{ .mode = 0o644 });
    const partition_length = (last_lba - first_lba + 1) *
        vmiz.gpt.sector_size;
    const filesystem_length = requested_filesystem_length orelse
        partition_length / vmiz.ext4.default_block_size *
            vmiz.ext4.default_block_size;
    _ = try vmiz.ext4.populate(
        io,
        image.file,
        allocator,
        try tree.cursor(),
        .{
            .offset = first_lba * vmiz.gpt.sector_size,
            .length = filesystem_length,
            .label = "vmiz-root",
            .uuid = [_]u8{0x55} ** 16,
        },
    );
}

const WriteIdentityTestFile = struct {
    path: []const u8,
    contents: []const u8,
};

const old_root_partition_guid = vmiz.guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
const old_esp_partition_guid = vmiz.guid.parse("11111111-1111-1111-1111-111111111111");
const old_disk_guid = vmiz.guid.parse("99999999-8888-7777-6666-555555555555");
const old_root_filesystem_uuid = [_]u8{0x55} ** 16;
const old_esp_volume_id: u32 = 0x5A56_4D49;
const old_root_filesystem_uuid_text = "55555555-5555-5555-5555-555555555555";
const old_esp_volume_id_text = "5A56-4D49";

const FreshIdentityImageOptions = struct {
    root_fstab: ?[]const u8 = null,
    root_extra_files: []const WriteIdentityTestFile = &.{},
    esp_extra_files: []const WriteIdentityTestFile = &.{},
    include_esp: bool = true,
};

const default_root_fstab =
    "UUID=" ++ old_root_filesystem_uuid_text ++ " / ext4 defaults 0 1\n" ++
    "UUID=" ++ old_esp_volume_id_text ++ " /boot/efi vfat umask=0077 0 1\n";

fn fatLabelFromText(text: []const u8) [11]u8 {
    var label: [11]u8 = "           ".*;
    @memcpy(label[0..text.len], text);
    return label;
}

fn createFreshIdentityTestImage(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    options: FreshIdentityImageOptions,
) !void {
    const total_size = 128 * 1024 * 1024;
    var image = try vmiz.Image.create(io, path, .raw, total_size, .{});
    defer image.close(io);

    const esp_first_lba: u64 = 2048;
    const esp_last_lba: u64 = esp_first_lba + (16 * 1024 * 1024 / vmiz.gpt.sector_size) - 1;
    const root_first_lba: u64 = esp_last_lba + 1;
    const root_last_lba = total_size / vmiz.gpt.sector_size -
        2 - vmiz.gpt.partition_array_sectors;

    if (options.include_esp) {
        const specs = [_]vmiz.gpt.PlacedPartitionSpec{
            .{
                .type_guid = vmiz.guid.esp,
                .unique_guid = old_esp_partition_guid,
                .placement = .{ .first_lba = esp_first_lba, .last_lba = esp_last_lba },
                .name_utf16le = vmiz.gpt.asciiName("ESP"),
            },
            .{
                .type_guid = vmiz.guid.linux_root_x86_64,
                .unique_guid = old_root_partition_guid,
                .placement = .{ .first_lba = root_first_lba, .last_lba = root_last_lba },
                .name_utf16le = vmiz.gpt.asciiName("root"),
            },
        };
        try vmiz.gpt.writeGptPlaced(&image, io, old_disk_guid, &specs);
    } else {
        const specs = [_]vmiz.gpt.PlacedPartitionSpec{.{
            .type_guid = vmiz.guid.linux_root_x86_64,
            .unique_guid = old_root_partition_guid,
            .placement = .{ .first_lba = root_first_lba, .last_lba = root_last_lba },
            .name_utf16le = vmiz.gpt.asciiName("root"),
        }};
        try vmiz.gpt.writeGptPlaced(&image, io, old_disk_guid, &specs);
    }

    var root_tree = vmiz.root_tree.RootTree.initMemory(allocator, io, .{});
    defer root_tree.deinit();
    try root_tree.putFileBytes("marker", "preserve me", .{ .mode = 0o644 });
    const fstab_text = options.root_fstab orelse default_root_fstab;
    try root_tree.putFileBytes("etc/fstab", fstab_text, .{ .mode = 0o644 });
    try root_tree.putFileBytes(
        "etc/default/grub",
        "GRUB_CMDLINE_LINUX=\"root=UUID=" ++ old_root_filesystem_uuid_text ++ " rootfstype=ext4\"\n",
        .{ .mode = 0o644 },
    );
    try root_tree.putFileBytes(
        "etc/kernel/cmdline",
        "root=UUID=" ++ old_root_filesystem_uuid_text ++ " rootfstype=ext4 quiet\n",
        .{ .mode = 0o644 },
    );
    try root_tree.putFileBytes(
        "boot/grub/grub.cfg",
        "linux /vmlinuz root=UUID=" ++ old_root_filesystem_uuid_text ++ " rootfstype=ext4\n",
        .{ .mode = 0o644 },
    );
    try root_tree.putFileBytes(
        "boot/loader/entries/vmiz.conf",
        "title vmiz\nlinux /vmlinuz\noptions root=UUID=" ++ old_root_filesystem_uuid_text ++ " rootfstype=ext4\n",
        .{ .mode = 0o644 },
    );
    for (options.root_extra_files) |extra| {
        try root_tree.putFileBytes(extra.path, extra.contents, .{ .mode = 0o644 });
    }

    const root_offset = root_first_lba * vmiz.gpt.sector_size;
    const root_length = (root_last_lba - root_first_lba + 1) * vmiz.gpt.sector_size;
    _ = try vmiz.ext4.populate(
        io,
        image.file,
        allocator,
        try root_tree.cursor(),
        .{
            .offset = root_offset,
            .length = root_length,
            .label = "vmiz-root",
            .uuid = old_root_filesystem_uuid,
        },
    );

    if (!options.include_esp) return;

    var esp_tree = vmiz.root_tree.RootTree.initMemory(allocator, io, .{});
    defer esp_tree.deinit();
    try esp_tree.putFileBytes(
        "EFI/vmiz/grub.cfg",
        "search --fs-uuid --set=root " ++ old_root_filesystem_uuid_text ++ "\n",
        .{ .mode = 0o644 },
    );
    try esp_tree.putFileBytes(
        "loader/entries/vmiz.conf",
        "title vmiz\nlinux /vmlinuz\noptions root=UUID=" ++ old_root_filesystem_uuid_text ++ " rootfstype=ext4\n",
        .{ .mode = 0o644 },
    );
    for (options.esp_extra_files) |extra| {
        try esp_tree.putFileBytes(extra.path, extra.contents, .{ .mode = 0o644 });
    }

    const esp_offset = esp_first_lba * vmiz.gpt.sector_size;
    const esp_length = (esp_last_lba - esp_first_lba + 1) * vmiz.gpt.sector_size;
    try vmiz.fat32.format(&image, io, .{
        .partition_offset = esp_offset,
        .partition_len = esp_length,
        .volume_id = old_esp_volume_id,
        .volume_label = fatLabelFromText("ESP"),
    });
    var esp_fs = try vmiz.fat32.open(&image, io, .{
        .offset = esp_offset,
        .length = esp_length,
    });
    try esp_tree.populateFat32(&esp_fs, .{});
}

fn readExt4PartitionFileAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    image: vmiz.Image,
    offset: u64,
    length: u64,
    path: []const u8,
) ![]u8 {
    var readable = try vmiz.ext4.openGeneralReadOnlySource(image, io, .{
        .offset = offset,
        .length = length,
    });
    const tree = try readable.scanReadable(io, allocator);
    var root_tree = vmiz.root_tree.RootTree{};
    defer root_tree.deinit(allocator);
    try root_tree.importExt4GeneralBorrowed(allocator, tree);
    return root_tree.readFileAlloc(allocator, path, 64 * 1024);
}

fn readFatPartitionFileAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    image: *vmiz.Image,
    offset: u64,
    length: u64,
    path: []const u8,
) ![]u8 {
    var fs = try vmiz.fat32.open(image, io, .{ .offset = offset, .length = length });
    _ = 64 * 1024;
    return fs.readFileAlloc(io, allocator, path);
}

fn prepareFreshIdentityForTest(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_path: []const u8,
) !PreparedIdentity {
    var source = try vmiz.Image.openPathReadOnly(io, source_path);
    defer source.close(io);
    var report = testReport();
    const detected = try detectGpt(null, source, io, allocator);
    return prepareIdentity(
        null,
        allocator,
        io,
        &source,
        &report,
        detected,
        null,
        .{ .new_uuids = true },
    );
}

test "write requires explicit device-write opt-in before opening anything" {
    var fake = FakeOperations{};
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            std.testing.io,
            &.{ "source.qcow2", "target" },
            fake.operations(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fake.open_calls);
}

test "write accepts every supported source image format" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const target = "test-write-command-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, target);
    var report = testReport();

    const cases = [_]struct {
        format: vmiz.Format,
        path: []const u8,
    }{
        .{ .format = .raw, .path = "test-write-command-source.raw" },
        .{ .format = .vhd, .path = "test-write-command-source.vhd" },
        .{ .format = .vhdx, .path = "test-write-command-source.vhdx" },
        .{ .format = .qcow2, .path = "test-write-command-source.qcow2" },
    };
    defer for (cases) |case| std.Io.Dir.cwd().deleteFile(io, case.path) catch {};

    for (cases) |case| {
        var image = try vmiz.Image.create(io, case.path, case.format, 16 * 1024 * 1024, .{});
        image.close(io);

        var fake = FakeOperations{
            .report = &report,
            .expected_format = case.format,
        };
        try std.testing.expectEqual(
            @as(u8, 0),
            runWithOperations(
                std.testing.allocator,
                io,
                &.{ "--allow-device-write", "--yes", case.path, target },
                fake.operations(),
            ),
        );
        try std.testing.expect(fake.allow_device_write_seen);
        try std.testing.expectEqual(@as(usize, 0), fake.confirm_calls);
        try std.testing.expectEqual(@as(usize, 1), fake.copy_calls);
    }
}

test "write refuses target and preflight failures before copying" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-preflight-source.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    try createRawTestImage(io, source);

    const errors = [_]anyerror{
        error.NotBlockDevice,
        error.DestinationTooSmall,
        error.TargetMounted,
        error.TargetContainsMountedPartition,
        error.TargetHasHolders,
        error.RootDeviceWriteRefused,
    };
    for (errors) |open_error| {
        var fake = FakeOperations{ .open_error = open_error };
        try std.testing.expectEqual(
            @as(u8, 1),
            runWithOperations(
                std.testing.allocator,
                io,
                &.{ "--allow-device-write", "--yes", source, "target" },
                fake.operations(),
            ),
        );
        try std.testing.expectEqual(@as(usize, 0), fake.copy_calls);
    }
}

test "write production path refuses a regular-file target without mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-regular-source.raw";
    const target = "test-write-command-regular-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    const marker = "keep existing target bytes";
    {
        var image = try vmiz.Image.openPath(io, target);
        defer image.close(io);
        try image.pwrite(io, marker, 4096);
    }

    try std.testing.expectEqual(
        @as(u8, 1),
        run(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", source, target },
        ),
    );
    var image = try vmiz.Image.openPathReadOnly(io, target);
    defer image.close(io);
    var actual: [marker.len]u8 = undefined;
    try std.testing.expectEqual(marker.len, try image.pread(io, &actual, 4096));
    try std.testing.expectEqualStrings(marker, &actual);
}

test "write confirmation can cancel before the copy" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-confirm-source.raw";
    const target = "test-write-command-confirm-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    var report = testReport();
    var fake = FakeOperations{
        .report = &report,
        .confirm_result = false,
    };

    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), fake.confirm_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.copy_calls);
}

test "write reports refresh failures as partial success" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-outcome-source.raw";
    const target = "test-write-command-outcome-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    var report = testReport();

    for ([_]vmiz.DeviceWriteOutcome{
        .partition_table_stale_busy,
        .partition_table_stale_unsupported,
        .partition_table_stale_failed,
    }) |outcome| {
        var fake = FakeOperations{
            .report = &report,
            .outcome = outcome,
        };
        try std.testing.expectEqual(
            @as(u8, 2),
            runWithOperations(
                std.testing.allocator,
                io,
                &.{ "--allow-device-write", "--yes", source, target },
                fake.operations(),
            ),
        );
        try std.testing.expectEqual(@as(usize, 1), fake.copy_calls);
    }
}

test "write fails copy or flush errors after warning about partial mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-flush-source.raw";
    const target = "test-write-command-flush-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    var report = testReport();
    var fake = FakeOperations{
        .report = &report,
        .copy_error = error.NoSpaceLeft,
    };

    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), fake.copy_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.finish_calls);
    try std.testing.expectEqualStrings("dixu", fake.eventSlice());
}

test "write orders confirmation, invalidation, copy, and one final refresh" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-order-source.raw";
    const target = "test-write-command-order-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    var report = testReport();
    var fake = FakeOperations{ .report = &report };

    try std.testing.expectEqual(
        @as(u8, 0),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dcixf", fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 1), fake.finish_calls);
}

test "write passes through non-GPT sources while clearing stale destination metadata" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-non-gpt-source.raw";
    const target = "test-write-command-non-gpt-target.raw";
    const source_size: u64 = 16 * 1024 * 1024;
    const target_size: u64 = 20 * 1024 * 1024;
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    {
        var image = try vmiz.Image.create(io, source, .raw, source_size, .{});
        defer image.close(io);
        try image.pwrite(io, "payload", 4 * 1024 * 1024);
    }
    {
        var image = try vmiz.Image.create(io, target, .raw, target_size, .{});
        defer image.close(io);
        try image.pwrite(io, &([_]u8{0xa5} ** 512), target_size - 512);
    }
    var report = testReport();
    var fake = FakeOperations{ .report = &report, .real_pipeline = true };

    try std.testing.expectEqual(
        @as(u8, 0),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dixf", fake.eventSlice());
    var destination = try vmiz.Image.openPathReadOnly(io, target);
    defer destination.close(io);
    var payload: ["payload".len]u8 = undefined;
    try std.testing.expectEqual(
        payload.len,
        try destination.pread(io, &payload, 4 * 1024 * 1024),
    );
    try std.testing.expectEqualStrings("payload", &payload);
    var end_sector: [512]u8 = undefined;
    try std.testing.expectEqual(
        end_sector.len,
        try destination.pread(io, &end_sector, target_size - 512),
    );
    try std.testing.expect(std.mem.allEqual(u8, &end_sector, 0));
}

test "write relocates or visibly accepts same-size GPT and preserves its opaque array" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source_size: u64 = 16 * 1024 * 1024;
    const cases = [_]struct {
        suffix: []const u8,
        target_size: u64,
    }{
        .{ .suffix = "grown", .target_size = 24 * 1024 * 1024 },
        .{ .suffix = "same", .target_size = source_size },
    };

    for (cases) |case| {
        const source = try std.fmt.allocPrint(
            std.testing.allocator,
            "test-write-command-gpt-source-{s}.raw",
            .{case.suffix},
        );
        defer std.testing.allocator.free(source);
        const target = try std.fmt.allocPrint(
            std.testing.allocator,
            "test-write-command-gpt-target-{s}.raw",
            .{case.suffix},
        );
        defer std.testing.allocator.free(target);
        defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
        defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
        try createGptTestImage(io, source, source_size);
        {
            var image = try vmiz.Image.create(io, target, .raw, case.target_size, .{});
            image.close(io);
        }

        var source_image = try vmiz.Image.openPathReadOnly(io, source);
        defer source_image.close(io);
        var source_gpt = try vmiz.gpt.readVerifiedGpt(
            source_image,
            io,
            std.testing.allocator,
            vmiz.gpt.default_max_partition_array_bytes,
        );
        defer source_gpt.deinit(std.testing.allocator);
        const original_array = try std.testing.allocator.dupe(
            u8,
            source_gpt.partition_array,
        );
        defer std.testing.allocator.free(original_array);

        var report = testReport();
        var fake = FakeOperations{ .report = &report, .real_pipeline = true };
        try std.testing.expectEqual(
            @as(u8, 0),
            runWithOperations(
                std.testing.allocator,
                io,
                &.{ "--allow-device-write", "--yes", source, target },
                fake.operations(),
            ),
        );
        try std.testing.expectEqualStrings("dixrvf", fake.eventSlice());
        try std.testing.expectEqual(@as(usize, 1), fake.finish_calls);

        var destination = try vmiz.Image.openPathReadOnly(io, target);
        defer destination.close(io);
        var destination_gpt = try vmiz.gpt.readVerifiedGpt(
            destination,
            io,
            std.testing.allocator,
            vmiz.gpt.default_max_partition_array_bytes,
        );
        defer destination_gpt.deinit(std.testing.allocator);
        try std.testing.expectEqual(
            case.target_size / vmiz.gpt.sector_size - 1,
            destination_gpt.primary_header.backup_lba,
        );
        try std.testing.expectEqualSlices(
            u8,
            original_array,
            destination_gpt.partition_array,
        );
    }
}

test "write rejects malformed GPT before destination mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-malformed-gpt-source.raw";
    const target = "test-write-command-malformed-gpt-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    {
        var image = try vmiz.Image.openPath(io, source);
        defer image.close(io);
        const protective = vmiz.mbr.protectiveMbr(
            image.virtual_size / vmiz.gpt.sector_size,
        ).encode();
        try image.pwrite(io, &protective, 0);
    }
    const marker = "destination remains intact";
    {
        var image = try vmiz.Image.openPath(io, target);
        defer image.close(io);
        try image.pwrite(io, marker, 4096);
    }

    var report = testReport();
    var fake = FakeOperations{ .report = &report, .real_pipeline = true };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("d", fake.eventSlice());
    var destination = try vmiz.Image.openPathReadOnly(io, target);
    defer destination.close(io);
    var actual: [marker.len]u8 = undefined;
    try std.testing.expectEqual(
        actual.len,
        try destination.pread(io, &actual, 4096),
    );
    try std.testing.expectEqualStrings(marker, &actual);
}

test "write stops at invalidation and finalization errors in the correct phase" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-phase-error-source.raw";
    const target = "test-write-command-phase-error-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    var report = testReport();

    var invalidate_fake = FakeOperations{
        .report = &report,
        .invalidate_error = error.InputOutput,
    };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", source, target },
            invalidate_fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("diu", invalidate_fake.eventSlice());

    var finish_fake = FakeOperations{
        .report = &report,
        .finish_error = error.InputOutput,
    };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", source, target },
            finish_fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dixfu", finish_fake.eventSlice());
}

test "write does not finalize an unverified relocated GPT" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-gpt-error-source.raw";
    const target = "test-write-command-gpt-error-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createGptTestImage(io, source, 16 * 1024 * 1024);
    try createRawTestImage(io, target);
    var report = testReport();

    var relocate_fake = FakeOperations{
        .report = &report,
        .real_pipeline = true,
        .relocate_error = error.InputOutput,
    };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", source, target },
            relocate_fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dixru", relocate_fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 0), relocate_fake.finish_calls);

    var verify_fake = FakeOperations{
        .report = &report,
        .real_pipeline = true,
        .verify_error = error.BadHeaderChecksum,
    };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", source, target },
            verify_fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dixrvu", verify_fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 0), verify_fake.finish_calls);
}

test "write grow-root preflights before confirmation and mutates in order" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-grow-order-source.raw";
    const target = "test-write-command-grow-order-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRootGptTestImage(std.testing.allocator, io, source, 64 * 1024 * 1024);
    try createRawTestImageWithSize(io, target, 96 * 1024 * 1024);
    var report = testReport();
    var fake = FakeOperations{ .report = &report, .real_pipeline = true };

    try std.testing.expectEqual(
        @as(u8, 0),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--grow-root", "--allow-device-write", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dpcixgevqf", fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 1), fake.finish_calls);
}

test "write grow-root grows GPT and ext4 offline on a larger file stand-in" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source = "test-write-command-grow-source.raw";
    const target = "test-write-command-grow-target.raw";
    const source_size: u64 = 64 * 1024 * 1024;
    const target_size: u64 = 96 * 1024 * 1024;
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRootGptTestImage(allocator, io, source, source_size);
    try createRawTestImageWithSize(io, target, target_size);
    var report = testReport();
    var fake = FakeOperations{ .report = &report, .real_pipeline = true };

    try std.testing.expectEqual(
        @as(u8, 0),
        runWithOperations(
            allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--grow-root", source, target },
            fake.operations(),
        ),
    );
    var destination = try vmiz.Image.openPathReadOnly(io, target);
    defer destination.close(io);
    var gpt = try vmiz.gpt.readVerifiedGpt(
        destination,
        io,
        allocator,
        vmiz.gpt.default_max_partition_array_bytes,
    );
    defer gpt.deinit(allocator);
    const root = try vmiz.root_resize.selectRoot(
        allocator,
        io,
        &destination,
        gpt,
        .{ .require_last_partition = true },
    );
    try std.testing.expectEqual(
        target_size / vmiz.gpt.sector_size -
            vmiz.gpt.partition_array_sectors - 2,
        root.last_lba,
    );
    try std.testing.expectEqual(
        root.partition_length / vmiz.ext4.default_block_size *
            vmiz.ext4.default_block_size,
        root.filesystem_length,
    );
    try std.testing.expectEqual(@as(usize, 1), fake.resize_calls);
}

test "write grow-root accepts an already-full partition and filesystem as a no-op" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-grow-full-source.raw";
    const target = "test-write-command-grow-full-target.raw";
    const size: u64 = 64 * 1024 * 1024;
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRootGptTestImage(std.testing.allocator, io, source, size);
    try createRawTestImageWithSize(io, target, size);
    var report = testReport();
    var fake = FakeOperations{ .report = &report, .real_pipeline = true };

    try std.testing.expectEqual(
        @as(u8, 0),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--grow-root", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dpixrvqf", fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 0), fake.grow_partition_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.resize_calls);
}

test "write grow-root fills a smaller filesystem in a same-size full partition" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-grow-filesystem-source.raw";
    const target = "test-write-command-grow-filesystem-target.raw";
    const size: u64 = 64 * 1024 * 1024;
    const initial_filesystem_length: u64 = 48 * 1024 * 1024;
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRootGptTestImageWithFilesystemLength(
        std.testing.allocator,
        io,
        source,
        size,
        initial_filesystem_length,
    );
    try createRawTestImageWithSize(io, target, size);
    var report = testReport();
    var fake = FakeOperations{ .report = &report, .real_pipeline = true };

    try std.testing.expectEqual(
        @as(u8, 0),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--grow-root", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dpixrevqf", fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 0), fake.grow_partition_calls);
    try std.testing.expectEqual(@as(usize, 1), fake.resize_calls);

    var destination = try vmiz.Image.openPathReadOnly(io, target);
    defer destination.close(io);
    var gpt = try vmiz.gpt.readVerifiedGpt(
        destination,
        io,
        std.testing.allocator,
        vmiz.gpt.default_max_partition_array_bytes,
    );
    defer gpt.deinit(std.testing.allocator);
    const root = try vmiz.root_resize.selectRoot(
        std.testing.allocator,
        io,
        &destination,
        gpt,
        .{ .require_last_partition = true },
    );
    try std.testing.expect(root.filesystem_length > initial_filesystem_length);
    try std.testing.expectEqual(
        root.partition_length / vmiz.ext4.default_block_size *
            vmiz.ext4.default_block_size,
        root.filesystem_length,
    );
}

test "write grow-root rejects selection and ext4 preflight failures before mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-grow-preflight-source.raw";
    const target = "test-write-command-grow-preflight-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createGptTestImage(io, source, 64 * 1024 * 1024);
    try createRawTestImageWithSize(io, target, 96 * 1024 * 1024);
    var report = testReport();

    for ([_]anyerror{
        error.RootFilesystemNotFound,
        error.AmbiguousRootFilesystem,
        error.RootPartitionNotLast,
        error.UnsupportedFeatures,
        error.UnsupportedResizeLayout,
    }) |preflight_error| {
        var fake = FakeOperations{
            .report = &report,
            .plan_root_error = preflight_error,
            .real_pipeline = true,
        };
        try std.testing.expectEqual(
            @as(u8, 1),
            runWithOperations(
                std.testing.allocator,
                io,
                &.{ "--allow-device-write", "--grow-root", source, target },
                fake.operations(),
            ),
        );
        try std.testing.expectEqualStrings("dp", fake.eventSlice());
        try std.testing.expectEqual(@as(usize, 0), fake.confirm_calls);
        try std.testing.expectEqual(@as(usize, 0), fake.invalidate_calls);
    }
}

test "write grow-root failures after mutation are made durable without finalizing" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-grow-errors-source.raw";
    const target = "test-write-command-grow-errors-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRootGptTestImage(std.testing.allocator, io, source, 64 * 1024 * 1024);
    try createRawTestImageWithSize(io, target, 96 * 1024 * 1024);
    var report = testReport();

    var resize_fake = FakeOperations{
        .report = &report,
        .real_pipeline = true,
        .resize_error = error.InputOutput,
    };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--grow-root", source, target },
            resize_fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dpixgeu", resize_fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 0), resize_fake.finish_calls);

    try createRawTestImageWithSize(io, target, 96 * 1024 * 1024);
    var verify_fake = FakeOperations{
        .report = &report,
        .real_pipeline = true,
        .verify_root_error = error.FilesystemIdentityChanged,
    };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--grow-root", source, target },
            verify_fake.operations(),
        ),
    );
    try std.testing.expectEqualStrings("dpixgevqu", verify_fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 0), verify_fake.finish_calls);
}

test "write grow-root preserves refresh partial success" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-grow-refresh-source.raw";
    const target = "test-write-command-grow-refresh-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRootGptTestImage(std.testing.allocator, io, source, 64 * 1024 * 1024);
    try createRawTestImageWithSize(io, target, 96 * 1024 * 1024);
    var report = testReport();
    var fake = FakeOperations{
        .report = &report,
        .real_pipeline = true,
        .outcome = .partition_table_stale_busy,
    };
    try std.testing.expectEqual(
        @as(u8, 2),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--grow-root", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), fake.finish_calls);
}

test "write preflight output inventories the target" {
    var partition = vmiz.block_device.PartitionReport{
        .table_index = 0,
        .first_lba = 2048,
        .last_lba = 4095,
        .name_len = 3,
        .gpt_unique_guid_len = 36,
        .filesystem = .{
            .kind = .fat,
            .identifier_len = 9,
        },
        .signatures = .{ .fat = true },
    };
    @memcpy(partition.name[0..3], "EFI");
    @memcpy(partition.gpt_unique_guid[0..36], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    @memcpy(partition.filesystem.identifier[0..9], "1234-5678");
    var partitions = [_]vmiz.block_device.PartitionReport{partition};
    var report = testReport();
    report.partition_table = .gpt;
    report.device_signatures.ext4 = true;
    report.gpt_disk_guid_len = 36;
    @memcpy(report.gpt_disk_guid[0..36], "99999999-8888-7777-6666-555555555555");
    report.device_filesystem = .{
        .kind = .ext4,
        .identifier_len = 36,
    };
    @memcpy(
        report.device_filesystem.identifier[0..36],
        "11111111-2222-3333-4444-555555555555",
    );
    report.partitions = &partitions;

    const text = try formatPreflightReport(std.testing.allocator, "target", &report);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "transport: usb") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "partition table: gpt") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "disk GUID: 99999999-8888-7777-6666-555555555555") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "device signatures: ext4") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "device filesystem: ext4 11111111-2222-3333-4444-555555555555") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "guid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "name=\"EFI\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "signatures: fat") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "filesystem: fat 1234-5678") != null);
}

test "write source identity output reports visible collisions" {
    var partition = vmiz.block_device.PartitionReport{
        .table_index = 0,
        .first_lba = 2048,
        .last_lba = 4095,
        .gpt_unique_guid_len = 36,
        .filesystem = .{
            .kind = .ext4,
            .identifier_len = 36,
        },
    };
    @memcpy(partition.gpt_unique_guid[0..36], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    @memcpy(
        partition.filesystem.identifier[0..36],
        "11111111-2222-3333-4444-555555555555",
    );
    var partitions = [_]vmiz.block_device.PartitionReport{partition};
    var inventory = vmiz.block_device.IdentityInventory{
        .partition_table = .gpt,
        .partitions = &partitions,
        .device_signatures = .{},
        .gpt_disk_guid_len = 36,
    };
    @memcpy(inventory.gpt_disk_guid[0..36], "99999999-8888-7777-6666-555555555555");

    var collisions = [_]vmiz.block_device.Collision{
        .{
            .kind = .gpt_disk_guid,
            .identifier_len = 36,
            .visible_device_name = @constCast("sdc"),
        },
        .{
            .kind = .gpt_partition_guid,
            .identifier_len = 36,
            .source_partition_table_index = 0,
            .visible_device_name = @constCast("sdc"),
            .visible_partition_table_index = 1,
        },
        .{
            .kind = .filesystem_identifier,
            .identifier_len = 36,
            .source_partition_table_index = 0,
            .source_filesystem = .ext4,
            .visible_device_name = @constCast("sdc"),
            .visible_partition_table_index = 1,
            .visible_filesystem = .xfs,
        },
    };
    @memcpy(collisions[0].identifier[0..36], inventory.gpt_disk_guid[0..36]);
    @memcpy(collisions[1].identifier[0..36], partition.gpt_unique_guid[0..36]);
    @memcpy(collisions[2].identifier[0..36], partition.filesystem.identifier[0..36]);
    const report = vmiz.block_device.CollisionReport{
        .collisions = &collisions,
        .scanned_visible_disks = 2,
    };

    const text = try formatSourceIdentityReport(std.testing.allocator, &inventory, &report);
    defer std.testing.allocator.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "source identity inventory") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "visible-device identifier collisions (2 whole disks scanned)") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "source disk GUID 99999999-8888-7777-6666-555555555555 already exists on sdc") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "source partition 1 GUID aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee already exists on sdc partition 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "source partition 1 ext4 identifier 11111111-2222-3333-4444-555555555555 already exists on sdc partition 2 (xfs)") != null);
}

test "write parses new identity flags and refuses collisions before confirmation or mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-collision-source.raw";
    const target = "test-write-command-collision-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    var report = testReport();
    var fake = FakeOperations{
        .report = &report,
        .source_identity_report_text = "write: source identity inventory:\n  none\n",
        .prepared_collision_count = 1,
    };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--new-uuids", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expect(fake.new_uuids_seen);
    try std.testing.expect(!fake.allow_duplicate_identifiers_seen);
    try std.testing.expectEqual(@as(usize, 0), fake.confirm_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.invalidate_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.copy_calls);
}

test "write allows duplicate identifiers only with an explicit override" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-collision-override-source.raw";
    const target = "test-write-command-collision-override-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    var report = testReport();
    var fake = FakeOperations{
        .report = &report,
        .source_identity_report_text = "write: source identity inventory:\n  none\n",
        .prepared_collision_count = 1,
    };
    try std.testing.expectEqual(
        @as(u8, 0),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{
                "--allow-device-write",
                "--yes",
                "--new-uuids",
                "--allow-duplicate-identifiers",
                source,
                target,
            },
            fake.operations(),
        ),
    );
    try std.testing.expect(fake.new_uuids_seen);
    try std.testing.expect(fake.allow_duplicate_identifiers_seen);
    try std.testing.expectEqual(@as(usize, 1), fake.copy_calls);
}

test "write prepared fresh-identity refusals stop before confirmation or mutation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-prepared-refusal-source.raw";
    const target = "test-write-command-prepared-refusal-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createRawTestImage(io, source);
    try createRawTestImage(io, target);
    var report = testReport();
    var fake = FakeOperations{
        .report = &report,
        .prepared_refusal_message = "--new-uuids left an unrewriteable stale boot reference",
    };
    try std.testing.expectEqual(
        @as(u8, 1),
        runWithOperations(
            std.testing.allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--new-uuids", source, target },
            fake.operations(),
        ),
    );
    try std.testing.expect(fake.new_uuids_seen);
    try std.testing.expectEqual(@as(usize, 0), fake.confirm_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.invalidate_calls);
    try std.testing.expectEqual(@as(usize, 0), fake.copy_calls);
}

test "write new-uuids prepares unique fresh identifiers" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-new-uuids-prepare-source.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    try createFreshIdentityTestImage(std.testing.allocator, io, source, .{});

    var prepared = try prepareFreshIdentityForTest(std.testing.allocator, io, source);
    defer prepared.deinit(std.testing.allocator);
    try std.testing.expect(prepared.refusal_message == null);
    const state: *IdentityRewriteState = @ptrCast(@alignCast(prepared.context.?));
    try std.testing.expect(!vmiz.guid.eql(state.gpt_replacements.?.disk_guid, old_disk_guid));
    try std.testing.expect(state.partitions.len == 2);
    try std.testing.expect(!std.mem.eql(u8, state.partitions[0].new_partition_guid_text, state.partitions[1].new_partition_guid_text));
    try std.testing.expect(!std.mem.eql(u8, state.partitions[0].new_partition_guid_text, state.partitions[0].old_partition_guid_text));
    try std.testing.expect(!std.mem.eql(u8, state.partitions[1].new_partition_guid_text, state.partitions[1].old_partition_guid_text));
    try std.testing.expect(state.partitions[0].new_filesystem_identifier != null);
    try std.testing.expect(state.partitions[1].new_filesystem_identifier != null);
    try std.testing.expect(!std.mem.eql(
        u8,
        state.partitions[0].new_filesystem_identifier.?,
        state.partitions[1].new_filesystem_identifier.?,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        state.partitions[1].new_filesystem_identifier.?,
        old_root_filesystem_uuid_text,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        state.partitions[0].new_filesystem_identifier.?,
        old_esp_volume_id_text,
    ));
}

test "write new-uuids post-write verification rejects an unreworked image" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source = "test-write-command-new-uuids-verify-source.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    try createFreshIdentityTestImage(allocator, io, source, .{});

    var prepared = try prepareFreshIdentityForTest(allocator, io, source);
    defer prepared.deinit(allocator);
    try std.testing.expect(prepared.refusal_message == null);
    const state: *IdentityRewriteState = @ptrCast(@alignCast(prepared.context.?));

    var image = try vmiz.Image.openPathReadOnly(io, source);
    defer image.close(io);
    try std.testing.expectError(
        error.IdentityRewriteVerificationFailed,
        verifyFreshIdentityDestination(allocator, io, &image, state),
    );
}

test "write new-uuids refuses unsupported filesystem inventory" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source_path = "test-write-command-unsupported-fs-source.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source_path) catch {};
    try createFreshIdentityTestImage(allocator, io, source_path, .{ .include_esp = false });

    var source = try vmiz.Image.openPathReadOnly(io, source_path);
    defer source.close(io);
    var inventory = try vmiz.block_device.inspectIdentityInventory(
        allocator,
        io,
        source,
        vmiz.gpt.default_max_partition_array_bytes,
    );
    defer inventory.deinit(allocator);
    inventory.partitions[0].signatures = .{ .ext4 = true, .xfs = true };
    inventory.partitions[0].filesystem.kind = .ambiguous;
    inventory.partitions[0].filesystem.identifier_len = 0;

    var detected = try detectGpt(null, source, io, allocator);
    defer detected.deinit(allocator);
    const verified = switch (detected) {
        .gpt => |gpt| gpt,
        .not_gpt => unreachable,
    };
    var report = testReport();
    const state = try allocator.create(IdentityRewriteState);
    defer {
        state.deinit(allocator);
        allocator.destroy(state);
    }
    state.* = .{};
    const setup = try initializeFreshIdentityState(
        allocator,
        io,
        &source,
        &report,
        &inventory,
        verified,
        null,
        state,
    );
    defer allocator.free(setup.report_text);
    defer if (setup.refusal_message) |message| allocator.free(message);
    try std.testing.expect(setup.refusal_message != null);
    try std.testing.expect(std.mem.indexOf(u8, setup.refusal_message.?, "unsupported signatures") != null);
}

test "write new-uuids refuses stale unsupported boot references" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-stale-boot-source.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    const stale_file = [_]WriteIdentityTestFile{.{
        .path = "boot/loader/entries/vmiz.extra",
        .contents = "options root=UUID=" ++ old_root_filesystem_uuid_text ++ " rootfstype=ext4\n",
    }};
    try createFreshIdentityTestImage(std.testing.allocator, io, source, .{
        .root_extra_files = &stale_file,
    });

    var prepared = try prepareFreshIdentityForTest(std.testing.allocator, io, source);
    defer prepared.deinit(std.testing.allocator);
    try std.testing.expect(prepared.refusal_message != null);
    try std.testing.expect(std.mem.indexOf(u8, prepared.refusal_message.?, "omit --new-uuids") != null);
}

test "write new-uuids refuses immutable or signed UKI references" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const source = "test-write-command-uki-refusal-source.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    const esp_extra = [_]WriteIdentityTestFile{.{
        .path = "EFI/Linux/vmiz.efi",
        .contents = "stub root=UUID=" ++ old_root_filesystem_uuid_text ++ "\n",
    }};
    try createFreshIdentityTestImage(std.testing.allocator, io, source, .{
        .esp_extra_files = &esp_extra,
    });

    var prepared = try prepareFreshIdentityForTest(std.testing.allocator, io, source);
    defer prepared.deinit(std.testing.allocator);
    try std.testing.expect(prepared.refusal_message != null);
    try std.testing.expect(
        std.mem.indexOf(u8, prepared.refusal_message.?, "signed or immutable boot artifacts is unsupported") != null,
    );
}

test "write new-uuids rewrites identities and verifies supported references" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const source = "test-write-command-new-uuids-source.raw";
    const target = "test-write-command-new-uuids-target.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, target) catch {};
    try createFreshIdentityTestImage(allocator, io, source, .{});
    try createRawTestImageWithSize(io, target, 128 * 1024 * 1024);

    var report = testReport();
    var fake = FakeOperations{
        .report = &report,
        .real_pipeline = true,
        .real_prepare_identity = true,
    };
    try std.testing.expectEqual(
        @as(u8, 0),
        runWithOperations(
            allocator,
            io,
            &.{ "--allow-device-write", "--yes", "--new-uuids", source, target },
            fake.operations(),
        ),
    );

    var destination = try vmiz.Image.openPathReadOnly(io, target);
    defer destination.close(io);
    var inventory = try vmiz.block_device.inspectIdentityInventory(
        allocator,
        io,
        destination,
        vmiz.gpt.default_max_partition_array_bytes,
    );
    defer inventory.deinit(allocator);
    try std.testing.expectEqual(vmiz.block_device.PartitionTable.gpt, inventory.partition_table);
    try std.testing.expect(!std.mem.eql(u8, inventory.gptDiskGuid().?, "99999999-8888-7777-6666-555555555555"));

    var esp_partition: ?vmiz.block_device.PartitionReport = null;
    var root_partition: ?vmiz.block_device.PartitionReport = null;
    for (inventory.partitions) |partition| {
        switch (partition.filesystem.kind) {
            .fat => esp_partition = partition,
            .ext4 => root_partition = partition,
            else => {},
        }
    }
    try std.testing.expect(esp_partition != null);
    try std.testing.expect(root_partition != null);
    try std.testing.expect(!std.mem.eql(u8, esp_partition.?.filesystem.identifierText().?, old_esp_volume_id_text));
    try std.testing.expect(!std.mem.eql(u8, root_partition.?.filesystem.identifierText().?, old_root_filesystem_uuid_text));

    const root_offset = root_partition.?.first_lba * vmiz.gpt.sector_size;
    const root_length = (root_partition.?.last_lba - root_partition.?.first_lba + 1) * vmiz.gpt.sector_size;
    const esp_offset = esp_partition.?.first_lba * vmiz.gpt.sector_size;
    const esp_length = (esp_partition.?.last_lba - esp_partition.?.first_lba + 1) * vmiz.gpt.sector_size;

    const fstab = try readExt4PartitionFileAlloc(
        allocator,
        io,
        destination,
        root_offset,
        root_length,
        "etc/fstab",
    );
    defer allocator.free(fstab);
    try std.testing.expect(std.mem.indexOf(u8, fstab, old_root_filesystem_uuid_text) == null);
    try std.testing.expect(std.mem.indexOf(u8, fstab, old_esp_volume_id_text) == null);
    try std.testing.expect(std.mem.indexOf(u8, fstab, root_partition.?.filesystem.identifierText().?) != null);
    try std.testing.expect(std.mem.indexOf(u8, fstab, esp_partition.?.filesystem.identifierText().?) != null);

    const cmdline = try readExt4PartitionFileAlloc(
        allocator,
        io,
        destination,
        root_offset,
        root_length,
        "etc/kernel/cmdline",
    );
    defer allocator.free(cmdline);
    try std.testing.expect(std.mem.indexOf(u8, cmdline, old_root_filesystem_uuid_text) == null);
    try std.testing.expect(std.mem.indexOf(u8, cmdline, root_partition.?.filesystem.identifierText().?) != null);

    const esp_cfg = try readFatPartitionFileAlloc(
        allocator,
        io,
        &destination,
        esp_offset,
        esp_length,
        "EFI/vmiz/grub.cfg",
    );
    defer allocator.free(esp_cfg);
    try std.testing.expect(std.mem.indexOf(u8, esp_cfg, old_root_filesystem_uuid_text) == null);
    try std.testing.expect(std.mem.indexOf(u8, esp_cfg, root_partition.?.filesystem.identifierText().?) != null);
}
