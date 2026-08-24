//! `vmiz write --allow-device-write [--yes] <source> <block-device>`

const std = @import("std");
const builtin = @import("builtin");
const vmiz = @import("vmiz");

const help_text =
    \\usage: vmiz write --allow-device-write [--yes] <source> <block-device>
    \\
    \\Writes a raw, VHD, VHDX, or qcow2 image directly to an existing Linux
    \\block device. The source format is detected automatically.
    \\
    \\  --allow-device-write  Required acknowledgement that the destination
    \\                        device will be overwritten.
    \\  --yes                 Skip the final interactive confirmation.
    \\
    \\The command checks the target while it is read-only, refuses a target
    \\that is too small or in use, writes zero regions explicitly, flushes the
    \\device, and asks the kernel to re-read its partition table. A stale
    \\kernel partition view is reported as partial success with exit status 2.
    \\The separate `vmiz convert` command remains unable to write devices.
    \\
;

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
    source_identity_report_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
        std.Io,
        *const vmiz.Image,
        *const vmiz.DevicePreflightReport,
    ) anyerror![]u8 = sourceIdentityReport,
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
    verify_fn: *const fn (
        ?*anyopaque,
        vmiz.Image,
        std.Io,
        std.mem.Allocator,
    ) anyerror!vmiz.gpt.VerifiedGpt = verifyGpt,
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
    var positional: [2][]const u8 = undefined;
    var positional_count: usize = 0;

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--allow-device-write")) {
            allow_device_write = true;
        } else if (std.mem.eql(u8, arg, "--yes")) {
            yes = true;
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

    const source_report_text = operations.source_identity_report_fn(
        operations.context,
        gpa,
        io,
        &source,
        report,
    ) catch |err| {
        return fail(
            "write: source identity inspection failed: {s}; no data was written",
            .{@errorName(err)},
        );
    };
    defer gpa.free(source_report_text);
    if (source_report_text.len != 0) std.debug.print("{s}", .{source_report_text});

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
        return fail(
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
        return fail(
            "write: data copy failed: {s}; the device may be partially written",
            .{@errorName(err)},
        );
    };

    switch (detected) {
        .not_gpt => {},
        .verified => |verified| {
            const relocation = operations.relocate_fn(
                operations.context,
                &destination,
                io,
                gpa,
                verified,
            ) catch |err| {
                return fail(
                    "write: backup GPT relocation failed: {s}; the device was copied but may contain incomplete GPT metadata",
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

            var destination_gpt = operations.verify_fn(
                operations.context,
                destination,
                io,
                gpa,
            ) catch |err| {
                return fail(
                    "write: destination GPT verification failed after copy: {s}; the device was modified",
                    .{@errorName(err)},
                );
            };
            defer destination_gpt.deinit(gpa);
            if (!std.mem.eql(
                u8,
                verified.partition_array,
                destination_gpt.partition_array,
            )) {
                return fail(
                    "write: destination GPT verification failed after copy: opaque partition array changed; the device was modified",
                    .{},
                );
            }
        },
    }

    const outcome = (operations.finish_fn(
        operations.context,
        &destination,
        io,
    ) catch |err| {
        return fail(
            "write: device finalization failed: {s}; the device was modified",
            .{@errorName(err)},
        );
    }) orelse return fail(
        "write: device finalization did not report an outcome; the device may be partially written",
        .{},
    );

    if (outcome.warning()) |warning| {
        std.debug.print("write: partial success: {s}\n", .{warning});
        return 2;
    }
    std.debug.print(
        "write: wrote and flushed {d} bytes. {s}\n",
        .{ source.virtual_size, outcome.message() },
    );
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

fn sourceIdentityReport(
    _: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *const vmiz.Image,
    destination_report: *const vmiz.DevicePreflightReport,
) anyerror![]u8 {
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

    return formatSourceIdentityReport(allocator, &inventory, &collisions);
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

fn finishDeviceWrite(
    _: ?*anyopaque,
    destination: *vmiz.Image,
    io: std.Io,
) anyerror!?vmiz.DeviceWriteOutcome {
    return destination.finishDeviceWrite(io);
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
            try writeCollision(writer, collision);
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
    try writer.writeAll("  ");
    switch (collision.kind) {
        .gpt_disk_guid => try writer.print(
            "source disk GUID {s} already exists on {s}\n",
            .{ collision.identifierText(), collision.visible_device_name },
        ),
        .gpt_partition_guid => try writer.print(
            "source partition {d} GUID {s} already exists on {s} partition {d}\n",
            .{
                collision.source_partition_table_index.? + 1,
                collision.identifierText(),
                collision.visible_device_name,
                collision.visible_partition_table_index.? + 1,
            },
        ),
        .filesystem_identifier => {
            if (collision.source_partition_table_index) |source_partition| {
                try writer.print(
                    "source partition {d} {s} identifier {s} already exists on {s}",
                    .{
                        source_partition + 1,
                        @tagName(collision.source_filesystem),
                        collision.identifierText(),
                        collision.visible_device_name,
                    },
                );
            } else {
                try writer.print(
                    "source device {s} identifier {s} already exists on {s}",
                    .{
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
    verify_error: ?anyerror = null,
    finish_error: ?anyerror = null,
    outcome: ?vmiz.DeviceWriteOutcome = .partition_table_refreshed,
    report: ?*const vmiz.DevicePreflightReport = null,
    source_identity_report_text: []const u8 = "",
    confirm_result: bool = true,
    expected_format: ?vmiz.Format = null,
    open_calls: usize = 0,
    confirm_calls: usize = 0,
    detect_calls: usize = 0,
    invalidate_calls: usize = 0,
    copy_calls: usize = 0,
    finish_calls: usize = 0,
    allow_device_write_seen: bool = false,
    real_pipeline: bool = false,
    events: [8]u8 = undefined,
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

    fn sourceIdentityReportFake(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        _: std.Io,
        _: *const vmiz.Image,
        _: *const vmiz.DevicePreflightReport,
    ) anyerror![]u8 {
        const self: *FakeOperations = @ptrCast(@alignCast(context.?));
        return allocator.dupe(u8, self.source_identity_report_text);
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
            .source_identity_report_fn = sourceIdentityReportFake,
            .confirm_fn = confirmFake,
            .detect_gpt_fn = detectGptFake,
            .invalidate_fn = invalidateFake,
            .copy_fn = copyFake,
            .relocate_fn = relocateFake,
            .verify_fn = verifyFake,
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
    var image = try vmiz.Image.create(io, path, .raw, 16 * 1024 * 1024, .{});
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
    try std.testing.expectEqualStrings("dix", fake.eventSlice());
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
    try std.testing.expectEqualStrings("di", invalidate_fake.eventSlice());

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
    try std.testing.expectEqualStrings("dixf", finish_fake.eventSlice());
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
    try std.testing.expectEqualStrings("dixr", relocate_fake.eventSlice());
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
    try std.testing.expectEqualStrings("dixrv", verify_fake.eventSlice());
    try std.testing.expectEqual(@as(usize, 0), verify_fake.finish_calls);
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
