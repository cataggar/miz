//! Preflight and post-copy fitting for virtual disk images.
//!
//! GPT metadata is validated and retained before a caller starts a destructive
//! copy. After the copy, the same plan can relocate the backup GPT, grow the
//! partition that is physically last by LBA, and optionally grow ext4.

const std = @import("std");
const Io = std.Io;
const ext4 = @import("ext4.zig");
const gpt = @import("gpt.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const mbr = @import("mbr.zig");

pub const default_max_partition_array_bytes: u64 = 1024 * 1024;

pub const Options = struct {
    relocate_backup: bool = false,
    grow_partition: bool = false,
    grow_filesystem: bool = false,

    fn requested(self: Options) bool {
        return self.relocate_backup or self.grow_partition or
            self.grow_filesystem;
    }
};

pub const TableKind = enum {
    gpt,
    mbr,
    none,
};

pub const GptMetadata = struct {
    verified: gpt.VerifiedGpt,
    last_partition: ?gpt.PartitionEntry,
    filesystem_length: ?u64 = null,
};

pub const Table = union(TableKind) {
    gpt: GptMetadata,
    mbr,
    none,
};

pub const Plan = struct {
    source_virtual_size: u64,
    options: Options,
    table: Table,

    pub fn kind(self: *const Plan) TableKind {
        return self.table;
    }

    pub fn selectedPartition(self: *const Plan) ?gpt.PartitionEntry {
        return switch (self.table) {
            .gpt => |metadata| metadata.last_partition,
            .mbr, .none => null,
        };
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        switch (self.table) {
            .gpt => |*metadata| metadata.verified.deinit(allocator),
            .mbr, .none => {},
        }
        self.* = undefined;
    }
};

pub const Report = struct {
    table_kind: TableKind,
    relocated_backup: bool = false,
    partition_grown: bool = false,
    filesystem_grown: bool = false,
    selected_table_index: ?u32 = null,
    old_partition_last_lba: ?u64 = null,
    new_partition_last_lba: ?u64 = null,
    old_filesystem_length: ?u64 = null,
    new_filesystem_length: ?u64 = null,
};

const ReadContext = struct {
    image: *const Image,
    io: Io,
};

fn readImageAt(
    context: *const anyopaque,
    io: Io,
    buffer: []u8,
    offset: u64,
) anyerror!usize {
    const read_context: *const ReadContext = @ptrCast(@alignCast(context));
    _ = io;
    return read_context.image.pread(read_context.io, buffer, offset);
}

fn readSector(image: Image, io: Io) ![mbr.sector_size]u8 {
    var sector: [mbr.sector_size]u8 = undefined;
    if (try image.pread(io, &sector, 0) != sector.len) {
        return error.UnexpectedEndOfFile;
    }
    return sector;
}

fn lastPartition(partitions: []const gpt.PartitionEntry) ?gpt.PartitionEntry {
    var selected: ?gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (partition.isEmpty()) continue;
        if (selected == null or partition.last_lba > selected.?.last_lba) {
            selected = partition;
        }
    }
    return selected;
}

fn ext4Length(
    allocator: std.mem.Allocator,
    io: Io,
    image: *const Image,
    offset: u64,
) !u64 {
    var context = ReadContext{ .image = image, .io = io };
    var reader = ext4.Reader.openReadOnlySource(
        io,
        image.file,
        .{ .ctx = &context, .read_at_fn = readImageAt },
        allocator,
        .{ .offset = offset },
    ) catch |err| switch (err) {
        error.BadMagic => return error.UnrecognizedFilesystem,
        error.UnsupportedBlockSize,
        error.UnsupportedDescriptorSize,
        error.UnsupportedFeatures,
        error.UnsupportedInodeSize,
        error.UnsupportedRevision,
        => return error.UnsupportedFilesystem,
        else => return err,
    };
    defer reader.deinit();
    return std.math.mul(
        u64,
        reader.total_blocks,
        reader.block_size,
    ) catch error.FilesystemTooLarge;
}

fn partitionOffset(partition: gpt.PartitionEntry) !u64 {
    return std.math.mul(
        u64,
        partition.first_lba,
        gpt.sector_size,
    ) catch error.InvalidPartitionBounds;
}

fn partitionLength(partition: gpt.PartitionEntry) !u64 {
    const sectors = std.math.add(
        u64,
        partition.last_lba - partition.first_lba,
        1,
    ) catch return error.InvalidPartitionBounds;
    return std.math.mul(
        u64,
        sectors,
        gpt.sector_size,
    ) catch error.InvalidPartitionBounds;
}

/// Classifies a source through its guest-visible bytes. A protective MBR is
/// treated as a GPT claim and therefore must pass strict validation of both
/// headers and both partition arrays before this function succeeds.
pub fn preflight(
    allocator: std.mem.Allocator,
    io: Io,
    source: Image,
    options: Options,
    max_partition_array_bytes: u64,
) !Plan {
    if (options.grow_filesystem and !options.grow_partition) {
        return error.FilesystemGrowthRequiresPartitionGrowth;
    }

    const sector = readSector(source, io) catch |err| switch (err) {
        error.UnexpectedEndOfFile => {
            if (options.requested()) return error.UnsupportedPartitionTable;
            return .{
                .source_virtual_size = source.virtual_size,
                .options = options,
                .table = .none,
            };
        },
        else => return err,
    };
    const decoded = mbr.Mbr.decode(&sector) catch |err| switch (err) {
        error.BadBootSignature => {
            if (options.requested()) return error.UnsupportedPartitionTable;
            return .{
                .source_virtual_size = source.virtual_size,
                .options = options,
                .table = .none,
            };
        },
    };

    var has_protective = false;
    var has_partition = false;
    for (decoded.entries) |entry| {
        if (entry.partition_type == .gpt_protective) has_protective = true;
        if (entry.partition_type != .empty) has_partition = true;
    }
    if (!has_protective) {
        if (!has_partition and options.requested()) {
            return error.UnsupportedPartitionTable;
        }
        return .{
            .source_virtual_size = source.virtual_size,
            .options = options,
            .table = if (has_partition) .mbr else .none,
        };
    }

    var verified = try gpt.readVerifiedGpt(
        source,
        io,
        allocator,
        max_partition_array_bytes,
    );
    errdefer verified.deinit(allocator);
    const selected = lastPartition(verified.partitions);
    if ((options.grow_partition or options.grow_filesystem) and selected == null) {
        return error.NoPartitions;
    }

    var filesystem_length: ?u64 = null;
    if (options.grow_filesystem) {
        const partition = selected.?;
        const length = try ext4Length(
            allocator,
            io,
            &source,
            try partitionOffset(partition),
        );
        if (length > try partitionLength(partition)) {
            return error.FilesystemExceedsPartition;
        }
        filesystem_length = length;
    }

    return .{
        .source_virtual_size = source.virtual_size,
        .options = options,
        .table = .{ .gpt = .{
            .verified = verified,
            .last_partition = selected,
            .filesystem_length = filesystem_length,
        } },
    };
}

/// Applies a preflighted fit after the source bytes have been copied to
/// `destination`. Plain MBR images are intentionally always passed through.
pub fn apply(
    allocator: std.mem.Allocator,
    io: Io,
    destination: *Image,
    plan: *const Plan,
) !Report {
    if (destination.virtual_size < plan.source_virtual_size) {
        return error.DestinationTooSmall;
    }

    var report = Report{ .table_kind = plan.kind() };
    switch (plan.table) {
        .mbr, .none => return report,
        .gpt => |metadata| {
            if (plan.options.grow_filesystem and destination.format != .raw) {
                return error.FilesystemGrowthRequiresRawDestination;
            }
            const selected = metadata.last_partition;
            report.selected_table_index = if (selected) |partition|
                partition.table_index
            else
                null;

            if (plan.options.grow_partition) {
                const partition = selected orelse return error.NoPartitions;
                const result = try gpt.growPartitionToEnd(
                    destination,
                    io,
                    allocator,
                    metadata.verified,
                    partition.table_index,
                );
                report.relocated_backup = result.relocation.was_relocated;
                report.partition_grown = result.new_last_lba != result.old_last_lba;
                report.old_partition_last_lba = result.old_last_lba;
                report.new_partition_last_lba = result.new_last_lba;

                if (plan.options.grow_filesystem) {
                    const offset = try partitionOffset(partition);
                    const actual_old_length = try ext4Length(
                        allocator,
                        io,
                        destination,
                        offset,
                    );
                    if (actual_old_length != metadata.filesystem_length.?) {
                        return error.FilesystemChangedAfterPreflight;
                    }

                    const grown = gpt.PartitionEntry{
                        .first_lba = partition.first_lba,
                        .last_lba = result.new_last_lba,
                    };
                    const partition_length = try partitionLength(grown);
                    const new_length = partition_length -
                        (partition_length % ext4.default_block_size);
                    if (new_length <= actual_old_length) {
                        return error.NotEnoughFilesystemSpace;
                    }
                    _ = try ext4.resize(io, destination.file, allocator, .{
                        .offset = offset,
                        .length = new_length,
                    });
                    report.filesystem_grown = true;
                    report.old_filesystem_length = actual_old_length;
                    report.new_filesystem_length = new_length;
                }
            } else if (plan.options.relocate_backup) {
                const result = try gpt.relocateBackup(
                    destination,
                    io,
                    allocator,
                    metadata.verified,
                );
                report.relocated_backup = result.was_relocated;
            }
            return report;
        },
    }
}

test "preflight classifies MBR through virtual VHD reads and passes fit options through" {
    const io = std.testing.io;
    const path = "test-disk-fit-mbr.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var image = try Image.create(io, path, .vhd, 16 * 1024 * 1024, .{});
    defer image.close(io);
    const sector = mbr.singleLinuxPartitionMbr(2048, 4096).encode();
    try image.pwrite(io, &sector, 0);

    var plan = try preflight(
        std.testing.allocator,
        io,
        image,
        .{
            .relocate_backup = true,
            .grow_partition = true,
            .grow_filesystem = true,
        },
        default_max_partition_array_bytes,
    );
    defer plan.deinit(std.testing.allocator);
    try std.testing.expectEqual(TableKind.mbr, plan.kind());
    const report = try apply(std.testing.allocator, io, &image, &plan);
    try std.testing.expectEqual(TableKind.mbr, report.table_kind);
    try std.testing.expect(!report.relocated_backup);
    try std.testing.expect(!report.partition_grown);
}

test "preflight distinguishes an unrecognized partition table" {
    const io = std.testing.io;
    const path = "test-disk-fit-none.raw";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var image = try Image.create(io, path, .raw, 1024 * 1024, .{});
    defer image.close(io);
    var plan = try preflight(
        std.testing.allocator,
        io,
        image,
        .{},
        default_max_partition_array_bytes,
    );
    defer plan.deinit(std.testing.allocator);
    try std.testing.expectEqual(TableKind.none, plan.kind());
    try std.testing.expectError(
        error.UnsupportedPartitionTable,
        preflight(
            std.testing.allocator,
            io,
            image,
            .{ .relocate_backup = true },
            default_max_partition_array_bytes,
        ),
    );
}

test "last GPT partition is selected by greatest last_lba rather than table order" {
    const linux = @import("guid.zig").linux_filesystem_data;
    const partitions = [_]gpt.PartitionEntry{
        .{
            .partition_type_guid = linux,
            .table_index = 7,
            .first_lba = 2048,
            .last_lba = 8191,
        },
        .{
            .partition_type_guid = linux,
            .table_index = 2,
            .first_lba = 32768,
            .last_lba = 65535,
        },
        .{
            .partition_type_guid = linux,
            .table_index = 9,
            .first_lba = 16384,
            .last_lba = 24575,
        },
    };
    const selected = lastPartition(&partitions).?;
    try std.testing.expectEqual(@as(u32, 2), selected.table_index);
    try std.testing.expectEqual(@as(u64, 65535), selected.last_lba);
}

test "GPT orchestration grows the true last partition on a sparse 4 TiB target" {
    const io = std.testing.io;
    const path = "test-disk-fit-sparse-4tib.raw";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const source_size: u64 = 64 * 1024 * 1024;
    const target_size: u64 = 4 * 1024 * 1024 * 1024 * 1024;
    var image = try Image.create(io, path, .raw, source_size, .{});
    defer image.close(io);
    const specs = [_]gpt.PlacedPartitionSpec{
        .{
            .type_guid = @import("guid.zig").linux_filesystem_data,
            .unique_guid = @import("guid.zig").parse("11111111-1111-1111-1111-111111111111"),
            .placement = .{ .first_lba = 32768, .last_lba = 65535 },
        },
        .{
            .type_guid = @import("guid.zig").esp,
            .unique_guid = @import("guid.zig").parse("22222222-2222-2222-2222-222222222222"),
            .placement = .{ .first_lba = 2048, .last_lba = 8191 },
        },
    };
    // writeGptPlaced requires LBA order, while the selection invariant itself
    // is covered independently above.
    const ordered = [_]gpt.PlacedPartitionSpec{ specs[1], specs[0] };
    try gpt.writeGptPlaced(
        &image,
        io,
        @import("guid.zig").parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        &ordered,
    );

    var plan = try preflight(
        std.testing.allocator,
        io,
        image,
        .{ .grow_partition = true },
        default_max_partition_array_bytes,
    );
    defer plan.deinit(std.testing.allocator);
    try image.resize(io, target_size);
    const report = try apply(std.testing.allocator, io, &image, &plan);
    try std.testing.expect(report.relocated_backup);
    try std.testing.expect(report.partition_grown);

    var verified = try gpt.readVerifiedGpt(
        image,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer verified.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        target_size / gpt.sector_size - 1,
        verified.primary_header.backup_lba,
    );
    try std.testing.expectEqual(
        target_size / gpt.sector_size - 34,
        lastPartition(verified.partitions).?.last_lba,
    );
}

test "filesystem growth rejects unrecognized data during preflight" {
    const io = std.testing.io;
    const path = "test-disk-fit-not-ext4.raw";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var image = try Image.create(io, path, .raw, 64 * 1024 * 1024, .{});
    defer image.close(io);
    const specs = [_]gpt.PlacedPartitionSpec{.{
        .type_guid = @import("guid.zig").linux_filesystem_data,
        .unique_guid = @import("guid.zig").parse("33333333-3333-3333-3333-333333333333"),
        .placement = .{ .first_lba = 2048, .last_lba = 65535 },
    }};
    try gpt.writeGptPlaced(
        &image,
        io,
        @import("guid.zig").parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff"),
        &specs,
    );
    try std.testing.expectError(
        error.UnrecognizedFilesystem,
        preflight(
            std.testing.allocator,
            io,
            image,
            .{ .grow_partition = true, .grow_filesystem = true },
            default_max_partition_array_bytes,
        ),
    );
}

const EmptyTree = struct {
    fn next(_: *anyopaque) @import("tree_cursor.zig").Cursor.IteratorError!?@import("tree_cursor.zig").Cursor.Entry {
        return null;
    }

    fn reset(_: *anyopaque) void {}

    fn cursor(self: *EmptyTree) @import("tree_cursor.zig").Cursor {
        return .{
            .ctx = self,
            .next_fn = next,
            .reset_fn = reset,
        };
    }
};

test "filesystem growth validates ext4 and resizes it after partition growth" {
    const io = std.testing.io;
    const path = "test-disk-fit-ext4.raw";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const source_size: u64 = 128 * 1024 * 1024;
    const target_size: u64 = 256 * 1024 * 1024;
    const first_lba: u64 = 2048;
    const old_last_lba: u64 = 196607;
    const filesystem_length: u64 = 64 * 1024 * 1024;
    var image = try Image.create(io, path, .raw, source_size, .{});
    defer image.close(io);
    const specs = [_]gpt.PlacedPartitionSpec{.{
        .type_guid = @import("guid.zig").linux_filesystem_data,
        .unique_guid = @import("guid.zig").parse("44444444-4444-4444-4444-444444444444"),
        .placement = .{ .first_lba = first_lba, .last_lba = old_last_lba },
    }};
    try gpt.writeGptPlaced(
        &image,
        io,
        @import("guid.zig").parse("cccccccc-dddd-eeee-ffff-000000000000"),
        &specs,
    );
    var empty = EmptyTree{};
    var cursor = empty.cursor();
    _ = try ext4.populate(io, image.file, std.testing.allocator, &cursor, .{
        .offset = first_lba * gpt.sector_size,
        .length = filesystem_length,
    });

    var plan = try preflight(
        std.testing.allocator,
        io,
        image,
        .{ .grow_partition = true, .grow_filesystem = true },
        default_max_partition_array_bytes,
    );
    defer plan.deinit(std.testing.allocator);
    try image.resize(io, target_size);
    const report = try apply(std.testing.allocator, io, &image, &plan);
    try std.testing.expect(report.partition_grown);
    try std.testing.expect(report.filesystem_grown);
    try std.testing.expectEqual(filesystem_length, report.old_filesystem_length.?);

    var reader = try ext4.Reader.open(
        io,
        image.file,
        std.testing.allocator,
        .{ .offset = first_lba * gpt.sector_size },
    );
    defer reader.deinit();
    try std.testing.expectEqual(
        report.new_filesystem_length.?,
        @as(u64, reader.total_blocks) * reader.block_size,
    );
}
