//! Transactional, native growth for an existing Ubuntu-style QCOW2 image.
//!
//! The source is copied to a private raw staging image, where GPT and ext4
//! can use their native positional writers. The completed raw image is then
//! copied into a QCOW2 staging file and atomically published over the source.
//! A failure therefore leaves the caller's image untouched.

const std = @import("std");
const Io = std.Io;
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const ext4 = @import("ext4.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");

pub const default_filesystem_label: []const u8 = "cloudimg-rootfs";
pub const max_partition_array_bytes: u64 = 1024 * 1024;

pub const Options = struct {
    target_size: u64,
    filesystem_label: []const u8 = default_filesystem_label,
};

pub const Report = struct {
    old_virtual_size: u64,
    new_virtual_size: u64,
    root_table_index: u32,
    root_offset: u64,
    old_root_length: u64,
    new_root_length: u64,
    new_filesystem_length: u64,
    filesystem_uuid: [16]u8,
    filesystem_label: [16]u8,
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

fn temporarySiblingPath(
    allocator: std.mem.Allocator,
    io: Io,
    destination: []const u8,
    purpose: []const u8,
) ![]u8 {
    var random: [8]u8 = undefined;
    Io.random(io, &random);
    const token = std.mem.readInt(u64, &random, .little);
    const directory = std.fs.path.dirname(destination) orelse ".";
    const basename = std.fs.path.basename(destination);
    const temporary_name = try std.fmt.allocPrint(
        allocator,
        ".{s}.vmiz-{s}-{x}",
        .{ basename, purpose, token },
    );
    defer allocator.free(temporary_name);
    return std.fs.path.join(allocator, &.{ directory, temporary_name });
}

fn labelBytes(label: *const [16]u8) []const u8 {
    for (label, 0..) |byte, index| {
        if (byte == 0) return label[0..index];
    }
    return label[0..];
}

fn supportedRootType(type_guid: guid.Guid) bool {
    return std.mem.eql(u8, &type_guid, &guid.linux_root_x86_64) or
        std.mem.eql(u8, &type_guid, &guid.linux_root_aarch64) or
        std.mem.eql(u8, &type_guid, &guid.linux_filesystem_data);
}

const RootSelection = struct {
    partition: gpt.PartitionEntry,
    reader_uuid: [16]u8,
    reader_label: [16]u8,
    reader_feature_compat: u32,
    reader_feature_incompat: u32,
    reader_feature_ro_compat: u32,
};

fn selectRoot(
    allocator: std.mem.Allocator,
    io: Io,
    image: *const Image,
    parsed: gpt.VerifiedGpt,
    filesystem_label: []const u8,
) !RootSelection {
    if (filesystem_label.len == 0 or filesystem_label.len > 16) {
        return error.InvalidFilesystemLabel;
    }

    var context = ReadContext{ .image = image, .io = io };
    var selected: ?RootSelection = null;
    for (parsed.partitions) |partition| {
        if (!supportedRootType(partition.partition_type_guid)) continue;
        const offset = std.math.mul(
            u64,
            partition.first_lba,
            gpt.sector_size,
        ) catch return error.InvalidPartitionBounds;
        var reader = ext4.Reader.openReadOnlySource(
            io,
            image.file,
            .{
                .ctx = &context,
                .read_at_fn = readImageAt,
            },
            allocator,
            .{ .offset = offset },
        ) catch |err| switch (err) {
            error.BadMagic => continue,
            else => return err,
        };
        defer reader.deinit();

        if (!std.mem.eql(u8, labelBytes(&reader.label), filesystem_label)) {
            continue;
        }
        if (selected != null) return error.AmbiguousRootFilesystem;

        const partition_length = std.math.mul(
            u64,
            partition.last_lba - partition.first_lba + 1,
            gpt.sector_size,
        ) catch return error.InvalidPartitionBounds;
        const filesystem_length = std.math.mul(
            u64,
            reader.total_blocks,
            reader.block_size,
        ) catch return error.FilesystemTooLarge;
        if (filesystem_length > partition_length) {
            return error.FilesystemExceedsPartition;
        }
        selected = .{
            .partition = partition,
            .reader_uuid = reader.uuid,
            .reader_label = reader.label,
            .reader_feature_compat = reader.feature_compat,
            .reader_feature_incompat = reader.feature_incompat,
            .reader_feature_ro_compat = reader.feature_ro_compat,
        };
    }
    return selected orelse error.RootFilesystemNotFound;
}

fn expectFilesystemIdentity(
    allocator: std.mem.Allocator,
    io: Io,
    image: *const Image,
    offset: u64,
    expected: RootSelection,
    expected_length: u64,
) !void {
    var context = ReadContext{ .image = image, .io = io };
    var reader = try ext4.Reader.openReadOnlySource(
        io,
        image.file,
        .{
            .ctx = &context,
            .read_at_fn = readImageAt,
        },
        allocator,
        .{ .offset = offset },
    );
    defer reader.deinit();
    if (!std.mem.eql(u8, &reader.uuid, &expected.reader_uuid) or
        !std.mem.eql(u8, &reader.label, &expected.reader_label) or
        reader.feature_compat != expected.reader_feature_compat or
        reader.feature_incompat != expected.reader_feature_incompat or
        reader.feature_ro_compat != expected.reader_feature_ro_compat)
    {
        return error.FilesystemIdentityChanged;
    }
    const actual_length = std.math.mul(
        u64,
        reader.total_blocks,
        reader.block_size,
    ) catch return error.FilesystemTooLarge;
    if (actual_length != expected_length) return error.FilesystemLengthMismatch;
}

/// Grows an existing standalone QCOW2 image in place and publishes the
/// completed result atomically. The selected ext4 root is found by its
/// validated filesystem label, not by a partition number.
pub fn growExistingQcow2(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    options: Options,
) !Report {
    if (options.target_size == 0 or options.target_size % gpt.sector_size != 0) {
        return error.InvalidTargetSize;
    }

    var source = try Image.openPathReadOnlyStandalone(io, path);
    var source_open = true;
    defer if (source_open) source.close(io);
    if (source.format != .qcow2) return error.UnsupportedFormat;
    if (options.target_size <= source.virtual_size) return error.ImageDidNotGrow;
    const old_virtual_size = source.virtual_size;

    var source_gpt = try gpt.readVerifiedGpt(
        source,
        io,
        allocator,
        max_partition_array_bytes,
    );
    defer source_gpt.deinit(allocator);
    const root = try selectRoot(
        allocator,
        io,
        &source,
        source_gpt,
        options.filesystem_label,
    );
    for (source_gpt.partitions) |partition| {
        if (partition.table_index != root.partition.table_index and
            partition.last_lba > root.partition.last_lba)
        {
            return error.RootPartitionNotLast;
        }
    }

    const root_offset = std.math.mul(
        u64,
        root.partition.first_lba,
        gpt.sector_size,
    ) catch return error.InvalidPartitionBounds;
    const old_root_length = std.math.mul(
        u64,
        root.partition.last_lba - root.partition.first_lba + 1,
        gpt.sector_size,
    ) catch return error.InvalidPartitionBounds;

    const raw_path = try temporarySiblingPath(allocator, io, path, "raw");
    defer allocator.free(raw_path);
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    var raw = try Image.createExclusive(
        io,
        raw_path,
        .raw,
        options.target_size,
        .{},
    );
    var raw_open = true;
    defer if (raw_open) raw.close(io);

    try image_mod.copyAll(io, source, &raw, allocator);
    const grow_result = try gpt.growPartitionToEnd(
        &raw,
        io,
        allocator,
        source_gpt,
        root.partition.table_index,
    );

    const grown_root_last_lba = grow_result.new_last_lba;
    const new_root_length = std.math.mul(
        u64,
        grown_root_last_lba - root.partition.first_lba + 1,
        gpt.sector_size,
    ) catch return error.InvalidPartitionBounds;
    const new_filesystem_length = new_root_length -
        (new_root_length % ext4.default_block_size);
    if (new_filesystem_length == 0) return error.FilesystemTooSmall;
    _ = try ext4.resize(io, raw.file, allocator, .{
        .offset = root_offset,
        .length = new_filesystem_length,
    });

    var raw_gpt = try gpt.readVerifiedGpt(
        raw,
        io,
        allocator,
        max_partition_array_bytes,
    );
    defer raw_gpt.deinit(allocator);
    var grown_partition: ?gpt.PartitionEntry = null;
    for (raw_gpt.partitions) |partition| {
        if (partition.table_index == root.partition.table_index) {
            grown_partition = partition;
            break;
        }
    }
    const final_partition = grown_partition orelse return error.RootFilesystemNotFound;
    if (final_partition.last_lba != grown_root_last_lba) {
        return error.PartitionGeometryMismatch;
    }
    try expectFilesystemIdentity(
        allocator,
        io,
        &raw,
        root_offset,
        root,
        new_filesystem_length,
    );

    raw.close(io);
    raw_open = false;
    var raw_source = try Image.openPathReadOnly(io, raw_path);
    defer raw_source.close(io);

    const output_path = try temporarySiblingPath(allocator, io, path, "output");
    defer allocator.free(output_path);
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    var output = try Image.createExclusive(
        io,
        output_path,
        .qcow2,
        options.target_size,
        .{},
    );
    var output_open = true;
    defer if (output_open) output.close(io);
    try image_mod.copyAll(io, raw_source, &output, allocator);

    const check = try output.check(io);
    if (!check.ok) return error.FinalImageInvalid;
    var output_gpt = try gpt.readVerifiedGpt(
        output,
        io,
        allocator,
        max_partition_array_bytes,
    );
    defer output_gpt.deinit(allocator);
    try expectFilesystemIdentity(
        allocator,
        io,
        &output,
        root_offset,
        root,
        new_filesystem_length,
    );
    try output.file.sync(io);
    output.close(io);
    output_open = false;
    source.close(io);
    source_open = false;
    try Io.Dir.cwd().rename(output_path, Io.Dir.cwd(), path, io);

    return .{
        .old_virtual_size = old_virtual_size,
        .new_virtual_size = options.target_size,
        .root_table_index = root.partition.table_index,
        .root_offset = root_offset,
        .old_root_length = old_root_length,
        .new_root_length = new_root_length,
        .new_filesystem_length = new_filesystem_length,
        .filesystem_uuid = root.reader_uuid,
        .filesystem_label = root.reader_label,
    };
}

test "grows a labeled root in a standalone QCOW2 transactionally" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const raw_path = "test-root-resize-source.raw";
    const qcow_path = "test-root-resize-source.qcow2";
    const raw_stage_path = qcow_path ++ ".vmiz-root-resize-raw";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, qcow_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_stage_path) catch {};

    const old_size: u64 = 128 * 1024 * 1024;
    const new_size: u64 = 256 * 1024 * 1024;
    const root_first_lba: u64 = 4096;
    const old_last_usable = old_size / gpt.sector_size - 2 - gpt.partition_array_sectors;
    const root_last_lba = old_last_usable - 7;
    const root_offset = root_first_lba * gpt.sector_size;
    const root_length = (root_last_lba - root_first_lba + 1) * gpt.sector_size;
    const filesystem_uuid = [_]u8{0x41} ** 16;

    var raw = try Image.create(io, raw_path, .raw, old_size, .{});
    var raw_open = true;
    defer if (raw_open) raw.close(io);
    const specs = [_]gpt.PlacedPartitionSpec{
        .{
            .type_guid = guid.esp,
            .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111"),
            .placement = .{ .first_lba = 2048, .last_lba = 4095 },
            .name_utf16le = gpt.asciiName("EFI System"),
        },
        .{
            .type_guid = guid.linux_root_x86_64,
            .unique_guid = guid.parse("22222222-2222-2222-2222-222222222222"),
            .placement = .{ .first_lba = root_first_lba, .last_lba = root_last_lba },
            .name_utf16le = gpt.asciiName("root"),
        },
    };
    try gpt.writeGptPlaced(
        &raw,
        io,
        guid.parse("33333333-3333-3333-3333-333333333333"),
        &specs,
    );

    const root_tree = @import("root_tree.zig");
    var tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer tree.deinit();
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putFileBytes("etc/hostname", "vmiz-root-resize\n", .{ .mode = 0o644 });
    const cursor = try tree.cursor();
    _ = try ext4.populate(io, raw.file, allocator, cursor, .{
        .offset = root_offset,
        .length = root_length,
        .label = default_filesystem_label,
        .uuid = filesystem_uuid,
    });
    // Exercise the stock Ubuntu profile as well as vmiz's compact writer:
    // 64-byte descriptors, 64bit/flex_bg/csum_seed, and resize_inode.
    var stock_superblock: [1024]u8 = undefined;
    _ = try raw.file.readPositionalAll(io, &stock_superblock, root_offset + 1024);
    std.mem.writeInt(
        u32,
        stock_superblock[0x5C..0x60],
        std.mem.readInt(u32, stock_superblock[0x5C..0x60], .little) | 0x0010,
        .little,
    );
    std.mem.writeInt(
        u32,
        stock_superblock[0x60..0x64],
        std.mem.readInt(u32, stock_superblock[0x60..0x64], .little) |
            0x0080 | 0x0200 | 0x2000,
        .little,
    );
    std.mem.writeInt(u16, stock_superblock[0xFE..0x100], 64, .little);
    try raw.file.writePositionalAll(io, &stock_superblock, root_offset + 1024);
    var stock_gdt: [4096]u8 = [_]u8{0} ** 4096;
    _ = try raw.file.readPositionalAll(io, &stock_gdt, root_offset + 4096);
    var first_descriptor: [32]u8 = undefined;
    @memcpy(&first_descriptor, stock_gdt[0..32]);
    @memset(&stock_gdt, 0);
    @memcpy(stock_gdt[0..32], &first_descriptor);
    try raw.file.writePositionalAll(io, &stock_gdt, root_offset + 4096);
    var qcow = try Image.create(io, qcow_path, .qcow2, old_size, .{});
    try image_mod.copyAll(io, raw, &qcow, allocator);
    qcow.close(io);
    raw.close(io);
    raw_open = false;

    const report = try growExistingQcow2(allocator, io, qcow_path, .{
        .target_size = new_size,
    });
    try std.testing.expectEqual(old_size, report.old_virtual_size);
    try std.testing.expectEqual(new_size, report.new_virtual_size);
    try std.testing.expectEqual(@as(u32, 1), report.root_table_index);
    try std.testing.expectEqualSlices(u8, &filesystem_uuid, &report.filesystem_uuid);

    var grown = try Image.openPathReadOnlyStandalone(io, qcow_path);
    defer grown.close(io);
    try std.testing.expectEqual(new_size, grown.virtual_size);
    var parsed = try gpt.readVerifiedGpt(grown, io, allocator, max_partition_array_bytes);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), parsed.partitions.len);
    try std.testing.expectEqual(
        new_size / gpt.sector_size - 2 - gpt.partition_array_sectors,
        parsed.partitions[1].last_lba,
    );
    try std.testing.expectEqualSlices(
        u8,
        &specs[1].unique_guid,
        &parsed.partitions[1].unique_partition_guid,
    );

    var context = ReadContext{ .image = &grown, .io = io };
    var reader = try ext4.Reader.openReadOnlySource(
        io,
        grown.file,
        .{ .ctx = &context, .read_at_fn = readImageAt },
        allocator,
        .{ .offset = root_offset },
    );
    defer reader.deinit();
    try std.testing.expectEqualSlices(u8, &filesystem_uuid, &reader.uuid);
    try std.testing.expectEqualStrings(default_filesystem_label, labelBytes(&reader.label));
    const hostname = try reader.readFileAlloc(io, allocator, "etc/hostname");
    defer allocator.free(hostname);
    try std.testing.expectEqualStrings("vmiz-root-resize\n", hostname);
}

test "rejects an image without a verified GPT before replacing it" {
    const io = std.testing.io;
    const path = "test-root-resize-invalid.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var image = try Image.create(io, path, .qcow2, 32 * 1024 * 1024, .{});
    image.close(io);
    try std.testing.expectError(
        error.BadBootSignature,
        growExistingQcow2(std.testing.allocator, io, path, .{
            .target_size = 64 * 1024 * 1024,
        }),
    );

    var unchanged = try Image.openPathReadOnlyStandalone(io, path);
    defer unchanged.close(io);
    try std.testing.expectEqual(@as(u64, 32 * 1024 * 1024), unchanged.virtual_size);
}
