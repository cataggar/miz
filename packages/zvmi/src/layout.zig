//! Pure partition-layout planning: turn fixed-size and percentage-based
//! partition requests into aligned byte offsets and lengths that fit inside
//! GPT's usable address range.

const std = @import("std");
const azure = @import("azure.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");

pub const default_alignment: u64 = azure.one_mib;
const percent_epsilon: f64 = 1e-9;

pub const PlanError = std.mem.Allocator.Error || error{
    DiskTooSmall,
    InvalidAlignment,
    InvalidDiskSize,
    InvalidFixedSize,
    InvalidPercentage,
    OverAllocated,
    PartitionTooSmall,
};

pub const PartitionRole = enum {
    esp,
    boot,
    root_x86_64,
    root_aarch64,
    usr_x86_64,
    usr_aarch64,
    linux_filesystem_data,
    microsoft_basic_data,

    pub fn defaultTypeGuid(self: PartitionRole) guid.Guid {
        return switch (self) {
            .esp => guid.esp,
            .boot => guid.linux_xbootldr,
            .root_x86_64 => guid.linux_root_x86_64,
            .root_aarch64 => guid.linux_root_aarch64,
            .usr_x86_64 => guid.linux_usr_x86_64,
            .usr_aarch64 => guid.linux_usr_aarch64,
            .linux_filesystem_data => guid.linux_filesystem_data,
            .microsoft_basic_data => guid.microsoft_basic_data,
        };
    }
};

/// Which native writer formats a partition's contents once it is written.
///
/// This is deliberately independent of `PartitionRole`: a role picks a GPT
/// partition *type* GUID (what the partition table says the partition is
/// for), while `FilesystemKind` picks what bytes a writer actually puts
/// inside it. The two correlate at most call sites today -- an ESP is
/// FAT32, a Linux root is ext4 -- but that correlation lives at the call
/// site, not in either enum, because neither a role nor a type GUID implies
/// a filesystem by itself. A vendor-specific root GUID and a `linux_root_*`
/// GUID could both hold ext4; an ESP's GUID is fixed by the UEFI spec yet
/// says nothing about FAT32 versus FAT16.
///
/// Deliberately covers only what zvmi can actually write today. XFS has a
/// bounded read-only reader (`xfs.zig`) and ISO9660/SquashFS are read-only
/// by design; none of them belong in a "how do I format this partition"
/// enum until a writer exists for them. Adding a variant here for a
/// filesystem zvmi cannot write would claim a capability that does not
/// exist (see issue #327).
pub const FilesystemKind = enum {
    ext4,
    fat32,
};

pub const PartitionRequest = struct {
    name: []const u8,
    role: PartitionRole,
    /// Stated explicitly by every caller rather than derived from `role`:
    /// a role and its filesystem are orthogonal choices, so defaulting one
    /// from the other would let a call site get a filesystem it never
    /// actually asked for.
    filesystem: FilesystemKind,
    size: union(enum) {
        fixed: u64,
        percent: f64,
    },
    type_guid: ?guid.Guid = null,
};

/// Planned partitions borrow `name` directly from the corresponding input
/// request.
pub const PlannedPartition = struct {
    name: []const u8,
    role: PartitionRole,
    filesystem: FilesystemKind,
    type_guid: guid.Guid,
    offset_bytes: u64,
    length_bytes: u64,

    pub fn firstLba(self: PlannedPartition) u64 {
        return self.offset_bytes / gpt.sector_size;
    }

    pub fn lastLba(self: PlannedPartition) u64 {
        return self.firstLba() + self.sizeSectors() - 1;
    }

    pub fn sizeSectors(self: PlannedPartition) u64 {
        return self.length_bytes / gpt.sector_size;
    }
};

fn alignSize(size: u64, alignment: u64) u64 {
    std.debug.assert(alignment != 0);
    if (alignment == default_alignment) return azure.alignSizeToMib(size);
    if (size == 0) return 0;
    return ((size - 1) / alignment + 1) * alignment;
}

fn alignSizeDown(size: u64, alignment: u64) u64 {
    std.debug.assert(alignment != 0);
    return size / alignment * alignment;
}

fn scaleUnits(total_units: u64, numerator: f64, denominator: f64) u64 {
    const exact = @as(f64, @floatFromInt(total_units)) * numerator / denominator;
    return @as(u64, @intFromFloat(@floor(exact + percent_epsilon)));
}

/// Plans partitions inside GPT's usable region. Fixed-size requests are
/// aligned up first; percentage requests then consume their requested share
/// of the remaining aligned capacity. If percentage requests sum to less
/// than 100, any tail space is left unallocated at the end of the disk.
pub fn planLayout(
    allocator: std.mem.Allocator,
    disk_size: u64,
    requests: []const PartitionRequest,
    alignment_override: ?u64,
) PlanError![]PlannedPartition {
    const alignment = alignment_override orelse default_alignment;
    if (alignment == 0 or alignment % gpt.sector_size != 0) return error.InvalidAlignment;
    if (disk_size % gpt.sector_size != 0) return error.InvalidDiskSize;

    const total_sectors = disk_size / gpt.sector_size;
    const first_usable_lba: u64 = 2 + gpt.partition_array_sectors;
    const backup_reserved_sectors: u64 = 1 + gpt.partition_array_sectors;
    if (total_sectors <= first_usable_lba + backup_reserved_sectors) return error.DiskTooSmall;

    const first_usable_offset = first_usable_lba * gpt.sector_size;
    const usable_end_offset = disk_size - backup_reserved_sectors * gpt.sector_size;
    const first_partition_offset = alignSize(first_usable_offset, alignment);
    if (first_partition_offset >= usable_end_offset) return error.DiskTooSmall;

    const usable_aligned_bytes = alignSizeDown(usable_end_offset - first_partition_offset, alignment);

    const lengths = try allocator.alloc(u64, requests.len);
    defer allocator.free(lengths);
    @memset(lengths, 0);

    var fixed_total_bytes: u64 = 0;
    var percent_total: f64 = 0.0;
    var percent_count: usize = 0;
    for (requests, 0..) |request, i| {
        switch (request.size) {
            .fixed => |bytes| {
                if (bytes == 0) return error.InvalidFixedSize;
                lengths[i] = alignSize(bytes, alignment);
                if (lengths[i] > usable_aligned_bytes -| fixed_total_bytes) return error.OverAllocated;
                fixed_total_bytes += lengths[i];
            },
            .percent => |percent| {
                if (!std.math.isFinite(percent) or percent <= 0.0) return error.InvalidPercentage;
                percent_total += percent;
                if (percent_total > 100.0 + percent_epsilon) return error.OverAllocated;
                percent_count += 1;
            },
        }
    }

    const remaining_units = (usable_aligned_bytes - fixed_total_bytes) / alignment;
    var remaining_percent_total = percent_total;
    var remaining_percent_units = scaleUnits(remaining_units, percent_total, 100.0);
    var remaining_percent_count = percent_count;
    for (requests, 0..) |request, i| {
        switch (request.size) {
            .fixed => {},
            .percent => |percent| {
                const units = if (remaining_percent_count == 1)
                    remaining_percent_units
                else
                    scaleUnits(remaining_percent_units, percent, remaining_percent_total);
                if (units == 0) return error.PartitionTooSmall;

                lengths[i] = units * alignment;
                remaining_percent_units -= units;
                remaining_percent_total -= percent;
                remaining_percent_count -= 1;
            },
        }
    }

    const planned = try allocator.alloc(PlannedPartition, requests.len);
    errdefer allocator.free(planned);

    var cursor = first_partition_offset;
    for (requests, lengths, 0..) |request, length, i| {
        planned[i] = .{
            .name = request.name,
            .role = request.role,
            .filesystem = request.filesystem,
            .type_guid = request.type_guid orelse request.role.defaultTypeGuid(),
            .offset_bytes = cursor,
            .length_bytes = length,
        };
        cursor += length;
    }

    return planned;
}

test "planLayout mixes fixed and percentage requests deterministically" {
    const requests = [_]PartitionRequest{
        .{ .name = "ESP", .role = .esp, .filesystem = .fat32, .size = .{ .fixed = 64 * azure.one_mib } },
        .{ .name = "boot", .role = .boot, .filesystem = .ext4, .size = .{ .fixed = 32 * azure.one_mib } },
        .{ .name = "root", .role = .root_x86_64, .filesystem = .ext4, .size = .{ .percent = 75.0 } },
        .{ .name = "usr", .role = .usr_x86_64, .filesystem = .ext4, .size = .{ .percent = 25.0 }, .type_guid = guid.linux_filesystem_data },
    };

    const planned = try planLayout(std.testing.allocator, 512 * azure.one_mib, &requests, null);
    defer std.testing.allocator.free(planned);

    try std.testing.expectEqual(@as(usize, requests.len), planned.len);
    try std.testing.expectEqual(@as(u64, azure.one_mib), planned[0].offset_bytes);
    try std.testing.expectEqual(@as(u64, 64 * azure.one_mib), planned[0].length_bytes);
    try std.testing.expectEqual(FilesystemKind.fat32, planned[0].filesystem);
    try std.testing.expectEqual(@as(u64, 65 * azure.one_mib), planned[1].offset_bytes);
    try std.testing.expectEqualSlices(u8, &guid.linux_xbootldr, &planned[1].type_guid);
    try std.testing.expectEqual(FilesystemKind.ext4, planned[1].filesystem);
    try std.testing.expectEqual(@as(u64, 97 * azure.one_mib), planned[2].offset_bytes);
    try std.testing.expectEqual(@as(u64, 310 * azure.one_mib), planned[2].length_bytes);
    try std.testing.expectEqual(@as(u64, 407 * azure.one_mib), planned[3].offset_bytes);
    try std.testing.expectEqual(@as(u64, 104 * azure.one_mib), planned[3].length_bytes);
    try std.testing.expectEqualSlices(u8, &guid.linux_filesystem_data, &planned[3].type_guid);
    // The `usr` request overrides its type GUID away from the role default
    // yet still asks for ext4: role and filesystem are set independently,
    // and neither is inferred from the other.
    try std.testing.expectEqual(FilesystemKind.ext4, planned[3].filesystem);
}

test "planLayout rounds offsets and lengths to the requested alignment" {
    const requests = [_]PartitionRequest{
        .{ .name = "boot", .role = .boot, .filesystem = .ext4, .size = .{ .fixed = azure.one_mib } },
        .{ .name = "root", .role = .root_aarch64, .filesystem = .ext4, .size = .{ .fixed = 5 * azure.one_mib } },
    };

    const four_mib = 4 * azure.one_mib;
    const planned = try planLayout(std.testing.allocator, 128 * azure.one_mib, &requests, four_mib);
    defer std.testing.allocator.free(planned);

    try std.testing.expectEqual(@as(u64, four_mib), planned[0].offset_bytes);
    try std.testing.expectEqual(@as(u64, four_mib), planned[0].length_bytes);
    try std.testing.expectEqual(@as(u64, 2 * four_mib), planned[1].offset_bytes);
    try std.testing.expectEqual(@as(u64, 2 * four_mib), planned[1].length_bytes);
}

test "planLayout rejects over-allocation" {
    const requests = [_]PartitionRequest{
        .{ .name = "ESP", .role = .esp, .filesystem = .fat32, .size = .{ .fixed = 32 * azure.one_mib } },
        .{ .name = "root", .role = .root_x86_64, .filesystem = .ext4, .size = .{ .percent = 80.0 } },
        .{ .name = "usr", .role = .usr_x86_64, .filesystem = .ext4, .size = .{ .percent = 30.0 } },
    };

    try std.testing.expectError(error.OverAllocated, planLayout(std.testing.allocator, 128 * azure.one_mib, &requests, null));
}

test "planLayout rejects a positive percentage that cannot reach one alignment unit" {
    const requests = [_]PartitionRequest{
        .{ .name = "tiny", .role = .linux_filesystem_data, .filesystem = .ext4, .size = .{ .percent = 1.0 } },
    };

    try std.testing.expectError(error.PartitionTooSmall, planLayout(std.testing.allocator, 64 * azure.one_mib, &requests, null));
}

test "planLayout survives a GPT write/read round-trip" {
    const io = std.testing.io;
    const path = "test-layout-gpt-roundtrip.img";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size = 256 * azure.one_mib;
    const requests = [_]PartitionRequest{
        .{ .name = "ESP", .role = .esp, .filesystem = .fat32, .size = .{ .fixed = 64 * azure.one_mib } },
        .{ .name = "root", .role = .root_x86_64, .filesystem = .ext4, .size = .{ .percent = 100.0 } },
    };

    const planned = try planLayout(std.testing.allocator, disk_size, &requests, null);
    defer std.testing.allocator.free(planned);

    const Image = @import("image.zig").Image;
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const specs = [_]gpt.PlacedPartitionSpec{
        .{
            .type_guid = planned[0].type_guid,
            .unique_guid = guid.parse("88888888-8888-8888-8888-888888888888"),
            .placement = .{ .first_lba = planned[0].firstLba(), .last_lba = planned[0].lastLba() },
            .name_utf16le = gpt.asciiName(planned[0].name),
        },
        .{
            .type_guid = planned[1].type_guid,
            .unique_guid = guid.parse("99999999-9999-9999-9999-999999999999"),
            .placement = .{ .first_lba = planned[1].firstLba(), .last_lba = planned[1].lastLba() },
            .name_utf16le = gpt.asciiName(planned[1].name),
        },
    };

    const disk_guid = guid.parse("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA");
    try gpt.writeGptPlaced(&img, io, disk_guid, &specs);

    const parsed = try gpt.readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(parsed.partitions);

    try std.testing.expectEqual(@as(usize, specs.len), parsed.partitions.len);
    try std.testing.expectEqual(planned[0].firstLba(), parsed.partitions[0].first_lba);
    try std.testing.expectEqual(planned[0].lastLba(), parsed.partitions[0].last_lba);
    try std.testing.expectEqual(planned[1].firstLba(), parsed.partitions[1].first_lba);
    try std.testing.expectEqual(planned[1].lastLba(), parsed.partitions[1].last_lba);
    try std.testing.expectEqualSlices(u8, &guid.esp, &parsed.partitions[0].partition_type_guid);
    try std.testing.expectEqualSlices(u8, &guid.linux_root_x86_64, &parsed.partitions[1].partition_type_guid);
    try std.testing.expectEqualSlices(u8, &disk_guid, &parsed.header.disk_guid);
}

test "planLayout propagates each request's filesystem to its planned partition unchanged" {
    const requests = [_]PartitionRequest{
        .{ .name = "ESP", .role = .esp, .filesystem = .fat32, .size = .{ .fixed = 64 * azure.one_mib } },
        .{ .name = "boot", .role = .boot, .filesystem = .ext4, .size = .{ .fixed = 32 * azure.one_mib } },
        .{ .name = "root", .role = .root_x86_64, .filesystem = .ext4, .size = .{ .percent = 100.0 } },
    };

    const planned = try planLayout(std.testing.allocator, 256 * azure.one_mib, &requests, null);
    defer std.testing.allocator.free(planned);

    for (requests, planned) |request, partition| {
        try std.testing.expectEqual(request.filesystem, partition.filesystem);
    }
    try std.testing.expectEqual(FilesystemKind.fat32, planned[0].filesystem);
    try std.testing.expectEqual(FilesystemKind.ext4, planned[1].filesystem);
    try std.testing.expectEqual(FilesystemKind.ext4, planned[2].filesystem);
}

test "planLayout keeps role and filesystem independent: a role's GPT type GUID does not change with filesystem" {
    // Two requests share the same role (and so the same default type GUID)
    // but ask for different filesystems. If `filesystem` were derived from
    // `role`, this would be inexpressible; instead both plan cleanly and the
    // type GUID -- which comes from `role` alone -- is identical.
    const requests = [_]PartitionRequest{
        .{ .name = "data-a", .role = .linux_filesystem_data, .filesystem = .ext4, .size = .{ .fixed = 16 * azure.one_mib } },
        .{ .name = "data-b", .role = .linux_filesystem_data, .filesystem = .fat32, .size = .{ .fixed = 16 * azure.one_mib } },
    };

    const planned = try planLayout(std.testing.allocator, 128 * azure.one_mib, &requests, null);
    defer std.testing.allocator.free(planned);

    try std.testing.expectEqual(FilesystemKind.ext4, planned[0].filesystem);
    try std.testing.expectEqual(FilesystemKind.fat32, planned[1].filesystem);
    try std.testing.expectEqualSlices(u8, &planned[0].type_guid, &planned[1].type_guid);
    try std.testing.expectEqualSlices(u8, &guid.linux_filesystem_data, &planned[0].type_guid);
}

test "planLayout keeps filesystem independent of an explicit type_guid override" {
    // The `usr` role defaults to a usr-specific type GUID, but a caller can
    // override the GUID (as the "usr" request above does) without that
    // override implying anything about the filesystem: the two fields are
    // set, and vary, independently of one another.
    const requests = [_]PartitionRequest{
        .{
            .name = "usr",
            .role = .usr_x86_64,
            .filesystem = .fat32,
            .size = .{ .fixed = 32 * azure.one_mib },
            .type_guid = guid.linux_filesystem_data,
        },
    };

    const planned = try planLayout(std.testing.allocator, 128 * azure.one_mib, &requests, null);
    defer std.testing.allocator.free(planned);

    try std.testing.expectEqual(FilesystemKind.fat32, planned[0].filesystem);
    try std.testing.expectEqualSlices(u8, &guid.linux_filesystem_data, &planned[0].type_guid);
}
