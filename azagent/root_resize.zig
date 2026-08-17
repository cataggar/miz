//! Grows the root partition + ext4 filesystem to fill a larger disk than
//! the image was built at ("growpart"/`resize2fs` equivalent). See vmiz
//! issue #130.
//!
//! Generalized images are typically built small and deployed onto VMs with
//! a larger, user-chosen OS disk (Azure lets you specify an OS disk size
//! larger than the image at deployment time, never smaller); without this,
//! that extra space is simply unreachable. Real `waagent` does not
//! implement this at all -- on real Azure Linux images this is
//! cloud-init's job (`growpart`/`resizefs` modules), not waagent's. But
//! `azagent` already deliberately never defers to cloud-init and always
//! fully owns provisioning instead (issue #112's explicit scope decision),
//! so this falls to `azagent` by the same logic that put SSH-key/user
//! provisioning there.
//!
//! Runs on *every* boot, like `resource_disk.zig` (#113), not gated by the
//! provisioning sentinel: disk resize is a deployment-time/redeploy-time
//! event, not a first-boot-only one. Idempotent by construction: growing
//! the partition table and the filesystem are both no-ops once they
//! already reach the disk's current real size.
//!
//! The partition table (GPT/MBR) is grown by writing directly to the
//! whole-disk block device, then the kernel's cached size for the mounted
//! root partition is updated with `BLKPG_RESIZE_PARTITION`. The root ext4
//! filesystem itself is *always* mounted while this runs (that's how it's
//! found at all, via `/proc/mounts`), so it's grown live via the kernel's
//! own `EXT4_IOC_RESIZE_FS` ioctl (matching what `resize2fs` itself does
//! against a mounted filesystem) rather than this package's own
//! `ext4.resize()`, which writes new metadata directly to the backing
//! block device and is only safe when a filesystem is *not* currently
//! mounted (e.g. `resource_disk.zig`'s fresh-format case).
const std = @import("std");
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const vmiz = @import("vmiz");
const mbr = vmiz.mbr;
const gpt = vmiz.gpt;
const ext4 = vmiz.ext4;
const Image = vmiz.Image;
const resource_disk = @import("resource_disk.zig");

pub const RootDevice = struct {
    /// Owned. Whole-disk kernel device name, e.g. `"sda"` or `"nvme0n1"`.
    disk_name: []u8,
    /// Owned. Root partition's kernel device name, e.g. `"sda2"` or
    /// `"nvme0n1p2"`.
    partition_name: []u8,
    /// 1-based partition number (from the `partition` sysfs attribute,
    /// not hand-parsed from the name), used as a cross-check that the
    /// partition table entry about to be grown really is the mounted
    /// root, not just assumed from table position.
    partition_number: u32,
};

/// Pure parser: finds the device-path field (first whitespace-separated
/// column) of the `/proc/mounts` line whose mount point (second column) is
/// exactly `/`, and returns its basename (e.g. `/dev/sda2` -> `sda2`,
/// `/dev/nvme0n1p2` -> `nvme0n1p2`). Borrows from `content`.
fn rootPartitionNameFromMounts(content: []const u8) error{RootMountNotFound}![]const u8 {
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const device = fields.next() orelse continue;
        const mount_point = fields.next() orelse continue;
        if (std.mem.eql(u8, mount_point, "/")) {
            return std.fs.path.basename(device);
        }
    }
    return error.RootMountNotFound;
}

/// Resolves the root partition's whole-disk name and partition number.
///
/// `class_block_dir` is an open handle to `/sys/class/block` (production)
/// or a synthetic directory tree (tests). The partition's whole-disk name
/// is found by reading its symlink target text (e.g.
/// `/sys/class/block/sda2` -> `../../devices/.../block/sda/sda2`) and
/// taking the parent path component's basename -- purely string
/// manipulation on the link text, no real filesystem walk needed, and
/// robust across `sdXN`/`vdXN`/`nvme0n1pN`/`mmcblk0pN` naming schemes
/// without hand-parsing the partition name itself.
pub fn findRootDevice(allocator: Allocator, io: std.Io, proc_mounts_content: []const u8, class_block_dir: std.Io.Dir) !RootDevice {
    const partition_name = try rootPartitionNameFromMounts(proc_mounts_content);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_len = try class_block_dir.readLink(io, partition_name, &link_buf);
    const link_target = link_buf[0..link_len];
    const parent = std.fs.path.dirname(link_target) orelse return error.RootDiskNameNotFound;
    const disk_name = std.fs.path.basename(parent);

    var partition_attr_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const partition_attr_path = try std.fmt.bufPrint(&partition_attr_path_buf, "{s}/partition", .{partition_name});
    const partition_number_content = try class_block_dir.readFileAlloc(io, partition_attr_path, allocator, .limited(64));
    defer allocator.free(partition_number_content);
    const partition_number = try std.fmt.parseInt(u32, std.mem.trim(u8, partition_number_content, " \t\r\n"), 10);

    return .{
        .disk_name = try allocator.dupe(u8, disk_name),
        .partition_name = try allocator.dupe(u8, partition_name),
        .partition_number = partition_number,
    };
}

/// Reads the full content of `/proc/mounts` via raw `open(2)`/`read(2)`
/// syscalls, working around `/proc/mounts` reporting a misleadingly small
/// `stat` size (confirmed: 11 bytes, regardless of real content) that
/// silently empties/truncates results read through `Io.Dir.readFileAlloc`
/// (which trusts that reported size) -- matching this repo's established
/// workaround in `resource_disk.zig`'s `isSwapActive` for `/proc/swaps`.
pub fn readProcMounts(allocator: Allocator) ![]u8 {
    const open_rc = linux.open("/proc/mounts", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return error.ProcMountsOpenFailed;
    const fd: linux.fd_t = @intCast(open_rc);
    defer _ = linux.close(fd);

    var list = std.array_list.Managed(u8).init(allocator);
    errdefer list.deinit();

    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const read_rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(read_rc) != .SUCCESS) return error.ProcMountsReadFailed;
        if (read_rc == 0) break;
        try list.appendSlice(buf[0..read_rc]);
    }
    return try list.toOwnedSlice();
}

const PartitionExtent = struct {
    start_bytes: u64,
    length_bytes: u64,

    fn fromLbaRange(first_lba: u64, last_lba: u64) !PartitionExtent {
        if (last_lba < first_lba) return error.InvalidPartitionExtent;
        const sector_count = try std.math.add(u64, try std.math.sub(u64, last_lba, first_lba), 1);
        return .{
            .start_bytes = try std.math.mul(u64, first_lba, mbr.sector_size),
            .length_bytes = try std.math.mul(u64, sector_count, mbr.sector_size),
        };
    }
};

/// Grows the GPT root partition (identified as the *last* entry in the
/// table, matching both vmiz-built images and real Azure Linux images) to
/// the disk's new, larger end. Always returns the resulting partition
/// extent, including when the table was already grown, so callers can
/// retry the kernel and filesystem resize steps after an earlier failure.
fn growGptRoot(allocator: Allocator, io: std.Io, img: *Image, partition_number: u32) !PartitionExtent {
    const parsed = try gpt.readGpt(img.*, io, allocator);
    defer allocator.free(parsed.partitions);
    if (parsed.partitions.len == 0) return error.RootPartitionNotFound;

    // Safety cross-check: the root partition's kernel-reported partition
    // number should match its position in the table. Fail loudly rather
    // than silently growing the wrong partition if this ever doesn't
    // hold.
    if (partition_number != parsed.partitions.len) return error.RootPartitionPositionMismatch;

    gpt.growLastPartition(img, io, parsed.header.disk_guid, parsed.partitions) catch |err| switch (err) {
        error.NotEnoughSpace => {},
        else => return err,
    };

    const root_partition = parsed.partitions[parsed.partitions.len - 1];
    return PartitionExtent.fromLbaRange(root_partition.first_lba, root_partition.last_lba);
}

/// Grows the MBR (Gen1) root partition in place while preserving the BIOS
/// bootstrap code in sector 0. Like `growGptRoot`, it returns the resulting
/// extent even when the table was already grown.
fn growMbrRoot(io: std.Io, img: *Image, sector0: *[mbr.sector_size]u8, decoded: mbr.Mbr, partition_number: u32) !PartitionExtent {
    if (partition_number == 0 or partition_number > mbr.max_entries) return error.RootPartitionPositionMismatch;

    var table = decoded;
    const partition_index = partition_number - 1;
    const total_sectors = img.virtual_size / mbr.sector_size;
    const table_grown = blk: {
        mbr.growPartition(&table, partition_index, total_sectors) catch |err| switch (err) {
            error.NotEnoughSpace => break :blk false,
            else => return err,
        };
        break :blk true;
    };

    if (table_grown) {
        table.encodePartitionTableInto(sector0);
        try img.pwrite(io, sector0, 0);
    }

    const root_partition = table.entries[partition_index];
    if (root_partition.sector_count == 0) return error.RootPartitionNotFound;
    const last_lba = try std.math.sub(
        u64,
        try std.math.add(u64, root_partition.first_lba, root_partition.sector_count),
        1,
    );
    return PartitionExtent.fromLbaRange(root_partition.first_lba, last_lba);
}

/// Linux `BLKPG` request (`_IO(0x12, 105)`) and
/// `BLKPG_RESIZE_PARTITION` operation. Unlike `BLKRRPART`, this updates one
/// partition in place and works while that partition is mounted.
const blkpg: u32 = 0x1269;
const blkpg_resize_partition: c_int = 3;
const blkpg_name_len = 64;

const BlkpgPartition = extern struct {
    start: i64,
    length: i64,
    pno: c_int,
    devname: [blkpg_name_len]u8,
    volname: [blkpg_name_len]u8,
};

const BlkpgIoctlArg = extern struct {
    op: c_int,
    flags: c_int,
    datalen: c_int,
    data: *anyopaque,
};

fn resizeKernelPartition(disk_file: std.Io.File, partition_number: u32, extent: PartitionExtent) !void {
    var partition = BlkpgPartition{
        .start = std.math.cast(i64, extent.start_bytes) orelse return error.PartitionExtentTooLarge,
        .length = std.math.cast(i64, extent.length_bytes) orelse return error.PartitionExtentTooLarge,
        .pno = std.math.cast(c_int, partition_number) orelse return error.PartitionNumberTooLarge,
        .devname = [_]u8{0} ** blkpg_name_len,
        .volname = [_]u8{0} ** blkpg_name_len,
    };
    var arg = BlkpgIoctlArg{
        .op = blkpg_resize_partition,
        .flags = 0,
        .datalen = @intCast(@sizeOf(BlkpgPartition)),
        .data = @ptrCast(&partition),
    };

    const rc = linux.ioctl(disk_file.handle, blkpg, @intFromPtr(&arg));
    if (linux.errno(rc) != .SUCCESS) return error.KernelPartitionResizeFailed;
}

fn partitionSizeBytes(io: std.Io, part_path: [:0]const u8) !u64 {
    var part_file = try std.Io.Dir.cwd().openFile(io, part_path, .{ .mode = .read_only });
    defer part_file.close(io);
    return resource_disk.blockDeviceSizeBytes(part_file);
}

fn partitionNeedsKernelResize(current_size: u64, target_size: u64) !bool {
    if (current_size > target_size) return error.KernelPartitionLargerThanTable;
    return current_size < target_size;
}

fn updateKernelPartition(
    io: std.Io,
    disk_file: std.Io.File,
    part_path: [:0]const u8,
    partition_number: u32,
    extent: PartitionExtent,
) !u64 {
    const current_size = try partitionSizeBytes(io, part_path);
    if (try partitionNeedsKernelResize(current_size, extent.length_bytes)) {
        try resizeKernelPartition(disk_file, partition_number, extent);
    }

    const updated_size = try partitionSizeBytes(io, part_path);
    if (updated_size != extent.length_bytes) return error.KernelPartitionResizeNotVisible;
    return updated_size;
}

/// Linux `EXT4_IOC_RESIZE_FS` ioctl request code (`_IOW('f', 16, __u64)`),
/// used to grow an *already-mounted* ext4 filesystem live, in the kernel,
/// so its own in-memory cached superblock/group-descriptor state stays
/// consistent with what lands on disk.
///
/// Deliberately NOT this package's own `ext4.resize()`: that's an offline
/// algorithm (see its doc comment) that `pwrite`s new metadata directly to
/// the backing block device, bypassing the kernel's ext4 driver entirely
/// -- safe for `resource_disk.zig`'s fresh, not-yet-mounted disk, but not
/// for the root filesystem here, which is *always* mounted while
/// `azagent` runs (that's literally how `findRootDevice` locates it, via
/// `/proc/mounts`). Writing directly to a live mounted filesystem's
/// backing device risks the kernel's cached view going stale (the growth
/// silently unnoticed, or later overwritten by the kernel's own stale
/// cached metadata) -- exactly what `resize2fs` itself avoids by using
/// this same ioctl on a mounted filesystem instead of touching the device
/// directly.
const ext4_ioc_resize_fs: u32 = 0x40086610;

/// Issues `EXT4_IOC_RESIZE_FS` against the filesystem mounted at
/// `mount_point_path` (always `"/"` for this module's use), asking the
/// kernel to grow it live to `new_block_count` (4096-byte) blocks.
fn onlineResizeExt4(mount_point_path: [:0]const u8, new_block_count: u64) !void {
    const open_rc = linux.open(mount_point_path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return error.MountPointOpenFailed;
    const fd: linux.fd_t = @intCast(open_rc);
    defer _ = linux.close(fd);

    var arg: u64 = new_block_count;
    const rc = linux.ioctl(fd, ext4_ioc_resize_fs, @intFromPtr(&arg));
    if (linux.errno(rc) != .SUCCESS) return error.Ext4OnlineResizeFailed;
}

/// Grows the root partition table entry, updates the kernel's live view of
/// that mounted partition, and grows the mounted ext4 filesystem to match.
/// The latter two steps run even when the on-disk table was already grown,
/// so an interrupted or failed earlier attempt is retried on the next boot.
/// `disk_file` must be an already-open, read-write handle to the *whole
/// disk* device node (e.g. `/dev/sda`), not the partition node.
fn growRoot(io: std.Io, allocator: Allocator, disk_file: std.Io.File, part_path: [:0]const u8, root: RootDevice) !void {
    const real_size = try resource_disk.blockDeviceSizeBytes(disk_file);
    var img = Image{ .file = disk_file, .format = .raw, .data_offset = 0, .virtual_size = real_size };

    var sector0: [mbr.sector_size]u8 = undefined;
    _ = try img.pread(io, &sector0, 0);
    const decoded_mbr = mbr.Mbr.decode(&sector0) catch return error.UnrecognizedPartitionTable;

    const extent = switch (decoded_mbr.entries[0].partition_type) {
        .gpt_protective => try growGptRoot(allocator, io, &img, root.partition_number),
        .linux => try growMbrRoot(io, &img, &sector0, decoded_mbr, root.partition_number),
        else => return error.UnrecognizedPartitionTable,
    };

    const part_size_bytes = try updateKernelPartition(io, disk_file, part_path, root.partition_number, extent);
    // The partition's real size need not be an exact multiple of the
    // 4096-byte ext4 block size; round down to be safe.
    const aligned_length = part_size_bytes - (part_size_bytes % ext4.default_block_size);
    const new_block_count = aligned_length / ext4.default_block_size;

    // The root filesystem is always mounted (at "/") while this runs.
    try onlineResizeExt4("/", new_block_count);
}

pub const SetupOptions = struct {
    allocator: Allocator,
    io: std.Io,
    /// Open handle to `/sys/class/block` (production), or a synthetic
    /// directory tree (tests).
    class_block_dir: std.Io.Dir,
};

/// Runs the full every-boot root-grow sequence: find the root device from
/// `/proc/mounts`, read its partition table, and grow the partition +
/// ext4 filesystem to the disk's real current size if it has grown.
/// Deliberately not covered by an automated test end to end -- it needs a
/// real block device special file and root, matching `resource_disk.
/// setup`'s precedent for real-device-only glue in this package; the
/// pure/testable pieces above (mounts parser, sysfs symlink resolution,
/// codec-level grow logic in `gpt.zig`/`mbr.zig`) are covered directly.
pub fn setup(options: SetupOptions) !void {
    const mounts_content = try readProcMounts(options.allocator);
    defer options.allocator.free(mounts_content);

    const root = try findRootDevice(options.allocator, options.io, mounts_content, options.class_block_dir);
    defer options.allocator.free(root.disk_name);
    defer options.allocator.free(root.partition_name);

    var disk_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const disk_path = try std.fmt.bufPrintZ(&disk_path_buf, "/dev/{s}", .{root.disk_name});
    var part_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const part_path = try std.fmt.bufPrintZ(&part_path_buf, "/dev/{s}", .{root.partition_name});

    var disk_file = try std.Io.Dir.cwd().openFile(options.io, disk_path, .{ .mode = .read_write });
    defer disk_file.close(options.io);

    try growRoot(options.io, options.allocator, disk_file, part_path, root);
}

test "rootPartitionNameFromMounts finds the device mounted at /" {
    const content =
        \\/dev/sda3 / ext4 rw,relatime 0 0
        \\devtmpfs /dev devtmpfs rw,nosuid,size=4096k,nr_inodes=4094394,mode=755 0 0
        \\/dev/sda2 /boot ext4 rw,relatime 0 0
        \\/dev/sda1 /boot/efi vfat rw,relatime 0 0
        \\
    ;
    try std.testing.expectEqualStrings("sda3", try rootPartitionNameFromMounts(content));
}

test "rootPartitionNameFromMounts handles nvme-style partition names" {
    const content = "/dev/nvme0n1p2 / ext4 rw,relatime 0 0\n";
    try std.testing.expectEqualStrings("nvme0n1p2", try rootPartitionNameFromMounts(content));
}

test "rootPartitionNameFromMounts returns an error when nothing is mounted at /" {
    const content = "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n";
    try std.testing.expectError(error.RootMountNotFound, rootPartitionNameFromMounts(content));
}

test "growMbrRoot preserves BIOS bootstrap code and returns an extent on retry" {
    const io = std.testing.io;
    const path = "test-root-resize-mbr.img";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size: u64 = 16 * 1024 * 1024;
    const first_lba: u32 = 2048;
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    var sector0 = mbr.singleLinuxPartitionMbr(first_lba, 4096).encode();
    @memset(sector0[0..0x1B8], 0xA5);
    try img.pwrite(io, &sector0, 0);

    const first_extent = try growMbrRoot(io, &img, &sector0, try mbr.Mbr.decode(&sector0), 1);
    try std.testing.expectEqual(@as(u64, first_lba) * mbr.sector_size, first_extent.start_bytes);
    try std.testing.expectEqual(disk_size - first_extent.start_bytes, first_extent.length_bytes);

    var after_sector0: [mbr.sector_size]u8 = undefined;
    _ = try img.pread(io, &after_sector0, 0);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xA5} ** 0x1B8), after_sector0[0..0x1B8]);

    const retry_extent = try growMbrRoot(io, &img, &after_sector0, try mbr.Mbr.decode(&after_sector0), 1);
    try std.testing.expectEqual(first_extent, retry_extent);
}

test "kernel partition resize is required only when its cached size is smaller" {
    try std.testing.expect(try partitionNeedsKernelResize(8 * 1024, 16 * 1024));
    try std.testing.expect(!try partitionNeedsKernelResize(16 * 1024, 16 * 1024));
    try std.testing.expectError(error.KernelPartitionLargerThanTable, partitionNeedsKernelResize(32 * 1024, 16 * 1024));
}

test "findRootDevice resolves disk name and partition number via a synthetic /sys/class/block tree" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Synthetic sysfs shape:
    //   devices/mock/sda/sda2/partition  (content "2\n")
    //   class_block/sda2 -> ../devices/mock/sda/sda2  (symlink)
    try tmp.dir.createDirPath(io, "devices/mock/sda/sda2");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/mock/sda/sda2/partition", .data = "2\n" });
    try tmp.dir.createDirPath(io, "class_block");

    var class_block_dir = try tmp.dir.openDir(io, "class_block", .{});
    defer class_block_dir.close(io);
    try class_block_dir.symLink(io, "../devices/mock/sda/sda2", "sda2", .{});

    const mounts_content = "/dev/sda2 / ext4 rw,relatime 0 0\n";

    const root = try findRootDevice(std.testing.allocator, io, mounts_content, class_block_dir);
    defer std.testing.allocator.free(root.disk_name);
    defer std.testing.allocator.free(root.partition_name);

    try std.testing.expectEqualStrings("sda", root.disk_name);
    try std.testing.expectEqualStrings("sda2", root.partition_name);
    try std.testing.expectEqual(@as(u32, 2), root.partition_number);
}

test "findRootDevice handles nvme-style symlink targets" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "devices/mock/nvme0n1/nvme0n1p1");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/mock/nvme0n1/nvme0n1p1/partition", .data = "1\n" });
    try tmp.dir.createDirPath(io, "class_block");

    var class_block_dir = try tmp.dir.openDir(io, "class_block", .{});
    defer class_block_dir.close(io);
    try class_block_dir.symLink(io, "../devices/mock/nvme0n1/nvme0n1p1", "nvme0n1p1", .{});

    const mounts_content = "/dev/nvme0n1p1 / ext4 rw,relatime 0 0\n";

    const root = try findRootDevice(std.testing.allocator, io, mounts_content, class_block_dir);
    defer std.testing.allocator.free(root.disk_name);
    defer std.testing.allocator.free(root.partition_name);

    try std.testing.expectEqualStrings("nvme0n1", root.disk_name);
    try std.testing.expectEqualStrings("nvme0n1p1", root.partition_name);
    try std.testing.expectEqual(@as(u32, 1), root.partition_number);
}
