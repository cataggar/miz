//! Assigns non-OS disks stable, drive-letter-style mount points from `/d`
//! through `/z`. Azure's temporary resource disk is `/d`; managed data
//! disks use `/e` plus their stable Azure LUN.
const std = @import("std");
const resource_disk = @import("resource_disk.zig");

const Allocator = std.mem.Allocator;

pub const mount_points = [_][:0]const u8{
    "/d", "/e", "/f", "/g", "/h", "/i", "/j", "/k",
    "/l", "/m", "/n", "/o", "/p", "/q", "/r", "/s",
    "/t", "/u", "/v", "/w", "/x", "/y", "/z",
};

pub const Disk = struct {
    name: []u8,
    is_resource: bool,
    /// Azure managed-disk LUN. Resource disks do not use this field.
    lun: ?u32,
};

pub fn freeDisks(allocator: Allocator, disks: []Disk) void {
    for (disks) |disk| allocator.free(disk.name);
    allocator.free(disks);
}

fn isSupportedDiskName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "sd") or
        std.mem.startsWith(u8, name, "vd") or
        std.mem.startsWith(u8, name, "xvd") or
        std.mem.startsWith(u8, name, "nvme");
}

fn isPartition(allocator: Allocator, class_block_dir: std.Io.Dir, io: std.Io, name: []const u8) !bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/partition", .{name});
    const content = class_block_dir.readFileAlloc(io, path, allocator, .limited(64)) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    allocator.free(content);
    return true;
}

fn hasSectors(allocator: Allocator, class_block_dir: std.Io.Dir, io: std.Io, name: []const u8) !bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/size", .{name});
    const content = try class_block_dir.readFileAlloc(io, path, allocator, .limited(64));
    defer allocator.free(content);
    return (try std.fmt.parseInt(u64, std.mem.trim(u8, content, " \t\r\n"), 10)) > 0;
}

/// Azure identifies local temporary NVMe storage by this controller model.
/// Unlike the older SCSI resource disk, it is not represented by the VMBus
/// LUN-1 path that `findResourceDiskName` recognizes.
fn isNvmeResourceDisk(allocator: Allocator, class_block_dir: std.Io.Dir, io: std.Io, name: []const u8) !bool {
    if (!std.mem.startsWith(u8, name, "nvme")) return false;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/device/model", .{name});
    const content = class_block_dir.readFileAlloc(io, path, allocator, .limited(256)) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(content);
    return std.mem.startsWith(u8, std.mem.trim(u8, content, " \t\r\n"), "Microsoft NVMe Direct Disk");
}

/// Azure Boost presents remote managed disks through the
/// `MSFT NVMe Accelerator v1.0` controller. Namespace 1 is the OS disk;
/// namespace 2 and above map to managed-disk LUN `nsid - 2`.
fn nvmeManagedDiskLun(allocator: Allocator, class_block_dir: std.Io.Dir, io: std.Io, name: []const u8) !u32 {
    if (!std.mem.startsWith(u8, name, "nvme")) return error.StableDiskIdentityUnavailable;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const model_path = try std.fmt.bufPrint(&path_buf, "{s}/device/model", .{name});
    const model_content = class_block_dir.readFileAlloc(io, model_path, allocator, .limited(256)) catch |err| switch (err) {
        error.FileNotFound => return error.StableDiskIdentityUnavailable,
        else => return err,
    };
    defer allocator.free(model_content);
    if (!std.mem.eql(u8, std.mem.trim(u8, model_content, " \t\r\n"), "MSFT NVMe Accelerator v1.0")) {
        return error.StableDiskIdentityUnavailable;
    }

    const nsid_path = try std.fmt.bufPrint(&path_buf, "{s}/device/nsid", .{name});
    const nsid_content = class_block_dir.readFileAlloc(io, nsid_path, allocator, .limited(64)) catch |err| switch (err) {
        error.FileNotFound => return error.StableDiskIdentityUnavailable,
        else => return err,
    };
    defer allocator.free(nsid_content);
    const nsid = std.fmt.parseInt(u32, std.mem.trim(u8, nsid_content, " \t\r\n"), 10) catch
        return error.StableDiskIdentityUnavailable;
    if (nsid < 2) return error.StableDiskIdentityUnavailable;
    return nsid - 2;
}

/// Extracts the final LUN field from a SCSI sysfs link such as
/// `.../0:0:0:3/block/sdc`. Azure documents this host:channel:target:LUN
/// tuple as the stable mapping between managed disks and guest devices.
fn scsiLun(class_block_dir: std.Io.Dir, io: std.Io, name: []const u8) !u32 {
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_len = try class_block_dir.readLink(io, name, &link_buf);
    const target = link_buf[0..link_len];
    const block_index = std.mem.lastIndexOf(u8, target, "/block/") orelse return error.StableDiskIdentityUnavailable;
    const address = std.fs.path.basename(target[0..block_index]);
    const last_colon = std.mem.lastIndexOfScalar(u8, address, ':') orelse return error.StableDiskIdentityUnavailable;
    return std.fmt.parseInt(u32, address[last_colon + 1 ..], 10) catch return error.StableDiskIdentityUnavailable;
}

fn managedDiskLun(allocator: Allocator, class_block_dir: std.Io.Dir, io: std.Io, name: []const u8) !u32 {
    if (std.mem.startsWith(u8, name, "nvme")) {
        return nvmeManagedDiskLun(allocator, class_block_dir, io, name);
    }
    return scsiLun(class_block_dir, io, name);
}

/// Enumerates class-block disks while excluding the OS disk and partitions.
/// Disks that cannot be identified as either Azure temporary storage or a
/// managed-disk LUN are skipped rather than assigned an unstable path. When
/// the physical OS disk cannot be resolved (for example, a device-mapper
/// root), callers must disable managed-data-disk mounting.
pub fn discoverDisks(
    allocator: Allocator,
    class_block_dir: std.Io.Dir,
    io: std.Io,
    root_disk_name: ?[]const u8,
    scsi_resource_disk_name: ?[]const u8,
) ![]Disk {
    var disks = std.array_list.Managed(Disk).init(allocator);
    errdefer {
        for (disks.items) |disk| allocator.free(disk.name);
        disks.deinit();
    }

    var it = class_block_dir.iterate();
    while (try it.next(io)) |entry| {
        if (!isSupportedDiskName(entry.name)) continue;
        if (root_disk_name) |root_name| {
            if (std.mem.eql(u8, entry.name, root_name)) continue;
        }
        if (try isPartition(allocator, class_block_dir, io, entry.name)) continue;
        if (!try hasSectors(allocator, class_block_dir, io, entry.name)) continue;

        const is_scsi_resource = if (scsi_resource_disk_name) |resource_name|
            std.mem.eql(u8, entry.name, resource_name)
        else
            false;
        const is_resource = is_scsi_resource or try isNvmeResourceDisk(allocator, class_block_dir, io, entry.name);
        const lun = if (is_resource) null else managedDiskLun(allocator, class_block_dir, io, entry.name) catch |err| {
            std.debug.print("azagent: warning: skipping unclassified disk /dev/{s}: {t}\n", .{ entry.name, err });
            continue;
        };

        try disks.append(.{
            .name = try allocator.dupe(u8, entry.name),
            .is_resource = is_resource,
            .lun = lun,
        });
    }

    std.mem.sort(Disk, disks.items, {}, struct {
        fn lessThan(_: void, a: Disk, b: Disk) bool {
            if (a.is_resource != b.is_resource) return a.is_resource;
            if (a.lun != null and b.lun != null and a.lun.? != b.lun.?) return a.lun.? < b.lun.?;
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lessThan);

    return try disks.toOwnedSlice();
}

fn mountPointForDisk(disk: Disk) ?[:0]const u8 {
    if (disk.is_resource) return mount_points[0];
    const index = std.math.add(u32, disk.lun orelse return null, 1) catch return null;
    if (index >= mount_points.len) return null;
    return mount_points[index];
}

pub const SetupOptions = struct {
    allocator: Allocator,
    io: std.Io,
    class_block_dir: std.Io.Dir,
    root_disk_name: ?[]const u8,
    scsi_resource_disk_name: ?[]const u8,
    now_unix_seconds: i64,
    resource_enabled: bool,
    resource_mount_point: []const u8 = resource_disk.default_mount_point,
    resource_filesystem: resource_disk.Filesystem = .ext4,
    /// Applies to the resource disk only. Managed data disks are mount-only
    /// (this module never writes their metadata), so their ownership is
    /// whatever the person who formatted them chose, and is not ours to
    /// overwrite on every boot.
    resource_owner: ?resource_disk.Owner = null,
    resource_enable_swap: bool = false,
    resource_swap_size_mb: u32 = resource_disk.default_swap_size_mb,
    data_disks_enabled: bool = false,
};

/// Mounts one temporary resource disk and opted-in managed data disks. Data
/// disks are mount-only: no partition table or filesystem metadata is ever
/// written. Existing ext4 partition 1 mounts; blank and unknown layouts are
/// reported and left untouched.
pub fn setup(options: SetupOptions) !void {
    const disks = try discoverDisks(
        options.allocator,
        options.class_block_dir,
        options.io,
        options.root_disk_name,
        options.scsi_resource_disk_name,
    );
    defer freeDisks(options.allocator, disks);

    var mounted_resource = false;
    var used_mount_points: u32 = 0;
    for (disks) |disk| {
        if (disk.is_resource and (!options.resource_enabled or mounted_resource)) {
            if (mounted_resource) {
                std.debug.print("azagent: warning: additional temporary disk /dev/{s} is not mounted\n", .{disk.name});
            }
            continue;
        }
        if (!disk.is_resource and !options.data_disks_enabled) continue;

        const conventional_mount_point = mountPointForDisk(disk) orelse {
            std.debug.print("azagent: warning: no alphabetical mount point available for /dev/{s}\n", .{disk.name});
            continue;
        };
        const mount_index: u5 = @intCast(if (disk.is_resource) 0 else disk.lun.? + 1);
        const mount_mask = @as(u32, 1) << mount_index;
        if (used_mount_points & mount_mask != 0) {
            std.debug.print("azagent: warning: duplicate Azure disk LUN for /dev/{s}; leaving it unmounted\n", .{disk.name});
            continue;
        }
        const mount_point: []const u8 = if (disk.is_resource) options.resource_mount_point else conventional_mount_point;
        resource_disk.setupDevice(.{
            .allocator = options.allocator,
            .io = options.io,
            .device_name = disk.name,
            .now_unix_seconds = options.now_unix_seconds,
            .mount_point = mount_point,
            .format_policy = if (disk.is_resource) .replace_invalid else .mount_existing,
            .filesystem = if (disk.is_resource) options.resource_filesystem else .ext4,
            .owner = if (disk.is_resource) options.resource_owner else null,
            .write_dataloss_warning = disk.is_resource,
            .enable_swap = disk.is_resource and options.resource_enable_swap,
            .swap_size_mb = options.resource_swap_size_mb,
        }) catch |err| {
            std.debug.print("azagent: warning: failed to mount /dev/{s} at {s}: {t}\n", .{ disk.name, mount_point, err });
            continue;
        };
        used_mount_points |= mount_mask;
        if (disk.is_resource) mounted_resource = true;
    }
}

fn addSyntheticScsiDisk(io: std.Io, root: std.Io.Dir, class_dir: std.Io.Dir, name: []const u8, address: []const u8, size: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "devices/{s}/block/{s}", .{ address, name });
    try root.createDirPath(io, path);
    var disk_dir = try root.openDir(io, path, .{});
    defer disk_dir.close(io);
    try disk_dir.writeFile(io, .{ .sub_path = "size", .data = size });

    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "../{s}", .{path});
    try class_dir.symLink(io, target, name, .{});
}

fn addSyntheticNvmeResource(io: std.Io, root: std.Io.Dir, class_dir: std.Io.Dir, name: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "devices/nvme/{s}", .{name});
    try root.createDirPath(io, path);
    var disk_dir = try root.openDir(io, path, .{});
    defer disk_dir.close(io);
    try disk_dir.writeFile(io, .{ .sub_path = "size", .data = "1000\n" });
    try disk_dir.createDir(io, "device", .default_dir);
    var device_dir = try disk_dir.openDir(io, "device", .{});
    defer device_dir.close(io);
    try device_dir.writeFile(io, .{ .sub_path = "model", .data = "Microsoft NVMe Direct Disk v2\n" });

    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "../{s}", .{path});
    try class_dir.symLink(io, target, name, .{});
}

fn addSyntheticNvmeManaged(io: std.Io, root: std.Io.Dir, class_dir: std.Io.Dir, name: []const u8, nsid: []const u8) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "devices/nvme/{s}", .{name});
    try root.createDirPath(io, path);
    var disk_dir = try root.openDir(io, path, .{});
    defer disk_dir.close(io);
    try disk_dir.writeFile(io, .{ .sub_path = "size", .data = "1000\n" });
    try disk_dir.createDir(io, "device", .default_dir);
    var device_dir = try disk_dir.openDir(io, "device", .{});
    defer device_dir.close(io);
    try device_dir.writeFile(io, .{ .sub_path = "model", .data = "MSFT NVMe Accelerator v1.0\n" });
    try device_dir.writeFile(io, .{ .sub_path = "nsid", .data = nsid });

    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const target = try std.fmt.bufPrint(&target_buf, "../{s}", .{path});
    try class_dir.symLink(io, target, name, .{});
}

test "discoverDisks puts the resource disk first and orders managed disks by Azure LUN" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "class", .default_dir);
    var class_dir = try tmp.dir.openDir(io, "class", .{ .iterate = true });
    defer class_dir.close(io);

    try addSyntheticScsiDisk(io, tmp.dir, class_dir, "sda", "0:0:0:0", "1000\n");
    try addSyntheticScsiDisk(io, tmp.dir, class_dir, "sdb", "1:0:0:2", "3000\n");
    try addSyntheticScsiDisk(io, tmp.dir, class_dir, "sdc", "0:0:0:1", "2000\n");
    try addSyntheticScsiDisk(io, tmp.dir, class_dir, "sdd", "1:0:0:0", "4000\n");

    const disks = try discoverDisks(allocator, class_dir, io, "sda", "sdc");
    defer freeDisks(allocator, disks);

    try std.testing.expectEqual(@as(usize, 3), disks.len);
    try std.testing.expectEqualStrings("sdc", disks[0].name);
    try std.testing.expect(disks[0].is_resource);
    try std.testing.expectEqualStrings("sdd", disks[1].name);
    try std.testing.expectEqual(@as(?u32, 0), disks[1].lun);
    try std.testing.expectEqualStrings("sdb", disks[2].name);
    try std.testing.expectEqual(@as(?u32, 2), disks[2].lun);
}

test "discoverDisks recognizes Azure NVMe temporary storage by model" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "class", .default_dir);
    var class_dir = try tmp.dir.openDir(io, "class", .{ .iterate = true });
    defer class_dir.close(io);

    try addSyntheticNvmeResource(io, tmp.dir, class_dir, "nvme0n1");
    const disks = try discoverDisks(allocator, class_dir, io, "sda", null);
    defer freeDisks(allocator, disks);

    try std.testing.expectEqual(@as(usize, 1), disks.len);
    try std.testing.expect(disks[0].is_resource);
}

test "discoverDisks maps Azure Boost NVMe namespaces to managed-disk LUNs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "class", .default_dir);
    var class_dir = try tmp.dir.openDir(io, "class", .{ .iterate = true });
    defer class_dir.close(io);

    try addSyntheticNvmeManaged(io, tmp.dir, class_dir, "nvme0n1", "1\n");
    try addSyntheticNvmeManaged(io, tmp.dir, class_dir, "nvme0n2", "2\n");
    try addSyntheticNvmeManaged(io, tmp.dir, class_dir, "nvme0n4", "4\n");
    const disks = try discoverDisks(allocator, class_dir, io, "nvme0n1", null);
    defer freeDisks(allocator, disks);

    try std.testing.expectEqual(@as(usize, 2), disks.len);
    try std.testing.expectEqualStrings("nvme0n2", disks[0].name);
    try std.testing.expectEqual(@as(?u32, 0), disks[0].lun);
    try std.testing.expectEqualStrings("nvme0n4", disks[1].name);
    try std.testing.expectEqual(@as(?u32, 2), disks[1].lun);
}

test "mount points reserve d and map managed-disk LUN zero through twenty-one to e through z" {
    var unused_name: [0]u8 = .{};
    try std.testing.expectEqualStrings("/d", mountPointForDisk(.{ .name = &unused_name, .is_resource = true, .lun = null }).?);
    try std.testing.expectEqualStrings("/e", mountPointForDisk(.{ .name = &unused_name, .is_resource = false, .lun = 0 }).?);
    try std.testing.expectEqualStrings("/z", mountPointForDisk(.{ .name = &unused_name, .is_resource = false, .lun = 21 }).?);
    try std.testing.expectEqual(@as(?[:0]const u8, null), mountPointForDisk(.{ .name = &unused_name, .is_resource = false, .lun = 22 }));
}
