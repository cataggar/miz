//! Block-device geometry probing.
//!
//! `stat(2)` on a block-device special file reports `st_size == 0` on Linux
//! -- the size belongs to the device the node points at, not to the node
//! itself -- so an image opened from `/dev/nvme0n1`, `/dev/sda`, or a
//! device-mapper node like `/dev/mapper/vg-lv` has to ask the kernel for its
//! real size instead of trusting `Io.File.stat`. Linux answers that with the
//! `BLKGETSIZE64`/`BLKSSZGET` ioctls; every other platform gets a clear
//! `error.UnsupportedBlockDevice` rather than a silently zero-length image.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const guid = @import("guid.zig");
const identity_rewrite = @import("identity_rewrite.zig");
const mbr = @import("mbr.zig");

/// The Linux `BLKGETSIZE64` ioctl request code (`_IOR(0x12, 114, size_t)`),
/// which reports the device's size in bytes. Same constant as the one
/// `azagent/resource_disk.zig` uses for the resource disk.
const blkgetsize64: u32 = 0x80081272;

/// The Linux `BLKSSZGET` ioctl request code (`_IO(0x12, 104)`), which
/// reports the logical (smallest addressable) sector size as a C `int`.
const blkssget: u32 = 0x1268;

/// The Linux `BLKRRPART` ioctl request code (`_IO(0x12, 95)`), which asks
/// the kernel to discard its cached partition layout and read it again.
const blkrrpart: u32 = 0x125F;

/// Smallest logical sector size any supported disk layout can use: every
/// partition table this library writes addresses 512-byte LBAs at minimum.
pub const min_logical_sector_size: u32 = 512;

/// Generous upper bound on a sane logical sector size. Real hardware tops
/// out at 4096 today; anything beyond this is a garbage ioctl answer rather
/// than a disk we could lay out.
pub const max_logical_sector_size: u32 = 64 * 1024;

pub const ProbeError = error{
    /// The platform has no block-device size interface wired up here.
    UnsupportedBlockDevice,
    /// The `BLKGETSIZE64` ioctl failed.
    BlockDeviceSizeUnavailable,
    /// The `BLKSSZGET` ioctl failed.
    BlockDeviceSectorSizeUnavailable,
    /// The device exists but has no medium/backing extent (an empty loop
    /// device, an optical drive with no disc). Reported instead of handing
    /// back a zero-length image whose every read silently returns nothing.
    EmptyBlockDevice,
    InvalidLogicalSectorSize,
    UnalignedBlockDeviceSize,
    BlockDeviceChangedDuringOpen,
};

pub const ReReadPartitionTableError = error{
    UnsupportedBlockDevice,
    BlockDeviceBusy,
    PartitionTableRefreshFailed,
};

pub const Geometry = struct {
    /// The device's real size in bytes, as reported by the kernel. This, not
    /// the `stat` size, is authoritative for a device-backed image.
    size_bytes: u64,
    logical_sector_size: u32,
};

pub const DeviceNumber = struct {
    major: u32,
    minor: u32,

    pub fn eql(a: DeviceNumber, b: DeviceNumber) bool {
        return a.major == b.major and a.minor == b.minor;
    }
};

pub const Transport = enum {
    usb,
    nvme,
    mmc,
    virtio,
    scsi,
    device_mapper,
    md,
    unknown,
};

pub const PartitionTable = enum {
    none,
    mbr,
    gpt,
};

pub const Signatures = packed struct {
    ext4: bool = false,
    xfs: bool = false,
    fat: bool = false,
    ntfs: bool = false,
    btrfs: bool = false,
    swap: bool = false,
    luks: bool = false,
    lvm2: bool = false,
};

pub const FilesystemIdentityKind = enum {
    none,
    fat,
    ext4,
    xfs,
    ambiguous,
};

pub const FilesystemIdentity = struct {
    kind: FilesystemIdentityKind = .none,
    identifier: [identity_rewrite.canonical_uuid_bytes]u8 =
        [_]u8{0} ** identity_rewrite.canonical_uuid_bytes,
    identifier_len: u8 = 0,

    pub fn identifierText(self: *const FilesystemIdentity) ?[]const u8 {
        return switch (self.kind) {
            .fat, .ext4, .xfs => if (self.identifier_len == 0)
                null
            else
                self.identifier[0..self.identifier_len],
            .none, .ambiguous => null,
        };
    }
};

pub const PartitionReport = struct {
    table_index: u32,
    first_lba: u64,
    last_lba: u64,
    name: [72]u8 = [_]u8{0} ** 72,
    name_len: u8 = 0,
    gpt_unique_guid: [identity_rewrite.canonical_uuid_bytes]u8 =
        [_]u8{0} ** identity_rewrite.canonical_uuid_bytes,
    gpt_unique_guid_len: u8 = 0,
    filesystem: FilesystemIdentity = .{},
    signatures: Signatures = .{},

    pub fn partitionName(self: *const PartitionReport) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn gptUniqueGuid(self: *const PartitionReport) ?[]const u8 {
        return if (self.gpt_unique_guid_len == 0)
            null
        else
            self.gpt_unique_guid[0..self.gpt_unique_guid_len];
    }
};

pub const IdentityInventory = struct {
    partition_table: PartitionTable,
    partitions: []PartitionReport,
    device_signatures: Signatures,
    gpt_disk_guid: [identity_rewrite.canonical_uuid_bytes]u8 =
        [_]u8{0} ** identity_rewrite.canonical_uuid_bytes,
    gpt_disk_guid_len: u8 = 0,
    device_filesystem: FilesystemIdentity = .{},

    pub fn deinit(self: *IdentityInventory, allocator: std.mem.Allocator) void {
        allocator.free(self.partitions);
        self.* = undefined;
    }

    pub fn gptDiskGuid(self: *const IdentityInventory) ?[]const u8 {
        return if (self.gpt_disk_guid_len == 0)
            null
        else
            self.gpt_disk_guid[0..self.gpt_disk_guid_len];
    }
};

/// Information callers should show before asking a human to approve
/// destruction of a device. The partition slice and device names are owned.
pub const PreflightReport = struct {
    target_name: []u8,
    whole_disk_name: []u8,
    geometry: Geometry,
    removable: bool,
    transport: Transport,
    partition_table: PartitionTable,
    partitions: []PartitionReport,
    device_signatures: Signatures,
    gpt_disk_guid: [identity_rewrite.canonical_uuid_bytes]u8 =
        [_]u8{0} ** identity_rewrite.canonical_uuid_bytes,
    gpt_disk_guid_len: u8 = 0,
    device_filesystem: FilesystemIdentity = .{},

    pub fn deinit(self: *PreflightReport, allocator: std.mem.Allocator) void {
        allocator.free(self.target_name);
        allocator.free(self.whole_disk_name);
        allocator.free(self.partitions);
        self.* = undefined;
    }

    pub fn gptDiskGuid(self: *const PreflightReport) ?[]const u8 {
        return if (self.gpt_disk_guid_len == 0)
            null
        else
            self.gpt_disk_guid[0..self.gpt_disk_guid_len];
    }
};

pub const ReadAtSource = struct {
    ctx: *const anyopaque,
    read_at_fn: *const fn (
        ctx: *const anyopaque,
        io: Io,
        buffer: []u8,
        offset: u64,
    ) anyerror!usize,
};

pub const InventoryError = std.mem.Allocator.Error || error{
    DeviceInspectionFailed,
};

pub const CollisionKind = enum {
    gpt_disk_guid,
    gpt_partition_guid,
    filesystem_identifier,
};

pub const Collision = struct {
    kind: CollisionKind,
    identifier: [identity_rewrite.canonical_uuid_bytes]u8 =
        [_]u8{0} ** identity_rewrite.canonical_uuid_bytes,
    identifier_len: u8 = 0,
    source_partition_table_index: ?u32 = null,
    source_filesystem: FilesystemIdentityKind = .none,
    visible_device_name: []u8,
    visible_partition_table_index: ?u32 = null,
    visible_filesystem: FilesystemIdentityKind = .none,

    pub fn identifierText(self: *const Collision) []const u8 {
        return self.identifier[0..self.identifier_len];
    }
};

pub const CollisionReport = struct {
    collisions: []Collision,
    scanned_visible_disks: usize = 0,

    pub fn deinit(self: *CollisionReport, allocator: std.mem.Allocator) void {
        for (self.collisions) |collision| allocator.free(collision.visible_device_name);
        allocator.free(self.collisions);
        self.* = undefined;
    }
};

pub const CollisionError = InventoryError || ProbeError || error{
    UnsupportedBlockDevicePreflight,
    BlockDeviceSysfsUnavailable,
    InvalidBlockDeviceSysfs,
    VisibleDeviceUnavailable,
    VisibleDeviceNotBlockDevice,
};

pub const OpenedVisibleDevice = struct {
    file: Io.File,
    geometry: Geometry,
};

pub const VisibleDeviceOpener = struct {
    context: ?*anyopaque = null,
    open_fn: *const fn (
        context: ?*anyopaque,
        io: Io,
        device_name: []const u8,
    ) CollisionError!OpenedVisibleDevice = openVisibleDeviceFromDev,
};

pub const PreflightOptions = struct {
    /// Reserved for advisory policy. It deliberately does not relax size,
    /// mount, holder, or running-root refusals.
    force: bool = false,
};

pub const PreflightError = ProbeError || std.mem.Allocator.Error || error{
    DestinationTooSmall,
    UnsupportedBlockDevicePreflight,
    BlockDeviceIdentityUnavailable,
    BlockDeviceNotInSysfs,
    BlockDeviceSysfsUnavailable,
    InvalidBlockDeviceSysfs,
    MountInfoUnavailable,
    InvalidMountInfo,
    RootDeviceResolutionFailed,
    RootDeviceWriteRefused,
    TargetMounted,
    TargetContainsMountedPartition,
    TargetHasHolders,
    DeviceInspectionFailed,
};

pub fn describePreflightFailure(err: anyerror) ?[]const u8 {
    return switch (err) {
        error.DestinationTooSmall => "the source image is larger than the target device",
        error.RootDeviceWriteRefused => "the target backs the running root filesystem and can never be overwritten",
        error.TargetMounted => "the target device is mounted",
        error.TargetContainsMountedPartition => "a partition beneath the target device is mounted",
        error.TargetHasHolders => "the target device or one of its partitions is in use by device-mapper, md, or LVM",
        error.BlockDeviceNotInSysfs => "the target block device is not represented in /sys/class/block",
        error.BlockDeviceSysfsUnavailable => "block-device safety data under /sys/class/block is unavailable",
        error.MountInfoUnavailable => "mount safety data in /proc/self/mountinfo is unavailable",
        error.RootDeviceResolutionFailed => "the device backing the running root filesystem could not be resolved safely",
        error.DeviceInspectionFailed => "the target's existing partition table and filesystem signatures could not be inspected",
        error.BlockDeviceChangedDuringOpen => "the target device changed between the safety check and writable open",
        else => null,
    };
}

/// Reads `file`'s real geometry. `file` must already be known to be a
/// block-device node (`Io.File.Stat.kind == .block_device`); the ioctls are
/// not meaningful on anything else.
pub fn probe(file: Io.File) ProbeError!Geometry {
    return switch (builtin.os.tag) {
        .linux => probeLinux(file),
        else => error.UnsupportedBlockDevice,
    };
}

fn probeLinux(file: Io.File) ProbeError!Geometry {
    const linux = std.os.linux;

    var size_bytes: u64 = 0;
    const size_rc = linux.ioctl(file.handle, blkgetsize64, @intFromPtr(&size_bytes));
    switch (linux.errno(size_rc)) {
        .SUCCESS => {},
        .NODEV, .NXIO => return error.BlockDeviceChangedDuringOpen,
        else => return error.BlockDeviceSizeUnavailable,
    }

    var logical_sector_size: c_int = 0;
    const sector_rc = linux.ioctl(file.handle, blkssget, @intFromPtr(&logical_sector_size));
    switch (linux.errno(sector_rc)) {
        .SUCCESS => {},
        .NODEV, .NXIO => return error.BlockDeviceChangedDuringOpen,
        else => return error.BlockDeviceSectorSizeUnavailable,
    }

    return geometryFrom(size_bytes, logical_sector_size);
}

const IoctlFn = *const fn (?*anyopaque, std.os.linux.fd_t, u32, usize) usize;

fn systemIoctl(_: ?*anyopaque, fd: std.os.linux.fd_t, request: u32, argument: usize) usize {
    return std.os.linux.ioctl(fd, request, argument);
}

fn reReadPartitionTableLinux(
    file: Io.File,
    context: ?*anyopaque,
    ioctl_fn: IoctlFn,
) ReReadPartitionTableError!void {
    switch (std.os.linux.errno(ioctl_fn(context, file.handle, blkrrpart, 0))) {
        .SUCCESS => {},
        .BUSY => return error.BlockDeviceBusy,
        else => return error.PartitionTableRefreshFailed,
    }
}

/// Asks the kernel to re-read the partition table from an already-open whole
/// block device. `BlockDeviceBusy` is distinct because it means a partition
/// is still in use; every other ioctl failure is reported without being
/// silently treated as success.
pub fn reReadPartitionTable(file: Io.File) ReReadPartitionTableError!void {
    return switch (builtin.os.tag) {
        .linux => reReadPartitionTableLinux(file, null, systemIoctl),
        else => error.UnsupportedBlockDevice,
    };
}

/// Returns the kernel major/minor pair for an already-open block-device
/// descriptor. Using `AT_EMPTY_PATH` binds the identity to the descriptor
/// rather than re-resolving a path that could have changed.
pub fn deviceNumber(file: Io.File) PreflightError!DeviceNumber {
    if (builtin.os.tag != .linux) return error.UnsupportedBlockDevicePreflight;

    const linux = std.os.linux;
    var statx_buf: linux.Statx = undefined;
    const rc = linux.statx(
        file.handle,
        "",
        linux.AT.EMPTY_PATH,
        .{ .TYPE = true },
        &statx_buf,
    );
    if (linux.errno(rc) != .SUCCESS) return error.BlockDeviceIdentityUnavailable;
    return .{ .major = statx_buf.rdev_major, .minor = statx_buf.rdev_minor };
}

/// Reads `/proc/self/mountinfo` without trusting procfs' synthetic stat size.
pub fn readMountInfo(allocator: std.mem.Allocator) PreflightError![]u8 {
    if (builtin.os.tag != .linux) return error.UnsupportedBlockDevicePreflight;

    const linux = std.os.linux;
    const open_rc = linux.open("/proc/self/mountinfo", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return error.MountInfoUnavailable;
    const fd: linux.fd_t = @intCast(open_rc);
    defer _ = linux.close(fd);

    var content = std.array_list.Managed(u8).init(allocator);
    errdefer content.deinit();
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const read_rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(read_rc) != .SUCCESS) return error.MountInfoUnavailable;
        if (read_rc == 0) break;
        try content.appendSlice(buf[0..read_rc]);
    }
    return content.toOwnedSlice();
}

/// Resolves a partition's containing whole-disk name from its sysfs symlink,
/// without guessing from `sda2`, `nvme0n1p2`, or `mmcblk0p2` spelling.
pub fn parentDiskName(
    io: Io,
    class_block_dir: Io.Dir,
    partition_name: []const u8,
    link_buf: []u8,
) PreflightError![]const u8 {
    const link_len = class_block_dir.readLink(io, partition_name, link_buf) catch
        return error.InvalidBlockDeviceSysfs;
    const parent = std.fs.path.dirname(link_buf[0..link_len]) orelse
        return error.InvalidBlockDeviceSysfs;
    const disk_name = std.fs.path.basename(parent);
    if (disk_name.len == 0 or std.mem.eql(u8, disk_name, partition_name)) {
        return error.InvalidBlockDeviceSysfs;
    }
    return disk_name;
}

const NameSet = struct {
    allocator: std.mem.Allocator,
    items: std.array_list.Managed([]u8),

    fn init(allocator: std.mem.Allocator) NameSet {
        return .{
            .allocator = allocator,
            .items = std.array_list.Managed([]u8).init(allocator),
        };
    }

    fn deinit(self: *NameSet) void {
        for (self.items.items) |item| self.allocator.free(item);
        self.items.deinit();
    }

    fn contains(self: NameSet, name: []const u8) bool {
        for (self.items.items) |item| {
            if (std.mem.eql(u8, item, name)) return true;
        }
        return false;
    }

    fn append(self: *NameSet, name: []const u8) std.mem.Allocator.Error!bool {
        if (self.contains(name)) return false;
        try self.items.append(try self.allocator.dupe(u8, name));
        return true;
    }
};

fn sysfsPath(buf: []u8, device_name: []const u8, leaf: []const u8) PreflightError![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ device_name, leaf }) catch
        return error.InvalidBlockDeviceSysfs;
}

fn readSmallSysfsFile(
    io: Io,
    class_block_dir: Io.Dir,
    device_name: []const u8,
    leaf: []const u8,
    out: []u8,
) PreflightError![]const u8 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try sysfsPath(&path_buf, device_name, leaf);
    const file = class_block_dir.openFile(io, path, .{}) catch
        return error.InvalidBlockDeviceSysfs;
    defer file.close(io);
    const n = file.readPositionalAll(io, out, 0) catch
        return error.InvalidBlockDeviceSysfs;
    if (n == out.len) return error.InvalidBlockDeviceSysfs;
    return std.mem.trim(u8, out[0..n], " \t\r\n");
}

fn isPartition(io: Io, class_block_dir: Io.Dir, device_name: []const u8) PreflightError!bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try sysfsPath(&path_buf, device_name, "partition");
    const file = class_block_dir.openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return error.InvalidBlockDeviceSysfs,
    };
    file.close(io);
    return true;
}

fn parseDeviceNumber(text: []const u8) PreflightError!DeviceNumber {
    const colon = std.mem.indexOfScalar(u8, text, ':') orelse return error.InvalidBlockDeviceSysfs;
    return .{
        .major = std.fmt.parseInt(u32, text[0..colon], 10) catch
            return error.InvalidBlockDeviceSysfs,
        .minor = std.fmt.parseInt(u32, text[colon + 1 ..], 10) catch
            return error.InvalidBlockDeviceSysfs,
    };
}

fn deviceNumberFromSysfs(
    io: Io,
    class_block_dir: Io.Dir,
    device_name: []const u8,
) PreflightError!DeviceNumber {
    var content_buf: [64]u8 = undefined;
    return parseDeviceNumber(try readSmallSysfsFile(
        io,
        class_block_dir,
        device_name,
        "dev",
        &content_buf,
    ));
}

fn findNameByDeviceNumber(
    allocator: std.mem.Allocator,
    io: Io,
    class_block_dir: Io.Dir,
    wanted: DeviceNumber,
) PreflightError![]u8 {
    var iterator = class_block_dir.iterate();
    while (iterator.next(io) catch return error.InvalidBlockDeviceSysfs) |entry| {
        const number = deviceNumberFromSysfs(io, class_block_dir, entry.name) catch |err| switch (err) {
            error.InvalidBlockDeviceSysfs => continue,
            else => return err,
        };
        if (number.eql(wanted)) return allocator.dupe(u8, entry.name);
    }
    return error.BlockDeviceNotInSysfs;
}

fn wholeDiskNameAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    class_block_dir: Io.Dir,
    device_name: []const u8,
) PreflightError![]u8 {
    if (!try isPartition(io, class_block_dir, device_name)) {
        return allocator.dupe(u8, device_name);
    }
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    return allocator.dupe(u8, try parentDiskName(io, class_block_dir, device_name, &link_buf));
}

fn collectTargetDevices(
    allocator: std.mem.Allocator,
    io: Io,
    class_block_dir: Io.Dir,
    target_name: []const u8,
) PreflightError!NameSet {
    var devices = NameSet.init(allocator);
    errdefer devices.deinit();
    _ = try devices.append(target_name);

    if (try isPartition(io, class_block_dir, target_name)) return devices;

    var iterator = class_block_dir.iterate();
    while (iterator.next(io) catch return error.InvalidBlockDeviceSysfs) |entry| {
        if (!try isPartition(io, class_block_dir, entry.name)) continue;
        var link_buf: [std.fs.max_path_bytes]u8 = undefined;
        const parent = try parentDiskName(io, class_block_dir, entry.name, &link_buf);
        if (std.mem.eql(u8, parent, target_name)) _ = try devices.append(entry.name);
    }
    return devices;
}

fn collectBackingDevices(
    devices: *NameSet,
    io: Io,
    class_block_dir: Io.Dir,
    device_name: []const u8,
) PreflightError!void {
    if (!try devices.append(device_name)) return;

    const partition = try isPartition(io, class_block_dir, device_name);
    if (partition) {
        var link_buf: [std.fs.max_path_bytes]u8 = undefined;
        try collectBackingDevices(
            devices,
            io,
            class_block_dir,
            try parentDiskName(io, class_block_dir, device_name, &link_buf),
        );
    }

    if (partition) return;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const slaves_path = try sysfsPath(&path_buf, device_name, "slaves");
    var slaves = class_block_dir.openDir(io, slaves_path, .{ .iterate = true }) catch
        return error.InvalidBlockDeviceSysfs;
    defer slaves.close(io);
    var iterator = slaves.iterate();
    while (iterator.next(io) catch return error.InvalidBlockDeviceSysfs) |entry| {
        try collectBackingDevices(devices, io, class_block_dir, entry.name);
    }
}

const MountState = struct {
    root: ?DeviceNumber = null,
    mounted: std.array_list.Managed(DeviceNumber),

    fn deinit(self: *MountState) void {
        self.mounted.deinit();
    }
};

fn parseMountInfo(
    allocator: std.mem.Allocator,
    content: []const u8,
) PreflightError!MountState {
    var state = MountState{
        .mounted = std.array_list.Managed(DeviceNumber).init(allocator),
    };
    errdefer state.deinit();

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        _ = fields.next() orelse return error.InvalidMountInfo;
        _ = fields.next() orelse return error.InvalidMountInfo;
        const device_text = fields.next() orelse return error.InvalidMountInfo;
        _ = fields.next() orelse return error.InvalidMountInfo;
        const mount_point = fields.next() orelse return error.InvalidMountInfo;

        const colon = std.mem.indexOfScalar(u8, device_text, ':') orelse
            return error.InvalidMountInfo;
        const number = DeviceNumber{
            .major = std.fmt.parseInt(u32, device_text[0..colon], 10) catch
                return error.InvalidMountInfo,
            .minor = std.fmt.parseInt(u32, device_text[colon + 1 ..], 10) catch
                return error.InvalidMountInfo,
        };
        try state.mounted.append(number);
        if (std.mem.eql(u8, mount_point, "/")) state.root = number;
    }
    return state;
}

fn deviceHasHolders(io: Io, class_block_dir: Io.Dir, device_name: []const u8) PreflightError!bool {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const holders_path = try sysfsPath(&path_buf, device_name, "holders");
    var holders = class_block_dir.openDir(io, holders_path, .{ .iterate = true }) catch
        return error.InvalidBlockDeviceSysfs;
    defer holders.close(io);
    var iterator = holders.iterate();
    return (iterator.next(io) catch return error.InvalidBlockDeviceSysfs) != null;
}

fn mountedState(
    target: DeviceNumber,
    target_devices: NameSet,
    mount_state: MountState,
    io: Io,
    class_block_dir: Io.Dir,
) PreflightError!void {
    for (mount_state.mounted.items) |mounted| {
        if (mounted.eql(target)) return error.TargetMounted;
        for (target_devices.items.items[1..]) |child| {
            if ((try deviceNumberFromSysfs(io, class_block_dir, child)).eql(mounted)) {
                return error.TargetContainsMountedPartition;
            }
        }
    }
}

fn transportFor(
    io: Io,
    class_block_dir: Io.Dir,
    whole_disk_name: []const u8,
) PreflightError!Transport {
    if (std.mem.startsWith(u8, whole_disk_name, "dm-")) return .device_mapper;
    if (std.mem.startsWith(u8, whole_disk_name, "md")) return .md;

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_len = class_block_dir.readLink(io, whole_disk_name, &link_buf) catch
        return error.InvalidBlockDeviceSysfs;
    const target = link_buf[0..link_len];
    if (std.mem.indexOf(u8, target, "/usb") != null) return .usb;
    if (std.mem.indexOf(u8, target, "/nvme") != null or
        std.mem.startsWith(u8, whole_disk_name, "nvme"))
    {
        return .nvme;
    }
    if (std.mem.indexOf(u8, target, "/mmc") != null or
        std.mem.startsWith(u8, whole_disk_name, "mmcblk"))
    {
        return .mmc;
    }
    if (std.mem.indexOf(u8, target, "/virtio") != null or
        std.mem.startsWith(u8, whole_disk_name, "vd"))
    {
        return .virtio;
    }
    if (std.mem.indexOf(u8, target, "/host") != null or
        std.mem.startsWith(u8, whole_disk_name, "sd"))
    {
        return .scsi;
    }
    return .unknown;
}

fn removableFor(io: Io, class_block_dir: Io.Dir, whole_disk_name: []const u8) PreflightError!bool {
    var content_buf: [8]u8 = undefined;
    const content = try readSmallSysfsFile(
        io,
        class_block_dir,
        whole_disk_name,
        "removable",
        &content_buf,
    );
    if (std.mem.eql(u8, content, "0")) return false;
    if (std.mem.eql(u8, content, "1")) return true;
    return error.InvalidBlockDeviceSysfs;
}

fn fileReadAt(
    ctx: *const anyopaque,
    io: Io,
    buffer: []u8,
    offset: u64,
) anyerror!usize {
    const file: *const Io.File = @ptrCast(@alignCast(ctx));
    return file.readPositionalAll(io, buffer, offset);
}

fn readAtExact(
    source: ReadAtSource,
    io: Io,
    buffer: []u8,
    offset: u64,
) InventoryError!void {
    const got = source.read_at_fn(source.ctx, io, buffer, offset) catch
        return error.DeviceInspectionFailed;
    if (got != buffer.len) return error.DeviceInspectionFailed;
}

fn matchAt(
    source: ReadAtSource,
    io: Io,
    region_offset: u64,
    region_length: u64,
    offset: u64,
    value: []const u8,
) InventoryError!bool {
    if (offset > region_length or value.len > region_length - offset or value.len > 16) return false;
    var buf: [16]u8 = undefined;
    try readAtExact(source, io, buf[0..value.len], region_offset + offset);
    return std.mem.eql(u8, buf[0..value.len], value);
}

fn inspectSignatures(
    source: ReadAtSource,
    io: Io,
    region_offset: u64,
    region_length: u64,
) InventoryError!Signatures {
    var signatures = Signatures{};
    signatures.xfs = try matchAt(source, io, region_offset, region_length, 0, "XFSB");
    signatures.ntfs = try matchAt(source, io, region_offset, region_length, 3, "NTFS    ");
    signatures.fat =
        try matchAt(source, io, region_offset, region_length, 54, "FAT16   ") or
        try matchAt(source, io, region_offset, region_length, 82, "FAT32   ");
    signatures.ext4 = try matchAt(source, io, region_offset, region_length, 1024 + 0x38, &.{ 0x53, 0xEF });
    signatures.btrfs = try matchAt(source, io, region_offset, region_length, 64 * 1024 + 0x40, "_BHRfS_M");
    signatures.luks = try matchAt(source, io, region_offset, region_length, 0, "LUKS\xba\xbe");
    signatures.lvm2 =
        try matchAt(source, io, region_offset, region_length, 512, "LABELONE") and
        try matchAt(source, io, region_offset, region_length, 512 + 24, "LVM2 001");
    inline for (.{ 4096, 8192, 16384, 65536 }) |page_size| {
        signatures.swap = signatures.swap or
            try matchAt(source, io, region_offset, region_length, page_size - 10, "SWAPSPACE2");
    }
    return signatures;
}

fn copyIdentifierText(buffer: *[identity_rewrite.canonical_uuid_bytes]u8, text: []const u8) u8 {
    @memcpy(buffer[0..text.len], text);
    return @intCast(text.len);
}

fn copyGuidText(buffer: *[identity_rewrite.canonical_uuid_bytes]u8, value: guid.Guid) u8 {
    var guid_text: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    return copyIdentifierText(buffer, guid.formatLower(&guid_text, value));
}

fn setFilesystemUuidIdentity(
    identity: *FilesystemIdentity,
    kind: FilesystemIdentityKind,
    bytes: *const [16]u8,
) void {
    var uuid_text: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    identity.kind = kind;
    identity.identifier_len = copyIdentifierText(
        &identity.identifier,
        identity_rewrite.formatFilesystemUuid(&uuid_text, bytes),
    );
}

fn setFatVolumeIdentity(identity: *FilesystemIdentity, volume_id: u32) void {
    var serial_text: [identity_rewrite.fat_serial_bytes]u8 = undefined;
    identity.kind = .fat;
    identity.identifier_len = copyIdentifierText(
        &identity.identifier,
        identity_rewrite.formatFatVolumeSerial(&serial_text, volume_id),
    );
}

fn inspectFatIdentity(
    source: ReadAtSource,
    io: Io,
    region_offset: u64,
    region_length: u64,
) InventoryError!FilesystemIdentity {
    var identity = FilesystemIdentity{ .kind = .fat };
    if (region_length < 512) return identity;

    var boot: [512]u8 = undefined;
    try readAtExact(source, io, &boot, region_offset);
    if (boot[510] != 0x55 or boot[511] != 0xAA) return identity;

    if (std.mem.eql(u8, boot[82..90], "FAT32   ")) {
        if (boot[66] == 0x29) {
            setFatVolumeIdentity(&identity, std.mem.readInt(u32, boot[67..71], .little));
        }
        return identity;
    }
    if (std.mem.eql(u8, boot[54..62], "FAT16   ")) {
        if (boot[38] == 0x29) {
            setFatVolumeIdentity(&identity, std.mem.readInt(u32, boot[39..43], .little));
        }
        return identity;
    }
    return identity;
}

fn inspectExt4Identity(
    source: ReadAtSource,
    io: Io,
    region_offset: u64,
    region_length: u64,
) InventoryError!FilesystemIdentity {
    if (region_length < 1024 + 0x78) return error.DeviceInspectionFailed;

    var superblock: [0x78]u8 = undefined;
    try readAtExact(source, io, &superblock, region_offset + 1024);
    if (std.mem.readInt(u16, superblock[0x38..0x3A], .little) != 0xEF53) {
        return .{};
    }

    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, superblock[0x68..0x78]);
    var identity = FilesystemIdentity{};
    setFilesystemUuidIdentity(&identity, .ext4, &uuid);
    return identity;
}

fn inspectXfsIdentity(
    source: ReadAtSource,
    io: Io,
    region_offset: u64,
    region_length: u64,
) InventoryError!FilesystemIdentity {
    if (region_length < 120) return error.DeviceInspectionFailed;

    var superblock: [120]u8 = undefined;
    try readAtExact(source, io, &superblock, region_offset);
    if (!std.mem.eql(u8, superblock[0..4], "XFSB")) return .{};

    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, superblock[32..48]);
    var identity = FilesystemIdentity{};
    setFilesystemUuidIdentity(&identity, .xfs, &uuid);
    return identity;
}

fn inspectFilesystemIdentity(
    source: ReadAtSource,
    io: Io,
    region_offset: u64,
    region_length: u64,
    signatures: Signatures,
) InventoryError!FilesystemIdentity {
    const recognized =
        @as(u3, @intFromBool(signatures.fat)) +
        @as(u3, @intFromBool(signatures.ext4)) +
        @as(u3, @intFromBool(signatures.xfs));
    if (recognized == 0) return .{};
    if (recognized > 1) return .{ .kind = .ambiguous };
    if (signatures.fat) return inspectFatIdentity(source, io, region_offset, region_length);
    if (signatures.ext4) return inspectExt4Identity(source, io, region_offset, region_length);
    return inspectXfsIdentity(source, io, region_offset, region_length);
}

fn decodeGptName(entry: []const u8, report: *PartitionReport) void {
    var offset: usize = 56;
    while (offset + 1 < 128 and report.name_len < report.name.len) : (offset += 2) {
        const code_unit = std.mem.readInt(u16, entry[offset..][0..2], .little);
        if (code_unit == 0) break;
        report.name[report.name_len] = if (code_unit <= 0x7f) @intCast(code_unit) else '?';
        report.name_len += 1;
    }
}

pub fn inspectIdentityInventory(
    allocator: std.mem.Allocator,
    io: Io,
    source: ReadAtSource,
    size_bytes: u64,
) InventoryError!IdentityInventory {
    var partitions = std.array_list.Managed(PartitionReport).init(allocator);
    errdefer partitions.deinit();

    var sector0: [mbr.sector_size]u8 = undefined;
    const has_mbr = blk: {
        if (size_bytes < sector0.len) break :blk false;
        try readAtExact(source, io, &sector0, 0);
        break :blk std.mem.eql(u8, sector0[510..512], &mbr.boot_signature);
    };

    var gpt_header: [mbr.sector_size]u8 = undefined;
    const has_gpt = blk: {
        if (size_bytes < 2 * mbr.sector_size) break :blk false;
        try readAtExact(source, io, &gpt_header, mbr.sector_size);
        break :blk std.mem.eql(u8, gpt_header[0..8], "EFI PART");
    };

    const table: PartitionTable = if (has_gpt) .gpt else if (has_mbr) .mbr else .none;
    var gpt_disk_guid_len: u8 = 0;
    var gpt_disk_guid: [identity_rewrite.canonical_uuid_bytes]u8 =
        [_]u8{0} ** identity_rewrite.canonical_uuid_bytes;
    if (has_gpt) {
        const entry_lba = std.mem.readInt(u64, gpt_header[72..80], .little);
        const entry_count = std.mem.readInt(u32, gpt_header[80..84], .little);
        const entry_size = std.mem.readInt(u32, gpt_header[84..88], .little);
        if (entry_size < 128 or entry_size > 4096 or entry_count > 4096) {
            return error.DeviceInspectionFailed;
        }
        var disk_guid: guid.Guid = undefined;
        @memcpy(&disk_guid, gpt_header[56..72]);
        if (!std.mem.eql(u8, &disk_guid, &guid.nil)) {
            gpt_disk_guid_len = copyGuidText(&gpt_disk_guid, disk_guid);
        }
        const entry_offset = std.math.mul(u64, entry_lba, mbr.sector_size) catch
            return error.DeviceInspectionFailed;
        var entry_buf: [4096]u8 = undefined;
        var index: u32 = 0;
        while (index < entry_count) : (index += 1) {
            const offset = std.math.add(
                u64,
                entry_offset,
                std.math.mul(u64, index, entry_size) catch return error.DeviceInspectionFailed,
            ) catch return error.DeviceInspectionFailed;
            if (offset > size_bytes or entry_size > size_bytes - offset) {
                return error.DeviceInspectionFailed;
            }
            try readAtExact(source, io, entry_buf[0..entry_size], offset);
            if (std.mem.allEqual(u8, entry_buf[0..16], 0)) continue;

            var report = PartitionReport{
                .table_index = index,
                .first_lba = std.mem.readInt(u64, entry_buf[32..40], .little),
                .last_lba = std.mem.readInt(u64, entry_buf[40..48], .little),
            };
            var unique_guid: guid.Guid = undefined;
            @memcpy(&unique_guid, entry_buf[16..32]);
            if (!std.mem.eql(u8, &unique_guid, &guid.nil)) {
                report.gpt_unique_guid_len = copyGuidText(&report.gpt_unique_guid, unique_guid);
            }
            if (report.last_lba < report.first_lba) return error.DeviceInspectionFailed;
            decodeGptName(entry_buf[0..128], &report);
            const region_offset = std.math.mul(u64, report.first_lba, mbr.sector_size) catch
                return error.DeviceInspectionFailed;
            const sector_count = std.math.add(
                u64,
                std.math.sub(u64, report.last_lba, report.first_lba) catch
                    return error.DeviceInspectionFailed,
                1,
            ) catch return error.DeviceInspectionFailed;
            const region_length = std.math.mul(u64, sector_count, mbr.sector_size) catch
                return error.DeviceInspectionFailed;
            if (region_offset > size_bytes or region_length > size_bytes - region_offset) {
                return error.DeviceInspectionFailed;
            }
            report.signatures = try inspectSignatures(source, io, region_offset, region_length);
            report.filesystem = try inspectFilesystemIdentity(
                source,
                io,
                region_offset,
                region_length,
                report.signatures,
            );
            try partitions.append(report);
        }
    } else if (has_mbr) {
        const decoded = mbr.Mbr.decode(&sector0) catch return error.DeviceInspectionFailed;
        for (decoded.entries, 0..) |entry, index| {
            if (entry.partition_type == .empty or entry.sector_count == 0) continue;
            const first_lba: u64 = entry.first_lba;
            const last_lba = std.math.add(u64, first_lba, entry.sector_count - 1) catch
                return error.DeviceInspectionFailed;
            const region_offset = std.math.mul(u64, first_lba, mbr.sector_size) catch
                return error.DeviceInspectionFailed;
            const region_length = std.math.mul(u64, entry.sector_count, mbr.sector_size) catch
                return error.DeviceInspectionFailed;
            if (region_offset > size_bytes or region_length > size_bytes - region_offset) {
                return error.DeviceInspectionFailed;
            }
            var report = PartitionReport{
                .table_index = @intCast(index),
                .first_lba = first_lba,
                .last_lba = last_lba,
                .signatures = try inspectSignatures(source, io, region_offset, region_length),
            };
            report.filesystem = try inspectFilesystemIdentity(
                source,
                io,
                region_offset,
                region_length,
                report.signatures,
            );
            try partitions.append(report);
        }
    }

    const device_signatures = try inspectSignatures(source, io, 0, size_bytes);
    return .{
        .partition_table = table,
        .partitions = try partitions.toOwnedSlice(),
        .device_signatures = device_signatures,
        .gpt_disk_guid = gpt_disk_guid,
        .gpt_disk_guid_len = gpt_disk_guid_len,
        .device_filesystem = try inspectFilesystemIdentity(source, io, 0, size_bytes, device_signatures),
    };
}

pub fn inspectFileIdentityInventory(
    allocator: std.mem.Allocator,
    io: Io,
    file: Io.File,
    size_bytes: u64,
) InventoryError!IdentityInventory {
    return inspectIdentityInventory(allocator, io, .{
        .ctx = &file,
        .read_at_fn = fileReadAt,
    }, size_bytes);
}

/// Applies every destructive-write refusal against injected mountinfo and
/// sysfs inputs, then inventories the target while it is still read-only.
pub fn preflight(
    allocator: std.mem.Allocator,
    io: Io,
    read_only_file: Io.File,
    geometry: Geometry,
    source_virtual_size: u64,
    target: DeviceNumber,
    mountinfo: []const u8,
    class_block_dir: Io.Dir,
    options: PreflightOptions,
) PreflightError!PreflightReport {
    _ = options.force;
    if (source_virtual_size > geometry.size_bytes) return error.DestinationTooSmall;

    const target_name = try findNameByDeviceNumber(allocator, io, class_block_dir, target);
    errdefer allocator.free(target_name);
    const whole_disk_name = try wholeDiskNameAlloc(allocator, io, class_block_dir, target_name);
    errdefer allocator.free(whole_disk_name);

    var mount_state = try parseMountInfo(allocator, mountinfo);
    defer mount_state.deinit();

    if (mount_state.root) |root_number| {
        const root_name = findNameByDeviceNumber(
            allocator,
            io,
            class_block_dir,
            root_number,
        ) catch |err| switch (err) {
            // Network, overlay, and other pseudo roots have no block entry.
            error.BlockDeviceNotInSysfs => if (root_number.major == 0)
                null
            else
                return error.RootDeviceResolutionFailed,
            else => return error.RootDeviceResolutionFailed,
        };
        if (root_name) |name| {
            defer allocator.free(name);
            var root_backing = NameSet.init(allocator);
            defer root_backing.deinit();
            try collectBackingDevices(&root_backing, io, class_block_dir, name);
            if (root_backing.contains(target_name)) return error.RootDeviceWriteRefused;
        }
    }

    var target_devices = try collectTargetDevices(allocator, io, class_block_dir, target_name);
    defer target_devices.deinit();
    try mountedState(target, target_devices, mount_state, io, class_block_dir);
    for (target_devices.items.items) |name| {
        if (try deviceHasHolders(io, class_block_dir, name)) return error.TargetHasHolders;
    }

    var contents = try inspectFileIdentityInventory(allocator, io, read_only_file, geometry.size_bytes);
    errdefer contents.deinit(allocator);
    return .{
        .target_name = target_name,
        .whole_disk_name = whole_disk_name,
        .geometry = geometry,
        .removable = try removableFor(io, class_block_dir, whole_disk_name),
        .transport = try transportFor(io, class_block_dir, whole_disk_name),
        .partition_table = contents.partition_table,
        .partitions = contents.partitions,
        .device_signatures = contents.device_signatures,
        .gpt_disk_guid = contents.gpt_disk_guid,
        .gpt_disk_guid_len = contents.gpt_disk_guid_len,
        .device_filesystem = contents.device_filesystem,
    };
}

fn identifierEql(a: []const u8, b: []const u8) bool {
    return a.len == b.len and std.ascii.eqlIgnoreCase(a, b);
}

fn visibleDeviceNameLess(_: void, a: []u8, b: []u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn collectVisibleWholeDisks(
    allocator: std.mem.Allocator,
    io: Io,
    class_block_dir: Io.Dir,
    excluded_whole_disk_name: []const u8,
) CollisionError!NameSet {
    var whole_disks = NameSet.init(allocator);
    errdefer whole_disks.deinit();

    var iterator = class_block_dir.iterate();
    while (iterator.next(io) catch return error.InvalidBlockDeviceSysfs) |entry| {
        if (std.mem.eql(u8, entry.name, excluded_whole_disk_name)) continue;
        if ((isPartition(io, class_block_dir, entry.name) catch
            return error.InvalidBlockDeviceSysfs))
        {
            continue;
        }
        _ = try whole_disks.append(entry.name);
    }
    std.mem.sort([]u8, whole_disks.items.items, {}, visibleDeviceNameLess);
    return whole_disks;
}

fn appendCollision(
    collisions: *std.array_list.Managed(Collision),
    allocator: std.mem.Allocator,
    kind: CollisionKind,
    identifier: []const u8,
    source_partition_table_index: ?u32,
    source_filesystem: FilesystemIdentityKind,
    visible_device_name: []const u8,
    visible_partition_table_index: ?u32,
    visible_filesystem: FilesystemIdentityKind,
) std.mem.Allocator.Error!void {
    var collision = Collision{
        .kind = kind,
        .source_partition_table_index = source_partition_table_index,
        .source_filesystem = source_filesystem,
        .visible_device_name = try allocator.dupe(u8, visible_device_name),
        .visible_partition_table_index = visible_partition_table_index,
        .visible_filesystem = visible_filesystem,
    };
    errdefer allocator.free(collision.visible_device_name);
    collision.identifier_len = copyIdentifierText(&collision.identifier, identifier);
    try collisions.append(collision);
}

fn appendFilesystemCollisions(
    collisions: *std.array_list.Managed(Collision),
    allocator: std.mem.Allocator,
    source_filesystem: FilesystemIdentity,
    source_partition_table_index: ?u32,
    visible_device_name: []const u8,
    visible: *const IdentityInventory,
) std.mem.Allocator.Error!void {
    const identifier = source_filesystem.identifierText() orelse return;

    if (visible.device_filesystem.identifierText()) |visible_identifier| {
        if (identifierEql(identifier, visible_identifier)) {
            try appendCollision(
                collisions,
                allocator,
                .filesystem_identifier,
                identifier,
                source_partition_table_index,
                source_filesystem.kind,
                visible_device_name,
                null,
                visible.device_filesystem.kind,
            );
        }
    }

    for (visible.partitions) |partition| {
        const visible_identifier = partition.filesystem.identifierText() orelse continue;
        if (!identifierEql(identifier, visible_identifier)) continue;
        try appendCollision(
            collisions,
            allocator,
            .filesystem_identifier,
            identifier,
            source_partition_table_index,
            source_filesystem.kind,
            visible_device_name,
            partition.table_index,
            partition.filesystem.kind,
        );
    }
}

fn compareIdentityCollisions(
    collisions: *std.array_list.Managed(Collision),
    allocator: std.mem.Allocator,
    source: *const IdentityInventory,
    visible_device_name: []const u8,
    visible: *const IdentityInventory,
) std.mem.Allocator.Error!void {
    if (source.gptDiskGuid()) |source_guid| {
        if (visible.gptDiskGuid()) |visible_guid| {
            if (identifierEql(source_guid, visible_guid)) {
                try appendCollision(
                    collisions,
                    allocator,
                    .gpt_disk_guid,
                    source_guid,
                    null,
                    .none,
                    visible_device_name,
                    null,
                    .none,
                );
            }
        }
    }

    for (source.partitions) |source_partition| {
        if (source_partition.gptUniqueGuid()) |source_guid| {
            for (visible.partitions) |visible_partition| {
                const visible_guid = visible_partition.gptUniqueGuid() orelse continue;
                if (!identifierEql(source_guid, visible_guid)) continue;
                try appendCollision(
                    collisions,
                    allocator,
                    .gpt_partition_guid,
                    source_guid,
                    source_partition.table_index,
                    .none,
                    visible_device_name,
                    visible_partition.table_index,
                    .none,
                );
            }
        }
    }

    try appendFilesystemCollisions(
        collisions,
        allocator,
        source.device_filesystem,
        null,
        visible_device_name,
        visible,
    );
    for (source.partitions) |source_partition| {
        try appendFilesystemCollisions(
            collisions,
            allocator,
            source_partition.filesystem,
            source_partition.table_index,
            visible_device_name,
            visible,
        );
    }
}

fn openVisibleDeviceFromDev(
    _: ?*anyopaque,
    io: Io,
    device_name: []const u8,
) CollisionError!OpenedVisibleDevice {
    var dev_dir = Io.Dir.openDirAbsolute(io, "/dev", .{}) catch
        return error.VisibleDeviceUnavailable;
    defer dev_dir.close(io);

    const file = dev_dir.openFile(io, device_name, .{ .mode = .read_only }) catch
        return error.VisibleDeviceUnavailable;
    errdefer file.close(io);
    if ((file.stat(io) catch return error.VisibleDeviceUnavailable).kind != .block_device) {
        return error.VisibleDeviceNotBlockDevice;
    }
    return .{ .file = file, .geometry = try probe(file) };
}

pub fn findVisibleIdentityCollisions(
    allocator: std.mem.Allocator,
    io: Io,
    source: *const IdentityInventory,
    class_block_dir: Io.Dir,
    excluded_whole_disk_name: []const u8,
    opener: VisibleDeviceOpener,
) CollisionError!CollisionReport {
    var whole_disks = try collectVisibleWholeDisks(
        allocator,
        io,
        class_block_dir,
        excluded_whole_disk_name,
    );
    defer whole_disks.deinit();

    var collisions = std.array_list.Managed(Collision).init(allocator);
    errdefer {
        for (collisions.items) |collision| allocator.free(collision.visible_device_name);
        collisions.deinit();
    }

    for (whole_disks.items.items) |whole_disk_name| {
        var visible_device = try opener.open_fn(opener.context, io, whole_disk_name);
        defer visible_device.file.close(io);

        var visible = try inspectFileIdentityInventory(
            allocator,
            io,
            visible_device.file,
            visible_device.geometry.size_bytes,
        );
        defer visible.deinit(allocator);

        try compareIdentityCollisions(
            &collisions,
            allocator,
            source,
            whole_disk_name,
            &visible,
        );
    }

    return .{
        .collisions = try collisions.toOwnedSlice(),
        .scanned_visible_disks = whole_disks.items.items.len,
    };
}

pub fn findLinuxVisibleIdentityCollisions(
    allocator: std.mem.Allocator,
    io: Io,
    source: *const IdentityInventory,
    excluded_whole_disk_name: []const u8,
) CollisionError!CollisionReport {
    if (builtin.os.tag != .linux) return error.UnsupportedBlockDevicePreflight;

    var class_block_dir = Io.Dir.openDirAbsolute(io, "/sys/class/block", .{ .iterate = true }) catch
        return error.BlockDeviceSysfsUnavailable;
    defer class_block_dir.close(io);

    return findVisibleIdentityCollisions(
        allocator,
        io,
        source,
        class_block_dir,
        excluded_whole_disk_name,
        .{},
    );
}

/// Validates the raw ioctl answers and turns them into a `Geometry`. Split
/// out from `probeLinux` so the validation rules are testable without a real
/// device (which no CI runner is guaranteed to have).
pub fn geometryFrom(size_bytes: u64, logical_sector_size: c_int) ProbeError!Geometry {
    if (size_bytes == 0) return error.EmptyBlockDevice;
    if (logical_sector_size <= 0) return error.InvalidLogicalSectorSize;

    const sector_size: u64 = @intCast(logical_sector_size);
    if (sector_size < min_logical_sector_size or
        sector_size > max_logical_sector_size or
        !std.math.isPowerOfTwo(sector_size))
    {
        return error.InvalidLogicalSectorSize;
    }
    if (size_bytes % sector_size != 0) return error.UnalignedBlockDeviceSize;

    return .{ .size_bytes = size_bytes, .logical_sector_size = @intCast(sector_size) };
}

test "geometryFrom accepts real-world device geometries" {
    const nvme = try geometryFrom(1_024_209_543_168, 512);
    try std.testing.expectEqual(@as(u64, 1_024_209_543_168), nvme.size_bytes);
    try std.testing.expectEqual(@as(u32, 512), nvme.logical_sector_size);

    const advanced_format = try geometryFrom(8 * 1024 * 1024 * 1024, 4096);
    try std.testing.expectEqual(@as(u32, 4096), advanced_format.logical_sector_size);
}

test "geometryFrom rejects a device with no medium" {
    try std.testing.expectError(error.EmptyBlockDevice, geometryFrom(0, 512));
}

test "geometryFrom rejects implausible sector sizes" {
    try std.testing.expectError(error.InvalidLogicalSectorSize, geometryFrom(4096, 0));
    try std.testing.expectError(error.InvalidLogicalSectorSize, geometryFrom(4096, -1));
    try std.testing.expectError(error.InvalidLogicalSectorSize, geometryFrom(4096, 256));
    try std.testing.expectError(error.InvalidLogicalSectorSize, geometryFrom(4096, 1536));
    try std.testing.expectError(
        error.InvalidLogicalSectorSize,
        geometryFrom(4096, max_logical_sector_size * 2),
    );
}

test "geometryFrom rejects a size that is not a whole number of sectors" {
    try std.testing.expectError(error.UnalignedBlockDeviceSize, geometryFrom(4096 + 512, 4096));
}

const TestIoctl = struct {
    calls: usize = 0,
    result: std.os.linux.E = .SUCCESS,
    request: ?u32 = null,
    argument: ?usize = null,

    fn call(context: ?*anyopaque, _: std.os.linux.fd_t, request: u32, argument: usize) usize {
        const self: *TestIoctl = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        self.request = request;
        self.argument = argument;
        if (self.result == .SUCCESS) return 0;
        const errno_value: isize = @intCast(@intFromEnum(self.result));
        return @bitCast(-errno_value);
    }
};

test "reReadPartitionTable issues BLKRRPART and reports ioctl results" {
    const file = Io.File{ .handle = 123, .flags = .{ .nonblocking = false } };
    var ioctl = TestIoctl{};

    try reReadPartitionTableLinux(file, &ioctl, TestIoctl.call);
    try std.testing.expectEqual(@as(usize, 1), ioctl.calls);
    try std.testing.expectEqual(blkrrpart, ioctl.request.?);
    try std.testing.expectEqual(@as(usize, 0), ioctl.argument.?);

    ioctl.result = .IO;
    try std.testing.expectError(
        error.PartitionTableRefreshFailed,
        reReadPartitionTableLinux(file, &ioctl, TestIoctl.call),
    );
    try std.testing.expectEqual(@as(usize, 2), ioctl.calls);
}

test "reReadPartitionTable preserves EBUSY as a distinct result" {
    const file = Io.File{ .handle = 123, .flags = .{ .nonblocking = false } };
    var ioctl = TestIoctl{ .result = .BUSY };

    try std.testing.expectError(
        error.BlockDeviceBusy,
        reReadPartitionTableLinux(file, &ioctl, TestIoctl.call),
    );
    try std.testing.expectEqual(@as(usize, 1), ioctl.calls);
}

fn addTestSysfsDevice(
    allocator: std.mem.Allocator,
    io: Io,
    root: Io.Dir,
    name: []const u8,
    relative_device_path: []const u8,
    number: DeviceNumber,
    partition_number: ?u32,
    removable: bool,
    holders: []const []const u8,
    slaves: []const []const u8,
) !void {
    const device_path = try std.fmt.allocPrint(allocator, "devices/{s}", .{relative_device_path});
    defer allocator.free(device_path);
    try root.createDirPath(io, device_path);

    const dev_path = try std.fmt.allocPrint(allocator, "{s}/dev", .{device_path});
    defer allocator.free(dev_path);
    const dev_content = try std.fmt.allocPrint(allocator, "{d}:{d}\n", .{ number.major, number.minor });
    defer allocator.free(dev_content);
    try root.writeFile(io, .{ .sub_path = dev_path, .data = dev_content });

    const removable_path = try std.fmt.allocPrint(allocator, "{s}/removable", .{device_path});
    defer allocator.free(removable_path);
    try root.writeFile(io, .{
        .sub_path = removable_path,
        .data = if (removable) "1\n" else "0\n",
    });

    if (partition_number) |partition| {
        const partition_path = try std.fmt.allocPrint(allocator, "{s}/partition", .{device_path});
        defer allocator.free(partition_path);
        const partition_content = try std.fmt.allocPrint(allocator, "{d}\n", .{partition});
        defer allocator.free(partition_content);
        try root.writeFile(io, .{ .sub_path = partition_path, .data = partition_content });
    }

    const holders_path = try std.fmt.allocPrint(allocator, "{s}/holders", .{device_path});
    defer allocator.free(holders_path);
    try root.createDirPath(io, holders_path);
    for (holders) |holder| {
        const holder_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ holders_path, holder });
        defer allocator.free(holder_path);
        try root.writeFile(io, .{ .sub_path = holder_path, .data = "" });
    }

    const slaves_path = try std.fmt.allocPrint(allocator, "{s}/slaves", .{device_path});
    defer allocator.free(slaves_path);
    try root.createDirPath(io, slaves_path);
    for (slaves) |slave| {
        const slave_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ slaves_path, slave });
        defer allocator.free(slave_path);
        try root.writeFile(io, .{ .sub_path = slave_path, .data = "" });
    }

    const link_target = try std.fmt.allocPrint(allocator, "../{s}", .{device_path});
    defer allocator.free(link_target);
    const link_path = try std.fmt.allocPrint(allocator, "class_block/{s}", .{name});
    defer allocator.free(link_path);
    try root.symLink(io, link_target, link_path, .{});
}

fn createTestTree(io: Io, root: Io.Dir) !Io.Dir {
    try root.createDirPath(io, "class_block");
    return root.openDir(io, "class_block", .{ .iterate = true });
}

fn createTestDisk(io: Io, root: Io.Dir, size: u64) !Io.File {
    const file = try root.createFile(io, "disk.img", .{ .read = true });
    try file.setLength(io, size);
    return file;
}

fn createNamedTestDisk(io: Io, root: Io.Dir, path: []const u8, size: u64) !Io.File {
    const file = try root.createFile(io, path, .{ .read = true });
    try file.setLength(io, size);
    return file;
}

const test_gpt_disk_guid = guid.parse("99999999-8888-7777-6666-555555555555");
const test_gpt_partition_guid = guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
const test_ext4_uuid = [16]u8{
    0x11, 0x11, 0x11, 0x11,
    0x22, 0x22, 0x33, 0x33,
    0x44, 0x44, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55,
};
const test_fat_volume_id: u32 = 0x1234_5678;
const test_xfs_uuid = [16]u8{
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C,
    0x0D, 0x0E, 0x0F, 0x10,
};

fn writeTestExt4Identity(io: Io, file: Io.File, region_offset: u64) !void {
    var superblock = [_]u8{0} ** 0x78;
    std.mem.writeInt(u16, superblock[0x38..0x3A], 0xEF53, .little);
    @memcpy(superblock[0x68..0x78], &test_ext4_uuid);
    try file.writePositionalAll(io, &superblock, region_offset + 1024);
}

fn writeTestFatIdentity(io: Io, file: Io.File, region_offset: u64) !void {
    var boot = [_]u8{0} ** 512;
    boot[510] = 0x55;
    boot[511] = 0xAA;
    boot[66] = 0x29;
    std.mem.writeInt(u32, boot[67..71], test_fat_volume_id, .little);
    @memcpy(boot[82..90], "FAT32   ");
    try file.writePositionalAll(io, &boot, region_offset);
}

fn writeTestXfsIdentity(io: Io, file: Io.File, region_offset: u64) !void {
    var superblock = [_]u8{0} ** 120;
    @memcpy(superblock[0..4], "XFSB");
    @memcpy(superblock[32..48], &test_xfs_uuid);
    try file.writePositionalAll(io, &superblock, region_offset);
}

fn writeTestGpt(io: Io, file: Io.File) !void {
    const protective = mbr.protectiveMbr(4096).encode();
    try file.writePositionalAll(io, &protective, 0);

    var header = [_]u8{0} ** mbr.sector_size;
    header[0..8].* = "EFI PART".*;
    @memcpy(header[56..72], &test_gpt_disk_guid);
    std.mem.writeInt(u64, header[72..80], 2, .little);
    std.mem.writeInt(u32, header[80..84], 1, .little);
    std.mem.writeInt(u32, header[84..88], 128, .little);
    try file.writePositionalAll(io, &header, mbr.sector_size);

    var entry = [_]u8{0} ** 128;
    entry[0] = 1;
    @memcpy(entry[16..32], &test_gpt_partition_guid);
    std.mem.writeInt(u64, entry[32..40], 2048, .little);
    std.mem.writeInt(u64, entry[40..48], 3071, .little);
    for ("root", 0..) |c, i| std.mem.writeInt(u16, entry[56 + i * 2 ..][0..2], c, .little);
    try file.writePositionalAll(io, &entry, 2 * mbr.sector_size);
    try writeTestExt4Identity(io, file, 2048 * mbr.sector_size);
}

const TestVisibleDeviceOpener = struct {
    dev_dir: Io.Dir,

    fn open(context: ?*anyopaque, io: Io, device_name: []const u8) CollisionError!OpenedVisibleDevice {
        const self: *TestVisibleDeviceOpener = @ptrCast(@alignCast(context.?));
        const file = self.dev_dir.openFile(io, device_name, .{ .mode = .read_only }) catch
            return error.VisibleDeviceUnavailable;
        errdefer file.close(io);
        const stat = file.stat(io) catch return error.VisibleDeviceUnavailable;
        return .{
            .file = file,
            .geometry = .{
                .size_bytes = stat.size,
                .logical_sector_size = 512,
            },
        };
    }
};

test "preflight rejects a source larger than the target before consulting sysfs" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try createTestDisk(io, tmp.dir, 4096);
    defer file.close(io);
    var class_block_dir = try createTestTree(io, tmp.dir);
    defer class_block_dir.close(io);

    try std.testing.expectError(error.DestinationTooSmall, preflight(
        std.testing.allocator,
        io,
        file,
        .{ .size_bytes = 4096, .logical_sector_size = 512 },
        4097,
        .{ .major = 8, .minor = 0 },
        "",
        class_block_dir,
        .{},
    ));
}

test "preflight rejects a mounted target and a mounted nvme child" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var class_block_dir = try createTestTree(io, tmp.dir);
    defer class_block_dir.close(io);

    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "nvme0n1",
        "pci/nvme/nvme0/nvme0n1",
        .{ .major = 259, .minor = 0 },
        null,
        false,
        &.{},
        &.{},
    );
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "nvme0n1p1",
        "pci/nvme/nvme0/nvme0n1/nvme0n1p1",
        .{ .major = 259, .minor = 1 },
        1,
        false,
        &.{},
        &.{},
    );
    const file = try createTestDisk(io, tmp.dir, 2 * 1024 * 1024);
    defer file.close(io);
    const geometry = Geometry{ .size_bytes = 2 * 1024 * 1024, .logical_sector_size = 512 };

    try std.testing.expectError(error.TargetMounted, preflight(
        allocator,
        io,
        file,
        geometry,
        4096,
        .{ .major = 259, .minor = 0 },
        "20 1 259:0 / /media/disk rw - ext4 /dev/nvme0n1 rw\n21 1 0:42 / / rw - overlay overlay rw\n",
        class_block_dir,
        .{},
    ));
    try std.testing.expectError(error.TargetContainsMountedPartition, preflight(
        allocator,
        io,
        file,
        geometry,
        4096,
        .{ .major = 259, .minor = 0 },
        "20 1 259:1 / /media/root rw - ext4 /dev/nvme0n1p1 rw\n21 1 0:42 / / rw - overlay overlay rw\n",
        class_block_dir,
        .{},
    ));
}

test "preflight rejects holders on a child partition" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var class_block_dir = try createTestTree(io, tmp.dir);
    defer class_block_dir.close(io);
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "sda",
        "pci/host0/target0/block/sda",
        .{ .major = 8, .minor = 0 },
        null,
        false,
        &.{},
        &.{},
    );
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "sda2",
        "pci/host0/target0/block/sda/sda2",
        .{ .major = 8, .minor = 2 },
        2,
        false,
        &.{"dm-0"},
        &.{},
    );
    const file = try createTestDisk(io, tmp.dir, 2 * 1024 * 1024);
    defer file.close(io);

    try std.testing.expectError(error.TargetHasHolders, preflight(
        allocator,
        io,
        file,
        .{ .size_bytes = 2 * 1024 * 1024, .logical_sector_size = 512 },
        4096,
        .{ .major = 8, .minor = 0 },
        "21 1 0:42 / / rw - overlay overlay rw\n",
        class_block_dir,
        .{},
    ));
}

test "preflight refuses a root backing disk through device-mapper even with force" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var class_block_dir = try createTestTree(io, tmp.dir);
    defer class_block_dir.close(io);
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "mmcblk0",
        "platform/mmc/mmc_host/mmcblk0",
        .{ .major = 179, .minor = 0 },
        null,
        true,
        &.{},
        &.{},
    );
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "mmcblk0p2",
        "platform/mmc/mmc_host/mmcblk0/mmcblk0p2",
        .{ .major = 179, .minor = 2 },
        2,
        false,
        &.{"dm-0"},
        &.{},
    );
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "dm-0",
        "virtual/block/dm-0",
        .{ .major = 253, .minor = 0 },
        null,
        false,
        &.{},
        &.{"mmcblk0p2"},
    );
    const file = try createTestDisk(io, tmp.dir, 2 * 1024 * 1024);
    defer file.close(io);

    try std.testing.expectError(error.RootDeviceWriteRefused, preflight(
        allocator,
        io,
        file,
        .{ .size_bytes = 2 * 1024 * 1024, .logical_sector_size = 512 },
        4096,
        .{ .major = 179, .minor = 0 },
        "21 1 253:0 / / rw - ext4 /dev/mapper/root rw\n",
        class_block_dir,
        .{ .force = true },
    ));
}

test "safe preflight reports transport, removability, GPT name, and filesystem signature" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var class_block_dir = try createTestTree(io, tmp.dir);
    defer class_block_dir.close(io);
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "sdb",
        "pci/usb1/1-1/host2/target2/block/sdb",
        .{ .major = 8, .minor = 16 },
        null,
        true,
        &.{},
        &.{},
    );
    const file = try createTestDisk(io, tmp.dir, 2 * 1024 * 1024);
    defer file.close(io);
    try writeTestGpt(io, file);

    var report = try preflight(
        allocator,
        io,
        file,
        .{ .size_bytes = 2 * 1024 * 1024, .logical_sector_size = 512 },
        1024 * 1024,
        .{ .major = 8, .minor = 16 },
        "21 1 0:42 / / rw - overlay overlay rw\n",
        class_block_dir,
        .{},
    );
    defer report.deinit(allocator);

    try std.testing.expectEqualStrings("sdb", report.target_name);
    try std.testing.expectEqualStrings("sdb", report.whole_disk_name);
    try std.testing.expect(report.removable);
    try std.testing.expectEqual(Transport.usb, report.transport);
    try std.testing.expectEqual(PartitionTable.gpt, report.partition_table);
    var disk_guid_text: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        guid.formatLower(&disk_guid_text, test_gpt_disk_guid),
        report.gptDiskGuid().?,
    );
    try std.testing.expectEqual(@as(usize, 1), report.partitions.len);
    try std.testing.expectEqualStrings("root", report.partitions[0].partitionName());
    var partition_guid_text: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        guid.formatLower(&partition_guid_text, test_gpt_partition_guid),
        report.partitions[0].gptUniqueGuid().?,
    );
    try std.testing.expect(report.partitions[0].signatures.ext4);
    try std.testing.expectEqual(FilesystemIdentityKind.ext4, report.partitions[0].filesystem.kind);
    var filesystem_uuid_text: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        identity_rewrite.formatFilesystemUuid(&filesystem_uuid_text, &test_ext4_uuid),
        report.partitions[0].filesystem.identifierText().?,
    );
}

test "identity inventory recognizes FAT and XFS filesystem identifiers" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const fat = try createNamedTestDisk(io, tmp.dir, "fat.img", 2 * 1024 * 1024);
    defer fat.close(io);
    try writeTestFatIdentity(io, fat, 0);
    var fat_inventory = try inspectFileIdentityInventory(allocator, io, fat, 2 * 1024 * 1024);
    defer fat_inventory.deinit(allocator);
    try std.testing.expectEqual(FilesystemIdentityKind.fat, fat_inventory.device_filesystem.kind);
    var fat_serial_text: [identity_rewrite.fat_serial_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        identity_rewrite.formatFatVolumeSerial(&fat_serial_text, test_fat_volume_id),
        fat_inventory.device_filesystem.identifierText().?,
    );

    const xfs_file = try createNamedTestDisk(io, tmp.dir, "xfs.img", 2 * 1024 * 1024);
    defer xfs_file.close(io);
    try writeTestXfsIdentity(io, xfs_file, 0);
    var xfs_inventory = try inspectFileIdentityInventory(allocator, io, xfs_file, 2 * 1024 * 1024);
    defer xfs_inventory.deinit(allocator);
    try std.testing.expectEqual(FilesystemIdentityKind.xfs, xfs_inventory.device_filesystem.kind);
    var xfs_uuid_text: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        identity_rewrite.formatFilesystemUuid(&xfs_uuid_text, &test_xfs_uuid),
        xfs_inventory.device_filesystem.identifierText().?,
    );
}

test "visible identity collisions exclude the destination whole-disk hierarchy" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var class_block_dir = try createTestTree(io, tmp.dir);
    defer class_block_dir.close(io);

    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "sdb",
        "pci/host0/target0/block/sdb",
        .{ .major = 8, .minor = 16 },
        null,
        false,
        &.{},
        &.{},
    );
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "sdb1",
        "pci/host0/target0/block/sdb/sdb1",
        .{ .major = 8, .minor = 17 },
        1,
        false,
        &.{},
        &.{},
    );
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "sdc",
        "pci/host1/target1/block/sdc",
        .{ .major = 8, .minor = 32 },
        null,
        false,
        &.{},
        &.{},
    );

    try tmp.dir.createDirPath(io, "dev");
    var dev_dir = try tmp.dir.openDir(io, "dev", .{});
    defer dev_dir.close(io);

    const source = try createNamedTestDisk(io, tmp.dir, "source.img", 2 * 1024 * 1024);
    defer source.close(io);
    try writeTestGpt(io, source);

    const excluded = try createNamedTestDisk(io, tmp.dir, "dev/sdb", 2 * 1024 * 1024);
    defer excluded.close(io);
    try writeTestGpt(io, excluded);

    const visible = try createNamedTestDisk(io, tmp.dir, "dev/sdc", 2 * 1024 * 1024);
    defer visible.close(io);
    try writeTestGpt(io, visible);

    var source_inventory = try inspectFileIdentityInventory(allocator, io, source, 2 * 1024 * 1024);
    defer source_inventory.deinit(allocator);

    var opener = TestVisibleDeviceOpener{ .dev_dir = dev_dir };
    var collisions = try findVisibleIdentityCollisions(
        allocator,
        io,
        &source_inventory,
        class_block_dir,
        "sdb",
        .{
            .context = &opener,
            .open_fn = TestVisibleDeviceOpener.open,
        },
    );
    defer collisions.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), collisions.scanned_visible_disks);
    try std.testing.expectEqual(@as(usize, 3), collisions.collisions.len);
    try std.testing.expectEqual(CollisionKind.gpt_disk_guid, collisions.collisions[0].kind);
    try std.testing.expectEqual(CollisionKind.gpt_partition_guid, collisions.collisions[1].kind);
    try std.testing.expectEqual(CollisionKind.filesystem_identifier, collisions.collisions[2].kind);
    for (collisions.collisions) |collision| {
        try std.testing.expectEqualStrings("sdc", collision.visible_device_name);
    }
}

test "parentDiskName handles nvme and mmc partition names through sysfs" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var class_block_dir = try createTestTree(io, tmp.dir);
    defer class_block_dir.close(io);
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "nvme0n1p3",
        "pci/nvme/nvme0/nvme0n1/nvme0n1p3",
        .{ .major = 259, .minor = 3 },
        3,
        false,
        &.{},
        &.{},
    );
    try addTestSysfsDevice(
        allocator,
        io,
        tmp.dir,
        "mmcblk0p1",
        "platform/mmc/mmcblk0/mmcblk0p1",
        .{ .major = 179, .minor = 1 },
        1,
        false,
        &.{},
        &.{},
    );

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "nvme0n1",
        try parentDiskName(io, class_block_dir, "nvme0n1p3", &link_buf),
    );
    try std.testing.expectEqualStrings(
        "mmcblk0",
        try parentDiskName(io, class_block_dir, "mmcblk0p1", &link_buf),
    );
}
