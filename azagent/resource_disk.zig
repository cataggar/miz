//! Detects, formats, and mounts Azure's temporary/local "resource disk"
//! (typically `/dev/sdb`) at `/d`, with optional swap-file setup.
//! Native replacement for the resource-disk portion of Python `waagent`
//! (`azurelinuxagent/daemon/resourcedisk/default.py`) -- see zvmi issue #113.
//!
//! Unlike `hostname.zig`/`passwd.zig`/`ssh_keys.zig` (which only ever run
//! once, gated by the sentinel in `sentinel.zig`), this module's `setup`
//! must run on *every* boot: Azure can reallocate/resize the resource disk
//! across a VM's lifetime, so its formatted state must be re-checked each
//! time, not assumed from a previous run (see `main.zig`'s wiring).
//!
//! Reuses `zvmi`'s `mbr.zig`/`ext4.zig` codecs directly against a real block
//! device special file -- both already operate on any `Io.File` plus a byte
//! offset/length, so no library changes were needed to point them at
//! `/dev/sdb` instead of a disk-image file.
const std = @import("std");
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const zvmi = @import("zvmi");
const mbr = zvmi.mbr;
const gpt = zvmi.gpt;
const guid_codec = zvmi.guid;
const ext4 = zvmi.ext4;
const Image = zvmi.Image;

/// Gen1 (BIOS/synthetic-IDE) resource-disk VMBus device IDs start with this
/// prefix (IDE port 1, per upstream's `device_for_ide_port(1)`).
pub const gen1_device_id_prefix = "00000000-0001";
/// Gen2 (UEFI/synthetic-SCSI) VMBus controller device ID; the resource disk
/// is always LUN 1 on this controller (LUN 0 is the OS disk, LUN 2 the
/// CD-ROM/provisioning media).
pub const gen2_device_id = "f8b3781a-1e82-4818-a1c3-63d806ec15bb";

/// Walks `devices_dir` (production passes an open handle to
/// `/sys/bus/vmbus/devices`; tests pass a synthetic directory tree) looking
/// for the Gen1 or Gen2 resource-disk VMBus device, and returns the owned
/// kernel block device name (e.g. `"sdb"`) backing it.
pub fn findResourceDiskName(allocator: Allocator, devices_dir: std.Io.Dir, io: std.Io) ![]u8 {
    var top_it = devices_dir.iterate();
    while (try top_it.next(io)) |top_entry| {
        // Real `/sys/bus/vmbus/devices/<id>` entries are themselves symlinks
        // to the actual device directory elsewhere under `/sys/devices`.
        // Opening by name follows that symlink (unlike a kind-based
        // auto-descend, which would skip a readdir entry reported as a
        // symlink rather than a plain directory).
        var device_dir = (try openChildDirOrNull(devices_dir, io, top_entry.name)) orelse continue;
        defer device_dir.close(io);

        const device_guid = (try readDeviceIdGuid(allocator, device_dir, io)) orelse continue;
        defer allocator.free(device_guid);

        const is_gen1 = std.mem.startsWith(u8, device_guid, gen1_device_id_prefix);
        const is_gen2 = std.mem.eql(u8, device_guid, gen2_device_id);
        if (!is_gen1 and !is_gen2) continue;

        if (try findBlockDeviceName(allocator, device_dir, io, is_gen2)) |name| return name;
    }
    return error.ResourceDiskNotFound;
}

fn openChildDirOrNull(dir: std.Io.Dir, io: std.Io, name: []const u8) !?std.Io.Dir {
    return dir.openDir(io, name, .{ .iterate = true }) catch |err| switch (err) {
        error.NotDir, error.FileNotFound => null,
        else => return err,
    };
}

/// Reads `device_id` under `dir` and strips the surrounding `{}`/whitespace,
/// matching upstream's `guid.strip('{}\n')`. Returns `null` if the file
/// doesn't exist (a non-VMBus-device directory).
fn readDeviceIdGuid(allocator: Allocator, dir: std.Io.Dir, io: std.Io) !?[]u8 {
    const content = dir.readFileAlloc(io, "device_id", allocator, .limited(256)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(content);
    const trimmed = std.mem.trim(u8, content, "{}\n\r \t");
    return try allocator.dupe(u8, trimmed);
}

/// Walks the subtree rooted at `dir` (a matched VMBus device directory)
/// looking for a `block` directory (Gen1, or Gen2 with the containing
/// `<host:bus:target:lun>` directory's LUN segment equal to `1`), or an
/// older-distro-style `block:<name>` directory directly, returning the
/// owned block device name found under it.
fn findBlockDeviceName(allocator: Allocator, dir: std.Io.Dir, io: std.Io, require_lun1: bool) !?[]u8 {
    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind != .directory) continue;

        if (std.mem.startsWith(u8, entry.basename, "block:")) {
            return try allocator.dupe(u8, entry.basename["block:".len..]);
        }
        if (!std.mem.eql(u8, entry.basename, "block")) continue;

        if (require_lun1) {
            const parent = std.fs.path.dirname(entry.path);
            const lun_owner = if (parent) |p| std.fs.path.basename(p) else entry.path;
            if (!lastColonSegmentIsOne(lun_owner)) continue;
        }

        var block_dir = try entry.dir.openDir(io, entry.basename, .{ .iterate = true });
        defer block_dir.close(io);
        var block_it = block_dir.iterate();
        if (try block_it.next(io)) |dev_entry| {
            return try allocator.dupe(u8, dev_entry.name);
        }
    }
    return null;
}

fn lastColonSegmentIsOne(name: []const u8) bool {
    const idx = std.mem.lastIndexOfScalar(u8, name, ':') orelse return false;
    return std.mem.eql(u8, name[idx + 1 ..], "1");
}

/// Byte offset (in sectors) where the resource disk's single data partition
/// starts: 1 MiB aligned, matching `packages/zvmi/src/layout.zig`'s own
/// `default_alignment` convention used elsewhere in this repo.
pub const partition_start_lba: u32 = 2048;

/// True if `decoded` already describes a single Linux partition spanning
/// `[partition_start_lba, total_sectors)` with no other partitions defined
/// -- the shape `ensureFormatted` writes, checked before deciding whether a
/// (re)format is needed.
pub fn isWholeDiskLinuxPartition(decoded: mbr.Mbr, total_sectors: u64) bool {
    const e = decoded.entries[0];
    if (e.partition_type != .linux) return false;
    if (e.first_lba != partition_start_lba) return false;
    if (e.first_lba >= total_sectors) return false;
    if (@as(u64, e.first_lba) + e.sector_count != total_sectors) return false;
    for (decoded.entries[1..]) |other| {
        if (other.partition_type != .empty) return false;
    }
    return true;
}

pub const default_mount_point = "/d";
pub const dataloss_warning_file_name = "DATALOSS_WARNING_README.txt";

/// zvmi's own wording (not copied from upstream's copyrighted text):
/// a plain notice that the resource disk is temporary/non-persistent.
pub const dataloss_warning_text =
    \\This is the VM's temporary resource disk.
    \\
    \\Anything stored here can be lost at any time: for example, when the VM
    \\is stopped/deallocated, resized, or moved to different host hardware.
    \\Do not rely on this disk for anything you cannot afford to lose. Use a
    \\persistent (managed/attached) disk instead for data that matters.
    \\
;

pub const default_swap_size_mb: u32 = 2048;

/// A single-entry `FileTreeView` yielding no entries, used to format the
/// resource disk's partition as an empty ext4 filesystem via
/// `ext4.populate`.
const EmptyFileTree = struct {
    fn next(ctx: *anyopaque) ext4.FileTreeView.IteratorError!?ext4.FileTreeView.Entry {
        _ = ctx;
        return null;
    }
    fn reset(ctx: *anyopaque) void {
        _ = ctx;
    }
    fn view(self: *EmptyFileTree) ext4.FileTreeView {
        return .{ .ctx = self, .next_fn = next, .reset_fn = reset };
    }
};

/// Checks `file` (an already-open block device, or -- in tests -- a plain
/// file standing in for one) for an existing whole-disk Linux partition
/// already formatted ext4; if absent, (re)creates a single MBR partition
/// spanning `[partition_start_lba, total_sectors)` and formats it ext4.
/// Idempotent: safe to call every boot, since a previously-formatted disk
/// (persisted by the platform across reboots of the *same* VM) is left
/// untouched.
pub fn ensureFormatted(io: std.Io, allocator: Allocator, file: std.Io.File, total_sectors: u64, now_unix_seconds: i64) !void {
    if (total_sectors > std.math.maxInt(u32)) {
        try ensureFormattedGpt(io, allocator, file, total_sectors, now_unix_seconds);
    } else {
        try ensureFormattedMbr(io, allocator, file, @intCast(total_sectors), now_unix_seconds);
    }
}

fn ensureFormattedMbr(io: std.Io, allocator: Allocator, file: std.Io.File, total_sectors: u32, now_unix_seconds: i64) !void {
    if (total_sectors <= partition_start_lba) return error.DiskTooSmall;

    var sector0: [mbr.sector_size]u8 = undefined;
    const already_formatted = blk: {
        _ = file.readPositionalAll(io, &sector0, 0) catch break :blk false;
        const decoded = mbr.Mbr.decode(&sector0) catch break :blk false;
        if (!isWholeDiskLinuxPartition(decoded, total_sectors)) break :blk false;

        const partition_offset = @as(u64, partition_start_lba) * mbr.sector_size;
        var reader = ext4.open(io, file, allocator, .{ .offset = partition_offset }) catch break :blk false;
        reader.deinit();
        break :blk true;
    };
    if (already_formatted) return;

    const sector_count = total_sectors - partition_start_lba;
    var table = mbr.singleLinuxPartitionMbr(partition_start_lba, sector_count);
    table.disk_signature = @truncate(@as(u64, @bitCast(now_unix_seconds)));
    const encoded = table.encode();
    try file.writePositionalAll(io, &encoded, 0);

    const partition_offset = @as(u64, partition_start_lba) * mbr.sector_size;
    const partition_length = @as(u64, sector_count) * mbr.sector_size;

    var empty_tree: EmptyFileTree = .{};
    var tree_view = empty_tree.view();
    _ = try ext4.populate(io, file, allocator, &tree_view, .{
        .offset = partition_offset,
        .length = partition_length,
        .label = "resource",
        .timestamp = std.math.cast(u32, now_unix_seconds) orelse 0,
    });

    // Tell the kernel to re-read the partition table so the partition
    // device node (e.g. `/dev/sdb1`) actually appears/updates before
    // `setup` tries to mount it -- matching real waagent's own
    // `reread_partition_table` step after (re)partitioning. Best-effort:
    // some environments return an error here even though the partition
    // table was written correctly, in which case the caller's subsequent
    // mount attempt is the real test.
    reReadPartitionTable(file);
}

fn resourceGuid(now_unix_seconds: i64, total_sectors: u64, salt: u8) guid_codec.Guid {
    var result: guid_codec.Guid = undefined;
    std.mem.writeInt(i64, result[0..8], now_unix_seconds, .little);
    std.mem.writeInt(u64, result[8..16], total_sectors, .little);
    result[15] ^= salt;
    result[7] = (result[7] & 0x0f) | 0x40;
    result[8] = (result[8] & 0x3f) | 0x80;
    return result;
}

fn isWholeDiskGptExt4(io: std.Io, allocator: Allocator, file: std.Io.File, total_sectors: u64) bool {
    const img = Image{
        .file = file,
        .format = .raw,
        .data_offset = 0,
        .virtual_size = total_sectors * gpt.sector_size,
    };
    const parsed = gpt.readGpt(img, io, allocator) catch return false;
    defer allocator.free(parsed.partitions);
    const expected_first_usable = 2 + gpt.partition_array_sectors;
    const expected_last_usable = total_sectors - 2 - gpt.partition_array_sectors;
    if (parsed.header.current_lba != 1 or parsed.header.backup_lba != total_sectors - 1) return false;
    if (parsed.header.first_usable_lba != expected_first_usable or parsed.header.last_usable_lba != expected_last_usable) return false;
    if (parsed.partitions.len != 1) return false;
    const partition = parsed.partitions[0];
    if (!std.mem.eql(u8, &partition.partition_type_guid, &guid_codec.linux_filesystem_data)) return false;
    if (partition.first_lba != partition_start_lba) return false;
    const alignment_sectors = ext4.default_block_size / gpt.sector_size;
    const partition_sectors = partition.last_lba - partition.first_lba + 1;
    if (partition_sectors % alignment_sectors != 0) return false;
    if (expected_last_usable - partition.last_lba >= alignment_sectors) return false;

    var reader = ext4.open(io, file, allocator, .{ .offset = partition.first_lba * gpt.sector_size }) catch return false;
    reader.deinit();
    return true;
}

fn ensureFormattedGpt(io: std.Io, allocator: Allocator, file: std.Io.File, total_sectors: u64, now_unix_seconds: i64) !void {
    if (total_sectors <= 2 * gpt.partition_array_sectors + 3) return error.DiskTooSmall;
    if (isWholeDiskGptExt4(io, allocator, file, total_sectors)) return;

    var img = Image{
        .file = file,
        .format = .raw,
        .data_offset = 0,
        .virtual_size = total_sectors * gpt.sector_size,
    };
    const last_usable_lba = total_sectors - 2 - gpt.partition_array_sectors;
    if (last_usable_lba < partition_start_lba) return error.DiskTooSmall;
    const alignment_sectors = ext4.default_block_size / gpt.sector_size;
    const available_sectors = last_usable_lba - partition_start_lba + 1;
    const partition_sectors = available_sectors / alignment_sectors * alignment_sectors;
    if (partition_sectors == 0) return error.DiskTooSmall;
    const placement = gpt.Placement{
        .first_lba = partition_start_lba,
        .last_lba = partition_start_lba + partition_sectors - 1,
    };
    const specs = [_]gpt.PlacedPartitionSpec{.{
        .type_guid = guid_codec.linux_filesystem_data,
        .unique_guid = resourceGuid(now_unix_seconds, total_sectors, 1),
        .placement = placement,
        .name_utf16le = gpt.asciiName("resource"),
    }};
    try gpt.writeGptPlaced(&img, io, resourceGuid(now_unix_seconds, total_sectors, 0), &specs);

    var empty_tree: EmptyFileTree = .{};
    var tree_view = empty_tree.view();
    _ = try ext4.populate(io, file, allocator, &tree_view, .{
        .offset = placement.first_lba * gpt.sector_size,
        .length = partition_sectors * gpt.sector_size,
        .label = "resource",
        .timestamp = std.math.cast(u32, now_unix_seconds) orelse 0,
    });
    reReadPartitionTable(file);
}

/// The Linux `BLKRRPART` ioctl request code (`_IO(0x12, 95)`), used to ask
/// the kernel to re-read a block device's partition table.
const blkrrpart: u32 = 0x125F;

fn reReadPartitionTable(file: std.Io.File) void {
    _ = linux.ioctl(file.handle, blkrrpart, 0);
}

/// Mounts `device_path` (e.g. `/dev/sdb1`) at `mount_point` via a direct
/// `mount(2)` syscall (matching `cdrom.zig`/`zvminit`'s style), creating
/// the mount point directory if needed. `EBUSY` is accepted only when
/// `/proc/mounts` confirms this exact source/target pair is already mounted.
pub fn mountAt(io: std.Io, device_path: [:0]const u8, mount_point: [:0]const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, mount_point);
    switch (mountStatus(device_path, mount_point)) {
        .exact => return,
        .occupied => return error.MountPointBusy,
        .unmounted => {},
    }

    const rc = linux.mount(device_path.ptr, mount_point.ptr, "ext4", 0, 0);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .BUSY => if (mountStatus(device_path, mount_point) != .exact) return error.MountPointBusy,
        else => return error.MountFailed,
    }
}

const MountStatus = enum { unmounted, exact, occupied };

fn mountStatusFromContent(content: []const u8, device_path: []const u8, mount_point: []const u8) MountStatus {
    var status: MountStatus = .unmounted;
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const device = fields.next() orelse continue;
        const target = fields.next() orelse continue;
        if (!std.mem.eql(u8, target, mount_point)) continue;
        if (!std.mem.eql(u8, device, device_path)) return .occupied;
        status = .exact;
    }
    return status;
}

fn mountStatus(device_path: []const u8, mount_point: []const u8) MountStatus {
    const open_rc = linux.open("/proc/mounts", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return .occupied;
    const fd: linux.fd_t = @intCast(open_rc);
    defer _ = linux.close(fd);

    var buf: [64 * 1024]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const read_rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        if (linux.errno(read_rc) != .SUCCESS) return .occupied;
        if (read_rc == 0) break;
        total += read_rc;
    }
    return mountStatusFromContent(buf[0..total], device_path, mount_point);
}

/// Writes the data-loss warning file into `mount_dir` (the mounted resource
/// disk's root).
pub fn writeDataLossWarning(mount_dir: std.Io.Dir, io: std.Io) !void {
    try mount_dir.writeFile(io, .{ .sub_path = dataloss_warning_file_name, .data = dataloss_warning_text });
}

/// True if `swapfile_path` already appears in `/proc/swaps`, i.e. swap is
/// already active there -- checked before (re)running `mkswap`, since
/// rewriting an active swap area's header is not something to risk.
///
/// Reads `/proc/swaps` via raw syscalls rather than `Io.Dir.readFileAlloc`:
/// procfs pseudo-files like this report a `stat` size of 0 despite having
/// real content, which trips up `Io.Writer.Allocating`'s `sendFile` fast
/// path (it trusts that reported size and returns `EndOfStream`
/// immediately without ever issuing a real read when size == 0), silently
/// yielding empty content instead of an error -- confirmed by direct
/// testing against a real `/proc/swaps` in this Zig toolchain.
fn isSwapActive(swapfile_path: []const u8) bool {
    const open_rc = linux.open("/proc/swaps", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return false;
    const fd: linux.fd_t = @intCast(open_rc);
    defer _ = linux.close(fd);

    var buf: [16 * 1024]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const read_rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        if (linux.errno(read_rc) != .SUCCESS) return false;
        if (read_rc == 0) break;
        total += read_rc;
    }
    return std.mem.indexOf(u8, buf[0..total], swapfile_path) != null;
}

/// Creates a fixed-size `swapfile` on the mounted resource disk (at
/// `mount_dir`/`mount_point`), formats it with `mkswap` (an explicit,
/// deliberate shell-out exception -- matching `ssh_keys.zig`'s
/// `ssh-keygen` precedent: swap-file format isn't security-sensitive the
/// way SSH host keys are, and getting `mkswap`'s on-disk format subtly
/// wrong is a real risk not worth taking here), then activates it with a
/// direct `swapon(2)` syscall. Idempotent via `isSwapActive`.
pub fn enableSwap(allocator: Allocator, io: std.Io, mount_dir: std.Io.Dir, mount_point: []const u8, size_mb: u32) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const swapfile_path = try std.fmt.bufPrintZ(&path_buf, "{s}/swapfile", .{mount_point});

    if (isSwapActive(swapfile_path)) return;

    const size_bytes: u64 = @as(u64, size_mb) * 1024 * 1024;
    {
        const file = try mount_dir.createFile(io, "swapfile", .{ .truncate = true });
        defer file.close(io);
        // A plain `setLength` (ftruncate) leaves the file sparse (all
        // holes, no real blocks backing it), which the kernel's `swapon`
        // refuses ("it appears to have holes"); real blocks must actually
        // be allocated. `fallocate(2)` does that directly; on filesystems
        // that don't support it, fall back to writing real zero bytes
        // throughout (matching upstream's own fallocate-then-`dd`
        // fallback in `create_swap_space`).
        const rc = linux.fallocate(file.handle, 0, 0, @intCast(size_bytes));
        if (linux.errno(rc) != .SUCCESS) {
            try zeroFillFile(io, file, size_bytes);
        }
    }
    try mount_dir.setFilePermissions(io, "swapfile", .fromMode(0o600), .{});

    const result = try std.process.run(allocator, io, .{ .argv = &.{ "mkswap", swapfile_path } });
    allocator.free(result.stdout);
    allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) return error.MkswapFailed,
        else => return error.MkswapFailed,
    }

    const swapon_rc = linux.syscall2(.swapon, @intFromPtr(swapfile_path.ptr), 0);
    switch (linux.errno(swapon_rc)) {
        .SUCCESS, .BUSY => {},
        else => return error.SwaponFailed,
    }
}

/// Writes real zero bytes across the whole of `file`, leaving no sparse
/// holes -- the fallback path for `enableSwap` when `fallocate(2)` isn't
/// supported by the underlying filesystem.
fn zeroFillFile(io: std.Io, file: std.Io.File, size_bytes: u64) !void {
    var zero_buf: [64 * 1024]u8 = [_]u8{0} ** (64 * 1024);
    var written: u64 = 0;
    while (written < size_bytes) {
        const chunk = @min(zero_buf.len, size_bytes - written);
        try file.writePositionalAll(io, zero_buf[0..chunk], written);
        written += chunk;
    }
}

/// The Linux `BLKGETSIZE64` ioctl request code (`_IOR(0x12, 114, size_t)`),
/// used to read a block device's real byte size -- unlike a regular file,
/// `stat(2)` on a block-device special file reports `st_size == 0`, so
/// `Io.File.stat` cannot be used for this.
const blkgetsize64: u32 = 0x80081272;

/// Reads the real size, in bytes, of the open block device `file`.
pub fn blockDeviceSizeBytes(file: std.Io.File) !u64 {
    var size: u64 = 0;
    const rc = linux.ioctl(file.handle, blkgetsize64, @intFromPtr(&size));
    if (linux.errno(rc) != .SUCCESS) return error.BlockDeviceSizeUnavailable;
    return size;
}

pub const SetupOptions = struct {
    allocator: Allocator,
    io: std.Io,
    /// Open handle to `/sys/bus/vmbus/devices` (production), or a synthetic
    /// directory tree (tests).
    devices_dir: std.Io.Dir,
    now_unix_seconds: i64,
    /// Borrowed, not necessarily null-terminated (e.g. a slice straight out
    /// of a parsed `/etc/waagent.conf` -- see `waagent_conf.zig`'s
    /// `resourcedisk_mount_point`); `setup` null-terminates its own copy
    /// internally before any real syscall that needs one.
    mount_point: []const u8 = default_mount_point,
    /// When set, `chown`s the mount point to these ids after mounting, so
    /// the disk is usable as scratch space without `sudo`.
    ///
    /// Has to be reapplied on every boot rather than done once at
    /// provisioning time: ownership of a mount point lives in the mounted
    /// filesystem's root inode, not the host's, so a reformat (which this
    /// module performs whenever Azure hands back a blank or resized
    /// resource disk) discards it along with everything else on the disk.
    owner: ?Owner = null,
    enable_swap: bool = false,
    swap_size_mb: u32 = default_swap_size_mb,
};

pub const FormatPolicy = enum {
    replace_invalid,
    mount_existing,
};

/// Numeric ids for the mount point's owner, resolved from `/etc/passwd` by
/// the caller (`main.zig`) so this module stays free of account lookups.
pub const Owner = struct { uid: u32, gid: u32 };

pub const SetupDeviceOptions = struct {
    allocator: Allocator,
    io: std.Io,
    device_name: []const u8,
    now_unix_seconds: i64,
    mount_point: []const u8,
    format_policy: FormatPolicy,
    /// When set, `chown`s the mount point to these ids once mounted. See
    /// `SetupOptions.owner`.
    owner: ?Owner = null,
    write_dataloss_warning: bool = false,
    enable_swap: bool = false,
    swap_size_mb: u32 = default_swap_size_mb,
};

fn partitionDevicePath(buf: []u8, device_name: []const u8) ![:0]const u8 {
    const separator = if (device_name.len > 0 and std.ascii.isDigit(device_name[device_name.len - 1])) "p" else "";
    return std.fmt.bufPrintZ(buf, "/dev/{s}{s}1", .{ device_name, separator });
}

pub fn setupDevice(options: SetupDeviceOptions) !void {
    var dev_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dev_path = try std.fmt.bufPrintZ(&dev_path_buf, "/dev/{s}", .{options.device_name});
    var part_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const part_path = try partitionDevicePath(&part_path_buf, options.device_name);
    var mount_point_buf: [std.fs.max_path_bytes]u8 = undefined;
    const mount_point = try std.fmt.bufPrintZ(&mount_point_buf, "{s}", .{options.mount_point});

    {
        const device_file = try std.Io.Dir.cwd().openFile(options.io, dev_path, .{ .mode = .read_write });
        defer device_file.close(options.io);

        switch (options.format_policy) {
            .replace_invalid => {
                const total_bytes = try blockDeviceSizeBytes(device_file);
                const total_sectors = total_bytes / mbr.sector_size;
                try ensureFormatted(options.io, options.allocator, device_file, total_sectors, options.now_unix_seconds);
            },
            .mount_existing => {},
        }
    }

    try mountAt(options.io, part_path, mount_point);

    var mount_dir = try std.Io.Dir.cwd().openDir(options.io, mount_point, .{});
    defer mount_dir.close(options.io);
    if (options.owner) |owner| try mount_dir.setOwner(options.io, owner.uid, owner.gid);
    if (options.write_dataloss_warning) try writeDataLossWarning(mount_dir, options.io);
    if (options.enable_swap) {
        try enableSwap(options.allocator, options.io, mount_dir, mount_point, options.swap_size_mb);
    }
}

/// Runs the full resource-disk activation sequence: locate the device,
/// (re)format it idempotently if needed, mount it, write the data-loss
/// warning, and optionally enable swap. Deliberately not covered by an
/// automated test end to end -- it requires a real block device special
/// file and `mount(2)`/`swapon(2)` privileges, matching `cdrom.zig`'s and
/// `ssh_keys.regenerateHostKeys`'s precedent for real-device-only glue in
/// this package; the pure/testable pieces above (sysfs walk, partition-
/// table shape check) are covered directly.
pub fn setup(options: SetupOptions) !void {
    const name = try findResourceDiskName(options.allocator, options.devices_dir, options.io);
    defer options.allocator.free(name);
    try setupDevice(.{
        .allocator = options.allocator,
        .io = options.io,
        .device_name = name,
        .now_unix_seconds = options.now_unix_seconds,
        .mount_point = options.mount_point,
        .format_policy = .replace_invalid,
        .owner = options.owner,
        .write_dataloss_warning = true,
        .enable_swap = options.enable_swap,
        .swap_size_mb = options.swap_size_mb,
    });
}

test "isWholeDiskLinuxPartition accepts the exact shape ensureFormatted writes" {
    var table = mbr.singleLinuxPartitionMbr(partition_start_lba, 100_000 - partition_start_lba);
    try std.testing.expect(isWholeDiskLinuxPartition(table, 100_000));

    // Wrong start.
    var wrong_start = table;
    wrong_start.entries[0].first_lba = 63;
    try std.testing.expect(!isWholeDiskLinuxPartition(wrong_start, 100_000));

    // Doesn't span the whole disk.
    var short = table;
    short.entries[0].sector_count -= 1;
    try std.testing.expect(!isWholeDiskLinuxPartition(short, 100_000));

    // A second partition present.
    var extra = table;
    extra.entries[1].partition_type = .linux;
    try std.testing.expect(!isWholeDiskLinuxPartition(extra, 100_000));

    // Not a Linux partition type.
    var wrong_type = table;
    wrong_type.entries[0].partition_type = .gpt_protective;
    try std.testing.expect(!isWholeDiskLinuxPartition(wrong_type, 100_000));

    _ = &table;
}

fn writeDeviceId(io: std.Io, dir: std.Io.Dir, device_guid: []const u8) !void {
    var buf: [64]u8 = undefined;
    const content = try std.fmt.bufPrint(&buf, "{{{s}}}\n", .{device_guid});
    try dir.writeFile(io, .{ .sub_path = "device_id", .data = content });
}

test "findResourceDiskName finds a Gen1-style device via a plain block dir" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "vmbus-0", .default_dir);
    {
        var dev_dir = try tmp.dir.openDir(io, "vmbus-0", .{ .iterate = true });
        defer dev_dir.close(io);
        try writeDeviceId(io, dev_dir, "00000000-0001-8899-0000-000000000000");
        try dev_dir.createDir(io, "block", .default_dir);
        var block_dir = try dev_dir.openDir(io, "block", .{ .iterate = true });
        defer block_dir.close(io);
        try block_dir.createDir(io, "sdb", .default_dir);
    }

    var devices_dir = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer devices_dir.close(io);

    const name = try findResourceDiskName(allocator, devices_dir, io);
    defer allocator.free(name);
    try std.testing.expectEqualStrings("sdb", name);
}

test "findResourceDiskName finds a Gen2-style device at LUN 1, skipping LUN 0 and 2" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "vmbus-scsi", .default_dir);
    {
        var dev_dir = try tmp.dir.openDir(io, "vmbus-scsi", .{ .iterate = true });
        defer dev_dir.close(io);
        try writeDeviceId(io, dev_dir, gen2_device_id);

        for ([_]struct { lun: []const u8, name: []const u8 }{
            .{ .lun = "5:0:0:0", .name = "sda" },
            .{ .lun = "5:0:0:1", .name = "sdb" },
            .{ .lun = "5:0:0:2", .name = "sr0" },
        }) |case| {
            try dev_dir.createDirPath(io, case.lun);
            var lun_dir = try dev_dir.openDir(io, case.lun, .{ .iterate = true });
            defer lun_dir.close(io);
            try lun_dir.createDir(io, "block", .default_dir);
            var block_dir = try lun_dir.openDir(io, "block", .{ .iterate = true });
            defer block_dir.close(io);
            try block_dir.createDir(io, case.name, .default_dir);
        }
    }

    var devices_dir = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer devices_dir.close(io);

    const name = try findResourceDiskName(allocator, devices_dir, io);
    defer allocator.free(name);
    try std.testing.expectEqualStrings("sdb", name);
}

test "findResourceDiskName ignores unrelated VMBus devices" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "vmbus-net", .default_dir);
    {
        var dev_dir = try tmp.dir.openDir(io, "vmbus-net", .{ .iterate = true });
        defer dev_dir.close(io);
        try writeDeviceId(io, dev_dir, "f8615163-df3e-46c5-913f-f2d2f965ed0e");
    }

    var devices_dir = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer devices_dir.close(io);

    try std.testing.expectError(error.ResourceDiskNotFound, findResourceDiskName(allocator, devices_dir, io));
}

test "findResourceDiskName supports the older-distro block:<name> directory shape" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(io, "vmbus-0", .default_dir);
    {
        var dev_dir = try tmp.dir.openDir(io, "vmbus-0", .{ .iterate = true });
        defer dev_dir.close(io);
        try writeDeviceId(io, dev_dir, "00000000-0001-8899-0000-000000000000");
        try dev_dir.createDir(io, "block:sdb", .default_dir);
    }

    var devices_dir = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer devices_dir.close(io);

    const name = try findResourceDiskName(allocator, devices_dir, io);
    defer allocator.free(name);
    try std.testing.expectEqualStrings("sdb", name);
}

test "ensureFormatted formats an unformatted disk then is a no-op on a second call" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const total_sectors: u32 = (16 * 1024 * 1024) / mbr.sector_size; // 16 MiB fake disk
    const file = try tmp.dir.createFile(io, "disk.img", .{ .truncate = true, .read = true });
    defer file.close(io);
    try file.setLength(io, @as(u64, total_sectors) * mbr.sector_size);

    try ensureFormatted(io, allocator, file, total_sectors, 1_700_000_000);

    var sector0: [mbr.sector_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sector0, 0);
    const decoded = try mbr.Mbr.decode(&sector0);
    try std.testing.expect(isWholeDiskLinuxPartition(decoded, total_sectors));

    var reader = try ext4.open(io, file, allocator, .{ .offset = @as(u64, partition_start_lba) * mbr.sector_size });
    reader.deinit();

    // Corrupt the partition table's tail marker to prove a second call is a
    // true no-op (it wouldn't be re-detected as already-formatted, so if it
    // silently skipped work we'd still see the corruption -- but if it did
    // reformat, this specific corruption would be gone; we instead assert
    // the *content* written the first time survives untouched).
    var sector0_again: [mbr.sector_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sector0_again, 0);
    try ensureFormatted(io, allocator, file, total_sectors, 1_800_000_000);
    var sector0_after: [mbr.sector_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sector0_after, 0);
    try std.testing.expectEqualSlices(u8, &sector0_again, &sector0_after);
}

test "ensureFormatted rejects a disk too small to hold the aligned partition" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile(io, "disk.img", .{ .truncate = true, .read = true });
    defer file.close(io);
    try file.setLength(io, 1024 * 1024);

    try std.testing.expectError(error.DiskTooSmall, ensureFormatted(io, allocator, file, partition_start_lba, 0));
}

test "partitionDevicePath handles conventional and digit-ending disk names" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/dev/sdb1", try partitionDevicePath(&buf, "sdb"));
    try std.testing.expectEqualStrings("/dev/nvme0n1p1", try partitionDevicePath(&buf, "nvme0n1"));
}

test "mount status distinguishes exact, occupied, and free targets" {
    const mounts =
        \\/dev/sda2 / ext4 rw 0 0
        \\/dev/sdb1 /d ext4 rw 0 0
        \\/dev/sdc1 /e ext4 rw 0 0
    ;
    try std.testing.expectEqual(MountStatus.exact, mountStatusFromContent(mounts, "/dev/sdb1", "/d"));
    try std.testing.expectEqual(MountStatus.occupied, mountStatusFromContent(mounts, "/dev/sdb1", "/e"));
    try std.testing.expectEqual(MountStatus.occupied, mountStatusFromContent(mounts, "/dev/sdd1", "/d"));
    try std.testing.expectEqual(MountStatus.unmounted, mountStatusFromContent(mounts, "/dev/sdd1", "/f"));
}

test "GPT resource formatting supports a whole-disk ext4 partition" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const total_sectors: u64 = (64 * 1024 * 1024) / gpt.sector_size;
    const file = try tmp.dir.createFile(io, "resource-gpt.img", .{ .truncate = true, .read = true });
    defer file.close(io);
    try file.setLength(io, total_sectors * gpt.sector_size);
    try ensureFormattedGpt(io, allocator, file, total_sectors, 1_700_000_000);
    try std.testing.expect(isWholeDiskGptExt4(io, allocator, file, total_sectors));

    const grown_sectors = total_sectors + 2048;
    try file.setLength(io, grown_sectors * gpt.sector_size);
    try std.testing.expect(!isWholeDiskGptExt4(io, allocator, file, grown_sectors));
}

test "writeDataLossWarning writes the warning file under a scoped directory" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir = try tmp.dir.openDir(io, ".", .{});
    defer dir.close(io);

    try writeDataLossWarning(dir, io);

    const content = try tmp.dir.readFileAlloc(io, dataloss_warning_file_name, allocator, .limited(4096));
    defer allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "temporary") != null);
}
