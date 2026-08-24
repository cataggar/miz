//! The `Image` abstraction: a format-agnostic view over a disk image file,
//! analogous to qemu's `BlockDriver`. Supports `raw`, fixed `vhd`, dynamic
//! `vhd` (sparse, block-allocated), `vhdx`, and `qcow2`.
//! Because there are only ever a
//! handful of formats, this uses a plain tagged union rather than a
//! vtable/`anyopaque` interface -- simpler and fully type-safe for a small,
//! closed set of variants.
//!
//! Every operation takes an explicit `std.Io` parameter (Zig 0.16's I/O
//! interface), matching the pattern used by `std.Io.File`/`std.Io.Dir`
//! themselves -- there is no implicit global filesystem or event loop.
//!
//! Dynamic VHD layout/semantics (BAT sector numbering, sector bitmap size,
//! and the "footer trailer always sits at the current end of file, and gets
//! overwritten by the next block's bitmap" allocation strategy) are verified
//! against QEMU's `block/vpc.c` (`vpc_open`, `alloc_block`, `get_image_offset`,
//! `create_dynamic_disk`), the de-facto interoperability reference.

const std = @import("std");
const Io = std.Io;
const vhd = @import("vhd.zig");
const vhdx = @import("vhdx.zig");
const qcow2 = @import("qcow2.zig");
const block_device = @import("block_device.zig");
pub const Format = @import("formats.zig").Format;

pub const OpenError = error{
    UnsupportedVhdDiskType,
    InvalidBlockSize,
    NotBlockDevice,
} || block_device.PreflightError || Io.File.OpenError || Io.File.ReadPositionalError || Io.File.StatError ||
    vhd.Footer.DecodeError || vhd.DynamicHeader.DecodeError || vhdx.OpenError || qcow2.OpenError;

pub const OpenDeviceForWriteError = error{
    BlockDeviceWriteNotPermitted,
    NotBlockDevice,
    DestinationTooSmall,
} || block_device.PreflightError || Io.File.OpenError || Io.File.StatError;

pub const CreateError = error{
    SizeNotSectorAligned,
    UnsupportedFormatForCreate,
    /// `create` never writes through a block-device node: creating an image
    /// means laying down a fresh format from byte 0, which on a device means
    /// destroying whatever system is installed on it.
    BlockDeviceCreateNotSupported,
} || Io.File.OpenError || Io.File.WritePositionalError || Io.File.SetLengthError ||
    Io.File.StatError || vhdx.CreateError || qcow2.CreateError;

pub const VhdSubformat = enum { fixed, dynamic };

pub const CreateOptions = struct {
    /// Only consulted when `format == .vhd`. Defaults to `.dynamic` to match
    /// real qemu-img's default subformat for `-f vpc`. Azure managed-disk
    /// uploads require *fixed* VHDs -- pass `.fixed` explicitly (the future
    /// `vmiz build-image`/`azure fixup` commands do this automatically).
    vhd_subformat: VhdSubformat = .dynamic,
    unique_id: ?[16]u8 = null,
    timestamp_unix: ?i64 = null,
    vhdx: vhdx.CreateOptions = .{},
};

pub const Info = struct {
    format: Format,
    /// Guest-visible disk size, in bytes.
    virtual_size: u64,
    /// Bytes actually occupied by the file on disk. For `raw`/fixed `vhd`
    /// this equals the virtual size (+ footer for vhd); for dynamic `vhd`
    /// `vhdx`, and `qcow2` it reflects only the blocks actually allocated so far.
    file_size: u64,
    subformat: ?VhdSubformat,
};

/// Per-image state needed to navigate a dynamic VHD's BAT and data blocks.
/// Not cached in memory beyond these scalars -- BAT entries themselves are
/// read/written directly against the file on each access (see `readBatEntry`),
/// trading a little I/O for a much simpler, allocation-free `Image`.
const DynamicState = struct {
    bat_offset: u64,
    max_table_entries: u32,
    block_size: u32,
    bitmap_size: u32,
    /// Where the *next* allocated block (bitmap + data) will be written.
    /// Also where a copy of the footer currently sits (matching QEMU: the
    /// footer trailer always sits at the true end of file, and gets
    /// overwritten by the next block's bitmap when another block is
    /// allocated).
    free_data_block_offset: u64,
    /// A ready-to-write encoded footer, rewritten to `free_data_block_offset`
    /// after every new block allocation.
    footer_template: [vhd.footer_size]u8,
};

const VhdxState = vhdx.Info;

const CopyPolicy = enum {
    /// The destination already reads as zero wherever no bytes have been
    /// written, so all-zero chunks may stay sparse.
    skip_zero_chunks,
    /// The destination may contain old data, so zero chunks must overwrite it.
    write_zero_chunks,
};

/// Extra state carried by images whose bytes live on a block-device node
/// (`/dev/nvme0n1`, `/dev/sda`, `/dev/mapper/vg-lv`, ...) rather than in a
/// regular file.
pub const DeviceInfo = struct {
    /// Kernel-reported geometry. `geometry.size_bytes` -- not the `stat`
    /// size, which is always 0 for a device node -- is the authoritative
    /// size of the image, and is what `virtual_size` reflects for a
    /// device-backed raw image.
    geometry: block_device.Geometry,
    /// Whether the caller explicitly opted in to writing through the device
    /// node via `OpenOptions` or `DeviceWriteOptions`. When false, every
    /// mutating operation fails with `error.BlockDeviceWriteNotPermitted`.
    write_allowed: bool,
    /// Safety and inventory data captured while the device was still open
    /// read-only. Present for the dedicated destructive-write constructor.
    preflight: ?block_device.PreflightReport = null,
    preflight_allocator: ?std.mem.Allocator = null,

    fn deinit(self: *DeviceInfo) void {
        if (self.preflight) |*report| {
            report.deinit(self.preflight_allocator.?);
        }
        self.* = undefined;
    }
};

pub const OpenOptions = struct {
    /// Whether the caller intends to write through the returned image. A
    /// regular file is opened `read_write` when this is set, `read_only`
    /// otherwise.
    write: bool = true,
    /// Reject qcow2 backing and external data files instead of opening the
    /// host paths named by the image header.
    standalone_qcow2: bool = false,
    /// Opt in (`vmiz --allow-device-write`) to writing through a
    /// block-device node. Without it, a device is opened read-only even when
    /// `write` is set, so that inspecting a live disk can never damage it by
    /// accident.
    allow_device_write: bool = false,
    /// Owns any preflight report attached to a writable device-backed image.
    allocator: std.mem.Allocator = std.heap.page_allocator,
    /// Only advisory policies may consult this. Mandatory refusals remain.
    force: bool = false,
};

pub const DeviceWriteOptions = struct {
    /// Required acknowledgement that opening this destination permits raw
    /// writes to the entire device.
    allow_device_write: bool = false,
    /// Only advisory policies may consult this. Mandatory size, mount,
    /// holder, and running-root refusals are never relaxed.
    force: bool = false,
    /// Owns the preflight report attached to the returned `Image`.
    allocator: std.mem.Allocator = std.heap.page_allocator,
};

pub const DeviceWriteOutcome = enum {
    partition_table_refreshed,
    partition_table_stale_busy,
    partition_table_stale_unsupported,
    partition_table_stale_failed,

    pub fn message(self: DeviceWriteOutcome) []const u8 {
        return switch (self) {
            .partition_table_refreshed => "The kernel partition table was refreshed. Partition device nodes may still be settling.",
            .partition_table_stale_busy => "The data on the device is correct and durable, but the kernel partition table could not be refreshed because the device is busy. The kernel's view is stale; detach and reattach the device before using its partitions.",
            .partition_table_stale_unsupported => "The data on the device is correct and durable, but this platform cannot refresh the kernel partition table. The kernel's view may be stale; detach and reattach the device before using its partitions.",
            .partition_table_stale_failed => "The data on the device is correct and durable, but the kernel partition table refresh failed. The kernel's view is stale; detach and reattach the device before using its partitions.",
        };
    }

    /// A non-null message means the bytes are durable but the kernel is still
    /// using its old partition layout. Device-write commands must show this
    /// instead of reporting plain success.
    pub fn warning(self: DeviceWriteOutcome) ?[]const u8 {
        return switch (self) {
            .partition_table_refreshed => null,
            else => self.message(),
        };
    }
};

pub const CopyResult = struct {
    /// True when a device destination was durably flushed.
    device_flushed: bool = false,
    /// The partition refresh outcome when requested; null for ordinary files
    /// and when `.flush_device` intentionally defers the refresh.
    device_write: ?DeviceWriteOutcome = null,
};

pub const CopyFinalization = enum {
    /// Make device writes durable without refreshing the kernel partition view.
    flush_device,
    /// Make device writes durable and refresh the kernel partition view.
    finish_device_write,
};

/// Where an image's authoritative size comes from, resolved once at open
/// time and then used in place of the `stat` size for format sniffing.
const Source = union(enum) {
    /// A regular file: `stat` reports the real size.
    file: u64,
    /// A block-device node: `stat` reports `st_size == 0`, so the size comes
    /// from the kernel instead.
    device: DeviceInfo,

    fn sizeBytes(self: Source) u64 {
        return switch (self) {
            .file => |size| size,
            .device => |dev| dev.geometry.size_bytes,
        };
    }

    fn deviceInfo(self: Source) ?DeviceInfo {
        return switch (self) {
            .file => null,
            .device => |dev| dev,
        };
    }
};

const PreparedDevice = struct {
    geometry: block_device.Geometry,
    number: block_device.DeviceNumber,
    report: block_device.PreflightReport,
    allocator: std.mem.Allocator,

    fn deinit(self: *PreparedDevice) void {
        self.report.deinit(self.allocator);
        self.* = undefined;
    }
};

fn prepareDeviceForWrite(
    allocator: std.mem.Allocator,
    io: Io,
    read_only_file: Io.File,
    source_virtual_size: ?u64,
    force: bool,
) block_device.PreflightError!PreparedDevice {
    const geometry = try block_device.probe(read_only_file);
    const required_size = source_virtual_size orelse geometry.size_bytes;
    if (required_size > geometry.size_bytes) return error.DestinationTooSmall;
    const number = try block_device.deviceNumber(read_only_file);

    const mountinfo = try block_device.readMountInfo(allocator);
    defer allocator.free(mountinfo);
    var class_block_dir = Io.Dir.openDirAbsolute(io, "/sys/class/block", .{ .iterate = true }) catch
        return error.BlockDeviceSysfsUnavailable;
    defer class_block_dir.close(io);

    return .{
        .geometry = geometry,
        .number = number,
        .report = try block_device.preflight(
            allocator,
            io,
            read_only_file,
            geometry,
            required_size,
            number,
            mountinfo,
            class_block_dir,
            .{ .force = force },
        ),
        .allocator = allocator,
    };
}

fn verifyPreparedDevice(
    io: Io,
    writable_file: Io.File,
    prepared: PreparedDevice,
) (block_device.PreflightError || Io.File.StatError)!void {
    if ((try writable_file.stat(io)).kind != .block_device) {
        return error.BlockDeviceChangedDuringOpen;
    }
    if (!(try block_device.deviceNumber(writable_file)).eql(prepared.number)) {
        return error.BlockDeviceChangedDuringOpen;
    }
    const geometry = try block_device.probe(writable_file);
    if (geometry.size_bytes != prepared.geometry.size_bytes or
        geometry.logical_sector_size != prepared.geometry.logical_sector_size)
    {
        return error.BlockDeviceChangedDuringOpen;
    }
}

pub const Image = struct {
    file: Io.File,
    format: Format,
    /// Offset within `file` where guest-visible byte 0 lives (0 for raw,
    /// fixed vhd, and dynamic vhd -- dynamic vhd's "offset 0" is virtual;
    /// actual block placement is indirected through the BAT).
    data_offset: u64,
    virtual_size: u64,
    dynamic: ?DynamicState = null,
    vhdx: ?VhdxState = null,
    qcow2: ?qcow2.Info = null,
    /// Non-null when `file` is a block-device node instead of a regular file.
    device: ?DeviceInfo = null,

    pub fn openPath(io: Io, path: []const u8) OpenError!Image {
        return openPathWithOptions(io, path, .{});
    }

    /// Opens an image and all path-relative backing files without write access.
    /// Mutating methods on the returned image fail through the underlying
    /// read-only file handle.
    pub fn openPathReadOnly(io: Io, path: []const u8) OpenError!Image {
        return openPathWithOptions(io, path, .{ .write = false });
    }

    /// Opens an image read-only while rejecting QCOW2 backing and external
    /// data paths before they can cause host-file I/O.
    pub fn openPathReadOnlyStandalone(io: Io, path: []const u8) OpenError!Image {
        return openPathWithOptions(io, path, .{ .write = false, .standalone_qcow2 = true });
    }

    /// Opens `path`, which may name a regular image file or a block-device
    /// node. Devices are opened read-only unless
    /// `options.allow_device_write` is set.
    pub fn openPathWithOptions(io: Io, path: []const u8, options: OpenOptions) OpenError!Image {
        // Classify the path *before* opening it so a writable descriptor
        // onto a live disk is never created in the first place. A failure
        // here is deliberately not diagnosed separately: the open below
        // reports the same underlying problem with a better error.
        const path_is_device = if (Io.Dir.cwd().statFile(io, path, .{})) |path_stat|
            path_stat.kind == .block_device
        else |_|
            false;
        if (path_is_device and options.write and options.allow_device_write) {
            var read_only_file: ?Io.File = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
            defer if (read_only_file) |file| file.close(io);
            if ((try read_only_file.?.stat(io)).kind != .block_device) return error.NotBlockDevice;
            var prepared = try prepareDeviceForWrite(
                options.allocator,
                io,
                read_only_file.?,
                null,
                options.force,
            );
            errdefer prepared.deinit();
            read_only_file.?.close(io);
            read_only_file = null;

            const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
            errdefer file.close(io);
            try verifyPreparedDevice(io, file, prepared);
            var image = try openFileFromSource(io, file, path, options.standalone_qcow2, .{
                .device = .{
                    .geometry = prepared.geometry,
                    .write_allowed = true,
                },
            });
            image.attachPreflight(prepared);
            return image;
        }
        const write = options.write and (!path_is_device or options.allow_device_write);

        const file = try Io.Dir.cwd().openFile(io, path, .{
            .mode = if (write) .read_write else .read_only,
        });
        errdefer file.close(io);
        if (write and (try file.stat(io)).kind == .block_device) {
            return error.BlockDeviceChangedDuringOpen;
        }
        return openFileWithPath(io, file, path, options);
    }

    /// Opens an existing block device as a raw write destination. Unlike
    /// `create`, this never truncates or initializes the target. The caller
    /// must explicitly allow device writes and provide the source virtual size
    /// so a destination that is too small is rejected before any bytes land.
    pub fn openDeviceForWrite(
        io: Io,
        path: []const u8,
        source_virtual_size: u64,
        options: DeviceWriteOptions,
    ) OpenDeviceForWriteError!Image {
        if (!options.allow_device_write) return error.BlockDeviceWriteNotPermitted;

        // Refuse ordinary paths before opening anything writable. The opened
        // handle is checked again below so a path replacement cannot turn
        // this deliberate device operation into a regular-file write.
        const path_stat = try Io.Dir.cwd().statFile(io, path, .{});
        if (path_stat.kind != .block_device) return error.NotBlockDevice;

        var read_only_file: ?Io.File = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        defer if (read_only_file) |file| file.close(io);
        if ((try read_only_file.?.stat(io)).kind != .block_device) return error.NotBlockDevice;
        var prepared = try prepareDeviceForWrite(
            options.allocator,
            io,
            read_only_file.?,
            source_virtual_size,
            options.force,
        );
        errdefer prepared.deinit();
        read_only_file.?.close(io);
        read_only_file = null;

        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
        errdefer file.close(io);
        try verifyPreparedDevice(io, file, prepared);

        var image = try deviceWriteImage(
            file,
            prepared.geometry,
            source_virtual_size,
            options,
        );
        image.attachPreflight(prepared);
        return image;
    }

    /// Takes ownership of `file` (closing the returned `Image` closes it).
    pub fn openFile(io: Io, file: Io.File) OpenError!Image {
        return openFileWithPath(io, file, null, .{});
    }

    /// Takes ownership of `file`, which may be an already-open block-device
    /// handle. Only writes through a device when the caller opted in with
    /// `options.allow_device_write` *and* opened the handle writable.
    pub fn openFileWithOptions(io: Io, file: Io.File, options: OpenOptions) OpenError!Image {
        const file_stat = try file.stat(io);
        if (file_stat.kind == .block_device and options.write and options.allow_device_write) {
            var prepared = try prepareDeviceForWrite(
                options.allocator,
                io,
                file,
                null,
                options.force,
            );
            errdefer prepared.deinit();
            var image = try openFileFromSource(io, file, null, options.standalone_qcow2, .{
                .device = .{
                    .geometry = prepared.geometry,
                    .write_allowed = true,
                },
            });
            image.attachPreflight(prepared);
            return image;
        }
        return openFileWithPath(io, file, null, options);
    }

    /// Takes ownership of a standalone qcow2 file without resolving or
    /// opening any path named by its header.
    pub fn openStandaloneQcow2File(io: Io, file: Io.File) OpenError!Image {
        const qcow2_info = try qcow2.openStandalone(io, file);
        return .{
            .file = file,
            .format = .qcow2,
            .data_offset = 0,
            .virtual_size = qcow2_info.virtual_size,
            .qcow2 = qcow2_info,
        };
    }

    /// Lists path-resolved host files, excluding the top-level image, that
    /// contribute guest-visible data. Only qcow2 currently has dependencies.
    pub fn sourceDependencyPaths(
        self: Image,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![][]u8 {
        if (self.qcow2) |qcow_info| {
            return qcow2.sourceDependencyPaths(allocator, qcow_info);
        }
        return allocator.alloc([]u8, 0);
    }

    fn openFileWithPath(
        io: Io,
        file: Io.File,
        path: ?[]const u8,
        options: OpenOptions,
    ) OpenError!Image {
        const file_stat = try file.stat(io);
        // The kind of the *opened handle* -- not of the path stat'ed before
        // opening -- decides device treatment, so a path swapped between the
        // two still cannot be written through without the opt-in.
        const source: Source = switch (file_stat.kind) {
            .block_device => .{ .device = .{
                .geometry = try block_device.probe(file),
                .write_allowed = options.write and options.allow_device_write,
            } },
            else => .{ .file = file_stat.size },
        };

        return openFileFromSource(io, file, path, options.standalone_qcow2, source);
    }

    /// Opens `file` against an already-resolved `source`, stamping the
    /// device state onto whatever format was sniffed.
    fn openFileFromSource(
        io: Io,
        file: Io.File,
        path: ?[]const u8,
        standalone_qcow2: bool,
        source: Source,
    ) OpenError!Image {
        var image = try sniffFormat(io, file, path, standalone_qcow2, source.sizeBytes());
        image.device = source.deviceInfo();
        return image;
    }

    fn deviceWriteImage(
        file: Io.File,
        geometry: block_device.Geometry,
        source_virtual_size: u64,
        options: DeviceWriteOptions,
    ) OpenDeviceForWriteError!Image {
        if (!options.allow_device_write) return error.BlockDeviceWriteNotPermitted;
        if (source_virtual_size > geometry.size_bytes) return error.DestinationTooSmall;
        return .{
            .file = file,
            .format = .raw,
            .data_offset = 0,
            .virtual_size = geometry.size_bytes,
            .device = .{
                .geometry = geometry,
                .write_allowed = true,
            },
        };
    }

    fn attachPreflight(self: *Image, prepared: PreparedDevice) void {
        self.device.?.preflight = prepared.report;
        self.device.?.preflight_allocator = prepared.allocator;
    }

    /// Sniffs the format at `source`'s authoritative size. Every read stays
    /// within that size, so a device is never read past its end even though
    /// the VHD probe works backwards from the last sector.
    fn sniffFormat(
        io: Io,
        file: Io.File,
        path: ?[]const u8,
        standalone_qcow2: bool,
        file_size: u64,
    ) OpenError!Image {

        // qcow2 and VHDX signatures both live at the very start of the file
        // (unlike VHD's footer, which trails the data); sniff them first so
        // we never misdetect either format as raw. Once a signature matches,
        // any further parse failure is a real error, not a fallback-to-raw
        // case.
        if (file_size >= 4) {
            var sig_buf: [8]u8 = undefined;
            const n = try file.readPositionalAll(io, &sig_buf, 0);
            if (n >= 4 and std.mem.eql(u8, sig_buf[0..4], &qcow2.file_signature)) {
                const qcow2_info = if (standalone_qcow2)
                    try qcow2.openStandalone(io, file)
                else if (path) |p|
                    try qcow2.openAtPath(io, file, p)
                else
                    try qcow2.open(io, file);
                return .{
                    .file = file,
                    .format = .qcow2,
                    .data_offset = 0,
                    .virtual_size = qcow2_info.virtual_size,
                    .qcow2 = qcow2_info,
                };
            }
            if (n == 8 and std.mem.eql(u8, &sig_buf, &vhdx.file_signature)) {
                const vhdx_info = try vhdx.open(io, file);
                return .{
                    .file = file,
                    .format = .vhdx,
                    .data_offset = 0,
                    .virtual_size = vhdx_info.virtual_size,
                    .vhdx = vhdx_info,
                };
            }
        }

        if (file_size >= vhd.footer_size) {
            var footer_buf: [vhd.footer_size]u8 = undefined;
            const n = try file.readPositionalAll(io, &footer_buf, file_size - vhd.footer_size);
            if (n == vhd.footer_size) {
                if (vhd.Footer.decode(&footer_buf)) |footer| {
                    switch (footer.disk_type) {
                        .fixed => return .{
                            .file = file,
                            .format = .vhd,
                            .data_offset = 0,
                            .virtual_size = footer.virtualSize(),
                        },
                        .dynamic => return try openDynamic(io, file, footer, footer_buf),
                        else => return error.UnsupportedVhdDiskType,
                    }
                } else |_| {
                    // Not a valid VHD footer -- fall through and treat as raw.
                }
            }
        }

        return .{
            .file = file,
            .format = .raw,
            .data_offset = 0,
            .virtual_size = file_size,
        };
    }

    fn openDynamic(io: Io, file: Io.File, footer: vhd.Footer, footer_buf: [vhd.footer_size]u8) OpenError!Image {
        var header_buf: [vhd.dynamic_header_size]u8 = undefined;
        _ = try file.readPositionalAll(io, &header_buf, footer.data_offset);
        const header = try vhd.DynamicHeader.decode(&header_buf);

        if (!std.math.isPowerOfTwo(header.block_size) or header.block_size < 512) {
            return error.InvalidBlockSize;
        }
        const bitmap_size = vhd.bitmapSize(header.block_size);
        const free_offset = try computeFreeDataBlockOffset(
            file,
            io,
            header.table_offset,
            header.max_table_entries,
            bitmap_size,
            header.block_size,
        );

        return .{
            .file = file,
            .format = .vhd,
            .data_offset = 0,
            .virtual_size = footer.virtualSize(),
            .dynamic = .{
                .bat_offset = header.table_offset,
                .max_table_entries = header.max_table_entries,
                .block_size = header.block_size,
                .bitmap_size = bitmap_size,
                .free_data_block_offset = free_offset,
                .footer_template = footer_buf,
            },
        };
    }

    /// Creates a brand-new image file of the given format and virtual size.
    /// `size` must be a multiple of the 512-byte sector size.
    pub fn create(io: Io, path: []const u8, format: Format, size: u64, options: CreateOptions) CreateError!Image {
        return createPath(io, path, format, size, options, false);
    }

    /// Creates a brand-new image without following or truncating an existing
    /// path. Intended for transactional scratch and output artifacts.
    pub fn createExclusive(io: Io, path: []const u8, format: Format, size: u64, options: CreateOptions) CreateError!Image {
        return createPath(io, path, format, size, options, true);
    }

    fn createPath(
        io: Io,
        path: []const u8,
        format: Format,
        size: u64,
        options: CreateOptions,
        exclusive: bool,
    ) CreateError!Image {
        try validateCreate(format, size, options);
        try rejectDeviceTarget(existingTargetKind(io, path));

        const file = try Io.Dir.cwd().createFile(io, path, .{
            .read = true,
            .truncate = true,
            .exclusive = exclusive,
        });
        errdefer if (exclusive) Io.Dir.cwd().deleteFile(io, path) catch {};
        errdefer file.close(io);
        return initializeFile(io, file, format, size, options);
    }

    /// Initializes an already-open file as a new image and takes ownership of
    /// its handle. Callers can use this with descriptor-pinned atomic staging
    /// files without reopening a pathname.
    pub fn createFile(io: Io, file: Io.File, format: Format, size: u64, options: CreateOptions) CreateError!Image {
        errdefer file.close(io);
        try validateCreate(format, size, options);
        try rejectDeviceTarget((try file.stat(io)).kind);
        try file.setLength(io, 0);
        return initializeFile(io, file, format, size, options);
    }

    fn initializeFile(
        io: Io,
        file: Io.File,
        format: Format,
        size: u64,
        options: CreateOptions,
    ) CreateError!Image {
        switch (format) {
            .raw => {
                try file.setLength(io, size);
                return .{ .file = file, .format = .raw, .data_offset = 0, .virtual_size = size };
            },
            .vhd => switch (options.vhd_subformat) {
                .fixed => {
                    try file.setLength(io, size + vhd.footer_size);
                    const footer = vhd.Footer.forFixedDisk(
                        size,
                        options.unique_id orelse randomUuid(io),
                        options.timestamp_unix orelse nowUnix(io),
                    );
                    const encoded = footer.encode();
                    try file.writePositionalAll(io, &encoded, size);
                    return .{ .file = file, .format = .vhd, .data_offset = 0, .virtual_size = size };
                },
                .dynamic => return try createDynamic(io, file, size, options),
            },
            .qcow2 => {
                const qcow2_info = try qcow2.create(io, file, size);
                return .{ .file = file, .format = .qcow2, .data_offset = 0, .virtual_size = size, .qcow2 = qcow2_info };
            },
            .vhdx => {
                const vhdx_info = try vhdx.createWithOptions(io, file, size, options.vhdx);
                return .{ .file = file, .format = .vhdx, .data_offset = 0, .virtual_size = size, .vhdx = vhdx_info };
            },
        }
    }

    /// Reports the kind of an existing `path`, or `.unknown` when it cannot
    /// be classified. A stat failure is not diagnosed here -- the usual case
    /// is a path that does not exist yet, which is exactly what `create` is
    /// for, and any real problem resurfaces from the create call itself.
    fn existingTargetKind(io: Io, path: []const u8) Io.File.Kind {
        const target_stat = Io.Dir.cwd().statFile(io, path, .{}) catch return .unknown;
        return target_stat.kind;
    }

    /// `create` lays a fresh format down from byte 0 and truncates whatever
    /// was there, so pointing it at a device node would destroy the disk it
    /// names. Refuse before anything is opened or written.
    fn rejectDeviceTarget(kind: Io.File.Kind) CreateError!void {
        if (kind == .block_device) return error.BlockDeviceCreateNotSupported;
    }

    fn validateCreate(format: Format, size: u64, options: CreateOptions) CreateError!void {
        if (size % 512 != 0) return error.SizeNotSectorAligned;
        switch (format) {
            .raw => {},
            .vhd => switch (options.vhd_subformat) {
                .fixed => if (size > std.math.maxInt(u64) - vhd.footer_size) return error.ImageTooLarge,
                .dynamic => {
                    const total_sectors = size / 512;
                    const sectors_per_block = vhd.default_block_size / 512;
                    const entries = std.math.divCeil(u64, total_sectors, sectors_per_block) catch unreachable;
                    if (entries > std.math.maxInt(u32)) return error.ImageTooLarge;
                },
            },
            .qcow2 => try qcow2.validateCreateSize(size),
            .vhdx => try vhdx.validateCreateOptions(size, options.vhdx),
        }
    }

    fn createDynamic(io: Io, file: Io.File, size: u64, options: CreateOptions) CreateError!Image {
        const block_size: u32 = vhd.default_block_size;
        const bitmap_size = vhd.bitmapSize(block_size);
        const total_sectors = size / 512;
        const sectors_per_block = block_size / 512;
        const max_table_entries: u32 = @intCast(std.math.divCeil(u64, total_sectors, sectors_per_block) catch unreachable);

        const bat_offset: u64 = vhd.footer_size + vhd.dynamic_header_size;
        const bat_bytes_len: u64 = @as(u64, max_table_entries) * 4;
        const free_offset = alignUp(bat_offset + bat_bytes_len, 512);

        const footer = vhd.Footer.forDynamicDisk(
            size,
            vhd.footer_size,
            options.unique_id orelse randomUuid(io),
            options.timestamp_unix orelse nowUnix(io),
        );
        const footer_bytes = footer.encode();
        try file.writePositionalAll(io, &footer_bytes, 0);

        const header = vhd.DynamicHeader{
            .table_offset = bat_offset,
            .max_table_entries = max_table_entries,
            .block_size = block_size,
        };
        const header_bytes = header.encode();
        try file.writePositionalAll(io, &header_bytes, vhd.footer_size);

        try fillBatUnallocated(file, io, bat_offset, max_table_entries);

        try file.setLength(io, free_offset + vhd.footer_size);
        try file.writePositionalAll(io, &footer_bytes, free_offset);

        return .{
            .file = file,
            .format = .vhd,
            .data_offset = 0,
            .virtual_size = size,
            .dynamic = .{
                .bat_offset = bat_offset,
                .max_table_entries = max_table_entries,
                .block_size = block_size,
                .bitmap_size = bitmap_size,
                .free_data_block_offset = free_offset,
                .footer_template = footer_bytes,
            },
        };
    }

    pub fn info(self: Image, io: Io) Io.File.StatError!Info {
        // A device node's `stat` size is 0, so its occupied size is its full
        // extent: nothing about a device is sparse.
        const file_size = if (self.device) |dev|
            dev.geometry.size_bytes
        else
            (try self.file.stat(io)).size;
        const subformat: ?VhdSubformat = if (self.format != .vhd)
            null
        else if (self.dynamic != null) .dynamic else .fixed;
        return .{ .format = self.format, .virtual_size = self.virtual_size, .file_size = file_size, .subformat = subformat };
    }

    pub const PreadError = vhdx.PreadError || qcow2.PreadError || Io.File.ReadPositionalError;

    pub fn pread(self: Image, io: Io, buffer: []u8, offset: u64) PreadError!usize {
        if (self.qcow2) |q| return qcow2.pread(self.file, io, q, buffer, offset);
        if (self.dynamic) |d| {
            var total: usize = 0;
            var off = offset;
            var remaining = buffer.len;
            while (remaining > 0) {
                const block_index: u32 = @intCast(off / d.block_size);
                const in_block_offset: u32 = @intCast(off % d.block_size);
                const chunk: usize = @min(remaining, d.block_size - in_block_offset);

                const bat_value = try readBatEntry(self.file, io, d.bat_offset, block_index);
                if (bat_value == unallocated_bat_entry) {
                    @memset(buffer[total..][0..chunk], 0);
                } else {
                    const block_data_offset = @as(u64, bat_value) * 512 + d.bitmap_size;
                    const got = try self.file.readPositionalAll(io, buffer[total..][0..chunk], block_data_offset + in_block_offset);
                    if (got < chunk) @memset(buffer[total + got ..][0 .. chunk - got], 0);
                }

                total += chunk;
                off += chunk;
                remaining -= chunk;
            }
            return total;
        }
        if (self.vhdx) |v| return vhdx.pread(self.file, io, v, buffer, offset);
        return self.file.readPositionalAll(io, buffer, self.data_offset + offset);
    }

    pub const PwriteError = error{
        /// The image is backed by a block-device node opened without the
        /// explicit `allow_device_write` opt-in.
        BlockDeviceWriteNotPermitted,
    } || vhdx.PwriteError || qcow2.PwriteError || Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError || Io.File.StatError;

    pub fn pwrite(self: *Image, io: Io, buffer: []const u8, offset: u64) PwriteError!void {
        // Checked here rather than only at open time so that every write
        // path -- partition tables, filesystems, customization -- is covered
        // by the single opt-in, whatever route it took to this image.
        if (self.device) |dev| {
            if (!dev.write_allowed) return error.BlockDeviceWriteNotPermitted;
        }
        if (self.vhdx) |*v| return vhdx.pwrite(self.file, io, v, buffer, offset);
        if (self.qcow2) |*q| return qcow2.pwrite(self.file, io, q, buffer, offset);
        if (self.dynamic) |*d| {
            var off = offset;
            var remaining = buffer.len;
            var src: usize = 0;
            while (remaining > 0) {
                const block_index: u32 = @intCast(off / d.block_size);
                const in_block_offset: u32 = @intCast(off % d.block_size);
                const chunk: usize = @min(remaining, d.block_size - in_block_offset);

                var bat_value = try readBatEntry(self.file, io, d.bat_offset, block_index);
                if (bat_value == unallocated_bat_entry) {
                    bat_value = try allocateBlock(self.file, io, d, block_index);
                }
                const block_data_offset = @as(u64, bat_value) * 512 + d.bitmap_size;
                try self.file.writePositionalAll(io, buffer[src..][0..chunk], block_data_offset + in_block_offset);

                src += chunk;
                off += chunk;
                remaining -= chunk;
            }
            return;
        }
        try self.file.writePositionalAll(io, buffer, self.data_offset + offset);
    }

    fn copyPolicy(self: Image) CopyPolicy {
        return if (self.device == null)
            .skip_zero_chunks
        else
            .write_zero_chunks;
    }

    pub fn close(self: *Image, io: Io) void {
        self.file.close(io);
        if (self.device) |*device| device.deinit();
        self.* = undefined;
    }

    pub const FlushDeviceWriteError = error{
        BlockDeviceWriteNotPermitted,
    } || Io.File.SyncError;
    pub const FinishDeviceWriteError = FlushDeviceWriteError;

    /// Makes all bytes written through a writable device-backed image durable
    /// without asking the kernel to re-read its partition table.
    ///
    /// Returns false for an ordinary file.
    pub fn flushDeviceWrite(
        self: *Image,
        io: Io,
    ) FlushDeviceWriteError!bool {
        return self.flushDeviceWriteWith(io, .{});
    }

    fn flushDeviceWriteWith(
        self: *Image,
        io: Io,
        operations: DeviceWriteOperations,
    ) FlushDeviceWriteError!bool {
        const device = self.device orelse return false;
        if (!device.write_allowed) return error.BlockDeviceWriteNotPermitted;

        try operations.sync_fn(operations.context, self.file, io);
        return true;
    }

    /// Makes all bytes written through a writable device-backed image durable,
    /// then asks the kernel to re-read the device's partition table. Refresh
    /// failure is a reportable partial-success outcome rather than a write
    /// failure because the flushed bytes on the device are already correct.
    ///
    /// Returns null for an ordinary file, preserving existing file-copy
    /// behavior. Call this again after any post-copy device mutations.
    pub fn finishDeviceWrite(
        self: *Image,
        io: Io,
    ) FinishDeviceWriteError!?DeviceWriteOutcome {
        return self.finishDeviceWriteWith(io, .{});
    }

    fn finishDeviceWriteWith(
        self: *Image,
        io: Io,
        operations: DeviceWriteOperations,
    ) FinishDeviceWriteError!?DeviceWriteOutcome {
        const device = self.device orelse return null;
        if (!device.write_allowed) return error.BlockDeviceWriteNotPermitted;

        _ = try self.flushDeviceWriteWith(io, operations);
        operations.re_read_partition_table_fn(operations.context, self.file) catch |err| {
            return switch (err) {
                error.BlockDeviceBusy => .partition_table_stale_busy,
                error.UnsupportedBlockDevice => .partition_table_stale_unsupported,
                error.PartitionTableRefreshFailed => .partition_table_stale_failed,
            };
        };
        return .partition_table_refreshed;
    }

    /// Safety and inventory data collected before the writable device handle
    /// was created. Callers should print this before beginning the copy.
    pub fn devicePreflight(self: *const Image) ?*const block_device.PreflightReport {
        const device = self.device orelse return null;
        if (device.preflight) |*report| return report;
        return null;
    }

    pub const ResizeError = error{
        ShrinkNotSupported,
        ExceedsAllocatedBatCapacity,
        /// A block device's size is fixed by the device itself; growing it
        /// is the job of whatever provides it (partitioning tool, LVM,
        /// hypervisor), not of an image writer.
        BlockDeviceResizeNotSupported,
    } || vhdx.ResizeError || qcow2.ResizeError || Io.File.SetLengthError || Io.File.WritePositionalError || Io.File.ReadPositionalError || Io.File.StatError;

    /// Changes the guest-visible virtual size. Growing is supported for all
    /// formats (raw: extend with zeros; fixed vhd: extend + move footer;
    /// dynamic vhd: only if the new size still fits within the already
    /// allocated BAT capacity, i.e. no BAT growth -- otherwise returns
    /// `error.ExceedsAllocatedBatCapacity`). Shrinking is not yet supported
    /// (`error.ShrinkNotSupported`) since it requires format-specific data
    /// loss handling that qemu-img itself guards behind `--shrink`. qcow2
    /// grows its L1/refcount metadata on demand; VHDX grows its BAT region
    /// and virtual-size metadata on demand. Device-backed images are
    /// rejected outright (`error.BlockDeviceResizeNotSupported`).
    pub fn resize(self: *Image, io: Io, new_size: u64) ResizeError!void {
        // Rejected before the no-op and shrink checks so that "resize a
        // device" always reports the real reason, even when the requested
        // size happens to match what the device already is.
        if (self.device != null) return error.BlockDeviceResizeNotSupported;
        if (new_size < self.virtual_size) return error.ShrinkNotSupported;
        if (new_size == self.virtual_size) return;

        if (self.vhdx) |*v| {
            try vhdx.resize(self.file, io, v, new_size);
            self.virtual_size = v.virtual_size;
            return;
        }

        if (self.qcow2) |*q| {
            try qcow2.resize(self.file, io, q, new_size);
            self.virtual_size = q.virtual_size;
            return;
        }

        switch (self.format) {
            .raw => {
                try self.file.setLength(io, new_size);
                self.virtual_size = new_size;
            },
            .vhd => {
                if (self.dynamic) |*d| {
                    const capacity = @as(u64, d.max_table_entries) * d.block_size;
                    if (new_size > capacity) return error.ExceedsAllocatedBatCapacity;
                    const footer = vhd.Footer.forDynamicDisk(new_size, vhd.footer_size, randomUuid(io), nowUnix(io));
                    d.footer_template = footer.encode();
                    try self.file.writePositionalAll(io, &d.footer_template, d.free_data_block_offset);
                    self.virtual_size = new_size;
                } else {
                    // Fixed: move the footer to the new end of the raw data
                    // region and rewrite it with the new size/geometry.
                    try self.file.setLength(io, new_size + vhd.footer_size);
                    const footer = vhd.Footer.forFixedDisk(new_size, randomUuid(io), nowUnix(io));
                    const encoded = footer.encode();
                    try self.file.writePositionalAll(io, &encoded, new_size);
                    self.virtual_size = new_size;
                }
            },
            .vhdx, .qcow2 => unreachable, // handled above
        }
    }

    pub const CheckError = vhdx.OpenError || qcow2.OpenError || qcow2.CheckError || Io.File.StatError;

    pub const CheckResult = struct {
        ok: bool,
        message: []const u8,
    };

    /// Validates format metadata: VHD footer/header checksums and BAT bounds,
    /// VHDX header/region/metadata parsing, and qcow2 header/L1/L2 mapping
    /// sanity for the active image state.
    pub fn check(self: Image, io: Io) CheckError!CheckResult {
        if (self.format == .raw) return .{ .ok = true, .message = "raw image: nothing to check" };

        if (self.format == .vhdx) {
            _ = vhdx.open(io, self.file) catch |err| return .{
                .ok = false,
                .message = @errorName(err),
            };
            return .{ .ok = true, .message = "vhdx header/region/metadata checks passed" };
        }

        if (self.qcow2) |q| {
            qcow2.check(self.file, io, q) catch |err| return .{
                .ok = false,
                .message = @errorName(err),
            };
            return .{ .ok = true, .message = "qcow2 header/L1/L2 checks passed" };
        }

        const file_size = if (self.device) |dev|
            dev.geometry.size_bytes
        else
            (try self.file.stat(io)).size;
        if (file_size < vhd.footer_size) return .{ .ok = false, .message = "file too small for a VHD footer" };

        var footer_buf: [vhd.footer_size]u8 = undefined;
        _ = try self.file.readPositionalAll(io, &footer_buf, file_size - vhd.footer_size);
        const footer = vhd.Footer.decode(&footer_buf) catch |err| return .{
            .ok = false,
            .message = switch (err) {
                error.BadCookie => "footer: bad cookie",
                error.BadChecksum => "footer: bad checksum",
            },
        };

        if (self.dynamic) |d| {
            var header_buf: [vhd.dynamic_header_size]u8 = undefined;
            _ = try self.file.readPositionalAll(io, &header_buf, footer.data_offset);
            const header_ok = if (vhd.DynamicHeader.decode(&header_buf)) |_| true else |_| false;
            if (!header_ok) return .{ .ok = false, .message = "dynamic header: bad cookie or checksum" };

            var index: u32 = 0;
            while (index < d.max_table_entries) : (index += 1) {
                const bat_value = try readBatEntry(self.file, io, d.bat_offset, index);
                if (bat_value == unallocated_bat_entry) continue;
                const block_end = @as(u64, bat_value) * 512 + d.bitmap_size + d.block_size;
                if (block_end > file_size) return .{ .ok = false, .message = "BAT entry points past end of file" };
            }
        }

        return .{ .ok = true, .message = "no errors found" };
    }

    pub const Extent = struct {
        /// Offset within the guest-visible virtual disk.
        offset: u64,
        length: u64,
        allocated: bool,
    };

    pub const MapError = Io.File.ReadPositionalError || qcow2.MapError || std.mem.Allocator.Error;

    /// Returns the list of allocated/unallocated extents covering the whole
    /// virtual disk (coalescing adjacent same-state blocks), analogous to
    /// `qemu-img map`. Caller owns the returned slice. `raw` and fixed `vhd`
    /// report a single, fully allocated extent (neither format has a sparse
    /// concept); dynamic `vhd`, `vhdx`, and `qcow2` walk their format-specific
    /// mapping tables.
    pub fn mapExtents(self: Image, io: Io, allocator: std.mem.Allocator) MapError![]Extent {
        if (self.dynamic) |d| {
            var extents = std.array_list.Managed(Extent).init(allocator);
            errdefer extents.deinit();

            var index: u32 = 0;
            while (index < d.max_table_entries) {
                const bat_value = try readBatEntry(self.file, io, d.bat_offset, index);
                const allocated = bat_value != unallocated_bat_entry;
                const block_start = @as(u64, index) * d.block_size;

                var run_end_index = index + 1;
                while (run_end_index < d.max_table_entries) : (run_end_index += 1) {
                    const next = try readBatEntry(self.file, io, d.bat_offset, run_end_index);
                    if ((next != unallocated_bat_entry) != allocated) break;
                }

                const run_end_offset = @min(@as(u64, run_end_index) * d.block_size, self.virtual_size);
                try extents.append(.{ .offset = block_start, .length = run_end_offset - block_start, .allocated = allocated });
                index = run_end_index;
            }
            return extents.toOwnedSlice();
        }

        if (self.vhdx) |v| {
            var extents = std.array_list.Managed(Extent).init(allocator);
            errdefer extents.deinit();

            const total_blocks = std.math.divCeil(u64, self.virtual_size, v.block_size) catch unreachable;

            var index: u64 = 0;
            while (index < total_blocks) {
                const allocated = try vhdxBlockAllocated(self.file, io, v, index);
                const block_start = index * v.block_size;

                var run_end_index = index + 1;
                while (run_end_index < total_blocks) : (run_end_index += 1) {
                    if (try vhdxBlockAllocated(self.file, io, v, run_end_index) != allocated) break;
                }

                const run_end_offset = @min(run_end_index * v.block_size, self.virtual_size);
                try extents.append(.{ .offset = block_start, .length = run_end_offset - block_start, .allocated = allocated });
                index = run_end_index;
            }
            return extents.toOwnedSlice();
        }

        if (self.qcow2) |q| {
            const src_extents = try qcow2.mapExtents(self.file, io, q, allocator);
            defer allocator.free(src_extents);

            const dst_extents = try allocator.alloc(Extent, src_extents.len);
            for (src_extents, 0..) |e, i| {
                dst_extents[i] = .{ .offset = e.offset, .length = e.length, .allocated = e.allocated };
            }
            return dst_extents;
        }

        const single = try allocator.alloc(Extent, 1);
        single[0] = .{ .offset = 0, .length = self.virtual_size, .allocated = true };
        return single;
    }
};

const unallocated_bat_entry: u32 = 0xFFFF_FFFF;

fn vhdxBlockAllocated(file: Io.File, io: Io, v: VhdxState, block_index: u64) Io.File.ReadPositionalError!bool {
    const bat_index = vhdx.batIndexForBlock(block_index, v.chunk_ratio);
    const entry = try readBatEntryU64(file, io, v.bat_offset, bat_index);
    const state: vhdx.BlockState = @enumFromInt(entry & vhdx.bat_state_mask);
    return state == .fully_present or state == .partially_present;
}

fn readBatEntryU64(file: Io.File, io: Io, bat_offset: u64, index: u64) Io.File.ReadPositionalError!u64 {
    var buf: [8]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, bat_offset + index * 8);
    return std.mem.readInt(u64, &buf, .little);
}

fn readBatEntry(file: Io.File, io: Io, bat_offset: u64, index: u32) Io.File.ReadPositionalError!u32 {
    var buf: [4]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, bat_offset + @as(u64, index) * 4);
    return std.mem.readInt(u32, &buf, .big);
}

fn writeBatEntry(file: Io.File, io: Io, bat_offset: u64, index: u32, value: u32) Io.File.WritePositionalError!void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try file.writePositionalAll(io, &buf, bat_offset + @as(u64, index) * 4);
}

fn fillBatUnallocated(file: Io.File, io: Io, bat_offset: u64, max_table_entries: u32) Io.File.WritePositionalError!void {
    const bat_bytes_len: u64 = @as(u64, max_table_entries) * 4;
    const chunk: [4096]u8 = [_]u8{0xFF} ** 4096;
    var written: u64 = 0;
    while (written < bat_bytes_len) {
        const n: usize = @intCast(@min(bat_bytes_len - written, chunk.len));
        try file.writePositionalAll(io, chunk[0..n], bat_offset + written);
        written += n;
    }
}

/// Scans the BAT once to determine the current end of allocated data,
/// mirroring QEMU's `vpc_open`: starts from just past the BAT itself, then
/// grows to cover every already-allocated block (bitmap + data).
fn computeFreeDataBlockOffset(
    file: Io.File,
    io: Io,
    bat_offset: u64,
    max_table_entries: u32,
    bitmap_size: u32,
    block_size: u32,
) Io.File.ReadPositionalError!u64 {
    var free_offset = alignUp(bat_offset + @as(u64, max_table_entries) * 4, 512);

    var buf: [4096]u8 = undefined; // 1024 BAT entries per chunk
    var index: u32 = 0;
    while (index < max_table_entries) {
        const entries_this_chunk = @min(max_table_entries - index, 1024);
        const bytes_len = entries_this_chunk * 4;
        _ = try file.readPositionalAll(io, buf[0..bytes_len], bat_offset + @as(u64, index) * 4);

        var i: u32 = 0;
        while (i < entries_this_chunk) : (i += 1) {
            const val = std.mem.readInt(u32, buf[i * 4 ..][0..4], .big);
            if (val != unallocated_bat_entry) {
                const candidate = @as(u64, val) * 512 + bitmap_size + block_size;
                if (candidate > free_offset) free_offset = candidate;
            }
        }
        index += entries_this_chunk;
    }
    return free_offset;
}

/// Allocates a fresh block for `block_index`: writes an all-1s sector
/// bitmap, advances `d.free_data_block_offset` past it, rewrites the footer
/// trailer at the new end of file, and records the BAT entry. Returns the
/// BAT entry value (sector number of the bitmap) to use for this write.
fn allocateBlock(file: Io.File, io: Io, d: *DynamicState, block_index: u32) (Io.File.WritePositionalError)!u32 {
    const bitmap_offset = d.free_data_block_offset;
    const bat_value: u32 = @intCast(bitmap_offset / 512);

    const bitmap_chunk: [512]u8 = [_]u8{0xFF} ** 512;
    var written: u64 = 0;
    while (written < d.bitmap_size) {
        const n: usize = @intCast(@min(@as(u64, d.bitmap_size) - written, bitmap_chunk.len));
        try file.writePositionalAll(io, bitmap_chunk[0..n], bitmap_offset + written);
        written += n;
    }

    d.free_data_block_offset += d.block_size + d.bitmap_size;
    try file.writePositionalAll(io, &d.footer_template, d.free_data_block_offset);
    try writeBatEntry(file, io, d.bat_offset, block_index, bat_value);

    return bat_value;
}

fn alignUp(v: u64, a: u64) u64 {
    return (v + a - 1) / a * a;
}

fn nowUnix(io: Io) i64 {
    return @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
}

fn randomUuid(io: Io) [16]u8 {
    var bytes: [16]u8 = undefined;
    Io.random(io, &bytes);
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 10
    return bytes;
}

const DeviceWriteOperations = struct {
    context: ?*anyopaque = null,
    sync_fn: *const fn (?*anyopaque, Io.File, Io) Io.File.SyncError!void = syncDevice,
    re_read_partition_table_fn: *const fn (
        ?*anyopaque,
        Io.File,
    ) block_device.ReReadPartitionTableError!void = reReadPartitionTable,

    fn syncDevice(_: ?*anyopaque, file: Io.File, io: Io) Io.File.SyncError!void {
        try file.sync(io);
    }

    fn reReadPartitionTable(
        _: ?*anyopaque,
        file: Io.File,
    ) block_device.ReReadPartitionTableError!void {
        try block_device.reReadPartitionTable(file);
    }
};

pub const CopyError = Image.PreadError || Image.PwriteError ||
    Image.FinishDeviceWriteError || std.mem.Allocator.Error ||
    error{ UnexpectedEndOfFile, DestinationTooSmall };

/// Copies all `src` virtual-disk bytes into `*dst` (which must already have
/// been created with at least `src`'s virtual size). Used by `vmiz convert`.
/// Takes `dst` by pointer since sparse destination formats mutate their
/// allocation state as writes land, and that updated state must remain
/// visible to the caller after this returns.
///
/// All-zero chunks are skipped for ordinary file destinations, so converting
/// into a sparse image stays sparse instead of eagerly allocating every block
/// it touches. Device destinations explicitly write those chunks because they
/// may contain stale data. For sparse destination formats, the chunk size is
/// aligned to the format's allocation unit so a mostly-zero chunk cannot force
/// adjacent blocks or clusters to be allocated just because one contains live
/// data. A device destination is flushed and its partition table is refreshed
/// before return; callers must inspect `CopyResult.device_write` so a stale
/// kernel partition view is reported as partial success rather than hidden.
pub fn copyAll(
    io: Io,
    src: Image,
    dst: *Image,
    allocator: std.mem.Allocator,
) CopyError!CopyResult {
    return copyAllWithDeviceWriteOperations(io, src, dst, allocator, .{});
}

/// Copies all bytes and applies the requested device finalization. Use
/// `.flush_device` when post-copy mutations must complete before the final
/// `Image.finishDeviceWrite` partition-table refresh.
pub fn copyAllWithFinalization(
    io: Io,
    src: Image,
    dst: *Image,
    allocator: std.mem.Allocator,
    finalization: CopyFinalization,
) CopyError!CopyResult {
    return copyAllWithFinalizationAndDeviceWriteOperations(
        io,
        src,
        dst,
        allocator,
        finalization,
        .{},
    );
}

fn copyAllWithDeviceWriteOperations(
    io: Io,
    src: Image,
    dst: *Image,
    allocator: std.mem.Allocator,
    operations: DeviceWriteOperations,
) CopyError!CopyResult {
    return copyAllWithFinalizationAndDeviceWriteOperations(
        io,
        src,
        dst,
        allocator,
        .finish_device_write,
        operations,
    );
}

fn copyAllWithFinalizationAndDeviceWriteOperations(
    io: Io,
    src: Image,
    dst: *Image,
    allocator: std.mem.Allocator,
    finalization: CopyFinalization,
    operations: DeviceWriteOperations,
) CopyError!CopyResult {
    if (dst.virtual_size < src.virtual_size) return error.DestinationTooSmall;
    const copy_policy = dst.copyPolicy();
    const chunk_size: usize = if (dst.dynamic) |d|
        d.block_size
    else if (dst.vhdx) |v|
        v.block_size
    else if (dst.qcow2) |q|
        @intCast(q.cluster_size)
    else
        4 * 1024 * 1024;
    const buf = try allocator.alloc(u8, chunk_size);
    defer allocator.free(buf);

    var offset: u64 = 0;
    while (offset < src.virtual_size) {
        const remaining = src.virtual_size - offset;
        const n: usize = @intCast(@min(remaining, chunk_size));
        const got = try src.pread(io, buf[0..n], offset);
        if (got != n) return error.UnexpectedEndOfFile;
        if (copy_policy == .write_zero_chunks or !isAllZero(buf[0..n])) {
            try dst.pwrite(io, buf[0..n], offset);
        }
        offset += n;
    }
    return switch (finalization) {
        .flush_device => blk: {
            break :blk .{
                .device_flushed = try dst.flushDeviceWriteWith(io, operations),
            };
        },
        .finish_device_write => blk: {
            const outcome = try dst.finishDeviceWriteWith(io, operations);
            break :blk .{
                .device_flushed = outcome != null,
                .device_write = outcome,
            };
        },
    };
}

/// Public because the streaming output path in `output.zig` needs exactly
/// the same "is this chunk worth writing" test that `copyAll` uses.
pub fn isAllZero(buf: []const u8) bool {
    for (buf) |b| {
        if (b != 0) return false;
    }
    return true;
}

test "create raw image, then open and read back zeros" {
    const io = std.testing.io;
    const path = "test-create-raw.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var img = try Image.create(io, path, .raw, 1024 * 1024, .{});
    img.close(io);

    var opened = try Image.openPath(io, path);
    defer opened.close(io);
    try std.testing.expectEqual(Format.raw, opened.format);
    try std.testing.expectEqual(@as(u64, 1024 * 1024), opened.virtual_size);

    var buf: [16]u8 = undefined;
    _ = try opened.pread(io, &buf, 0);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &buf);
}

test "invalid create options do not truncate an existing image" {
    const io = std.testing.io;
    const path = "test-image-invalid-create.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        const file = try Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, "preserve-me", 0);
    }

    try std.testing.expectError(
        error.HeaderSequenceOverflow,
        Image.create(io, path, .vhdx, 512, .{
            .vhdx = .{ .header_sequence_base = std.math.maxInt(u64) },
        }),
    );
    try std.testing.expectError(
        error.ImageTooLarge,
        Image.create(io, path, .vhd, std.math.maxInt(u64) / 512 * 512, .{
            .vhd_subformat = .fixed,
        }),
    );

    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var bytes: ["preserve-me".len]u8 = undefined;
    _ = try file.readPositionalAll(io, &bytes, 0);
    try std.testing.expectEqualStrings("preserve-me", &bytes);
}

test "exclusive creation removes a file when initialization fails" {
    const io = std.testing.io;
    const path = "test-image-failed-exclusive-create.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const result = Image.createExclusive(io, path, .vhd, @as(u64, 1) << 63, .{
        .vhd_subformat = .fixed,
    });
    if (result) |image_value| {
        var image = image_value;
        image.close(io);
        return error.TestUnexpectedResult;
    } else |_| {}

    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, path, .{}));
}

test "create fixed vhd image, then open and recover virtual size" {
    const io = std.testing.io;
    const path = "test-create-fixed.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const size: u64 = 8 * 1024 * 1024;
    var img = try Image.create(io, path, .vhd, size, .{ .vhd_subformat = .fixed });
    try img.pwrite(io, "hello", 0);
    img.close(io);

    var opened = try Image.openPath(io, path);
    defer opened.close(io);
    try std.testing.expectEqual(Format.vhd, opened.format);
    try std.testing.expectEqual(size, opened.virtual_size);

    var buf: [5]u8 = undefined;
    _ = try opened.pread(io, &buf, 0);
    try std.testing.expectEqualSlices(u8, "hello", &buf);

    // The footer must not be readable/writable as guest data.
    try std.testing.expectEqual(size + vhd.footer_size, (try opened.info(io)).file_size);
}

test "convert raw to fixed vhd round-trips data" {
    const io = std.testing.io;
    const src_path = "test-convert-src.img";
    const dst_path = "test-convert-dst.vhd";
    defer Io.Dir.cwd().deleteFile(io, src_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, dst_path) catch {};

    const size: u64 = 2 * 1024 * 1024;
    var src = try Image.create(io, src_path, .raw, size, .{});
    try src.pwrite(io, "some payload bytes", 4096);

    var dst = try Image.create(io, dst_path, .vhd, size, .{ .vhd_subformat = .fixed });
    _ = try copyAll(io, src, &dst, std.testing.allocator);
    src.close(io);
    dst.close(io);

    var reopened = try Image.openPath(io, dst_path);
    defer reopened.close(io);
    var buf: [18]u8 = undefined;
    _ = try reopened.pread(io, &buf, 4096);
    try std.testing.expectEqualSlices(u8, "some payload bytes", &buf);
}

test "convert raw to dynamic vhd keeps full and final partial zero regions sparse" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const src_path = try std.fs.path.join(allocator, &.{ root_buf[0..root_len], "source.img" });
    defer allocator.free(src_path);
    const dst_path = try std.fs.path.join(allocator, &.{ root_buf[0..root_len], "destination.vhd" });
    defer allocator.free(dst_path);

    // The first block and final partial block are zero; only block 1 has data.
    const size: u64 = 2 * @as(u64, vhd.default_block_size) + 512;
    var src = try Image.create(io, src_path, .raw, size, .{});
    try src.pwrite(io, "only-block-1", vhd.default_block_size + 123);

    var dst = try Image.create(io, dst_path, .vhd, size, .{ .vhd_subformat = .dynamic });
    _ = try copyAll(io, src, &dst, allocator);
    src.close(io);

    const extents = try dst.mapExtents(io, allocator);
    defer allocator.free(extents);
    dst.close(io);

    // Only the block actually touched should be allocated; both the full
    // leading block and the partial final block stay sparse.
    try std.testing.expectEqual(@as(usize, 3), extents.len);
    try std.testing.expectEqual(false, extents[0].allocated);
    try std.testing.expectEqual(true, extents[1].allocated);
    try std.testing.expectEqual(@as(u64, vhd.default_block_size), extents[1].offset);
    try std.testing.expectEqual(@as(u64, vhd.default_block_size), extents[1].length);
    try std.testing.expectEqual(false, extents[2].allocated);
    try std.testing.expectEqual(@as(u64, 512), extents[2].length);
}

test "convert raw to qcow2 allocates only non-zero clusters" {
    const io = std.testing.io;
    const src_path = "test-convert-sparse-qcow2-src.img";
    const dst_path = "test-convert-sparse-dst.qcow2";
    defer Io.Dir.cwd().deleteFile(io, src_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, dst_path) catch {};

    const cluster_size: u64 = 1 << qcow2.default_cluster_bits;
    const size = 4 * cluster_size;
    var src = try Image.create(io, src_path, .raw, size, .{});
    try src.pwrite(io, "only-cluster-1", cluster_size + 123);

    var dst = try Image.create(io, dst_path, .qcow2, size, .{});
    _ = try copyAll(io, src, &dst, std.testing.allocator);
    src.close(io);

    const extents = try dst.mapExtents(io, std.testing.allocator);
    defer std.testing.allocator.free(extents);
    dst.close(io);

    try std.testing.expectEqual(@as(usize, 3), extents.len);
    try std.testing.expectEqual(false, extents[0].allocated);
    try std.testing.expectEqual(true, extents[1].allocated);
    try std.testing.expectEqual(cluster_size, extents[1].offset);
    try std.testing.expectEqual(cluster_size, extents[1].length);
    try std.testing.expectEqual(false, extents[2].allocated);
}

test "create dynamic vhd, write across blocks, reopen and read back" {
    const io = std.testing.io;
    const path = "test-create-dynamic.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // 3 blocks' worth so we exercise multiple BAT entries.
    const size: u64 = 3 * @as(u64, vhd.default_block_size);
    var img = try Image.create(io, path, .vhd, size, .{ .vhd_subformat = .dynamic });
    try std.testing.expect(img.dynamic != null);

    // Write into the 2nd block only -- the 1st and 3rd should stay unallocated.
    const payload = "dynamic-vhd-payload";
    try img.pwrite(io, payload, vhd.default_block_size + 4096);
    img.close(io);

    var opened = try Image.openPath(io, path);
    defer opened.close(io);
    try std.testing.expectEqual(Format.vhd, opened.format);
    try std.testing.expectEqual(size, opened.virtual_size);
    try std.testing.expect(opened.dynamic != null);

    var buf: [payload.len]u8 = undefined;
    _ = try opened.pread(io, &buf, vhd.default_block_size + 4096);
    try std.testing.expectEqualSlices(u8, payload, &buf);

    // Reading from an untouched region returns zeros (sparse).
    var zero_buf: [64]u8 = undefined;
    _ = try opened.pread(io, &zero_buf, 0);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &zero_buf);

    // The file on disk should be much smaller than the virtual size, since
    // only one block was ever allocated.
    const stat = try opened.info(io);
    try std.testing.expect(stat.file_size < size);
}

test "dynamic vhd map reports sparse extents" {
    const io = std.testing.io;
    const path = "test-map-dynamic.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const size: u64 = 3 * @as(u64, vhd.default_block_size);
    var img = try Image.create(io, path, .vhd, size, .{ .vhd_subformat = .dynamic });
    try img.pwrite(io, "x", vhd.default_block_size);

    const extents = try img.mapExtents(io, std.testing.allocator);
    defer std.testing.allocator.free(extents);
    img.close(io);

    try std.testing.expectEqual(@as(usize, 3), extents.len);
    try std.testing.expectEqual(false, extents[0].allocated);
    try std.testing.expectEqual(true, extents[1].allocated);
    try std.testing.expectEqual(false, extents[2].allocated);
    try std.testing.expectEqual(@as(u64, vhd.default_block_size), extents[1].offset);
}

test "raw and fixed vhd map report a single allocated extent" {
    const io = std.testing.io;
    const raw_path = "test-map-raw.img";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};

    var img = try Image.create(io, raw_path, .raw, 4096, .{});
    const extents = try img.mapExtents(io, std.testing.allocator);
    defer std.testing.allocator.free(extents);
    img.close(io);

    try std.testing.expectEqual(@as(usize, 1), extents.len);
    try std.testing.expectEqual(true, extents[0].allocated);
    try std.testing.expectEqual(@as(u64, 4096), extents[0].length);
}

test "check reports ok for freshly created images" {
    const io = std.testing.io;

    {
        const path = "test-check-fixed.vhd";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};
        var img = try Image.create(io, path, .vhd, 1024 * 1024, .{ .vhd_subformat = .fixed });
        defer img.close(io);
        const result = try img.check(io);
        try std.testing.expect(result.ok);
    }
    {
        const path = "test-check-dynamic.vhd";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};
        var img = try Image.create(io, path, .vhd, 4 * 1024 * 1024, .{ .vhd_subformat = .dynamic });
        try img.pwrite(io, "abc", 0);
        defer img.close(io);
        const result = try img.check(io);
        try std.testing.expect(result.ok);
    }
}

test "check detects a corrupted footer" {
    const io = std.testing.io;
    const path = "test-check-corrupt.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var img = try Image.create(io, path, .vhd, 1024 * 1024, .{ .vhd_subformat = .fixed });
    defer img.close(io);

    // Corrupt a reserved footer byte in place.
    var one: [1]u8 = .{0xFF};
    try img.file.writePositionalAll(io, &one, img.virtual_size + 100);

    const result = try img.check(io);
    try std.testing.expect(!result.ok);
}

test "resize grows raw and fixed vhd images" {
    const io = std.testing.io;
    {
        const path = "test-resize-raw.img";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};
        var img = try Image.create(io, path, .raw, 1024, .{});
        defer img.close(io);
        try img.resize(io, 4096);
        try std.testing.expectEqual(@as(u64, 4096), img.virtual_size);
        try std.testing.expectEqual(@as(u64, 4096), (try img.info(io)).file_size);
    }
    {
        const path = "test-resize-fixed.vhd";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};
        var img = try Image.create(io, path, .vhd, 1024 * 1024, .{ .vhd_subformat = .fixed });
        defer img.close(io);
        try img.resize(io, 2 * 1024 * 1024);
        try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024), img.virtual_size);

        var reopened = try Image.openPath(io, path);
        defer reopened.close(io);
        try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024), reopened.virtual_size);
    }
}

test "resize rejects shrinking" {
    const io = std.testing.io;
    const path = "test-resize-shrink.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    var img = try Image.create(io, path, .raw, 4096, .{});
    defer img.close(io);
    try std.testing.expectError(error.ShrinkNotSupported, img.resize(io, 1024));
}

// ---- qcow2 end-to-end integration test ----
//
// This exercises the full writable qcow2 path through `Image.create`,
// `pwrite`, `resize`, direct `qcow2.open`/`pread`, and `Image.openPath`.
test "Image creates, writes, resizes, and reopens qcow2 images" {
    const io = std.testing.io;
    const path = "test-qcow2-roundtrip.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const cluster_size: u64 = 1 << qcow2.default_cluster_bits;
    const initial_size: u64 = 256 * 1024 * 1024;
    const grown_size: u64 = 1024 * 1024 * 1024;
    const sparse_offset: u64 = 3 * cluster_size + 41;
    const cross_boundary_offset: u64 = 512 * 1024 * 1024 - 96;
    const distant_offset: u64 = 768 * 1024 * 1024 + 123;
    const payload0 = "image-qcow2-0";
    const payload1 = "image-qcow2-1";
    const payload2 = [_]u8{0xA5} ** 256;

    var img = try Image.create(io, path, .qcow2, initial_size, .{});
    try img.pwrite(io, payload0, sparse_offset);
    try img.resize(io, grown_size);
    try img.pwrite(io, &payload2, cross_boundary_offset);
    try img.pwrite(io, payload1, distant_offset);
    try std.testing.expect((try img.info(io)).file_size < grown_size);
    img.close(io);

    const direct_file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer direct_file.close(io);
    const direct_info = try qcow2.open(io, direct_file);
    try std.testing.expect(direct_info.l1_size > 1);

    var direct0: [payload0.len]u8 = undefined;
    _ = try qcow2.pread(direct_file, io, direct_info, &direct0, sparse_offset);
    try std.testing.expectEqualSlices(u8, payload0, &direct0);

    var direct1: [payload1.len]u8 = undefined;
    _ = try qcow2.pread(direct_file, io, direct_info, &direct1, distant_offset);
    try std.testing.expectEqualSlices(u8, payload1, &direct1);

    var direct2: [payload2.len]u8 = undefined;
    _ = try qcow2.pread(direct_file, io, direct_info, &direct2, cross_boundary_offset);
    try std.testing.expectEqualSlices(u8, &payload2, &direct2);

    var opened = try Image.openPath(io, path);
    defer opened.close(io);
    try std.testing.expectEqual(Format.qcow2, opened.format);
    try std.testing.expectEqual(grown_size, opened.virtual_size);

    var buf0: [payload0.len]u8 = undefined;
    _ = try opened.pread(io, &buf0, sparse_offset);
    try std.testing.expectEqualSlices(u8, payload0, &buf0);

    var buf1: [payload1.len]u8 = undefined;
    _ = try opened.pread(io, &buf1, distant_offset);
    try std.testing.expectEqualSlices(u8, payload1, &buf1);

    var buf2: [payload2.len]u8 = undefined;
    _ = try opened.pread(io, &buf2, cross_boundary_offset);
    try std.testing.expectEqualSlices(u8, &payload2, &buf2);

    const result = try opened.check(io);
    try std.testing.expect(result.ok);

    const extents = try opened.mapExtents(io, std.testing.allocator);
    defer std.testing.allocator.free(extents);
    try std.testing.expect(extents.len >= 5);
}

// ---- VHDX end-to-end integration test ----
//
// This exercises the full writable VHDX path through `Image.create`,
// `pwrite`, `resize`, direct `vhdx.open`/`pread`, and `Image.openPath`.
test "Image creates, writes, resizes, and reopens VHDX images" {
    const io = std.testing.io;
    const path = "test-vhdx-roundtrip.vhdx";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const gib: u64 = 1024 * 1024 * 1024;
    const initial_size: u64 = 120 * gib;
    const grown_size: u64 = 132 * gib;
    const block_size = vhdx.default_block_size;
    const sparse_offset: u64 = 3 * @as(u64, block_size) + 41;
    const cross_boundary_offset: u64 = 4 * @as(u64, block_size) - 96;
    const distant_offset: u64 = 130 * gib + 123;
    const payload0 = "image-vhdx-0";
    const payload1 = "image-vhdx-1";
    const payload2 = [_]u8{0xC7} ** 256;

    var img = try Image.create(io, path, .vhdx, initial_size, .{});
    const initial_bat_length = img.vhdx.?.bat_length;
    try img.pwrite(io, payload0, sparse_offset);
    try img.pwrite(io, &payload2, cross_boundary_offset);
    try img.resize(io, grown_size);
    try std.testing.expect(img.vhdx.?.bat_length > initial_bat_length);
    try img.pwrite(io, payload1, distant_offset);
    try std.testing.expect((try img.info(io)).file_size < grown_size);
    img.close(io);

    const direct_file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer direct_file.close(io);
    const direct_info = try vhdx.open(io, direct_file);
    try std.testing.expectEqual(grown_size, direct_info.virtual_size);

    var direct0: [payload0.len]u8 = undefined;
    _ = try vhdx.pread(direct_file, io, direct_info, &direct0, sparse_offset);
    try std.testing.expectEqualSlices(u8, payload0, &direct0);

    var direct1: [payload1.len]u8 = undefined;
    _ = try vhdx.pread(direct_file, io, direct_info, &direct1, distant_offset);
    try std.testing.expectEqualSlices(u8, payload1, &direct1);

    var direct2: [payload2.len]u8 = undefined;
    _ = try vhdx.pread(direct_file, io, direct_info, &direct2, cross_boundary_offset);
    try std.testing.expectEqualSlices(u8, &payload2, &direct2);

    var opened = try Image.openPath(io, path);
    defer opened.close(io);
    try std.testing.expectEqual(Format.vhdx, opened.format);
    try std.testing.expectEqual(grown_size, opened.virtual_size);

    var buf0: [payload0.len]u8 = undefined;
    _ = try opened.pread(io, &buf0, sparse_offset);
    try std.testing.expectEqualSlices(u8, payload0, &buf0);

    var buf1: [payload1.len]u8 = undefined;
    _ = try opened.pread(io, &buf1, distant_offset);
    try std.testing.expectEqualSlices(u8, payload1, &buf1);

    var buf2: [payload2.len]u8 = undefined;
    _ = try opened.pread(io, &buf2, cross_boundary_offset);
    try std.testing.expectEqualSlices(u8, &payload2, &buf2);

    var zero_buf: [64]u8 = undefined;
    _ = try opened.pread(io, &zero_buf, @as(u64, block_size));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &zero_buf);

    const result = try opened.check(io);
    try std.testing.expect(result.ok);

    const extents = try opened.mapExtents(io, std.testing.allocator);
    defer std.testing.allocator.free(extents);
    try std.testing.expectEqual(@as(usize, 5), extents.len);
    try std.testing.expectEqual(false, extents[0].allocated);
    try std.testing.expectEqual(true, extents[1].allocated);
    try std.testing.expectEqual(false, extents[2].allocated);
    try std.testing.expectEqual(true, extents[3].allocated);
    try std.testing.expectEqual(false, extents[4].allocated);
}

// ---- block-device-backed images ----
//
// A real device node can't be assumed on any test runner, so these stub out
// the one part that genuinely needs one -- the `BLKGETSIZE64`/`BLKSSZGET`
// probe -- and run everything downstream of it (size resolution, sniffing
// bounds, write enforcement) through exactly the same code the `/dev/...`
// open path uses.

fn openAsSyntheticDevice(
    io: Io,
    file: Io.File,
    geometry: block_device.Geometry,
    write_allowed: bool,
) OpenError!Image {
    return Image.openFileFromSource(io, file, null, false, .{ .device = .{
        .geometry = geometry,
        .write_allowed = write_allowed,
    } });
}

fn openSyntheticDeviceForWrite(
    file: Io.File,
    geometry: block_device.Geometry,
    source_virtual_size: u64,
    options: DeviceWriteOptions,
) OpenDeviceForWriteError!Image {
    return Image.deviceWriteImage(file, geometry, source_virtual_size, options);
}

const TestDeviceWriteOperations = struct {
    sync_attempts: usize = 0,
    refresh_attempts: usize = 0,
    sequence: usize = 0,
    expected_sync_sequence: usize = 0,
    order_valid: bool = true,
    refresh_allowed: bool = true,
    sync_failure: ?Io.File.SyncError = null,
    refresh_failure: ?block_device.ReReadPartitionTableError = null,

    fn sync(context: ?*anyopaque, _: Io.File, _: Io) Io.File.SyncError!void {
        const self: *TestDeviceWriteOperations = @ptrCast(@alignCast(context.?));
        self.sync_attempts += 1;
        self.order_valid = self.order_valid and self.sequence == self.expected_sync_sequence;
        self.sequence += 1;
        if (self.sync_failure) |err| return err;
    }

    fn refresh(
        context: ?*anyopaque,
        _: Io.File,
    ) block_device.ReReadPartitionTableError!void {
        const self: *TestDeviceWriteOperations = @ptrCast(@alignCast(context.?));
        self.refresh_attempts += 1;
        self.order_valid = self.order_valid and
            self.refresh_allowed and
            self.sequence == self.expected_sync_sequence + 1;
        self.sequence += 1;
        if (self.refresh_failure) |err| return err;
    }

    fn operations(self: *TestDeviceWriteOperations) DeviceWriteOperations {
        return .{
            .context = self,
            .sync_fn = sync,
            .re_read_partition_table_fn = refresh,
        };
    }
};

test "copyAll flushes a device before refreshing its partition table" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source_file = try tmp.dir.createFile(io, "source.img", .{ .truncate = true, .read = true });
    try source_file.setLength(io, 4096);
    var source = try Image.openFile(io, source_file);
    defer source.close(io);
    try source.pwrite(io, "durable payload", 512);

    const destination_file = try tmp.dir.createFile(io, "destination.img", .{ .truncate = true, .read = true });
    try destination_file.setLength(io, 4096);
    var destination = try openSyntheticDeviceForWrite(destination_file, .{
        .size_bytes = 4096,
        .logical_sector_size = 512,
    }, 4096, .{ .allow_device_write = true });
    defer destination.close(io);

    var operations = TestDeviceWriteOperations{};
    const result = try copyAllWithDeviceWriteOperations(
        io,
        source,
        &destination,
        allocator,
        operations.operations(),
    );

    try std.testing.expectEqual(
        DeviceWriteOutcome.partition_table_refreshed,
        result.device_write.?,
    );
    try std.testing.expect(result.device_flushed);
    try std.testing.expectEqual(@as(usize, 1), operations.sync_attempts);
    try std.testing.expectEqual(@as(usize, 1), operations.refresh_attempts);
    try std.testing.expectEqual(@as(usize, 2), operations.sequence);
    try std.testing.expect(operations.order_valid);
    try std.testing.expect(std.mem.indexOf(
        u8,
        result.device_write.?.message(),
        "may still be settling",
    ) != null);
}

test "copy finalization can defer partition refresh until after mutations" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source_file = try tmp.dir.createFile(io, "source.img", .{ .truncate = true, .read = true });
    try source_file.setLength(io, 512);
    var source = try Image.openFile(io, source_file);
    defer source.close(io);
    try source.pwrite(io, "payload", 0);

    const destination_file = try tmp.dir.createFile(io, "destination.img", .{ .truncate = true, .read = true });
    try destination_file.setLength(io, 512);
    var destination = try openSyntheticDeviceForWrite(destination_file, .{
        .size_bytes = 512,
        .logical_sector_size = 512,
    }, 512, .{ .allow_device_write = true });
    defer destination.close(io);

    var operations = TestDeviceWriteOperations{ .refresh_allowed = false };
    const copy_result = try copyAllWithFinalizationAndDeviceWriteOperations(
        io,
        source,
        &destination,
        std.testing.allocator,
        .flush_device,
        operations.operations(),
    );
    try std.testing.expect(copy_result.device_flushed);
    try std.testing.expectEqual(@as(?DeviceWriteOutcome, null), copy_result.device_write);
    try std.testing.expectEqual(@as(usize, 1), operations.sync_attempts);
    try std.testing.expectEqual(@as(usize, 0), operations.refresh_attempts);

    try destination.pwrite(io, "post-copy mutation", 128);
    operations.refresh_allowed = true;
    operations.expected_sync_sequence = 1;
    try std.testing.expectEqual(
        DeviceWriteOutcome.partition_table_refreshed,
        (try destination.finishDeviceWriteWith(io, operations.operations())).?,
    );
    try std.testing.expectEqual(@as(usize, 2), operations.sync_attempts);
    try std.testing.expectEqual(@as(usize, 1), operations.refresh_attempts);
    try std.testing.expectEqual(@as(usize, 3), operations.sequence);
    try std.testing.expect(operations.order_valid);
}

test "copyAll propagates a device flush failure without attempting refresh" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source_file = try tmp.dir.createFile(io, "source.img", .{ .truncate = true, .read = true });
    try source_file.setLength(io, 512);
    var source = try Image.openFile(io, source_file);
    defer source.close(io);

    const destination_file = try tmp.dir.createFile(io, "destination.img", .{ .truncate = true, .read = true });
    try destination_file.setLength(io, 512);
    var destination = try openSyntheticDeviceForWrite(destination_file, .{
        .size_bytes = 512,
        .logical_sector_size = 512,
    }, 512, .{ .allow_device_write = true });
    defer destination.close(io);

    var operations = TestDeviceWriteOperations{ .sync_failure = error.NoSpaceLeft };
    try std.testing.expectError(
        error.NoSpaceLeft,
        copyAllWithDeviceWriteOperations(
            io,
            source,
            &destination,
            allocator,
            operations.operations(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), operations.sync_attempts);
    try std.testing.expectEqual(@as(usize, 0), operations.refresh_attempts);
}

test "device finish reports stale partition outcomes without losing durable success" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile(io, "destination.img", .{ .truncate = true, .read = true });
    try file.setLength(io, 512);
    var destination = try openSyntheticDeviceForWrite(file, .{
        .size_bytes = 512,
        .logical_sector_size = 512,
    }, 512, .{ .allow_device_write = true });
    defer destination.close(io);

    var busy = TestDeviceWriteOperations{ .refresh_failure = error.BlockDeviceBusy };
    try std.testing.expectEqual(
        DeviceWriteOutcome.partition_table_stale_busy,
        (try destination.finishDeviceWriteWith(io, busy.operations())).?,
    );
    try std.testing.expectEqual(@as(usize, 1), busy.sync_attempts);
    try std.testing.expectEqual(@as(usize, 1), busy.refresh_attempts);
    try std.testing.expect(std.mem.indexOf(
        u8,
        DeviceWriteOutcome.partition_table_stale_busy.warning().?,
        "data on the device is correct and durable",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        DeviceWriteOutcome.partition_table_stale_busy.warning().?,
        "detach and reattach",
    ) != null);

    var failed = TestDeviceWriteOperations{ .refresh_failure = error.PartitionTableRefreshFailed };
    try std.testing.expectEqual(
        DeviceWriteOutcome.partition_table_stale_failed,
        (try destination.finishDeviceWriteWith(io, failed.operations())).?,
    );
    try std.testing.expectEqual(@as(usize, 1), failed.sync_attempts);
    try std.testing.expectEqual(@as(usize, 1), failed.refresh_attempts);
}

test "copyAll preserves ordinary file behavior without device finalization" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const source_file = try tmp.dir.createFile(io, "source.img", .{ .truncate = true, .read = true });
    try source_file.setLength(io, 512);
    var source = try Image.openFile(io, source_file);
    defer source.close(io);
    try source.pwrite(io, "ordinary file", 0);

    const destination_file = try tmp.dir.createFile(io, "destination.img", .{ .truncate = true, .read = true });
    try destination_file.setLength(io, 512);
    var destination = try Image.openFile(io, destination_file);
    defer destination.close(io);

    var operations = TestDeviceWriteOperations{
        .sync_failure = error.NoSpaceLeft,
        .refresh_failure = error.PartitionTableRefreshFailed,
    };
    const result = try copyAllWithDeviceWriteOperations(
        io,
        source,
        &destination,
        std.testing.allocator,
        operations.operations(),
    );
    try std.testing.expectEqual(@as(?DeviceWriteOutcome, null), result.device_write);
    try std.testing.expect(!result.device_flushed);
    try std.testing.expectEqual(@as(usize, 0), operations.sync_attempts);
    try std.testing.expectEqual(@as(usize, 0), operations.refresh_attempts);

    var payload: ["ordinary file".len]u8 = undefined;
    _ = try destination.pread(io, &payload, 0);
    try std.testing.expectEqualStrings("ordinary file", &payload);
}

test "copyAll overwrites full and final partial zero chunks on a used device" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const src_path = try std.fs.path.join(allocator, &.{ root_buf[0..root_len], "source.img" });
    defer allocator.free(src_path);
    const dst_path = try std.fs.path.join(allocator, &.{ root_buf[0..root_len], "destination.img" });
    defer allocator.free(dst_path);

    const raw_chunk_size: u64 = 4 * 1024 * 1024;
    const source_size: u64 = 2 * raw_chunk_size + 512;
    const device_size: u64 = source_size + 4096;
    const payload = "nonzero middle chunk";

    var src = try Image.create(io, src_path, .raw, source_size, .{});
    defer src.close(io);
    try src.pwrite(io, payload, raw_chunk_size + 1024);

    {
        var backing = try Image.create(io, dst_path, .raw, device_size, .{});
        defer backing.close(io);
        const pattern = [_]u8{0xa5} ** (64 * 1024);
        var offset: u64 = 0;
        while (offset < device_size) {
            const n: usize = @intCast(@min(device_size - offset, pattern.len));
            try backing.pwrite(io, pattern[0..n], offset);
            offset += n;
        }
    }

    const file = try Io.Dir.cwd().openFile(io, dst_path, .{ .mode = .read_write });
    var dst = try openSyntheticDeviceForWrite(file, .{
        .size_bytes = device_size,
        .logical_sector_size = 512,
    }, source_size, .{ .allow_device_write = true });
    defer dst.close(io);

    _ = try copyAll(io, src, &dst, allocator);

    var leading: [64]u8 = undefined;
    _ = try dst.pread(io, &leading, 0);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** leading.len), &leading);

    var copied_payload: [payload.len]u8 = undefined;
    _ = try dst.pread(io, &copied_payload, raw_chunk_size + 1024);
    try std.testing.expectEqualSlices(u8, payload, &copied_payload);

    var final_partial: [512]u8 = undefined;
    _ = try dst.pread(io, &final_partial, 2 * raw_chunk_size);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** final_partial.len), &final_partial);

    var past_source: [64]u8 = undefined;
    _ = try dst.pread(io, &past_source, source_size);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** past_source.len), &past_source);
}

test "a device-backed image takes its size from the kernel probe, not from stat" {
    const io = std.testing.io;
    const path = "test-device-size.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Deliberately larger on disk than the "device" reports: the probed size
    // has to win, the way it does for a device node whose `stat` size is 0.
    const device_size: u64 = 512 * 1024;
    {
        var img = try Image.create(io, path, .raw, 1024 * 1024, .{});
        img.close(io);
    }

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    var img = try openAsSyntheticDevice(io, file, .{
        .size_bytes = device_size,
        .logical_sector_size = 512,
    }, false);
    defer img.close(io);

    try std.testing.expectEqual(Format.raw, img.format);
    try std.testing.expectEqual(device_size, img.virtual_size);
    try std.testing.expectEqual(@as(u32, 512), img.device.?.geometry.logical_sector_size);

    // `stat` would report 0 for a real device node, so `info` must fall back
    // to the probed size for the occupied size too.
    const stat = try img.info(io);
    try std.testing.expectEqual(device_size, stat.file_size);
    try std.testing.expectEqual(device_size, stat.virtual_size);

    const extents = try img.mapExtents(io, std.testing.allocator);
    defer std.testing.allocator.free(extents);
    try std.testing.expectEqual(@as(usize, 1), extents.len);
    try std.testing.expectEqual(device_size, extents[0].length);
}

test "format sniffing still runs on a device, bounded by the reported size" {
    const io = std.testing.io;
    const path = "test-device-vhd-probe.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size: u64 = 512 * 1024;
    {
        var img = try Image.create(io, path, .vhd, disk_size, .{ .vhd_subformat = .fixed });
        img.close(io);
    }

    {
        // The whole fixed VHD, footer included, is inside the device: sniff
        // it exactly as a file-backed image would be sniffed.
        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        var img = try openAsSyntheticDevice(io, file, .{
            .size_bytes = disk_size + vhd.footer_size,
            .logical_sector_size = 512,
        }, false);
        defer img.close(io);
        try std.testing.expectEqual(Format.vhd, img.format);
        try std.testing.expectEqual(disk_size, img.virtual_size);
    }

    {
        // The same bytes behind a device that reports a smaller size: the
        // footer now sits past the device's end, so the probe must not see
        // it and must not claim a virtual size the device cannot back.
        const short_size: u64 = 64 * 1024;
        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        var img = try openAsSyntheticDevice(io, file, .{
            .size_bytes = short_size,
            .logical_sector_size = 512,
        }, false);
        defer img.close(io);
        try std.testing.expectEqual(Format.raw, img.format);
        try std.testing.expectEqual(short_size, img.virtual_size);
    }
}

test "a device opened without the write opt-in refuses every write" {
    const io = std.testing.io;
    const path = "test-device-readonly.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const device_size: u64 = 64 * 1024;
    {
        var img = try Image.create(io, path, .raw, device_size, .{});
        img.close(io);
    }

    {
        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
        var img = try openAsSyntheticDevice(io, file, .{
            .size_bytes = device_size,
            .logical_sector_size = 512,
        }, false);
        defer img.close(io);

        // The handle itself is writable here, proving the refusal comes from
        // the missing opt-in and not merely from the open mode.
        try std.testing.expectError(
            error.BlockDeviceWriteNotPermitted,
            img.pwrite(io, "installed system", 0),
        );
    }

    {
        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        var img = try openAsSyntheticDevice(io, file, .{
            .size_bytes = device_size,
            .logical_sector_size = 512,
        }, false);
        defer img.close(io);

        var buf: [16]u8 = undefined;
        _ = try img.pread(io, &buf, 0);
        try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 16), &buf);
    }
}

test "a device opened with the write opt-in writes through" {
    const io = std.testing.io;
    const path = "test-device-writable.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const device_size: u64 = 64 * 1024;
    {
        var img = try Image.create(io, path, .raw, device_size, .{});
        img.close(io);
    }

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    var img = try openAsSyntheticDevice(io, file, .{
        .size_bytes = device_size,
        .logical_sector_size = 512,
    }, true);
    defer img.close(io);

    try img.pwrite(io, "installed system", 1024);
    var buf: [16]u8 = undefined;
    _ = try img.pread(io, &buf, 1024);
    try std.testing.expectEqualSlices(u8, "installed system", &buf);
}

test "openDeviceForWrite requires explicit device-write opt-in" {
    const io = std.testing.io;
    const path = "test-device-destination-opt-in.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    {
        var backing = try Image.create(io, path, .raw, 64 * 1024, .{});
        backing.close(io);
    }

    try std.testing.expectError(
        error.BlockDeviceWriteNotPermitted,
        Image.openDeviceForWrite(io, path, 4096, .{}),
    );
}

test "openDeviceForWrite rejects a regular file" {
    const io = std.testing.io;
    const path = "test-device-destination-regular.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    {
        const file = try Io.Dir.cwd().createFile(io, path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, "ordinary file", 0);
    }

    try std.testing.expectError(
        error.NotBlockDevice,
        Image.openDeviceForWrite(io, path, 4096, .{ .allow_device_write = true }),
    );

    var bytes: [13]u8 = undefined;
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    _ = try file.readPositionalAll(io, &bytes, 0);
    try std.testing.expectEqualSlices(u8, "ordinary file", &bytes);
}

test "openDeviceForWrite is raw and sized from kernel geometry" {
    const io = std.testing.io;
    const path = "test-device-destination-geometry.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const device_size: u64 = 2 * 1024 * 1024;
    {
        // Device destinations are raw even when their current bytes happen to
        // contain a recognizable container footer.
        var backing = try Image.create(io, path, .vhd, device_size, .{ .vhd_subformat = .fixed });
        backing.close(io);
    }

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    var img = try openSyntheticDeviceForWrite(file, .{
        .size_bytes = device_size,
        .logical_sector_size = 4096,
    }, 1024 * 1024, .{ .allow_device_write = true });
    defer img.close(io);

    try std.testing.expectEqual(Format.raw, img.format);
    try std.testing.expectEqual(@as(u64, 0), img.data_offset);
    try std.testing.expectEqual(device_size, img.virtual_size);
    try std.testing.expectEqual(device_size, img.device.?.geometry.size_bytes);
    try std.testing.expectEqual(@as(u32, 4096), img.device.?.geometry.logical_sector_size);
    try std.testing.expect(img.device.?.write_allowed);
}

test "openDeviceForWrite rejects an oversized source before writing" {
    const io = std.testing.io;
    const path = "test-device-destination-too-small.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const device_size: u64 = 64 * 1024;
    {
        var backing = try Image.create(io, path, .raw, device_size, .{});
        defer backing.close(io);
        try backing.pwrite(io, "unchanged", 0);
    }

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);
    try std.testing.expectError(
        error.DestinationTooSmall,
        openSyntheticDeviceForWrite(file, .{
            .size_bytes = device_size,
            .logical_sector_size = 512,
        }, device_size + 512, .{ .allow_device_write = true }),
    );

    var bytes: [9]u8 = undefined;
    _ = try file.readPositionalAll(io, &bytes, 0);
    try std.testing.expectEqualSlices(u8, "unchanged", &bytes);
}

test "resize is rejected on a device-backed image" {
    const io = std.testing.io;
    const path = "test-device-resize.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const device_size: u64 = 64 * 1024;
    {
        var img = try Image.create(io, path, .raw, device_size, .{});
        img.close(io);
    }

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    var img = try openSyntheticDeviceForWrite(file, .{
        .size_bytes = device_size,
        .logical_sector_size = 512,
    }, device_size, .{ .allow_device_write = true });
    defer img.close(io);

    // Rejected for every direction, including the no-op, so the diagnostic
    // is always about the device rather than about the requested size.
    try std.testing.expectError(error.BlockDeviceResizeNotSupported, img.resize(io, device_size * 2));
    try std.testing.expectError(error.BlockDeviceResizeNotSupported, img.resize(io, device_size));
    try std.testing.expectError(error.BlockDeviceResizeNotSupported, img.resize(io, device_size / 2));
    try std.testing.expectEqual(device_size, img.virtual_size);
}

test "create refuses a block-device target and accepts ordinary ones" {
    const io = std.testing.io;
    try std.testing.expectError(
        error.BlockDeviceCreateNotSupported,
        Image.rejectDeviceTarget(.block_device),
    );
    try Image.rejectDeviceTarget(.file);
    try Image.rejectDeviceTarget(.unknown);

    const path = "test-create-target-kind.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    try std.testing.expectEqual(Io.File.Kind.unknown, Image.existingTargetKind(io, path));
    {
        var img = try Image.create(io, path, .raw, 4096, .{});
        img.close(io);
    }
    try std.testing.expectEqual(Io.File.Kind.file, Image.existingTargetKind(io, path));
}
