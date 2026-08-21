//! Bounded, mountless access to an existing ext4 filesystem.
//!
//! The filesystem is scanned with the general ext4 importer and its content
//! is spooled into `RootTree`; no host directory is created and no guest
//! permissions are interpreted by the host. Callers can inspect or mutate the
//! tree and commit it back to the same partition with the existing ext4
//! writer.

const std = @import("std");
const builtin = @import("builtin");
const ext4 = @import("ext4.zig");
const limits_mod = @import("limits.zig");
const root_tree = @import("root_tree.zig");
const tree_cursor = @import("tree_cursor.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Limits = limits_mod.ImportLimits;
pub const Metadata = root_tree.Metadata;
pub const Kind = root_tree.Kind;
pub const Entry = root_tree.NodeView;
pub const Device = root_tree.Device;

pub const OpenOptions = struct {
    offset: u64 = 0,
    length: u64,
    spool_path: []const u8,
    /// Path of the image file to replace on commit. Commits are refused
    /// without this so a caller cannot accidentally mutate the original
    /// partition in place.
    atomic_path: ?[]const u8 = null,
    limits: Limits = .{},
    diagnostic: ?*limits_mod.Diagnostic = null,
};

pub const HostTreeOptions = struct {
    max_file_bytes: u64 = 16 * 1024 * 1024 * 1024,
    /// Runtime-only directories are represented by their mount points in a
    /// package-manager root and must remain untouched in the ext4 tree.
    excluded_top_level: []const []const u8 = &.{ "dev", "proc", "run", "sys" },
};

pub const HostTreeManifest = struct {
    allocator: Allocator,
    excluded_paths: std.array_list.Managed([]u8),

    pub fn init(allocator: Allocator) HostTreeManifest {
        return .{ .allocator = allocator, .excluded_paths = .init(allocator) };
    }

    pub fn deinit(self: *HostTreeManifest) void {
        for (self.excluded_paths.items) |path| self.allocator.free(path);
        self.excluded_paths.deinit();
        self.* = undefined;
    }

    fn contains(self: *const HostTreeManifest, path: []const u8) bool {
        for (self.excluded_paths.items) |excluded| {
            if (std.mem.eql(u8, excluded, path)) return true;
        }
        return false;
    }
};

pub const Error = anyerror;

const CommitProfile = struct {
    descriptor_size: u16,
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    checksum_seed: ?u32 = null,
};

const HostXattr = struct {
    name: []u8,
    value: []u8,
};

const HostMetadata = struct {
    permissions: Io.File.Permissions,
    uid: ?Io.File.Uid,
    gid: ?Io.File.Gid,
    atime: ?Io.Timestamp,
    mtime: Io.Timestamp,
    xattrs: []HostXattr,

    fn deinit(self: *HostMetadata, allocator: Allocator) void {
        for (self.xattrs) |xattr| {
            allocator.free(xattr.name);
            allocator.free(xattr.value);
        }
        allocator.free(self.xattrs);
        self.* = undefined;
    }
};

pub const CommitResult = struct {
    allocator: Allocator,
    filesystem: ext4.FilesystemInfo,
    /// Owned private same-filesystem directory containing the displaced
    /// original. It is retained for operator recovery and is never removed by
    /// vmiz. Call `deinit()` after recording or using the path.
    recovery_path: []u8,

    pub fn deinit(self: *CommitResult) void {
        self.allocator.free(self.recovery_path);
        self.* = undefined;
    }
};

const max_host_xattr_bytes: usize = 16 * 1024 * 1024;

fn failedLinuxSyscall(result: usize) bool {
    return @as(isize, @bitCast(result)) < 0;
}

const DeviceIdentity = struct {
    major: u32,
    minor: u32,
};

fn linuxDeviceFromFile(file: Io.File) Error!DeviceIdentity {
    if (comptime builtin.os.tag != .linux) return .{ .major = 0, .minor = 0 };
    var statx: std.os.linux.Statx = undefined;
    const result = std.os.linux.statx(
        @intCast(file.handle),
        "",
        std.os.linux.AT.EMPTY_PATH,
        std.os.linux.STATX.BASIC_STATS,
        &statx,
    );
    if (failedLinuxSyscall(result)) return error.AtomicSourceChanged;
    return .{ .major = statx.dev_major, .minor = statx.dev_minor };
}

fn linuxDeviceFromPath(allocator: Allocator, io: Io, path: []const u8) Error!DeviceIdentity {
    if (comptime builtin.os.tag != .linux) return .{ .major = 0, .minor = 0 };
    const path_z = try allocator.allocSentinel(u8, path.len, 0);
    defer allocator.free(path_z);
    @memcpy(path_z, path);
    var statx: std.os.linux.Statx = undefined;
    const result = std.os.linux.statx(
        std.os.linux.AT.FDCWD,
        path_z.ptr,
        std.os.linux.AT.SYMLINK_NOFOLLOW | std.os.linux.AT.STATX_DONT_SYNC,
        std.os.linux.STATX.BASIC_STATS,
        &statx,
    );
    if (failedLinuxSyscall(result)) return error.AtomicSourceChanged;
    _ = io;
    return .{ .major = statx.dev_major, .minor = statx.dev_minor };
}

fn syncDirectoryPath(io: Io, path: []const u8) Error!void {
    if (comptime builtin.os.tag != .linux) {
        return error.AtomicDurabilityUnsupported;
    }
    var directory = if (std.fs.path.isAbsolute(path))
        try Io.Dir.openDirAbsolute(io, path, .{ .iterate = true })
    else
        try Io.Dir.cwd().openDir(io, if (path.len == 0) "." else path, .{ .iterate = true });
    defer directory.close(io);
    const sync_result = std.os.linux.fsync(directory.handle);
    if (failedLinuxSyscall(sync_result)) {
        return error.AtomicDurabilityFailed;
    }
}

fn syncDestinationDirectory(io: Io, atomic_path: []const u8) Error!void {
    const parent = std.fs.path.dirname(atomic_path) orelse ".";
    return syncDirectoryPath(io, parent);
}

fn captureHostMetadata(allocator: Allocator, io: Io, file: Io.File) Error!HostMetadata {
    const stat = try file.stat(io);
    if (comptime builtin.os.tag != .linux) {
        return error.HostMetadataPreservationUnsupported;
    }
    const linux = std.os.linux;
    var statx: linux.Statx = undefined;
    const statx_result = linux.statx(
        @intCast(file.handle),
        "",
        linux.AT.EMPTY_PATH,
        linux.STATX.BASIC_STATS,
        &statx,
    );
    if (failedLinuxSyscall(statx_result) or
        !statx.mask.UID or !statx.mask.GID)
    {
        return error.HostMetadataPreservationFailed;
    }
    var xattr_probe: [1]u8 = undefined;
    const xattr_bytes = linux.flistxattr(file.handle, &xattr_probe, 0);
    if (failedLinuxSyscall(xattr_bytes)) return error.HostMetadataPreservationFailed;
    if (xattr_bytes > max_host_xattr_bytes) return error.HostMetadataPreservationFailed;
    const names = try allocator.alloc(u8, @intCast(xattr_bytes));
    defer allocator.free(names);
    const names_len = if (names.len == 0) 0 else blk: {
        const result = linux.flistxattr(file.handle, names.ptr, names.len);
        if (failedLinuxSyscall(result)) return error.HostMetadataPreservationFailed;
        break :blk @as(usize, @intCast(result));
    };
    var xattrs = std.array_list.Managed(HostXattr).init(allocator);
    errdefer {
        for (xattrs.items) |xattr| {
            allocator.free(xattr.name);
            allocator.free(xattr.value);
        }
        xattrs.deinit();
    }
    var cursor: usize = 0;
    var total_bytes: usize = 0;
    while (cursor < names_len) {
        const end = std.mem.indexOfScalarPos(u8, names[0..names_len], cursor, 0) orelse
            return error.HostMetadataPreservationFailed;
        if (end == cursor) return error.HostMetadataPreservationFailed;
        const name = try allocator.dupe(u8, names[cursor..end]);
        errdefer allocator.free(name);
        const name_z = try allocator.allocSentinel(u8, name.len, 0);
        defer allocator.free(name_z);
        @memcpy(name_z, name);
        const raw_size = linux.fgetxattr(file.handle, name_z.ptr, &xattr_probe, 0);
        if (failedLinuxSyscall(raw_size)) return error.HostMetadataPreservationFailed;
        const value_len: usize = @intCast(raw_size);
        total_bytes = std.math.add(usize, total_bytes, name.len + value_len) catch
            return error.HostMetadataPreservationFailed;
        if (total_bytes > max_host_xattr_bytes) return error.HostMetadataPreservationFailed;
        const value = try allocator.alloc(u8, value_len);
        errdefer allocator.free(value);
        if (value_len != 0) {
            const result = linux.fgetxattr(file.handle, name_z.ptr, value.ptr, value.len);
            if (failedLinuxSyscall(result) or @as(usize, @intCast(result)) != value.len) {
                return error.HostMetadataPreservationFailed;
            }
        }
        try xattrs.append(.{ .name = name, .value = value });
        cursor = end + 1;
    }
    return .{
        .permissions = stat.permissions,
        .uid = @intCast(statx.uid),
        .gid = @intCast(statx.gid),
        .atime = stat.atime,
        .mtime = stat.mtime,
        .xattrs = try xattrs.toOwnedSlice(),
    };
}

fn purgeHostXattrsNotInSource(
    allocator: Allocator,
    file: Io.File,
    metadata: *const HostMetadata,
) Error!void {
    if (comptime builtin.os.tag != .linux) {
        return error.HostMetadataPreservationUnsupported;
    }
    const linux = std.os.linux;
    var probe: [1]u8 = undefined;
    const raw_size = linux.flistxattr(file.handle, &probe, 0);
    if (failedLinuxSyscall(raw_size)) return error.HostMetadataPreservationFailed;
    if (raw_size > max_host_xattr_bytes) return error.HostMetadataPreservationFailed;
    const names = try allocator.alloc(u8, @intCast(raw_size));
    defer allocator.free(names);
    const names_len = if (names.len == 0) 0 else blk: {
        const result = linux.flistxattr(file.handle, names.ptr, names.len);
        if (failedLinuxSyscall(result)) return error.HostMetadataPreservationFailed;
        break :blk @as(usize, @intCast(result));
    };
    var cursor: usize = 0;
    while (cursor < names_len) {
        const end = std.mem.indexOfScalarPos(u8, names[0..names_len], cursor, 0) orelse
            return error.HostMetadataPreservationFailed;
        if (end == cursor) return error.HostMetadataPreservationFailed;
        const name = names[cursor..end];
        var retained = false;
        for (metadata.xattrs) |xattr| {
            if (std.mem.eql(u8, xattr.name, name)) {
                retained = true;
                break;
            }
        }
        if (!retained) {
            const name_z = try allocator.allocSentinel(u8, name.len, 0);
            defer allocator.free(name_z);
            @memcpy(name_z, name);
            if (failedLinuxSyscall(linux.fremovexattr(@intCast(file.handle), name_z.ptr))) {
                return error.HostMetadataPreservationFailed;
            }
        }
        cursor = end + 1;
    }
}

fn purgeAllHostXattrsFd(allocator: Allocator, fd: std.posix.fd_t) Error!void {
    if (comptime builtin.os.tag != .linux) {
        return error.HostMetadataPreservationUnsupported;
    }
    const linux = std.os.linux;
    var probe: [1]u8 = undefined;
    const raw_size = linux.flistxattr(fd, &probe, 0);
    if (failedLinuxSyscall(raw_size)) return error.HostMetadataPreservationFailed;
    if (raw_size > max_host_xattr_bytes) return error.HostMetadataPreservationFailed;
    const names = try allocator.alloc(u8, @intCast(raw_size));
    defer allocator.free(names);
    const names_len = if (names.len == 0) 0 else blk: {
        const result = linux.flistxattr(fd, names.ptr, names.len);
        if (failedLinuxSyscall(result)) return error.HostMetadataPreservationFailed;
        break :blk @as(usize, @intCast(result));
    };
    var cursor: usize = 0;
    while (cursor < names_len) {
        const end = std.mem.indexOfScalarPos(u8, names[0..names_len], cursor, 0) orelse
            return error.HostMetadataPreservationFailed;
        if (end == cursor) return error.HostMetadataPreservationFailed;
        const name_z = try allocator.allocSentinel(u8, end - cursor, 0);
        defer allocator.free(name_z);
        @memcpy(name_z, names[cursor..end]);
        if (failedLinuxSyscall(linux.fremovexattr(@intCast(fd), name_z.ptr))) {
            return error.HostMetadataPreservationFailed;
        }
        cursor = end + 1;
    }
}

fn purgeAllHostXattrs(allocator: Allocator, file: Io.File) Error!void {
    return purgeAllHostXattrsFd(allocator, file.handle);
}

fn applyHostMetadata(io: Io, file: Io.File, metadata: *const HostMetadata) Error!void {
    if (comptime builtin.os.tag != .linux) {
        return error.HostMetadataPreservationUnsupported;
    }
    if (metadata.uid != null or metadata.gid != null) {
        file.setOwner(io, metadata.uid, metadata.gid) catch
            return error.HostMetadataPreservationFailed;
    }
    const linux = std.os.linux;
    for (metadata.xattrs) |xattr| {
        const name_z = try std.heap.page_allocator.allocSentinel(u8, xattr.name.len, 0);
        defer std.heap.page_allocator.free(name_z);
        @memcpy(name_z, xattr.name);
        const result = linux.fsetxattr(
            file.handle,
            name_z.ptr,
            xattr.value.ptr,
            xattr.value.len,
            0,
        );
        if (failedLinuxSyscall(result)) return error.HostMetadataPreservationFailed;
    }
    file.setPermissions(io, metadata.permissions) catch
        return error.HostMetadataPreservationFailed;
    file.setTimestamps(io, .{
        .access_timestamp = Io.File.SetTimestamp.init(metadata.atime),
        .modify_timestamp = .{ .new = metadata.mtime },
    }) catch return error.HostMetadataPreservationFailed;
}

fn createPrivateDirectory(allocator: Allocator, io: Io, atomic_path: []const u8) Error![]u8 {
    const timestamp = @as(u64, @intCast(Io.Clock.real.now(io).nanoseconds));
    var attempt: u32 = 0;
    while (attempt < 64) : (attempt += 1) {
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}.mountless-private-{x}-{d}",
            .{ atomic_path, timestamp, attempt },
        );
        Io.Dir.cwd().createDir(io, path, .fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(path);
                continue;
            },
            else => {
                allocator.free(path);
                return err;
            },
        };
        return path;
    }
    return error.AtomicPublishFailed;
}

fn preparePrivateDirectory(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    expected_device: DeviceIdentity,
) Error!Io.Dir {
    if (comptime builtin.os.tag != .linux) return error.AtomicPublishUnsupported;
    var directory = Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch
        return error.AtomicPublishFailed;
    errdefer directory.close(io);
    const linux = std.os.linux;
    var statx: linux.Statx = undefined;
    const statx_result = linux.statx(
        @intCast(directory.handle),
        "",
        linux.AT.EMPTY_PATH,
        linux.STATX.BASIC_STATS,
        &statx,
    );
    const io_stat = Io.Dir.cwd().statFile(io, path, .{}) catch
        return error.AtomicPublishFailed;
    if (failedLinuxSyscall(statx_result) or
        !statx.mask.UID or statx.uid != linux.geteuid() or
        statx.dev_major != expected_device.major or
        statx.dev_minor != expected_device.minor or
        io_stat.kind != .directory)
    {
        return error.AtomicPublishFailed;
    }
    try purgeAllHostXattrsFd(allocator, directory.handle);
    directory.setPermissions(io, .fromMode(0o700)) catch
        return error.AtomicPublishFailed;
    const sanitized_stat = Io.Dir.cwd().statFile(io, path, .{}) catch
        return error.AtomicPublishFailed;
    if (@as(u16, @intCast(sanitized_stat.permissions.toMode() & 0o7777)) != 0o700) {
        return error.AtomicPublishFailed;
    }
    return directory;
}

pub const FileSystem = struct {
    allocator: Allocator,
    io: Io,
    file: Io.File,
    reader: ext4.Reader,
    source: ext4.GeneralTree,
    tree: root_tree.RootTree,
    offset: u64,
    length: u64,
    identity: ext4.GeneralFilesystemIdentity,
    atomic_path: ?[]const u8,
    source_inode: Io.File.INode,
    source_device_major: u32 = 0,
    source_device_minor: u32 = 0,
    source_size: u64,
    source_mtime: Io.Timestamp,
    source_ctime: Io.Timestamp,
    committed: bool = false,
    test_publish_hook: ?*const fn (ctx: *anyopaque) anyerror!void = null,
    test_publish_hook_ctx: ?*anyopaque = null,
    test_after_exchange_hook: ?*const fn (
        ctx: *anyopaque,
        stage_path: []const u8,
        atomic_path: []const u8,
    ) anyerror!void = null,
    test_after_exchange_hook_ctx: ?*anyopaque = null,
    test_stage_ready_hook: ?*const fn (ctx: *anyopaque, stage_path: []const u8) anyerror!void = null,
    test_stage_ready_hook_ctx: ?*anyopaque = null,
    recovery_path: ?[]u8 = null,

    /// Opens and imports an ext4 partition without mounting it. The source
    /// bytes are bounded by `limits` and retained in the tree's spool, not in
    /// a permission-sensitive host directory.
    pub fn open(
        allocator: Allocator,
        io: Io,
        file: Io.File,
        options: OpenOptions,
    ) Error!FileSystem {
        if (options.length == 0) return error.InvalidRange;
        if (options.spool_path.len == 0) return error.InvalidSpoolPath;
        const end = std.math.add(u64, options.offset, options.length) catch
            return error.InvalidRange;
        const file_stat = try file.stat(io);
        const file_size = file_stat.size;
        if (end > file_size) return error.InvalidRange;
        const source_device = try linuxDeviceFromFile(file);
        if (options.atomic_path) |atomic_path| {
            const atomic_stat = try Io.Dir.cwd().statFile(io, atomic_path, .{
                .follow_symlinks = false,
            });
            if (atomic_stat.kind == .sym_link) return error.AtomicPathSymlink;
            const atomic_device = try linuxDeviceFromPath(allocator, io, atomic_path);
            if (atomic_stat.inode != file_stat.inode or
                atomic_device.major != source_device.major or
                atomic_device.minor != source_device.minor)
            {
                return error.AtomicSourceChanged;
            }
        }

        var reader = try ext4.openGeneral(io, file, allocator, .{ .offset = options.offset });
        errdefer reader.deinit();
        var source = ext4.scanReadable(&reader, io, allocator, .{
            .available_length = options.length,
            .max_nodes = options.limits.max_nodes,
            .max_path_bytes = options.limits.max_path_bytes,
            .max_component_bytes = options.limits.max_component_bytes,
            .max_file_bytes = options.limits.max_file_bytes,
            .max_total_bytes = options.limits.max_total_bytes,
            .max_xattrs_per_node = options.limits.max_xattrs_per_node,
            .max_xattr_bytes_per_node = options.limits.max_xattr_bytes_per_node,
            .max_scan_metadata_bytes = options.limits.max_scan_metadata_bytes,
            .diagnostic = options.diagnostic,
        }) catch |err| return err;
        errdefer source.deinit();

        var tree = try root_tree.RootTree.init(
            allocator,
            io,
            options.spool_path,
            options.limits.tree(),
        );
        tree.diagnostic = options.diagnostic;
        errdefer tree.deinit();
        try tree.importExt4General(&source);

        return .{
            .allocator = allocator,
            .io = io,
            .file = file,
            .reader = reader,
            .source = source,
            .tree = tree,
            .offset = options.offset,
            .length = options.length,
            .identity = source.identity,
            .atomic_path = options.atomic_path,
            .source_inode = file_stat.inode,
            .source_device_major = source_device.major,
            .source_device_minor = source_device.minor,
            .source_size = file_stat.size,
            .source_mtime = file_stat.mtime,
            .source_ctime = file_stat.ctime,
        };
    }

    pub fn deinit(self: *FileSystem) void {
        self.tree.deinit();
        self.source.deinit();
        self.reader.deinit();
        if (self.recovery_path) |path| self.allocator.free(path);
        self.* = undefined;
    }

    pub fn filesystemIdentity(self: *const FileSystem) ext4.GeneralFilesystemIdentity {
        return self.identity;
    }

    /// Rejects a source before a host package stage or image stage is
    /// created when the writer cannot reproduce its reserved structures.
    pub fn validateCommitProfile(self: *const FileSystem) !void {
        _ = try self.commitProfile();
    }

    pub fn rootMetadata(self: *const FileSystem) root_tree.RootMetadata {
        return self.tree.rootMetadata();
    }

    pub fn stat(self: *const FileSystem, path: []const u8) Error!Entry {
        const relative = try normalizePath(path);
        if (relative.len == 0) {
            return .{
                .path = "",
                .kind = .directory,
                .metadata = .{
                    .mode = self.tree.rootMetadata().mode,
                    .uid = self.tree.rootMetadata().uid,
                    .gid = self.tree.rootMetadata().gid,
                    .atime = self.tree.rootMetadata().atime,
                    .mtime = self.tree.rootMetadata().mtime,
                    .ctime = self.tree.rootMetadata().ctime,
                    .atime_nsec = self.tree.rootMetadata().atime_nsec,
                    .mtime_nsec = self.tree.rootMetadata().mtime_nsec,
                    .ctime_nsec = self.tree.rootMetadata().ctime_nsec,
                    .crtime = self.tree.rootMetadata().crtime,
                    .crtime_nsec = self.tree.rootMetadata().crtime_nsec,
                    .xattrs = self.tree.rootMetadata().xattrs,
                },
                .payload = .none,
            };
        }
        return self.tree.findNode(relative) orelse error.PathNotFound;
    }

    /// Returns immediate children of `path`. Returned paths, metadata, xattrs,
    /// and payload views borrow this filesystem until the next mutation.
    pub fn list(
        self: *const FileSystem,
        allocator: Allocator,
        path: []const u8,
        max_entries: usize,
    ) Error![]Entry {
        const relative = try normalizePath(path);
        const parent = if (relative.len == 0)
            @as(?Entry, null)
        else
            self.tree.findNode(relative) orelse return error.PathNotFound;
        if (parent) |entry| if (entry.kind != .directory) return error.NotDirectory;

        var result = std.array_list.Managed(Entry).init(allocator);
        errdefer result.deinit();
        for (0..self.tree.nodeCount()) |index| {
            const entry = self.tree.nodeView(index);
            if (!isImmediateChild(relative, entry.path)) continue;
            if (result.items.len >= max_entries) return error.NodeLimitExceeded;
            try result.append(entry);
        }
        return result.toOwnedSlice();
    }

    pub fn read(
        self: *const FileSystem,
        allocator: Allocator,
        path: []const u8,
        max_bytes: u64,
    ) Error![]u8 {
        var relative = try normalizePath(path);
        if (self.tree.findNode(relative)) |entry| {
            if (entry.kind == .hardlink) {
                relative = switch (entry.payload) {
                    .hardlink_target => |target| target,
                    else => return error.NotRegularFile,
                };
            }
        }
        return self.tree.readFileAlloc(allocator, relative, max_bytes) catch |err| switch (err) {
            error.MissingNode => error.PathNotFound,
            error.NotRegularFile => error.NotRegularFile,
            else => err,
        };
    }

    pub fn readLink(
        self: *const FileSystem,
        allocator: Allocator,
        path: []const u8,
        max_bytes: u64,
    ) Error![]u8 {
        const entry = try self.stat(path);
        if (entry.kind != .symlink) return error.NotSymlink;
        const target_size = switch (entry.payload) {
            .content => |content| content.size,
            else => return error.NotSymlink,
        };
        if (target_size > max_bytes) return error.FileLimitExceeded;
        const relative = try normalizePath(path);
        const bytes = try allocator.alloc(u8, std.math.cast(usize, target_size) orelse
            return error.FileLimitExceeded);
        errdefer allocator.free(bytes);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = try self.tree.readNodeContent(relative, bytes[offset..], offset);
            if (count == 0) return error.UnexpectedSourceLength;
            offset += count;
        }
        return bytes;
    }

    pub fn write(
        self: *FileSystem,
        path: []const u8,
        bytes: []const u8,
        metadata: ?Metadata,
    ) Error!void {
        try self.ensureMutable();
        var relative = try normalizePath(path);
        var existing = self.tree.findNode(relative);
        if (existing) |entry| {
            if (entry.kind == .hardlink) {
                relative = switch (entry.payload) {
                    .hardlink_target => |target| target,
                    else => return error.NotRegularFile,
                };
                existing = self.tree.findNode(relative);
            }
        }
        const selected = metadata orelse if (existing) |entry|
            entry.metadata
        else
            Metadata{ .mode = 0o644 };
        try self.tree.putFileBytes(relative, bytes, selected);
    }

    pub fn mkdir(
        self: *FileSystem,
        path: []const u8,
        metadata: Metadata,
    ) Error!void {
        try self.ensureMutable();
        try self.tree.putDirectory(try normalizePath(path), metadata);
    }

    pub fn remove(self: *FileSystem, path: []const u8, recursive: bool) Error!void {
        try self.ensureMutable();
        const relative = try normalizePath(path);
        const entry = self.tree.findNode(relative) orelse return error.PathNotFound;
        if (entry.kind == .directory and !recursive) {
            for (0..self.tree.nodeCount()) |index| {
                const child = self.tree.nodeView(index).path;
                if (isDescendant(relative, child)) return error.DirectoryNotEmpty;
            }
        }
        if (!try self.tree.remove(relative)) return error.PathNotFound;
    }

    /// Copies one host regular file into the guest tree. The host file is
    /// streamed through the existing bounded RootTree spool.
    pub fn copyIn(
        self: *FileSystem,
        source_path: []const u8,
        destination: []const u8,
        metadata: ?Metadata,
    ) Error!void {
        try self.ensureMutable();
        const source = try Io.Dir.cwd().openFile(self.io, source_path, .{});
        defer source.close(self.io);
        const source_stat = try source.stat(self.io);
        if (source_stat.kind != .file) return error.HostSourceNotRegularFile;
        var relative = try normalizePath(destination);
        var existing = self.tree.findNode(relative);
        if (existing) |entry| {
            if (entry.kind == .hardlink) {
                relative = switch (entry.payload) {
                    .hardlink_target => |target| target,
                    else => return error.NotRegularFile,
                };
                existing = self.tree.findNode(relative);
            }
        }
        const selected = metadata orelse if (existing) |entry|
            entry.metadata
        else
            Metadata{ .mode = 0o644 };
        try self.tree.putFileFromPath(relative, source_path, selected);
    }

    /// Copies one guest regular file to a single host destination file. It
    /// never walks or materializes a guest directory.
    pub fn copyOut(
        self: *const FileSystem,
        source_path: []const u8,
        destination_path: []const u8,
        max_bytes: u64,
    ) Error!void {
        const bytes = try self.read(self.allocator, source_path, max_bytes);
        defer self.allocator.free(bytes);
        const destination = Io.Dir.cwd().createFile(self.io, destination_path, .{ .truncate = true }) catch
            return error.HostDestinationNotRegularFile;
        defer destination.close(self.io);
        try destination.writePositionalAll(self.io, bytes, 0);
    }

    /// Materializes a bounded, tool-safe package root. Guest bytes are read
    /// through the ext4 tree, so mode `000` entries never become unreadable
    /// host inputs; regular files receive ordinary readable staging modes.
    pub fn exportHostTree(
        self: *const FileSystem,
        destination: []const u8,
        options: HostTreeOptions,
    ) Error!void {
        return self.exportHostTreeWithManifest(destination, options, null);
    }

    pub fn exportHostTreeWithManifest(
        self: *const FileSystem,
        destination: []const u8,
        options: HostTreeOptions,
        manifest: ?*HostTreeManifest,
    ) Error!void {
        try Io.Dir.cwd().createDirPath(self.io, destination);
        for (0..self.tree.nodeCount()) |index| {
            const entry = self.tree.nodeView(index);
            if (excludedTopLevel(entry.path, options.excluded_top_level)) {
                if (manifest) |out| try out.excluded_paths.append(try self.allocator.dupe(u8, entry.path));
                continue;
            }
            const host_path = try std.fs.path.join(self.allocator, &.{ destination, entry.path });
            defer self.allocator.free(host_path);
            const parent = std.fs.path.dirname(host_path) orelse destination;
            try Io.Dir.cwd().createDirPath(self.io, parent);
            switch (entry.kind) {
                .directory => try Io.Dir.cwd().createDirPath(self.io, host_path),
                .file, .hardlink => {
                    const bytes = try self.read(self.allocator, entry.path, options.max_file_bytes);
                    defer self.allocator.free(bytes);
                    try Io.Dir.cwd().writeFile(self.io, .{ .sub_path = host_path, .data = bytes });
                    try Io.Dir.cwd().setFilePermissions(self.io, host_path, .fromMode(0o644), .{});
                },
                .symlink => {
                    const target = try self.readLink(self.allocator, entry.path, options.max_file_bytes);
                    defer self.allocator.free(target);
                    Io.Dir.cwd().deleteFile(self.io, host_path) catch {};
                    try Io.Dir.cwd().symLink(self.io, target, host_path, .{});
                },
                // A package root only needs the mount points for these
                // entries. The original special nodes remain in the native
                // tree and are never replaced by host placeholders.
                .block_device, .char_device, .fifo => {
                    if (manifest) |out| {
                        try out.excluded_paths.append(try self.allocator.dupe(u8, entry.path));
                    }
                },
            }
        }
    }

    /// Imports files produced by a host package tool without using a host
    /// archive extractor. Existing native metadata remains authoritative;
    /// new files receive root ownership and the host mode bits.
    pub fn importHostTree(
        self: *FileSystem,
        source: []const u8,
        options: HostTreeOptions,
    ) Error!void {
        return self.importHostTreeWithManifest(source, options, null);
    }

    pub fn importHostTreeWithManifest(
        self: *FileSystem,
        source: []const u8,
        options: HostTreeOptions,
        manifest: ?*const HostTreeManifest,
    ) Error!void {
        const HardlinkUpdate = struct {
            host_path: []u8,
            target: []u8,
            canonical_changed: bool,
            target_missing: bool,
        };
        var hardlink_updates = std.array_list.Managed(HardlinkUpdate).init(self.allocator);
        defer {
            for (hardlink_updates.items) |update| {
                self.allocator.free(update.host_path);
                self.allocator.free(update.target);
            }
            hardlink_updates.deinit();
        }
        for (0..self.tree.nodeCount()) |index| {
            const node = self.tree.nodeView(index);
            if (node.kind != .hardlink) continue;
            const target = switch (node.payload) {
                .hardlink_target => |path| path,
                else => continue,
            };
            const alias_host = try std.fs.path.join(self.allocator, &.{ source, node.path });
            defer self.allocator.free(alias_host);
            const alias_stat = Io.Dir.cwd().statFile(self.io, alias_host, .{}) catch continue;
            if (alias_stat.kind != .file) continue;
            const target_host = try std.fs.path.join(self.allocator, &.{ source, target });
            defer self.allocator.free(target_host);
            var target_missing = false;
            const canonical_changed = blk: {
                if (Io.Dir.cwd().statFile(self.io, target_host, .{})) |target_stat| {
                    break :blk target_stat.kind != .file or
                        !try self.hostFileEquals(target_host, target, target_stat.size, options.max_file_bytes);
                } else |err| switch (err) {
                    error.FileNotFound => {
                        target_missing = true;
                        break :blk true;
                    },
                    else => return err,
                }
            };
            const alias_changed = !try self.hostFileEquals(alias_host, target, alias_stat.size, options.max_file_bytes);
            if (alias_changed) {
                try hardlink_updates.append(.{
                    .host_path = try self.allocator.dupe(u8, alias_host),
                    .target = try self.allocator.dupe(u8, target),
                    .canonical_changed = canonical_changed,
                    .target_missing = target_missing,
                });
            }
        }
        for (hardlink_updates.items, 0..) |update, index| {
            for (hardlink_updates.items[index + 1 ..]) |other| {
                if (std.mem.eql(u8, update.target, other.target) and
                    !try self.hostFilesEqual(update.host_path, other.host_path, options.max_file_bytes))
                {
                    return error.ConflictingHardlinkUpdate;
                }
            }
        }
        var pre_seen = std.StringHashMap(void).init(self.allocator);
        defer {
            var iterator = pre_seen.keyIterator();
            while (iterator.next()) |key| self.allocator.free(key.*);
            pre_seen.deinit();
        }
        try self.collectHostPaths(source, "", options, &pre_seen);
        for (0..self.tree.nodeCount()) |index| {
            const node = self.tree.nodeView(index);
            if (node.kind != .file or excludedTopLevel(node.path, options.excluded_top_level) or
                (manifest != null and manifest.?.contains(node.path)) or pre_seen.contains(node.path))
            {
                continue;
            }
        }
        var seen = std.StringHashMap(void).init(self.allocator);
        defer {
            var iterator = seen.keyIterator();
            while (iterator.next()) |key| self.allocator.free(key.*);
            seen.deinit();
        }
        try self.importHostDirectory(source, "", options, &seen);

        var removals = std.array_list.Managed([]u8).init(self.allocator);
        defer {
            for (removals.items) |path| self.allocator.free(path);
            removals.deinit();
        }
        for (hardlink_updates.items) |update| {
            const target = self.tree.findNode(update.target) orelse continue;
            if (update.target_missing) {
                if (update.canonical_changed) {
                    try self.copyIn(update.host_path, update.target, target.metadata);
                }
            } else if (update.canonical_changed) {
                if (!try self.hostFileEquals(update.host_path, update.target, (try Io.Dir.cwd().statFile(self.io, update.host_path, .{})).size, options.max_file_bytes)) {
                    return error.ConflictingHardlinkUpdate;
                }
            } else {
                try self.copyIn(update.host_path, update.target, target.metadata);
            }
        }
        for (0..self.tree.nodeCount()) |index| {
            const entry = self.tree.nodeView(index);
            if (excludedTopLevel(entry.path, options.excluded_top_level) or
                (manifest != null and manifest.?.contains(entry.path))) continue;
            if (seen.contains(entry.path)) continue;
            try removals.append(try self.allocator.dupe(u8, entry.path));
        }
        std.mem.sortUnstable([]u8, removals.items, {}, struct {
            fn less(_: void, a: []u8, b: []u8) bool {
                return a.len > b.len;
            }
        }.less);
        for (removals.items) |path| {
            _ = try self.tree.remove(path);
        }
    }

    fn collectHostPaths(
        self: *const FileSystem,
        host_path: []const u8,
        relative: []const u8,
        options: HostTreeOptions,
        seen: *std.StringHashMap(void),
    ) Error!void {
        var directory = try Io.Dir.cwd().openDir(self.io, host_path, .{ .iterate = true });
        defer directory.close(self.io);
        var iterator = directory.iterate();
        while (try iterator.next(self.io)) |entry| {
            const child = if (relative.len == 0)
                try self.allocator.dupe(u8, entry.name)
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ relative, entry.name });
            defer self.allocator.free(child);
            if (excludedTopLevel(child, options.excluded_top_level)) continue;
            try seen.put(try self.allocator.dupe(u8, child), {});
            if (entry.kind == .directory) {
                const child_host = try std.fs.path.join(self.allocator, &.{ host_path, entry.name });
                defer self.allocator.free(child_host);
                try self.collectHostPaths(child_host, child, options, seen);
            }
        }
    }

    fn importHostDirectory(
        self: *FileSystem,
        host_path: []const u8,
        relative: []const u8,
        options: HostTreeOptions,
        seen: *std.StringHashMap(void),
    ) Error!void {
        var directory = try Io.Dir.cwd().openDir(self.io, host_path, .{ .iterate = true });
        defer directory.close(self.io);
        var iterator = directory.iterate();
        while (try iterator.next(self.io)) |entry| {
            const child = if (relative.len == 0)
                try self.allocator.dupe(u8, entry.name)
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ relative, entry.name });
            errdefer self.allocator.free(child);
            if (excludedTopLevel(child, options.excluded_top_level)) continue;
            try seen.put(try self.allocator.dupe(u8, child), {});
            const child_host = try std.fs.path.join(self.allocator, &.{ host_path, entry.name });
            defer self.allocator.free(child_host);
            switch (entry.kind) {
                .directory => {
                    const existing = self.tree.findNode(child);
                    if (existing == null) try self.mkdir(child, .{ .mode = 0o755 });
                    try self.importHostDirectory(child_host, child, options, seen);
                },
                .file => {
                    const host_stat = try Io.Dir.cwd().statFile(self.io, child_host, .{});
                    const existing = self.tree.findNode(child);
                    if (existing == null or existing.?.kind != .hardlink) {
                        if (existing) |node| {
                            if (node.kind == .file and
                                try self.hostFileEquals(child_host, child, host_stat.size, options.max_file_bytes))
                            {
                                self.allocator.free(child);
                                continue;
                            }
                        }
                        const metadata = if (existing) |node| node.metadata else Metadata{
                            .mode = @intCast(host_stat.permissions.toMode() & 0o7777),
                        };
                        try self.copyIn(child_host, child, metadata);
                    }
                },
                .sym_link => {
                    var target_buffer: [4096]u8 = undefined;
                    const target_len = try Io.Dir.cwd().readLink(self.io, child_host, &target_buffer);
                    const existing = self.tree.findNode(child);
                    const metadata = if (existing) |node| node.metadata else Metadata{ .mode = 0o777 };
                    try self.symlink(child, target_buffer[0..target_len], metadata);
                },
                else => {},
            }
            self.allocator.free(child);
        }
    }

    fn hostFileEquals(
        self: *const FileSystem,
        host_path: []const u8,
        guest_path: []const u8,
        size: u64,
        max_bytes: u64,
    ) !bool {
        if (size > max_bytes) return error.FileLimitExceeded;
        const host = try Io.Dir.cwd().openFile(self.io, host_path, .{});
        defer host.close(self.io);
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < size) {
            const wanted: usize = @intCast(@min(@as(u64, buffer.len), size - offset));
            const got = try host.readPositionalAll(self.io, buffer[0..wanted], offset);
            if (got != wanted) return false;
            var guest_buffer: [64 * 1024]u8 = undefined;
            const guest_got = try self.tree.readNodeContent(guest_path, guest_buffer[0..wanted], offset);
            if (guest_got != wanted or !std.mem.eql(u8, buffer[0..wanted], guest_buffer[0..wanted])) {
                return false;
            }
            offset += wanted;
        }
        return true;
    }

    fn hostFilesEqual(
        self: *const FileSystem,
        first_path: []const u8,
        second_path: []const u8,
        max_bytes: u64,
    ) !bool {
        const first = try Io.Dir.cwd().openFile(self.io, first_path, .{});
        defer first.close(self.io);
        const second = try Io.Dir.cwd().openFile(self.io, second_path, .{});
        defer second.close(self.io);
        const first_stat = try first.stat(self.io);
        const second_stat = try second.stat(self.io);
        if (first_stat.kind != .file or second_stat.kind != .file or
            first_stat.size != second_stat.size)
        {
            return false;
        }
        if (first_stat.size > max_bytes) return error.FileLimitExceeded;
        var first_buffer: [64 * 1024]u8 = undefined;
        var second_buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < first_stat.size) {
            const wanted: usize = @intCast(@min(@as(u64, first_buffer.len), first_stat.size - offset));
            if (try first.readPositionalAll(self.io, first_buffer[0..wanted], offset) != wanted or
                try second.readPositionalAll(self.io, second_buffer[0..wanted], offset) != wanted or
                !std.mem.eql(u8, first_buffer[0..wanted], second_buffer[0..wanted]))
            {
                return false;
            }
            offset += wanted;
        }
        return true;
    }

    pub fn symlink(
        self: *FileSystem,
        path: []const u8,
        target: []const u8,
        metadata: Metadata,
    ) Error!void {
        try self.ensureMutable();
        try self.tree.putSymlink(try normalizePath(path), target, metadata);
    }

    /// Rewrites the selected ext4 range with the mutated tree, retaining its
    /// UUID, label, root metadata, filesystem length, and journal presence.
    pub fn commit(self: *FileSystem) Error!CommitResult {
        try self.ensureMutable();
        const atomic_path = self.atomic_path orelse return error.AtomicPublishPathRequired;
        const current_stat = try self.file.stat(self.io);
        if (!self.sameSourceStat(current_stat) or !try self.sameSourcePath(atomic_path)) {
            return error.AtomicSourceChanged;
        }
        const commit_profile = try self.commitProfile();
        const cursor = try self.tree.cursor();
        const root = self.tree.rootMetadata();
        const label = self.identity.label;
        const lock_path = try std.fmt.allocPrint(self.allocator, "{s}.mountless-lock", .{atomic_path});
        defer self.allocator.free(lock_path);
        var lock_file = try Io.Dir.cwd().createFile(self.io, lock_path, .{
            .read = true,
            .truncate = true,
            .exclusive = true,
        });
        defer {
            lock_file.close(self.io);
            DirDelete(self.io, lock_path);
        }
        var host_metadata = try captureHostMetadata(self.allocator, self.io, self.file);
        defer host_metadata.deinit(self.allocator);
        const private_dir_path = try createPrivateDirectory(self.allocator, self.io, atomic_path);
        defer self.allocator.free(private_dir_path);
        var exchanged = false;
        defer if (!exchanged) Io.Dir.cwd().deleteTree(self.io, private_dir_path) catch {};
        var private_dir = try preparePrivateDirectory(self.allocator, self.io, private_dir_path, .{
            .major = self.source_device_major,
            .minor = self.source_device_minor,
        });
        defer private_dir.close(self.io);
        try syncDestinationDirectory(self.io, atomic_path);
        try syncDirectoryPath(self.io, private_dir_path);
        const stage_path = try std.fs.path.join(self.allocator, &.{ private_dir_path, "stage" });
        defer self.allocator.free(stage_path);
        var stage_file = try private_dir.createFile(self.io, "stage", .{
            .read = true,
            .truncate = true,
            .exclusive = true,
            .permissions = .fromMode(0o600),
        });
        var stage_open = true;
        defer if (stage_open) stage_file.close(self.io);
        try purgeAllHostXattrs(self.allocator, stage_file);
        stage_file.setPermissions(self.io, .fromMode(0o600)) catch
            return error.HostMetadataPreservationFailed;
        try syncDirectoryPath(self.io, private_dir_path);
        if (comptime builtin.is_test) {
            if (self.test_stage_ready_hook) |hook| {
                try hook(
                    self.test_stage_ready_hook_ctx orelse return error.AtomicPublishFailed,
                    stage_path,
                );
            }
        }
        var copy_buffer: [1024 * 1024]u8 = undefined;
        var copied: u64 = 0;
        while (copied < self.source_size) {
            const wanted: usize = @intCast(@min(@as(u64, copy_buffer.len), self.source_size - copied));
            const got = try self.file.readPositionalAll(self.io, copy_buffer[0..wanted], copied);
            if (got != wanted) return error.SourceChangedDuringCopy;
            try stage_file.writePositionalAll(self.io, copy_buffer[0..got], copied);
            copied += got;
        }
        if (!self.sameSourceStat(try self.file.stat(self.io))) return error.AtomicSourceChanged;
        const info = try ext4.populate(self.io, stage_file, self.allocator, cursor, .{
            .offset = self.offset,
            .length = self.identity.filesystem_length,
            .block_size = self.identity.block_size,
            .label = &label,
            .root_xattrs = root.xattrs,
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
            .uuid = self.identity.uuid,
            .timestamp = std.math.cast(u32, root.mtime orelse 0) orelse 0,
            .journal = .{ .enabled = self.identity.has_journal },
            .preserve_feature_ro_compat = commit_profile.feature_ro_compat,
            .preserve_feature_compat = if (commit_profile.descriptor_size == 64)
                commit_profile.feature_compat
            else
                null,
            .preserve_feature_incompat = if (commit_profile.descriptor_size == 64)
                commit_profile.feature_incompat
            else
                null,
            .descriptor_size = commit_profile.descriptor_size,
            .preserve_checksum_seed = if (commit_profile.descriptor_size == 64)
                commit_profile.checksum_seed
            else
                null,
        });
        try purgeHostXattrsNotInSource(self.allocator, stage_file, &host_metadata);
        try applyHostMetadata(self.io, stage_file, &host_metadata);
        try stage_file.sync(self.io);
        stage_file.close(self.io);
        stage_open = false;
        if (!self.sameSourceStat(try self.file.stat(self.io)) or
            !try self.sameSourcePath(atomic_path))
        {
            return error.AtomicSourceChanged;
        }
        if (comptime builtin.is_test) {
            if (self.test_publish_hook) |hook| {
                try hook(self.test_publish_hook_ctx orelse return error.AtomicPublishFailed);
            }
        }
        try self.publishStage(stage_path, private_dir_path, atomic_path, &exchanged);
        self.committed = true;
        const owned_recovery_path = try self.allocator.dupe(u8, self.recovery_path.?);
        return .{
            .allocator = self.allocator,
            .filesystem = info,
            .recovery_path = owned_recovery_path,
        };
    }

    fn publishStage(
        self: *FileSystem,
        stage_path: []const u8,
        private_dir_path: []const u8,
        atomic_path: []const u8,
        exchanged: *bool,
    ) Error!void {
        if (comptime builtin.os.tag != .linux) {
            return error.AtomicPublishUnsupported;
        }
        const linux = std.os.linux;
        if (!try self.sameSourcePath(atomic_path)) return error.AtomicSourceChanged;
        var recovery_path: ?[]u8 = try self.allocator.dupe(u8, private_dir_path);
        defer if (recovery_path) |path| self.allocator.free(path);
        const stage_z = try self.allocator.allocSentinel(u8, stage_path.len, 0);
        defer self.allocator.free(stage_z);
        const atomic_z = try self.allocator.allocSentinel(u8, atomic_path.len, 0);
        defer self.allocator.free(atomic_z);
        @memcpy(stage_z, stage_path);
        @memcpy(atomic_z, atomic_path);
        const exchange_result = linux.renameat2(
            linux.AT.FDCWD,
            stage_z.ptr,
            linux.AT.FDCWD,
            atomic_z.ptr,
            .{ .EXCHANGE = true },
        );
        if (failedLinuxSyscall(exchange_result)) return error.AtomicPublishUnsupported;
        exchanged.* = true;
        self.recovery_path = recovery_path.?;
        recovery_path = null;

        if (comptime builtin.is_test) {
            if (self.test_after_exchange_hook) |hook| {
                try hook(
                    self.test_after_exchange_hook_ctx orelse return error.AtomicPublishFailed,
                    stage_path,
                    atomic_path,
                );
            }
        }

        syncDestinationDirectory(self.io, atomic_path) catch
            return error.AtomicDurabilityUnknown;
        syncDirectoryPath(self.io, private_dir_path) catch
            return error.AtomicDurabilityUnknown;
    }

    /// Returns the private same-filesystem directory containing the displaced
    /// original. The directory remains valid until an operator removes it.
    pub fn recoveryArtifactPath(self: *const FileSystem) ?[]const u8 {
        return self.recovery_path;
    }

    fn ensureMutable(self: *const FileSystem) Error!void {
        if (self.committed) return error.AlreadyCommitted;
    }

    fn sameSourceStat(self: *const FileSystem, observed: Io.File.Stat) bool {
        return observed.inode == self.source_inode and
            observed.size == self.source_size and
            std.meta.eql(observed.mtime, self.source_mtime) and
            std.meta.eql(observed.ctime, self.source_ctime);
    }

    fn sameSourcePath(self: *const FileSystem, path: []const u8) Error!bool {
        const path_stat = try Io.Dir.cwd().statFile(self.io, path, .{
            .follow_symlinks = false,
        });
        if (path_stat.kind == .sym_link) return error.AtomicPathSymlink;
        const device = try linuxDeviceFromPath(self.allocator, self.io, path);
        return self.sameSourceStat(path_stat) and
            device.major == self.source_device_major and
            device.minor == self.source_device_minor;
    }

    fn commitProfile(self: *const FileSystem) !CommitProfile {
        if (self.identity.inode_size != 256) {
            return error.UnsupportedCommitProfile;
        }
        const expected_compat = ext4.writer_feature_compat |
            if (self.identity.has_journal) ext4.feature_compat_has_journal else 0;
        const optional = ext4.writer_feature_ro_compat_optional;
        var contains_large_file = false;
        for (0..self.tree.nodeCount()) |index| {
            const node = self.tree.nodeView(index);
            switch (node.payload) {
                .content => |content| if (content.size > std.math.maxInt(i32)) {
                    contains_large_file = true;
                },
                else => {},
            }
            if (contains_large_file) break;
        }
        const expected_ro = ext4.writer_feature_ro_compat_base |
            if ((self.identity.feature_ro_compat & optional) != 0 or contains_large_file) optional else 0;
        if (self.identity.descriptor_size == 32 and
            self.identity.feature_compat == expected_compat and
            self.identity.feature_incompat == ext4.writer_feature_incompat and
            self.identity.feature_ro_compat == expected_ro)
        {
            return .{
                .descriptor_size = 32,
                .feature_compat = self.identity.feature_compat,
                .feature_incompat = self.identity.feature_incompat,
                .feature_ro_compat = self.identity.feature_ro_compat,
            };
        }
        if (self.identity.descriptor_size == 64 and
            self.identity.feature_compat == 0x103c and
            self.identity.feature_incompat == 0x22c2 and
            self.identity.feature_ro_compat == 0x046b)
        {
            return .{
                .descriptor_size = 64,
                .feature_compat = self.identity.feature_compat,
                .feature_incompat = self.identity.feature_incompat,
                .feature_ro_compat = self.identity.feature_ro_compat,
                .checksum_seed = self.identity.checksum_seed,
            };
        }
        return error.UnsupportedCommitProfile;
    }
};

fn DirDelete(io: Io, path: []const u8) void {
    Io.Dir.cwd().deleteFile(io, path) catch {};
}

pub const NativeFilesystem = FileSystem;
pub const Mountless = FileSystem;

fn normalizePath(path: []const u8) Error![]const u8 {
    var relative = path;
    while (relative.len > 0 and relative[0] == '/') relative = relative[1..];
    while (relative.len > 0 and relative[relative.len - 1] == '/') {
        relative = relative[0 .. relative.len - 1];
    }
    if (relative.len == 0) return relative;
    var components = std.mem.splitScalar(u8, relative, '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or
            std.mem.indexOfScalar(u8, component, 0) != null)
        {
            return error.InvalidPath;
        }
    }
    return relative;
}

fn isDescendant(parent: []const u8, path: []const u8) bool {
    return path.len > parent.len and
        std.mem.startsWith(u8, path, parent) and
        path[parent.len] == '/';
}

fn isImmediateChild(parent: []const u8, path: []const u8) bool {
    if (parent.len == 0) {
        return std.mem.indexOfScalar(u8, path, '/') == null;
    }
    if (!isDescendant(parent, path)) return false;
    return std.mem.indexOfScalar(u8, path[parent.len + 1 ..], '/') == null;
}

fn excludedTopLevel(path: []const u8, excluded: []const []const u8) bool {
    const first = if (std.mem.indexOfScalar(u8, path, '/')) |slash| path[0..slash] else path;
    for (excluded) |name| if (std.mem.eql(u8, first, name)) return true;
    return false;
}

fn setTestHostXattr(io: Io, path: []const u8, name: []const u8, value: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);
    const name_z = try std.heap.page_allocator.allocSentinel(u8, name.len, 0);
    defer std.heap.page_allocator.free(name_z);
    @memcpy(name_z, name);
    const result = std.os.linux.fsetxattr(
        file.handle,
        name_z.ptr,
        value.ptr,
        value.len,
        0,
    );
    if (failedLinuxSyscall(result)) return error.HostMetadataPreservationFailed;
}

fn setTestHostDirectoryXattr(io: Io, path: []const u8, name: []const u8, value: []const u8) !void {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    _ = io;
    const path_z = try std.heap.page_allocator.allocSentinel(u8, path.len, 0);
    defer std.heap.page_allocator.free(path_z);
    @memcpy(path_z, path);
    const name_z = try std.heap.page_allocator.allocSentinel(u8, name.len, 0);
    defer std.heap.page_allocator.free(name_z);
    @memcpy(name_z, name);
    const result = std.os.linux.setxattr(
        path_z.ptr,
        name_z.ptr,
        value.ptr,
        value.len,
        0,
    );
    if (failedLinuxSyscall(result)) return error.HostMetadataPreservationFailed;
}

fn testHostXattrExists(allocator: Allocator, io: Io, path: []const u8, name: []const u8) !bool {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const name_z = try allocator.allocSentinel(u8, name.len, 0);
    defer allocator.free(name_z);
    @memcpy(name_z, name);
    var probe: [1]u8 = undefined;
    const raw_size = std.os.linux.fgetxattr(file.handle, name_z.ptr, &probe, 0);
    if (failedLinuxSyscall(raw_size)) {
        return if (std.os.linux.errno(raw_size) == .NODATA)
            false
        else
            error.HostMetadataPreservationFailed;
    }
    return true;
}

fn readTestHostXattr(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    name: []const u8,
) ![]u8 {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const name_z = try allocator.allocSentinel(u8, name.len, 0);
    defer allocator.free(name_z);
    @memcpy(name_z, name);
    var xattr_probe: [1]u8 = undefined;
    const raw_size = std.os.linux.fgetxattr(file.handle, name_z.ptr, &xattr_probe, 0);
    if (failedLinuxSyscall(raw_size)) return error.HostMetadataPreservationFailed;
    const value = try allocator.alloc(u8, @intCast(raw_size));
    errdefer allocator.free(value);
    if (value.len != 0) {
        const result = std.os.linux.fgetxattr(file.handle, name_z.ptr, value.ptr, value.len);
        if (failedLinuxSyscall(result) or @as(usize, @intCast(result)) != value.len) {
            return error.HostMetadataPreservationFailed;
        }
    }
    return value;
}

const PublishRaceContext = struct {
    io: Io,
    atomic_path: []const u8,
    replacement_path: []const u8,
    length: u64,
};

const StageReadyContext = struct {
    allocator: Allocator,
    io: Io,
    mode_ok: bool = false,
    access_acl_present: bool = true,
};

fn inspectStageReady(ctx_ptr: *anyopaque, stage_path: []const u8) anyerror!void {
    const ctx: *StageReadyContext = @ptrCast(@alignCast(ctx_ptr));
    const stat = try Io.Dir.cwd().statFile(ctx.io, stage_path, .{});
    ctx.mode_ok = @as(u16, @intCast(stat.permissions.toMode() & 0o7777)) == 0o600 and
        stat.size == 0;
    ctx.access_acl_present = try testHostXattrExists(
        ctx.allocator,
        ctx.io,
        stage_path,
        "system.posix_acl_access",
    );
}

fn replaceAtomicPathBeforePublish(ctx_ptr: *anyopaque) anyerror!void {
    const ctx: *PublishRaceContext = @ptrCast(@alignCast(ctx_ptr));
    const replacement = try Io.Dir.cwd().createFile(ctx.io, ctx.replacement_path, .{
        .read = true,
        .truncate = true,
        .exclusive = true,
    });
    try replacement.setLength(ctx.io, ctx.length);
    replacement.close(ctx.io);
    try Io.Dir.cwd().rename(
        ctx.replacement_path,
        Io.Dir.cwd(),
        ctx.atomic_path,
        ctx.io,
    );
}

fn replaceAtomicPathAfterExchange(
    ctx_ptr: *anyopaque,
    _: []const u8,
    _: []const u8,
) anyerror!void {
    return replaceAtomicPathBeforePublish(ctx_ptr);
}

test "atomic commit preserves host image mode timestamps and xattrs" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const parent_path = "test-ext4-mountless-host-metadata-parent";
    const image_path = "test-ext4-mountless-host-metadata-parent/image.raw";
    const spool_path = "test-ext4-mountless-host-metadata.spool";
    defer Io.Dir.cwd().deleteTree(io, parent_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    try Io.Dir.cwd().createDirPath(io, parent_path);

    var image = try @import("image.zig").Image.createExclusive(
        io,
        image_path,
        .raw,
        32 * 1024 * 1024,
        .{},
    );
    var image_open = true;
    defer if (image_open) image.close(io);
    var source_tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer source_tree.deinit();
    try source_tree.putFileBytes("etc", "source", .{ .mode = 0o600 });
    _ = try ext4.populate(io, image.file, allocator, try source_tree.cursor(), .{
        .length = 32 * 1024 * 1024,
    });

    try Io.Dir.cwd().setFilePermissions(io, image_path, .fromMode(0o600), .{});
    const expected_mtime = Io.Timestamp.fromNanoseconds(1_700_000_123_456_789_000);
    try Io.Dir.cwd().setTimestamps(io, image_path, .{
        .access_timestamp = .{ .new = expected_mtime },
        .modify_timestamp = .{ .new = expected_mtime },
    });
    try setTestHostXattr(io, image_path, "user.vmiz-host", "preserve-me");
    const default_acl = [_]u8{
        0x02, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x06, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x04, 0x00, 0x04, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x10, 0x00, 0x06, 0x00,
        0xff, 0xff, 0xff, 0xff,
        0x20, 0x00, 0x04, 0x00,
        0xff, 0xff, 0xff, 0xff,
    };
    setTestHostDirectoryXattr(io, parent_path, "system.posix_acl_default", &default_acl) catch |err| switch (err) {
        error.HostMetadataPreservationFailed => return error.SkipZigTest,
        else => return err,
    };

    var fs = try FileSystem.open(allocator, io, image.file, .{
        .length = 32 * 1024 * 1024,
        .spool_path = spool_path,
        .atomic_path = image_path,
    });
    var fs_open = true;
    defer if (fs_open) fs.deinit();
    var stage_ready = StageReadyContext{ .allocator = allocator, .io = io };
    fs.test_stage_ready_hook = inspectStageReady;
    fs.test_stage_ready_hook_ctx = &stage_ready;
    try fs.write("/etc", "changed", null);
    var commit_result = try fs.commit();
    defer commit_result.deinit();
    const recovery_path = try allocator.dupe(u8, commit_result.recovery_path);
    defer {
        Io.Dir.cwd().deleteTree(io, recovery_path) catch {};
        allocator.free(recovery_path);
    }
    fs.deinit();
    fs_open = false;
    image.close(io);
    image_open = false;

    const stat = try Io.Dir.cwd().statFile(io, image_path, .{});
    try std.testing.expectEqual(
        @as(u16, 0o600),
        @as(u16, @intCast(stat.permissions.toMode() & 0o7777)),
    );
    try std.testing.expectEqual(expected_mtime.nanoseconds, stat.mtime.nanoseconds);
    const xattr = try readTestHostXattr(allocator, io, image_path, "user.vmiz-host");
    defer allocator.free(xattr);
    try std.testing.expectEqualStrings("preserve-me", xattr);
    try std.testing.expect(stage_ready.mode_ok);
    try std.testing.expect(!stage_ready.access_acl_present);
    try std.testing.expect(!try testHostXattrExists(
        allocator,
        io,
        image_path,
        "system.posix_acl_access",
    ));
}

test "atomic commit detects a replacement between validation and exchange" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless-publish-race.raw";
    const replacement_path = "test-ext4-mountless-publish-race-replacement.raw";
    const spool_path = "test-ext4-mountless-publish-race.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, replacement_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var image = try @import("image.zig").Image.createExclusive(
        io,
        image_path,
        .raw,
        32 * 1024 * 1024,
        .{},
    );
    var image_open = true;
    defer if (image_open) image.close(io);
    var source_tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer source_tree.deinit();
    try source_tree.putFileBytes("etc", "source", .{ .mode = 0o600 });
    _ = try ext4.populate(io, image.file, allocator, try source_tree.cursor(), .{
        .length = 32 * 1024 * 1024,
    });

    var fs = try FileSystem.open(allocator, io, image.file, .{
        .length = 32 * 1024 * 1024,
        .spool_path = spool_path,
        .atomic_path = image_path,
    });
    var race = PublishRaceContext{
        .io = io,
        .atomic_path = image_path,
        .replacement_path = replacement_path,
        .length = 32 * 1024 * 1024,
    };
    fs.test_publish_hook = replaceAtomicPathBeforePublish;
    fs.test_publish_hook_ctx = &race;
    try std.testing.expectError(error.AtomicSourceChanged, fs.commit());
    fs.deinit();
    image.close(io);
    image_open = false;

    const replacement_stat = try Io.Dir.cwd().statFile(io, image_path, .{});
    try std.testing.expectEqual(@as(u64, 32 * 1024 * 1024), replacement_stat.size);
}

test "atomic commit preserves a replacement after exchange and leaves recovery artifacts" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless-after-exchange-race.raw";
    const replacement_path = "test-ext4-mountless-after-exchange-race-replacement.raw";
    const spool_path = "test-ext4-mountless-after-exchange-race.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, replacement_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var image = try @import("image.zig").Image.createExclusive(
        io,
        image_path,
        .raw,
        32 * 1024 * 1024,
        .{},
    );
    var image_open = true;
    defer if (image_open) image.close(io);
    var source_tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer source_tree.deinit();
    try source_tree.putFileBytes("etc", "source", .{ .mode = 0o600 });
    _ = try ext4.populate(io, image.file, allocator, try source_tree.cursor(), .{
        .length = 32 * 1024 * 1024,
    });

    var fs = try FileSystem.open(allocator, io, image.file, .{
        .length = 32 * 1024 * 1024,
        .spool_path = spool_path,
        .atomic_path = image_path,
    });
    var race = PublishRaceContext{
        .io = io,
        .atomic_path = image_path,
        .replacement_path = replacement_path,
        .length = 32 * 1024 * 1024,
    };
    fs.test_after_exchange_hook = replaceAtomicPathAfterExchange;
    fs.test_after_exchange_hook_ctx = &race;
    var result = try fs.commit();
    defer result.deinit();
    const recovery_path = try allocator.dupe(u8, result.recovery_path);
    defer allocator.free(recovery_path);
    try std.testing.expectEqual(
        Io.File.Kind.directory,
        (try Io.Dir.cwd().statFile(io, recovery_path, .{})).kind,
    );
    try Io.Dir.cwd().deleteTree(io, recovery_path);
    fs.deinit();
    image.close(io);
    image_open = false;

    const replacement_stat = try Io.Dir.cwd().statFile(io, image_path, .{});
    try std.testing.expectEqual(@as(u64, 32 * 1024 * 1024), replacement_stat.size);
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, recovery_path, .{}));
}

test "mountless ext4 API preserves mode zero and exposes bounded mutations" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless.raw";
    const spool_path = "test-ext4-mountless.spool";
    const copy_in_path = "test-ext4-mountless-copy-in";
    const copy_out_path = "test-ext4-mountless-copy-out";
    const host_tree_path = "test-ext4-mountless-host-tree";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, copy_in_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, copy_out_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, host_tree_path) catch {};

    var image = try @import("image.zig").Image.createExclusive(
        io,
        image_path,
        .raw,
        32 * 1024 * 1024,
        .{},
    );
    defer image.close(io);
    var source_tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer source_tree.deinit();
    try source_tree.putDirectory("etc", .{ .mode = 0o755 });
    try source_tree.putFileBytes("etc/void", "secret", .{ .mode = 0 });
    _ = try ext4.populate(io, image.file, allocator, try source_tree.cursor(), .{
        .length = 32 * 1024 * 1024,
        .label = "mountless",
        .uuid = [_]u8{0x52} ** 16,
    });
    var fs = try FileSystem.open(allocator, io, image.file, .{
        .length = 32 * 1024 * 1024,
        .spool_path = spool_path,
        .atomic_path = image_path,
    });
    defer fs.deinit();
    try std.testing.expectEqualSlices(u8, &([_]u8{0x52} ** 16), &fs.filesystemIdentity().uuid);
    try std.testing.expectEqualSlices(u8, "mountless", fs.filesystemIdentity().label[0..9]);
    const listed = try fs.list(allocator, "/", 16);
    defer allocator.free(listed);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
    var host_manifest = HostTreeManifest.init(allocator);
    defer host_manifest.deinit();
    try fs.exportHostTreeWithManifest(host_tree_path, .{}, &host_manifest);
    try fs.importHostTreeWithManifest(host_tree_path, .{}, &host_manifest);
    try std.testing.expectEqual(@as(u16, 0), (try fs.stat("/etc/void")).metadata.mode);
    try std.testing.expectError(error.FileLimitExceeded, fs.read(allocator, "/etc/void", 2));
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = copy_in_path, .data = "from-host" });
    try fs.copyIn(copy_in_path, "/new/from-host", .{ .mode = 0o640 });
    try fs.copyOut("/new/from-host", copy_out_path, 64);
    const copied = try Io.Dir.cwd().readFileAlloc(io, copy_out_path, allocator, .limited(64));
    defer allocator.free(copied);
    try std.testing.expectEqualStrings("from-host", copied);
    try fs.mkdir("/new", .{ .mode = 0o000 });
    try fs.write("/new/file", "changed", null);
    try fs.remove("/etc/void", false);
    const original_compat = fs.identity.feature_compat;
    fs.identity.feature_compat |= 0x0010; // resize_inode, not emitted by the writer
    try std.testing.expectError(error.UnsupportedCommitProfile, fs.commit());
    fs.identity.feature_compat = original_compat;
    fs.identity.feature_compat = original_compat & ~ext4.writer_feature_compat;
    try std.testing.expectError(error.UnsupportedCommitProfile, fs.commit());
    fs.identity.feature_compat = original_compat;
    var commit_result = try fs.commit();
    defer commit_result.deinit();
    const recovery_path = try allocator.dupe(u8, commit_result.recovery_path);
    defer {
        Io.Dir.cwd().deleteTree(io, recovery_path) catch {};
        allocator.free(recovery_path);
    }
}

test "mountless commit preserves the pinned Ubuntu descriptor-64 profile" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless-pinned.raw";
    const spool_path = "test-ext4-mountless-pinned.spool";
    const reopen_spool_path = "test-ext4-mountless-pinned-reopen.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, reopen_spool_path) catch {};

    const length: u64 = 64 * 1024 * 1024;
    var image = try @import("image.zig").Image.createExclusive(
        io,
        image_path,
        .raw,
        length,
        .{},
    );
    var image_open = true;
    defer if (image_open) image.close(io);

    var source_tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer source_tree.deinit();
    try source_tree.putDirectory("etc", .{ .mode = 0o755 });
    try source_tree.putFileBytes("etc/os-release", "NAME=vmiz\n", .{ .mode = 0o644 });
    _ = try ext4.populate(io, image.file, allocator, try source_tree.cursor(), .{
        .length = length,
        .label = "ubuntu-root",
        .uuid = [_]u8{0x71} ** 16,
        .timestamp = 1_724_000_000,
        .journal = .{ .enabled = true },
        .preserve_feature_ro_compat = 0x046b,
        .preserve_feature_compat = 0x103c,
        .preserve_feature_incompat = 0x22c2,
        .descriptor_size = 64,
        .preserve_checksum_seed = 0x89AB_CDEF,
    });

    var fs = try FileSystem.open(allocator, io, image.file, .{
        .length = length,
        .spool_path = spool_path,
        .atomic_path = image_path,
    });
    var fs_open = true;
    defer if (fs_open) fs.deinit();
    const identity = fs.filesystemIdentity();
    try std.testing.expectEqual(@as(u16, 64), identity.descriptor_size);
    try std.testing.expectEqual(@as(u32, 0x103c), identity.feature_compat);
    try std.testing.expectEqual(@as(u32, 0x22c2), identity.feature_incompat);
    try std.testing.expectEqual(@as(u32, 0x046b), identity.feature_ro_compat);
    try fs.write("/etc/os-release", "NAME=vmiz-pinned\n", null);
    var commit_result = try fs.commit();
    defer commit_result.deinit();
    const recovery_path = try allocator.dupe(u8, commit_result.recovery_path);
    defer {
        Io.Dir.cwd().deleteTree(io, recovery_path) catch {};
        allocator.free(recovery_path);
    }
    fs.deinit();
    fs_open = false;
    image.close(io);
    image_open = false;

    try ext4.expectE2fsckClean(image_path);
    var reopened_image = try @import("image.zig").Image.openPath(io, image_path);
    defer reopened_image.close(io);
    var reopened = try FileSystem.open(allocator, io, reopened_image.file, .{
        .length = length,
        .spool_path = reopen_spool_path,
        .atomic_path = image_path,
    });
    defer reopened.deinit();
    try std.testing.expectEqual(@as(u16, 64), reopened.filesystemIdentity().descriptor_size);
    try std.testing.expectEqual(@as(u32, 0x103c), reopened.filesystemIdentity().feature_compat);
    try std.testing.expectEqual(@as(u32, 0x22c2), reopened.filesystemIdentity().feature_incompat);
    try std.testing.expectEqual(@as(u32, 0x046b), reopened.filesystemIdentity().feature_ro_compat);
    const content = try reopened.read(allocator, "/etc/os-release", 64);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("NAME=vmiz-pinned\n", content);
}

test "mountless round trip preserves security metadata and special nodes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless-fidelity.raw";
    const spool_path = "test-ext4-mountless-fidelity.spool";
    const reopen_spool_path = "test-ext4-mountless-fidelity-reopen.spool";
    const host_tree_path = "test-ext4-mountless-fidelity-host-tree";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, reopen_spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, host_tree_path) catch {};

    var image = try @import("image.zig").Image.createExclusive(
        io,
        image_path,
        .raw,
        64 * 1024 * 1024,
        .{},
    );
    var image_open = true;
    defer if (image_open) image.close(io);
    var source_tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer source_tree.deinit();
    const xattrs = [_]tree_cursor.Xattr{
        .{ .name = "user.origin", .value = "mountless" },
        .{ .name = "system.posix_acl_access", .value = "\x02\x00\x00\x00" },
        .{ .name = "security.capability", .value = "cap_net_raw+p" },
    };
    source_tree.setRootMetadata(.{ .xattrs = &xattrs });
    try source_tree.putDirectory("etc", .{ .mode = 0o755 });
    try source_tree.putDirectory("dev", .{ .mode = 0o755 });
    try source_tree.putDirectory("usr", .{ .mode = 0o755 });
    try source_tree.putDirectory("usr/bin", .{ .mode = 0o755 });
    try source_tree.putDirectory("var", .{ .mode = 0o755 });
    try source_tree.putFileBytes("etc/void", "inaccessible", .{
        .mode = 0,
        .uid = 1234,
        .gid = 2345,
        .mtime = 1_700_000_001,
        .xattrs = &xattrs,
    });
    var sparse_bytes = [_]u8{0} ** 8192;
    @memcpy(sparse_bytes[0..6], "sparse");
    try source_tree.putFileBytesSparse("etc/sparse", &sparse_bytes, &.{
        .{ .logical_block = 1, .block_count = 1 },
    }, .{ .mode = 0o600 });
    try std.testing.expectEqual(
        @as(usize, 1),
        (source_tree.findNode("etc/sparse").?.payload.content).sparse_extents.len,
    );
    try source_tree.putHardlink("usr/bin/void-alias", "etc/void", .{ .mode = 0 });
    try source_tree.putHardlink("usr/bin/void-alias2", "etc/void", .{ .mode = 0 });
    try source_tree.putSymlink("etc/void-link", "void", .{ .mode = 0o777 });
    try source_tree.putDevice("dev/null", .char_device, .{ .major = 1, .minor = 3 }, .{ .mode = 0o666 });
    try source_tree.putFifo("dev/initctl", .{ .mode = 0o600 });
    try source_tree.putFifo("var/fifo", .{ .mode = 0o600 });
    _ = try ext4.populate(io, image.file, allocator, try source_tree.cursor(), .{
        .length = 64 * 1024 * 1024,
        .label = "fidelity",
        .uuid = [_]u8{0x45} ** 16,
        .root_xattrs = &xattrs,
    });

    const probe_spool_path = "test-ext4-mountless-fidelity-probe.spool";
    defer Io.Dir.cwd().deleteFile(io, probe_spool_path) catch {};
    var probe_diagnostic = limits_mod.Diagnostic{};
    var probe = try FileSystem.open(allocator, io, image.file, .{
        .length = 64 * 1024 * 1024,
        .spool_path = probe_spool_path,
        .atomic_path = image_path,
        .diagnostic = &probe_diagnostic,
    });
    probe.deinit();
    const sparse_metadata_peak = probe_diagnostic.peaks.scan_metadata_bytes;
    try std.testing.expect(sparse_metadata_peak > 0);
    var limited_diagnostic = limits_mod.Diagnostic{};
    try std.testing.expectError(
        error.ScanMetadataLimitExceeded,
        FileSystem.open(allocator, io, image.file, .{
            .length = 64 * 1024 * 1024,
            .spool_path = probe_spool_path,
            .atomic_path = image_path,
            .limits = .{ .max_scan_metadata_bytes = @intCast(sparse_metadata_peak - 1) },
            .diagnostic = &limited_diagnostic,
        }),
    );

    var fs = try FileSystem.open(allocator, io, image.file, .{
        .length = 64 * 1024 * 1024,
        .spool_path = spool_path,
        .atomic_path = image_path,
    });
    var fs_open = true;
    defer if (fs_open) fs.deinit();
    var host_manifest = HostTreeManifest.init(allocator);
    defer host_manifest.deinit();
    try fs.exportHostTreeWithManifest(host_tree_path, .{}, &host_manifest);
    const staged_alias = try std.fs.path.join(allocator, &.{ host_tree_path, "usr/bin/void-alias" });
    defer allocator.free(staged_alias);
    const staged_alias2 = try std.fs.path.join(allocator, &.{ host_tree_path, "usr/bin/void-alias2" });
    defer allocator.free(staged_alias2);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = staged_alias, .data = "staged-alias" });
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = staged_alias2, .data = "different-alias" });
    try std.testing.expectError(
        error.ConflictingHardlinkUpdate,
        fs.importHostTreeWithManifest(host_tree_path, .{}, &host_manifest),
    );
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = staged_alias2, .data = "staged-alias" });
    try fs.importHostTreeWithManifest(host_tree_path, .{}, &host_manifest);
    const staged_target = try fs.read(allocator, "/etc/void", 64);
    defer allocator.free(staged_target);
    try std.testing.expectEqualStrings("staged-alias", staged_target);
    try std.testing.expectEqual(Kind.hardlink, (try fs.stat("/usr/bin/void-alias")).kind);
    const staged_canonical = try std.fs.path.join(allocator, &.{ host_tree_path, "etc/void" });
    defer allocator.free(staged_canonical);
    try Io.Dir.cwd().deleteFile(io, staged_canonical);
    try fs.importHostTreeWithManifest(host_tree_path, .{}, &host_manifest);
    try std.testing.expectError(error.PathNotFound, fs.stat("/etc/void"));
    try std.testing.expectEqual(Kind.file, (try fs.stat("/usr/bin/void-alias")).kind);
    try std.testing.expectEqual(
        Kind.hardlink,
        (try fs.stat("/usr/bin/void-alias2")).kind,
    );
    try std.testing.expectEqualStrings(
        "usr/bin/void-alias",
        (try fs.stat("/usr/bin/void-alias2")).payload.hardlink_target,
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0x45} ** 16), &fs.filesystemIdentity().uuid);
    try std.testing.expectEqualSlices(u8, "fidelity", fs.filesystemIdentity().label[0..8]);
    const locked = try fs.stat("/usr/bin/void-alias");
    try std.testing.expectEqual(@as(u16, 0), locked.metadata.mode);
    try std.testing.expectEqual(@as(u32, 1234), locked.metadata.uid);
    try std.testing.expectEqual(@as(u32, 2345), locked.metadata.gid);
    try std.testing.expectEqual(@as(?i64, 1_700_000_001), locked.metadata.mtime);
    try std.testing.expectEqual(@as(usize, 3), locked.metadata.xattrs.len);
    try std.testing.expectEqual(@as(usize, 3), (try fs.stat("/")).metadata.xattrs.len);
    const sparse = try fs.stat("/etc/sparse");
    try std.testing.expectEqual(@as(usize, 1), sparse.payload.content.sparse_extents.len);
    const alias_bytes = try fs.read(allocator, "/usr/bin/void-alias", 64);
    defer allocator.free(alias_bytes);
    try std.testing.expectEqualStrings("staged-alias", alias_bytes);
    try fs.write("/usr/bin/void-alias", "shared", null);
    const shared_target = try fs.read(allocator, "/usr/bin/void-alias2", 64);
    defer allocator.free(shared_target);
    try std.testing.expectEqualStrings("shared", shared_target);
    try std.testing.expectEqual(Kind.file, (try fs.stat("/usr/bin/void-alias")).kind);
    try std.testing.expectEqual(Kind.hardlink, (try fs.stat("/usr/bin/void-alias2")).kind);
    const link = try fs.readLink(allocator, "/etc/void-link", 64);
    defer allocator.free(link);
    try std.testing.expectEqualStrings("void", link);
    try std.testing.expectEqual(Kind.char_device, (try fs.stat("/dev/null")).kind);
    try std.testing.expectEqual(Device{ .major = 1, .minor = 3 }, (try fs.stat("/dev/null")).payload.device);
    try std.testing.expectEqual(Kind.fifo, (try fs.stat("/dev/initctl")).kind);
    try fs.mkdir("/empty", .{ .mode = 0 });
    try fs.write("/empty/file", "new", null);
    try fs.remove("/empty", true);
    var commit_result = try fs.commit();
    defer commit_result.deinit();
    const recovery_path = try allocator.dupe(u8, commit_result.recovery_path);
    defer {
        Io.Dir.cwd().deleteTree(io, recovery_path) catch {};
        allocator.free(recovery_path);
    }
    fs.deinit();
    fs_open = false;
    image.close(io);
    image_open = false;

    var reopened_image = try @import("image.zig").Image.openPath(io, image_path);
    defer reopened_image.close(io);
    var reopened = try FileSystem.open(allocator, io, reopened_image.file, .{
        .length = 64 * 1024 * 1024,
        .spool_path = reopen_spool_path,
        .atomic_path = image_path,
    });
    defer reopened.deinit();
    try std.testing.expectEqual(@as(u16, 0), (try reopened.stat("/usr/bin/void-alias")).metadata.mode);
    try std.testing.expectEqual(@as(u16, 32), reopened.filesystemIdentity().descriptor_size);
    try std.testing.expectEqual(@as(usize, 3), (try reopened.stat("/")).metadata.xattrs.len);
    try std.testing.expectEqual(
        @as(usize, 1),
        (try reopened.stat("/etc/sparse")).payload.content.sparse_extents.len,
    );
    try std.testing.expectEqual(Kind.char_device, (try reopened.stat("/dev/null")).kind);
    try std.testing.expectEqual(Kind.fifo, (try reopened.stat("/var/fifo")).kind);
    try std.testing.expectEqual(Kind.file, (try reopened.stat("/usr/bin/void-alias")).kind);
    try std.testing.expectEqual(Kind.hardlink, (try reopened.stat("/usr/bin/void-alias2")).kind);
    const reopened_shared = try reopened.read(allocator, "/usr/bin/void-alias", 64);
    defer allocator.free(reopened_shared);
    try std.testing.expectEqualStrings("shared", reopened_shared);
    try std.testing.expectError(error.PathNotFound, reopened.stat("/empty"));
}

test "atomic commit rejects replacement of the source path after open" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless-source-replaced.raw";
    const replacement_path = "test-ext4-mountless-source-replacement.raw";
    const spool_path = "test-ext4-mountless-source-replaced.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, replacement_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var image = try @import("image.zig").Image.createExclusive(io, image_path, .raw, 32 * 1024 * 1024, .{});
    var image_open = true;
    defer if (image_open) image.close(io);
    var tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer tree.deinit();
    try tree.putFileBytes("etc", "source", .{ .mode = 0o644 });
    _ = try ext4.populate(io, image.file, allocator, try tree.cursor(), .{ .length = 32 * 1024 * 1024 });

    var fs = try FileSystem.open(allocator, io, image.file, .{
        .length = 32 * 1024 * 1024,
        .spool_path = spool_path,
        .atomic_path = image_path,
    });
    defer fs.deinit();

    var replacement = try @import("image.zig").Image.createExclusive(
        io,
        replacement_path,
        .raw,
        32 * 1024 * 1024,
        .{},
    );
    replacement.close(io);
    try Io.Dir.cwd().rename(replacement_path, Io.Dir.cwd(), image_path, io);
    try std.testing.expectError(error.AtomicSourceChanged, fs.commit());
    image_open = false;
    image.close(io);
}

test "mountless open rejects an atomic final-component symlink" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless-atomic-symlink.raw";
    const symlink_path = "test-ext4-mountless-atomic-symlink";
    const spool_path = "test-ext4-mountless-atomic-symlink.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, symlink_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var image = try @import("image.zig").Image.createExclusive(
        io,
        image_path,
        .raw,
        32 * 1024 * 1024,
        .{},
    );
    defer image.close(io);
    var tree = root_tree.RootTree.initMemory(allocator, io, .{});
    defer tree.deinit();
    try tree.putFileBytes("etc", "source", .{ .mode = 0o644 });
    _ = try ext4.populate(io, image.file, allocator, try tree.cursor(), .{
        .length = 32 * 1024 * 1024,
    });
    try Io.Dir.cwd().symLink(io, image_path, symlink_path, .{});

    try std.testing.expectError(
        error.AtomicPathSymlink,
        FileSystem.open(allocator, io, image.file, .{
            .length = 32 * 1024 * 1024,
            .spool_path = spool_path,
            .atomic_path = symlink_path,
        }),
    );
}
