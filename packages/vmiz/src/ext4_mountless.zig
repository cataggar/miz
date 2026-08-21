//! Bounded, mountless access to an existing ext4 filesystem.
//!
//! The filesystem is scanned with the general ext4 importer and its content
//! is spooled into `RootTree`; no host directory is created and no guest
//! permissions are interpreted by the host. Callers can inspect or mutate the
//! tree and commit it back to the same partition with the existing ext4
//! writer.

const std = @import("std");
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
    limits: Limits = .{},
    diagnostic: ?*limits_mod.Diagnostic = null,
};

pub const Error = anyerror;

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
    committed: bool = false,

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
        const file_size = (try file.stat(io)).size;
        if (end > file_size) return error.InvalidRange;

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
        };
    }

    pub fn deinit(self: *FileSystem) void {
        self.tree.deinit();
        self.source.deinit();
        self.reader.deinit();
        self.* = undefined;
    }

    pub fn filesystemIdentity(self: *const FileSystem) ext4.GeneralFilesystemIdentity {
        return self.identity;
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
        const relative = try normalizePath(path);
        const existing = self.tree.findNode(relative);
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
        const relative = try normalizePath(destination);
        const existing = self.tree.findNode(relative);
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

    /// Rewrites the selected ext4 range with the mutated tree, retaining its
    /// UUID, label, root metadata, filesystem length, and journal presence.
    pub fn commit(self: *FileSystem) Error!ext4.FilesystemInfo {
        try self.ensureMutable();
        const cursor = try self.tree.cursor();
        const root = self.tree.rootMetadata();
        const label = self.identity.label;
        const info = try ext4.populate(self.io, self.file, self.allocator, cursor, .{
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
        });
        self.committed = true;
        return info;
    }

    fn ensureMutable(self: *const FileSystem) Error!void {
        if (self.committed) return error.AlreadyCommitted;
    }
};

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

test "mountless ext4 API preserves mode zero and exposes bounded mutations" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless.raw";
    const spool_path = "test-ext4-mountless.spool";
    const copy_in_path = "test-ext4-mountless-copy-in";
    const copy_out_path = "test-ext4-mountless-copy-out";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, copy_in_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, copy_out_path) catch {};

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
    });
    defer fs.deinit();
    try std.testing.expectEqualSlices(u8, &([_]u8{0x52} ** 16), &fs.filesystemIdentity().uuid);
    try std.testing.expectEqualSlices(u8, "mountless", fs.filesystemIdentity().label[0..9]);
    const listed = try fs.list(allocator, "/", 16);
    defer allocator.free(listed);
    try std.testing.expectEqual(@as(usize, 1), listed.len);
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
    _ = try fs.commit();
}

test "mountless round trip preserves security metadata and special nodes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-ext4-mountless-fidelity.raw";
    const spool_path = "test-ext4-mountless-fidelity.spool";
    const reopen_spool_path = "test-ext4-mountless-fidelity-reopen.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, reopen_spool_path) catch {};

    var image = try @import("image.zig").Image.createExclusive(
        io,
        image_path,
        .raw,
        64 * 1024 * 1024,
        .{},
    );
    defer image.close(io);
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
    try source_tree.putSymlink("etc/void-link", "void", .{ .mode = 0o777 });
    try source_tree.putDevice("dev/null", .char_device, .{ .major = 1, .minor = 3 }, .{ .mode = 0o666 });
    try source_tree.putFifo("dev/initctl", .{ .mode = 0o600 });
    _ = try ext4.populate(io, image.file, allocator, try source_tree.cursor(), .{
        .length = 64 * 1024 * 1024,
        .label = "fidelity",
        .uuid = [_]u8{0x45} ** 16,
        .root_xattrs = &xattrs,
    });

    var fs = try FileSystem.open(allocator, io, image.file, .{
        .length = 64 * 1024 * 1024,
        .spool_path = spool_path,
    });
    defer fs.deinit();
    try std.testing.expectEqualSlices(u8, &([_]u8{0x45} ** 16), &fs.filesystemIdentity().uuid);
    try std.testing.expectEqualSlices(u8, "fidelity", fs.filesystemIdentity().label[0..8]);
    const locked = try fs.stat("/etc/void");
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
    try std.testing.expectEqualStrings("inaccessible", alias_bytes);
    const link = try fs.readLink(allocator, "/etc/void-link", 64);
    defer allocator.free(link);
    try std.testing.expectEqualStrings("void", link);
    try std.testing.expectEqual(Kind.char_device, (try fs.stat("/dev/null")).kind);
    try std.testing.expectEqual(Device{ .major = 1, .minor = 3 }, (try fs.stat("/dev/null")).payload.device);
    try std.testing.expectEqual(Kind.fifo, (try fs.stat("/dev/initctl")).kind);
    try fs.mkdir("/empty", .{ .mode = 0 });
    try fs.write("/empty/file", "new", null);
    try fs.remove("/empty", true);
    _ = try fs.commit();

    var reopened = try FileSystem.open(allocator, io, image.file, .{
        .length = 64 * 1024 * 1024,
        .spool_path = reopen_spool_path,
    });
    defer reopened.deinit();
    try std.testing.expectEqual(@as(u16, 0), (try reopened.stat("/etc/void")).metadata.mode);
    try std.testing.expectEqual(@as(usize, 3), (try reopened.stat("/")).metadata.xattrs.len);
    try std.testing.expectEqual(
        @as(usize, 1),
        (try reopened.stat("/etc/sparse")).payload.content.sparse_extents.len,
    );
    try std.testing.expectEqual(Kind.char_device, (try reopened.stat("/dev/null")).kind);
    try std.testing.expectError(error.PathNotFound, reopened.stat("/empty"));
}
