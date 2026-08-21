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
    source_size: u64,
    source_mtime: Io.Timestamp,
    source_ctime: Io.Timestamp,
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
        const file_stat = try file.stat(io);
        const file_size = file_stat.size;
        if (end > file_size) return error.InvalidRange;
        if (options.atomic_path) |atomic_path| {
            const atomic_stat = try Io.Dir.cwd().statFile(io, atomic_path, .{});
            if (atomic_stat.inode != file_stat.inode) return error.AtomicSourceChanged;
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
            .source_size = file_stat.size,
            .source_mtime = file_stat.mtime,
            .source_ctime = file_stat.ctime,
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
            const canonical_changed = if (Io.Dir.cwd().statFile(self.io, target_host, .{})) |target_stat|
                target_stat.kind != .file or
                    !try self.hostFileEquals(target_host, target, target_stat.size, options.max_file_bytes)
            else |_|
                true;
            const alias_changed = !try self.hostFileEquals(alias_host, target, alias_stat.size, options.max_file_bytes);
            if (alias_changed) {
                try hardlink_updates.append(.{
                    .host_path = try self.allocator.dupe(u8, alias_host),
                    .target = try self.allocator.dupe(u8, target),
                    .canonical_changed = canonical_changed,
                });
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
            if (update.canonical_changed) {
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
            _ = self.tree.remove(path) catch {};
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
    pub fn commit(self: *FileSystem) Error!ext4.FilesystemInfo {
        try self.ensureMutable();
        const atomic_path = self.atomic_path orelse return error.AtomicPublishPathRequired;
        const current_stat = try self.file.stat(self.io);
        const atomic_stat = try Io.Dir.cwd().statFile(self.io, atomic_path, .{});
        if (!self.sameSourceStat(current_stat) or !self.sameSourceStat(atomic_stat)) {
            return error.AtomicSourceChanged;
        }
        const preserve_feature_ro_compat = try self.validateCommitProfile();
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
        const stage_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}.mountless-stage-{d}",
            .{ atomic_path, @as(u64, @intCast(Io.Clock.real.now(self.io).nanoseconds)) },
        );
        defer self.allocator.free(stage_path);
        var stage_published = false;
        defer if (!stage_published) DirDelete(self.io, stage_path);
        var stage_file = try Io.Dir.cwd().createFile(self.io, stage_path, .{
            .read = true,
            .truncate = true,
            .exclusive = true,
        });
        var stage_open = true;
        defer if (stage_open) stage_file.close(self.io);
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
            .preserve_feature_ro_compat = preserve_feature_ro_compat,
        });
        try stage_file.sync(self.io);
        stage_file.close(self.io);
        stage_open = false;
        if (!self.sameSourceStat(try self.file.stat(self.io)) or
            !self.sameSourceStat(try Io.Dir.cwd().statFile(self.io, atomic_path, .{})))
        {
            return error.AtomicSourceChanged;
        }
        // POSIX rename atomically replaces the old image path after the
        // fully validated stage has been closed. This API targets ext4/Linux
        // image mutation; Windows/WASI callers should provide a filesystem
        // layer with equivalent replace semantics.
        try Io.Dir.cwd().rename(stage_path, Io.Dir.cwd(), atomic_path, self.io);
        stage_published = true;
        self.committed = true;
        return info;
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

    fn validateCommitProfile(self: *const FileSystem) !u32 {
        if (self.identity.inode_size != 256 or self.identity.descriptor_size != 32) {
            return error.UnsupportedCommitProfile;
        }
        const expected_compat = ext4.writer_feature_compat |
            if (self.identity.has_journal) ext4.feature_compat_has_journal else 0;
        if (self.identity.feature_compat != expected_compat or
            self.identity.feature_incompat != ext4.writer_feature_incompat)
        {
            return error.UnsupportedCommitProfile;
        }
        const optional = ext4.writer_feature_ro_compat_optional;
        if (self.identity.feature_ro_compat & ~(ext4.writer_feature_ro_compat_base | optional) != 0) {
            return error.UnsupportedCommitProfile;
        }
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
        if (self.identity.feature_ro_compat != expected_ro) return error.UnsupportedCommitProfile;
        return self.identity.feature_ro_compat & optional;
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
    _ = try fs.commit();
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
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = staged_alias, .data = "staged-alias" });
    try fs.importHostTreeWithManifest(host_tree_path, .{}, &host_manifest);
    const staged_target = try fs.read(allocator, "/etc/void", 64);
    defer allocator.free(staged_target);
    try std.testing.expectEqualStrings("staged-alias", staged_target);
    try std.testing.expectEqual(Kind.hardlink, (try fs.stat("/usr/bin/void-alias")).kind);
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
    try std.testing.expectEqualStrings("staged-alias", alias_bytes);
    try fs.write("/usr/bin/void-alias", "shared", null);
    const shared_target = try fs.read(allocator, "/etc/void", 64);
    defer allocator.free(shared_target);
    try std.testing.expectEqualStrings("shared", shared_target);
    try std.testing.expectEqual(Kind.hardlink, (try fs.stat("/usr/bin/void-alias")).kind);
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
    try std.testing.expectEqual(@as(u16, 0), (try reopened.stat("/etc/void")).metadata.mode);
    try std.testing.expectEqual(@as(usize, 3), (try reopened.stat("/")).metadata.xattrs.len);
    try std.testing.expectEqual(
        @as(usize, 1),
        (try reopened.stat("/etc/sparse")).payload.content.sparse_extents.len,
    );
    try std.testing.expectEqual(Kind.char_device, (try reopened.stat("/dev/null")).kind);
    try std.testing.expectEqual(Kind.fifo, (try reopened.stat("/var/fifo")).kind);
    try std.testing.expectEqual(Kind.hardlink, (try reopened.stat("/usr/bin/void-alias")).kind);
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
