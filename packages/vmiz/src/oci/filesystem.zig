//! Secure rootfs extraction for OCI layer entries.
const std = @import("std");
const builtin = @import("builtin");
const snapshot = @import("snapshot.zig");
const tar = @import("../tar.zig");

const Io = std.Io;

pub const Options = struct {
    preserve_ownership: bool = false,
};

const Node = struct {
    kind: tar.Kind,
    generation: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: tar.Timestamp,
    explicit: bool,
};

pub const Extractor = struct {
    allocator: std.mem.Allocator,
    io: Io,
    root: Io.Dir,
    options: Options,
    nodes: std.StringHashMap(Node),
    generation: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        root: Io.Dir,
        options: Options,
    ) Extractor {
        return .{
            .allocator = allocator,
            .io = io,
            .root = root,
            .options = options,
            .nodes = std.StringHashMap(Node).init(allocator),
        };
    }

    pub fn deinit(self: *Extractor) void {
        var iterator = self.nodes.keyIterator();
        while (iterator.next()) |path| self.allocator.free(path.*);
        self.nodes.deinit();
        self.* = undefined;
    }

    pub fn beginLayer(self: *Extractor) !void {
        self.generation = std.math.add(u64, self.generation, 1) catch
            return error.TooManyLayers;
    }

    pub fn apply(
        self: *Extractor,
        archive: *tar.StreamReader,
        entry: tar.StreamEntry,
    ) !void {
        if (self.generation == 0) return error.LayerNotStarted;
        const path = try normalizePath(self.allocator, entry.path);
        defer self.allocator.free(path);

        if (path.len == 0) {
            if (entry.kind != .directory) return error.InvalidLayerPath;
            try self.putNode("", entry, true);
            return;
        }

        const parent = parentPath(path);
        const basename = baseName(path);
        if (std.mem.eql(u8, basename, ".wh..wh..opq")) {
            try validateWhiteout(entry);
            try self.removeLowerDescendants(parent);
            return;
        }
        if (std.mem.startsWith(u8, basename, ".wh.")) {
            try validateWhiteout(entry);
            if (basename.len == 4) return error.InvalidWhiteout;
            const target = try joinPath(self.allocator, parent, basename[4..]);
            defer self.allocator.free(target);
            try self.removeLowerPath(target);
            return;
        }

        try self.ensureParents(parent);
        switch (entry.kind) {
            .directory => try self.applyDirectory(path, entry),
            .file => try self.applyFile(path, archive, entry),
            .symlink => try self.applySymlink(path, entry),
            .hardlink => try self.applyHardlink(path, entry),
            .fifo, .character_device, .block_device => try self.applySpecial(path, entry),
        }
    }

    pub fn finish(self: *Extractor) !void {
        var paths = std.array_list.Managed([]const u8).init(self.allocator);
        defer paths.deinit();
        var iterator = self.nodes.iterator();
        while (iterator.next()) |item| {
            if (item.value_ptr.kind == .directory and item.value_ptr.explicit) {
                try paths.append(item.key_ptr.*);
            }
        }
        std.mem.sort([]const u8, paths.items, {}, deeperPathFirst);
        for (paths.items) |path| {
            const node = self.nodes.get(path).?;
            try self.applyMetadata(path, node);
        }
    }

    pub fn overlaySnapshot(self: *const Extractor, entries: []snapshot.Entry) void {
        for (entries) |*entry| {
            const node = self.nodes.get(entry.path) orelse continue;
            entry.uid = node.uid;
            entry.gid = node.gid;
        }
    }

    fn applyDirectory(
        self: *Extractor,
        path: []const u8,
        entry: tar.StreamEntry,
    ) !void {
        if (self.nodes.get(path)) |existing| {
            if (existing.kind != .directory) {
                try self.removePathAndDescendants(path);
            }
        }
        var parent = try self.openParent(path, true);
        defer parent.close(self.io);
        parent.dir.createDir(self.io, parent.basename, directoryPermissions(0o755)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        try self.putNode(path, entry, true);
        try self.applyXattrs(path, entry);
    }

    fn applyFile(
        self: *Extractor,
        path: []const u8,
        archive: *tar.StreamReader,
        entry: tar.StreamEntry,
    ) !void {
        try self.removePathAndDescendants(path);
        var parent = try self.openParent(path, true);
        defer parent.close(self.io);
        var file = try parent.dir.createFile(self.io, parent.basename, .{
            .exclusive = true,
            .permissions = filePermissions(0o600),
        });
        defer file.close(self.io);
        var buffer: [64 * 1024]u8 = undefined;
        while (true) {
            const count = try archive.readEntry(&buffer);
            if (count == 0) break;
            try file.writeStreamingAll(self.io, buffer[0..count]);
        }
        try file.setOwner(
            self.io,
            if (self.options.preserve_ownership) entry.uid else null,
            if (self.options.preserve_ownership) entry.gid else null,
        );
        try file.setPermissions(self.io, filePermissions(@intCast(entry.mode & 0o7777)));
        try self.setXattrsFile(file, entry.xattrs);
        try file.setTimestamps(self.io, .{
            .modify_timestamp = .{ .new = timestamp(entry.mtime) },
        });
        try self.putNode(path, entry, true);
    }

    fn applySymlink(
        self: *Extractor,
        path: []const u8,
        entry: tar.StreamEntry,
    ) !void {
        const link_name = entry.link_name orelse return error.InvalidLayerPath;
        try self.removePathAndDescendants(path);
        var parent = try self.openParent(path, true);
        defer parent.close(self.io);
        try parent.dir.symLink(self.io, link_name, parent.basename, .{});
        try self.putNode(path, entry, true);
        if (entry.xattrs.len != 0) return error.UnsupportedSymlinkXattr;
        try self.applyMetadata(path, self.nodes.get(path).?);
    }

    fn applyHardlink(
        self: *Extractor,
        path: []const u8,
        entry: tar.StreamEntry,
    ) !void {
        const raw_target = entry.link_name orelse return error.InvalidLayerPath;
        const target = try normalizePath(self.allocator, raw_target);
        defer self.allocator.free(target);
        if (target.len == 0) return error.InvalidLayerPath;
        const target_node = self.nodes.get(target) orelse return error.InvalidHardlink;
        if (target_node.kind == .directory) {
            return error.InvalidHardlink;
        }

        try self.removePathAndDescendants(path);
        var old_parent = try self.openParent(target, false);
        defer old_parent.close(self.io);
        var new_parent = try self.openParent(path, true);
        defer new_parent.close(self.io);
        try Io.Dir.hardLink(
            old_parent.dir,
            old_parent.basename,
            new_parent.dir,
            new_parent.basename,
            self.io,
            .{ .follow_symlinks = false },
        );
        try self.putNode(path, entry, true);
        self.nodes.getPtr(path).?.kind = target_node.kind;
        if (target_node.kind == .symlink and entry.xattrs.len != 0) {
            return error.UnsupportedSymlinkXattr;
        }
        if (target_node.kind == .fifo or
            target_node.kind == .character_device or
            target_node.kind == .block_device)
        {
            try self.setXattrsAt(new_parent.dir, new_parent.basename, entry.xattrs);
        } else {
            try self.applyXattrs(path, entry);
        }
        try self.applyMetadata(path, self.nodes.get(path).?);
    }

    fn applySpecial(
        self: *Extractor,
        path: []const u8,
        entry: tar.StreamEntry,
    ) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedEntryKind;
        try self.removePathAndDescendants(path);
        var parent = try self.openParent(path, true);
        defer parent.close(self.io);
        const name = try self.allocator.dupeZ(u8, parent.basename);
        defer self.allocator.free(name);
        const linux = std.os.linux;
        const kind_mode: u32 = switch (entry.kind) {
            .fifo => linux.S.IFIFO,
            .character_device => linux.S.IFCHR,
            .block_device => linux.S.IFBLK,
            else => unreachable,
        };
        const device = try linuxDevice(entry.device_major, entry.device_minor);
        switch (linux.errno(linux.mknodat(
            parent.dir.handle,
            name.ptr,
            kind_mode | @as(u32, @intCast(entry.mode & 0o7777)),
            device,
        ))) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.PermissionDenied,
            else => return error.SpecialFileCreationFailed,
        }
        try self.putNode(path, entry, true);
        try self.setXattrsAt(parent.dir, parent.basename, entry.xattrs);
        try self.applyMetadata(path, self.nodes.get(path).?);
    }

    fn applyXattrs(
        self: *Extractor,
        path: []const u8,
        entry: tar.StreamEntry,
    ) !void {
        if (entry.xattrs.len == 0) return;
        var parent = try self.openParent(path, false);
        defer parent.close(self.io);
        var file = try parent.dir.openFile(self.io, parent.basename, .{
            .allow_directory = true,
            .follow_symlinks = false,
        });
        defer file.close(self.io);
        try self.setXattrsFile(file, entry.xattrs);
    }

    fn setXattrsFile(
        self: *Extractor,
        file: Io.File,
        xattrs: []const tar.Xattr,
    ) !void {
        if (xattrs.len == 0) return;
        if (builtin.os.tag != .linux) return error.UnsupportedXattr;
        const linux = std.os.linux;
        for (xattrs) |xattr| {
            const name = try self.allocator.dupeZ(u8, xattr.name);
            defer self.allocator.free(name);
            switch (linux.errno(linux.fsetxattr(
                file.handle,
                name.ptr,
                xattr.value.ptr,
                xattr.value.len,
                0,
            ))) {
                .SUCCESS => {},
                .ACCES, .PERM => return error.PermissionDenied,
                else => return error.SetXattrFailed,
            }
        }
    }

    fn setXattrsAt(
        self: *Extractor,
        dir: Io.Dir,
        path: []const u8,
        xattrs: []const tar.Xattr,
    ) !void {
        if (xattrs.len == 0) return;
        if (builtin.os.tag != .linux) return error.UnsupportedXattr;
        const proc_path = try std.fmt.allocPrintSentinel(
            self.allocator,
            "/proc/self/fd/{d}/{s}",
            .{ dir.handle, path },
            0,
        );
        defer self.allocator.free(proc_path);
        const linux = std.os.linux;
        for (xattrs) |xattr| {
            const name = try self.allocator.dupeZ(u8, xattr.name);
            defer self.allocator.free(name);
            switch (linux.errno(linux.setxattr(
                proc_path.ptr,
                name.ptr,
                xattr.value.ptr,
                xattr.value.len,
                0,
            ))) {
                .SUCCESS => {},
                .ACCES, .PERM => return error.PermissionDenied,
                else => return error.SetXattrFailed,
            }
        }
    }

    fn ensureParents(self: *Extractor, path: []const u8) !void {
        if (path.len == 0) return;
        var cursor: usize = 0;
        while (true) {
            const slash = std.mem.indexOfScalarPos(u8, path, cursor, '/');
            const parent = if (slash) |index| path[0..index] else path;
            if (self.nodes.get(parent)) |existing| {
                if (existing.kind != .directory) {
                    try self.removePathAndDescendants(parent);
                    try self.createSyntheticDirectory(parent);
                }
            } else {
                try self.createSyntheticDirectory(parent);
            }
            if (slash == null) break;
            cursor = slash.? + 1;
        }
    }

    fn createSyntheticDirectory(self: *Extractor, path: []const u8) !void {
        var parent = try self.openParent(path, true);
        defer parent.close(self.io);
        parent.dir.createDir(self.io, parent.basename, directoryPermissions(0o755)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const synthetic = tar.StreamEntry{
            .path = path,
            .kind = .directory,
            .mode = 0o755,
            .uid = 0,
            .gid = 0,
            .mtime = .{},
            .size = 0,
            .link_name = null,
            .device_major = 0,
            .device_minor = 0,
            .xattrs = &.{},
        };
        try self.putNode(path, synthetic, false);
    }

    fn removeLowerPath(self: *Extractor, path: []const u8) !void {
        const node = self.nodes.get(path) orelse return;
        if (node.generation == self.generation) return;
        try self.removeLower(path, true);
    }

    fn removeLowerDescendants(self: *Extractor, path: []const u8) !void {
        try self.removeLower(path, false);
    }

    fn removeLower(
        self: *Extractor,
        path: []const u8,
        include_path: bool,
    ) !void {
        var doomed = std.array_list.Managed([]const u8).init(self.allocator);
        defer doomed.deinit();
        var iterator = self.nodes.iterator();
        while (iterator.next()) |item| {
            const candidate = item.key_ptr.*;
            if (item.value_ptr.generation == self.generation) continue;
            if ((include_path and std.mem.eql(u8, candidate, path)) or
                isDescendant(candidate, path))
            {
                try doomed.append(candidate);
            }
        }
        std.mem.sort([]const u8, doomed.items, {}, deeperPathFirst);
        for (doomed.items) |candidate| {
            if (self.hasUpperDescendant(candidate)) {
                const node = self.nodes.getPtr(candidate) orelse continue;
                node.* = .{
                    .kind = .directory,
                    .generation = self.generation,
                    .mode = 0o755,
                    .uid = 0,
                    .gid = 0,
                    .mtime = .{},
                    .explicit = false,
                };
                continue;
            }
            try self.removeFilesystemPath(candidate);
            if (self.nodes.fetchRemove(candidate)) |removed| {
                self.allocator.free(removed.key);
            }
        }
    }

    fn hasUpperDescendant(self: *Extractor, path: []const u8) bool {
        var iterator = self.nodes.iterator();
        while (iterator.next()) |item| {
            if (item.value_ptr.generation == self.generation and
                isDescendant(item.key_ptr.*, path))
            {
                return true;
            }
        }
        return false;
    }

    fn removePathAndDescendants(self: *Extractor, path: []const u8) !void {
        var doomed = std.array_list.Managed([]const u8).init(self.allocator);
        defer doomed.deinit();
        var iterator = self.nodes.iterator();
        while (iterator.next()) |item| {
            if (std.mem.eql(u8, item.key_ptr.*, path) or
                isDescendant(item.key_ptr.*, path))
            {
                try doomed.append(item.key_ptr.*);
            }
        }
        std.mem.sort([]const u8, doomed.items, {}, deeperPathFirst);
        for (doomed.items) |candidate| {
            try self.removeFilesystemPath(candidate);
            if (self.nodes.fetchRemove(candidate)) |removed| {
                self.allocator.free(removed.key);
            }
        }
    }

    fn removeFilesystemPath(self: *Extractor, path: []const u8) !void {
        if (path.len == 0) return;
        var parent = try self.openParent(path, false);
        defer parent.close(self.io);
        const stat = parent.dir.statFile(
            self.io,
            parent.basename,
            .{ .follow_symlinks = false },
        ) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        if (stat.kind == .directory) {
            try parent.dir.deleteTree(self.io, parent.basename);
        } else {
            try parent.dir.deleteFile(self.io, parent.basename);
        }
    }

    fn applyMetadata(self: *Extractor, path: []const u8, node: Node) !void {
        if (node.kind == .symlink) {
            var parent = try self.openParent(path, false);
            defer parent.close(self.io);
            if (self.options.preserve_ownership) {
                if (builtin.os.tag != .linux) return error.UnsupportedSymlinkOwnership;
                const name = try self.allocator.dupeZ(u8, parent.basename);
                defer self.allocator.free(name);
                const linux = std.os.linux;
                switch (linux.errno(linux.fchownat(
                    parent.dir.handle,
                    name.ptr,
                    node.uid,
                    node.gid,
                    linux.AT.SYMLINK_NOFOLLOW,
                ))) {
                    .SUCCESS => {},
                    .ACCES, .PERM => return error.PermissionDenied,
                    else => return error.SymlinkOwnershipFailed,
                }
            }
            try parent.dir.setTimestamps(self.io, parent.basename, .{
                .follow_symlinks = false,
                .modify_timestamp = .{ .new = timestamp(node.mtime) },
            });
            return;
        }
        if (node.kind == .fifo or
            node.kind == .character_device or
            node.kind == .block_device)
        {
            if (builtin.os.tag != .linux) return error.UnsupportedEntryKind;
            var parent = try self.openParent(path, false);
            defer parent.close(self.io);
            if (self.options.preserve_ownership) {
                const name = try self.allocator.dupeZ(u8, parent.basename);
                defer self.allocator.free(name);
                const linux = std.os.linux;
                switch (linux.errno(linux.fchownat(
                    parent.dir.handle,
                    name.ptr,
                    node.uid,
                    node.gid,
                    0,
                ))) {
                    .SUCCESS => {},
                    .ACCES, .PERM => return error.PermissionDenied,
                    else => return error.SpecialFileOwnershipFailed,
                }
            }
            try parent.dir.setFilePermissions(
                self.io,
                parent.basename,
                filePermissions(@intCast(node.mode & 0o7777)),
                .{},
            );
            try parent.dir.setTimestamps(self.io, parent.basename, .{
                .modify_timestamp = .{ .new = timestamp(node.mtime) },
            });
            return;
        }
        const file = if (path.len == 0)
            try self.root.openFile(self.io, ".", .{
                .allow_directory = true,
                .follow_symlinks = false,
            })
        else blk: {
            var parent = try self.openParent(path, false);
            defer parent.close(self.io);
            break :blk try parent.dir.openFile(self.io, parent.basename, .{
                .allow_directory = true,
                .follow_symlinks = false,
            });
        };

        defer file.close(self.io);
        if (self.options.preserve_ownership) {
            try file.setOwner(self.io, node.uid, node.gid);
        }
        try file.setPermissions(
            self.io,
            if (node.kind == .directory)
                directoryPermissions(@intCast(node.mode & 0o7777))
            else
                filePermissions(@intCast(node.mode & 0o7777)),
        );
        try file.setTimestamps(self.io, .{
            .modify_timestamp = .{ .new = timestamp(node.mtime) },
        });
    }

    fn putNode(
        self: *Extractor,
        path: []const u8,
        entry: tar.StreamEntry,
        explicit: bool,
    ) !void {
        if (self.nodes.getPtr(path)) |node| {
            node.* = nodeFromEntry(entry, self.generation, explicit);
            return;
        }
        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        try self.nodes.put(
            owned_path,
            nodeFromEntry(entry, self.generation, explicit),
        );
    }

    fn openParent(
        self: *Extractor,
        path: []const u8,
        create: bool,
    ) !Parent {
        const parent_path = parentPath(path);
        const basename = baseName(path);
        if (basename.len == 0) return error.InvalidLayerPath;
        if (parent_path.len == 0) {
            return .{ .dir = self.root, .basename = basename, .owned = false };
        }

        var current = self.root;
        var current_owned = false;
        errdefer if (current_owned) current.close(self.io);
        var components = std.mem.splitScalar(u8, parent_path, '/');
        while (components.next()) |component| {
            const next = current.openDir(self.io, component, .{
                .follow_symlinks = false,
            }) catch |err| switch (err) {
                error.FileNotFound => blk: {
                    if (!create) return err;
                    try current.createDir(self.io, component, directoryPermissions(0o755));
                    break :blk try current.openDir(self.io, component, .{
                        .follow_symlinks = false,
                    });
                },
                else => return err,
            };

            if (current_owned) current.close(self.io);
            current = next;
            current_owned = true;
        }
        return .{ .dir = current, .basename = basename, .owned = true };
    }
};

fn directoryPermissions(mode: u16) Io.File.Permissions {
    return switch (builtin.os.tag) {
        .windows => .default_dir,
        else => .fromMode(mode),
    };
}

fn filePermissions(mode: u16) Io.File.Permissions {
    return switch (builtin.os.tag) {
        .windows => .default_file,
        else => .fromMode(mode),
    };
}

fn validateWhiteout(entry: tar.StreamEntry) !void {
    if (entry.kind != .file or
        entry.size != 0 or
        entry.link_name != null or
        entry.xattrs.len != 0)
    {
        return error.InvalidWhiteout;
    }
}

fn linuxDevice(major: u32, minor: u32) !u32 {
    if (major > 0xfff or minor > 0xfffff) return error.InvalidDeviceNumber;
    return (minor & 0xff) |
        ((major & 0xfff) << 8) |
        ((minor & 0xfffff00) << 12);
}

const Parent = struct {
    dir: Io.Dir,
    basename: []const u8,
    owned: bool,

    fn close(self: Parent, io: Io) void {
        if (self.owned) self.dir.close(io);
    }
};

fn nodeFromEntry(entry: tar.StreamEntry, generation: u64, explicit: bool) Node {
    return .{
        .kind = entry.kind,
        .generation = generation,
        .mode = entry.mode,
        .uid = entry.uid,
        .gid = entry.gid,
        .mtime = entry.mtime,
        .explicit = explicit,
    };
}

fn normalizePath(allocator: std.mem.Allocator, raw_path: []const u8) ![]u8 {
    if (raw_path.len > 0 and raw_path[0] == '/') return error.InvalidLayerPath;
    var out = Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    var first = true;
    var components = std.mem.splitScalar(u8, raw_path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) return error.InvalidLayerPath;
        if (!first) try out.writer.writeByte('/');
        try out.writer.writeAll(component);
        first = false;
    }
    return out.toOwnedSlice();
}

fn timestamp(value: tar.Timestamp) Io.Timestamp {
    return .fromNanoseconds(
        @as(i96, value.seconds) * std.time.ns_per_s + value.nanoseconds,
    );
}

fn parentPath(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "";
    return path[0..slash];
}

fn baseName(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[slash + 1 ..];
}

fn joinPath(
    allocator: std.mem.Allocator,
    parent: []const u8,
    child: []const u8,
) ![]u8 {
    if (parent.len == 0) return allocator.dupe(u8, child);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent, child });
}

fn isDescendant(candidate: []const u8, parent: []const u8) bool {
    if (parent.len == 0) return candidate.len > 0;
    return candidate.len > parent.len and
        std.mem.startsWith(u8, candidate, parent) and
        candidate[parent.len] == '/';
}

fn deeperPathFirst(_: void, left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return left.len > right.len;
    return std.mem.lessThan(u8, left, right);
}

fn applyTestArchive(extractor: *Extractor, bytes: []const u8) !void {
    var input = Io.Reader.fixed(bytes);
    var archive = tar.StreamReader.init(extractor.allocator, &input, .{});
    defer archive.deinit();
    while (try archive.next()) |entry| try extractor.apply(&archive, entry);
}

fn cleanupOrderedLayerTest(io: Io, root_path: []const u8) void {
    var root = Io.Dir.cwd().openDir(io, root_path, .{}) catch return;
    if (root.openFile(io, "etc", .{})) |etc| {
        var writable = etc;
        writable.setPermissions(io, .fromMode(0o755)) catch {};
        writable.close(io);
    } else |_| {}
    root.close(io);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
}

test "extractor applies ordered layers whiteouts hardlinks and deferred directories" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root_path = "test-oci-filesystem-root";
    defer cleanupOrderedLayerTest(io, root_path);
    cleanupOrderedLayerTest(io, root_path);
    try Io.Dir.cwd().createDir(io, root_path, .default_dir);
    var root = try Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);

    var extractor = Extractor.init(allocator, io, root, .{});
    defer extractor.deinit();

    var lower = Io.Writer.Allocating.init(allocator);
    defer lower.deinit();
    var lower_writer = tar.Writer.init(&lower.writer);
    try lower_writer.writeEntry(.{
        .path = "etc",
        .kind = .directory,
        .mode = 0o555,
        .mtime = .{ .seconds = 100 },
    });
    try lower_writer.writeFile("etc/base", 0o644, "lower");
    try lower_writer.writeFile("opaque/old", 0o644, "old");
    try lower_writer.finish();
    try extractor.beginLayer();
    try applyTestArchive(&extractor, lower.written());

    var upper = Io.Writer.Allocating.init(allocator);
    defer upper.deinit();
    var upper_writer = tar.Writer.init(&upper.writer);
    try upper_writer.writeFile("etc/new", 0o600, "upper");
    try upper_writer.writeEntry(.{
        .path = "etc/new-link",
        .kind = .hardlink,
        .mode = 0o600,
        .link_name = "etc/new",
    });
    try upper_writer.writeEntry(.{
        .path = "etc/.wh.base",
        .kind = .file,
        .mode = 0o000,
    });
    try upper_writer.writeFile("opaque/new", 0o644, "new");
    try upper_writer.writeEntry(.{
        .path = "opaque/.wh..wh..opq",
        .kind = .file,
        .mode = 0o000,
    });
    try upper_writer.writeFile("late", 0o644, "kept");
    try upper_writer.writeEntry(.{
        .path = ".wh.late",
        .kind = .file,
        .mode = 0o000,
    });
    try upper_writer.finish();
    try extractor.beginLayer();
    try applyTestArchive(&extractor, upper.written());
    try extractor.finish();

    const new_bytes = try root.readFileAlloc(io, "etc/new", allocator, .limited(16));
    defer allocator.free(new_bytes);
    try std.testing.expectEqualStrings("upper", new_bytes);
    try std.testing.expectError(
        error.FileNotFound,
        root.statFile(io, "etc/base", .{}),
    );
    try std.testing.expectError(
        error.FileNotFound,
        root.statFile(io, "opaque/old", .{}),
    );
    _ = try root.statFile(io, "opaque/new", .{});
    _ = try root.statFile(io, "late", .{});
    const original = try root.statFile(io, "etc/new", .{});
    const linked = try root.statFile(io, "etc/new-link", .{});
    try std.testing.expectEqual(original.inode, linked.inode);
    const etc = try root.statFile(io, "etc", .{});
    try std.testing.expectEqual(@as(u32, 0o555), @intFromEnum(etc.permissions) & 0o7777);
    try std.testing.expectEqual(@as(i96, 100 * std.time.ns_per_s), etc.mtime.nanoseconds);
}

test "extractor replaces symlink parents instead of following them" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root_path = "test-oci-filesystem-symlink-root";
    const outside_path = "test-oci-filesystem-outside";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    try Io.Dir.cwd().createDir(io, root_path, .default_dir);
    try Io.Dir.cwd().createDir(io, outside_path, .default_dir);
    var root = try Io.Dir.cwd().openDir(io, root_path, .{});
    defer root.close(io);

    var bytes = Io.Writer.Allocating.init(allocator);
    defer bytes.deinit();
    var writer = tar.Writer.init(&bytes.writer);
    try writer.writeEntry(.{
        .path = "jump",
        .kind = .symlink,
        .mode = 0o777,
        .link_name = "../test-oci-filesystem-outside",
    });
    try writer.writeFile("jump/pwn", 0o644, "contained");
    try writer.finish();

    var extractor = Extractor.init(allocator, io, root, .{});
    defer extractor.deinit();
    try extractor.beginLayer();
    try applyTestArchive(&extractor, bytes.written());
    try extractor.finish();
    _ = try root.statFile(io, "jump/pwn", .{});
    var outside = try Io.Dir.cwd().openDir(io, outside_path, .{});
    defer outside.close(io);
    try std.testing.expectError(
        error.FileNotFound,
        outside.statFile(io, "pwn", .{}),
    );
}

test "extractor preserves FIFOs and regular-file xattrs" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root_path = "test-oci-filesystem-metadata-root";
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDir(io, root_path, .default_dir);
    var root = try Io.Dir.cwd().openDir(io, root_path, .{});
    defer root.close(io);

    var bytes = Io.Writer.Allocating.init(allocator);
    defer bytes.deinit();
    var writer = tar.Writer.init(&bytes.writer);
    try writer.beginEntry(.{
        .path = "with-xattr",
        .kind = .file,
        .mode = 0o640,
        .size = 4,
        .xattrs = &.{.{ .name = "user.vmiz", .value = "kept" }},
    });
    try writer.writeAll("data");
    try writer.endEntry();
    try writer.writeEntry(.{
        .path = "pipe",
        .kind = .fifo,
        .mode = 0o620,
    });
    try writer.finish();

    var extractor = Extractor.init(allocator, io, root, .{});
    defer extractor.deinit();
    try extractor.beginLayer();
    try applyTestArchive(&extractor, bytes.written());
    try extractor.finish();

    const pipe = try root.statFile(io, "pipe", .{ .follow_symlinks = false });
    try std.testing.expectEqual(Io.File.Kind.named_pipe, pipe.kind);
    var file = try root.openFile(io, "with-xattr", .{});
    defer file.close(io);
    const name = "user.vmiz";
    var value: [16]u8 = undefined;
    const result = std.os.linux.fgetxattr(
        file.handle,
        name,
        &value,
        value.len,
    );
    try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(result));
    try std.testing.expectEqualStrings("kept", value[0..result]);
}
