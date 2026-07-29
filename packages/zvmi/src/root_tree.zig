const std = @import("std");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const limits_mod = @import("limits.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

/// The tree limits and their conservative defaults live in `limits.zig`
/// alongside the flag that raises each one and the diagnostic that reports a
/// breach, so a limit cannot exist without a documented way out of it.
pub const Limits = limits_mod.Limits;

pub const Kind = enum {
    directory,
    file,
    symlink,
    hardlink,
    block_device,
    char_device,
    fifo,
};

pub const Metadata = struct {
    mode: u16,
    uid: u32 = 0,
    gid: u32 = 0,
    atime: ?i64 = null,
    mtime: ?i64 = null,
    ctime: ?i64 = null,
    xattrs: []const ext4.Xattr = &.{},
};

pub const Device = struct {
    major: u32,
    minor: u32,
};

const Content = struct {
    io: Io,
    size: u64,
    sha256: [32]u8,
    source: union(enum) {
        spooled: struct {
            file: Io.File,
            offset: u64,
        },
        memory: []u8,
        borrowed: ext4.FileTreeView.ContentReader,
        host_path: []u8,
    },

    pub fn readAt(self: Content, buffer: []u8, offset: u64) !usize {
        if (offset >= self.size) return 0;
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), self.size - offset));
        return switch (self.source) {
            .spooled => |spooled| spooled.file.readPositionalAll(
                self.io,
                buffer[0..wanted],
                spooled.offset + offset,
            ),
            .memory => |bytes| blk: {
                @memcpy(buffer[0..wanted], bytes[@intCast(offset)..][0..wanted]);
                break :blk wanted;
            },
            .borrowed => |reader| reader.readAt(buffer[0..wanted], offset),
            .host_path => |path| blk: {
                const file = try Io.Dir.cwd().openFile(self.io, path, .{});
                defer file.close(self.io);
                break :blk try file.readPositionalAll(self.io, buffer[0..wanted], offset);
            },
        };
    }
};

const Payload = union(enum) {
    none,
    content: Content,
    hardlink_target: []u8,
    device: Device,
};

const Node = struct {
    path: []u8,
    kind: Kind,
    metadata: Metadata,
    owned_xattrs: []ext4.OwnedXattr,
    payload: Payload,

    pub fn size(self: Node) u64 {
        return switch (self.payload) {
            .content => |content| content.size,
            .hardlink_target => |target| target.len,
            .none, .device => 0,
        };
    }
};

pub const ContentView = struct {
    size: u64,
    sha256: [32]u8,
};

pub const NodePayload = union(enum) {
    none,
    content: ContentView,
    hardlink_target: []const u8,
    device: Device,
};

pub const NodeView = struct {
    path: []const u8,
    kind: Kind,
    metadata: Metadata,
    payload: NodePayload,

    pub fn size(self: NodeView) u64 {
        return switch (self.payload) {
            .content => |content| content.size,
            .hardlink_target => |target| target.len,
            .none, .device => 0,
        };
    }
};

pub const RootMetadata = struct {
    mode: u16 = 0o755,
    uid: u32 = 0,
    gid: u32 = 0,
    atime: ?i64 = null,
    mtime: ?i64 = null,
    ctime: ?i64 = null,
};

pub const FatMetadataPolicy = enum {
    strict,
    lossy_posix_metadata,
};

pub const FatPopulateOptions = struct {
    metadata_policy: FatMetadataPolicy = .strict,
};

pub const RootTree = struct {
    allocator: Allocator,
    io: Io,
    spool_path: ?[]u8,
    spool: ?Io.File,
    storage: enum { spooled, memory },
    spool_len: u64 = 0,
    nodes: std.array_list.Managed(Node),
    limits: Limits,
    /// Optional sink for the peak measurements and the first limit breach.
    /// Assigned after `init` because it is the caller's, not the tree's, and
    /// must outlive the tree. Nothing is measured before the first node.
    diagnostic: ?*limits_mod.Diagnostic = null,
    root_metadata: RootMetadata = .{},
    iteration_index: usize = 0,
    sorted: bool = true,
    view: ext4.FileTreeView,

    pub fn init(
        allocator: Allocator,
        io: Io,
        spool_path: []const u8,
        limits: Limits,
    ) !RootTree {
        const owned_path = try allocator.dupe(u8, spool_path);
        errdefer allocator.free(owned_path);
        const spool = try Io.Dir.cwd().createFile(io, spool_path, .{
            .read = true,
            .truncate = true,
            .exclusive = true,
        });
        return .{
            .allocator = allocator,
            .io = io,
            .spool_path = owned_path,
            .spool = spool,
            .storage = .spooled,
            .nodes = .init(allocator),
            .limits = limits,
            .view = .{
                .ctx = undefined,
                .next_fn = nextExt4,
                .reset_fn = resetExt4,
            },
        };
    }

    pub fn initMemory(allocator: Allocator, io: Io, limits: Limits) RootTree {
        return .{
            .allocator = allocator,
            .io = io,
            .spool_path = null,
            .spool = null,
            .storage = .memory,
            .nodes = .init(allocator),
            .limits = limits,
            .view = .{
                .ctx = undefined,
                .next_fn = nextExt4,
                .reset_fn = resetExt4,
            },
        };
    }

    pub fn deinit(self: *RootTree) void {
        for (self.nodes.items) |*node| self.freeNode(node);
        self.nodes.deinit();
        if (self.spool) |spool| spool.close(self.io);
        if (self.spool_path) |path| {
            Io.Dir.cwd().deleteFile(self.io, path) catch {};
            self.allocator.free(path);
        }
        self.* = undefined;
    }

    pub fn rootMetadata(self: *const RootTree) RootMetadata {
        return self.root_metadata;
    }

    pub fn setRootMetadata(self: *RootTree, metadata: RootMetadata) void {
        self.root_metadata = metadata;
    }

    /// The peaks and breach observed so far, for callers that did not attach
    /// a diagnostic of their own.
    pub fn limitDiagnostic(self: *const RootTree) ?limits_mod.Diagnostic {
        const sink = self.diagnostic orelse return null;
        return sink.*;
    }

    pub fn setMetadata(self: *RootTree, path: []const u8, metadata: Metadata) !void {
        try validatePath(path, self.limits, self.diagnostic);
        const index = self.findIndex(path) orelse return error.MissingNode;
        const owned_xattrs = try self.dupeXattrs(metadata.xattrs);
        freeOwnedXattrs(self.allocator, self.nodes.items[index].owned_xattrs);
        self.nodes.items[index].owned_xattrs = owned_xattrs;
        self.nodes.items[index].metadata = metadata;
        self.nodes.items[index].metadata.xattrs = ownedXattrsView(owned_xattrs);
    }

    pub fn readFileAlloc(
        self: *const RootTree,
        allocator: Allocator,
        path: []const u8,
        max_bytes: u64,
    ) ![]u8 {
        const index = self.findIndex(path) orelse return error.MissingNode;
        const entry = self.nodes.items[index];
        if (entry.kind != .file) return error.NotRegularFile;
        if (entry.size() > max_bytes) return error.FileLimitExceeded;
        const length = std.math.cast(usize, entry.size()) orelse return error.FileLimitExceeded;
        const output = try allocator.alloc(u8, length);
        errdefer allocator.free(output);
        var offset: usize = 0;
        while (offset < output.len) {
            const count = try entry.payload.content.readAt(output[offset..], offset);
            if (count == 0) return error.UnexpectedSourceLength;
            offset += count;
        }
        return output;
    }

    pub fn putDirectory(self: *RootTree, path: []const u8, metadata: Metadata) !void {
        try self.putNode(path, .directory, metadata, .none);
    }

    pub fn putFileBytes(
        self: *RootTree,
        path: []const u8,
        bytes: []const u8,
        metadata: Metadata,
    ) !void {
        var reader = BytesReader{ .bytes = bytes };
        try self.putFileReader(path, bytes.len, .{
            .ctx = &reader,
            .read_at_fn = BytesReader.readAt,
        }, metadata);
    }

    pub fn putFileFromPath(
        self: *RootTree,
        path: []const u8,
        source_path: []const u8,
        metadata: Metadata,
    ) !void {
        const file = try Io.Dir.cwd().openFile(self.io, source_path, .{});
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return error.SourceNotRegularFile;
        if (self.storage == .memory) {
            const old_spool_len = self.spool_len;
            const content = self.referenceHostFile(file, source_path, stat.size) catch |err| {
                try self.rollbackSpool(old_spool_len);
                return err;
            };
            self.putNode(path, .file, metadata, .{ .content = content }) catch |err| {
                try self.rollbackSpool(old_spool_len);
                return err;
            };
            return;
        }
        var reader = FileReader{ .io = self.io, .file = file };
        try self.putFileReader(path, stat.size, .{
            .ctx = &reader,
            .read_at_fn = FileReader.readAt,
        }, metadata);
    }

    pub fn putFileReader(
        self: *RootTree,
        path: []const u8,
        size: u64,
        reader: ext4.FileTreeView.ContentReader,
        metadata: Metadata,
    ) !void {
        try validatePath(path, self.limits, self.diagnostic);
        try self.checkFileBytes(size);
        const old_spool_len = self.spool_len;
        const content = self.spoolContent(size, reader) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
        self.putNode(path, .file, metadata, .{ .content = content }) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
    }

    pub fn putSymlink(
        self: *RootTree,
        path: []const u8,
        target: []const u8,
        metadata: Metadata,
    ) !void {
        try validatePath(path, self.limits, self.diagnostic);
        try self.checkFileBytes(target.len);
        const old_spool_len = self.spool_len;
        var reader = BytesReader{ .bytes = target };
        const content = self.spoolContent(target.len, .{
            .ctx = &reader,
            .read_at_fn = BytesReader.readAt,
        }) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
        self.putNode(path, .symlink, metadata, .{ .content = content }) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
    }

    pub fn putHardlink(
        self: *RootTree,
        path: []const u8,
        target: []const u8,
        metadata: Metadata,
    ) !void {
        try validatePath(target, self.limits, self.diagnostic);
        const target_index = self.findIndex(target) orelse return error.MissingHardlinkTarget;
        if (self.nodes.items[target_index].kind != .file) return error.UnsupportedHardlinkTarget;
        if (pathEqualsOrDescendant(path, target) or pathEqualsOrDescendant(target, path)) {
            return error.HardlinkTargetRemovedByOverlay;
        }
        try self.putNode(
            path,
            .hardlink,
            metadata,
            .{ .hardlink_target = try self.allocator.dupe(u8, target) },
        );
    }

    pub fn putDevice(
        self: *RootTree,
        path: []const u8,
        kind: Kind,
        device: Device,
        metadata: Metadata,
    ) !void {
        if (kind != .block_device and kind != .char_device) return error.InvalidDeviceKind;
        try self.putNode(path, kind, metadata, .{ .device = device });
    }

    pub fn putFifo(self: *RootTree, path: []const u8, metadata: Metadata) !void {
        try self.putNode(path, .fifo, metadata, .none);
    }

    pub fn remove(self: *RootTree, path: []const u8) !bool {
        try validatePath(path, self.limits, self.diagnostic);
        const stable_path = try self.allocator.dupe(u8, path);
        defer self.allocator.free(stable_path);
        if (self.removalBreaksHardlinks(stable_path, true)) return error.HardlinkTargetInUse;
        return self.removeInternal(stable_path, true);
    }

    fn removeInternal(self: *RootTree, path: []const u8, recursive: bool) bool {
        var removed = false;
        var index: usize = 0;
        while (index < self.nodes.items.len) {
            if (std.mem.eql(u8, path, self.nodes.items[index].path) or
                (recursive and pathEqualsOrDescendant(path, self.nodes.items[index].path)))
            {
                var node = self.nodes.orderedRemove(index);
                self.freeNode(&node);
                removed = true;
            } else {
                index += 1;
            }
        }
        if (removed) self.sorted = false;
        return removed;
    }

    pub fn importExt4View(self: *RootTree, source: *ext4.FileTreeView) !void {
        try self.importExt4ViewMode(source, .owned);
    }

    /// Imports only paths and metadata while retaining read-only content
    /// readers supplied by `source`. The source must outlive this tree.
    pub fn importExt4ViewBorrowed(self: *RootTree, source: *ext4.FileTreeView) !void {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        try self.importExt4ViewMode(source, .borrowed);
    }

    fn importExt4ViewMode(
        self: *RootTree,
        source: *ext4.FileTreeView,
        mode: enum { owned, borrowed },
    ) !void {
        source.reset();
        while (try source.next()) |entry| {
            const metadata = Metadata{
                .mode = entry.mode,
                .uid = entry.uid,
                .gid = entry.gid,
                .xattrs = entry.xattrs,
            };
            switch (entry.kind) {
                .directory => try self.putDirectory(entry.path, metadata),
                .fifo => try self.putFifo(entry.path, metadata),
                .block_device, .char_device => try self.putDevice(
                    entry.path,
                    if (entry.kind == .block_device) .block_device else .char_device,
                    .{ .major = entry.device.major, .minor = entry.device.minor },
                    metadata,
                ),
                .hardlink => try self.putHardlink(entry.path, entry.hardlink_target, metadata),
                .file => {
                    const content = entry.content orelse if (entry.size == 0)
                        emptyContentReader()
                    else
                        return error.MissingContent;
                    if (mode == .owned) {
                        try self.putFileReader(entry.path, entry.size, content, metadata);
                    } else {
                        try self.putBorrowedContent(
                            entry.path,
                            .file,
                            entry.size,
                            content,
                            metadata,
                        );
                    }
                },
                .symlink => {
                    const content = entry.content orelse return error.MissingContent;
                    if (mode == .owned) {
                        try self.checkFileBytes(entry.size);
                        try validatePath(entry.path, self.limits, self.diagnostic);
                        const old_spool_len = self.spool_len;
                        const owned = self.spoolContent(entry.size, content) catch |err| {
                            try self.rollbackSpool(old_spool_len);
                            return err;
                        };
                        self.putNode(entry.path, .symlink, metadata, .{ .content = owned }) catch |err| {
                            try self.rollbackSpool(old_spool_len);
                            return err;
                        };
                    } else {
                        try self.putBorrowedContent(
                            entry.path,
                            .symlink,
                            entry.size,
                            content,
                            metadata,
                        );
                    }
                },
            }
        }
    }

    /// Imports a tree produced by the general ext4 importer. `FileTreeView`
    /// cannot carry timestamps, device numbers or hardlink targets, so the
    /// general tree is consumed directly rather than being squeezed through
    /// that interface and losing exactly the fidelity it exists to preserve.
    pub fn importExt4General(self: *RootTree, source: *ext4.GeneralTree) !void {
        try self.importExt4GeneralMode(source, .owned);
    }

    /// Imports paths and metadata while retaining read-only content readers
    /// owned by `source`, which must outlive this tree.
    pub fn importExt4GeneralBorrowed(self: *RootTree, source: *ext4.GeneralTree) !void {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        try self.importExt4GeneralMode(source, .borrowed);
    }

    fn importExt4GeneralMode(
        self: *RootTree,
        source: *ext4.GeneralTree,
        mode: enum { owned, borrowed },
    ) !void {
        self.setRootMetadata(.{
            .mode = source.root.mode,
            .uid = source.root.uid,
            .gid = source.root.gid,
            .atime = source.root.atime,
            .mtime = source.root.mtime,
            .ctime = source.root.ctime,
        });

        var index: usize = 0;
        while (index < source.nodeCount()) : (index += 1) {
            const entry = source.entryAt(index);
            const metadata = Metadata{
                .mode = entry.mode,
                .uid = entry.uid,
                .gid = entry.gid,
                .atime = entry.atime,
                .mtime = entry.mtime,
                .ctime = entry.ctime,
                .xattrs = entry.xattrs,
            };
            switch (entry.kind) {
                .directory => try self.putDirectory(entry.path, metadata),
                .fifo => try self.putFifo(entry.path, metadata),
                .block_device => try self.putDevice(entry.path, .block_device, .{
                    .major = entry.device.major,
                    .minor = entry.device.minor,
                }, metadata),
                .char_device => try self.putDevice(entry.path, .char_device, .{
                    .major = entry.device.major,
                    .minor = entry.device.minor,
                }, metadata),
                // The scanner always emits the content-bearing name before any
                // further link to it, so the target is already present.
                .hardlink => try self.putHardlink(entry.path, entry.hardlink_target, metadata),
                .file, .symlink => {
                    const kind: Kind = if (entry.kind == .file) .file else .symlink;
                    const content = entry.content orelse if (entry.size == 0)
                        emptyContentReader()
                    else
                        return error.MissingContent;
                    if (mode == .borrowed) {
                        try self.putBorrowedContent(
                            entry.path,
                            kind,
                            entry.size,
                            content,
                            metadata,
                        );
                        continue;
                    }
                    if (kind == .file) {
                        try self.putFileReader(entry.path, entry.size, content, metadata);
                        continue;
                    }
                    try self.checkFileBytes(entry.size);
                    try validatePath(entry.path, self.limits, self.diagnostic);
                    const old_spool_len = self.spool_len;
                    const owned = self.spoolContent(entry.size, content) catch |err| {
                        try self.rollbackSpool(old_spool_len);
                        return err;
                    };
                    self.putNode(entry.path, .symlink, metadata, .{ .content = owned }) catch |err| {
                        try self.rollbackSpool(old_spool_len);
                        return err;
                    };
                },
            }
        }
    }

    pub fn ext4View(self: *RootTree) !*ext4.FileTreeView {
        try self.sortAndValidate();
        self.iteration_index = 0;
        self.view = .{
            .ctx = self,
            .next_fn = nextExt4,
            .reset_fn = resetExt4,
        };
        return &self.view;
    }

    pub fn populateFat32(
        self: *RootTree,
        filesystem: *fat32.FileSystem,
        options: FatPopulateOptions,
    ) !void {
        try self.sortAndValidateRepresentable();
        try self.preflightFat32(options);

        for (self.nodes.items) |node| {
            switch (node.kind) {
                .directory => try filesystem.createDir(self.io, node.path),
                .file => try self.populateFatFile(filesystem, node),
                else => unreachable,
            }
        }
    }

    pub fn manifestDigest(self: *RootTree) ![32]u8 {
        try self.sortAndValidateRepresentable();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("zvmi-root-tree-v1\x00");
        hashInt(&hash, self.root_metadata.mode);
        hashInt(&hash, self.root_metadata.uid);
        hashInt(&hash, self.root_metadata.gid);
        hashOptionalInt(&hash, self.root_metadata.atime);
        hashOptionalInt(&hash, self.root_metadata.mtime);
        hashOptionalInt(&hash, self.root_metadata.ctime);
        for (self.nodes.items) |node| {
            hashString(&hash, node.path);
            hashInt(&hash, @intFromEnum(node.kind));
            hashInt(&hash, node.metadata.mode);
            hashInt(&hash, node.metadata.uid);
            hashInt(&hash, node.metadata.gid);
            hashOptionalInt(&hash, node.metadata.atime);
            hashOptionalInt(&hash, node.metadata.mtime);
            hashOptionalInt(&hash, node.metadata.ctime);
            for (node.owned_xattrs) |xattr| {
                hashString(&hash, xattr.name);
                hashString(&hash, xattr.value);
            }
            switch (node.payload) {
                .none => {},
                .content => |content| {
                    hashInt(&hash, content.size);
                    hash.update(&content.sha256);
                },
                .hardlink_target => |target| hashString(&hash, target),
                .device => |device| {
                    hashInt(&hash, device.major);
                    hashInt(&hash, device.minor);
                },
            }
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        return digest;
    }

    pub fn sortNodes(self: *RootTree) !void {
        try self.sortAndValidateRepresentable();
    }

    pub fn nodeCount(self: *const RootTree) usize {
        return self.nodes.items.len;
    }

    pub fn nodeView(self: *const RootTree, index: usize) NodeView {
        const node = self.nodes.items[index];
        return .{
            .path = node.path,
            .kind = node.kind,
            .metadata = node.metadata,
            .payload = switch (node.payload) {
                .none => .none,
                .content => |content| .{ .content = .{
                    .size = content.size,
                    .sha256 = content.sha256,
                } },
                .hardlink_target => |target| .{ .hardlink_target = target },
                .device => |device| .{ .device = device },
            },
        };
    }

    pub fn findNode(self: *const RootTree, path: []const u8) ?NodeView {
        const index = self.findIndex(path) orelse return null;
        return self.nodeView(index);
    }

    pub fn readNodeContent(self: *const RootTree, path: []const u8, buffer: []u8, offset: u64) !usize {
        const index = self.findIndex(path) orelse return error.MissingNode;
        return switch (self.nodes.items[index].payload) {
            .content => |content| content.readAt(buffer, offset),
            else => 0,
        };
    }

    fn putNode(
        self: *RootTree,
        path: []const u8,
        kind: Kind,
        metadata: Metadata,
        payload: Payload,
    ) anyerror!void {
        try validatePath(path, self.limits, self.diagnostic);
        var payload_owned = true;
        errdefer if (payload_owned) self.freePayload(payload);
        const owned_path = try self.allocator.dupe(u8, path);
        var path_owned = true;
        errdefer if (path_owned) self.allocator.free(owned_path);
        const owned_xattrs = try self.dupeXattrs(metadata.xattrs);
        var xattrs_owned = true;
        errdefer if (xattrs_owned) freeOwnedXattrs(self.allocator, owned_xattrs);

        var parents = try self.prepareParents(owned_path);
        defer {
            for (parents.items) |parent| {
                if (parent.path.len != 0) self.allocator.free(parent.path);
            }
            parents.deinit();
        }
        if (self.overlayBreaksHardlinks(owned_path, kind, parents.items)) {
            return error.HardlinkTargetInUse;
        }

        var remaining_nodes: usize = 0;
        var final_bytes = payloadSize(payload);
        for (self.nodes.items) |node| {
            if (removedByOverlay(node.path, owned_path, kind, parents.items)) continue;
            remaining_nodes += 1;
            final_bytes = std.math.add(u64, final_bytes, node.size()) catch return error.TotalContentLimitExceeded;
        }
        const additions = std.math.add(usize, parents.items.len, 1) catch
            return error.NodeLimitExceeded;
        const final_node_count = std.math.add(usize, remaining_nodes, additions) catch
            return error.NodeLimitExceeded;
        limits_mod.observe(self.diagnostic, .nodes, final_node_count);
        if (final_node_count > self.limits.max_nodes) {
            return limits_mod.exceeded(
                self.diagnostic,
                .nodes,
                final_node_count,
                self.limits.max_nodes,
            );
        }
        limits_mod.observe(self.diagnostic, .total_bytes, final_bytes);
        if (final_bytes > self.limits.max_total_bytes) {
            return limits_mod.exceeded(
                self.diagnostic,
                .total_bytes,
                final_bytes,
                self.limits.max_total_bytes,
            );
        }
        try self.nodes.ensureUnusedCapacity(parents.items.len + 1);

        for (parents.items) |*parent| {
            if (parent.replace_existing) _ = self.removeInternal(parent.path, true);
            self.nodes.appendAssumeCapacity(.{
                .path = parent.path,
                .kind = .directory,
                .metadata = .{ .mode = 0o755 },
                .owned_xattrs = &.{},
                .payload = .none,
            });
            parent.path = &.{};
        }
        _ = self.removeInternal(owned_path, kind != .directory);
        self.nodes.appendAssumeCapacity(.{
            .path = owned_path,
            .kind = kind,
            .metadata = .{
                .mode = metadata.mode,
                .uid = metadata.uid,
                .gid = metadata.gid,
                .atime = metadata.atime,
                .mtime = metadata.mtime,
                .ctime = metadata.ctime,
                .xattrs = ownedXattrsView(owned_xattrs),
            },
            .owned_xattrs = owned_xattrs,
            .payload = payload,
        });
        path_owned = false;
        xattrs_owned = false;
        payload_owned = false;
        self.sorted = false;
    }

    const ParentPlan = struct {
        path: []u8,
        replace_existing: bool,
    };

    fn prepareParents(self: *RootTree, path: []const u8) !std.array_list.Managed(ParentPlan) {
        var parents = std.array_list.Managed(ParentPlan).init(self.allocator);
        errdefer {
            for (parents.items) |parent| self.allocator.free(parent.path);
            parents.deinit();
        }
        var cursor: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, cursor, '/')) |slash| {
            const parent = path[0..slash];
            if (self.findIndex(parent)) |index| {
                if (self.nodes.items[index].kind != .directory) {
                    const owned_parent = try self.allocator.dupe(u8, parent);
                    parents.append(.{ .path = owned_parent, .replace_existing = true }) catch |err| {
                        self.allocator.free(owned_parent);
                        return err;
                    };
                }
            } else {
                const owned_parent = try self.allocator.dupe(u8, parent);
                parents.append(.{ .path = owned_parent, .replace_existing = false }) catch |err| {
                    self.allocator.free(owned_parent);
                    return err;
                };
            }
            cursor = slash + 1;
        }
        return parents;
    }

    fn checkFileBytes(self: *RootTree, size: u64) limits_mod.Error!void {
        limits_mod.observe(self.diagnostic, .file_bytes, size);
        if (size > self.limits.max_file_bytes) {
            return limits_mod.exceeded(
                self.diagnostic,
                .file_bytes,
                size,
                self.limits.max_file_bytes,
            );
        }
    }

    /// The spool holds a full copy of every imported byte, so this is also
    /// the scratch space the import needs on the workspace filesystem.
    fn checkSpoolBytes(self: *RootTree, end: u64) limits_mod.Error!void {
        limits_mod.observe(self.diagnostic, .spool_bytes, end);
        if (end > self.limits.max_spool_bytes) {
            return limits_mod.exceeded(
                self.diagnostic,
                .spool_bytes,
                end,
                self.limits.max_spool_bytes,
            );
        }
    }

    fn spoolContent(
        self: *RootTree,
        size: u64,
        reader: ext4.FileTreeView.ContentReader,
    ) !Content {
        const start = self.spool_len;
        const end = std.math.add(u64, start, size) catch return error.SpoolLimitExceeded;
        try self.checkSpoolBytes(end);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        const memory = if (self.storage == .memory) memory: {
            const length = std.math.cast(usize, size) orelse return error.SpoolLimitExceeded;
            break :memory try self.allocator.alloc(u8, length);
        } else null;
        errdefer if (memory) |bytes| self.allocator.free(bytes);
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < size) {
            const wanted: usize = @intCast(@min(@as(u64, buffer.len), size - offset));
            const got = reader.readAt(buffer[0..wanted], offset) catch return error.SourceReadFailed;
            if (got == 0 or got > wanted) return error.UnexpectedSourceLength;
            if (memory) |bytes| {
                @memcpy(bytes[@intCast(offset)..][0..got], buffer[0..got]);
            } else {
                try self.spool.?.writePositionalAll(self.io, buffer[0..got], start + offset);
            }
            hash.update(buffer[0..got]);
            offset += got;
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        self.spool_len = end;
        return .{
            .io = self.io,
            .size = size,
            .sha256 = digest,
            .source = if (memory) |bytes|
                .{ .memory = bytes }
            else
                .{ .spooled = .{ .file = self.spool.?, .offset = start } },
        };
    }

    fn rollbackSpool(self: *RootTree, length: u64) !void {
        if (self.spool) |spool| try spool.setLength(self.io, length);
        self.spool_len = length;
    }

    fn putBorrowedContent(
        self: *RootTree,
        path: []const u8,
        kind: Kind,
        size: u64,
        reader: ext4.FileTreeView.ContentReader,
        metadata: Metadata,
    ) !void {
        try self.checkFileBytes(size);
        try validatePath(path, self.limits, self.diagnostic);
        const old_spool_len = self.spool_len;
        const end = std.math.add(u64, old_spool_len, size) catch
            return error.SpoolLimitExceeded;
        try self.checkSpoolBytes(end);
        const digest = try hashContentReader(reader, size);
        self.spool_len = end;
        self.putNode(path, kind, metadata, .{ .content = .{
            .io = self.io,
            .size = size,
            .sha256 = digest,
            .source = .{ .borrowed = reader },
        } }) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
    }

    fn referenceHostFile(
        self: *RootTree,
        file: Io.File,
        path: []const u8,
        size: u64,
    ) !Content {
        try self.checkFileBytes(size);
        const end = std.math.add(u64, self.spool_len, size) catch
            return error.SpoolLimitExceeded;
        try self.checkSpoolBytes(end);
        var file_reader = FileReader{ .io = self.io, .file = file };
        const digest = try hashContentReader(.{
            .ctx = &file_reader,
            .read_at_fn = FileReader.readAt,
        }, size);
        const owned_path = try self.allocator.dupe(u8, path);
        self.spool_len = end;
        return .{
            .io = self.io,
            .size = size,
            .sha256 = digest,
            .source = .{ .host_path = owned_path },
        };
    }

    fn dupeXattrs(self: *RootTree, source: []const ext4.Xattr) ![]ext4.OwnedXattr {
        limits_mod.observe(self.diagnostic, .xattrs_per_node, source.len);
        if (source.len > self.limits.max_xattrs_per_node) {
            return limits_mod.exceeded(
                self.diagnostic,
                .xattrs_per_node,
                source.len,
                self.limits.max_xattrs_per_node,
            );
        }
        var total: usize = 0;
        for (source) |xattr| {
            total = std.math.add(usize, total, xattr.name.len + xattr.value.len) catch
                return error.XattrByteLimitExceeded;
        }
        limits_mod.observe(self.diagnostic, .xattr_bytes_per_node, total);
        if (total > self.limits.max_xattr_bytes_per_node) {
            return limits_mod.exceeded(
                self.diagnostic,
                .xattr_bytes_per_node,
                total,
                self.limits.max_xattr_bytes_per_node,
            );
        }

        const out = try self.allocator.alloc(ext4.OwnedXattr, source.len);
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |xattr| {
                self.allocator.free(xattr.name);
                self.allocator.free(xattr.value);
            }
            self.allocator.free(out);
        }
        for (source, 0..) |xattr, index| {
            out[index] = .{
                .name = try self.allocator.dupe(u8, xattr.name),
                .value = self.allocator.dupe(u8, xattr.value) catch |err| {
                    self.allocator.free(out[index].name);
                    return err;
                },
            };
            initialized += 1;
        }
        std.mem.sort(ext4.OwnedXattr, out, {}, lessXattr);
        if (out.len > 1) {
            for (out[1..], out[0 .. out.len - 1]) |current, previous| {
                if (std.mem.eql(u8, current.name, previous.name)) return error.DuplicateXattr;
            }
        }
        return out;
    }

    fn sortAndValidate(self: *RootTree) !void {
        try self.sortAndValidateRepresentable();
        if (self.root_metadata.mode != 0o755 or
            self.root_metadata.uid != 0 or
            self.root_metadata.gid != 0)
        {
            return error.Ext4RootMetadataUnsupported;
        }
        if (self.root_metadata.atime != null or
            self.root_metadata.mtime != null or
            self.root_metadata.ctime != null)
        {
            return error.Ext4TimestampsUnsupported;
        }
        for (self.nodes.items) |node| {
            if (node.metadata.atime != null or node.metadata.mtime != null or node.metadata.ctime != null) {
                return error.Ext4TimestampsUnsupported;
            }
            switch (node.kind) {
                .directory, .file, .symlink => {},
                .hardlink => return error.Ext4HardlinksUnsupported,
                .block_device, .char_device, .fifo => return error.Ext4SpecialFilesUnsupported,
            }
        }
    }

    fn sortAndValidateRepresentable(self: *RootTree) !void {
        if (!self.sorted) {
            std.mem.sort(Node, self.nodes.items, {}, lessNode);
            self.sorted = true;
        }
        for (self.nodes.items) |node| {
            if (node.kind == .hardlink) {
                const target = node.payload.hardlink_target;
                const target_index = self.findIndex(target) orelse return error.MissingHardlinkTarget;
                if (self.nodes.items[target_index].kind != .file) return error.UnsupportedHardlinkTarget;
            }
        }
    }

    fn removalBreaksHardlinks(self: *const RootTree, path: []const u8, recursive: bool) bool {
        for (self.nodes.items) |entry| {
            if (entry.kind != .hardlink) continue;
            const link_removed = std.mem.eql(u8, path, entry.path) or
                (recursive and pathEqualsOrDescendant(path, entry.path));
            if (link_removed) continue;
            const target = entry.payload.hardlink_target;
            if (std.mem.eql(u8, path, target) or
                (recursive and pathEqualsOrDescendant(path, target)))
            {
                return true;
            }
        }
        return false;
    }

    fn overlayBreaksHardlinks(
        self: *const RootTree,
        destination: []const u8,
        kind: Kind,
        parents: []const ParentPlan,
    ) bool {
        for (self.nodes.items) |entry| {
            if (entry.kind != .hardlink) continue;
            if (removedByOverlay(entry.path, destination, kind, parents)) continue;
            const target = entry.payload.hardlink_target;
            if (!removedByOverlay(target, destination, kind, parents)) continue;
            if (std.mem.eql(u8, target, destination) and kind == .file) continue;
            return true;
        }
        return false;
    }

    fn preflightFat32(self: *const RootTree, options: FatPopulateOptions) !void {
        if (options.metadata_policy == .strict and !hasCanonicalFatRootMetadata(self.root_metadata)) {
            return error.FatRootMetadataUnsupported;
        }
        for (self.nodes.items, 0..) |node, index| {
            try fat32.validateRelativePath(node.path);
            switch (node.kind) {
                .directory, .file => {},
                else => return error.FatNodeKindUnsupported,
            }
            if (node.size() > std.math.maxInt(u32)) return error.FatFileTooLarge;
            if (options.metadata_policy == .strict and !hasCanonicalFatMetadata(node)) {
                return error.FatMetadataUnsupported;
            }
            for (self.nodes.items[0..index]) |previous| {
                if (fatPathEqual(previous.path, node.path)) return error.FatPathCollision;
            }
        }
    }

    fn populateFatFile(self: *const RootTree, filesystem: *fat32.FileSystem, node: Node) !void {
        var writer = try filesystem.beginFile(self.io, node.path);
        var offset: u64 = 0;
        var buffer: [64 * 1024]u8 = undefined;
        while (offset < node.size()) {
            const wanted: usize = @intCast(@min(@as(u64, buffer.len), node.size() - offset));
            const got = node.payload.content.readAt(buffer[0..wanted], offset) catch |err| {
                writer.abort(self.io) catch |abort_err| return abort_err;
                return err;
            };
            if (got == 0 or got > wanted) {
                writer.abort(self.io) catch |abort_err| return abort_err;
                return error.UnexpectedSourceLength;
            }
            writer.writeChunk(self.io, buffer[0..got]) catch |err| {
                writer.abort(self.io) catch |abort_err| return abort_err;
                return err;
            };
            offset += got;
        }
        writer.endFile(self.io) catch |err| {
            writer.abort(self.io) catch |abort_err| return abort_err;
            return err;
        };
    }

    fn findIndex(self: *const RootTree, path: []const u8) ?usize {
        for (self.nodes.items, 0..) |node, index| {
            if (std.mem.eql(u8, node.path, path)) return index;
        }
        return null;
    }

    fn freeNode(self: *RootTree, node: *Node) void {
        self.allocator.free(node.path);
        freeOwnedXattrs(self.allocator, node.owned_xattrs);
        self.freePayload(node.payload);
    }

    fn freePayload(self: *RootTree, payload: Payload) void {
        switch (payload) {
            .hardlink_target => |target| self.allocator.free(target),
            .content => |content| switch (content.source) {
                .memory => |bytes| self.allocator.free(bytes),
                .host_path => |path| self.allocator.free(path),
                .spooled, .borrowed => {},
            },
            .none, .device => {},
        }
    }

    fn resetExt4(ctx: *anyopaque) void {
        const self: *RootTree = @ptrCast(@alignCast(ctx));
        self.iteration_index = 0;
    }

    fn nextExt4(ctx: *anyopaque) ext4.FileTreeView.IteratorError!?ext4.FileTreeView.Entry {
        const self: *RootTree = @ptrCast(@alignCast(ctx));
        if (self.iteration_index >= self.nodes.items.len) return null;
        const node = &self.nodes.items[self.iteration_index];
        self.iteration_index += 1;
        const kind: ext4.Kind = switch (node.kind) {
            .directory => .directory,
            .file => .file,
            .symlink => .symlink,
            .hardlink => .hardlink,
            .block_device => .block_device,
            .char_device => .char_device,
            .fifo => .fifo,
        };
        const carries_content = kind == .file or kind == .symlink;
        return .{
            .path = node.path,
            .kind = kind,
            .mode = node.metadata.mode,
            .uid = node.metadata.uid,
            .gid = node.metadata.gid,
            .size = if (carries_content) node.size() else 0,
            .content = if (carries_content) .{
                .ctx = &node.payload.content,
                .read_at_fn = readExt4Content,
            } else null,
            .xattrs = node.metadata.xattrs,
            .device = switch (node.payload) {
                .device => |device| .{ .major = device.major, .minor = device.minor },
                else => .{},
            },
            .hardlink_target = switch (node.payload) {
                .hardlink_target => |target| target,
                else => "",
            },
        };
    }

    fn readExt4Content(
        ctx: *const anyopaque,
        buffer: []u8,
        offset: u64,
    ) ext4.FileTreeView.ContentError!usize {
        const content: *const Content = @ptrCast(@alignCast(ctx));
        return content.readAt(buffer, offset) catch error.ReadFailed;
    }
};

fn hashContentReader(
    reader: ext4.FileTreeView.ContentReader,
    size: u64,
) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), size - offset));
        const got = reader.readAt(buffer[0..wanted], offset) catch
            return error.SourceReadFailed;
        if (got == 0 or got > wanted) return error.UnexpectedSourceLength;
        hash.update(buffer[0..got]);
        offset += got;
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

/// A malformed path and an over-long path are different failures: the first
/// can never be imported, the second only needs a larger limit, so they are
/// reported as distinct errors.
fn validatePath(
    path: []const u8,
    limits: Limits,
    diagnostic: ?*limits_mod.Diagnostic,
) !void {
    if (path.len == 0 or path[0] == '/') return error.InvalidPath;
    limits_mod.observe(diagnostic, .path_bytes, path.len);
    if (path.len > limits.max_path_bytes) {
        return limits_mod.exceeded(diagnostic, .path_bytes, path.len, limits.max_path_bytes);
    }
    var iterator = std.mem.splitScalar(u8, path, '/');
    while (iterator.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or
            std.mem.indexOfScalar(u8, component, 0) != null)
        {
            return error.InvalidPath;
        }
        limits_mod.observe(diagnostic, .component_bytes, component.len);
        if (component.len > limits.max_component_bytes) {
            return limits_mod.exceeded(
                diagnostic,
                .component_bytes,
                component.len,
                limits.max_component_bytes,
            );
        }
    }
}

fn pathEqualsOrDescendant(parent: []const u8, path: []const u8) bool {
    return std.mem.eql(u8, parent, path) or
        (path.len > parent.len and std.mem.startsWith(u8, path, parent) and path[parent.len] == '/');
}

fn removedByOverlay(
    existing_path: []const u8,
    destination: []const u8,
    kind: Kind,
    parents: []const RootTree.ParentPlan,
) bool {
    for (parents) |parent| {
        if (parent.replace_existing and pathEqualsOrDescendant(parent.path, existing_path)) return true;
    }
    return std.mem.eql(u8, destination, existing_path) or
        (kind != .directory and pathEqualsOrDescendant(destination, existing_path));
}

fn payloadSize(payload: Payload) u64 {
    return switch (payload) {
        .content => |content| content.size,
        .hardlink_target => |target| target.len,
        .none, .device => 0,
    };
}

fn hasCanonicalFatMetadata(node: Node) bool {
    const expected_mode: u16 = switch (node.kind) {
        .directory => 0o755,
        .file => 0o644,
        else => return false,
    };
    return node.metadata.mode == expected_mode and
        node.metadata.uid == 0 and
        node.metadata.gid == 0 and
        node.metadata.atime == null and
        node.metadata.mtime == null and
        node.metadata.ctime == null and
        node.owned_xattrs.len == 0;
}

fn hasCanonicalFatRootMetadata(metadata: RootMetadata) bool {
    return metadata.mode == 0o755 and
        metadata.uid == 0 and
        metadata.gid == 0 and
        metadata.atime == null and
        metadata.mtime == null and
        metadata.ctime == null;
}

fn fatPathEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_byte, right_byte| {
        if (left_byte < 128 and right_byte < 128) {
            if (std.ascii.toUpper(left_byte) != std.ascii.toUpper(right_byte)) return false;
        } else if (left_byte != right_byte) {
            return false;
        }
    }
    return true;
}

fn lessNode(_: void, left: Node, right: Node) bool {
    return std.mem.order(u8, left.path, right.path) == .lt;
}

fn lessXattr(_: void, left: ext4.OwnedXattr, right: ext4.OwnedXattr) bool {
    return std.mem.order(u8, left.name, right.name) == .lt;
}

fn ownedXattrsView(source: []ext4.OwnedXattr) []const ext4.Xattr {
    return @ptrCast(source);
}

fn freeOwnedXattrs(allocator: Allocator, xattrs: []ext4.OwnedXattr) void {
    if (xattrs.len == 0) return;
    for (xattrs) |xattr| {
        allocator.free(xattr.name);
        allocator.free(xattr.value);
    }
    allocator.free(xattrs);
}

const BytesReader = struct {
    bytes: []const u8,

    fn readAt(ctx: *const anyopaque, buffer: []u8, offset: u64) ext4.FileTreeView.ContentError!usize {
        const self: *const BytesReader = @ptrCast(@alignCast(ctx));
        if (offset >= self.bytes.len) return 0;
        const count = @min(buffer.len, self.bytes.len - @as(usize, @intCast(offset)));
        @memcpy(buffer[0..count], self.bytes[@intCast(offset)..][0..count]);
        return count;
    }
};

const FileReader = struct {
    io: Io,
    file: Io.File,

    fn readAt(ctx: *const anyopaque, buffer: []u8, offset: u64) ext4.FileTreeView.ContentError!usize {
        const self: *const FileReader = @ptrCast(@alignCast(ctx));
        return self.file.readPositionalAll(self.io, buffer, offset) catch error.ReadFailed;
    }
};

const EmptyReader = struct {
    fn readAt(_: *const anyopaque, _: []u8, _: u64) ext4.FileTreeView.ContentError!usize {
        return 0;
    }
};

fn emptyContentReader() ext4.FileTreeView.ContentReader {
    return .{ .ctx = undefined, .read_at_fn = EmptyReader.readAt };
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .big);
    hash.update(&bytes);
}

fn hashOptionalInt(hash: *std.crypto.hash.sha2.Sha256, value: ?i64) void {
    if (value) |present| {
        hash.update(&.{1});
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(i64, &bytes, present, .big);
        hash.update(&bytes);
    } else {
        hash.update(&.{0});
    }
}

fn hashString(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    hashInt(hash, value.len);
    hash.update(value);
}

test "owned tree overlays deterministically and survives source closure" {
    const io = std.testing.io;
    const spool_path = "test-root-tree.spool";
    const source_path = "test-root-tree-source";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    {
        const source = try Io.Dir.cwd().createFile(io, source_path, .{});
        defer source.close(io);
        try source.writePositionalAll(io, "from-source", 0);
    }

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putFileFromPath("etc/value", source_path, .{ .mode = 0o644 });
    try Io.Dir.cwd().deleteFile(io, source_path);
    try tree.putFileBytes("etc/value", "replacement", .{ .mode = 0o600, .uid = 12, .gid = 34 });
    try tree.putSymlink("link", "etc/value", .{ .mode = 0o777 });

    const first = try tree.manifestDigest();
    const second = try tree.manifestDigest();
    try std.testing.expectEqualSlices(u8, &first, &second);

    try tree.sortNodes();
    try std.testing.expectEqualStrings("etc", tree.nodeView(0).path);
    try std.testing.expectEqualStrings("etc/value", tree.nodeView(1).path);
    var bytes: [11]u8 = undefined;
    _ = try tree.readNodeContent("etc/value", &bytes, 0);
    try std.testing.expectEqualStrings("replacement", &bytes);
}

test "owned tree refuses to truncate an existing spool path" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-existing.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    {
        const file = try Io.Dir.cwd().createFile(io, spool_path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, "preserve", 0);
    }

    try std.testing.expectError(
        error.PathAlreadyExists,
        RootTree.init(std.testing.allocator, io, spool_path, .{}),
    );
    const preserved = try Io.Dir.cwd().readFileAlloc(io, spool_path, std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("preserve", preserved);
}

test "owned tree populates ext4 with metadata xattrs and symlinks" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-ext4.spool";
    const image_path = "test-root-tree-ext4.img";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putFileBytes("etc/hostname", "appliance\n", .{
        .mode = 0o640,
        .uid = 4,
        .gid = 5,
        .xattrs = &.{.{ .name = "user.origin", .value = "root-tree" }},
    });
    try tree.putSymlink("hostname", "etc/hostname", .{ .mode = 0o777 });

    const image = try Io.Dir.cwd().createFile(io, image_path, .{ .read = true });
    defer image.close(io);
    _ = try ext4.populate(io, image, std.testing.allocator, try tree.ext4View(), .{
        .length = 32 * 1024 * 1024,
    });

    var reader = try ext4.Reader.open(io, image, std.testing.allocator, .{});
    defer reader.deinit();
    const stat = try reader.statPath(io, "etc/hostname");
    try std.testing.expectEqual(@as(u16, 0o640), stat.mode);
    try std.testing.expectEqual(@as(u32, 4), stat.uid);
    try std.testing.expectEqual(@as(u32, 5), stat.gid);
    const content = try reader.readFileAlloc(io, std.testing.allocator, "etc/hostname");
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("appliance\n", content);
    const target = try reader.readLinkAlloc(io, std.testing.allocator, "hostname");
    defer std.testing.allocator.free(target);
    try std.testing.expectEqualStrings("etc/hostname", target);
}

test "owned tree rejects unsupported ext4 node kinds explicitly" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-special.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDevice("dev/console", .char_device, .{ .major = 5, .minor = 1 }, .{ .mode = 0o600 });
    try std.testing.expectError(error.Ext4SpecialFilesUnsupported, tree.ext4View());
}

test "borrowed node paths are safe overlay and removal inputs" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-borrowed-path.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("value", "old", .{ .mode = 0o644 });
    try tree.sortNodes();
    try tree.putFileBytes(tree.nodeView(0).path, "new", .{ .mode = 0o600 });
    var content: [3]u8 = undefined;
    _ = try tree.readNodeContent("value", &content, 0);
    try std.testing.expectEqualStrings("new", &content);

    try tree.sortNodes();
    try std.testing.expect(try tree.remove(tree.nodeView(0).path));
    try std.testing.expectEqual(@as(usize, 0), tree.nodeCount());
}

test "rejected overlays preserve nodes and roll back spool bytes" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-transaction.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{
        .max_nodes = 2,
        .max_total_bytes = 8,
    });
    defer tree.deinit();

    try tree.putFileBytes("dir/value", "12345678", .{ .mode = 0o644 });
    const before_digest = try tree.manifestDigest();
    const before_spool_len = tree.spool_len;
    try std.testing.expectError(
        error.TotalContentLimitExceeded,
        tree.putFileBytes("dir", "123456789", .{ .mode = 0o600 }),
    );
    try std.testing.expectError(
        error.NodeLimitExceeded,
        tree.putFileBytes("other/value", "", .{ .mode = 0o600 }),
    );
    const after_digest = try tree.manifestDigest();
    try std.testing.expectEqualSlices(u8, &before_digest, &after_digest);
    try std.testing.expectEqual(before_spool_len, tree.spool_len);
    var content: [8]u8 = undefined;
    _ = try tree.readNodeContent("dir/value", &content, 0);
    try std.testing.expectEqualStrings("12345678", &content);
}

test "overlay accounting removes descendants and conflicting ancestors" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-overlay-accounting.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{
        .max_total_bytes = 8,
    });
    defer tree.deinit();

    try tree.putFileBytes("dir/value", "12345678", .{ .mode = 0o644 });
    try tree.putFileBytes("dir", "abcdefgh", .{ .mode = 0o644 });
    try std.testing.expect(tree.findIndex("dir/value") == null);
    try tree.putFileBytes("dir/value", "ABCDEFGH", .{ .mode = 0o644 });
    try std.testing.expectEqual(Kind.directory, tree.nodes.items[tree.findIndex("dir").?].kind);
    try std.testing.expect(tree.findIndex("dir/value") != null);
}

test "symlinks and hardlinks participate in total content limits" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-link-limits.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{
        .max_total_bytes = 4,
    });
    defer tree.deinit();

    try tree.putFileBytes("target", "x", .{ .mode = 0o644 });
    try std.testing.expectError(
        error.TotalContentLimitExceeded,
        tree.putSymlink("symlink", "1234", .{ .mode = 0o777 }),
    );
    try std.testing.expectError(
        error.TotalContentLimitExceeded,
        tree.putHardlink("hardlink", "target", .{ .mode = 0o644 }),
    );
}

test "hardlink targets remain valid across removals and overlays" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-hardlink-integrity.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("target", "x", .{ .mode = 0o644 });
    try tree.putHardlink("link", "target", .{ .mode = 0o644 });
    try std.testing.expectError(error.HardlinkTargetInUse, tree.remove("target"));
    try std.testing.expectError(
        error.HardlinkTargetInUse,
        tree.putDirectory("target", .{ .mode = 0o755 }),
    );
    try tree.putFileBytes("target", "replacement", .{ .mode = 0o600 });
    _ = try tree.manifestDigest();
    try std.testing.expectError(
        error.UnsupportedHardlinkTarget,
        tree.putHardlink("invalid", "link", .{ .mode = 0o644 }),
    );
}

test "physical spool growth is bounded across replacements" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-spool-limit.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{
        .max_total_bytes = 16,
        .max_spool_bytes = 3,
    });
    defer tree.deinit();

    try tree.putFileBytes("value", "12", .{ .mode = 0o644 });
    try std.testing.expectError(
        error.SpoolLimitExceeded,
        tree.putFileBytes("value", "34", .{ .mode = 0o644 }),
    );
    try std.testing.expectEqual(@as(u64, 2), tree.spool_len);
    var content: [2]u8 = undefined;
    _ = try tree.readNodeContent("value", &content, 0);
    try std.testing.expectEqualStrings("12", &content);
}

test "root timestamps affect manifests and unsupported ext4 metadata is explicit" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-timestamps.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    const original = try tree.manifestDigest();
    tree.setRootMetadata(.{ .atime = 1 });
    const timestamped = try tree.manifestDigest();
    try std.testing.expect(!std.mem.eql(u8, &original, &timestamped));
    try std.testing.expectError(error.Ext4TimestampsUnsupported, tree.ext4View());

    tree.setRootMetadata(.{});
    try tree.putFileBytes("value", "x", .{ .mode = 0o644, .mtime = 1 });
    try std.testing.expectError(error.Ext4TimestampsUnsupported, tree.ext4View());
    tree.setRootMetadata(.{ .mode = 0o700 });
    try std.testing.expectError(error.Ext4RootMetadataUnsupported, tree.ext4View());
}

test "owned tree populates FAT32 with an explicit metadata-loss policy" {
    const Image = @import("image.zig").Image;
    const io = std.testing.io;
    const spool_path = "test-root-tree-fat32.spool";
    const image_path = "test-root-tree-fat32.img";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putFileBytes("EFI/BOOT/BOOTAA64.EFI", "firmware", .{
        .mode = 0o700,
        .uid = 10,
        .xattrs = &.{.{ .name = "user.origin", .value = "root-tree" }},
    });

    const image_size: u64 = 64 * 1024 * 1024;
    var image = try Image.create(io, image_path, .raw, image_size, .{});
    defer image.close(io);
    try fat32.format(&image, io, .{
        .partition_offset = 0,
        .partition_len = image_size,
    });
    var filesystem = try fat32.open(&image, io, .{ .offset = 0, .length = image_size });

    try std.testing.expectError(
        error.FatMetadataUnsupported,
        tree.populateFat32(&filesystem, .{ .metadata_policy = .strict }),
    );
    try tree.populateFat32(&filesystem, .{ .metadata_policy = .lossy_posix_metadata });
    const content = try filesystem.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/BOOTAA64.EFI");
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("firmware", content);
}

test "FAT32 preflight rejects semantic node loss and folded path collisions" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-fat32-preflight.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("EFI/file", "x", .{ .mode = 0o644 });
    try tree.putSymlink("link", "EFI/file", .{ .mode = 0o777 });
    try tree.sortNodes();
    try std.testing.expectError(
        error.FatNodeKindUnsupported,
        tree.preflightFat32(.{ .metadata_policy = .lossy_posix_metadata }),
    );
    _ = try tree.remove("link");
    try tree.putFileBytes("efi/FILE", "y", .{ .mode = 0o644 });
    try tree.sortNodes();
    try std.testing.expectError(
        error.FatPathCollision,
        tree.preflightFat32(.{ .metadata_policy = .lossy_posix_metadata }),
    );
}

test "each limit reports the observed value and the flag that raises it" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-limit-diagnostics.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var diagnostic = limits_mod.Diagnostic{};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{
        .max_nodes = 1,
        .max_file_bytes = 4,
    });
    tree.diagnostic = &diagnostic;
    defer tree.deinit();

    try tree.putFileBytes("first", "ab", .{ .mode = 0o644 });
    try std.testing.expectError(
        error.NodeLimitExceeded,
        tree.putFileBytes("second", "cd", .{ .mode = 0o644 }),
    );

    const breach = diagnostic.exceeded.?;
    try std.testing.expectEqual(limits_mod.Limit.nodes, breach.limit);
    try std.testing.expectEqual(@as(u64, 2), breach.observed);
    try std.testing.expectEqual(@as(u64, 1), breach.configured);

    var buffer: [limits_mod.Exceeded.max_message_bytes]u8 = undefined;
    const message = try breach.describe(&buffer);
    try std.testing.expect(std.mem.indexOf(u8, message, "NodeLimitExceeded") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "--max-nodes") != null);
}

test "a limit records the peak it reached even when nothing was exceeded" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-limit-peaks.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var diagnostic = limits_mod.Diagnostic{};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    tree.diagnostic = &diagnostic;
    defer tree.deinit();

    try tree.putFileBytes("small", "ab", .{ .mode = 0o644 });
    try tree.putFileBytes("large", "abcdefgh", .{
        .mode = 0o644,
        .xattrs = &.{.{ .name = "user.one", .value = "value" }},
    });

    const peaks = tree.limitDiagnostic().?.peaks;
    try std.testing.expectEqual(@as(u64, 2), peaks.nodes);
    try std.testing.expectEqual(@as(u64, 8), peaks.file_bytes);
    try std.testing.expectEqual(@as(u64, 10), peaks.total_bytes);
    try std.testing.expectEqual(@as(u64, 10), peaks.spool_bytes);
    try std.testing.expectEqual(@as(u64, 1), peaks.xattrs_per_node);
    try std.testing.expectEqual(@as(u64, 5), peaks.path_bytes);
    try std.testing.expectEqual(@as(u64, 5), peaks.component_bytes);
    try std.testing.expect(diagnostic.exceeded == null);
}

test "an over-long path is a raisable limit, not a malformed path" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-path-limits.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var diagnostic = limits_mod.Diagnostic{};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{
        .max_path_bytes = 8,
        .max_component_bytes = 3,
    });
    tree.diagnostic = &diagnostic;
    defer tree.deinit();

    try std.testing.expectError(
        error.ComponentLimitExceeded,
        tree.putDirectory("abcd", .{ .mode = 0o755 }),
    );
    try std.testing.expectEqual(limits_mod.Limit.component_bytes, diagnostic.exceeded.?.limit);
    try std.testing.expectEqual(@as(u64, 4), diagnostic.exceeded.?.observed);

    var long = limits_mod.Diagnostic{};
    tree.diagnostic = &long;
    try std.testing.expectError(
        error.PathLimitExceeded,
        tree.putDirectory("abc/abc/abc", .{ .mode = 0o755 }),
    );
    try std.testing.expectEqual(limits_mod.Limit.path_bytes, long.exceeded.?.limit);
    try std.testing.expectEqual(@as(u64, 11), long.exceeded.?.observed);

    // A path that is malformed rather than long stays malformed: no flag
    // raises a limit that would admit it.
    try std.testing.expectError(error.InvalidPath, tree.putDirectory("/abs", .{ .mode = 0o755 }));
}

test "xattr count and byte limits are distinguishable" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-xattr-limits.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var diagnostic = limits_mod.Diagnostic{};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{
        .max_xattrs_per_node = 1,
        .max_xattr_bytes_per_node = 32,
    });
    tree.diagnostic = &diagnostic;
    defer tree.deinit();

    try tree.putFileBytes("file", "x", .{
        .mode = 0o644,
        .xattrs = &.{.{ .name = "user.one", .value = "value" }},
    });
    try std.testing.expectError(error.XattrLimitExceeded, tree.putFileBytes("file", "x", .{
        .mode = 0o644,
        .xattrs = &.{
            .{ .name = "user.one", .value = "value" },
            .{ .name = "user.two", .value = "value" },
        },
    }));
    try std.testing.expectEqual(limits_mod.Limit.xattrs_per_node, diagnostic.exceeded.?.limit);

    const wide_spool_path = "test-root-tree-xattr-byte-limits.spool";
    defer Io.Dir.cwd().deleteFile(io, wide_spool_path) catch {};
    var bytes = limits_mod.Diagnostic{};
    var wide = try RootTree.init(std.testing.allocator, io, wide_spool_path, .{
        .max_xattr_bytes_per_node = 8,
    });
    wide.diagnostic = &bytes;
    defer wide.deinit();
    try std.testing.expectError(error.XattrByteLimitExceeded, wide.putFileBytes("file", "x", .{
        .mode = 0o644,
        .xattrs = &.{.{ .name = "user.one", .value = "a longer value" }},
    }));
    try std.testing.expectEqual(limits_mod.Limit.xattr_bytes_per_node, bytes.exceeded.?.limit);
    try std.testing.expectEqual(@as(u64, 22), bytes.exceeded.?.observed);
}
