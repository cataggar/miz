const std = @import("std");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const xfs = @import("xfs.zig");
const limits_mod = @import("limits.zig");
const squashfs = @import("squashfs.zig");
const iso9660 = @import("iso9660.zig");
const tree_cursor = @import("tree_cursor.zig");

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
    /// Sub-second parts of the three times above, 0..999999999. Zero is both
    /// the default and what every node carried before these existed, so a
    /// caller that supplies nothing gets the bytes it always got.
    atime_nsec: u32 = 0,
    mtime_nsec: u32 = 0,
    ctime_nsec: u32 = 0,
    /// The node's creation time. Null means there is none to preserve, and
    /// the writer stamps the image-wide timestamp instead -- the honest
    /// answer for a node the build is genuinely creating.
    crtime: ?i64 = null,
    crtime_nsec: u32 = 0,
    xattrs: []const tree_cursor.Xattr = &.{},
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
        borrowed: tree_cursor.Cursor.ContentReader,
        /// Same lifecycle as `.borrowed`, for a source whose content reader
        /// is shaped like `xfs.ContentReader` rather than ext4's. Kept as its
        /// own variant instead of adapting to `tree_cursor.Cursor.ContentReader`
        /// because the two are structurally identical but nominally distinct
        /// Zig types with no implicit conversion between them.
        borrowed_xfs: xfs.ContentReader,
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
            .borrowed_xfs => |reader| reader.readAt(buffer[0..wanted], offset),
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
    owned_xattrs: []tree_cursor.OwnedXattr,
    payload: Payload,
    sparse_extents: []tree_cursor.SparseExtent = &.{},

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
    sparse_extents: []const tree_cursor.SparseExtent = &.{},
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
    /// See `Metadata` for what these mean and why zero and null preserve the
    /// behaviour that was there before they existed.
    atime_nsec: u32 = 0,
    mtime_nsec: u32 = 0,
    ctime_nsec: u32 = 0,
    crtime: ?i64 = null,
    crtime_nsec: u32 = 0,
    /// Extended attributes on the implicit ext4 root inode. The slice is
    /// borrowed from the source tree or caller and is copied by the ext4
    /// writer before the source is released.
    xattrs: []const tree_cursor.Xattr = &.{},
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
    path_index: std.StringHashMap(usize),
    total_node_bytes: u64 = 0,
    limits: Limits,
    /// Optional sink for the peak measurements and the first limit breach.
    /// Assigned after `init` because it is the caller's, not the tree's, and
    /// must outlive the tree. Nothing is measured before the first node.
    diagnostic: ?*limits_mod.Diagnostic = null,
    root_metadata: RootMetadata = .{},
    iteration_index: usize = 0,
    sorted: bool = true,
    append_only_import: bool = false,
    /// The neutral pull cursor `cursor()` (and its deprecated alias
    /// `ext4View()`) hands to a writer. Reused across calls rather than
    /// allocated fresh, since it carries no state of its own beyond the
    /// function pointers and `self` -- `iteration_index` above is the only
    /// mutable state, and `Cursor.reset()` is how a consumer rewinds it.
    tree_cursor_view: tree_cursor.Cursor,

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
            .path_index = .init(allocator),
            .limits = limits,
            .tree_cursor_view = .{
                .ctx = undefined,
                .next_fn = nextCursor,
                .reset_fn = resetCursor,
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
            .path_index = .init(allocator),
            .limits = limits,
            .tree_cursor_view = .{
                .ctx = undefined,
                .next_fn = nextCursor,
                .reset_fn = resetCursor,
            },
        };
    }

    pub fn deinit(self: *RootTree) void {
        self.path_index.deinit();
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
        return self.readFileAllocAt(allocator, index, max_bytes);
    }

    pub fn readFileAllocAt(
        self: *const RootTree,
        allocator: Allocator,
        index: usize,
        max_bytes: u64,
    ) ![]u8 {
        if (index >= self.nodes.items.len) return error.MissingNode;
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

    pub fn putFileBytesSparse(
        self: *RootTree,
        path: []const u8,
        bytes: []const u8,
        sparse_extents: []const tree_cursor.SparseExtent,
        metadata: Metadata,
    ) !void {
        var reader = BytesReader{ .bytes = bytes };
        try self.putFileReaderSparse(path, bytes.len, .{
            .ctx = &reader,
            .read_at_fn = BytesReader.readAt,
        }, sparse_extents, metadata);
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
        reader: tree_cursor.Cursor.ContentReader,
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

    pub fn putFileReaderSparse(
        self: *RootTree,
        path: []const u8,
        size: u64,
        reader: tree_cursor.Cursor.ContentReader,
        sparse_extents: []const tree_cursor.SparseExtent,
        metadata: Metadata,
    ) !void {
        try validatePath(path, self.limits, self.diagnostic);
        try self.checkFileBytes(size);
        const old_spool_len = self.spool_len;
        const content = self.spoolContent(size, reader) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
        var owned_sparse_extents = try self.allocator.dupe(
            tree_cursor.SparseExtent,
            sparse_extents,
        );
        errdefer self.allocator.free(owned_sparse_extents);
        self.putNode(path, .file, metadata, .{ .content = content }) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
        const index = self.findIndex(path) orelse return error.MissingNode;
        self.nodes.items[index].sparse_extents = owned_sparse_extents;
        owned_sparse_extents = &.{};
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
        const typed_reader: tree_cursor.Cursor.ContentReader = .{
            .ctx = &reader,
            .read_at_fn = BytesReader.readAt,
        };
        const content = self.spoolContent(target.len, typed_reader) catch |err| {
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
        // Removing a file that owns a hardlink set promotes a surviving alias
        // first, so the tree never leaves a hardlink pointing at a vanished
        // content owner.
        try validatePath(path, self.limits, self.diagnostic);
        const stable_path = try self.allocator.dupe(u8, path);
        defer self.allocator.free(stable_path);
        var promotions = std.array_list.Managed([]u8).init(self.allocator);
        defer {
            for (promotions.items) |candidate| self.allocator.free(candidate);
            promotions.deinit();
        }
        for (self.nodes.items) |node| {
            if (node.kind != .file or !pathEqualsOrDescendant(stable_path, node.path)) continue;
            try promotions.append(try self.allocator.dupe(u8, node.path));
        }
        for (promotions.items) |candidate| {
            try self.promoteHardlinkTarget(candidate, stable_path);
        }
        const removed = self.removeInternal(stable_path, true);
        if (removed) self.recomputeTotalNodeBytes();
        return removed;
    }

    /// A hardlink target is only a name in the tree model; the content and
    /// inode metadata belong to the one `.file` node. If that name is removed
    /// while aliases survive, move ownership to the lexicographically first
    /// surviving alias and retarget the rest before removing the old name.
    fn promoteHardlinkTarget(self: *RootTree, target_path: []const u8, removal_root: []const u8) !void {
        const target_index = self.findIndex(target_path) orelse return;
        if (self.nodes.items[target_index].kind != .file) return;

        var promoted_index: ?usize = null;
        for (self.nodes.items, 0..) |node, index| {
            if (node.kind != .hardlink or
                !std.mem.eql(u8, node.payload.hardlink_target, target_path) or
                pathEqualsOrDescendant(removal_root, node.path))
            {
                continue;
            }
            if (promoted_index == null or
                std.mem.order(u8, node.path, self.nodes.items[promoted_index.?].path) == .lt)
            {
                promoted_index = index;
            }
        }
        const promoted = promoted_index orelse return;

        const AliasPlan = struct {
            index: usize,
            target: []u8,
        };
        var plans = std.array_list.Managed(AliasPlan).init(self.allocator);
        errdefer {
            for (plans.items) |plan| {
                self.allocator.free(plan.target);
            }
        }
        defer plans.deinit();

        const canonical_metadata = self.nodes.items[target_index].metadata;
        for (self.nodes.items, 0..) |node, index| {
            if (index == promoted or node.kind != .hardlink or
                !std.mem.eql(u8, node.payload.hardlink_target, target_path) or
                pathEqualsOrDescendant(removal_root, node.path))
            {
                continue;
            }
            const planned_target = try self.allocator.dupe(u8, self.nodes.items[promoted].path);
            plans.append(.{
                .index = index,
                .target = planned_target,
            }) catch |err| {
                self.allocator.free(planned_target);
                return err;
            };
        }

        const target_payload = self.nodes.items[target_index].payload;
        const target_xattrs = self.nodes.items[target_index].owned_xattrs;
        const target_sparse = self.nodes.items[target_index].sparse_extents;
        self.nodes.items[target_index].payload = .none;
        self.nodes.items[target_index].owned_xattrs = &.{};
        self.nodes.items[target_index].sparse_extents = &.{};

        self.freePayload(self.nodes.items[promoted].payload);
        freeOwnedXattrs(self.allocator, self.nodes.items[promoted].owned_xattrs);
        self.allocator.free(self.nodes.items[promoted].sparse_extents);
        self.nodes.items[promoted].kind = .file;
        self.nodes.items[promoted].payload = target_payload;
        self.nodes.items[promoted].owned_xattrs = target_xattrs;
        self.nodes.items[promoted].sparse_extents = target_sparse;
        self.nodes.items[promoted].metadata = canonical_metadata;
        self.nodes.items[promoted].metadata.xattrs = ownedXattrsView(target_xattrs);

        for (plans.items) |plan| {
            self.freePayload(self.nodes.items[plan.index].payload);
            freeOwnedXattrs(self.allocator, self.nodes.items[plan.index].owned_xattrs);
            self.nodes.items[plan.index].payload = .{ .hardlink_target = plan.target };
            self.nodes.items[plan.index].owned_xattrs = &.{};
            self.nodes.items[plan.index].metadata = canonical_metadata;
            self.nodes.items[plan.index].metadata.xattrs = &.{};
        }
        plans.clearRetainingCapacity();
    }

    fn removeInternal(self: *RootTree, path: []const u8, recursive: bool) bool {
        // Every ancestor of a node is materialized as a directory (see
        // `prepareParents`), so a path missing from `path_index` has no
        // descendants, and a non-directory node never has children. In both
        // cases a "recursive" removal can touch at most the exact node, so we
        // resolve it in O(1) through the index instead of scanning the whole
        // tree. Production-scale customize issues tens of thousands of
        // overlays; the old full scan here made that path O(n^2).
        const existing = self.path_index.get(path);
        if (!recursive or existing == null or
            self.nodes.items[existing.?].kind != .directory)
        {
            const index = existing orelse return false;
            return self.removeNodeAt(index);
        }
        // Recursively dropping an existing directory subtree is the only case
        // that can reach descendants, and it is rare on the customize path.
        var removed = false;
        var index: usize = 0;
        while (index < self.nodes.items.len) {
            if (pathEqualsOrDescendant(path, self.nodes.items[index].path)) {
                _ = self.removeNodeAt(index);
                removed = true;
            } else {
                index += 1;
            }
        }
        return removed;
    }

    /// Removes exactly the node at `index` via swap-remove, keeping
    /// `path_index`, `total_node_bytes`, and `sorted` consistent.
    fn removeNodeAt(self: *RootTree, index: usize) bool {
        _ = self.path_index.remove(self.nodes.items[index].path);
        var node = self.nodes.swapRemove(index);
        self.total_node_bytes -= node.size();
        self.freeNode(&node);
        if (index < self.nodes.items.len) {
            self.path_index.putAssumeCapacity(self.nodes.items[index].path, index);
        }
        self.sorted = false;
        return true;
    }

    pub fn importExt4View(self: *RootTree, source: *tree_cursor.Cursor) !void {
        _ = try self.importExt4ViewMode(source, .owned, "");
    }

    /// Imports only paths and metadata while retaining read-only content
    /// readers supplied by `source`. The source must outlive this tree.
    pub fn importExt4ViewBorrowed(self: *RootTree, source: *tree_cursor.Cursor) !void {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        _ = try self.importExt4ViewMode(source, .borrowed, "");
    }

    fn importExt4ViewMode(
        self: *RootTree,
        source: *tree_cursor.Cursor,
        mode: ImportMode,
        prefix: []const u8,
    ) !usize {
        var path_buffer = std.array_list.Managed(u8).init(self.allocator);
        defer path_buffer.deinit();
        var target_buffer = std.array_list.Managed(u8).init(self.allocator);
        defer target_buffer.deinit();

        var imported: usize = 0;
        source.reset();
        while (try source.next()) |entry| {
            imported += 1;
            const metadata = Metadata{
                .mode = entry.mode,
                .uid = entry.uid,
                .gid = entry.gid,
                .xattrs = entry.xattrs,
            };
            const path = try joinMountPath(&path_buffer, prefix, entry.path);
            switch (entry.kind) {
                .directory => try self.putDirectory(path, metadata),
                .fifo => try self.putFifo(path, metadata),
                .block_device, .char_device => try self.putDevice(
                    path,
                    if (entry.kind == .block_device) .block_device else .char_device,
                    .{ .major = entry.device.major, .minor = entry.device.minor },
                    metadata,
                ),
                // A hardlink names a path inside the same source, so the name
                // it shares an inode with moves under the mount point too.
                .hardlink => try self.putHardlink(
                    path,
                    try joinMountPath(&target_buffer, prefix, entry.hardlink_target),
                    metadata,
                ),
                .file => {
                    const content = entry.content orelse if (entry.size == 0)
                        emptyContentReader()
                    else
                        return error.MissingContent;
                    if (mode == .owned) {
                        try self.putFileReaderSparse(
                            path,
                            entry.size,
                            content,
                            entry.sparse_extents,
                            metadata,
                        );
                    } else {
                        try self.putBorrowedContent(
                            path,
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
                        try self.putOwnedContent(path, .symlink, entry.size, content, metadata);
                    } else {
                        try self.putBorrowedContent(
                            path,
                            .symlink,
                            entry.size,
                            content,
                            metadata,
                        );
                    }
                },
            }
        }
        return imported;
    }

    /// Imports a tree produced by the general ext4 importer. `FileTreeView`
    /// cannot carry timestamps, device numbers or hardlink targets, so the
    /// general tree is consumed directly rather than being squeezed through
    /// that interface and losing exactly the fidelity it exists to preserve.
    pub fn importExt4General(self: *RootTree, source: *ext4.GeneralTree) !void {
        self.setRootMetadata(.{
            .mode = source.root.mode,
            .uid = source.root.uid,
            .gid = source.root.gid,
            .atime = source.root.atime,
            .mtime = source.root.mtime,
            .ctime = source.root.ctime,
            .atime_nsec = source.root.atime_nsec,
            .mtime_nsec = source.root.mtime_nsec,
            .ctime_nsec = source.root.ctime_nsec,
            .crtime = source.root.crtime,
            .crtime_nsec = source.root.crtime_nsec,
            .xattrs = source.root.xattrs,
        });
        _ = try self.importExt4GeneralMode(source, .owned, "");
    }

    /// Imports a strict writer-compatible ext4 tree while retaining the
    /// source root inode metadata and xattrs alongside its entries.
    pub fn importExt4Strict(self: *RootTree, source: *ext4.StrictTree) !void {
        self.setRootMetadata(.{
            .mode = source.root.mode,
            .uid = source.root.uid,
            .gid = source.root.gid,
            .atime = source.root.atime,
            .mtime = source.root.mtime,
            .ctime = source.root.ctime,
            .atime_nsec = source.root.atime_nsec,
            .mtime_nsec = source.root.mtime_nsec,
            .ctime_nsec = source.root.ctime_nsec,
            .crtime = source.root.crtime,
            .crtime_nsec = source.root.crtime_nsec,
            .xattrs = source.root.xattrs,
        });
        _ = try self.importExt4ViewMode(source.fileTreeView(), .owned, "");
    }

    /// Imports paths and metadata while retaining read-only content readers
    /// owned by `source`, which must outlive this tree.
    pub fn importExt4GeneralBorrowed(self: *RootTree, source: *ext4.GeneralTree) !void {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        self.setRootMetadata(.{
            .mode = source.root.mode,
            .uid = source.root.uid,
            .gid = source.root.gid,
            .atime = source.root.atime,
            .mtime = source.root.mtime,
            .ctime = source.root.ctime,
            .atime_nsec = source.root.atime_nsec,
            .mtime_nsec = source.root.mtime_nsec,
            .ctime_nsec = source.root.ctime_nsec,
            .crtime = source.root.crtime,
            .crtime_nsec = source.root.crtime_nsec,
            .xattrs = source.root.xattrs,
        });
        _ = try self.importExt4GeneralMode(source, .borrowed, "");
    }

    /// Imports a tree produced by the XFS scanner. XFS entries carry their
    /// own timestamps, xattrs, hardlink targets and device numbers directly
    /// (mirroring `ext4.GeneralTree`'s shape), so — like
    /// `importExt4General` — the scanned tree is consumed directly rather
    /// than squeezed through a filesystem-neutral view that would lose that
    /// fidelity.
    pub fn importXfs(self: *RootTree, source: *xfs.Tree) !void {
        self.setRootMetadata(.{
            .mode = source.root.mode,
            .uid = source.root.uid,
            .gid = source.root.gid,
            .atime = source.root.atime,
            .mtime = source.root.mtime,
            .ctime = source.root.ctime,
            .atime_nsec = source.root.atime_nsec,
            .mtime_nsec = source.root.mtime_nsec,
            .ctime_nsec = source.root.ctime_nsec,
            .crtime = source.root.crtime,
            .crtime_nsec = source.root.crtime_nsec,
            .xattrs = @ptrCast(source.root.xattrs),
        });
        _ = try self.importXfsMode(source, .owned, "");
    }

    /// Imports paths and metadata while retaining read-only content readers
    /// owned by `source`, which must outlive this tree.
    pub fn importXfsBorrowed(self: *RootTree, source: *xfs.Tree) !void {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        self.setRootMetadata(.{
            .mode = source.root.mode,
            .uid = source.root.uid,
            .gid = source.root.gid,
            .atime = source.root.atime,
            .mtime = source.root.mtime,
            .ctime = source.root.ctime,
            .atime_nsec = source.root.atime_nsec,
            .mtime_nsec = source.root.mtime_nsec,
            .ctime_nsec = source.root.ctime_nsec,
            .crtime = source.root.crtime,
            .crtime_nsec = source.root.crtime_nsec,
            .xattrs = @ptrCast(source.root.xattrs),
        });
        _ = try self.importXfsMode(source, .borrowed, "");
    }

    fn importExt4GeneralMode(
        self: *RootTree,
        source: *ext4.GeneralTree,
        mode: ImportMode,
        prefix: []const u8,
    ) !usize {
        const append_only = self.nodes.items.len == 0 and prefix.len == 0;
        if (append_only) {
            try self.nodes.ensureUnusedCapacity(source.nodeCount());
            try self.path_index.ensureUnusedCapacity(
                std.math.cast(u32, source.nodeCount()) orelse return error.NodeLimitExceeded,
            );
            self.append_only_import = true;
        }
        defer {
            if (append_only) self.append_only_import = false;
        }

        var path_buffer = std.array_list.Managed(u8).init(self.allocator);
        defer path_buffer.deinit();
        var target_buffer = std.array_list.Managed(u8).init(self.allocator);
        defer target_buffer.deinit();

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
                .atime_nsec = entry.atime_nsec,
                .mtime_nsec = entry.mtime_nsec,
                .ctime_nsec = entry.ctime_nsec,
                .crtime = entry.crtime,
                .crtime_nsec = entry.crtime_nsec,
                .xattrs = entry.xattrs,
            };
            const path = try joinMountPath(&path_buffer, prefix, entry.path);
            switch (entry.kind) {
                .directory => try self.putDirectory(path, metadata),
                .fifo => try self.putFifo(path, metadata),
                .block_device => try self.putDevice(path, .block_device, .{
                    .major = entry.device.major,
                    .minor = entry.device.minor,
                }, metadata),
                .char_device => try self.putDevice(path, .char_device, .{
                    .major = entry.device.major,
                    .minor = entry.device.minor,
                }, metadata),
                // The scanner always emits the content-bearing name before any
                // further link to it, so the target is already present. Both
                // names come from the same source, so a mount moves the two of
                // them together and the link survives the merge.
                .hardlink => try self.putHardlink(
                    path,
                    try joinMountPath(&target_buffer, prefix, entry.hardlink_target),
                    metadata,
                ),
                .file, .symlink => {
                    const kind: Kind = if (entry.kind == .file) .file else .symlink;
                    const content = entry.content orelse if (entry.size == 0)
                        emptyContentReader()
                    else
                        return error.MissingContent;
                    if (mode == .borrowed) {
                        try self.putBorrowedContent(path, kind, entry.size, content, metadata);
                        continue;
                    }
                    if (kind == .file) {
                        try self.putFileReaderSparse(
                            path,
                            entry.size,
                            content,
                            entry.sparse_extents,
                            metadata,
                        );
                        continue;
                    }
                    try self.putOwnedContent(path, .symlink, entry.size, content, metadata);
                },
            }
        }
        return source.nodeCount();
    }

    fn importXfsMode(
        self: *RootTree,
        source: *xfs.Tree,
        mode: ImportMode,
        prefix: []const u8,
    ) !usize {
        var path_buffer = std.array_list.Managed(u8).init(self.allocator);
        defer path_buffer.deinit();
        var target_buffer = std.array_list.Managed(u8).init(self.allocator);
        defer target_buffer.deinit();

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
                .atime_nsec = entry.atime_nsec,
                .mtime_nsec = entry.mtime_nsec,
                .ctime_nsec = entry.ctime_nsec,
                .crtime = entry.crtime,
                .crtime_nsec = entry.crtime_nsec,
                // xfs.Xattr and tree_cursor.Xattr are both exactly
                // `{name: []const u8, value: []const u8}`; reinterpreting
                // the slice reuses the whole existing xattr pipeline
                // (limits, dedup, sorting) instead of duplicating it.
                .xattrs = @ptrCast(entry.xattrs),
            };
            const path = try joinMountPath(&path_buffer, prefix, entry.path);
            switch (entry.kind) {
                .directory => try self.putDirectory(path, metadata),
                .fifo => try self.putFifo(path, metadata),
                // root_tree.Kind has no socket variant; reject it explicitly
                // rather than silently dropping or misclassifying it, the
                // same way ext4.zig rejects socket inodes during its scan.
                .socket => return error.UnsupportedSocketInode,
                .block_device => try self.putDevice(path, .block_device, .{
                    .major = entry.device.major,
                    .minor = entry.device.minor,
                }, metadata),
                .char_device => try self.putDevice(path, .char_device, .{
                    .major = entry.device.major,
                    .minor = entry.device.minor,
                }, metadata),
                // The scanner always emits the content-bearing name before any
                // further link to it, so the target is already present. Both
                // names come from the same source, so a mount moves the two of
                // them together and the link survives the merge.
                .hardlink => try self.putHardlink(
                    path,
                    try joinMountPath(&target_buffer, prefix, entry.hardlink_target),
                    metadata,
                ),
                .file, .symlink => {
                    const kind: Kind = if (entry.kind == .file) .file else .symlink;
                    // xfs always attaches a (possibly zero-length) content
                    // reader to file/symlink entries, but the null fallback
                    // is kept for defense in depth, matching the ext4 path.
                    const content = entry.content orelse if (entry.size == 0)
                        emptyXfsContentReader()
                    else
                        return error.MissingContent;
                    if (mode == .borrowed) {
                        try self.putBorrowedXfsContent(path, kind, entry.size, content, metadata);
                        continue;
                    }
                    if (kind == .file) {
                        try self.putXfsFileReader(path, entry.size, content, metadata);
                        continue;
                    }
                    try self.putOwnedXfsContent(path, .symlink, entry.size, content, metadata);
                },
            }
        }
        return source.nodeCount();
    }

    /// Spools `content` into this tree and records it at `path`, rolling the
    /// spool back to where it was if any part of that fails.
    fn putOwnedContent(
        self: *RootTree,
        path: []const u8,
        kind: Kind,
        size: u64,
        content: tree_cursor.Cursor.ContentReader,
        metadata: Metadata,
    ) !void {
        try self.checkFileBytes(size);
        try validatePath(path, self.limits, self.diagnostic);
        const old_spool_len = self.spool_len;
        const owned = self.spoolContent(size, content) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
        self.putNode(path, kind, metadata, .{ .content = owned }) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
    }

    // -----------------------------------------------------------------------
    // Mounting a second source under a path prefix
    //
    // A typical installed system is spread across several filesystems that a
    // simpler image wants collapsed into one. Merging them here, before the
    // writer runs, is what keeps hardlinks, xattrs, permissions, device nodes
    // and timestamps intact across the merge: the writer sees one tree and
    // cannot tell how many filesystems it came from.
    //
    // A mount *replaces* what the tree already had at the mount point rather
    // than merging with it entry by entry, because that is what a real mount
    // does. It matters: an installed root filesystem's `/boot` is a non-empty
    // stub whose contents the boot filesystem hides, and merging the two would
    // produce an image carrying a stale kernel or a stale bootloader
    // configuration beside the real one -- which looks fine and can boot the
    // wrong thing, or nothing at all.
    // -----------------------------------------------------------------------

    /// What a mount did, so a caller can state it rather than diff for it.
    pub const MountReport = struct {
        /// Nodes the mount point hid. Non-zero is entirely normal: a root
        /// filesystem's `/boot` stub is exactly this.
        shadowed_nodes: usize,
        /// Nodes taken from the mounted source, excluding the mount point
        /// directory itself.
        imported_nodes: usize,
    };

    /// Mounts a strict-profile or FAT source, whose entries reach this tree
    /// through `FileTreeView`. `root` is the mounted filesystem's own root
    /// directory metadata, which becomes the metadata of the mount point,
    /// exactly as a real mount makes the mounted root's mode and ownership
    /// the ones visible at the mount point.
    pub fn mountExt4View(
        self: *RootTree,
        source: *tree_cursor.Cursor,
        target: []const u8,
        root: Metadata,
    ) !MountReport {
        return self.mountInternal(target, root, .owned, .{ .view = source });
    }

    pub fn mountExt4ViewBorrowed(
        self: *RootTree,
        source: *tree_cursor.Cursor,
        target: []const u8,
        root: Metadata,
    ) !MountReport {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        return self.mountInternal(target, root, .borrowed, .{ .view = source });
    }

    pub fn mountExt4General(
        self: *RootTree,
        source: *ext4.GeneralTree,
        target: []const u8,
    ) !MountReport {
        return self.mountInternal(target, generalRootMetadata(source), .owned, .{ .general = source });
    }

    pub fn mountExt4GeneralBorrowed(
        self: *RootTree,
        source: *ext4.GeneralTree,
        target: []const u8,
    ) !MountReport {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        return self.mountInternal(
            target,
            generalRootMetadata(source),
            .borrowed,
            .{ .general = source },
        );
    }

    /// Mounts a FAT volume. Its entries carry the metadata the scan was told
    /// to synthesize, and so does the mount point.
    pub fn mountFat(
        self: *RootTree,
        source: *fat32.Tree,
        target: []const u8,
    ) !MountReport {
        return self.mountInternal(target, fatRootMetadata(source), .owned, .{
            .view = source.fileTreeView(),
        });
    }

    pub fn mountFatBorrowed(
        self: *RootTree,
        source: *fat32.Tree,
        target: []const u8,
    ) !MountReport {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        return self.mountInternal(target, fatRootMetadata(source), .borrowed, .{
            .view = source.fileTreeView(),
        });
    }

    /// Mounts an XFS volume produced by `xfs.scanReadable`. XFS entries carry
    /// their own timestamps, xattrs, hardlink targets and device numbers
    /// directly, so — like `mountExt4General` — the scanned tree is
    /// consumed directly rather than through `FileTreeView`.
    pub fn mountXfs(
        self: *RootTree,
        source: *xfs.Tree,
        target: []const u8,
    ) !MountReport {
        return self.mountInternal(target, xfsRootMetadata(source), .owned, .{ .xfs = source });
    }

    pub fn mountXfsBorrowed(
        self: *RootTree,
        source: *xfs.Tree,
        target: []const u8,
    ) !MountReport {
        if (self.storage != .memory) return error.BorrowedImportRequiresMemoryTree;
        return self.mountInternal(
            target,
            xfsRootMetadata(source),
            .borrowed,
            .{ .xfs = source },
        );
    }

    const MountSource = union(enum) {
        view: *tree_cursor.Cursor,
        general: *ext4.GeneralTree,
        xfs: *xfs.Tree,
    };

    fn mountInternal(
        self: *RootTree,
        target: []const u8,
        root: Metadata,
        mode: ImportMode,
        source: MountSource,
    ) !MountReport {
        const relative = try mountTargetToRelative(target);
        try validatePath(relative, self.limits, self.diagnostic);
        try self.validateMountPoint(relative);

        // A hardlink outside the mount point whose inode-bearing name is
        // inside it would be left pointing at nothing. That is a genuinely
        // ambiguous merge -- the link cannot be preserved and cannot be
        // silently turned into a copy -- so it is refused by name.
        if (self.removalBreaksHardlinks(relative, true)) {
            return error.MountShadowsHardlinkTarget;
        }

        // Owned separately: `removeInternal` frees the node that `relative`
        // may currently borrow its bytes from.
        const owned_target = try self.allocator.dupe(u8, relative);
        defer self.allocator.free(owned_target);

        var shadowed: usize = 0;
        for (self.nodes.items) |node| {
            if (!std.mem.eql(u8, node.path, owned_target) and
                pathEqualsOrDescendant(owned_target, node.path))
            {
                shadowed += 1;
            }
        }
        _ = self.removeInternal(owned_target, true);
        try self.putDirectory(owned_target, root);

        const before = self.nodes.items.len;
        const imported = switch (source) {
            .view => |view| try self.importExt4ViewMode(view, mode, owned_target),
            .general => |general| try self.importExt4GeneralMode(general, mode, owned_target),
            .xfs => |tree| try self.importXfsMode(tree, mode, owned_target),
        };
        // Every mounted entry's parent is a directory the same source already
        // emitted, so nothing is created implicitly and nothing may replace an
        // earlier entry. A count that does not add up means the merge dropped
        // or collided with something, which is precisely the silent corruption
        // this whole path exists to avoid.
        if (self.nodes.items.len != before + imported) return error.MountedNodeCountMismatch;

        return .{ .shadowed_nodes = shadowed, .imported_nodes = imported };
    }

    /// A mount point must already exist, as a directory, reached without
    /// traversing a symlink -- exactly the preconditions `mount(8)` enforces.
    /// Creating a missing one would be a silent fallback that turns a typo
    /// into a plausible-looking image.
    fn validateMountPoint(self: *const RootTree, relative: []const u8) !void {
        var scan: usize = 0;
        while (std.mem.indexOfScalarPos(u8, relative, scan, '/')) |slash| {
            const ancestor = relative[0..slash];
            const index = self.findIndex(ancestor) orelse return error.MissingMountTargetParent;
            switch (self.nodes.items[index].kind) {
                .directory => {},
                // A symlink in the path means the mount point named here and
                // the one the guest would resolve are different directories.
                .symlink => return error.MountTargetTraversesSymlink,
                else => return error.MountTargetTraversesNonDirectory,
            }
            scan = slash + 1;
        }
        const index = self.findIndex(relative) orelse return error.MissingMountTarget;
        switch (self.nodes.items[index].kind) {
            .directory => {},
            .symlink => return error.MountTargetIsSymlink,
            else => return error.MountTargetNotDirectory,
        }
    }

    /// Returns the filesystem-neutral pull cursor over this tree: every node
    /// in path order, with its kind, mode/uid/gid, device numbers, hardlink
    /// target, size, a content reader, and xattrs -- everything
    /// `ext4.populate` (or a future filesystem writer written against
    /// `tree_cursor.Cursor` rather than this module) needs to write an
    /// inode. This is the tree's primary consumption shape; `ext4View` is a
    /// compatibility alias for callers written before this name existed.
    ///
    /// Root-directory metadata is deliberately not part of the cursor: see
    /// `rootMetadata`/`setRootMetadata` and `ext4.PopulateOptions`'s `root_*`
    /// fields, which carry it instead of folding it silently into the entry
    /// stream.
    ///
    /// The returned pointer aliases this tree and is valid only until the
    /// next call that mutates it (`put*`, `remove`, a `mount*`, or another
    /// call to `cursor`/`ext4View`); a consumer resets it with
    /// `Cursor.reset()` rather than asking for a new one mid-drain.
    pub fn cursor(self: *RootTree) !*tree_cursor.Cursor {
        try self.sortAndValidate();
        self.iteration_index = 0;
        self.tree_cursor_view = .{
            .ctx = self,
            .next_fn = nextCursor,
            .reset_fn = resetCursor,
        };
        return &self.tree_cursor_view;
    }

    /// Deprecated alias for `cursor`, kept for source compatibility with
    /// callers written before the neutral cursor had its own name.
    pub fn ext4View(self: *RootTree) !*tree_cursor.Cursor {
        return self.cursor();
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

    /// The smallest FAT32 volume `populateFat32` fits this tree into.
    ///
    /// Derived from the tree rather than taken from a constant, because a
    /// captured system's EFI system partition holds whatever its vendor put
    /// there and no fixed number is right for all of them. FAT32's own floor
    /// of 65525 clusters usually dominates the answer, which is worth
    /// knowing rather than being surprised by: a nearly empty ESP still
    /// costs tens of megabytes.
    pub fn minimumFat32VolumeLength(
        self: *RootTree,
        options: FatPopulateOptions,
        size_options: fat32.VolumeLengthOptions,
    ) !u64 {
        try self.sortAndValidateRepresentable();
        try self.preflightFat32(options);

        var file_sizes = std.array_list.Managed(u64).init(self.allocator);
        defer file_sizes.deinit();
        var directory_slots = std.array_list.Managed(u32).init(self.allocator);
        defer directory_slots.deinit();
        // Slot 0 is the root directory, which every volume has and no node
        // names.
        try directory_slots.append(fat32.root_directory_overhead_slots);

        // Every directory is looked up by path rather than tracked on a
        // stack of open ones. A stack would need a directory's descendants
        // to follow it without interruption, and they do not: `/` is 0x2F,
        // so a sibling named `entries.srel` sorts between `entries` and
        // `entries/arch.conf` -- which is exactly the pair `bootctl` writes
        // onto a systemd-boot ESP. What sorting does guarantee is that a
        // directory precedes its own children, since its path is a prefix
        // of theirs, and that is all this needs.
        var directories = std.StringHashMap(usize).init(self.allocator);
        defer directories.deinit();
        try directories.put("", 0);

        for (self.nodes.items) |node| {
            const split = splitPath(node.path);
            const parent_slot = directories.get(split.parent) orelse
                return error.MissingParentDirectory;
            directory_slots.items[parent_slot] += try fat32.nameSlotCount(split.name);
            switch (node.kind) {
                .directory => {
                    try directory_slots.append(fat32.subdirectory_overhead_slots);
                    try directories.put(node.path, directory_slots.items.len - 1);
                },
                // `preflightFat32` has already refused every other kind.
                .file => try file_sizes.append(node.size()),
                else => unreachable,
            }
        }

        return fat32.minimumVolumeLength(.{
            .file_sizes = file_sizes.items,
            .directory_slots = directory_slots.items,
        }, size_options);
    }

    pub fn manifestDigest(self: *RootTree) ![32]u8 {
        try self.sortAndValidateRepresentable();
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("miz-root-tree-v1\x00");
        hashInt(&hash, self.root_metadata.mode);
        hashInt(&hash, self.root_metadata.uid);
        hashInt(&hash, self.root_metadata.gid);
        hashOptionalInt(&hash, self.root_metadata.atime);
        hashOptionalInt(&hash, self.root_metadata.mtime);
        hashOptionalInt(&hash, self.root_metadata.ctime);
        hashSubsecondTimes(&hash, self.root_metadata);
        for (self.root_metadata.xattrs) |xattr| {
            hashString(&hash, xattr.name);
            hashString(&hash, xattr.value);
        }
        for (self.nodes.items) |node| {
            hashString(&hash, node.path);
            hashInt(&hash, @intFromEnum(node.kind));
            hashInt(&hash, node.metadata.mode);
            hashInt(&hash, node.metadata.uid);
            hashInt(&hash, node.metadata.gid);
            hashOptionalInt(&hash, node.metadata.atime);
            hashOptionalInt(&hash, node.metadata.mtime);
            hashOptionalInt(&hash, node.metadata.ctime);
            hashSubsecondTimes(&hash, node.metadata);
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
            for (node.sparse_extents) |sparse| {
                hashInt(&hash, sparse.logical_block);
                hashInt(&hash, sparse.block_count);
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
                    .sparse_extents = node.sparse_extents,
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

    fn readNodeContentByIndex(self: *const RootTree, index: usize, buffer: []u8, offset: u64) !usize {
        return switch (self.nodes.items[index].payload) {
            .content => |content| content.readAt(buffer, offset),
            else => 0,
        };
    }

    /// Adapts this tree to the generic SquashFS `TreeSource`, so the filesystem
    /// codec can pull nodes without depending on `RootTree` itself. Sort the
    /// tree (`sortNodes`) beforehand if a specific enumeration order matters;
    /// the writer re-sorts by path regardless. Node kinds the SquashFS writer
    /// cannot represent (hardlink, device, fifo) and metadata it does not model
    /// (extended attributes) are reported as precise errors rather than being
    /// silently dropped.
    pub fn squashfsSource(self: *const RootTree) squashfs.TreeSource {
        return .{ .context = self, .vtable = &squashfs_vtable };
    }

    const squashfs_vtable = squashfs.TreeSource.VTable{
        .root = squashfsRoot,
        .count = squashfsCount,
        .node = squashfsNode,
        .read = squashfsRead,
    };

    fn squashfsCtx(context: *const anyopaque) *const RootTree {
        return @ptrCast(@alignCast(context));
    }

    fn squashfsRoot(context: *const anyopaque) squashfs.SourceRoot {
        const self = squashfsCtx(context);
        return .{
            .mode = self.root_metadata.mode,
            .uid = self.root_metadata.uid,
            .gid = self.root_metadata.gid,
            .mtime = clampMtime(self.root_metadata.mtime),
        };
    }

    fn squashfsCount(context: *const anyopaque) usize {
        return squashfsCtx(context).nodes.items.len;
    }

    fn squashfsNode(context: *const anyopaque, index: usize) anyerror!squashfs.SourceNode {
        const self = squashfsCtx(context);
        const node = self.nodes.items[index];
        if (node.metadata.xattrs.len != 0) return error.UnsupportedXattrs;
        const kind: squashfs.SourceKind = switch (node.kind) {
            .directory => .directory,
            .file => .file,
            .symlink => .symlink,
            .hardlink, .block_device, .char_device, .fifo => return error.UnsupportedNodeKind,
        };
        return .{
            .path = node.path,
            .kind = kind,
            .mode = node.metadata.mode,
            .uid = node.metadata.uid,
            .gid = node.metadata.gid,
            .mtime = clampMtime(node.metadata.mtime),
            .size = node.size(),
            .symlink_target = &.{},
        };
    }

    fn squashfsRead(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        return squashfsCtx(context).readNodeContentByIndex(index, buffer, offset);
    }

    /// Adapts this tree to the generic ISO9660 `TreeSource`, so the ISO writer
    /// can pull nodes without depending on `RootTree` itself. Sort the tree
    /// (`sortNodes`) beforehand if a specific enumeration order matters; the
    /// writer re-sorts by path regardless. Node kinds the ISO writer cannot
    /// represent (hardlink, device, fifo) and metadata it does not model
    /// (extended attributes) are reported as precise errors rather than being
    /// silently dropped.
    pub fn iso9660Source(self: *const RootTree) iso9660.TreeSource {
        return .{ .context = self, .vtable = &iso9660_vtable };
    }

    const iso9660_vtable = iso9660.TreeSource.VTable{
        .root = iso9660Root,
        .count = iso9660Count,
        .node = iso9660Node,
        .read = iso9660Read,
    };

    fn iso9660Ctx(context: *const anyopaque) *const RootTree {
        return @ptrCast(@alignCast(context));
    }

    fn iso9660Root(context: *const anyopaque) iso9660.SourceRoot {
        const self = iso9660Ctx(context);
        return .{
            .mode = self.root_metadata.mode,
            .uid = self.root_metadata.uid,
            .gid = self.root_metadata.gid,
            .mtime = self.root_metadata.mtime orelse 0,
        };
    }

    fn iso9660Count(context: *const anyopaque) usize {
        return iso9660Ctx(context).nodes.items.len;
    }

    fn iso9660Node(context: *const anyopaque, index: usize) anyerror!iso9660.SourceNode {
        const self = iso9660Ctx(context);
        const node = self.nodes.items[index];
        if (node.metadata.xattrs.len != 0) return error.UnsupportedXattrs;
        const kind: iso9660.SourceKind = switch (node.kind) {
            .directory => .directory,
            .file => .file,
            .symlink => .symlink,
            .hardlink, .block_device, .char_device, .fifo => return error.UnsupportedNodeKind,
        };
        return .{
            .path = node.path,
            .kind = kind,
            .mode = node.metadata.mode,
            .uid = node.metadata.uid,
            .gid = node.metadata.gid,
            .mtime = node.metadata.mtime orelse 0,
            .size = node.size(),
            .symlink_target = &.{},
        };
    }

    fn iso9660Read(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        return iso9660Ctx(context).readNodeContentByIndex(index, buffer, offset);
    }

    fn putNode(
        self: *RootTree,
        path: []const u8,
        kind: Kind,
        metadata: Metadata,
        payload: Payload,
    ) anyerror!void {
        if (self.append_only_import) {
            return self.appendImportedNode(path, kind, metadata, payload);
        }
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

        // Overlaying a node removes at most: the destination node, any
        // descendants of the destination (only when a non-directory shadows an
        // existing directory), and any non-directory ancestor that must become
        // a directory. Only a `.file` node is ever a hardlink target, and
        // replacing a file with another file at the same path is explicitly
        // allowed, so the common customize overlays -- a new file, a changed
        // file, or a re-published symlink -- provably break no hardlink and
        // drop no descendants. Detect that case and account for it in O(1) via
        // the path index and the running byte total, falling back to the full
        // O(n) scan only for the rare directory-shadowing / ancestor-
        // replacement cases. The old unconditional scans made production-scale
        // customize (tens of thousands of overlays) O(n^2).
        const existing_index = self.findIndex(owned_path);
        var has_replace_parent = false;
        for (parents.items) |parent| {
            if (parent.replace_existing) {
                has_replace_parent = true;
                break;
            }
        }
        const shadows_directory = kind != .directory and
            if (existing_index) |i| self.nodes.items[i].kind == .directory else false;
        const replaces_file_with_other = if (existing_index) |i|
            self.nodes.items[i].kind == .file and kind != .file
        else
            false;

        var final_bytes: u64 = undefined;
        var final_node_count: usize = undefined;
        if (has_replace_parent or shadows_directory or replaces_file_with_other) {
            if (self.overlayBreaksHardlinks(owned_path, kind, parents.items)) {
                return error.HardlinkTargetInUse;
            }
            var remaining_nodes: usize = 0;
            var scanned_bytes = payloadSize(payload);
            for (self.nodes.items) |node| {
                if (removedByOverlay(node.path, owned_path, kind, parents.items)) continue;
                remaining_nodes += 1;
                scanned_bytes = std.math.add(u64, scanned_bytes, node.size()) catch
                    return error.TotalContentLimitExceeded;
            }
            final_bytes = scanned_bytes;
            const additions = std.math.add(usize, parents.items.len, 1) catch
                return error.NodeLimitExceeded;
            final_node_count = std.math.add(usize, remaining_nodes, additions) catch
                return error.NodeLimitExceeded;
        } else {
            // Fast path: nothing removed here can be a live hardlink target and
            // no descendants are dropped, so `overlayBreaksHardlinks` is
            // necessarily false. Every entry in `parents.items` is a brand-new
            // directory (none replace an existing node), and the destination is
            // the only node that might be swapped out.
            const removed_count: usize = if (existing_index != null) 1 else 0;
            const removed_bytes: u64 = if (existing_index) |i| self.nodes.items[i].size() else 0;
            const additions = std.math.add(usize, parents.items.len, 1) catch
                return error.NodeLimitExceeded;
            final_node_count = std.math.add(
                usize,
                self.nodes.items.len - removed_count,
                additions,
            ) catch return error.NodeLimitExceeded;
            final_bytes = std.math.add(
                u64,
                self.total_node_bytes - removed_bytes,
                payloadSize(payload),
            ) catch return error.TotalContentLimitExceeded;
        }
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
        try self.path_index.ensureUnusedCapacity(
            std.math.cast(u32, parents.items.len + 1) orelse return error.NodeLimitExceeded,
        );

        for (parents.items) |*parent| {
            if (parent.replace_existing) _ = self.removeInternal(parent.path, true);
            const parent_index = self.nodes.items.len;
            self.nodes.appendAssumeCapacity(.{
                .path = parent.path,
                .kind = .directory,
                .metadata = .{ .mode = 0o755 },
                .owned_xattrs = &.{},
                .payload = .none,
            });
            self.path_index.putAssumeCapacity(
                self.nodes.items[parent_index].path,
                parent_index,
            );
            parent.path = &.{};
        }
        _ = self.removeInternal(owned_path, kind != .directory);
        const index = self.nodes.items.len;
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
                .atime_nsec = metadata.atime_nsec,
                .mtime_nsec = metadata.mtime_nsec,
                .ctime_nsec = metadata.ctime_nsec,
                .crtime = metadata.crtime,
                .crtime_nsec = metadata.crtime_nsec,
                .xattrs = ownedXattrsView(owned_xattrs),
            },
            .owned_xattrs = owned_xattrs,
            .payload = payload,
        });
        self.path_index.putAssumeCapacity(self.nodes.items[index].path, index);
        path_owned = false;
        xattrs_owned = false;
        payload_owned = false;
        self.total_node_bytes = final_bytes;
        self.sorted = false;
    }

    fn appendImportedNode(
        self: *RootTree,
        path: []const u8,
        kind: Kind,
        metadata: Metadata,
        payload: Payload,
    ) !void {
        var payload_owned = true;
        errdefer if (payload_owned) self.freePayload(payload);
        try validatePath(path, self.limits, self.diagnostic);
        if (self.findIndex(path) != null) return error.DuplicatePath;
        if (std.fs.path.dirname(path)) |parent| {
            if (parent.len != 0) {
                const parent_index = self.findIndex(parent) orelse return error.MissingParent;
                if (self.nodes.items[parent_index].kind != .directory) {
                    return error.ParentNotDirectory;
                }
            }
        }
        const final_node_count = std.math.add(usize, self.nodes.items.len, 1) catch
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
        const final_bytes = std.math.add(
            u64,
            self.total_node_bytes,
            payloadSize(payload),
        ) catch return error.TotalContentLimitExceeded;
        limits_mod.observe(self.diagnostic, .total_bytes, final_bytes);
        if (final_bytes > self.limits.max_total_bytes) {
            return limits_mod.exceeded(
                self.diagnostic,
                .total_bytes,
                final_bytes,
                self.limits.max_total_bytes,
            );
        }

        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        const owned_xattrs = try self.dupeXattrs(metadata.xattrs);
        errdefer freeOwnedXattrs(self.allocator, owned_xattrs);
        try self.nodes.ensureUnusedCapacity(1);
        try self.path_index.ensureUnusedCapacity(1);
        const index = self.nodes.items.len;
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
                .atime_nsec = metadata.atime_nsec,
                .mtime_nsec = metadata.mtime_nsec,
                .ctime_nsec = metadata.ctime_nsec,
                .crtime = metadata.crtime,
                .crtime_nsec = metadata.crtime_nsec,
                .xattrs = ownedXattrsView(owned_xattrs),
            },
            .owned_xattrs = owned_xattrs,
            .payload = payload,
        });
        self.path_index.putAssumeCapacity(self.nodes.items[index].path, index);
        payload_owned = false;
        self.total_node_bytes = final_bytes;
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
        var scan: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, scan, '/')) |slash| {
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
            scan = slash + 1;
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

    /// `reader` is `anytype` rather than `tree_cursor.Cursor.ContentReader`
    /// because every byte here is read once and copied immediately, so the
    /// reader's own type never has to be stored: an `xfs.ContentReader`
    /// works exactly as well as ext4's, without an adapter.
    fn spoolContent(
        self: *RootTree,
        size: u64,
        reader: anytype,
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
        reader: tree_cursor.Cursor.ContentReader,
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

    /// Same contract as `putBorrowedContent`, for an `xfs.ContentReader`
    /// instead of ext4's. The two are structurally identical but distinct
    /// Zig types, so the reader is kept in its own `Content.source` variant
    /// rather than adapted to look like the other.
    fn putBorrowedXfsContent(
        self: *RootTree,
        path: []const u8,
        kind: Kind,
        size: u64,
        reader: xfs.ContentReader,
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
            .source = .{ .borrowed_xfs = reader },
        } }) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
    }

    /// Spools an `xfs.ContentReader`'s bytes into this tree, exactly like
    /// `putFileReader` does for ext4's reader shape.
    fn putXfsFileReader(
        self: *RootTree,
        path: []const u8,
        size: u64,
        reader: xfs.ContentReader,
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

    /// Spools an `xfs.ContentReader`'s bytes for a non-file kind (a
    /// symlink), exactly like `putOwnedContent` does for ext4's reader
    /// shape.
    fn putOwnedXfsContent(
        self: *RootTree,
        path: []const u8,
        kind: Kind,
        size: u64,
        content: xfs.ContentReader,
        metadata: Metadata,
    ) !void {
        try self.checkFileBytes(size);
        try validatePath(path, self.limits, self.diagnostic);
        const old_spool_len = self.spool_len;
        const owned = self.spoolContent(size, content) catch |err| {
            try self.rollbackSpool(old_spool_len);
            return err;
        };
        self.putNode(path, kind, metadata, .{ .content = owned }) catch |err| {
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
        const typed_reader: tree_cursor.Cursor.ContentReader = .{
            .ctx = &file_reader,
            .read_at_fn = FileReader.readAt,
        };
        const digest = try hashContentReader(typed_reader, size);
        const owned_path = try self.allocator.dupe(u8, path);
        self.spool_len = end;
        return .{
            .io = self.io,
            .size = size,
            .sha256 = digest,
            .source = .{ .host_path = owned_path },
        };
    }

    fn dupeXattrs(self: *RootTree, source: []const tree_cursor.Xattr) ![]tree_cursor.OwnedXattr {
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

        const out = try self.allocator.alloc(tree_cursor.OwnedXattr, source.len);
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
        std.mem.sort(tree_cursor.OwnedXattr, out, {}, lessXattr);
        if (out.len > 1) {
            for (out[1..], out[0 .. out.len - 1]) |current, previous| {
                if (std.mem.eql(u8, current.name, previous.name)) return error.DuplicateXattr;
            }
        }
        return out;
    }

    fn sortAndValidate(self: *RootTree) !void {
        try self.sortAndValidateRepresentable();
        // Only the permission and setuid/setgid/sticky bits are the tree's to
        // choose; the file-type bits come from the kind, and a mode carrying
        // them would silently turn the root into something else.
        if (self.root_metadata.mode > 0o7777) return error.Ext4RootMetadataUnsupported;
        try validateExt4Time(self.root_metadata.atime);
        try validateExt4Time(self.root_metadata.mtime);
        try validateExt4Time(self.root_metadata.ctime);
        try validateExt4Time(self.root_metadata.crtime);
        try validateSubsecondTimes(self.root_metadata);
        for (self.nodes.items) |node| {
            if (node.metadata.mode > 0o7777) return error.Ext4ModeUnsupported;
            try validateExt4Time(node.metadata.atime);
            try validateExt4Time(node.metadata.mtime);
            try validateExt4Time(node.metadata.ctime);
            try validateExt4Time(node.metadata.crtime);
            try validateSubsecondTimes(node.metadata);
        }
    }

    /// ext4 stores each time as a signed 32-bit seconds field plus the two
    /// epoch bits of the matching `i_*_extra` word, which together reach
    /// 1901-12-13 through 2446-05-10. Anything outside that has nowhere to
    /// go, and refusing is the only honest option: a wrapped value looks like
    /// a perfectly ordinary date.
    /// The `i_*_extra` words carry the sub-second part in the thirty bits
    /// above the two epoch bits, so a value of a billion or more does not
    /// merely fail to fit -- it overlaps the epoch and moves the whole
    /// timestamp by 136 years.
    fn validateSubsecondTimes(metadata: anytype) !void {
        inline for (.{
            metadata.atime_nsec,
            metadata.mtime_nsec,
            metadata.ctime_nsec,
            metadata.crtime_nsec,
        }) |nanoseconds| {
            if (nanoseconds >= 1_000_000_000) return error.Ext4TimestampsUnsupported;
        }
    }

    fn validateExt4Time(value: ?i64) !void {
        const seconds = value orelse return;
        if (seconds < ext4.min_representable_time or seconds > ext4.max_representable_time) {
            return error.Ext4TimestampsUnsupported;
        }
    }

    fn sortAndValidateRepresentable(self: *RootTree) !void {
        if (!self.sorted) {
            std.mem.sort(Node, self.nodes.items, {}, lessNode);
            for (self.nodes.items, 0..) |node, index| {
                self.path_index.putAssumeCapacity(node.path, index);
            }
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
        return self.path_index.get(path);
    }

    fn recomputeTotalNodeBytes(self: *RootTree) void {
        var total: u64 = 0;
        for (self.nodes.items) |node| total += node.size();
        self.total_node_bytes = total;
    }

    fn freeNode(self: *RootTree, node: *Node) void {
        self.allocator.free(node.path);
        self.allocator.free(node.sparse_extents);
        freeOwnedXattrs(self.allocator, node.owned_xattrs);
        self.freePayload(node.payload);
    }

    fn freePayload(self: *RootTree, payload: Payload) void {
        switch (payload) {
            .hardlink_target => |target| self.allocator.free(target),
            .content => |content| switch (content.source) {
                .memory => |bytes| self.allocator.free(bytes),
                .host_path => |path| self.allocator.free(path),
                .spooled, .borrowed, .borrowed_xfs => {},
            },
            .none, .device => {},
        }
    }

    fn resetCursor(ctx: *anyopaque) void {
        const self: *RootTree = @ptrCast(@alignCast(ctx));
        self.iteration_index = 0;
    }

    fn nextCursor(ctx: *anyopaque) tree_cursor.Cursor.IteratorError!?tree_cursor.Cursor.Entry {
        const self: *RootTree = @ptrCast(@alignCast(ctx));
        if (self.iteration_index >= self.nodes.items.len) return null;
        const node = &self.nodes.items[self.iteration_index];
        self.iteration_index += 1;
        const kind: tree_cursor.Kind = switch (node.kind) {
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
                .read_at_fn = readCursorContent,
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
            .atime = node.metadata.atime,
            .mtime = node.metadata.mtime,
            .ctime = node.metadata.ctime,
            .atime_nsec = node.metadata.atime_nsec,
            .mtime_nsec = node.metadata.mtime_nsec,
            .ctime_nsec = node.metadata.ctime_nsec,
            .crtime = node.metadata.crtime,
            .crtime_nsec = node.metadata.crtime_nsec,
            .sparse_extents = node.sparse_extents,
        };
    }

    fn readCursorContent(
        ctx: *const anyopaque,
        buffer: []u8,
        offset: u64,
    ) tree_cursor.Cursor.ContentError!usize {
        const content: *const Content = @ptrCast(@alignCast(ctx));
        return content.readAt(buffer, offset) catch error.ReadFailed;
    }
};

/// `reader` is `anytype` so this works for both ext4's and xfs's identically
/// shaped, but nominally distinct, `ContentReader` types.
fn hashContentReader(
    reader: anytype,
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

const ImportMode = enum { owned, borrowed };

fn generalRootMetadata(source: *const ext4.GeneralTree) Metadata {
    return .{
        .mode = source.root.mode,
        .uid = source.root.uid,
        .gid = source.root.gid,
        .atime = source.root.atime,
        .mtime = source.root.mtime,
        .ctime = source.root.ctime,
        .atime_nsec = source.root.atime_nsec,
        .mtime_nsec = source.root.mtime_nsec,
        .ctime_nsec = source.root.ctime_nsec,
        .crtime = source.root.crtime,
        .crtime_nsec = source.root.crtime_nsec,
        .xattrs = source.root.xattrs,
    };
}

fn fatRootMetadata(source: *const fat32.Tree) Metadata {
    return .{
        .mode = source.metadata.directory_mode,
        .uid = source.metadata.uid,
        .gid = source.metadata.gid,
    };
}

fn xfsRootMetadata(source: *const xfs.Tree) Metadata {
    return .{
        .mode = source.root.mode,
        .uid = source.root.uid,
        .gid = source.root.gid,
        .atime = source.root.atime,
        .mtime = source.root.mtime,
        .ctime = source.root.ctime,
        .atime_nsec = source.root.atime_nsec,
        .mtime_nsec = source.root.mtime_nsec,
        .ctime_nsec = source.root.ctime_nsec,
        .crtime = source.root.crtime,
        .crtime_nsec = source.root.crtime_nsec,
        // See importXfsMode: xfs.Xattr and tree_cursor.Xattr share layout exactly.
        .xattrs = @ptrCast(source.root.xattrs),
    };
}

fn joinMountPath(
    buffer: *std.array_list.Managed(u8),
    prefix: []const u8,
    path: []const u8,
) ![]const u8 {
    if (prefix.len == 0) return path;
    buffer.clearRetainingCapacity();
    try buffer.appendSlice(prefix);
    try buffer.append('/');
    try buffer.appendSlice(path);
    return buffer.items;
}

/// Errors a mount target can produce before anything is read. Each names one
/// specific way the target was ambiguous, because "invalid mount point" tells
/// an operator nothing about which of five different mistakes was made.
pub const MountTargetError = error{
    /// A mount target is a path in the resulting tree, so a relative one has
    /// no defined meaning: relative to what?
    MountTargetNotAbsolute,
    /// `/` is the root source's job. Mounting a second source there would
    /// hide the first entirely, which is a way of saying the first was never
    /// wanted.
    MountTargetIsRoot,
    /// `//`, `/a/`, `/a/./b` or `/a/../b`. Normalizing silently would mean
    /// two spellings of the same target could still fail the overlap check.
    MountTargetNotNormalized,
    /// Two sources mounted at the same path. Whichever won would be decided
    /// by argument order, which is not a decision worth inferring.
    DuplicateMountTarget,
    /// A later mount whose target contains an earlier mount's target. The
    /// later one would shadow the earlier one away completely, so the earlier
    /// source would be read and then thrown out.
    MountTargetShadowedByLaterMount,
};

/// Validates a whole mount list before any source is opened, so an
/// unsatisfiable set of targets fails immediately rather than after however
/// long it takes to read the first filesystem.
///
/// Targets may nest -- `/boot` then `/boot/efi` is the layout this exists for
/// -- but only in that order, because each mount is applied to the tree the
/// previous ones produced.
pub fn validateMountTargets(targets: []const []const u8) MountTargetError!void {
    for (targets, 0..) |target, index| {
        _ = try mountTargetToRelative(target);
        for (targets[index + 1 ..]) |later| {
            const later_relative = mountTargetToRelative(later) catch continue;
            const relative = mountTargetToRelative(target) catch unreachable;
            if (std.mem.eql(u8, relative, later_relative)) return error.DuplicateMountTarget;
            if (pathEqualsOrDescendant(later_relative, relative)) {
                return error.MountTargetShadowedByLaterMount;
            }
        }
    }
}

/// Converts `/boot/efi` into the `boot/efi` form the tree stores, refusing
/// every spelling that is not already normalized and absolute.
fn mountTargetToRelative(target: []const u8) MountTargetError![]const u8 {
    if (target.len == 0 or target[0] != '/') return error.MountTargetNotAbsolute;
    if (target.len == 1) return error.MountTargetIsRoot;
    if (target[target.len - 1] == '/') return error.MountTargetNotNormalized;
    const relative = target[1..];
    var components = std.mem.splitScalar(u8, relative, '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.MountTargetNotNormalized;
        }
    }
    return relative;
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
        node.metadata.crtime == null and
        node.metadata.atime_nsec == 0 and
        node.metadata.mtime_nsec == 0 and
        node.metadata.ctime_nsec == 0 and
        node.metadata.crtime_nsec == 0 and
        node.owned_xattrs.len == 0;
}

fn hasCanonicalFatRootMetadata(metadata: RootMetadata) bool {
    return metadata.mode == 0o755 and
        metadata.uid == 0 and
        metadata.gid == 0 and
        metadata.atime == null and
        metadata.mtime == null and
        metadata.ctime == null and
        metadata.crtime == null and
        metadata.atime_nsec == 0 and
        metadata.mtime_nsec == 0 and
        metadata.ctime_nsec == 0 and
        metadata.crtime_nsec == 0;
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

fn clampMtime(value: ?i64) u32 {
    const seconds = value orelse return 0;
    if (seconds <= 0) return 0;
    if (seconds >= std.math.maxInt(u32)) return std.math.maxInt(u32);
    return @intCast(seconds);
}

/// Splits a tree-relative path into its parent directory and its own name.
/// A top-level node's parent is the empty string, which is how the root
/// directory is named everywhere in this file.
fn splitPath(path: []const u8) struct { parent: []const u8, name: []const u8 } {
    const separator = std.mem.lastIndexOfScalar(u8, path, '/') orelse
        return .{ .parent = "", .name = path };
    return .{ .parent = path[0..separator], .name = path[separator + 1 ..] };
}

fn lessXattr(_: void, left: tree_cursor.OwnedXattr, right: tree_cursor.OwnedXattr) bool {
    return std.mem.order(u8, left.name, right.name) == .lt;
}

fn ownedXattrsView(source: []tree_cursor.OwnedXattr) []const tree_cursor.Xattr {
    return @ptrCast(source);
}

fn freeOwnedXattrs(allocator: Allocator, xattrs: []tree_cursor.OwnedXattr) void {
    if (xattrs.len == 0) return;
    for (xattrs) |xattr| {
        allocator.free(xattr.name);
        allocator.free(xattr.value);
    }
    allocator.free(xattrs);
}

const BytesReader = struct {
    bytes: []const u8,

    fn readAt(ctx: *const anyopaque, buffer: []u8, offset: u64) tree_cursor.Cursor.ContentError!usize {
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

    fn readAt(ctx: *const anyopaque, buffer: []u8, offset: u64) tree_cursor.Cursor.ContentError!usize {
        const self: *const FileReader = @ptrCast(@alignCast(ctx));
        return self.file.readPositionalAll(self.io, buffer, offset) catch error.ReadFailed;
    }
};

const EmptyReader = struct {
    fn readAt(_: *const anyopaque, _: []u8, _: u64) tree_cursor.Cursor.ContentError!usize {
        return 0;
    }
};

fn emptyContentReader() tree_cursor.Cursor.ContentReader {
    return .{ .ctx = undefined, .read_at_fn = EmptyReader.readAt };
}

const EmptyXfsReader = struct {
    fn readAt(_: *const anyopaque, _: []u8, _: u64) xfs.ContentReader.ContentError!usize {
        return 0;
    }
};

fn emptyXfsContentReader() xfs.ContentReader {
    return .{ .ctx = undefined, .read_at_fn = EmptyXfsReader.readAt };
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

test "owned tree offers special files and hardlinks to the ext4 writer" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-special.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDirectory("dev", .{ .mode = 0o755 });
    try tree.putDevice("dev/console", .char_device, .{ .major = 5, .minor = 1 }, .{ .mode = 0o600 });
    try tree.putFileBytes("tool", "x", .{ .mode = 0o755 });
    try tree.putHardlink("tool-alias", "tool", .{ .mode = 0o755 });

    const view = try tree.ext4View();
    var saw_device = false;
    var saw_hardlink = false;
    while (try view.next()) |entry| {
        if (entry.kind == .char_device) {
            saw_device = true;
            try std.testing.expectEqual(@as(u32, 5), entry.device.major);
            try std.testing.expectEqual(@as(u32, 1), entry.device.minor);
        }
        if (entry.kind == .hardlink) {
            saw_hardlink = true;
            try std.testing.expectEqualStrings("tool", entry.hardlink_target);
        }
    }
    try std.testing.expect(saw_device);
    try std.testing.expect(saw_hardlink);
}

test "the neutral cursor resets, orders by path, and preserves content/hardlink/device/xattr fidelity" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-cursor-fidelity.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putDirectory("a", .{ .mode = 0o755 });
    try tree.putFileBytes("a/file", "hello", .{
        .mode = 0o640,
        .xattrs = &.{.{ .name = "user.test", .value = "v" }},
    });
    try tree.putHardlink("a/file-link", "a/file", .{ .mode = 0o640 });
    try tree.putDevice("dev0", .block_device, .{ .major = 7, .minor = 3 }, .{ .mode = 0o600 });

    // `cursor()`, not `ext4View()`, is the primary consumption shape: the
    // returned type is `*tree_cursor.Cursor` regardless of which name a
    // caller reaches it through.
    const first = try tree.cursor();

    var first_paths = std.array_list.Managed([]const u8).init(std.testing.allocator);
    defer first_paths.deinit();
    var saw_content = false;
    var saw_xattr = false;
    var saw_hardlink = false;
    var saw_device = false;
    while (try first.next()) |entry| {
        try first_paths.append(entry.path);
        switch (entry.kind) {
            .file => {
                var buffer: [5]u8 = undefined;
                const read = try entry.content.?.readAt(&buffer, 0);
                try std.testing.expectEqual(@as(usize, 5), read);
                try std.testing.expectEqualStrings("hello", &buffer);
                saw_content = true;

                try std.testing.expectEqual(@as(usize, 1), entry.xattrs.len);
                try std.testing.expectEqualStrings("user.test", entry.xattrs[0].name);
                try std.testing.expectEqualStrings("v", entry.xattrs[0].value);
                saw_xattr = true;
            },
            .hardlink => {
                try std.testing.expectEqualStrings("a/file", entry.hardlink_target);
                saw_hardlink = true;
            },
            .block_device => {
                try std.testing.expectEqual(@as(u32, 7), entry.device.major);
                try std.testing.expectEqual(@as(u32, 3), entry.device.minor);
                saw_device = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_content);
    try std.testing.expect(saw_xattr);
    try std.testing.expect(saw_hardlink);
    try std.testing.expect(saw_device);

    // Byte order on the path, which is what a writer relies on to see every
    // directory before its own children.
    try std.testing.expectEqual(@as(usize, 4), first_paths.items.len);
    try std.testing.expectEqualStrings("a", first_paths.items[0]);
    try std.testing.expectEqualStrings("a/file", first_paths.items[1]);
    try std.testing.expectEqualStrings("a/file-link", first_paths.items[2]);
    try std.testing.expectEqualStrings("dev0", first_paths.items[3]);

    // `reset()` rewinds the same cursor rather than requiring a new one, and
    // it yields the identical order every time -- what `ext4.populate`
    // relies on when a caller hands it a cursor that has already been
    // walked once (`preflightPopulate` followed by `populate`, say).
    first.reset();
    var second_paths = std.array_list.Managed([]const u8).init(std.testing.allocator);
    defer second_paths.deinit();
    while (try first.next()) |entry| try second_paths.append(entry.path);
    try std.testing.expectEqual(first_paths.items.len, second_paths.items.len);
    for (first_paths.items, second_paths.items) |before, after| {
        try std.testing.expectEqualStrings(before, after);
    }
}

test "ext4.populate emits identical bytes through cursor() and the ext4View() alias" {
    const io = std.testing.io;
    const fs_size: u64 = 8 * 1024 * 1024;

    var tree_a = try RootTree.init(std.testing.allocator, io, "test-root-tree-cursor-digest-a.spool", .{});
    defer tree_a.deinit();
    defer Io.Dir.cwd().deleteFile(io, "test-root-tree-cursor-digest-a.spool") catch {};
    try tree_a.putDirectory("etc", .{ .mode = 0o755 });
    try tree_a.putFileBytes("etc/hostname", "appliance\n", .{
        .mode = 0o640,
        .uid = 4,
        .gid = 5,
        .xattrs = &.{.{ .name = "user.origin", .value = "root-tree" }},
    });
    try tree_a.putSymlink("hostname", "etc/hostname", .{ .mode = 0o777 });
    try tree_a.putDevice("etc/console", .char_device, .{ .major = 5, .minor = 1 }, .{ .mode = 0o600 });
    try tree_a.putHardlink("etc/hostname-link", "etc/hostname", .{ .mode = 0o640 });

    var tree_b = try RootTree.init(std.testing.allocator, io, "test-root-tree-cursor-digest-b.spool", .{});
    defer tree_b.deinit();
    defer Io.Dir.cwd().deleteFile(io, "test-root-tree-cursor-digest-b.spool") catch {};
    try tree_b.putDirectory("etc", .{ .mode = 0o755 });
    try tree_b.putFileBytes("etc/hostname", "appliance\n", .{
        .mode = 0o640,
        .uid = 4,
        .gid = 5,
        .xattrs = &.{.{ .name = "user.origin", .value = "root-tree" }},
    });
    try tree_b.putSymlink("hostname", "etc/hostname", .{ .mode = 0o777 });
    try tree_b.putDevice("etc/console", .char_device, .{ .major = 5, .minor = 1 }, .{ .mode = 0o600 });
    try tree_b.putHardlink("etc/hostname-link", "etc/hostname", .{ .mode = 0o640 });

    const image_path_a = "test-root-tree-cursor-digest-a.img";
    const image_path_b = "test-root-tree-cursor-digest-b.img";
    defer Io.Dir.cwd().deleteFile(io, image_path_a) catch {};
    defer Io.Dir.cwd().deleteFile(io, image_path_b) catch {};

    const image_a = try Io.Dir.cwd().createFile(io, image_path_a, .{ .read = true });
    defer image_a.close(io);
    // The new, neutrally-named primary shape.
    _ = try ext4.populate(io, image_a, std.testing.allocator, try tree_a.cursor(), .{
        .length = fs_size,
        .uuid = [_]u8{0x61} ** 16,
        .timestamp = 1_717_171_717,
    });

    const image_b = try Io.Dir.cwd().createFile(io, image_path_b, .{ .read = true });
    defer image_b.close(io);
    // The pre-existing name, still accepted, still going through the same
    // `tree_cursor.Cursor` underneath.
    _ = try ext4.populate(io, image_b, std.testing.allocator, try tree_b.ext4View(), .{
        .length = fs_size,
        .uuid = [_]u8{0x61} ** 16,
        .timestamp = 1_717_171_717,
    });

    const bytes_a = try std.testing.allocator.alloc(u8, fs_size);
    defer std.testing.allocator.free(bytes_a);
    _ = try image_a.readPositionalAll(io, bytes_a, 0);
    const bytes_b = try std.testing.allocator.alloc(u8, fs_size);
    defer std.testing.allocator.free(bytes_b);
    _ = try image_b.readPositionalAll(io, bytes_b, 0);

    try std.testing.expectEqualSlices(u8, bytes_a, bytes_b);

    var digest_a: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes_a, &digest_a, .{});
    var digest_b: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes_b, &digest_b, .{});
    try std.testing.expectEqualSlices(u8, &digest_a, &digest_b);
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
    _ = try tree.remove("target");
    try std.testing.expectEqual(Kind.file, tree.findNode("link").?.kind);
    const promoted = try tree.readFileAlloc(std.testing.allocator, "link", 16);
    defer std.testing.allocator.free(promoted);
    try std.testing.expectEqualSlices(u8, "x", promoted);
    try std.testing.expectEqual(@as(u16, 0o644), tree.findNode("link").?.metadata.mode);
    try tree.putDirectory("target", .{ .mode = 0o755 });
    try tree.putFileBytes("target", "replacement", .{ .mode = 0o600 });
    _ = try tree.manifestDigest();
    try tree.putHardlink("invalid", "link", .{ .mode = 0o644 });
}

test "canonical hardlink removal promotes the deterministic surviving alias" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-hardlink-promotion.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    const xattrs = [_]tree_cursor.Xattr{.{ .name = "user.origin", .value = "canonical" }};
    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    try tree.putFileBytes("canonical", "payload", .{ .mode = 0o600, .uid = 42, .gid = 43, .xattrs = &xattrs });
    try tree.putHardlink("z-alias", "canonical", .{ .mode = 0o600 });
    try tree.putHardlink("a-alias", "canonical", .{ .mode = 0o600 });
    _ = try tree.remove("canonical");

    const promoted = tree.findNode("a-alias").?;
    try std.testing.expectEqual(Kind.file, promoted.kind);
    try std.testing.expectEqual(@as(u16, 0o600), promoted.metadata.mode);
    try std.testing.expectEqual(@as(u32, 42), promoted.metadata.uid);
    try std.testing.expectEqual(@as(usize, 1), promoted.metadata.xattrs.len);
    try std.testing.expectEqualStrings("canonical", promoted.metadata.xattrs[0].value);
    const remaining = tree.findNode("z-alias").?;
    try std.testing.expectEqual(Kind.hardlink, remaining.kind);
    try std.testing.expectEqualStrings("a-alias", remaining.payload.hardlink_target);
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
    _ = try tree.ext4View();

    try tree.putFileBytes("value", "x", .{ .mode = 0o644, .mtime = 1 });
    _ = try tree.ext4View();

    // A pre-1970 time is ordinary on an installed system -- an unset clock,
    // or an archive restored with its original dates -- and the epoch bits
    // reach back to 1901, so it has to be accepted rather than refused.
    tree.setRootMetadata(.{ .atime = -1 });
    _ = try tree.ext4View();
    tree.setRootMetadata(.{ .atime = @as(i64, std.math.maxInt(u32)) + 1 });
    _ = try tree.ext4View();

    // Nothing outside 1901-12-13..2446-05-10 fits an ext4 inode's time
    // fields, however wide the inode is.
    tree.setRootMetadata(.{ .atime = -2_147_483_649 });
    try std.testing.expectError(error.Ext4TimestampsUnsupported, tree.ext4View());
    tree.setRootMetadata(.{ .atime = 15_032_385_536 });
    try std.testing.expectError(error.Ext4TimestampsUnsupported, tree.ext4View());
    tree.setRootMetadata(.{ .mode = 0o40755 });
    try std.testing.expectError(error.Ext4RootMetadataUnsupported, tree.ext4View());
}

fn temporaryTestPath(
    allocator: std.mem.Allocator,
    io: Io,
    temporary: *std.testing.TmpDir,
    sub_path: []const u8,
) ![]const u8 {
    var root_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    return std.fs.path.join(allocator, &.{ root_buffer[0..root_length], sub_path });
}

test "owned tree populates FAT32 with an explicit metadata-loss policy" {
    const Image = @import("image.zig").Image;
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const spool_path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-root-tree-fat32.spool");
    defer std.testing.allocator.free(spool_path);
    const image_path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-root-tree-fat32.img");
    defer std.testing.allocator.free(image_path);

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
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const spool_path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-root-tree-fat32-preflight.spool");
    defer std.testing.allocator.free(spool_path);
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

test "a mount replaces what it covers instead of merging into it" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    defer Io.Dir.cwd().deleteFile(io, "test-root-tree-mount-root.spool") catch {};
    defer Io.Dir.cwd().deleteFile(io, "test-root-tree-mount-boot.spool") catch {};

    // The root source's `/boot` stub, which a real system's boot filesystem
    // hides the moment it is mounted.
    var root = try RootTree.init(allocator, io, "test-root-tree-mount-root.spool", .{});
    defer root.deinit();
    try root.putDirectory("boot", .{ .mode = 0o755 });
    try root.putFileBytes("boot/vmlinuz", "stale kernel", .{ .mode = 0o644 });
    try root.putDirectory("boot/grub", .{ .mode = 0o755 });
    try root.putFileBytes("boot/grub/grub.cfg", "stale config", .{ .mode = 0o644 });
    try root.putFileBytes("etc/hostname", "host\n", .{ .mode = 0o644 });

    var boot = try RootTree.init(allocator, io, "test-root-tree-mount-boot.spool", .{});
    defer boot.deinit();
    try boot.putFileBytes("vmlinuz", "real kernel", .{ .mode = 0o644 });

    const report = try root.mountExt4View(
        try boot.ext4View(),
        "/boot",
        .{ .mode = 0o700, .uid = 7, .gid = 8 },
    );
    try std.testing.expectEqual(@as(usize, 3), report.shadowed_nodes);
    try std.testing.expectEqual(@as(usize, 1), report.imported_nodes);

    // Nothing from the stub survives: not the file the mount replaced, and
    // not the subdirectory the mount had nothing to say about.
    try std.testing.expectEqual(@as(?NodeView, null), root.findNode("boot/grub"));
    try std.testing.expectEqual(@as(?NodeView, null), root.findNode("boot/grub/grub.cfg"));
    var content: [11]u8 = undefined;
    _ = try root.readNodeContent("boot/vmlinuz", &content, 0);
    try std.testing.expectEqualStrings("real kernel", &content);

    // The mount point wears the mounted filesystem's root metadata, exactly
    // as a real mount makes it the metadata a guest sees there.
    const mount_point = root.findNode("boot").?;
    try std.testing.expectEqual(Kind.directory, mount_point.kind);
    try std.testing.expectEqual(@as(u16, 0o700), mount_point.metadata.mode);
    try std.testing.expectEqual(@as(u32, 7), mount_point.metadata.uid);

    // Everything outside the mount point is untouched.
    try std.testing.expect(root.findNode("etc/hostname") != null);
}

test "mounts nest in the order they are applied" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const spools = [_][]const u8{
        "test-root-tree-nest-root.spool",
        "test-root-tree-nest-boot.spool",
        "test-root-tree-nest-esp.spool",
    };
    defer for (spools) |path| Io.Dir.cwd().deleteFile(io, path) catch {};

    var root = try RootTree.init(allocator, io, spools[0], .{});
    defer root.deinit();
    try root.putDirectory("boot", .{ .mode = 0o755 });
    try root.putFileBytes("boot/leftover", "x", .{ .mode = 0o644 });

    var boot = try RootTree.init(allocator, io, spools[1], .{});
    defer boot.deinit();
    try boot.putFileBytes("vmlinuz", "kernel", .{ .mode = 0o644 });
    try boot.putDirectory("efi", .{ .mode = 0o755 });

    var esp = try RootTree.init(allocator, io, spools[2], .{});
    defer esp.deinit();
    try esp.putDirectory("EFI", .{ .mode = 0o755 });
    try esp.putFileBytes("EFI/BOOTX64.EFI", "shim", .{ .mode = 0o644 });

    _ = try root.mountExt4View(try boot.ext4View(), "/boot", .{ .mode = 0o755 });
    const nested = try root.mountExt4View(try esp.ext4View(), "/boot/efi", .{ .mode = 0o755 });

    try std.testing.expectEqual(@as(usize, 0), nested.shadowed_nodes);
    try std.testing.expectEqual(@as(usize, 2), nested.imported_nodes);
    try std.testing.expect(root.findNode("boot/vmlinuz") != null);
    try std.testing.expect(root.findNode("boot/efi/EFI/BOOTX64.EFI") != null);
    try std.testing.expectEqual(@as(?NodeView, null), root.findNode("boot/leftover"));
}

test "hardlinks travel through a mount and refuse to be severed by one" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const spools = [_][]const u8{
        "test-root-tree-mount-link-root.spool",
        "test-root-tree-mount-link-boot.spool",
        "test-root-tree-mount-link-severed.spool",
    };
    defer for (spools) |path| Io.Dir.cwd().deleteFile(io, path) catch {};

    var root = try RootTree.init(allocator, io, spools[0], .{});
    defer root.deinit();
    try root.putDirectory("boot", .{ .mode = 0o755 });
    try root.putFileBytes("usr/bin/tool", "tool", .{ .mode = 0o755 });
    try root.putHardlink("usr/bin/tool-alias", "usr/bin/tool", .{ .mode = 0o755 });

    // A hardlink pair inside the mounted source moves under the mount point
    // together, so the two names still share one inode afterwards.
    var boot = try RootTree.init(allocator, io, spools[1], .{});
    defer boot.deinit();
    try boot.putFileBytes("vmlinuz", "kernel", .{ .mode = 0o644 });
    try boot.putHardlink("vmlinuz.old", "vmlinuz", .{ .mode = 0o644 });

    _ = try root.mountExt4View(try boot.ext4View(), "/boot", .{ .mode = 0o755 });
    const link = root.findNode("boot/vmlinuz.old").?;
    try std.testing.expectEqual(Kind.hardlink, link.kind);
    try std.testing.expectEqualStrings("boot/vmlinuz", link.payload.hardlink_target);
    try std.testing.expect(root.findNode("usr/bin/tool-alias") != null);

    // A link outside the mount point whose inode-bearing name is inside it
    // cannot survive and must not silently become a copy.
    var severed = try RootTree.init(allocator, io, spools[2], .{});
    defer severed.deinit();
    try severed.putDirectory("boot", .{ .mode = 0o755 });
    try severed.putFileBytes("boot/shared", "bytes", .{ .mode = 0o644 });
    try severed.putHardlink("elsewhere", "boot/shared", .{ .mode = 0o644 });

    var empty = try RootTree.init(allocator, io, "test-root-tree-mount-link-empty.spool", .{});
    defer Io.Dir.cwd().deleteFile(io, "test-root-tree-mount-link-empty.spool") catch {};
    defer empty.deinit();
    try empty.putFileBytes("vmlinuz", "kernel", .{ .mode = 0o644 });

    try std.testing.expectError(error.MountShadowsHardlinkTarget, severed.mountExt4View(
        try empty.ext4View(),
        "/boot",
        .{ .mode = 0o755 },
    ));
    try std.testing.expect(severed.findNode("boot/shared") != null);
}

test "a mount target must be absolute, normalized, and a directory that exists" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const spools = [_][]const u8{
        "test-root-tree-mount-target-root.spool",
        "test-root-tree-mount-target-src.spool",
    };
    defer for (spools) |path| Io.Dir.cwd().deleteFile(io, path) catch {};

    var root = try RootTree.init(allocator, io, spools[0], .{});
    defer root.deinit();
    try root.putDirectory("boot", .{ .mode = 0o755 });
    try root.putFileBytes("etc/hostname", "host\n", .{ .mode = 0o644 });
    try root.putSymlink("link", "boot", .{ .mode = 0o777 });
    try root.putDirectory("var", .{ .mode = 0o755 });
    try root.putSymlink("var/run", "../run", .{ .mode = 0o777 });

    var source = try RootTree.init(allocator, io, spools[1], .{});
    defer source.deinit();
    try source.putFileBytes("payload", "x", .{ .mode = 0o644 });

    const cases = [_]struct { target: []const u8, expected: anyerror }{
        .{ .target = "boot", .expected = error.MountTargetNotAbsolute },
        .{ .target = "", .expected = error.MountTargetNotAbsolute },
        .{ .target = "/", .expected = error.MountTargetIsRoot },
        .{ .target = "/boot/", .expected = error.MountTargetNotNormalized },
        .{ .target = "//boot", .expected = error.MountTargetNotNormalized },
        .{ .target = "/boot/./efi", .expected = error.MountTargetNotNormalized },
        .{ .target = "/boot/../etc", .expected = error.MountTargetNotNormalized },
        .{ .target = "/missing", .expected = error.MissingMountTarget },
        .{ .target = "/missing/deeper", .expected = error.MissingMountTargetParent },
        .{ .target = "/etc/hostname", .expected = error.MountTargetNotDirectory },
        .{ .target = "/link", .expected = error.MountTargetIsSymlink },
        .{ .target = "/var/run/deeper", .expected = error.MountTargetTraversesSymlink },
        .{ .target = "/etc/hostname/deeper", .expected = error.MountTargetTraversesNonDirectory },
    };
    for (cases) |case| {
        try std.testing.expectError(case.expected, root.mountExt4View(
            try source.ext4View(),
            case.target,
            .{ .mode = 0o755 },
        ));
    }
    // Every refusal left the tree exactly as it was.
    try std.testing.expectEqual(@as(?NodeView, null), root.findNode("boot/payload"));
}

test "a mount list rejects duplicate and later-shadowing targets" {
    try validateMountTargets(&.{ "/boot", "/boot/efi" });
    try validateMountTargets(&.{ "/boot", "/var/lib" });

    try std.testing.expectError(
        error.DuplicateMountTarget,
        validateMountTargets(&.{ "/boot", "/boot" }),
    );
    // `/boot` applied second would shadow the `/boot/efi` source away
    // completely, so the source would be read and then discarded.
    try std.testing.expectError(
        error.MountTargetShadowedByLaterMount,
        validateMountTargets(&.{ "/boot/efi", "/boot" }),
    );
    try std.testing.expectError(
        error.MountTargetNotAbsolute,
        validateMountTargets(&.{"boot"}),
    );
    try std.testing.expectError(
        error.MountTargetNotNormalized,
        validateMountTargets(&.{"/boot//efi"}),
    );
}

fn writeXfsFixture(io: Io, path: []const u8, bytes: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

test "owned tree imports an XFS volume preserving metadata xattrs hardlinks and devices" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-root-tree-xfs-owned.img";
    const spool_path = "test-root-tree-xfs-owned.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    const volume = try xfs.buildIntegrationVolume(allocator);
    defer allocator.free(volume);
    try writeXfsFixture(io, image_path, volume);

    var reader = try xfs.Reader.openPath(allocator, io, image_path);
    defer reader.close(io);
    var source = try xfs.scanReadable(&reader, io, allocator, .{
        .available_length = xfs.integration_data_blocks * xfs.integration_block_size,
    });
    defer source.deinit();

    var tree = try RootTree.init(allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.importXfs(&source);

    // Root metadata came from the XFS root inode, not a default.
    try std.testing.expectEqual(@as(u16, 0o755), tree.root_metadata.mode);

    // file.txt: plain EXTENTS content, spooled (owned) into the tree.
    var file_txt_bytes: [xfs.file_txt_content.len]u8 = undefined;
    _ = try tree.readNodeContent("file.txt", &file_txt_bytes, 0);
    try std.testing.expectEqualStrings(xfs.file_txt_content, &file_txt_bytes);

    // link: LOCAL symlink target preserved verbatim.
    const link = tree.findNode("link").?;
    try std.testing.expectEqual(Kind.symlink, link.kind);
    var link_target: [8]u8 = undefined;
    _ = try tree.readNodeContent("link", &link_target, 0);
    try std.testing.expectEqualStrings("file.txt", &link_target);

    // dev: char device major/minor round-trip without squeezing through an
    // ext4-shaped device type.
    const dev = tree.findNode("dev").?;
    try std.testing.expectEqual(Kind.char_device, dev.kind);
    try std.testing.expectEqual(Device{ .major = 1, .minor = 3 }, dev.payload.device);

    // hardlinked / sub/hardlinked2: two names, one inode, preserved as a
    // hardlink rather than a duplicated copy.
    var hardlinked_bytes: [xfs.hardlinked_content.len]u8 = undefined;
    _ = try tree.readNodeContent("hardlinked", &hardlinked_bytes, 0);
    try std.testing.expectEqualStrings(xfs.hardlinked_content, &hardlinked_bytes);
    const alias = tree.findNode("sub/hardlinked2").?;
    try std.testing.expectEqual(Kind.hardlink, alias.kind);
    try std.testing.expectEqualStrings("hardlinked", alias.payload.hardlink_target);

    // attrs.txt: xattrs preserved through the shared tree_cursor.Xattr-shaped
    // pipeline, including the root-flagged "trusted." namespace entry.
    const attrs_txt = tree.findNode("attrs.txt").?;
    var saw_foo = false;
    var saw_baz = false;
    for (attrs_txt.metadata.xattrs) |xattr| {
        if (std.mem.eql(u8, xattr.name, "user.foo")) {
            try std.testing.expectEqualStrings("bar", xattr.value);
            saw_foo = true;
        }
        if (std.mem.eql(u8, xattr.name, "trusted.baz")) {
            try std.testing.expectEqualStrings("qux", xattr.value);
            saw_baz = true;
        }
    }
    try std.testing.expect(saw_foo);
    try std.testing.expect(saw_baz);

    // sub: nested "block"-format directory scans as a plain directory.
    try std.testing.expectEqual(Kind.directory, tree.findNode("sub").?.kind);

    // big.bin: FMT_BTREE content across two extents, spooled whole.
    var big_bin_bytes: [2 * xfs.integration_block_size]u8 = undefined;
    _ = try tree.readNodeContent("big.bin", &big_bin_bytes, 0);
    try std.testing.expectEqualSlices(u8, &xfs.big_bin_block0, big_bin_bytes[0..xfs.integration_block_size]);
    try std.testing.expectEqualSlices(u8, &xfs.big_bin_block1, big_bin_bytes[xfs.integration_block_size..]);

    // rlink: remote-EXTENTS symlink target preserved.
    var rlink_target: [xfs.rlink_target.len]u8 = undefined;
    _ = try tree.readNodeContent("rlink", &rlink_target, 0);
    try std.testing.expectEqualStrings(xfs.rlink_target, &rlink_target);

    // unwritten.bin: sole extent is unwritten (allocated but never
    // written), so it reads back as zeros even though its backing block on
    // disk holds a non-zero marker -- proving the spool preserved the
    // XFS reader's zero-fill rather than accidentally copying real bytes.
    var unwritten_bytes: [xfs.unwritten_bin_size]u8 = undefined;
    _ = try tree.readNodeContent("unwritten.bin", &unwritten_bytes, 0);
    for (unwritten_bytes) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "borrowed XFS import requires a memory tree and reads content through the live source" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-root-tree-xfs-borrowed.img";
    const spool_path = "test-root-tree-xfs-borrowed-rejected.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    const volume = try xfs.buildIntegrationVolume(allocator);
    defer allocator.free(volume);
    try writeXfsFixture(io, image_path, volume);

    var reader = try xfs.Reader.openPath(allocator, io, image_path);
    defer reader.close(io);
    var source = try xfs.scanReadable(&reader, io, allocator, .{
        .available_length = xfs.integration_data_blocks * xfs.integration_block_size,
    });
    defer source.deinit();

    // A spooled (file-backed) tree cannot borrow: its own lifecycle does
    // not promise the source stays alive, so it must be refused up front.
    var spooled = try RootTree.init(allocator, io, spool_path, .{});
    defer spooled.deinit();
    try std.testing.expectError(error.BorrowedImportRequiresMemoryTree, spooled.importXfsBorrowed(&source));

    // A memory tree can, and reads bytes lazily through the still-open
    // xfs.Reader rather than copying them up front.
    var borrowed = RootTree.initMemory(allocator, io, .{});
    defer borrowed.deinit();
    try borrowed.importXfsBorrowed(&source);

    var file_txt_bytes: [xfs.file_txt_content.len]u8 = undefined;
    _ = try borrowed.readNodeContent("file.txt", &file_txt_bytes, 0);
    try std.testing.expectEqualStrings(xfs.file_txt_content, &file_txt_bytes);

    const alias = borrowed.findNode("sub/hardlinked2").?;
    try std.testing.expectEqual(Kind.hardlink, alias.kind);
}

test "mountXfs replaces a subtree with a scanned XFS volume and carries its root metadata" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-root-tree-xfs-mount.img";
    const spool_path = "test-root-tree-xfs-mount-root.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    const volume = try xfs.buildIntegrationVolume(allocator);
    defer allocator.free(volume);
    try writeXfsFixture(io, image_path, volume);

    var reader = try xfs.Reader.openPath(allocator, io, image_path);
    defer reader.close(io);
    var source = try xfs.scanReadable(&reader, io, allocator, .{
        .available_length = xfs.integration_data_blocks * xfs.integration_block_size,
    });
    defer source.deinit();

    var root = try RootTree.init(allocator, io, spool_path, .{});
    defer root.deinit();
    try root.putDirectory("data", .{ .mode = 0o755 });
    try root.putFileBytes("data/stale", "stale", .{ .mode = 0o644 });
    try root.putFileBytes("etc/hostname", "host\n", .{ .mode = 0o644 });

    const report = try root.mountXfs(&source, "/data");
    try std.testing.expectEqual(@as(usize, 1), report.shadowed_nodes);
    try std.testing.expectEqual(source.nodeCount(), report.imported_nodes);

    // The stale file the mount covered is gone; the mount point itself now
    // carries the mounted XFS root's own mode/uid/gid.
    try std.testing.expectEqual(@as(?NodeView, null), root.findNode("data/stale"));
    const mount_point = root.findNode("data").?;
    try std.testing.expectEqual(@as(u16, 0o755), mount_point.metadata.mode);

    var file_txt_bytes: [xfs.file_txt_content.len]u8 = undefined;
    _ = try root.readNodeContent("data/file.txt", &file_txt_bytes, 0);
    try std.testing.expectEqualStrings(xfs.file_txt_content, &file_txt_bytes);

    const dev = root.findNode("data/dev").?;
    try std.testing.expectEqual(Device{ .major = 1, .minor = 3 }, dev.payload.device);

    // Everything outside the mount point survives untouched.
    try std.testing.expect(root.findNode("etc/hostname") != null);
}

test "mountXfsBorrowed requires a memory tree" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-root-tree-xfs-mount-borrowed.img";
    const spool_path = "test-root-tree-xfs-mount-borrowed.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    const volume = try xfs.buildIntegrationVolume(allocator);
    defer allocator.free(volume);
    try writeXfsFixture(io, image_path, volume);

    var reader = try xfs.Reader.openPath(allocator, io, image_path);
    defer reader.close(io);
    var source = try xfs.scanReadable(&reader, io, allocator, .{
        .available_length = xfs.integration_data_blocks * xfs.integration_block_size,
    });
    defer source.deinit();

    var spooled = try RootTree.init(allocator, io, spool_path, .{});
    defer spooled.deinit();
    try spooled.putDirectory("data", .{ .mode = 0o755 });
    try std.testing.expectError(
        error.BorrowedImportRequiresMemoryTree,
        spooled.mountXfsBorrowed(&source, "/data"),
    );

    var memory = RootTree.initMemory(allocator, io, .{});
    defer memory.deinit();
    try memory.putDirectory("data", .{ .mode = 0o755 });
    _ = try memory.mountXfsBorrowed(&source, "/data");
    var file_txt_bytes: [xfs.file_txt_content.len]u8 = undefined;
    _ = try memory.readNodeContent("data/file.txt", &file_txt_bytes, 0);
    try std.testing.expectEqualStrings(xfs.file_txt_content, &file_txt_bytes);
}

test "importXfs rejects a socket entry by name instead of misclassifying it" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-root-tree-xfs-socket.img";
    const spool_path = "test-root-tree-xfs-socket.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    const volume = try xfs.buildSocketVolume(allocator);
    defer allocator.free(volume);
    try writeXfsFixture(io, image_path, volume);

    var reader = try xfs.Reader.openPath(allocator, io, image_path);
    defer reader.close(io);
    var source = try xfs.scanReadable(&reader, io, allocator, .{
        .available_length = xfs.socket_data_blocks * xfs.integration_block_size,
    });
    defer source.deinit();

    var tree = try RootTree.init(allocator, io, spool_path, .{});
    defer tree.deinit();
    try std.testing.expectError(error.UnsupportedSocketInode, tree.importXfs(&source));
}

test "opening a malformed XFS image is refused by the reader before any import" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-root-tree-xfs-malformed.img";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};

    // Not a valid XFS superblock at all: detection/opening must fail
    // outright rather than an import later silently producing an empty or
    // wrong tree.
    var garbage: [xfs.integration_block_size]u8 = [_]u8{0xAA} ** xfs.integration_block_size;
    try writeXfsFixture(io, image_path, &garbage);

    try std.testing.expectError(
        error.BadMagic,
        xfs.Reader.openPath(allocator, io, image_path),
    );
}

test "a FAT mount carries only the metadata the scan synthesized" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const image_path = "test-root-tree-mount-esp.img";
    const spool_path = "test-root-tree-mount-fat.spool";
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    const Image = @import("image.zig").Image;
    const partition_len: u64 = 64 * 1024 * 1024;
    var image = try Image.create(io, image_path, .raw, partition_len, .{});
    defer image.close(io);
    try fat32.format(&image, io, .{ .partition_offset = 0, .partition_len = partition_len });
    var writable = try fat32.open(&image, io, .{ .offset = 0, .length = partition_len });
    try writable.createDir(io, "EFI/BOOT");
    try writable.writeFile(io, "EFI/BOOT/BOOTX64.EFI", "shim");

    var filesystem = try fat32.open(&image, io, .{ .offset = 0, .length = partition_len });
    var esp = try fat32.scanTree(&filesystem, io, allocator, .{ .metadata = .{
        .directory_mode = 0o700,
        .file_mode = 0o600,
        .uid = 0,
        .gid = 0,
    } });
    defer esp.deinit();

    var root = try RootTree.init(allocator, io, spool_path, .{});
    defer root.deinit();
    try root.putDirectory("boot", .{ .mode = 0o755 });
    try root.putDirectory("boot/efi", .{ .mode = 0o755 });

    const report = try root.mountFat(&esp, "/boot/efi");
    try std.testing.expectEqual(@as(usize, 3), report.imported_nodes);
    try std.testing.expectEqual(@as(u16, 0o700), root.findNode("boot/efi").?.metadata.mode);
    try std.testing.expectEqual(@as(u16, 0o700), root.findNode("boot/efi/EFI").?.metadata.mode);

    const binary = root.findNode("boot/efi/EFI/BOOT/BOOTX64.EFI").?;
    try std.testing.expectEqual(@as(u16, 0o600), binary.metadata.mode);
    try std.testing.expectEqual(@as(u32, 0), binary.metadata.uid);
    // vfat has no timestamps and no xattrs, so neither may be invented.
    try std.testing.expectEqual(@as(?i64, null), binary.metadata.mtime);
    try std.testing.expectEqual(@as(usize, 0), binary.metadata.xattrs.len);

    var content: [4]u8 = undefined;
    _ = try root.readNodeContent("boot/efi/EFI/BOOT/BOOTX64.EFI", &content, 0);
    try std.testing.expectEqualStrings("shim", &content);
}

test "a tree's FAT32 size is one the tree fits in, and one byte less is not" {
    const Image = @import("image.zig").Image;
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const spool_path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-root-tree-fat-size.spool");
    defer std.testing.allocator.free(spool_path);
    const image_path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-root-tree-fat-size.img");
    defer std.testing.allocator.free(image_path);

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDirectory("EFI", .{ .mode = 0o755 });
    try tree.putDirectory("EFI/BOOT", .{ .mode = 0o755 });
    try tree.putDirectory("EFI/a-vendor-with-a-long-directory-name", .{ .mode = 0o755 });
    try tree.putFileBytes("EFI/BOOT/BOOTX64.EFI", "boot", .{ .mode = 0o644 });
    try tree.putFileBytes("EFI/a-vendor-with-a-long-directory-name/grub.cfg", "cfg", .{ .mode = 0o644 });

    // A kernel and an initramfs, which is what actually decides an ESP's
    // size once it holds more than a bootloader.
    const big = try std.testing.allocator.alloc(u8, 20 * 1024 * 1024);
    defer std.testing.allocator.free(big);
    @memset(big, 0x5A);
    try tree.putFileBytes("EFI/BOOT/vmlinuz", big, .{ .mode = 0o644 });
    try tree.putFileBytes("EFI/BOOT/initramfs.img", big, .{ .mode = 0o644 });

    const length = try tree.minimumFat32VolumeLength(.{}, .{});

    var img = try Image.create(io, image_path, .raw, length, .{});
    defer img.close(io);
    try fat32.format(&img, io, .{
        .partition_offset = 0,
        .partition_len = length,
        .volume_id = 0xFEED_FACE,
    });
    var fs = try fat32.open(&img, io, .{ .offset = 0, .length = length });
    try tree.populateFat32(&fs, .{});

    const read_back = try fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/vmlinuz");
    defer std.testing.allocator.free(read_back);
    try std.testing.expectEqualSlices(u8, big, read_back);

    // The size is a minimum rather than an estimate: one alignment unit
    // less is genuinely too small, so nothing here is padding.
    const alignment: u64 = 1024 * 1024;
    try std.testing.expect(length > alignment);
    const too_small = length - alignment;
    const short_path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-root-tree-fat-size-short.img");
    defer std.testing.allocator.free(short_path);
    var short_img = try Image.create(io, short_path, .raw, too_small, .{});
    defer short_img.close(io);
    try fat32.format(&short_img, io, .{
        .partition_offset = 0,
        .partition_len = too_small,
        .volume_id = 0xFEED_FACE,
    });
    var short_fs = try fat32.open(&short_img, io, .{ .offset = 0, .length = too_small });
    try std.testing.expectError(error.NoSpaceLeft, tree.populateFat32(&short_fs, .{}));
}

test "a FAT32 size accounts for a directory whose sibling sorts between it and its children" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const spool_path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-root-tree-fat-interleaved.spool");
    defer std.testing.allocator.free(spool_path);

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    // `/` is 0x2F, so `loader/entries.srel` sorts after `loader/entries` and
    // before `loader/entries/arch.conf`: a directory's descendants are not
    // contiguous in the sorted order. This exact pair is what systemd's
    // `bootctl` writes onto every systemd-boot ESP, so it is the common
    // case rather than a contrived one.
    try tree.putDirectory("loader", .{ .mode = 0o755 });
    try tree.putDirectory("loader/entries", .{ .mode = 0o755 });
    try tree.putFileBytes("loader/entries.srel", "type1\n", .{ .mode = 0o644 });
    try tree.putFileBytes("loader/entries/arch.conf", "title Arch\n", .{ .mode = 0o644 });
    try tree.putFileBytes("loader/loader.conf", "timeout 3\n", .{ .mode = 0o644 });

    const length = try tree.minimumFat32VolumeLength(.{}, .{});

    // Sizing succeeded; check the size it produced is one the tree fits in.
    const Image = @import("image.zig").Image;
    const image_path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-root-tree-fat-interleaved.img");
    defer std.testing.allocator.free(image_path);
    var img = try Image.create(io, image_path, .raw, length, .{});
    defer img.close(io);
    try fat32.format(&img, io, .{
        .partition_offset = 0,
        .partition_len = length,
        .volume_id = 0x0BAD_C0DE,
    });
    var fs = try fat32.open(&img, io, .{ .offset = 0, .length = length });
    try tree.populateFat32(&fs, .{});

    const conf = try fs.readFileAlloc(io, std.testing.allocator, "loader/entries/arch.conf");
    defer std.testing.allocator.free(conf);
    try std.testing.expectEqualStrings("title Arch\n", conf);
}

/// Hashed as a block after the seconds fields rather than interleaved with
/// them, so a tree carrying none of them -- which is every tree written
/// before they existed -- still hashes to what it always did.
fn hashSubsecondTimes(hash: *std.crypto.hash.sha2.Sha256, metadata: anytype) void {
    if (metadata.atime_nsec == 0 and
        metadata.mtime_nsec == 0 and
        metadata.ctime_nsec == 0 and
        metadata.crtime_nsec == 0 and
        metadata.crtime == null)
    {
        return;
    }
    hash.update("nsec\x00");
    hashInt(hash, metadata.atime_nsec);
    hashInt(hash, metadata.mtime_nsec);
    hashInt(hash, metadata.ctime_nsec);
    hashInt(hash, metadata.crtime_nsec);
    hashOptionalInt(hash, metadata.crtime);
}

test "root tree adapts to the squashfs writer and round-trips through the reader" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-squashfs.spool";
    const image_path = "test-root-tree-squashfs.img";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putFileBytes("etc/os-release", "NAME=miz\n", .{ .mode = 0o644, .uid = 5, .gid = 6 });
    try tree.putSymlink("etc/alias", "os-release", .{ .mode = 0o777 });
    try tree.sortNodes();

    _ = try squashfs.writeImagePath(
        std.testing.allocator,
        io,
        image_path,
        tree.squashfsSource(),
        .{ .compression = .zstd },
    );

    var reader = try squashfs.Reader.openPath(std.testing.allocator, io, image_path);
    defer reader.close(io);

    const file_index = try reader.lookup("/etc/os-release");
    const file_entry = reader.getEntry(file_index);
    try std.testing.expectEqual(@as(u32, 5), file_entry.uid);
    try std.testing.expectEqual(@as(u32, 6), file_entry.gid);
    const bytes = try reader.readFileAlloc(std.testing.allocator, io, file_index);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("NAME=miz\n", bytes);

    const link_index = try reader.lookup("/etc/alias");
    try std.testing.expectEqual(squashfs.EntryKind.symlink, reader.getEntry(link_index).kind);
    try std.testing.expectEqualStrings("os-release", try reader.readLink(link_index));
}

test "root tree squashfs adapter rejects node kinds and metadata it cannot represent" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-squashfs-reject.spool";
    const image_path = "test-root-tree-squashfs-reject.img";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putFifo("pipe", .{ .mode = 0o644 });
    try tree.sortNodes();

    try std.testing.expectError(error.UnsupportedNodeKind, squashfs.writeImagePath(
        std.testing.allocator,
        io,
        image_path,
        tree.squashfsSource(),
        .{},
    ));

    var xattr_tree = try RootTree.init(std.testing.allocator, io, spool_path ++ ".x", .{});
    defer xattr_tree.deinit();
    defer Io.Dir.cwd().deleteFile(io, spool_path ++ ".x") catch {};
    const xattrs = [_]tree_cursor.Xattr{.{ .name = "user.test", .value = "v" }};
    try xattr_tree.putFileBytes("f", "data", .{ .mode = 0o644, .xattrs = &xattrs });
    try xattr_tree.sortNodes();
    try std.testing.expectError(error.UnsupportedXattrs, squashfs.writeImagePath(
        std.testing.allocator,
        io,
        image_path,
        xattr_tree.squashfsSource(),
        .{},
    ));
}

test "root tree adapts to the iso9660 writer and round-trips through the reader" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-iso.spool";
    const image_path = "test-root-tree-iso.iso";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDirectory("boot", .{ .mode = 0o755 });
    try tree.putFileBytes("boot/grub.cfg", "set timeout=0\n", .{ .mode = 0o644, .uid = 7, .gid = 8 });
    try tree.putSymlink("boot/alias", "grub.cfg", .{ .mode = 0o777 });
    try tree.sortNodes();

    _ = try iso9660.writeImagePath(
        std.testing.allocator,
        io,
        image_path,
        tree.iso9660Source(),
        .{ .volume_id = "ROOTTREE" },
    );

    var reader = try iso9660.Reader.openPath(std.testing.allocator, io, image_path);
    defer reader.close(io);
    try std.testing.expect(reader.has_rock_ridge);

    const file_index = try reader.lookup("/boot/grub.cfg");
    const file_entry = reader.getEntry(file_index);
    try std.testing.expectEqual(@as(u32, 7), file_entry.uid);
    try std.testing.expectEqual(@as(u32, 8), file_entry.gid);
    const bytes = try reader.readFileAlloc(std.testing.allocator, io, file_index);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("set timeout=0\n", bytes);

    const link_index = try reader.lookup("/boot/alias");
    try std.testing.expectEqual(iso9660.EntryKind.symlink, reader.getEntry(link_index).kind);
    try std.testing.expectEqualStrings("grub.cfg", try reader.readLink(link_index));
}

test "root tree iso9660 adapter rejects node kinds and metadata it cannot represent" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-iso-reject.spool";
    const image_path = "test-root-tree-iso-reject.iso";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, image_path) catch {};

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putFifo("pipe", .{ .mode = 0o644 });
    try tree.sortNodes();

    try std.testing.expectError(error.UnsupportedNodeKind, iso9660.writeImagePath(
        std.testing.allocator,
        io,
        image_path,
        tree.iso9660Source(),
        .{},
    ));

    var xattr_tree = try RootTree.init(std.testing.allocator, io, spool_path ++ ".x", .{});
    defer xattr_tree.deinit();
    defer Io.Dir.cwd().deleteFile(io, spool_path ++ ".x") catch {};
    const xattrs = [_]tree_cursor.Xattr{.{ .name = "user.test", .value = "v" }};
    try xattr_tree.putFileBytes("f", "data", .{ .mode = 0o644, .xattrs = &xattrs });
    try xattr_tree.sortNodes();
    try std.testing.expectError(error.UnsupportedXattrs, iso9660.writeImagePath(
        std.testing.allocator,
        io,
        image_path,
        xattr_tree.iso9660Source(),
        .{},
    ));
}

test "indexed append import survives sort overlay and hardlink promotion" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-indexed-import.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    tree.append_only_import = true;
    try tree.putDirectory("usr", .{ .mode = 0o755 });
    try tree.putFileBytes("usr/tool", "old", .{ .mode = 0o755 });
    try tree.putHardlink("usr/tool-link", "usr/tool", .{ .mode = 0o755 });
    tree.append_only_import = false;

    const direct = try tree.readFileAllocAt(
        std.testing.allocator,
        tree.findIndex("usr/tool").?,
        16,
    );
    defer std.testing.allocator.free(direct);
    try std.testing.expectEqualStrings("old", direct);

    try tree.sortNodes();
    try std.testing.expect(tree.findNode("usr/tool-link") != null);
    try tree.putFileBytes("usr/tool", "new", .{ .mode = 0o755 });
    const replaced = try tree.readFileAlloc(std.testing.allocator, "usr/tool", 16);
    defer std.testing.allocator.free(replaced);
    try std.testing.expectEqualStrings("new", replaced);

    try std.testing.expect(try tree.remove("usr/tool"));
    try std.testing.expectEqual(Kind.file, tree.findNode("usr/tool-link").?.kind);
    const promoted = try tree.readFileAlloc(std.testing.allocator, "usr/tool-link", 16);
    defer std.testing.allocator.free(promoted);
    try std.testing.expectEqualStrings("new", promoted);
    try std.testing.expectEqual(@as(u64, 3), tree.total_node_bytes);
}

fn sumRootTreeNodeBytes(tree: *const RootTree) u64 {
    var total: u64 = 0;
    for (tree.nodes.items) |node| total += node.size();
    return total;
}

test "putNode customize-scale overlays stay correct across fast and slow paths (#455)" {
    const io = std.testing.io;
    const spool_path = "test-root-tree-putnode-scale.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var tree = try RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();

    // A production root holds ~150k nodes and customize re-overlays tens of
    // thousands of files and symlinks. The old putNode scanned every node on
    // every call, so that transition was O(n^2) and stalled the build. This
    // test drives the same overlay shapes on a smaller tree and pins the
    // correctness of the O(1) fast path (and the O(n) fallback) so the fix
    // cannot silently regress the node/byte accounting or hardlink safety.
    const dir_count = 32;
    const files_per_dir = 32; // 1024 leaf files across nested directories.
    var d: usize = 0;
    while (d < dir_count) : (d += 1) {
        var dir_buf: [64]u8 = undefined;
        const dir = try std.fmt.bufPrint(&dir_buf, "usr/lib/d{d}", .{d});
        try tree.putDirectory(dir, .{ .mode = 0o755 });
        var f: usize = 0;
        while (f < files_per_dir) : (f += 1) {
            var path_buf: [96]u8 = undefined;
            const p = try std.fmt.bufPrint(&path_buf, "usr/lib/d{d}/f{d}", .{ d, f });
            try tree.putFileBytes(p, "base", .{ .mode = 0o644 });
        }
    }
    try tree.putFileBytes("usr/bin/tool", "tool-v1", .{ .mode = 0o755 });
    try tree.putHardlink("usr/bin/tool-alias", "usr/bin/tool", .{ .mode = 0o755 });
    try tree.putSymlink("usr/bin/link", "tool", .{ .mode = 0o777 });

    const base_nodes = tree.nodeCount();
    try std.testing.expectEqual(sumRootTreeNodeBytes(&tree), tree.total_node_bytes);

    // Fast path: overwrite every file in place (file -> file) and re-publish
    // the symlink. None of these can break a hardlink or drop a descendant, so
    // the node count is unchanged and the running byte total stays exact.
    d = 0;
    while (d < dir_count) : (d += 1) {
        var f: usize = 0;
        while (f < files_per_dir) : (f += 1) {
            var path_buf: [96]u8 = undefined;
            const p = try std.fmt.bufPrint(&path_buf, "usr/lib/d{d}/f{d}", .{ d, f });
            try tree.putFileBytes(p, "changed-content", .{ .mode = 0o644 });
        }
    }
    try tree.putSymlink("usr/bin/link", "tool", .{ .mode = 0o777 });
    try std.testing.expectEqual(base_nodes, tree.nodeCount());
    try std.testing.expectEqual(sumRootTreeNodeBytes(&tree), tree.total_node_bytes);

    // Fast path: overwriting a hardlink target with another file is allowed
    // (the overlay exception), so it must not raise HardlinkTargetInUse. The
    // alias stays a hardlink to the target, and the target now holds the new
    // content.
    try tree.putFileBytes("usr/bin/tool", "tool-v2-longer", .{ .mode = 0o755 });
    try std.testing.expectEqual(Kind.hardlink, tree.findNode("usr/bin/tool-alias").?.kind);
    const tool = try tree.readFileAlloc(std.testing.allocator, "usr/bin/tool", 64);
    defer std.testing.allocator.free(tool);
    try std.testing.expectEqualStrings("tool-v2-longer", tool);
    try std.testing.expectEqual(base_nodes, tree.nodeCount());
    try std.testing.expectEqual(sumRootTreeNodeBytes(&tree), tree.total_node_bytes);

    // Fast path: add brand-new leaves (no removal at all). Two new directories
    // (opt, opt/new) are materialized alongside the 512 files.
    const before_new = tree.nodeCount();
    var n: usize = 0;
    while (n < 512) : (n += 1) {
        var path_buf: [96]u8 = undefined;
        const p = try std.fmt.bufPrint(&path_buf, "opt/new/g{d}", .{n});
        try tree.putFileBytes(p, "fresh", .{ .mode = 0o644 });
    }
    try std.testing.expectEqual(before_new + 512 + 2, tree.nodeCount());
    try std.testing.expectEqual(sumRootTreeNodeBytes(&tree), tree.total_node_bytes);

    // Slow path (replaces_file_with_other): replacing the hardlink target with a
    // non-file must be detected as breaking the surviving alias.
    try std.testing.expectError(
        error.HardlinkTargetInUse,
        tree.putSymlink("usr/bin/tool", "elsewhere", .{ .mode = 0o777 }),
    );
    try std.testing.expectEqual(sumRootTreeNodeBytes(&tree), tree.total_node_bytes);

    // Slow path (shadows_directory): a file overlaid on an existing directory
    // drops the whole subtree; the accounting must stay exact.
    const before_shadow = tree.nodeCount();
    try tree.putFileBytes("usr/lib/d0", "flat", .{ .mode = 0o644 });
    try std.testing.expectEqual(before_shadow - files_per_dir, tree.nodeCount());
    try std.testing.expect(tree.findNode("usr/lib/d0/f0") == null);
    try std.testing.expectEqual(Kind.file, tree.findNode("usr/lib/d0").?.kind);
    try std.testing.expectEqual(sumRootTreeNodeBytes(&tree), tree.total_node_bytes);

    // Slow path (has_replace_parent): creating a child under a path that is
    // currently a file forces that ancestor to be replaced by a directory.
    try tree.putFileBytes("usr/lib/d0/child", "nested", .{ .mode = 0o644 });
    try std.testing.expectEqual(Kind.directory, tree.findNode("usr/lib/d0").?.kind);
    try std.testing.expect(tree.findNode("usr/lib/d0/child") != null);
    try std.testing.expectEqual(sumRootTreeNodeBytes(&tree), tree.total_node_bytes);
}
