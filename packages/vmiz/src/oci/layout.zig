//! Verified access to a local OCI image layout.
//!
//! Files are synced before publication.  `std.Io` has no portable directory
//! sync primitive, so this cannot promise power-loss durability beyond the
//! file sync and atomic rename supplied by the platform.
const std = @import("std");
const content = @import("content.zig");
const model = @import("model.zig");
const reference = @import("reference.zig");
const transport = @import("transport.zig");

const Io = std.Io;

pub const Error = error{
    InvalidLayout,
    InvalidLayoutVersion,
    InvalidIndex,
    RootNotFound,
    AmbiguousRoot,
    CorruptBlob,
    DescriptorMismatch,
    ConflictingDescriptor,
    InjectedFailure,
} || std.mem.Allocator.Error;

pub const FailurePoint = enum {
    none,
    before_index_publish,
    after_blob_temp_sync,
    after_index_temp_sync,
};
pub const max_metadata_size = 16 * 1024 * 1024;
const transfer_buffer_size = 64 * 1024;

pub const BlobState = enum { missing, valid, corrupt };

pub const ResolvedRoot = struct {
    descriptor: model.Descriptor,
    bytes: []u8,
    /// JSON for the descriptor as it occurred in `index.json`, retaining
    /// extension fields when a named destination clones it.
    descriptor_json: []u8,
    descriptor_parsed: std.json.Parsed(model.Descriptor),
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ResolvedRoot) void {
        self.allocator.free(self.bytes);
        self.descriptor_parsed.deinit();
        self.allocator.free(self.descriptor_json);
        self.* = undefined;
    }
};

/// Read-only layout operations. All blob reads validate descriptor size and
/// SHA-256 while reading; a digest-shaped file name is never trusted.
pub const Source = struct {
    io: Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    metadata_limit: usize = max_metadata_size,

    pub fn init(io: Io, allocator: std.mem.Allocator, path: []const u8) Source {
        return .{ .io = io, .allocator = allocator, .path = path };
    }

    pub fn initWithMetadataLimit(io: Io, allocator: std.mem.Allocator, path: []const u8, metadata_limit: usize) Source {
        return .{ .io = io, .allocator = allocator, .path = path, .metadata_limit = metadata_limit };
    }

    /// Exposes the operations that the shared copy graph needs without
    /// coupling it to filesystem layout paths.
    pub fn asTransport(self: *Source) transport.Source {
        return .{
            .context = self,
            .read_metadata = readMetadataTransport,
            .read_manifest_metadata = readMetadataTransport,
            .copy_verified_to = copyVerifiedToTransport,
        };
    }

    pub fn resolve(self: Source, ref: reference.LayoutReference) !ResolvedRoot {
        if (!std.mem.eql(u8, self.path, ref.path)) return error.InvalidLayout;
        const index_bytes = try self.readFile("index.json", self.metadata_limit);
        defer self.allocator.free(index_bytes);
        try self.validateLayout();

        var index = try std.json.parseFromSlice(model.Index, self.allocator, index_bytes, .{ .ignore_unknown_fields = true });
        defer index.deinit();
        model.validateIndex(index.value) catch return error.InvalidIndex;

        var selected: ?model.Descriptor = null;
        var selected_index: ?usize = null;
        if (ref.selection) |selection| {
            switch (selection) {
                .digest => |digest| {
                    const text = digest.format();
                    for (index.value.manifests, 0..) |descriptor, i| {
                        if (std.mem.eql(u8, descriptor.digest, &text)) {
                            selected = descriptor;
                            selected_index = i;
                            break;
                        }
                    }
                    if (selected == null) return error.RootNotFound;
                },
                .tag => |name| {
                    for (index.value.manifests, 0..) |descriptor, i| {
                        if (annotation(descriptor, "org.opencontainers.image.ref.name")) |candidate| {
                            if (std.mem.eql(u8, candidate, name)) {
                                selected = descriptor;
                                selected_index = i;
                                break;
                            }
                        }
                    }
                    if (selected == null) return error.RootNotFound;
                },
            }
        } else {
            selected = try self.unambiguous(index.value.manifests);
            selected_index = 0;
        }
        const descriptor_json = try self.rawDescriptorJson(index_bytes, selected_index.?);
        errdefer self.allocator.free(descriptor_json);
        var descriptor_parsed = std.json.parseFromSlice(model.Descriptor, self.allocator, descriptor_json, .{ .ignore_unknown_fields = true }) catch return error.InvalidIndex;
        errdefer descriptor_parsed.deinit();
        const root = descriptor_parsed.value;
        model.validateRootDescriptor(root) catch return error.InvalidIndex;
        const bytes = try self.readMetadata(root);
        errdefer self.allocator.free(bytes);
        try validateRootDocument(self.allocator, root, bytes);
        return .{ .descriptor = root, .bytes = bytes, .descriptor_json = descriptor_json, .descriptor_parsed = descriptor_parsed, .allocator = self.allocator };
    }

    /// Reads a JSON metadata blob. Content blobs must use `copyVerifiedTo`;
    /// metadata is deliberately capped so descriptor sizes cannot become
    /// allocation requests.
    pub fn readMetadata(self: Source, descriptor: model.Descriptor) ![]u8 {
        if (descriptor.size > self.metadata_limit or descriptor.size > std.math.maxInt(usize)) return error.CorruptBlob;
        const digest = content.Digest.parse(descriptor.digest) catch return error.CorruptBlob;
        const name = digest.blobPathComponent();
        var path_buf: [80]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "blobs/sha256/{s}", .{name});
        return self.readVerifiedAlloc(path, digest, descriptor.size);
    }

    /// Opens a content blob after validating its canonical digest path and
    /// declared size. The caller must verify the digest while consuming it.
    pub fn openBlob(self: Source, descriptor: model.Descriptor) !Io.File {
        const digest = content.Digest.parse(descriptor.digest) catch return error.CorruptBlob;
        const hex = digest.blobPathComponent();
        var path_buf: [80]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "blobs/sha256/{s}", .{hex});
        var dir = try Io.Dir.cwd().openDir(self.io, self.path, .{});
        defer dir.close(self.io);
        const file = dir.openFile(self.io, path, .{}) catch return error.CorruptBlob;
        errdefer file.close(self.io);
        if (try file.length(self.io) != descriptor.size) return error.CorruptBlob;
        return file;
    }

    pub fn validateLayout(self: Source) !void {
        const bytes = try self.readFile("oci-layout", 4096);
        defer self.allocator.free(bytes);
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, bytes, .{}) catch return error.InvalidLayout;
        defer parsed.deinit();
        const object = switch (parsed.value) {
            .object => |object| object,
            else => return error.InvalidLayout,
        };
        const version = object.get("imageLayoutVersion") orelse return error.InvalidLayoutVersion;
        if (version != .string or !std.mem.eql(u8, version.string, "1.0.0")) return error.InvalidLayoutVersion;
        var dir = Io.Dir.cwd().openDir(self.io, self.path, .{}) catch return error.InvalidLayout;
        defer dir.close(self.io);
        var blobs = dir.openDir(self.io, "blobs/sha256", .{}) catch return error.InvalidLayout;
        blobs.close(self.io);
    }

    fn unambiguous(self: Source, descriptors: []const model.Descriptor) !model.Descriptor {
        _ = self;
        if (descriptors.len == 0) return error.RootNotFound;
        if (descriptors.len != 1) return error.AmbiguousRoot;
        return descriptors[0];
    }

    fn rawDescriptorJson(self: Source, index_bytes: []const u8, occurrence: usize) ![]u8 {
        var value = std.json.parseFromSlice(std.json.Value, self.allocator, index_bytes, .{}) catch return error.InvalidIndex;
        defer value.deinit();
        const object = switch (value.value) {
            .object => |object| object,
            else => return error.InvalidIndex,
        };
        const manifests = object.get("manifests") orelse return error.InvalidIndex;
        if (manifests != .array) return error.InvalidIndex;
        if (occurrence >= manifests.array.items.len) return error.RootNotFound;
        return std.json.Stringify.valueAlloc(self.allocator, manifests.array.items[occurrence], .{});
    }

    fn readFile(self: Source, relative: []const u8, max_size: usize) ![]u8 {
        var dir = try Io.Dir.cwd().openDir(self.io, self.path, .{});
        defer dir.close(self.io);
        var file = try dir.openFile(self.io, relative, .{});
        defer file.close(self.io);
        const size = try file.length(self.io);
        if (size > max_size) return error.CorruptBlob;
        if (size > std.math.maxInt(usize)) return error.CorruptBlob;
        const bytes = try self.allocator.alloc(u8, @intCast(size));
        errdefer self.allocator.free(bytes);
        if (try file.readPositionalAll(self.io, bytes, 0) != bytes.len) return error.CorruptBlob;
        return bytes;
    }

    /// Returns the destination state without using verification failure as a
    /// proxy for absence. A corrupt digest path is never safe to replace.
    pub fn blobState(self: Source, descriptor: model.Descriptor) !BlobState {
        const digest = content.Digest.parse(descriptor.digest) catch return .corrupt;
        const hex = digest.blobPathComponent();
        var path_buf: [80]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "blobs/sha256/{s}", .{hex});
        return self.verifiedPathState(path, digest, descriptor.size);
    }

    /// Streams a verified blob into `destination` using a fixed-size buffer.
    /// No content blob allocation is performed.
    pub fn copyVerifiedTo(self: Source, descriptor: model.Descriptor, destination: Io.File) !void {
        const digest = content.Digest.parse(descriptor.digest) catch return error.CorruptBlob;
        const hex = digest.blobPathComponent();
        var path_buf: [80]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "blobs/sha256/{s}", .{hex});
        var dir = try Io.Dir.cwd().openDir(self.io, self.path, .{});
        defer dir.close(self.io);
        var file = dir.openFile(self.io, path, .{}) catch return error.CorruptBlob;
        defer file.close(self.io);
        if (try file.length(self.io) != descriptor.size) return error.CorruptBlob;
        var verifier = content.Verifier.init(digest, descriptor.size);
        var buffer: [transfer_buffer_size]u8 = undefined;
        var offset: u64 = 0;
        while (offset < descriptor.size) {
            const count = try file.readPositional(self.io, &.{buffer[0..@intCast(@min(descriptor.size - offset, buffer.len))]}, offset);
            if (count == 0) return error.CorruptBlob;
            verifier.update(buffer[0..count]) catch return error.CorruptBlob;
            try destination.writeStreamingAll(self.io, buffer[0..count]);
            offset += count;
        }
        verifier.finish() catch return error.CorruptBlob;
    }

    fn verifiedPathState(self: Source, relative: []const u8, digest: content.Digest, size: u64) !BlobState {
        var dir = try Io.Dir.cwd().openDir(self.io, self.path, .{});
        defer dir.close(self.io);
        var file = dir.openFile(self.io, relative, .{}) catch |err| switch (err) {
            error.FileNotFound => return .missing,
            else => return err,
        };
        defer file.close(self.io);
        if (try file.length(self.io) != size) return .corrupt;
        var verifier = content.Verifier.init(digest, size);
        var buffer: [transfer_buffer_size]u8 = undefined;
        var offset: u64 = 0;
        while (offset < size) {
            const count = try file.readPositional(self.io, &.{buffer[0..@intCast(@min(size - offset, buffer.len))]}, offset);
            if (count == 0) return .corrupt;
            verifier.update(buffer[0..count]) catch return .corrupt;
            offset += count;
        }
        verifier.finish() catch return .corrupt;
        return .valid;
    }

    fn readVerifiedAlloc(self: Source, relative: []const u8, digest: content.Digest, size: u64) ![]u8 {
        if (size > std.math.maxInt(usize)) return error.CorruptBlob;
        var dir = try Io.Dir.cwd().openDir(self.io, self.path, .{});
        defer dir.close(self.io);
        var file = dir.openFile(self.io, relative, .{}) catch return error.CorruptBlob;
        defer file.close(self.io);
        if (try file.length(self.io) != size) return error.CorruptBlob;
        const result = try self.allocator.alloc(u8, @intCast(size));
        errdefer self.allocator.free(result);
        var verifier = content.Verifier.init(digest, size);
        var offset: u64 = 0;
        while (offset < size) {
            const count = try file.readPositional(self.io, &.{result[@intCast(offset)..][0..@intCast(@min(size - offset, std.math.maxInt(usize)))]}, offset);
            if (count == 0) return error.CorruptBlob;
            verifier.update(result[@intCast(offset)..][0..count]) catch return error.CorruptBlob;
            offset += count;
        }
        verifier.finish() catch return error.CorruptBlob;
        return result;
    }

    fn readMetadataTransport(context: *anyopaque, descriptor: model.Descriptor) anyerror![]u8 {
        const self: *Source = @ptrCast(@alignCast(context));
        return self.readMetadata(descriptor);
    }

    fn copyVerifiedToTransport(context: *anyopaque, descriptor: model.Descriptor, destination: Io.File) anyerror!void {
        const self: *Source = @ptrCast(@alignCast(context));
        return self.copyVerifiedTo(descriptor, destination);
    }
};

/// A destination is either the existing layout or a sibling staging layout.
/// `finish` makes a newly-created layout visible only after its index commit.
pub const Destination = struct {
    io: Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    work_path: []u8,
    is_new: bool,
    bootstrap_lock: ?Io.File = null,
    failure_point: FailurePoint = .none,
    root_staged: bool = false,

    pub fn init(io: Io, allocator: std.mem.Allocator, path: []const u8) !Destination {
        const parent = std.fs.path.dirname(path) orelse ".";
        const base = std.fs.path.basename(path);
        try Io.Dir.cwd().createDirPath(io, parent);
        var bootstrap_lock = try openBootstrapLock(io, allocator, parent, base);
        errdefer bootstrap_lock.close(io);
        const existing = Io.Dir.cwd().openDir(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (existing) |dir| {
            dir.close(io);
            try Source.init(io, allocator, path).validateLayout();
            const work_path = try allocator.dupe(u8, path);
            bootstrap_lock.close(io);
            return .{ .io = io, .allocator = allocator, .path = path, .work_path = work_path, .is_new = false };
        }
        const staging = try createUniqueDirectory(io, allocator, parent, base);
        errdefer Io.Dir.cwd().deleteTree(io, staging) catch {};
        errdefer allocator.free(staging);
        var result = Destination{
            .io = io,
            .allocator = allocator,
            .path = path,
            .work_path = staging,
            .is_new = true,
            .bootstrap_lock = bootstrap_lock,
        };
        try result.createSkeleton();
        return result;
    }

    /// Adapts the local transactional destination to the shared graph copy
    /// engine. The root blob is installed immediately before its index entry
    /// is committed, preserving the old index on all earlier failures.
    pub fn asTransport(self: *Destination) transport.Destination {
        return .{
            .context = self,
            .prepare = prepareTransport,
            .ensure_descriptor = ensureDescriptorTransport,
            .stage_root = stageRootTransport,
            .commit = commitTransport,
            .finish = finishTransport,
        };
    }

    pub fn deinit(self: *Destination) void {
        if (self.is_new) Io.Dir.cwd().deleteTree(self.io, self.work_path) catch {};
        if (self.bootstrap_lock) |lock| lock.close(self.io);
        self.allocator.free(self.work_path);
        self.* = undefined;
    }

    /// Ensures the destination has a valid digest path. Missing blobs are
    /// streamed from source into a unique exclusive temporary file. Existing
    /// corrupt paths are rejected and never overwritten.
    pub fn ensureBlob(self: *Destination, source: transport.Source, descriptor: model.Descriptor, counts: *Counts) !void {
        return self.ensureContent(source, descriptor, null, counts);
    }

    pub fn ensureBytes(self: *Destination, descriptor: model.Descriptor, bytes: []const u8, counts: *Counts) !void {
        return self.ensureMetadataBlob(descriptor, bytes, counts);
    }

    fn ensureMetadataBlob(
        self: *Destination,
        descriptor: model.Descriptor,
        bytes: []const u8,
        counts: *Counts,
    ) !void {
        const digest = content.Digest.parse(descriptor.digest) catch return error.CorruptBlob;
        content.verifyBytes(digest, descriptor.size, bytes) catch return error.CorruptBlob;
        return self.ensureContent(null, descriptor, bytes, counts);
    }

    fn ensureContent(
        self: *Destination,
        source: ?transport.Source,
        descriptor: model.Descriptor,
        bytes: ?[]const u8,
        counts: *Counts,
    ) !void {
        const digest = content.Digest.parse(descriptor.digest) catch return error.CorruptBlob;
        const hex = digest.blobPathComponent();
        switch (try Source.init(self.io, self.allocator, self.work_path).blobState(descriptor)) {
            .valid => {
                counts.reused += 1;
                return;
            },
            .corrupt => return error.CorruptBlob,
            .missing => {},
        }
        var layout_dir = try Io.Dir.cwd().openDir(self.io, self.work_path, .{});
        defer layout_dir.close(self.io);
        var dir = try layout_dir.openDir(self.io, "blobs/sha256", .{});
        defer dir.close(self.io);
        const temporary = try createUniqueTempFile(self.io, self.allocator, dir, "blob");
        defer self.allocator.free(temporary.name);
        var file = temporary.file;
        var file_closed = false;
        defer {
            if (!file_closed) file.close(self.io);
            dir.deleteFile(self.io, temporary.name) catch {};
        }
        if (bytes) |data| {
            try file.writeStreamingAll(self.io, data);
        } else {
            try source.?.copyVerifiedTo(descriptor, file);
        }
        try file.sync(self.io);
        if (self.failure_point == .after_blob_temp_sync) return error.InjectedFailure;
        file.close(self.io);
        file_closed = true;
        Io.Dir.renamePreserve(dir, temporary.name, dir, &hex, self.io) catch |err| switch (err) {
            error.PathAlreadyExists => switch (try Source.init(self.io, self.allocator, self.work_path).blobState(descriptor)) {
                .valid => {
                    counts.reused += 1;
                    return;
                },
                .missing, .corrupt => return error.CorruptBlob,
            },
            else => return err,
        };
        counts.transferred += 1;
    }

    pub fn commit(self: *Destination, root: model.Descriptor, selection: ?reference.Selection) !void {
        return self.commitExact(root, null, selection);
    }

    pub fn commitExact(self: *Destination, root: model.Descriptor, root_json: ?[]const u8, selection: ?reference.Selection) !void {
        var lock = try self.openLock();
        defer lock.close(self.io);
        // The old valid index remains visible until this final replacement.
        const bytes = try Source.init(self.io, self.allocator, self.work_path).readFile("index.json", max_metadata_size);
        defer self.allocator.free(bytes);
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, bytes, .{}) catch return error.InvalidIndex;
        defer parsed.deinit();
        try mergeRoot(parsed.arena.allocator(), &parsed.value, root, root_json, selection);
        const out = try std.json.Stringify.valueAlloc(self.allocator, parsed.value, .{});
        defer self.allocator.free(out);
        if (self.failure_point == .before_index_publish) return error.InjectedFailure;
        var dir = try Io.Dir.cwd().openDir(self.io, self.work_path, .{});
        defer dir.close(self.io);
        const temporary = try createUniqueTempFile(self.io, self.allocator, dir, "index");
        defer self.allocator.free(temporary.name);
        var tmp = temporary.file;
        var tmp_closed = false;
        defer {
            if (!tmp_closed) tmp.close(self.io);
            dir.deleteFile(self.io, temporary.name) catch {};
        }
        try tmp.writeStreamingAll(self.io, out);
        try tmp.sync(self.io);
        if (self.failure_point == .after_index_temp_sync) return error.InjectedFailure;
        tmp.close(self.io);
        tmp_closed = true;
        try Io.Dir.rename(dir, temporary.name, dir, "index.json", self.io);
    }

    pub fn finish(self: *Destination) !void {
        if (!self.is_new) return;
        try Io.Dir.renamePreserve(Io.Dir.cwd(), self.work_path, Io.Dir.cwd(), self.path, self.io);
        self.is_new = false;
        if (self.bootstrap_lock) |lock| {
            lock.close(self.io);
            self.bootstrap_lock = null;
        }
    }

    fn createSkeleton(self: *Destination) !void {
        var dir = try Io.Dir.cwd().openDir(self.io, self.work_path, .{});
        defer dir.close(self.io);
        try dir.createDirPath(self.io, "blobs/sha256");
        try dir.writeFile(self.io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}\n" });
        try dir.writeFile(self.io, .{ .sub_path = "index.json", .data = "{\"schemaVersion\":2,\"manifests\":[]}\n" });
    }

    fn openLock(self: *Destination) !Io.File {
        var dir = try Io.Dir.cwd().openDir(self.io, self.work_path, .{});
        defer dir.close(self.io);
        return try dir.createFile(self.io, ".vmiz-oci.lock", .{ .read = true, .truncate = false, .lock = .exclusive });
    }

    fn prepareTransport(
        context: *anyopaque,
        root: model.Descriptor,
        selection: ?reference.Selection,
    ) anyerror!void {
        const self: *Destination = @ptrCast(@alignCast(context));
        const requested = selection orelse return;
        switch (requested) {
            .tag => {},
            .digest => |expected| {
                const actual = content.Digest.parse(root.digest) catch return error.DescriptorMismatch;
                if (!std.mem.eql(u8, &actual.bytes, &expected.bytes)) return error.DescriptorMismatch;
                const bytes = try Source.init(self.io, self.allocator, self.work_path).readFile(
                    "index.json",
                    max_metadata_size,
                );
                defer self.allocator.free(bytes);
                var parsed = std.json.parseFromSlice(
                    std.json.Value,
                    self.allocator,
                    bytes,
                    .{},
                ) catch return error.InvalidIndex;
                defer parsed.deinit();
                const object = switch (parsed.value) {
                    .object => |object| object,
                    else => return error.InvalidIndex,
                };
                const manifests = object.get("manifests") orelse return error.InvalidIndex;
                if (manifests != .array) return error.InvalidIndex;
                _ = try containsCompatibleDigest(
                    parsed.arena.allocator(),
                    manifests.array.items,
                    root,
                );
            },
        }
    }

    fn ensureDescriptorTransport(
        context: *anyopaque,
        source: transport.Source,
        descriptor: model.Descriptor,
        role: transport.DescriptorRole,
        metadata: ?[]const u8,
        counts: *transport.Counts,
    ) anyerror!void {
        const self: *Destination = @ptrCast(@alignCast(context));
        if (role == .manifest) {
            return self.ensureMetadataBlob(descriptor, metadata orelse return error.InvalidIndex, counts);
        }
        return self.ensureBlob(source, descriptor, counts);
    }

    fn commitTransport(
        context: *anyopaque,
        source: transport.Source,
        root: model.Descriptor,
        root_descriptor_json: []const u8,
        _: []const u8,
        selection: ?reference.Selection,
        counts: *transport.Counts,
    ) anyerror!void {
        const self: *Destination = @ptrCast(@alignCast(context));
        if (!self.root_staged) try self.ensureBlob(source, root, counts);
        self.root_staged = false;
        return self.commitExact(root, root_descriptor_json, selection);
    }

    fn stageRootTransport(
        context: *anyopaque,
        source: transport.Source,
        root: model.Descriptor,
        counts: *transport.Counts,
    ) anyerror!void {
        const self: *Destination = @ptrCast(@alignCast(context));
        try self.ensureBlob(source, root, counts);
        self.root_staged = true;
    }

    fn finishTransport(context: *anyopaque) anyerror!void {
        const self: *Destination = @ptrCast(@alignCast(context));
        return self.finish();
    }
};

pub const Counts = transport.Counts;

const UniqueTempFile = struct {
    name: []u8,
    file: Io.File,
};

fn createUniqueDirectory(io: Io, allocator: std.mem.Allocator, parent: []const u8, base: []const u8) ![]u8 {
    var random: [16]u8 = undefined;
    for (0..64) |_| {
        try io.randomSecure(&random);
        const suffix = std.fmt.bytesToHex(random, .lower);
        const name = try std.fmt.allocPrint(allocator, ".{s}.vmiz-oci-staging-{s}", .{ base, suffix });
        const path = try std.fs.path.join(allocator, &.{ parent, name });
        allocator.free(name);
        Io.Dir.cwd().createDir(io, path, .default_dir) catch |err| switch (err) {
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

    return error.PathAlreadyExists;
}

fn openBootstrapLock(io: Io, allocator: std.mem.Allocator, parent: []const u8, base: []const u8) !Io.File {
    var parent_dir = try Io.Dir.cwd().openDir(io, parent, .{});
    defer parent_dir.close(io);
    const name = try std.fmt.allocPrint(allocator, ".{s}.vmiz-oci-bootstrap.lock", .{base});
    defer allocator.free(name);
    return try parent_dir.createFile(io, name, .{ .read = true, .truncate = false, .lock = .exclusive });
}

fn createUniqueTempFile(io: Io, allocator: std.mem.Allocator, dir: Io.Dir, kind: []const u8) !UniqueTempFile {
    var random: [16]u8 = undefined;
    for (0..64) |_| {
        try io.randomSecure(&random);
        const suffix = std.fmt.bytesToHex(random, .lower);
        const name = try std.fmt.allocPrint(allocator, ".vmiz-oci-{s}-{s}.tmp", .{ kind, suffix });
        const file = dir.createFile(io, name, .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(name);
                continue;
            },
            else => {
                allocator.free(name);
                return err;
            },
        };
        return .{ .name = name, .file = file };
    }
    return error.PathAlreadyExists;
}

fn annotation(descriptor: model.Descriptor, key: []const u8) ?[]const u8 {
    const value = descriptor.annotations orelse return null;
    const object = switch (value) {
        .object => |object| object,
        else => return null,
    };
    const result = object.get(key) orelse return null;
    return switch (result) {
        .string => |text| text,
        else => null,
    };
}

fn validateRootDocument(allocator: std.mem.Allocator, descriptor: model.Descriptor, bytes: []const u8) !void {
    switch (model.classifyMediaType(descriptor.mediaType)) {
        .oci_index, .docker_manifest_list => {
            var parsed = std.json.parseFromSlice(model.Index, allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidIndex;
            defer parsed.deinit();
            model.validateIndex(parsed.value) catch return error.InvalidIndex;
        },
        .oci_manifest, .docker_manifest => {
            var parsed = std.json.parseFromSlice(model.Manifest, allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidIndex;
            defer parsed.deinit();
            model.validateManifest(parsed.value) catch return error.InvalidIndex;
        },
        else => return error.InvalidIndex,
    }
}

fn mergeRoot(allocator: std.mem.Allocator, index: *std.json.Value, root: model.Descriptor, root_json: ?[]const u8, selection: ?reference.Selection) !void {
    const object = switch (index.*) {
        .object => |*object| object,
        else => return error.InvalidIndex,
    };
    const schema = object.get("schemaVersion") orelse return error.InvalidIndex;
    if (schema != .integer or schema.integer != 2) return error.InvalidIndex;
    const manifests = object.getPtr("manifests") orelse return error.InvalidIndex;
    if (manifests.* != .array) return error.InvalidIndex;
    const generated = if (root_json == null) try std.json.Stringify.valueAlloc(allocator, root, .{}) else null;
    defer if (generated) |encoded| allocator.free(encoded);
    var root_value = try std.json.parseFromSliceLeaky(std.json.Value, allocator, root_json orelse generated.?, .{});
    if (root_value != .object) return error.InvalidIndex;
    const name: ?[]const u8 = switch (selection orelse {
        try setReferenceName(allocator, &root_value.object, null);
        var unannotated_index: ?usize = null;
        for (manifests.array.items, 0..) |item, i| {
            if (try descriptorReferenceName(item) != null) continue;
            if (unannotated_index != null) return error.AmbiguousRoot;
            unannotated_index = i;
        }
        if (unannotated_index) |i| {
            manifests.array.items[i] = root_value;
        } else {
            try manifests.array.append(root_value);
        }
        return;
    }) {
        .tag => |tag| tag,
        .digest => |digest| {
            const text = digest.format();
            if (!std.mem.eql(u8, root.digest, &text)) return error.DescriptorMismatch;
            if (!try containsCompatibleDigest(allocator, manifests.array.items, root)) {
                try manifests.array.append(root_value);
            }
            return;
        },
    };
    const descriptor = &root_value.object;
    try setReferenceName(allocator, descriptor, name);
    for (manifests.array.items) |*item| {
        const old = try descriptorReferenceName(item.*) orelse continue;
        if (std.mem.eql(u8, old, name.?)) {
            item.* = root_value;
            return;
        }
    }
    try manifests.array.append(root_value);
}

const reference_name_annotation = "org.opencontainers.image.ref.name";

fn descriptorReferenceName(value: std.json.Value) !?[]const u8 {
    if (value != .object) return error.InvalidIndex;
    const annotations = value.object.get("annotations") orelse return null;
    if (annotations != .object) return error.InvalidIndex;
    const name = annotations.object.get(reference_name_annotation) orelse return null;
    if (name != .string) return error.InvalidIndex;
    return name.string;
}

fn setReferenceName(allocator: std.mem.Allocator, descriptor: *std.json.ObjectMap, name: ?[]const u8) !void {
    var annotations = descriptor.getPtr("annotations");
    if (annotations == null) {
        if (name == null) return;
        try descriptor.put(allocator, "annotations", .{ .object = .empty });
        annotations = descriptor.getPtr("annotations");
    } else if (annotations.?.* != .object) {
        return error.InvalidIndex;
    }
    if (name) |value| {
        try annotations.?.object.put(allocator, reference_name_annotation, .{ .string = value });
    } else {
        _ = annotations.?.object.orderedRemove(reference_name_annotation);
    }
}

fn containsCompatibleDigest(
    allocator: std.mem.Allocator,
    items: []const std.json.Value,
    root: model.Descriptor,
) !bool {
    var found = false;
    for (items) |item| {
        if (item != .object) continue;
        const candidate = item.object.get("digest") orelse continue;
        if (candidate != .string or !std.mem.eql(u8, candidate.string, root.digest)) continue;
        const parsed = std.json.parseFromValueLeaky(
            model.Descriptor,
            allocator,
            item,
            .{ .ignore_unknown_fields = true },
        ) catch return error.InvalidIndex;
        if (parsed.size != root.size or !optionalStringsEqual(parsed.mediaType, root.mediaType)) {
            return error.ConflictingDescriptor;
        }
        found = true;
    }
    return found;
}

fn optionalStringsEqual(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, left.?, right.?);
}
