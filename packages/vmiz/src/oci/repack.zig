//! Deterministic bundle diffing and transactional OCI graph publication.
const std = @import("std");
const bundle = @import("bundle.zig");
const content = @import("content.zig");
const image = @import("image.zig");
const layout = @import("layout.zig");
const model = @import("model.zig");
const reference = @import("reference.zig");
const snapshot = @import("snapshot.zig");
const tar = @import("../tar.zig");

const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const metadata_limit = 16 * 1024 * 1024;

pub const Options = struct {
    created_by: []const u8 = "vmiz oci repack",
    failure_point: FailurePoint = .none,
    compression: Compression = .same,
};

pub const Compression = enum {
    same,
    gzip,
    none,
};

pub const FailurePoint = enum {
    none,
    before_commit,
};

pub const Result = struct {
    root_digest: [71]u8,

    pub fn digest(self: *const Result) []const u8 {
        return &self.root_digest;
    }
};

const HashedFile = struct {
    digest: content.Digest,
    size: u64,
};

pub fn repackLayout(
    allocator: std.mem.Allocator,
    io: Io,
    target: reference.LayoutReference,
    bundle_path: []const u8,
    options: Options,
) !Result {
    var bundle_dir = try Io.Dir.cwd().openDir(io, bundle_path, .{});
    defer bundle_dir.close(io);
    var lock = try bundle_dir.createFile(io, ".vmiz/repack.lock", .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
    });
    defer lock.close(io);

    const metadata_bytes = try bundle_dir.readFileAlloc(
        io,
        ".vmiz/metadata.json",
        allocator,
        .limited(metadata_limit),
    );
    defer allocator.free(metadata_bytes);
    var metadata = std.json.parseFromSlice(
        bundle.Metadata,
        allocator,
        metadata_bytes,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidBundleMetadata;
    defer metadata.deinit();
    if (!std.mem.eql(u8, metadata.value.layout_path, target.path)) {
        return error.BaseLayoutMismatch;
    }

    const source_ref = reference.LayoutReference{
        .path = metadata.value.layout_path,
        .selection = .{
            .digest = content.Digest.parse(metadata.value.root_digest) catch
                return error.InvalidBundleMetadata,
        },
    };
    var source = layout.Source.init(io, allocator, source_ref.path);
    var resolved = try image.resolveLayout(allocator, &source, source_ref, .{
        .platform = metadata.value.platform,
    });
    defer resolved.deinit();
    if (!std.mem.eql(
        u8,
        resolved.manifestNode().descriptor.digest,
        metadata.value.manifest_digest,
    ) or !std.mem.eql(
        u8,
        resolved.manifest.config.digest,
        metadata.value.config_digest,
    )) return error.BaseImageChanged;

    const base_bytes = try bundle_dir.readFileAlloc(
        io,
        ".vmiz/base.json",
        allocator,
        .limited(metadata_limit),
    );
    defer allocator.free(base_bytes);
    var base = std.json.parseFromSlice(
        []snapshot.Entry,
        allocator,
        base_bytes,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidBundleMetadata;
    defer base.deinit();
    try validateSnapshot(base.value);

    var rootfs = try bundle_dir.openDir(io, "rootfs", .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer rootfs.close(io);
    var current = try snapshot.capture(allocator, io, rootfs);
    defer current.deinit();
    try validateSnapshot(current.entries);
    if (metadata.value.rootless) try overlayRootlessOwnership(
        base.value,
        current.entries,
        metadata.value.host_uid,
        metadata.value.host_gid,
    );

    const temporary_tar = try createUniqueTempFile(io, allocator, bundle_dir, ".vmiz", "layer.tar");
    defer allocator.free(temporary_tar.name);
    var tar_file = temporary_tar.file;
    var tar_closed = false;
    defer {
        if (!tar_closed) tar_file.close(io);
        bundle_dir.deleteFile(io, temporary_tar.name) catch {};
    }
    var tar_buffer: [64 * 1024]u8 = undefined;
    var tar_file_writer = tar_file.writer(io, &tar_buffer);
    var archive = tar.Writer.init(&tar_file_writer.interface);
    try writeDiff(allocator, io, rootfs, base.value, current.entries, &archive);
    try archive.finish();
    try tar_file_writer.interface.flush();
    try tar_file.sync(io);
    const diff = try hashFile(io, tar_file);
    tar_file.close(io);
    tar_closed = true;

    const blobs_path = try std.fs.path.join(allocator, &.{ target.path, "blobs/sha256" });
    defer allocator.free(blobs_path);
    var blobs = try Io.Dir.cwd().openDir(io, blobs_path, .{});
    defer blobs.close(io);
    const encoding = try layerEncoding(resolved, options.compression);
    const compressed_temp = try createUniqueTempFile(io, allocator, blobs, ".", "layer");
    defer allocator.free(compressed_temp.name);
    var compressed_file = compressed_temp.file;
    var compressed_closed = false;
    var compressed_installed = false;
    defer {
        if (!compressed_closed) compressed_file.close(io);
        if (!compressed_installed) blobs.deleteFile(io, compressed_temp.name) catch {};
    }
    switch (encoding.compression) {
        .gzip => try compressGzip(io, bundle_dir, temporary_tar.name, compressed_file),
        .none => try copyFile(io, bundle_dir, temporary_tar.name, compressed_file),
        .same => unreachable,
    }
    try compressed_file.sync(io);
    const compressed = try hashFile(io, compressed_file);
    compressed_file.close(io);
    compressed_closed = true;

    const layer_digest_text = compressed.digest.format();
    const layer_descriptor = model.Descriptor{
        .mediaType = encoding.media_type,
        .digest = &layer_digest_text,
        .size = compressed.size,
    };
    const layer_hex = compressed.digest.blobPathComponent();
    Io.Dir.renamePreserve(blobs, compressed_temp.name, blobs, &layer_hex, io) catch |err| switch (err) {
        error.PathAlreadyExists => {
            try verifyExistingBlob(io, blobs, &layer_hex, compressed);
            try blobs.deleteFile(io, compressed_temp.name);
        },
        else => return err,
    };
    compressed_installed = true;

    var destination = try layout.Destination.init(io, allocator, target.path);
    defer destination.deinit();
    var counts: layout.Counts = .{};
    const graph = try buildGraph(
        allocator,
        resolved,
        layer_descriptor,
        diff.digest,
        options,
        &destination,
        &counts,
    );
    defer graph.deinit(allocator);
    if (options.failure_point == .before_commit) return error.InjectedFailure;
    try destination.commitExact(graph.root, graph.root_json, target.selection);
    try destination.finish();
    return .{ .root_digest = (try content.Digest.parse(graph.root.digest)).format() };
}

const LayerEncoding = struct {
    compression: Compression,
    media_type: []const u8,
};

fn layerEncoding(resolved: image.Resolved, requested: Compression) !LayerEncoding {
    const last_media_type = if (resolved.manifest.layers.len == 0)
        null
    else
        resolved.manifest.layers[resolved.manifest.layers.len - 1].mediaType;
    const docker = if (last_media_type) |media_type|
        model.classifyMediaType(media_type) == .docker_layer
    else
        model.classifyMediaType(resolved.manifestNode().descriptor.mediaType) == .docker_manifest;
    const compression: Compression = switch (requested) {
        .same => if (last_media_type) |media_type|
            if (std.mem.eql(u8, media_type, model.media_type_oci_layer) or
                std.mem.eql(u8, media_type, model.media_type_oci_nondistributable_layer) or
                std.mem.eql(u8, media_type, model.media_type_docker_layer) or
                std.mem.eql(u8, media_type, model.media_type_docker_foreign_layer))
                .none
            else if (std.mem.eql(u8, media_type, model.media_type_oci_layer_gzip) or
                std.mem.eql(u8, media_type, model.media_type_oci_nondistributable_layer_gzip) or
                std.mem.eql(u8, media_type, model.media_type_docker_layer_gzip) or
                std.mem.eql(u8, media_type, model.media_type_docker_foreign_layer_gzip))
                .gzip
            else
                return error.UnsupportedRepackCompression
        else
            .gzip,
        .gzip => .gzip,
        .none => .none,
    };
    return .{
        .compression = compression,
        .media_type = switch (compression) {
            .gzip => if (docker)
                model.media_type_docker_layer_gzip
            else
                model.media_type_oci_layer_gzip,
            .none => if (docker)
                model.media_type_docker_layer
            else
                model.media_type_oci_layer,
            .same => unreachable,
        },
    };
}

const GraphResult = struct {
    root: model.Descriptor,
    root_json: []u8,
    root_digest: []u8,

    fn deinit(self: GraphResult, allocator: std.mem.Allocator) void {
        allocator.free(self.root_json);
        allocator.free(self.root_digest);
    }
};

fn buildGraph(
    allocator: std.mem.Allocator,
    resolved: image.Resolved,
    layer_descriptor: model.Descriptor,
    diff_digest: content.Digest,
    options: Options,
    destination: *layout.Destination,
    counts: *layout.Counts,
) !GraphResult {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var config_value = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena,
        resolved.config_bytes,
        .{},
    ) catch return error.InvalidConfig;
    const config_object = object(&config_value) orelse return error.InvalidConfig;
    const rootfs = object(config_object.getPtr("rootfs") orelse return error.InvalidConfig) orelse
        return error.InvalidConfig;
    const diff_ids = rootfs.getPtr("diff_ids") orelse return error.InvalidConfig;
    if (diff_ids.* != .array) return error.InvalidConfig;
    const diff_text = diff_digest.format();
    try diff_ids.array.append(.{ .string = try arena.dupe(u8, &diff_text) });
    var history = config_object.getPtr("history");
    if (history == null) {
        try config_object.put(arena, "history", .{
            .array = std.json.Array.init(arena),
        });
        history = config_object.getPtr("history");
    }
    if (history.?.* != .array) return error.InvalidConfig;
    var history_object: std.json.ObjectMap = .empty;
    try history_object.put(arena, "created_by", .{ .string = options.created_by });
    try history.?.array.append(.{ .object = history_object });
    const config_bytes = try std.json.Stringify.valueAlloc(allocator, config_value, .{});
    defer allocator.free(config_bytes);
    const config_digest = content.digestBytes(config_bytes);
    const config_digest_text = config_digest.format();
    const config_descriptor = model.Descriptor{
        .mediaType = resolved.manifest.config.mediaType,
        .digest = &config_digest_text,
        .size = config_bytes.len,
    };
    try destination.ensureBytes(config_descriptor, config_bytes, counts);

    var manifest_value = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena,
        resolved.manifest_bytes,
        .{},
    ) catch return error.InvalidManifest;
    const manifest_object = object(&manifest_value) orelse return error.InvalidManifest;
    const manifest_config = manifest_object.getPtr("config") orelse return error.InvalidManifest;
    try updateDescriptor(arena, manifest_config, config_descriptor);
    const layers = manifest_object.getPtr("layers") orelse return error.InvalidManifest;
    if (layers.* != .array) return error.InvalidManifest;
    try layers.array.append(try descriptorValue(arena, layer_descriptor));
    const manifest_bytes = try std.json.Stringify.valueAlloc(allocator, manifest_value, .{});
    defer allocator.free(manifest_bytes);

    var current_descriptor = resolved.manifestNode().descriptor;
    current_descriptor.size = manifest_bytes.len;
    const manifest_digest = content.digestBytes(manifest_bytes);
    const manifest_digest_text = manifest_digest.format();
    current_descriptor.digest = &manifest_digest_text;
    try destination.ensureBytes(current_descriptor, manifest_bytes, counts);

    var child_json = try updatedDescriptorJson(
        allocator,
        arena,
        resolved.manifestNode().descriptor_json,
        current_descriptor,
    );
    defer allocator.free(child_json);
    var path_index = resolved.path.len - 1;
    while (path_index > 0) {
        const parent_index = path_index - 1;
        const parent_node = resolved.path[parent_index];
        var parent_value = std.json.parseFromSliceLeaky(
            std.json.Value,
            arena,
            parent_node.document,
            .{},
        ) catch return error.InvalidIndex;
        const parent_object = object(&parent_value) orelse return error.InvalidIndex;
        const manifests = parent_object.getPtr("manifests") orelse return error.InvalidIndex;
        const selected = parent_node.selected_child_index orelse return error.InvalidIndex;
        if (manifests.* != .array or selected >= manifests.array.items.len) {
            return error.InvalidIndex;
        }
        manifests.array.items[selected] = std.json.parseFromSliceLeaky(
            std.json.Value,
            arena,
            child_json,
            .{},
        ) catch return error.InvalidIndex;
        const parent_bytes = try std.json.Stringify.valueAlloc(allocator, parent_value, .{});
        defer allocator.free(parent_bytes);
        const parent_digest = content.digestBytes(parent_bytes);
        const parent_digest_text = parent_digest.format();
        current_descriptor = parent_node.descriptor;
        current_descriptor.digest = &parent_digest_text;
        current_descriptor.size = parent_bytes.len;
        try destination.ensureBytes(current_descriptor, parent_bytes, counts);
        const replacement_json = try updatedDescriptorJson(
            allocator,
            arena,
            parent_node.descriptor_json,
            current_descriptor,
        );
        allocator.free(child_json);
        child_json = replacement_json;
        path_index = parent_index;
    }
    const root_digest = try allocator.dupe(u8, current_descriptor.digest);
    current_descriptor.digest = root_digest;
    return .{
        .root = current_descriptor,
        .root_json = try allocator.dupe(u8, child_json),
        .root_digest = root_digest,
    };
}

fn writeDiff(
    allocator: std.mem.Allocator,
    io: Io,
    rootfs: Io.Dir,
    base: []const snapshot.Entry,
    current: []const snapshot.Entry,
    archive: *tar.Writer,
) !void {
    var base_index: usize = 0;
    var current_index: usize = 0;
    var removed_directory: ?[]const u8 = null;
    while (base_index < base.len or current_index < current.len) {
        if (base_index == base.len) {
            try writeCurrent(allocator, io, rootfs, current, current_index, archive);
            current_index += 1;
            continue;
        }
        if (current_index == current.len) {
            if (!isDescendant(base[base_index].path, removed_directory)) {
                try writeWhiteout(base[base_index], archive);
                removed_directory = if (base[base_index].kind == .directory)
                    base[base_index].path
                else
                    null;
            }
            base_index += 1;
            continue;
        }
        const order = std.mem.order(u8, base[base_index].path, current[current_index].path);
        switch (order) {
            .lt => {
                if (!isDescendant(base[base_index].path, removed_directory)) {
                    try writeWhiteout(base[base_index], archive);
                    removed_directory = if (base[base_index].kind == .directory)
                        base[base_index].path
                    else
                        null;
                }
                base_index += 1;
            },
            .gt => {
                removed_directory = null;
                try writeCurrent(allocator, io, rootfs, current, current_index, archive);
                current_index += 1;
            },
            .eq => {
                removed_directory = null;
                if (!snapshot.Entry.same(base[base_index], current[current_index])) {
                    try writeCurrent(allocator, io, rootfs, current, current_index, archive);
                }
                base_index += 1;
                current_index += 1;
            },
        }
    }
}

fn writeWhiteout(entry: snapshot.Entry, archive: *tar.Writer) !void {
    const parent = std.fs.path.dirname(entry.path);
    const basename = std.fs.path.basename(entry.path);
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = if (parent) |value|
        try std.fmt.bufPrint(&buffer, "{s}/.wh.{s}", .{ value, basename })
    else
        try std.fmt.bufPrint(&buffer, ".wh.{s}", .{basename});
    try archive.writeEntry(.{
        .path = path,
        .kind = .file,
        .mode = 0,
    });
}

fn writeCurrent(
    allocator: std.mem.Allocator,
    io: Io,
    rootfs: Io.Dir,
    entries: []const snapshot.Entry,
    index: usize,
    archive: *tar.Writer,
) !void {
    const entry = entries[index];
    const archive_path = if (entry.path.len == 0) "." else entry.path;
    var xattr_arena = std.heap.ArenaAllocator.init(allocator);
    defer xattr_arena.deinit();
    const xattrs = try decodeXattrs(xattr_arena.allocator(), entry.xattrs);
    const mtime = tar.Timestamp{
        .seconds = entry.mtime.seconds,
        .nanoseconds = entry.mtime.nanoseconds,
    };
    if (entry.kind != .directory) {
        if (hardlinkTarget(entries, index)) |target| {
            try archive.writeEntry(.{
                .path = archive_path,
                .kind = .hardlink,
                .mode = entry.mode,
                .uid = entry.uid,
                .gid = entry.gid,
                .mtime = mtime,
                .link_name = target,
                .xattrs = xattrs,
            });
            return;
        }
    }
    switch (entry.kind) {
        .directory => try archive.writeEntry(.{
            .path = archive_path,
            .kind = .directory,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .mtime = mtime,
            .xattrs = xattrs,
        }),
        .symlink => try archive.writeEntry(.{
            .path = archive_path,
            .kind = .symlink,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .mtime = mtime,
            .link_name = entry.link_name,
            .xattrs = xattrs,
        }),
        .fifo => try archive.writeEntry(.{
            .path = archive_path,
            .kind = .fifo,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .mtime = mtime,
            .xattrs = xattrs,
        }),
        .character_device, .block_device => try archive.writeEntry(.{
            .path = archive_path,
            .kind = if (entry.kind == .character_device)
                .character_device
            else
                .block_device,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .mtime = mtime,
            .device_major = entry.device_major,
            .device_minor = entry.device_minor,
            .xattrs = xattrs,
        }),
        .file => {
            var file = try rootfs.openFile(io, entry.path, .{
                .allow_directory = false,
                .follow_symlinks = false,
                .resolve_beneath = true,
            });
            defer file.close(io);
            try verifyFileStat(entry, try file.stat(io));
            try archive.beginEntry(.{
                .path = archive_path,
                .kind = .file,
                .mode = entry.mode,
                .uid = entry.uid,
                .gid = entry.gid,
                .mtime = mtime,
                .size = entry.size,
                .xattrs = xattrs,
            });
            var buffer: [64 * 1024]u8 = undefined;
            var hasher = Sha256.init(.{});
            var offset: u64 = 0;
            while (offset < entry.size) {
                const count = try file.readPositionalAll(
                    io,
                    buffer[0..@intCast(@min(buffer.len, entry.size - offset))],
                    offset,
                );
                if (count == 0) return error.FileChangedDuringRepack;
                try archive.writeAll(buffer[0..count]);
                hasher.update(buffer[0..count]);
                offset += count;
            }
            var extra: [1]u8 = undefined;
            if (try file.readPositionalAll(io, &extra, entry.size) != 0) {
                return error.FileChangedDuringRepack;
            }
            var digest: [Sha256.digest_length]u8 = undefined;
            hasher.final(&digest);
            const digest_hex = std.fmt.bytesToHex(digest, .lower);
            if (!std.mem.eql(u8, &digest_hex, entry.digest orelse
                return error.FileChangedDuringRepack))
            {
                return error.FileChangedDuringRepack;
            }
            try verifyFileStat(entry, try file.stat(io));
            try archive.endEntry();
        },
    }
}

fn verifyFileStat(entry: snapshot.Entry, stat: Io.File.Stat) !void {
    const expected_mtime =
        @as(i96, entry.mtime.seconds) * std.time.ns_per_s +
        entry.mtime.nanoseconds;
    if (stat.kind != .file or
        stat.size != entry.size or
        @as(u64, @intCast(stat.inode)) != entry.inode or
        @as(u64, @intCast(stat.nlink)) != entry.nlink or
        (@intFromEnum(stat.permissions) & 0o7777) != entry.mode or
        stat.mtime.nanoseconds != expected_mtime)
    {
        return error.FileChangedDuringRepack;
    }
}

fn decodeXattrs(
    allocator: std.mem.Allocator,
    encoded: []const snapshot.Xattr,
) ![]const tar.Xattr {
    const result = try allocator.alloc(tar.Xattr, encoded.len);
    for (encoded, result) |source, *target| {
        const size = std.base64.standard.Decoder.calcSizeForSlice(
            source.value_base64,
        ) catch return error.InvalidBundleMetadata;
        const value = try allocator.alloc(u8, size);
        std.base64.standard.Decoder.decode(
            value,
            source.value_base64,
        ) catch return error.InvalidBundleMetadata;
        target.* = .{ .name = source.name, .value = value };
    }
    return result;
}

fn hardlinkTarget(entries: []const snapshot.Entry, index: usize) ?[]const u8 {
    const entry = entries[index];
    if (entry.nlink < 2 or entry.kind == .directory) return null;
    for (entries[0..index]) |candidate| {
        if (candidate.kind != .directory and
            candidate.filesystem_device == entry.filesystem_device and
            candidate.inode == entry.inode) return candidate.path;
    }
    return null;
}

fn validateSnapshot(entries: []const snapshot.Entry) !void {
    for (entries, 0..) |entry, index| {
        if (entry.path.len == 0) {
            if (index != 0 or entry.kind != .directory) return error.InvalidBundleMetadata;
            continue;
        }
        if (std.fs.path.isAbsolute(entry.path)) {
            return error.InvalidBundleMetadata;
        }
        var components = std.mem.splitScalar(u8, entry.path, '/');
        while (components.next()) |component| {
            if (component.len == 0 or std.mem.eql(u8, component, ".") or
                std.mem.eql(u8, component, "..")) return error.InvalidBundleMetadata;
            if (std.mem.startsWith(u8, component, ".wh.")) {
                return error.ReservedWhiteoutPath;
            }
        }
        if (index > 0 and std.mem.order(u8, entries[index - 1].path, entry.path) != .lt) {
            return error.InvalidBundleMetadata;
        }
    }
}

fn overlayRootlessOwnership(
    base: []const snapshot.Entry,
    current: []snapshot.Entry,
    host_uid: u32,
    host_gid: u32,
) !void {
    var base_index: usize = 0;
    var current_index: usize = 0;
    while (base_index < base.len and current_index < current.len) {
        switch (std.mem.order(u8, base[base_index].path, current[current_index].path)) {
            .lt => base_index += 1,
            .gt => current_index += 1,
            .eq => {
                current[current_index].uid = base[base_index].uid;
                current[current_index].gid = base[base_index].gid;
                base_index += 1;
                current_index += 1;
            },
        }
    }
    for (current) |*entry| {
        if (findSnapshotEntry(base, entry.path) != null) continue;
        if (entry.uid != host_uid or entry.gid != host_gid) {
            return error.UnmappedRootlessOwnership;
        }
        entry.uid = 0;
        entry.gid = 0;
    }
    for (current, 0..) |entry, index| {
        if (entry.kind == .directory or entry.nlink < 2) continue;
        var group_uid = entry.uid;
        var group_gid = entry.gid;
        for (current) |candidate| {
            if (candidate.kind == .directory or
                candidate.filesystem_device != entry.filesystem_device or
                candidate.inode != entry.inode) continue;
            if (findSnapshotEntry(base, candidate.path)) |base_entry| {
                group_uid = base_entry.uid;
                group_gid = base_entry.gid;
                break;
            }
        }
        for (current[index..]) |*candidate| {
            if (candidate.kind == .directory or
                candidate.filesystem_device != entry.filesystem_device or
                candidate.inode != entry.inode) continue;
            candidate.uid = group_uid;
            candidate.gid = group_gid;
        }
    }
}

fn findSnapshotEntry(
    entries: []const snapshot.Entry,
    path: []const u8,
) ?snapshot.Entry {
    var left: usize = 0;
    var right = entries.len;
    while (left < right) {
        const middle = left + (right - left) / 2;
        switch (std.mem.order(u8, entries[middle].path, path)) {
            .lt => left = middle + 1,
            .gt => right = middle,
            .eq => return entries[middle],
        }
    }
    return null;
}

fn isDescendant(path: []const u8, parent: ?[]const u8) bool {
    const value = parent orelse return false;
    return path.len > value.len and std.mem.startsWith(u8, path, value) and
        path[value.len] == '/';
}

fn compressGzip(io: Io, dir: Io.Dir, input_name: []const u8, output: Io.File) !void {
    var input = try dir.openFile(io, input_name, .{});
    defer input.close(io);
    const stat = try input.stat(io);
    var output_buffer: [64 * 1024]u8 = undefined;
    var output_writer = output.writer(io, &output_buffer);
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(
        &output_writer.interface,
        &history,
        .gzip,
        .default,
    );
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < stat.size) {
        const count = try input.readPositionalAll(
            io,
            buffer[0..@intCast(@min(buffer.len, stat.size - offset))],
            offset,
        );
        if (count == 0) return error.TruncatedLayer;
        try compressor.writer.writeAll(buffer[0..count]);
        offset += count;
    }

    try compressor.finish();
    try output_writer.interface.flush();
}

fn copyFile(io: Io, dir: Io.Dir, input_name: []const u8, output: Io.File) !void {
    var input = try dir.openFile(io, input_name, .{});
    defer input.close(io);
    const stat = try input.stat(io);
    var output_buffer: [64 * 1024]u8 = undefined;
    var output_writer = output.writer(io, &output_buffer);
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < stat.size) {
        const count = try input.readPositionalAll(
            io,
            buffer[0..@intCast(@min(buffer.len, stat.size - offset))],
            offset,
        );
        if (count == 0) return error.TruncatedLayer;
        try output_writer.interface.writeAll(buffer[0..count]);
        offset += count;
    }
    try output_writer.interface.flush();
}

fn hashFile(io: Io, file: Io.File) !HashedFile {
    const stat = try file.stat(io);
    var hasher = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < stat.size) {
        const count = try file.readPositionalAll(
            io,
            buffer[0..@intCast(@min(buffer.len, stat.size - offset))],
            offset,
        );
        if (count == 0) return error.TruncatedBlob;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return .{ .digest = .{ .bytes = digest }, .size = stat.size };
}

fn verifyExistingBlob(
    io: Io,
    dir: Io.Dir,
    path: []const u8,
    expected: HashedFile,
) !void {
    var file = try dir.openFile(io, path, .{});
    defer file.close(io);
    const actual = try hashFile(io, file);
    if (actual.size != expected.size or
        !std.mem.eql(u8, &actual.digest.bytes, &expected.digest.bytes))
    {
        return error.CorruptBlob;
    }
}

const TemporaryFile = struct {
    name: []u8,
    file: Io.File,
};

fn createUniqueTempFile(
    io: Io,
    allocator: std.mem.Allocator,
    dir: Io.Dir,
    prefix: []const u8,
    kind: []const u8,
) !TemporaryFile {
    var random: [16]u8 = undefined;
    for (0..64) |_| {
        try io.randomSecure(&random);
        const suffix = std.fmt.bytesToHex(random, .lower);
        const name = try std.fmt.allocPrint(
            allocator,
            "{s}/.vmiz-repack-{s}-{s}.tmp",
            .{ prefix, kind, suffix },
        );
        const file = dir.createFile(io, name, .{ .exclusive = true, .read = true }) catch |err| switch (err) {
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

fn object(value: *std.json.Value) ?*std.json.ObjectMap {
    return switch (value.*) {
        .object => |*result| result,
        else => null,
    };
}

fn descriptorValue(
    allocator: std.mem.Allocator,
    descriptor: model.Descriptor,
) !std.json.Value {
    const encoded = try std.json.Stringify.valueAlloc(allocator, descriptor, .{});
    return std.json.parseFromSliceLeaky(std.json.Value, allocator, encoded, .{});
}

fn updateDescriptor(
    allocator: std.mem.Allocator,
    value: *std.json.Value,
    descriptor: model.Descriptor,
) !void {
    const descriptor_object = object(value) orelse return error.InvalidDescriptor;
    _ = descriptor_object.orderedRemove("data");
    try descriptor_object.put(allocator, "digest", .{ .string = descriptor.digest });
    try descriptor_object.put(allocator, "size", .{ .integer = @intCast(descriptor.size) });
    if (descriptor.mediaType) |media_type| {
        try descriptor_object.put(allocator, "mediaType", .{ .string = media_type });
    }
}

fn updatedDescriptorJson(
    allocator: std.mem.Allocator,
    parse_allocator: std.mem.Allocator,
    original: []const u8,
    descriptor: model.Descriptor,
) ![]u8 {
    var value = std.json.parseFromSliceLeaky(std.json.Value, parse_allocator, original, .{}) catch
        return error.InvalidDescriptor;
    try updateDescriptor(parse_allocator, &value, descriptor);
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}
