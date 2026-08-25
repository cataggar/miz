//! Resolves one digest-pinned image manifest and its exact descriptor path.
const std = @import("std");
const content = @import("content.zig");
const layout = @import("layout.zig");
const model = @import("model.zig");
const reference = @import("reference.zig");
const transport = @import("transport.zig");

pub const Options = struct {
    platform: model.Platform,
    max_depth: usize = 32,
};

pub const Error = error{
    InvalidIndex,
    InvalidManifest,
    InvalidConfig,
    InvalidRootFs,
    LayerCountMismatch,
    PlatformNotFound,
    PlatformConfigMismatch,
    AmbiguousPlatform,
    UnsupportedSelectedObject,
    CycleDetected,
    MaximumDepthExceeded,
    DescriptorMismatch,
} || std.mem.Allocator.Error;

pub const PathNode = struct {
    descriptor: model.Descriptor,
    descriptor_json: []const u8,
    document: []const u8,
    selected_child_index: ?usize = null,
};

pub const Resolved = struct {
    arena: std.heap.ArenaAllocator,
    path: []const PathNode,
    manifest: model.Manifest,
    manifest_bytes: []const u8,
    config: model.ImageConfiguration,
    config_bytes: []const u8,
    platform: model.Platform,

    pub fn deinit(self: *Resolved) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn manifestNode(self: Resolved) PathNode {
        return self.path[self.path.len - 1];
    }
};

pub fn resolveLayout(
    allocator: std.mem.Allocator,
    source: *layout.Source,
    image_ref: reference.LayoutReference,
    options: Options,
) !Resolved {
    var root = try source.resolve(image_ref);
    defer root.deinit();
    return resolve(
        allocator,
        source.asTransport(),
        root.descriptor,
        root.descriptor_json,
        root.bytes,
        options,
    );
}

pub fn resolve(
    allocator: std.mem.Allocator,
    source: transport.Source,
    root_descriptor: model.Descriptor,
    root_descriptor_json: []const u8,
    root_bytes: []const u8,
    options: Options,
) (Error || anyerror)!Resolved {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    var context = Context{
        .source = source,
        .source_allocator = allocator,
        .allocator = owned,
        .options = options,
        .path = std.array_list.Managed(PathNode).init(owned),
        .active = std.StringHashMap(void).init(owned),
    };
    defer context.active.deinit();

    const root_json = try owned.dupe(u8, root_descriptor_json);
    const root_document = try owned.dupe(u8, root_bytes);
    const root = std.json.parseFromSliceLeaky(
        model.Descriptor,
        owned,
        root_json,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidIndex;
    if (!sameDescriptor(root, root_descriptor)) return error.DescriptorMismatch;

    try context.walk(root, root_json, root_document, 0, true);
    if (context.path.items.len == 0) return error.PlatformNotFound;
    const manifest_node = context.path.items[context.path.items.len - 1];
    const manifest = std.json.parseFromSliceLeaky(
        model.Manifest,
        owned,
        manifest_node.document,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidManifest;
    model.validateManifest(manifest) catch return error.InvalidManifest;

    const config_bytes_read = try source.readMetadata(manifest.config);
    defer allocator.free(config_bytes_read);
    const config_bytes = try owned.dupe(u8, config_bytes_read);
    const config = std.json.parseFromSliceLeaky(
        model.ImageConfiguration,
        owned,
        config_bytes,
        .{ .ignore_unknown_fields = true },
    ) catch return error.InvalidConfig;
    try validateConfig(config, manifest, options.platform);

    return .{
        .arena = arena,
        .path = try context.path.toOwnedSlice(),
        .manifest = manifest,
        .manifest_bytes = manifest_node.document,
        .config = config,
        .config_bytes = config_bytes,
        .platform = .{
            .os = config.os.?,
            .architecture = config.architecture.?,
            .variant = config.variant,
            .@"os.version" = config.@"os.version",
            .@"os.features" = config.@"os.features",
        },
    };
}

const Context = struct {
    source: transport.Source,
    source_allocator: std.mem.Allocator,
    allocator: std.mem.Allocator,
    options: Options,
    path: std.array_list.Managed(PathNode),
    active: std.StringHashMap(void),

    fn walk(
        self: *Context,
        descriptor: model.Descriptor,
        descriptor_json: []const u8,
        document: []const u8,
        depth: usize,
        permit_unannotated: bool,
    ) (Error || anyerror)!void {
        if (depth > self.options.max_depth) return error.MaximumDepthExceeded;
        _ = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;

        switch (model.classifyMediaType(descriptor.mediaType)) {
            .oci_index, .docker_manifest_list => {
                if (self.active.contains(descriptor.digest)) return error.CycleDetected;
                try self.active.put(descriptor.digest, {});
                defer _ = self.active.remove(descriptor.digest);

                const path_index = self.path.items.len;
                try self.path.append(.{
                    .descriptor = descriptor,
                    .descriptor_json = descriptor_json,
                    .document = document,
                });
                errdefer self.path.items.len = path_index;

                const index = std.json.parseFromSliceLeaky(
                    model.Index,
                    self.allocator,
                    document,
                    .{ .ignore_unknown_fields = true },
                ) catch return error.InvalidIndex;
                model.validateIndex(index) catch return error.InvalidIndex;

                for (index.manifests, 0..) |child, child_index| {
                    const candidate = child.platform orelse continue;
                    if (!model.platformMatches(candidate, self.options.platform)) continue;
                    const checkpoint = self.path.items.len;
                    const child_json = try descriptorJsonAt(self.allocator, document, child_index);
                    const child_document = try self.readDocument(child);
                    self.path.items[path_index].selected_child_index = child_index;
                    self.walk(
                        child,
                        child_json,
                        child_document,
                        depth + 1,
                        true,
                    ) catch |err| switch (err) {
                        error.PlatformNotFound => {
                            self.path.items.len = checkpoint;
                            self.path.items[path_index].selected_child_index = null;
                            continue;
                        },
                        else => return err,
                    };
                    return;
                }

                if (permit_unannotated and index.manifests.len == 1) {
                    const child = index.manifests[0];
                    if (child.platform == null and
                        model.classifyMediaType(child.mediaType).isManifest())
                    {
                        const child_json = try descriptorJsonAt(self.allocator, document, 0);
                        const child_document = try self.readDocument(child);
                        self.path.items[path_index].selected_child_index = 0;
                        try self.walk(child, child_json, child_document, depth + 1, true);
                        return;
                    }
                }

                var found = false;
                var selected_len: usize = 0;
                var selected_child: usize = 0;
                for (index.manifests, 0..) |child, child_index| {
                    if (child.platform != null or
                        !model.classifyMediaType(child.mediaType).isIndex()) continue;
                    const checkpoint = self.path.items.len;
                    const child_json = try descriptorJsonAt(self.allocator, document, child_index);
                    const child_document = try self.readDocument(child);
                    self.path.items[path_index].selected_child_index = child_index;
                    self.walk(
                        child,
                        child_json,
                        child_document,
                        depth + 1,
                        false,
                    ) catch |err| switch (err) {
                        error.PlatformNotFound => {
                            self.path.items.len = checkpoint;
                            self.path.items[path_index].selected_child_index = null;
                            continue;
                        },
                        else => return err,
                    };
                    if (found) return error.AmbiguousPlatform;
                    found = true;
                    selected_len = self.path.items.len;
                    selected_child = child_index;
                    self.path.items.len = checkpoint;
                }
                if (!found) return error.PlatformNotFound;

                const child = index.manifests[selected_child];
                const child_json = try descriptorJsonAt(self.allocator, document, selected_child);
                const child_document = try self.readDocument(child);
                self.path.items[path_index].selected_child_index = selected_child;
                try self.walk(child, child_json, child_document, depth + 1, false);
                std.debug.assert(self.path.items.len == selected_len);
            },
            .oci_manifest, .docker_manifest => {
                if (descriptor.platform) |candidate| {
                    if (!model.platformMatches(candidate, self.options.platform)) {
                        return error.PlatformNotFound;
                    }
                } else if (!permit_unannotated) {
                    return error.PlatformNotFound;
                }
                try self.path.append(.{
                    .descriptor = descriptor,
                    .descriptor_json = descriptor_json,
                    .document = document,
                });
            },
            else => {
                if (descriptor.platform) |candidate| {
                    if (model.platformMatches(candidate, self.options.platform)) {
                        return error.UnsupportedSelectedObject;
                    }
                }
                return error.PlatformNotFound;
            },
        }
    }

    fn readDocument(self: *Context, descriptor: model.Descriptor) ![]const u8 {
        const bytes = try self.source.readMetadata(descriptor);
        defer self.source_allocator.free(bytes);
        return self.allocator.dupe(u8, bytes);
    }
};

fn validateConfig(
    config: model.ImageConfiguration,
    manifest: model.Manifest,
    requested: model.Platform,
) Error!void {
    if (!std.mem.eql(u8, config.rootfs.type, "layers")) return error.InvalidRootFs;
    if (config.rootfs.diff_ids.len != manifest.layers.len) return error.LayerCountMismatch;
    for (config.rootfs.diff_ids) |diff_id| {
        _ = content.Digest.parse(diff_id) catch return error.InvalidRootFs;
    }

    if (config.os == null or config.architecture == null) {
        return error.PlatformConfigMismatch;
    }
    if (!std.mem.eql(u8, config.os.?, requested.os) or
        !std.mem.eql(u8, config.architecture.?, requested.architecture))
    {
        return error.PlatformConfigMismatch;
    }
    if (requested.variant) |variant| {
        if (config.variant == null or !std.mem.eql(u8, config.variant.?, variant)) {
            return error.PlatformConfigMismatch;
        }
    }
}

fn descriptorJsonAt(
    allocator: std.mem.Allocator,
    index_bytes: []const u8,
    occurrence: usize,
) ![]const u8 {
    const value = std.json.parseFromSliceLeaky(std.json.Value, allocator, index_bytes, .{}) catch
        return error.InvalidIndex;
    const object = switch (value) {
        .object => |object| object,
        else => return error.InvalidIndex,
    };
    const manifests = object.get("manifests") orelse return error.InvalidIndex;
    if (manifests != .array or occurrence >= manifests.array.items.len) {
        return error.InvalidIndex;
    }
    return std.json.Stringify.valueAlloc(
        allocator,
        manifests.array.items[occurrence],
        .{},
    );
}

fn sameDescriptor(left: model.Descriptor, right: model.Descriptor) bool {
    return std.mem.eql(u8, left.digest, right.digest) and
        left.size == right.size and
        optionalStringsEqual(left.mediaType, right.mediaType);
}

fn optionalStringsEqual(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, left.?, right.?);
}

const TestBlob = struct {
    descriptor: model.Descriptor,
    bytes: []const u8,
};

const TestSource = struct {
    allocator: std.mem.Allocator,
    blobs: []const TestBlob,

    fn transportSource(self: *TestSource) transport.Source {
        return .{
            .context = self,
            .read_metadata = readMetadata,
            .read_manifest_metadata = readMetadata,
            .copy_verified_to = copyVerifiedTo,
        };
    }

    fn readMetadata(context: *anyopaque, descriptor: model.Descriptor) anyerror![]u8 {
        const self: *TestSource = @ptrCast(@alignCast(context));
        for (self.blobs) |blob| {
            if (!std.mem.eql(u8, blob.descriptor.digest, descriptor.digest)) continue;
            if (!sameDescriptor(blob.descriptor, descriptor)) return error.DescriptorMismatch;
            const digest = try content.Digest.parse(descriptor.digest);
            try content.verifyBytes(digest, descriptor.size, blob.bytes);
            return self.allocator.dupe(u8, blob.bytes);
        }
        return error.MissingBlob;
    }

    fn copyVerifiedTo(
        _: *anyopaque,
        _: model.Descriptor,
        _: std.Io.File,
    ) anyerror!void {
        return error.UnsupportedOperation;
    }
};

test "resolver retains the selected descriptor path and full image config" {
    const allocator = std.testing.allocator;
    const diff_id = content.digestBytes("uncompressed layer").format();
    const layer_digest = content.digestBytes("compressed layer").format();
    const config_bytes = try std.fmt.allocPrint(
        allocator,
        "{{\"created\":\"2026-07-24T00:00:00Z\",\"architecture\":\"amd64\",\"os\":\"linux\",\"config\":{{\"User\":\"1000:1000\",\"Env\":[\"PATH=/bin\"],\"Entrypoint\":[\"/bin/app\"],\"Cmd\":[\"serve\"],\"ExposedPorts\":{{\"8080/tcp\":{{}}}},\"Labels\":{{\"org.example\":\"kept\"}}}},\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{s}\"]}},\"history\":[]}}",
        .{&diff_id},
    );
    defer allocator.free(config_bytes);
    const config_digest = content.digestBytes(config_bytes).format();
    const config_descriptor = model.Descriptor{
        .mediaType = model.media_type_oci_config,
        .digest = &config_digest,
        .size = config_bytes.len,
    };
    const manifest_bytes = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{
            model.media_type_oci_manifest,
            model.media_type_oci_config,
            &config_digest,
            config_bytes.len,
            model.media_type_oci_layer_gzip,
            &layer_digest,
            "compressed layer".len,
        },
    );
    defer allocator.free(manifest_bytes);
    const manifest_digest = content.digestBytes(manifest_bytes).format();
    const manifest_descriptor = model.Descriptor{
        .mediaType = model.media_type_oci_manifest,
        .digest = &manifest_digest,
        .size = manifest_bytes.len,
        .platform = .{ .os = "linux", .architecture = "amd64" },
    };
    const index_bytes = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}},\"x-path-extension\":\"kept\"}}]}}",
        .{
            model.media_type_oci_index,
            model.media_type_oci_manifest,
            &manifest_digest,
            manifest_bytes.len,
        },
    );
    defer allocator.free(index_bytes);
    const index_digest = content.digestBytes(index_bytes).format();
    const index_descriptor = model.Descriptor{
        .mediaType = model.media_type_oci_index,
        .digest = &index_digest,
        .size = index_bytes.len,
    };
    const index_descriptor_json = try std.json.Stringify.valueAlloc(
        allocator,
        index_descriptor,
        .{},
    );
    defer allocator.free(index_descriptor_json);

    const blobs = [_]TestBlob{
        .{ .descriptor = manifest_descriptor, .bytes = manifest_bytes },
        .{ .descriptor = config_descriptor, .bytes = config_bytes },
    };
    var source = TestSource{ .allocator = allocator, .blobs = &blobs };
    var resolved = try resolve(
        allocator,
        source.transportSource(),
        index_descriptor,
        index_descriptor_json,
        index_bytes,
        .{ .platform = .{ .os = "linux", .architecture = "amd64" } },
    );
    defer resolved.deinit();

    try std.testing.expectEqual(@as(usize, 2), resolved.path.len);
    try std.testing.expectEqual(@as(?usize, 0), resolved.path[0].selected_child_index);
    try std.testing.expectEqualStrings(&manifest_digest, resolved.manifestNode().descriptor.digest);
    try std.testing.expect(std.mem.indexOf(
        u8,
        resolved.manifestNode().descriptor_json,
        "\"x-path-extension\":\"kept\"",
    ) != null);
    try std.testing.expectEqualStrings("1000:1000", resolved.config.config.?.User.?);
    try std.testing.expectEqualStrings("/bin/app", resolved.config.config.?.Entrypoint.?[0]);
    try std.testing.expectEqualStrings("serve", resolved.config.config.?.Cmd.?[0]);
    try std.testing.expectEqualStrings(&diff_id, resolved.config.rootfs.diff_ids[0]);
}
