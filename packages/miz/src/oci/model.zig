const std = @import("std");

pub const media_type_oci_manifest = "application/vnd.oci.image.manifest.v1+json";
pub const media_type_oci_index = "application/vnd.oci.image.index.v1+json";
pub const media_type_oci_config = "application/vnd.oci.image.config.v1+json";
pub const media_type_oci_layer = "application/vnd.oci.image.layer.v1.tar";
pub const media_type_oci_layer_gzip = "application/vnd.oci.image.layer.v1.tar+gzip";
pub const media_type_oci_layer_zstd = "application/vnd.oci.image.layer.v1.tar+zstd";
pub const media_type_oci_nondistributable_layer = "application/vnd.oci.image.layer.nondistributable.v1.tar";
pub const media_type_oci_nondistributable_layer_gzip = "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";
pub const media_type_oci_nondistributable_layer_zstd = "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";
pub const media_type_docker_manifest = "application/vnd.docker.distribution.manifest.v2+json";
pub const media_type_docker_manifest_list = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const media_type_docker_config = "application/vnd.docker.container.image.v1+json";
pub const media_type_docker_layer = "application/vnd.docker.image.rootfs.diff.tar";
pub const media_type_docker_layer_gzip = "application/vnd.docker.image.rootfs.diff.tar.gzip";
pub const media_type_docker_layer_zstd = "application/vnd.docker.image.rootfs.diff.tar.zstd";
pub const media_type_docker_foreign_layer = "application/vnd.docker.image.rootfs.foreign.diff.tar";
pub const media_type_docker_foreign_layer_gzip = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";

pub const MediaTypeClass = enum {
    unknown,
    oci_manifest,
    oci_index,
    oci_config,
    oci_layer,
    docker_manifest,
    docker_manifest_list,
    docker_config,
    docker_layer,

    pub fn isManifest(self: MediaTypeClass) bool {
        return self == .oci_manifest or self == .docker_manifest;
    }

    pub fn isIndex(self: MediaTypeClass) bool {
        return self == .oci_index or self == .docker_manifest_list;
    }
};

pub const ValidationError = error{
    InvalidSchemaVersion,
    InvalidMediaType,
    UnsupportedDocumentMediaType,
    UnsupportedDescriptorMediaType,
    UnsupportedConfigMediaType,
    UnsupportedLayerMediaType,
};

pub const max_media_type_len = 255;

pub fn validateMediaType(media_type: []const u8) ValidationError!void {
    if (media_type.len == 0 or media_type.len > max_media_type_len) return error.InvalidMediaType;
    const slash = std.mem.indexOfScalar(u8, media_type, '/') orelse return error.InvalidMediaType;
    if (slash == 0 or slash + 1 == media_type.len) return error.InvalidMediaType;
    if (std.mem.indexOfScalarPos(u8, media_type, slash + 1, '/') != null) return error.InvalidMediaType;
    for (media_type[0..slash]) |byte| {
        if (!isTokenByte(byte)) return error.InvalidMediaType;
    }
    for (media_type[slash + 1 ..]) |byte| {
        if (!isTokenByte(byte)) return error.InvalidMediaType;
    }
}

fn isTokenByte(byte: u8) bool {
    if (std.ascii.isAlphanumeric(byte)) return true;
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn validateDescriptorMediaType(descriptor: Descriptor) ValidationError!void {
    if (descriptor.mediaType) |media_type| try validateMediaType(media_type);
}

pub fn classifyMediaType(media_type: ?[]const u8) MediaTypeClass {
    const value = media_type orelse return .unknown;
    if (std.mem.eql(u8, value, media_type_oci_manifest)) return .oci_manifest;
    if (std.mem.eql(u8, value, media_type_oci_index)) return .oci_index;
    if (std.mem.eql(u8, value, media_type_oci_config)) return .oci_config;
    if (std.mem.eql(u8, value, media_type_oci_layer) or
        std.mem.eql(u8, value, media_type_oci_layer_gzip) or
        std.mem.eql(u8, value, media_type_oci_layer_zstd) or
        std.mem.eql(u8, value, media_type_oci_nondistributable_layer) or
        std.mem.eql(u8, value, media_type_oci_nondistributable_layer_gzip) or
        std.mem.eql(u8, value, media_type_oci_nondistributable_layer_zstd)) return .oci_layer;
    if (std.mem.eql(u8, value, media_type_docker_manifest)) return .docker_manifest;
    if (std.mem.eql(u8, value, media_type_docker_manifest_list)) return .docker_manifest_list;
    if (std.mem.eql(u8, value, media_type_docker_config)) return .docker_config;
    if (std.mem.eql(u8, value, media_type_docker_layer) or
        std.mem.eql(u8, value, media_type_docker_layer_gzip) or
        std.mem.eql(u8, value, media_type_docker_layer_zstd) or
        std.mem.eql(u8, value, media_type_docker_foreign_layer) or
        std.mem.eql(u8, value, media_type_docker_foreign_layer_gzip)) return .docker_layer;
    return .unknown;
}

/// JSON object values are borrowed from `std.json.parseFromSlice` input.
pub const Annotations = std.json.Value;

pub const Platform = struct {
    architecture: []const u8,
    os: []const u8,
    @"os.version": ?[]const u8 = null,
    @"os.features": ?[]const []const u8 = null,
    variant: ?[]const u8 = null,
    features: ?[]const []const u8 = null,
};

pub const Descriptor = struct {
    mediaType: ?[]const u8 = null,
    digest: []const u8,
    size: u64,
    urls: ?[]const []const u8 = null,
    annotations: ?Annotations = null,
    data: ?[]const u8 = null,
    artifactType: ?[]const u8 = null,
    platform: ?Platform = null,
};

pub const Index = struct {
    schemaVersion: u32,
    mediaType: ?[]const u8 = null,
    manifests: []const Descriptor,
    artifactType: ?[]const u8 = null,
    subject: ?Descriptor = null,
    annotations: ?Annotations = null,
};

pub const Manifest = struct {
    schemaVersion: u32,
    mediaType: ?[]const u8 = null,
    config: Descriptor,
    layers: []const Descriptor,
    artifactType: ?[]const u8 = null,
    subject: ?Descriptor = null,
    annotations: ?Annotations = null,
};

pub const ConfigPlatform = struct {
    architecture: ?[]const u8 = null,
    os: ?[]const u8 = null,
    variant: ?[]const u8 = null,
    @"os.version": ?[]const u8 = null,
    @"os.features": ?[]const []const u8 = null,
};
pub const ImageConfigPlatform = ConfigPlatform;

pub const ImageRootFs = struct {
    type: []const u8,
    diff_ids: []const []const u8,
};

pub const ImageHistory = struct {
    created: ?[]const u8 = null,
    author: ?[]const u8 = null,
    created_by: ?[]const u8 = null,
    comment: ?[]const u8 = null,
    empty_layer: bool = false,
};

pub const ImageExecutionConfig = struct {
    User: ?[]const u8 = null,
    ExposedPorts: ?std.json.Value = null,
    Env: ?[]const []const u8 = null,
    Entrypoint: ?[]const []const u8 = null,
    Cmd: ?[]const []const u8 = null,
    Volumes: ?std.json.Value = null,
    WorkingDir: ?[]const u8 = null,
    Labels: ?std.json.Value = null,
    StopSignal: ?[]const u8 = null,
};

/// OCI image configuration fields needed by bundle conversion and mutation.
/// Callers that rewrite an image must retain the separately parsed raw JSON
/// value so extension fields not represented here survive the operation.
pub const ImageConfiguration = struct {
    created: ?[]const u8 = null,
    author: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    os: ?[]const u8 = null,
    variant: ?[]const u8 = null,
    @"os.version": ?[]const u8 = null,
    @"os.features": ?[]const []const u8 = null,
    config: ?ImageExecutionConfig = null,
    rootfs: ImageRootFs,
    history: ?[]const ImageHistory = null,
};

pub fn validateIndex(index: Index) ValidationError!void {
    if (index.schemaVersion != 2) return error.InvalidSchemaVersion;
    if (index.mediaType) |media_type| {
        try validateMediaType(media_type);
        if (!classifyMediaType(media_type).isIndex()) return error.UnsupportedDocumentMediaType;
    }
    for (index.manifests) |descriptor| try validateDescriptorMediaType(descriptor);
    if (index.subject) |descriptor| try validateDescriptorMediaType(descriptor);
}

pub fn validateRootDescriptor(descriptor: Descriptor) ValidationError!void {
    if (descriptor.mediaType) |media_type| {
        try validateMediaType(media_type);
        const class = classifyMediaType(media_type);
        if (!class.isManifest() and !class.isIndex()) return error.UnsupportedDescriptorMediaType;
    }
}

pub fn validateManifest(manifest: Manifest) ValidationError!void {
    if (manifest.schemaVersion != 2) return error.InvalidSchemaVersion;
    if (manifest.mediaType) |media_type| {
        try validateMediaType(media_type);
        if (!classifyMediaType(media_type).isManifest()) return error.UnsupportedDocumentMediaType;
    }
    if (manifest.config.mediaType) |media_type| {
        try validateMediaType(media_type);
        const class = classifyMediaType(media_type);
        if (class != .oci_config and class != .docker_config) return error.UnsupportedConfigMediaType;
    }
    for (manifest.layers) |layer| {
        if (layer.mediaType) |media_type| {
            try validateMediaType(media_type);
            const class = classifyMediaType(media_type);
            if (class != .oci_layer and class != .docker_layer) return error.UnsupportedLayerMediaType;
        }
    }
    if (manifest.subject) |descriptor| try validateDescriptorMediaType(descriptor);
}

/// Validates a manifest that carries artifact layers rather than image
/// layers.
///
/// `validateManifest` refuses a layer media type outside the image set, and
/// that is right for a manifest something is about to be unpacked from: a
/// pull that met an unknown layer type would otherwise carry on and produce a
/// root filesystem missing whatever it could not read. The image
/// specification places no such restriction, though, and artifacts depend on
/// it not doing so -- a cosign signature manifest's layers are JSON payloads
/// typed `application/vnd.dev.cosign.simplesigning.v1+json`, and every one of
/// them would be refused here.
///
/// So an artifact is validated for everything except what its layers are: the
/// schema version, well-formed media types, and a document media type that is
/// a manifest and not an index. Nothing about a manifest read this way makes
/// it eligible for the pull path, which keeps using `validateManifest`.
pub fn validateArtifactManifest(manifest: Manifest) ValidationError!void {
    if (manifest.schemaVersion != 2) return error.InvalidSchemaVersion;
    if (manifest.mediaType) |media_type| {
        try validateMediaType(media_type);
        if (!classifyMediaType(media_type).isManifest()) return error.UnsupportedDocumentMediaType;
    }
    try validateDescriptorMediaType(manifest.config);
    for (manifest.layers) |layer| try validateDescriptorMediaType(layer);
    if (manifest.subject) |descriptor| try validateDescriptorMediaType(descriptor);
}

pub fn platformMatches(candidate: Platform, requested: Platform) bool {
    if (!std.mem.eql(u8, candidate.os, requested.os) or
        !std.mem.eql(u8, candidate.architecture, requested.architecture)) return false;
    if (requested.variant) |variant| {
        return candidate.variant != null and std.mem.eql(u8, candidate.variant.?, variant);
    }
    return true;
}

/// Selects the first descriptor whose platform matches. Descriptors without
/// platform metadata intentionally cannot stand in for a platform-specific
/// index child.
pub fn selectPlatform(descriptors: []const Descriptor, requested: Platform) ?Descriptor {
    for (descriptors) |descriptor| {
        const candidate = descriptor.platform orelse continue;
        if (platformMatches(candidate, requested)) return descriptor;
    }
    return null;
}

pub const GraphMode = union(enum) {
    all,
    selected: Platform,
};

pub const GraphOptions = struct {
    mode: GraphMode = .all,
    max_depth: usize = 32,
};

/// A parsed OCI document and the descriptors it directly references.
pub const GraphNode = struct {
    descriptor: Descriptor,
    children: []const Descriptor,
};

pub const GraphError = error{
    MissingGraphNode,
    PlatformNotFound,
    AmbiguousPlatform,
    UnsupportedSelectedObject,
    CycleDetected,
    MaximumDepthExceeded,
} || std.mem.Allocator.Error;

/// A dependency-before-parent traversal result. Descriptor strings remain
/// borrowed from the graph supplied to `resolveGraph`.
pub const GraphResolution = struct {
    descriptors: []Descriptor,

    pub fn deinit(self: *GraphResolution, allocator: std.mem.Allocator) void {
        allocator.free(self.descriptors);
        self.* = undefined;
    }
};

pub fn resolveGraph(
    allocator: std.mem.Allocator,
    root: Descriptor,
    nodes: []const GraphNode,
    options: GraphOptions,
) GraphError!GraphResolution {
    var context = GraphContext{
        .allocator = allocator,
        .nodes = nodes,
        .max_depth = options.max_depth,
        .resolved = std.array_list.Managed(Descriptor).init(allocator),
        .visited = std.StringHashMap(void).init(allocator),
        .visiting = std.StringHashMap(void).init(allocator),
    };
    defer context.visited.deinit();
    defer context.visiting.deinit();
    errdefer context.resolved.deinit();

    switch (options.mode) {
        .all => try context.visit(root, 0),
        .selected => |platform| {
            const selected = try context.findSelectedLeaf(root, platform, 0, true) orelse return error.PlatformNotFound;
            try context.visit(selected, 0);
        },
    }
    return .{ .descriptors = try context.resolved.toOwnedSlice() };
}

const GraphContext = struct {
    allocator: std.mem.Allocator,
    nodes: []const GraphNode,
    max_depth: usize,
    resolved: std.array_list.Managed(Descriptor),
    visited: std.StringHashMap(void),
    visiting: std.StringHashMap(void),

    fn findNode(self: *const GraphContext, descriptor: Descriptor) ?GraphNode {
        for (self.nodes) |node| {
            if (std.mem.eql(u8, node.descriptor.digest, descriptor.digest)) return node;
        }
        return null;
    }

    fn visit(self: *GraphContext, descriptor: Descriptor, depth: usize) GraphError!void {
        if (depth > self.max_depth) return error.MaximumDepthExceeded;
        if (self.visited.contains(descriptor.digest)) return;
        if (self.visiting.contains(descriptor.digest)) return error.CycleDetected;

        const class = classifyMediaType(descriptor.mediaType);
        if (!class.isIndex() and !class.isManifest()) {
            try self.resolved.append(descriptor);
            try self.visited.put(descriptor.digest, {});
            return;
        }

        const node = self.findNode(descriptor) orelse return error.MissingGraphNode;
        try self.visiting.put(descriptor.digest, {});
        defer _ = self.visiting.remove(descriptor.digest);
        if (class.isIndex() or class.isManifest()) {
            for (node.children) |child| try self.visit(child, depth + 1);
        }
        try self.resolved.append(descriptor);
        try self.visited.put(descriptor.digest, {});
    }

    fn findSelectedLeaf(
        self: *GraphContext,
        descriptor: Descriptor,
        requested: Platform,
        depth: usize,
        allow_unannotated_manifest: bool,
    ) GraphError!?Descriptor {
        if (depth > self.max_depth) return error.MaximumDepthExceeded;
        const class = classifyMediaType(descriptor.mediaType);
        if (!class.isIndex()) {
            if (descriptor.platform) |platform| {
                if (!platformMatches(platform, requested)) return null;
                if (!class.isManifest()) return error.UnsupportedSelectedObject;
                return descriptor;
            }
            return if (allow_unannotated_manifest and class.isManifest()) descriptor else null;
        }

        if (self.visiting.contains(descriptor.digest)) return error.CycleDetected;
        const node = self.findNode(descriptor) orelse return error.MissingGraphNode;
        try self.visiting.put(descriptor.digest, {});
        defer _ = self.visiting.remove(descriptor.digest);

        // An annotated child is authoritative. Preserve descriptor order,
        // including for matching nested indexes.
        for (node.children) |child| {
            const child_platform = child.platform orelse continue;
            if (!platformMatches(child_platform, requested)) continue;
            if (try self.findSelectedLeaf(child, requested, depth + 1, true)) |selected| return selected;
        }

        if (allow_unannotated_manifest and node.children.len == 1) {
            const child = node.children[0];
            if (child.platform == null and classifyMediaType(child.mediaType).isManifest()) {
                return self.findSelectedLeaf(child, requested, depth + 1, true);
            }
        }

        // Platformless indexes are compatibility fallbacks. Search every
        // branch rather than silently choosing the first one.
        var fallback: ?Descriptor = null;
        for (node.children) |child| {
            if (child.platform != null or !classifyMediaType(child.mediaType).isIndex()) continue;
            const selected = try self.findSelectedLeaf(child, requested, depth + 1, false) orelse continue;
            if (fallback != null) return error.AmbiguousPlatform;
            fallback = selected;
        }
        return fallback;
    }
};

test "media type classification distinguishes known and unknown values" {
    try std.testing.expect(classifyMediaType(media_type_oci_index).isIndex());
    try std.testing.expect(classifyMediaType(media_type_docker_manifest).isManifest());
    try std.testing.expectEqual(MediaTypeClass.oci_layer, classifyMediaType(media_type_oci_nondistributable_layer_gzip));
    try std.testing.expectEqual(MediaTypeClass.docker_layer, classifyMediaType(media_type_docker_foreign_layer_gzip));
    try std.testing.expectEqual(MediaTypeClass.docker_layer, classifyMediaType(media_type_docker_layer_zstd));
    try std.testing.expectEqual(MediaTypeClass.unknown, classifyMediaType("application/example"));
    try std.testing.expectEqual(MediaTypeClass.unknown, classifyMediaType(null));
}

test "media type validation rejects values unsafe for HTTP headers" {
    try validateMediaType("application/example.opaque");
    try std.testing.expectError(error.InvalidMediaType, validateMediaType("application/example\r\nAuthorization: injected"));
    try std.testing.expectError(error.InvalidMediaType, validateMediaType("application/example; charset=utf-8"));
    try std.testing.expectError(error.InvalidMediaType, validateMediaType("application/"));
    try std.testing.expectError(error.InvalidMediaType, validateMediaType("/json"));
}

test "platform selection is first match and observes variants" {
    const descriptors = [_]Descriptor{
        .{ .digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .size = 1, .platform = .{ .os = "linux", .architecture = "arm64", .variant = "v8" } },
        .{ .digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", .size = 1, .platform = .{ .os = "linux", .architecture = "amd64" } },
        .{ .digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", .size = 1, .platform = .{ .os = "linux", .architecture = "amd64" } },
    };
    const selected = selectPlatform(&descriptors, .{ .os = "linux", .architecture = "amd64" }).?;
    try std.testing.expectEqualStrings(descriptors[1].digest, selected.digest);
    try std.testing.expect(selectPlatform(&descriptors, .{ .os = "linux", .architecture = "arm64", .variant = "v7" }) == null);
    try std.testing.expect(selectPlatform(&descriptors, .{ .os = "windows", .architecture = "amd64" }) == null);
}

test "platform JSON fields use OCI dotted names" {
    const allocator = std.testing.allocator;
    const descriptor_json =
        \\{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1,"platform":{"architecture":"amd64","os":"windows","os.version":"10.0.20348","os.features":["win32k"]}}
    ;
    const descriptor = try std.json.parseFromSlice(Descriptor, allocator, descriptor_json, .{});
    defer descriptor.deinit();
    try std.testing.expectEqualStrings("10.0.20348", descriptor.value.platform.?.@"os.version".?);
    try std.testing.expectEqualStrings("win32k", descriptor.value.platform.?.@"os.features".?[0]);

    const config_json =
        \\{"architecture":"amd64","os":"windows","os.version":"10.0.20348","os.features":["win32k"]}
    ;
    const config = try std.json.parseFromSlice(ConfigPlatform, allocator, config_json, .{});
    defer config.deinit();
    try std.testing.expectEqualStrings("10.0.20348", config.value.@"os.version".?);
    try std.testing.expectEqualStrings("win32k", config.value.@"os.features".?[0]);
}

test "model validators enforce schema two and role media types" {
    const descriptor = Descriptor{ .digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .size = 1 };
    try std.testing.expectError(error.InvalidSchemaVersion, validateIndex(.{ .schemaVersion = 1, .manifests = &.{} }));
    try std.testing.expectError(error.UnsupportedDocumentMediaType, validateIndex(.{ .schemaVersion = 2, .mediaType = media_type_oci_manifest, .manifests = &.{} }));
    try std.testing.expectError(error.UnsupportedDescriptorMediaType, validateRootDescriptor(.{ .digest = descriptor.digest, .size = 1, .mediaType = "application/vnd.docker.distribution.manifest.v1+json" }));
    try std.testing.expectError(error.UnsupportedConfigMediaType, validateManifest(.{
        .schemaVersion = 2,
        .config = .{ .digest = descriptor.digest, .size = 1, .mediaType = media_type_oci_layer },
        .layers = &.{},
    }));
    try std.testing.expectError(error.UnsupportedLayerMediaType, validateManifest(.{
        .schemaVersion = 2,
        .config = .{ .digest = descriptor.digest, .size = 1, .mediaType = media_type_oci_config },
        .layers = &.{.{ .digest = descriptor.digest, .size = 1, .mediaType = media_type_oci_manifest }},
    }));
}

fn graphDescriptor(digest: []const u8, media_type: ?[]const u8, platform: ?Platform) Descriptor {
    return .{ .digest = digest, .size = 1, .mediaType = media_type, .platform = platform };
}

test "graph resolver prefers direct matching children over platformless fallback" {
    const root = graphDescriptor("root", media_type_oci_index, null);
    const nested = graphDescriptor("nested", media_type_oci_index, null);
    const arm = graphDescriptor("arm", media_type_oci_manifest, .{ .os = "linux", .architecture = "arm64" });
    const first_amd = graphDescriptor("amd-first", media_type_oci_manifest, .{ .os = "linux", .architecture = "amd64" });
    const later_amd = graphDescriptor("amd-later", media_type_oci_manifest, .{ .os = "linux", .architecture = "amd64" });
    const nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{ nested, later_amd } },
        .{ .descriptor = nested, .children = &.{ arm, first_amd } },
        .{ .descriptor = arm, .children = &.{} },
        .{ .descriptor = first_amd, .children = &.{} },
        .{ .descriptor = later_amd, .children = &.{} },
    };
    var resolution = try resolveGraph(std.testing.allocator, root, &nodes, .{
        .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } },
    });
    defer resolution.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), resolution.descriptors.len);
    try std.testing.expectEqualStrings("amd-later", resolution.descriptors[0].digest);
    try std.testing.expectError(error.PlatformNotFound, resolveGraph(std.testing.allocator, root, &nodes, .{
        .mode = .{ .selected = .{ .os = "windows", .architecture = "amd64" } },
    }));
}

test "graph selected resolver rejects opaque matches and ambiguous platformless branches" {
    const root = graphDescriptor("root", media_type_oci_index, null);
    const opaque_child = graphDescriptor("opaque", "application/example", .{ .os = "linux", .architecture = "amd64" });
    const manifest_one = graphDescriptor("one", media_type_oci_manifest, .{ .os = "linux", .architecture = "amd64" });
    const manifest_two = graphDescriptor("two", media_type_oci_manifest, .{ .os = "linux", .architecture = "amd64" });
    const nested_one = graphDescriptor("nested-one", media_type_oci_index, null);
    const nested_two = graphDescriptor("nested-two", media_type_oci_index, null);
    const opaque_nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{opaque_child} },
    };
    try std.testing.expectError(error.UnsupportedSelectedObject, resolveGraph(std.testing.allocator, root, &opaque_nodes, .{
        .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } },
    }));
    const ambiguous_nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{ nested_one, nested_two } },
        .{ .descriptor = nested_one, .children = &.{manifest_one} },
        .{ .descriptor = nested_two, .children = &.{manifest_two} },
        .{ .descriptor = manifest_one, .children = &.{} },
        .{ .descriptor = manifest_two, .children = &.{} },
    };
    try std.testing.expectError(error.AmbiguousPlatform, resolveGraph(std.testing.allocator, root, &ambiguous_nodes, .{
        .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } },
    }));
}

test "graph selected resolver detects nested index cycles" {
    const root = graphDescriptor("root", media_type_oci_index, null);
    const child = graphDescriptor("child", media_type_oci_index, null);
    const nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{child} },
        .{ .descriptor = child, .children = &.{root} },
    };
    try std.testing.expectError(error.CycleDetected, resolveGraph(std.testing.allocator, root, &nodes, .{
        .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } },
    }));
}

test "graph selected resolver accepts an unannotated leaf below a matching index" {
    const root = graphDescriptor("root", media_type_oci_index, null);
    const nested = graphDescriptor("nested", media_type_oci_index, .{ .os = "linux", .architecture = "amd64" });
    const leaf = graphDescriptor("leaf", media_type_oci_manifest, null);
    const nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{nested} },
        .{ .descriptor = nested, .children = &.{leaf} },
        .{ .descriptor = leaf, .children = &.{} },
    };
    var resolution = try resolveGraph(std.testing.allocator, root, &nodes, .{
        .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } },
    });
    defer resolution.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("leaf", resolution.descriptors[0].digest);
}

test "graph resolver all mode orders, deduplicates, and keeps opaque leaves" {
    const root = graphDescriptor("root", media_type_oci_index, null);
    const one = graphDescriptor("one", media_type_oci_manifest, null);
    const two = graphDescriptor("two", media_type_oci_manifest, null);
    const shared = graphDescriptor("shared", media_type_oci_config, null);
    const layer = graphDescriptor("layer", media_type_oci_layer_gzip, null);
    const opaque_leaf = graphDescriptor("opaque", "application/example", null);
    const nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{ one, two, opaque_leaf } },
        .{ .descriptor = one, .children = &.{ shared, layer } },
        .{ .descriptor = two, .children = &.{shared} },
    };
    var resolution = try resolveGraph(std.testing.allocator, root, &nodes, .{});
    defer resolution.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 6), resolution.descriptors.len);
    try std.testing.expectEqualStrings("shared", resolution.descriptors[0].digest);
    try std.testing.expectEqualStrings("layer", resolution.descriptors[1].digest);
    try std.testing.expectEqualStrings("one", resolution.descriptors[2].digest);
    try std.testing.expectEqualStrings("two", resolution.descriptors[3].digest);
    try std.testing.expectEqualStrings("opaque", resolution.descriptors[4].digest);
    try std.testing.expectEqualStrings("root", resolution.descriptors[5].digest);
}

test "graph resolver selected mode accepts an unannotated single manifest" {
    const root = graphDescriptor("root", media_type_oci_manifest, null);
    const config = graphDescriptor("config", media_type_oci_config, null);
    const layer = graphDescriptor("layer", media_type_oci_layer, null);
    const nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{ config, layer } },
    };
    var resolution = try resolveGraph(std.testing.allocator, root, &nodes, .{
        .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } },
    });
    defer resolution.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), resolution.descriptors.len);
    try std.testing.expectEqualStrings("config", resolution.descriptors[0].digest);
    try std.testing.expectEqualStrings("layer", resolution.descriptors[1].digest);
    try std.testing.expectEqualStrings("root", resolution.descriptors[2].digest);
}

test "graph resolver detects cycles and limits depth" {
    const root = graphDescriptor("root", media_type_oci_index, null);
    const child = graphDescriptor("child", media_type_oci_index, null);
    const nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{child} },
        .{ .descriptor = child, .children = &.{root} },
    };
    try std.testing.expectError(error.CycleDetected, resolveGraph(std.testing.allocator, root, &nodes, .{}));
    const shallow_nodes = [_]GraphNode{
        .{ .descriptor = root, .children = &.{child} },
        .{ .descriptor = child, .children = &.{} },
    };
    try std.testing.expectError(error.MaximumDepthExceeded, resolveGraph(std.testing.allocator, root, &shallow_nodes, .{ .max_depth = 0 }));
}
