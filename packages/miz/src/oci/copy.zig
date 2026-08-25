//! Transport-neutral OCI graph copy.
const std = @import("std");
const content = @import("content.zig");
const model = @import("model.zig");
const reference = @import("reference.zig");
const layout = @import("layout.zig");
const transport = @import("transport.zig");

pub const Options = struct {
    mode: model.GraphMode = .all,
    /// True only when callers explicitly requested a platform rather than
    /// accepting host-default/single-manifest selection.
    platform_selection_explicit: bool = false,
    max_depth: usize = 32,
    failure_point: layout.FailurePoint = .none,
};

pub const Result = struct {
    root: model.Descriptor,
    /// Borrowed from `root_parsed` and valid until `deinit`; exposed directly
    /// so callers do not need to retain a transient source descriptor.
    root_digest: []const u8 = &.{},
    transferred: u64,
    reused: u64,
    mounted: u64 = 0,
    root_json: []u8,
    root_parsed: std.json.Parsed(model.Descriptor),

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        self.root_parsed.deinit();
        allocator.free(self.root_json);
        self.* = undefined;
    }
};

/// Copies exact blob bytes locally. In selected mode an index is traversed
/// only to select one leaf and that leaf becomes the destination root.
pub fn localToLocal(
    io: std.Io,
    allocator: std.mem.Allocator,
    source_ref: reference.LayoutReference,
    destination_ref: reference.LayoutReference,
    options: Options,
) !Result {
    var source = layout.Source.init(io, allocator, source_ref.path);
    var resolved = try source.resolve(source_ref);
    defer resolved.deinit();
    return resolvedToLayout(io, allocator, source.asTransport(), &resolved, destination_ref, options);
}

/// Transfers a previously resolved source into a local layout through the
/// shared graph traversal used by every transport pairing.
pub fn resolvedToLayout(
    io: std.Io,
    allocator: std.mem.Allocator,
    source: transport.Source,
    resolved: *const layout.ResolvedRoot,
    destination_ref: reference.LayoutReference,
    options: Options,
) !Result {
    var destination = try layout.Destination.init(io, allocator, destination_ref.path);
    defer destination.deinit();
    destination.failure_point = options.failure_point;
    return resolvedToDestination(
        allocator,
        source,
        resolved,
        destination.asTransport(),
        destination_ref.selection,
        options,
    );
}

/// The one graph planner/copy core used by layout and registry destinations.
/// It always visits dependencies before their parent and defers the root
/// destination reference commit until every dependency has completed.
pub fn resolvedToDestination(
    allocator: std.mem.Allocator,
    source: transport.Source,
    resolved: *const layout.ResolvedRoot,
    destination: transport.Destination,
    selection: ?reference.Selection,
    options: Options,
) !Result {
    var context = Context{
        .source = source,
        .destination = destination,
        .allocator = allocator,
        .options = options,
        .counts = .{},
        .plan = std.array_list.Managed(PlanEntry).init(allocator),
        .done = std.StringHashMap(DoneDescriptor).init(allocator),
        .active = std.StringHashMap(void).init(allocator),
        .selected_active = std.StringHashMap(void).init(allocator),
    };
    defer context.deinit();
    var selected: ?SelectedRoot = null;
    defer if (selected) |*value| value.deinit(allocator);
    const root, const root_json: []const u8 = switch (options.mode) {
        .all => blk: {
            _ = try context.planAll(resolved.descriptor, 0, true, .manifest);
            break :blk .{ resolved.descriptor, resolved.descriptor_json };
        },
        .selected => |platform| blk: {
            selected = try context.copySelected(resolved.descriptor, resolved.descriptor_json, platform, 0, true);
            _ = try context.planAll(selected.?.descriptor, selected.?.depth, true, .manifest);
            if (options.platform_selection_explicit) try context.validateSelectedConfig(selected.?.descriptor, platform);
            break :blk .{ selected.?.descriptor, selected.?.descriptor_json };
        },
    };
    try destination.prepareRoot(root, selection);
    try context.executePlan();
    switch (options.mode) {
        .all => {},
        .selected => try destination.stageRoot(source, root, &context.counts),
    }
    const root_bytes = context.takeRootBytes() orelse return error.InvalidIndex;
    defer allocator.free(root_bytes);
    const result_json = try allocator.dupe(u8, root_json);
    errdefer allocator.free(result_json);
    var result_parsed = try std.json.parseFromSlice(model.Descriptor, allocator, result_json, .{ .ignore_unknown_fields = true });
    errdefer result_parsed.deinit();
    try destination.commitRoot(source, root, root_json, root_bytes, selection, &context.counts);
    try destination.finishDestination();
    return .{
        .root = result_parsed.value,
        .root_digest = result_parsed.value.digest,
        .root_json = result_json,
        .root_parsed = result_parsed,
        .transferred = context.counts.transferred,
        .reused = context.counts.reused,
        .mounted = context.counts.mounted,
    };
}

const Context = struct {
    source: transport.Source,
    destination: transport.Destination,
    allocator: std.mem.Allocator,
    options: Options,
    counts: transport.Counts,
    root_bytes: ?[]u8 = null,
    plan: std.array_list.Managed(PlanEntry),
    done: std.StringHashMap(DoneDescriptor),
    active: std.StringHashMap(void),
    selected_active: std.StringHashMap(void),

    fn deinit(self: *Context) void {
        if (self.root_bytes) |bytes| self.allocator.free(bytes);
        for (self.plan.items) |*entry| entry.deinit(self.allocator);
        self.plan.deinit();
        freeMapKeys(&self.done, self.allocator);
        self.active.deinit();
        self.selected_active.deinit();
    }

    fn takeRootBytes(self: *Context) ?[]u8 {
        const bytes = self.root_bytes;
        self.root_bytes = null;
        return bytes;
    }

    fn planAll(
        self: *Context,
        descriptor: model.Descriptor,
        depth: usize,
        is_root: bool,
        role: transport.DescriptorRole,
    ) !model.Descriptor {
        if (depth > self.options.max_depth) return error.MaximumDepthExceeded;
        _ = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
        if (descriptor.mediaType) |media_type| {
            model.validateMediaType(media_type) catch return error.InvalidIndex;
        }
        if (self.active.contains(descriptor.digest)) return error.CycleDetected;
        if (self.done.get(descriptor.digest)) |previous| {
            if (previous.size != descriptor.size or
                !optionalStringsEqual(previous.media_type, descriptor.mediaType))
            {
                return error.ConflictingDescriptor;
            }
            if (previous.hasRole(role)) return descriptor;
        }
        try self.active.put(descriptor.digest, {});
        defer _ = self.active.remove(descriptor.digest);
        switch (model.classifyMediaType(descriptor.mediaType)) {
            .oci_index, .docker_manifest_list => {
                const bytes = try self.source.readMetadata(descriptor);
                var bytes_owned = true;
                defer if (bytes_owned) self.allocator.free(bytes);
                var parsed = std.json.parseFromSlice(model.Index, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidIndex;
                defer parsed.deinit();
                model.validateIndex(parsed.value) catch return error.InvalidIndex;
                for (parsed.value.manifests) |child| _ = try self.planAll(child, depth + 1, false, .manifest);
                if (is_root) {
                    if (self.root_bytes != null) return error.InvalidIndex;
                    self.root_bytes = bytes;
                    bytes_owned = false;
                } else {
                    try self.appendPlan(descriptor, role, bytes);
                    bytes_owned = false;
                }
            },
            .oci_manifest, .docker_manifest => {
                const bytes = try self.source.readMetadata(descriptor);
                var bytes_owned = true;
                defer if (bytes_owned) self.allocator.free(bytes);
                var parsed = std.json.parseFromSlice(model.Manifest, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidIndex;
                defer parsed.deinit();
                model.validateManifest(parsed.value) catch return error.InvalidIndex;
                _ = try self.planAll(parsed.value.config, depth + 1, false, .blob);
                for (parsed.value.layers) |child| _ = try self.planAll(child, depth + 1, false, .blob);
                if (is_root) {
                    if (self.root_bytes != null) return error.InvalidIndex;
                    self.root_bytes = bytes;
                    bytes_owned = false;
                } else {
                    try self.appendPlan(descriptor, role, bytes);
                    bytes_owned = false;
                }
            },
            else => if (!is_root) switch (role) {
                .blob => try self.appendPlan(descriptor, role, null),
                .manifest => {
                    const bytes = try self.source.readManifestMetadata(descriptor);
                    errdefer self.allocator.free(bytes);
                    try self.appendPlan(descriptor, role, bytes);
                },
            },
        }
        try putDigest(&self.done, self.allocator, descriptor, role);
        return descriptor;
    }

    fn appendPlan(
        self: *Context,
        descriptor: model.Descriptor,
        role: transport.DescriptorRole,
        metadata: ?[]u8,
    ) !void {
        const descriptor_json = try std.json.Stringify.valueAlloc(self.allocator, descriptor, .{});
        errdefer self.allocator.free(descriptor_json);
        var descriptor_parsed = try std.json.parseFromSlice(
            model.Descriptor,
            self.allocator,
            descriptor_json,
            .{ .ignore_unknown_fields = true },
        );
        errdefer descriptor_parsed.deinit();
        try self.plan.append(.{
            .descriptor = descriptor_parsed.value,
            .descriptor_json = descriptor_json,
            .descriptor_parsed = descriptor_parsed,
            .role = role,
            .metadata = metadata,
        });
    }

    fn executePlan(self: *Context) !void {
        for (self.plan.items) |entry| {
            try self.destination.ensureDescriptor(
                self.source,
                entry.descriptor,
                entry.role,
                entry.metadata,
                &self.counts,
            );
        }
    }

    fn copySelected(self: *Context, descriptor: model.Descriptor, descriptor_json: []const u8, platform: model.Platform, depth: usize, permit_unannotated: bool) anyerror!SelectedRoot {
        if (depth > self.options.max_depth) return error.MaximumDepthExceeded;
        switch (model.classifyMediaType(descriptor.mediaType)) {
            .oci_index, .docker_manifest_list => {
                if (self.selected_active.contains(descriptor.digest)) return error.CycleDetected;
                try self.selected_active.put(descriptor.digest, {});
                defer _ = self.selected_active.remove(descriptor.digest);
                const bytes = try self.source.readMetadata(descriptor);
                defer self.allocator.free(bytes);
                var parsed = std.json.parseFromSlice(model.Index, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidIndex;
                defer parsed.deinit();
                model.validateIndex(parsed.value) catch return error.InvalidIndex;

                // Explicit descriptor platforms are authoritative and retain
                // descriptor order. A matching non-manifest is not a leaf.
                for (parsed.value.manifests, 0..) |child, i| {
                    const candidate = child.platform orelse continue;
                    if (!model.platformMatches(candidate, platform)) continue;
                    const child_json = try descriptorJsonAt(self.allocator, bytes, i);
                    defer self.allocator.free(child_json);
                    if (model.classifyMediaType(child.mediaType).isIndex()) {
                        const result = self.copySelected(child, child_json, platform, depth + 1, true) catch |err| switch (err) {
                            error.PlatformNotFound => continue,
                            else => return err,
                        };
                        return result;
                    }
                    return self.selectLeaf(child, child_json, depth + 1, false);
                }

                if (permit_unannotated and parsed.value.manifests.len == 1) {
                    const child = parsed.value.manifests[0];
                    if (child.platform == null and model.classifyMediaType(child.mediaType).isManifest()) {
                        const child_json = try descriptorJsonAt(self.allocator, bytes, 0);
                        defer self.allocator.free(child_json);
                        return self.selectLeaf(child, child_json, depth + 1, true);
                    }
                }

                // A platformless nested index is a compatibility fallback.
                // Search every successful branch so selection is never an
                // accidental first-branch choice.
                var fallback: ?SelectedRoot = null;
                errdefer if (fallback) |*value| value.deinit(self.allocator);
                for (parsed.value.manifests, 0..) |child, i| {
                    if (child.platform != null or !model.classifyMediaType(child.mediaType).isIndex()) continue;
                    const child_json = try descriptorJsonAt(self.allocator, bytes, i);
                    defer self.allocator.free(child_json);
                    var candidate = self.copySelected(child, child_json, platform, depth + 1, false) catch |err| switch (err) {
                        error.PlatformNotFound => continue,
                        else => return err,
                    };
                    if (fallback != null) {
                        candidate.deinit(self.allocator);
                        return error.AmbiguousPlatform;
                    }
                    fallback = candidate;
                }
                return fallback orelse error.PlatformNotFound;
            },
            .oci_manifest, .docker_manifest => {
                return self.selectLeaf(descriptor, descriptor_json, depth, permit_unannotated);
            },
            else => {
                if (descriptor.platform) |candidate| {
                    if (model.platformMatches(candidate, platform)) return error.UnsupportedSelectedObject;
                }
                return error.PlatformNotFound;
            },
        }
    }

    fn selectLeaf(
        self: *Context,
        descriptor: model.Descriptor,
        descriptor_json: []const u8,
        depth: usize,
        permit_unannotated: bool,
    ) !SelectedRoot {
        if (!model.classifyMediaType(descriptor.mediaType).isManifest()) return error.UnsupportedSelectedObject;
        if (descriptor.platform) |candidate| {
            const requested = switch (self.options.mode) {
                .selected => |platform| platform,
                .all => unreachable,
            };
            if (!model.platformMatches(candidate, requested)) return error.PlatformNotFound;
        } else if (!permit_unannotated) return error.PlatformNotFound;
        const owned_json = try self.allocator.dupe(u8, descriptor_json);
        errdefer self.allocator.free(owned_json);
        var parsed = try std.json.parseFromSlice(model.Descriptor, self.allocator, owned_json, .{ .ignore_unknown_fields = true });
        errdefer parsed.deinit();
        return .{
            .descriptor = parsed.value,
            .descriptor_json = owned_json,
            .parsed = parsed,
            .depth = depth,
        };
    }

    fn validateSelectedConfig(self: *Context, manifest_descriptor: model.Descriptor, requested: model.Platform) !void {
        const manifest_bytes = try self.source.readMetadata(manifest_descriptor);
        defer self.allocator.free(manifest_bytes);
        var manifest = std.json.parseFromSlice(model.Manifest, self.allocator, manifest_bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidIndex;
        defer manifest.deinit();
        model.validateManifest(manifest.value) catch return error.InvalidIndex;
        const config_bytes = try self.source.readMetadata(manifest.value.config);
        defer self.allocator.free(config_bytes);
        var config = std.json.parseFromSlice(model.ImageConfigPlatform, self.allocator, config_bytes, .{ .ignore_unknown_fields = true }) catch return error.PlatformConfigMismatch;
        defer config.deinit();
        if (config.value.os == null or config.value.architecture == null or
            !std.mem.eql(u8, config.value.os.?, requested.os) or
            !std.mem.eql(u8, config.value.architecture.?, requested.architecture)) return error.PlatformConfigMismatch;
        if (requested.variant) |variant| {
            if (config.value.variant == null or !std.mem.eql(u8, config.value.variant.?, variant)) return error.PlatformConfigMismatch;
        }
    }
};

fn descriptorJsonAt(allocator: std.mem.Allocator, index_bytes: []const u8, occurrence: usize) ![]u8 {
    var value = std.json.parseFromSlice(std.json.Value, allocator, index_bytes, .{}) catch return error.InvalidIndex;
    defer value.deinit();
    const object = switch (value.value) {
        .object => |object| object,
        else => return error.InvalidIndex,
    };
    const manifests = object.get("manifests") orelse return error.InvalidIndex;
    if (manifests != .array or occurrence >= manifests.array.items.len) return error.InvalidIndex;
    return std.json.Stringify.valueAlloc(allocator, manifests.array.items[occurrence], .{});
}

const SelectedRoot = struct {
    descriptor: model.Descriptor,
    descriptor_json: []u8,
    parsed: std.json.Parsed(model.Descriptor),
    depth: usize,

    fn deinit(self: *SelectedRoot, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        allocator.free(self.descriptor_json);
    }
};

const PlanEntry = struct {
    descriptor: model.Descriptor,
    descriptor_json: []u8,
    descriptor_parsed: std.json.Parsed(model.Descriptor),
    role: transport.DescriptorRole,
    metadata: ?[]u8,

    fn deinit(self: *PlanEntry, allocator: std.mem.Allocator) void {
        if (self.metadata) |bytes| allocator.free(bytes);
        self.descriptor_parsed.deinit();
        allocator.free(self.descriptor_json);
        self.* = undefined;
    }
};

const DoneDescriptor = struct {
    size: u64,
    media_type: ?[]u8,
    blob: bool = false,
    manifest: bool = false,

    fn hasRole(self: DoneDescriptor, role: transport.DescriptorRole) bool {
        return switch (role) {
            .blob => self.blob,
            .manifest => self.manifest,
        };
    }
};

fn putDigest(
    map: *std.StringHashMap(DoneDescriptor),
    allocator: std.mem.Allocator,
    descriptor: model.Descriptor,
    role: transport.DescriptorRole,
) !void {
    if (map.getPtr(descriptor.digest)) |entry| {
        switch (role) {
            .blob => entry.blob = true,
            .manifest => entry.manifest = true,
        }
        return;
    }
    const key = try allocator.dupe(u8, descriptor.digest);
    errdefer allocator.free(key);
    const media_type = if (descriptor.mediaType) |value| try allocator.dupe(u8, value) else null;
    errdefer if (media_type) |value| allocator.free(value);
    var entry = DoneDescriptor{
        .size = descriptor.size,
        .media_type = media_type,
    };
    switch (role) {
        .blob => entry.blob = true,
        .manifest => entry.manifest = true,
    }
    try map.put(key, entry);
}

fn freeMapKeys(map: *std.StringHashMap(DoneDescriptor), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.media_type) |value| allocator.free(value);
        allocator.free(entry.key_ptr.*);
    }
    map.deinit();
}

fn optionalStringsEqual(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, left.?, right.?);
}

fn testDescriptor(allocator: std.mem.Allocator, media_type: []const u8, bytes: []const u8) !model.Descriptor {
    const digest = content.digestBytes(bytes).format();
    return .{
        .mediaType = media_type,
        .digest = try std.fmt.allocPrint(allocator, "{s}", .{digest}),
        .size = bytes.len,
    };
}

fn testWriteBlob(io: std.Io, dir: std.Io.Dir, descriptor: model.Descriptor, bytes: []const u8) !void {
    const digest = try content.Digest.parse(descriptor.digest);
    const hex = digest.blobPathComponent();
    var path: [80]u8 = undefined;
    const name = try std.fmt.bufPrint(&path, "blobs/sha256/{s}", .{hex});
    try dir.writeFile(io, .{ .sub_path = name, .data = bytes });
}

fn testMakeLayout(allocator: std.mem.Allocator, io: std.Io, path: []const u8, name: []const u8) !model.Descriptor {
    try std.Io.Dir.cwd().createDirPath(io, path);
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    try dir.createDirPath(io, "blobs/sha256");
    try dir.writeFile(io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}" });
    const config = try testDescriptor(allocator, model.media_type_oci_config, "{}");
    defer allocator.free(config.digest);
    try testWriteBlob(io, dir, config, "{}");
    const layer = try testDescriptor(allocator, model.media_type_oci_layer, "layer");
    defer allocator.free(layer.digest);
    try testWriteBlob(io, dir, layer, "layer");
    const manifest = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}", .{ model.media_type_oci_manifest, config.mediaType.?, config.digest, config.size, layer.mediaType.?, layer.digest, layer.size });
    defer allocator.free(manifest);
    const root = try testDescriptor(allocator, model.media_type_oci_manifest, manifest);
    try testWriteBlob(io, dir, root, manifest);
    const index = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"{s}\"}}}}],\"x-extra\":{{\"preserved\":true}}}}", .{ root.mediaType.?, root.digest, root.size, name });
    defer allocator.free(index);
    try dir.writeFile(io, .{ .sub_path = "index.json", .data = index });
    return root;
}

fn testMakePlatformLayout(allocator: std.mem.Allocator, io: std.Io, path: []const u8, name: []const u8, config_bytes: []const u8) !model.Descriptor {
    try std.Io.Dir.cwd().createDirPath(io, path);
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    try dir.createDirPath(io, "blobs/sha256");
    try dir.writeFile(io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}" });
    const config = try testDescriptor(allocator, model.media_type_oci_config, config_bytes);
    defer allocator.free(config.digest);
    try testWriteBlob(io, dir, config, config_bytes);
    const manifest = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[]}}", .{
        model.media_type_oci_manifest,
        config.mediaType.?,
        config.digest,
        config.size,
    });
    defer allocator.free(manifest);
    const root = try testDescriptor(allocator, model.media_type_oci_manifest, manifest);
    try testWriteBlob(io, dir, root, manifest);
    const index = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"{s}\"}}}}]}}", .{
        root.mediaType.?,
        root.digest,
        root.size,
        name,
    });
    defer allocator.free(index);
    try dir.writeFile(io, .{ .sub_path = "index.json", .data = index });
    return root;
}

test "local copy resolves named digest and unambiguous roots and preserves manifest bytes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-source";
    const named_destination = "test-oci-copy-named";
    const digest_destination = "test-oci-copy-digest";
    const unannotated_source = "test-oci-copy-unannotated";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, named_destination);
    defer testDeleteLayout(io, digest_destination);
    defer testDeleteLayout(io, unannotated_source);
    const root = try testMakeLayout(allocator, io, source_path, "stable");
    defer allocator.free(root.digest);
    const parsed_named = (try reference.parse("oci:test-oci-copy-source:stable", .source)).layout;
    var named = try layout.Source.init(io, allocator, source_path).resolve(parsed_named);
    defer named.deinit();
    const source_manifest = try allocator.dupe(u8, named.bytes);
    defer allocator.free(source_manifest);
    const parsed_destination = (try reference.parse("oci:test-oci-copy-named:copy", .destination)).layout;
    var result = try localToLocal(io, allocator, parsed_named, parsed_destination, .{});
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings(root.digest, result.root.digest);
    var copied = try layout.Source.init(io, allocator, named_destination).resolve(
        (try reference.parse("oci:test-oci-copy-named:copy", .source)).layout,
    );
    defer copied.deinit();
    try std.testing.expectEqualStrings(source_manifest, copied.bytes);
    const digest_reference = try std.fmt.allocPrint(allocator, "oci:test-oci-copy-source@{s}", .{root.digest});
    defer allocator.free(digest_reference);
    const parsed_digest = (try reference.parse(digest_reference, .source)).layout;
    const digest_destination_reference = try std.fmt.allocPrint(allocator, "oci:test-oci-copy-digest@{s}", .{root.digest});
    defer allocator.free(digest_destination_reference);
    var digest_result = try localToLocal(io, allocator, parsed_digest, (try reference.parse(digest_destination_reference, .destination)).layout, .{});
    defer digest_result.deinit(allocator);
}

test "copy preserves unrelated index fields, verifies reuse, and leaves staging unpublished on failure" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-merge-source";
    const destination_path = "test-oci-copy-merge-destination";
    const failed_path = "test-oci-copy-failed-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    defer testDeleteLayout(io, failed_path);
    const source_root = try testMakeLayout(allocator, io, source_path, "source");
    defer allocator.free(source_root.digest);
    const old_root = try testMakeLayout(allocator, io, destination_path, "other");
    defer allocator.free(old_root.digest);
    const source_ref = (try reference.parse("oci:test-oci-copy-merge-source:source", .source)).layout;
    const destination_ref = (try reference.parse("oci:test-oci-copy-merge-destination:new", .destination)).layout;
    var first = try localToLocal(io, allocator, source_ref, destination_ref, .{});
    defer first.deinit(allocator);
    var second = try localToLocal(io, allocator, source_ref, destination_ref, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), second.transferred);
    try std.testing.expect(second.reused >= 3);
    const index = try testRead(io, allocator, destination_path, "index.json");
    defer allocator.free(index);
    try std.testing.expect(std.mem.indexOf(u8, index, "\"x-extra\"") != null);
    var retained = try layout.Source.init(io, allocator, destination_path).resolve(
        (try reference.parse("oci:test-oci-copy-merge-destination:other", .source)).layout,
    );
    defer retained.deinit();
    try std.testing.expectError(error.InjectedFailure, localToLocal(
        io,
        allocator,
        source_ref,
        (try reference.parse("oci:test-oci-copy-failed-destination:new", .destination)).layout,
        .{ .failure_point = .before_index_publish },
    ));
    _ = std.Io.Dir.cwd().openDir(io, failed_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.TestUnexpectedResult;
}

test "copy rejects corrupt source and corrupt reusable destination blobs" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-corrupt-source";
    const destination_path = "test-oci-copy-corrupt-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    const source_root = try testMakeLayout(allocator, io, source_path, "source");
    defer allocator.free(source_root.digest);
    var source_dir = try std.Io.Dir.cwd().openDir(io, source_path, .{});
    defer source_dir.close(io);
    const source_digest = try content.Digest.parse(source_root.digest);
    const source_hex = source_digest.blobPathComponent();
    var source_blob: [80]u8 = undefined;
    const source_blob_path = try std.fmt.bufPrint(&source_blob, "blobs/sha256/{s}", .{source_hex});
    try source_dir.writeFile(io, .{ .sub_path = source_blob_path, .data = "corrupt" });
    try std.testing.expectError(error.CorruptBlob, localToLocal(
        io,
        allocator,
        (try reference.parse("oci:test-oci-copy-corrupt-source:source", .source)).layout,
        (try reference.parse("oci:test-oci-copy-corrupt-destination:new", .destination)).layout,
        .{},
    ));

    // A valid first copy must not make a later corruption look like a cache
    // miss: the bad digest path is an explicit destination error.
    const clean_source = "test-oci-copy-clean-source";
    const clean_destination = "test-oci-copy-clean-destination";
    defer testDeleteLayout(io, clean_source);
    defer testDeleteLayout(io, clean_destination);
    const clean_root = try testMakeLayout(allocator, io, clean_source, "source");
    defer allocator.free(clean_root.digest);
    const clean_ref = (try reference.parse("oci:test-oci-copy-clean-source:source", .source)).layout;
    const clean_dest_ref = (try reference.parse("oci:test-oci-copy-clean-destination:copy", .destination)).layout;
    var copied = try localToLocal(io, allocator, clean_ref, clean_dest_ref, .{});
    defer copied.deinit(allocator);
    var clean_dir = try std.Io.Dir.cwd().openDir(io, clean_destination, .{});
    defer clean_dir.close(io);
    const clean_digest = try content.Digest.parse(clean_root.digest);
    const clean_hex = clean_digest.blobPathComponent();
    var clean_path: [80]u8 = undefined;
    try clean_dir.writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&clean_path, "blobs/sha256/{s}", .{clean_hex}), .data = "bad" });
    try std.testing.expectError(error.CorruptBlob, localToLocal(io, allocator, clean_ref, clean_dest_ref, .{}));
}

test "copy streams content blobs larger than the transfer buffer" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-large-source";
    const destination_path = "test-oci-copy-large-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    const small_root = try testMakeLayout(allocator, io, source_path, "small");
    defer allocator.free(small_root.digest);
    var source_dir = try std.Io.Dir.cwd().openDir(io, source_path, .{});
    defer source_dir.close(io);
    const payload = try allocator.alloc(u8, 64 * 1024 * 3 + 17);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i);
    const layer = try testDescriptor(allocator, model.media_type_oci_layer, payload);
    defer allocator.free(layer.digest);
    try testWriteBlob(io, source_dir, layer, payload);
    const config = try testDescriptor(allocator, model.media_type_oci_config, "{}");
    defer allocator.free(config.digest);
    const manifest = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}", .{ config.mediaType.?, config.digest, config.size, layer.mediaType.?, layer.digest, layer.size });
    defer allocator.free(manifest);
    const root = try testDescriptor(allocator, model.media_type_oci_manifest, manifest);
    defer allocator.free(root.digest);
    try testWriteBlob(io, source_dir, root, manifest);
    const index = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"large\"}}}}]}}", .{ root.mediaType.?, root.digest, root.size });
    defer allocator.free(index);
    try source_dir.writeFile(io, .{ .sub_path = "index.json", .data = index });
    var result = try localToLocal(
        io,
        allocator,
        (try reference.parse("oci:test-oci-copy-large-source:large", .source)).layout,
        (try reference.parse("oci:test-oci-copy-large-destination:large", .destination)).layout,
        .{},
    );
    defer result.deinit(allocator);
    try std.testing.expect(result.transferred >= 3);
    const copied_payload = try testBlobBytes(io, allocator, destination_path, layer);
    defer allocator.free(copied_payload);
    try std.testing.expectEqualSlices(u8, payload, copied_payload);
    try std.testing.expectEqual(layout.BlobState.valid, try layout.Source.init(io, allocator, destination_path).blobState(layer));
}

test "copy preserves the existing index when publication is injected to fail" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-index-failure-source";
    const destination_path = "test-oci-copy-index-failure-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    const source_root = try testMakeLayout(allocator, io, source_path, "source");
    defer allocator.free(source_root.digest);
    const old_root = try testMakeLayout(allocator, io, destination_path, "old");
    defer allocator.free(old_root.digest);
    const before = try testRead(io, allocator, destination_path, "index.json");
    defer allocator.free(before);
    try std.testing.expectError(error.InjectedFailure, localToLocal(
        io,
        allocator,
        (try reference.parse("oci:test-oci-copy-index-failure-source:source", .source)).layout,
        (try reference.parse("oci:test-oci-copy-index-failure-destination:new", .destination)).layout,
        .{ .failure_point = .before_index_publish },
    ));
    const after = try testRead(io, allocator, destination_path, "index.json");
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    var old = try layout.Source.init(io, allocator, destination_path).resolve(
        (try reference.parse("oci:test-oci-copy-index-failure-destination:old", .source)).layout,
    );
    defer old.deinit();
}

test "copy cleans synced temporary files and preserves the old index on failure" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-sync-failure-source";
    const destination_path = "test-oci-copy-sync-failure-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    const source_root = try testMakePlatformLayout(allocator, io, source_path, "source", "{\"os\":\"linux\",\"architecture\":\"amd64\"}");
    defer allocator.free(source_root.digest);
    const old_root = try testMakeLayout(allocator, io, destination_path, "old");
    defer allocator.free(old_root.digest);
    const source = (try reference.parse("oci:test-oci-copy-sync-failure-source:source", .source)).layout;
    const destination = (try reference.parse("oci:test-oci-copy-sync-failure-destination:new", .destination)).layout;
    const before = try testRead(io, allocator, destination_path, "index.json");
    defer allocator.free(before);
    try std.testing.expectError(error.InjectedFailure, localToLocal(io, allocator, source, destination, .{
        .failure_point = .after_blob_temp_sync,
    }));
    try testExpectNoTempFiles(io, destination_path, "blobs/sha256");
    const after_blob = try testRead(io, allocator, destination_path, "index.json");
    defer allocator.free(after_blob);
    try std.testing.expectEqualSlices(u8, before, after_blob);
    try std.testing.expectError(error.InjectedFailure, localToLocal(io, allocator, source, destination, .{
        .failure_point = .after_index_temp_sync,
    }));
    try testExpectNoTempFiles(io, destination_path, ".");
    const after_index = try testRead(io, allocator, destination_path, "index.json");
    defer allocator.free(after_index);
    try std.testing.expectEqualSlices(u8, before, after_index);
    var old = try layout.Source.init(io, allocator, destination_path).resolve(
        (try reference.parse("oci:test-oci-copy-sync-failure-destination:old", .source)).layout,
    );
    defer old.deinit();
}

test "explicit platform selection verifies the selected config" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const match_source = "test-oci-copy-platform-config-match-source";
    const mismatch_source = "test-oci-copy-platform-config-mismatch-source";
    const match_destination = "test-oci-copy-platform-config-match-destination";
    const mismatch_destination = "test-oci-copy-platform-config-mismatch-destination";
    defer testDeleteLayout(io, match_source);
    defer testDeleteLayout(io, mismatch_source);
    defer testDeleteLayout(io, match_destination);
    defer testDeleteLayout(io, mismatch_destination);
    const matching = try testMakePlatformLayout(allocator, io, match_source, "single", "{\"os\":\"linux\",\"architecture\":\"amd64\",\"variant\":\"v3\"}");
    defer allocator.free(matching.digest);
    const mismatching = try testMakePlatformLayout(allocator, io, mismatch_source, "single", "{\"os\":\"linux\",\"architecture\":\"arm64\"}");
    defer allocator.free(mismatching.digest);
    const options = Options{
        .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64", .variant = "v3" } },
        .platform_selection_explicit = true,
    };
    var copied = try localToLocal(
        io,
        allocator,
        (try reference.parse("oci:test-oci-copy-platform-config-match-source:single", .source)).layout,
        (try reference.parse("oci:test-oci-copy-platform-config-match-destination:single", .destination)).layout,
        options,
    );
    defer copied.deinit(allocator);
    try std.testing.expectError(error.PlatformConfigMismatch, localToLocal(
        io,
        allocator,
        (try reference.parse("oci:test-oci-copy-platform-config-mismatch-source:single", .source)).layout,
        (try reference.parse("oci:test-oci-copy-platform-config-mismatch-destination:single", .destination)).layout,
        options,
    ));
}

test "copy rejects conflicting descriptors for the same digest" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-conflicting-descriptor-source";
    const destination_path = "test-oci-copy-conflicting-descriptor-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    try std.Io.Dir.cwd().createDirPath(io, source_path);
    var dir = try std.Io.Dir.cwd().openDir(io, source_path, .{});
    defer dir.close(io);
    try dir.createDirPath(io, "blobs/sha256");
    try dir.writeFile(io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}" });
    const shared = try testDescriptor(allocator, model.media_type_oci_config, "{}");
    defer allocator.free(shared.digest);
    try testWriteBlob(io, dir, shared, "{}");
    const manifest = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}", .{
        model.media_type_oci_config,
        shared.digest,
        shared.size,
        model.media_type_oci_layer,
        shared.digest,
        shared.size,
    });
    defer allocator.free(manifest);
    const root = try testDescriptor(allocator, model.media_type_oci_manifest, manifest);
    defer allocator.free(root.digest);
    try testWriteBlob(io, dir, root, manifest);
    const index = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"conflict\"}}}}]}}", .{ root.mediaType.?, root.digest, root.size });
    defer allocator.free(index);
    try dir.writeFile(io, .{ .sub_path = "index.json", .data = index });
    try std.testing.expectError(error.ConflictingDescriptor, localToLocal(
        io,
        allocator,
        (try reference.parse("oci:test-oci-copy-conflicting-descriptor-source:conflict", .source)).layout,
        (try reference.parse("oci:test-oci-copy-conflicting-descriptor-destination:conflict", .destination)).layout,
        .{},
    ));
}

test "digest layout destinations reject a different planned root before transfer" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-digest-mismatch-source";
    const destination_path = "test-oci-copy-digest-mismatch-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    const root = try testMakeLayout(allocator, io, source_path, "source");
    defer allocator.free(root.digest);
    const requested = try content.Digest.parse(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    try std.testing.expectError(error.DescriptorMismatch, localToLocal(
        io,
        allocator,
        .{ .path = source_path, .selection = .{ .tag = "source" } },
        .{ .path = destination_path, .selection = .{ .digest = requested } },
        .{},
    ));
    try testExpectMissingLayout(io, destination_path);
}

test "digest layout destinations reject conflicting existing descriptors before transfer" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-digest-conflict-source";
    const destination_path = "test-oci-copy-digest-conflict-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    const root = try testMakeLayout(allocator, io, source_path, "source");
    defer allocator.free(root.digest);
    try std.Io.Dir.cwd().createDirPath(io, destination_path);
    var destination_dir = try std.Io.Dir.cwd().openDir(io, destination_path, .{});
    defer destination_dir.close(io);
    try destination_dir.createDirPath(io, "blobs/sha256");
    try destination_dir.writeFile(io, .{
        .sub_path = "oci-layout",
        .data = "{\"imageLayoutVersion\":\"1.0.0\"}",
    });
    const index = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ root.mediaType.?, root.digest, root.size + 1 },
    );
    defer allocator.free(index);
    try destination_dir.writeFile(io, .{ .sub_path = "index.json", .data = index });
    const requested = try content.Digest.parse(root.digest);
    try std.testing.expectError(error.ConflictingDescriptor, localToLocal(
        io,
        allocator,
        .{ .path = source_path, .selection = .{ .tag = "source" } },
        .{ .path = destination_path, .selection = .{ .digest = requested } },
        .{},
    ));
    const media_conflict_index = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ model.media_type_oci_index, root.digest, root.size },
    );
    defer allocator.free(media_conflict_index);
    try destination_dir.writeFile(io, .{
        .sub_path = "index.json",
        .data = media_conflict_index,
    });
    try std.testing.expectError(error.ConflictingDescriptor, localToLocal(
        io,
        allocator,
        .{ .path = source_path, .selection = .{ .tag = "source" } },
        .{ .path = destination_path, .selection = .{ .digest = requested } },
        .{},
    ));
    var blobs = try destination_dir.openDir(io, "blobs/sha256", .{ .iterate = true });
    defer blobs.close(io);
    var iterator = blobs.iterate();
    try std.testing.expect((try iterator.next(io)) == null);
}

test "unannotated and digest destinations merge idempotently" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-idempotent-source";
    const plain_destination = "test-oci-copy-idempotent-plain";
    const digest_destination = "test-oci-copy-idempotent-digest";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, plain_destination);
    defer testDeleteLayout(io, digest_destination);
    const root = try testMakeLayout(allocator, io, source_path, "source");
    defer allocator.free(root.digest);
    const plain_source = reference.LayoutReference{ .path = source_path, .selection = .{ .tag = "source" } };
    const plain_dest = reference.LayoutReference{ .path = plain_destination, .selection = null };
    var first = try localToLocal(io, allocator, plain_source, plain_dest, .{});
    defer first.deinit(allocator);
    var second = try localToLocal(io, allocator, plain_source, plain_dest, .{});
    defer second.deinit(allocator);
    const plain_output = try testRead(io, allocator, plain_destination, "index.json");
    defer allocator.free(plain_output);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(plain_output, root.digest));
    try std.testing.expect(std.mem.indexOf(u8, plain_output, "org.opencontainers.image.ref.name") == null);
    const digest = try content.Digest.parse(root.digest);
    const digest_source = reference.LayoutReference{ .path = source_path, .selection = .{ .digest = digest } };
    const digest_dest = reference.LayoutReference{ .path = digest_destination, .selection = .{ .digest = digest } };
    var digest_first = try localToLocal(io, allocator, digest_source, digest_dest, .{});
    defer digest_first.deinit(allocator);
    var digest_second = try localToLocal(io, allocator, digest_source, digest_dest, .{});
    defer digest_second.deinit(allocator);
    const digest_output = try testRead(io, allocator, digest_destination, "index.json");
    defer allocator.free(digest_output);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(digest_output, root.digest));
}

test "selected copy materializes a leaf while all copy retains the index bytes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-platform-source";
    const all_path = "test-oci-copy-platform-all";
    const selected_path = "test-oci-copy-platform-selected";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, all_path);
    defer testDeleteLayout(io, selected_path);
    const manifest = try testMakeLayout(allocator, io, source_path, "single");
    defer allocator.free(manifest.digest);
    const original = try testBlobBytes(io, allocator, source_path, manifest);
    defer allocator.free(original);
    const alternate_bytes = try std.mem.concat(allocator, u8, &.{ original, " " });
    defer allocator.free(alternate_bytes);
    const alternate = try testDescriptor(allocator, model.media_type_oci_manifest, alternate_bytes);
    defer allocator.free(alternate.digest);
    var source_dir = try std.Io.Dir.cwd().openDir(io, source_path, .{});
    defer source_dir.close(io);
    try testWriteBlob(io, source_dir, alternate, alternate_bytes);
    const index_bytes = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"urls\":[\"https://example.invalid/blob\"],\"data\":\"opaque\",\"artifactType\":\"example/type\",\"annotations\":{{\"org.example.keep\":\"yes\"}},\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\",\"variant\":\"v3\"}},\"x-descriptor-extension\":{{\"kept\":true}}}},{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"platform\":{{\"os\":\"linux\",\"architecture\":\"arm64\"}}}}]}}", .{ model.media_type_oci_index, manifest.mediaType.?, manifest.digest, manifest.size, alternate.mediaType.?, alternate.digest, alternate.size });
    defer allocator.free(index_bytes);
    const root = try testDescriptor(allocator, model.media_type_oci_index, index_bytes);
    defer allocator.free(root.digest);
    try testWriteBlob(io, source_dir, root, index_bytes);
    const top_level = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"multi\"}}}}]}}", .{ root.mediaType.?, root.digest, root.size });
    defer allocator.free(top_level);
    try source_dir.writeFile(io, .{ .sub_path = "index.json", .data = top_level });
    const source_ref = (try reference.parse("oci:test-oci-copy-platform-source:multi", .source)).layout;
    var all = try localToLocal(io, allocator, source_ref, (try reference.parse("oci:test-oci-copy-platform-all:multi", .destination)).layout, .{});
    defer all.deinit(allocator);
    try std.testing.expectEqualStrings(root.digest, all.root.digest);
    var selected = try localToLocal(io, allocator, source_ref, (try reference.parse("oci:test-oci-copy-platform-selected:amd", .destination)).layout, .{
        .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } },
    });
    defer selected.deinit(allocator);
    try std.testing.expectEqualStrings(manifest.digest, selected.root.digest);
    var selected_root = try layout.Source.init(io, allocator, selected_path).resolve(
        (try reference.parse("oci:test-oci-copy-platform-selected:amd", .source)).layout,
    );
    defer selected_root.deinit();
    try std.testing.expectEqualStrings(manifest.digest, selected_root.descriptor.digest);
    const selected_index = try testRead(io, allocator, selected_path, "index.json");
    defer allocator.free(selected_index);
    try std.testing.expect(std.mem.indexOf(u8, selected_index, "\"x-descriptor-extension\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, selected_index, "\"org.example.keep\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, selected_index, "\"urls\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, selected_index, "\"data\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, selected_index, "\"artifactType\"") != null);
}

test "selected copy rejects opaque matches and ambiguous platformless indexes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const opaque_source = "test-oci-copy-selected-opaque-source";
    const ambiguous_source = "test-oci-copy-selected-ambiguous-source";
    const destination = "test-oci-copy-selected-rejection-destination";
    defer testDeleteLayout(io, opaque_source);
    defer testDeleteLayout(io, ambiguous_source);
    defer testDeleteLayout(io, destination);
    const opaque_manifest = try testMakeLayout(allocator, io, opaque_source, "single");
    defer allocator.free(opaque_manifest.digest);
    var opaque_dir = try std.Io.Dir.cwd().openDir(io, opaque_source, .{});
    defer opaque_dir.close(io);
    const opaque_blob = try testDescriptor(allocator, "application/example", "opaque");
    defer allocator.free(opaque_blob.digest);
    try testWriteBlob(io, opaque_dir, opaque_blob, "opaque");
    const opaque_index = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/example\",\"digest\":\"{s}\",\"size\":{d},\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}}]}}", .{ opaque_blob.digest, opaque_blob.size });
    defer allocator.free(opaque_index);
    const opaque_root = try testDescriptor(allocator, model.media_type_oci_index, opaque_index);
    defer allocator.free(opaque_root.digest);
    try testWriteBlob(io, opaque_dir, opaque_root, opaque_index);
    const opaque_top = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"multi\"}}}}]}}", .{ opaque_root.mediaType.?, opaque_root.digest, opaque_root.size });
    defer allocator.free(opaque_top);
    try opaque_dir.writeFile(io, .{ .sub_path = "index.json", .data = opaque_top });
    const platform_options = Options{ .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } } };
    try std.testing.expectError(error.UnsupportedSelectedObject, localToLocal(
        io,
        allocator,
        (try reference.parse("oci:test-oci-copy-selected-opaque-source:multi", .source)).layout,
        (try reference.parse("oci:test-oci-copy-selected-rejection-destination:opaque", .destination)).layout,
        platform_options,
    ));

    const manifest = try testMakeLayout(allocator, io, ambiguous_source, "single");
    defer allocator.free(manifest.digest);
    var ambiguous_dir = try std.Io.Dir.cwd().openDir(io, ambiguous_source, .{});
    defer ambiguous_dir.close(io);
    const nested_one_bytes = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}}]}}", .{ manifest.mediaType.?, manifest.digest, manifest.size });
    defer allocator.free(nested_one_bytes);
    const nested_two_bytes = try std.mem.concat(allocator, u8, &.{ nested_one_bytes, " " });
    defer allocator.free(nested_two_bytes);
    const nested_one = try testDescriptor(allocator, model.media_type_oci_index, nested_one_bytes);
    defer allocator.free(nested_one.digest);
    const nested_two = try testDescriptor(allocator, model.media_type_oci_index, nested_two_bytes);
    defer allocator.free(nested_two.digest);
    try testWriteBlob(io, ambiguous_dir, nested_one, nested_one_bytes);
    try testWriteBlob(io, ambiguous_dir, nested_two, nested_two_bytes);
    const outer_bytes = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}", .{
        nested_one.mediaType.?,
        nested_one.digest,
        nested_one.size,
        nested_two.mediaType.?,
        nested_two.digest,
        nested_two.size,
    });
    defer allocator.free(outer_bytes);
    const outer = try testDescriptor(allocator, model.media_type_oci_index, outer_bytes);
    defer allocator.free(outer.digest);
    try testWriteBlob(io, ambiguous_dir, outer, outer_bytes);
    const top = try std.fmt.allocPrint(allocator, "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"multi\"}}}}]}}", .{ outer.mediaType.?, outer.digest, outer.size });
    defer allocator.free(top);
    try ambiguous_dir.writeFile(io, .{ .sub_path = "index.json", .data = top });
    try std.testing.expectError(error.AmbiguousPlatform, localToLocal(
        io,
        allocator,
        (try reference.parse("oci:test-oci-copy-selected-ambiguous-source:multi", .source)).layout,
        (try reference.parse("oci:test-oci-copy-selected-rejection-destination:ambiguous", .destination)).layout,
        platform_options,
    ));
}

test "concurrent first writers retain both references through bootstrap lock" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-concurrent-source";
    const destination_path = "test-oci-copy-concurrent-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    const source_root = try testMakeLayout(allocator, io, source_path, "source");
    defer allocator.free(source_root.digest);
    var gate = StartGate{};
    var first = CopyThread{ .source_path = source_path, .destination_path = destination_path, .destination_name = "one", .gate = &gate };
    var second = CopyThread{ .source_path = source_path, .destination_path = destination_path, .destination_name = "two", .gate = &gate };
    var first_thread = try std.Thread.spawn(.{}, CopyThread.run, .{&first});
    var second_thread = try std.Thread.spawn(.{}, CopyThread.run, .{&second});
    gate.releaseWhenReady();
    first_thread.join();
    second_thread.join();
    try std.testing.expect(first.ok);
    try std.testing.expect(second.ok);
    var one = try layout.Source.init(io, allocator, destination_path).resolve(
        (try reference.parse("oci:test-oci-copy-concurrent-destination:one", .source)).layout,
    );
    defer one.deinit();
    var two = try layout.Source.init(io, allocator, destination_path).resolve(
        (try reference.parse("oci:test-oci-copy-concurrent-destination:two", .source)).layout,
    );
    defer two.deinit();
    try std.testing.expectEqual(layout.BlobState.valid, try layout.Source.init(io, allocator, destination_path).blobState(source_root));
}

test "concurrent existing-layout writers copy missing source blobs and retain both references" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-oci-copy-concurrent-existing-source";
    const destination_path = "test-oci-copy-concurrent-existing-destination";
    defer testDeleteLayout(io, source_path);
    defer testDeleteLayout(io, destination_path);
    const source_root = try testMakePlatformLayout(allocator, io, source_path, "source", "{\"os\":\"linux\",\"architecture\":\"amd64\"}");
    defer allocator.free(source_root.digest);
    const old_root = try testMakeLayout(allocator, io, destination_path, "existing");
    defer allocator.free(old_root.digest);
    try std.testing.expectEqual(layout.BlobState.missing, try layout.Source.init(io, allocator, destination_path).blobState(source_root));
    var gate = StartGate{};
    var first = CopyThread{ .source_path = source_path, .destination_path = destination_path, .destination_name = "one", .gate = &gate };
    var second = CopyThread{ .source_path = source_path, .destination_path = destination_path, .destination_name = "two", .gate = &gate };
    var first_thread = try std.Thread.spawn(.{}, CopyThread.run, .{&first});
    var second_thread = try std.Thread.spawn(.{}, CopyThread.run, .{&second});
    gate.releaseWhenReady();
    first_thread.join();
    second_thread.join();
    try std.testing.expect(first.ok);
    try std.testing.expect(second.ok);
    var one = try layout.Source.init(io, allocator, destination_path).resolve(.{ .path = destination_path, .selection = .{ .tag = "one" } });
    defer one.deinit();
    var two = try layout.Source.init(io, allocator, destination_path).resolve(.{ .path = destination_path, .selection = .{ .tag = "two" } });
    defer two.deinit();
    try std.testing.expectEqual(layout.BlobState.valid, try layout.Source.init(io, allocator, destination_path).blobState(source_root));
    var source_manifest = try std.json.parseFromSlice(model.Manifest, allocator, one.bytes, .{ .ignore_unknown_fields = true });
    defer source_manifest.deinit();
    try std.testing.expectEqual(layout.BlobState.valid, try layout.Source.init(io, allocator, destination_path).blobState(source_manifest.value.config));
}

const StartGate = struct {
    ready: std.atomic.Value(u8) = .init(0),
    released: std.atomic.Value(bool) = .init(false),

    fn wait(self: *StartGate) void {
        _ = self.ready.fetchAdd(1, .release);
        while (!self.released.load(.acquire)) std.atomic.spinLoopHint();
    }

    fn releaseWhenReady(self: *StartGate) void {
        while (self.ready.load(.acquire) < 2) std.atomic.spinLoopHint();
        self.released.store(true, .release);
    }
};

const CopyThread = struct {
    source_path: []const u8,
    destination_path: []const u8,
    destination_name: []const u8,
    gate: *StartGate,
    ok: bool = true,

    fn run(self: *CopyThread) void {
        self.gate.wait();
        const source = reference.LayoutReference{
            .path = self.source_path,
            .selection = .{ .tag = "source" },
        };
        const destination = reference.LayoutReference{
            .path = self.destination_path,
            .selection = .{ .tag = self.destination_name },
        };
        _ = localToLocal(std.testing.io, std.heap.page_allocator, source, destination, .{}) catch {
            self.ok = false;
        };
    }
};

fn testRead(io: std.Io, allocator: std.mem.Allocator, layout_path: []const u8, relative: []const u8) ![]u8 {
    var dir = try std.Io.Dir.cwd().openDir(io, layout_path, .{});
    defer dir.close(io);
    var file = try dir.openFile(io, relative, .{});
    defer file.close(io);
    const size = try file.length(io);
    const bytes = try allocator.alloc(u8, @intCast(size));
    errdefer allocator.free(bytes);
    _ = try file.readPositionalAll(io, bytes, 0);
    return bytes;
}

fn testBlobBytes(io: std.Io, allocator: std.mem.Allocator, layout_path: []const u8, descriptor: model.Descriptor) ![]u8 {
    const digest = try content.Digest.parse(descriptor.digest);
    const hex = digest.blobPathComponent();
    var path: [80]u8 = undefined;
    return testRead(io, allocator, layout_path, try std.fmt.bufPrint(&path, "blobs/sha256/{s}", .{hex}));
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var count: usize = 0;
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, offset, needle)) |found| {
        count += 1;
        offset = found + needle.len;
    }
    return count;
}

fn testDeleteLayout(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, path) catch {};
    const parent = std.fs.path.dirname(path) orelse ".";
    const base = std.fs.path.basename(path);
    var dir = std.Io.Dir.cwd().openDir(io, parent, .{}) catch return;
    defer dir.close(io);
    var lock_name: [512]u8 = undefined;
    const name = std.fmt.bufPrint(&lock_name, ".{s}.miz-oci-bootstrap.lock", .{base}) catch return;
    dir.deleteFile(io, name) catch {};
}

fn testExpectMissingLayout(io: std.Io, path: []const u8) !void {
    var directory = std.Io.Dir.cwd().openDir(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    directory.close(io);
    return error.TestUnexpectedResult;
}

fn testExpectNoTempFiles(io: std.Io, layout_path: []const u8, relative: []const u8) !void {
    var layout_dir = try std.Io.Dir.cwd().openDir(io, layout_path, .{ .iterate = true });
    defer layout_dir.close(io);
    if (std.mem.eql(u8, relative, ".")) {
        var iterator = layout_dir.iterate();
        while (try iterator.next(io)) |entry| {
            try std.testing.expect(!std.mem.startsWith(u8, entry.name, ".miz-oci-"));
        }
    } else {
        var dir = try layout_dir.openDir(io, relative, .{ .iterate = true });
        defer dir.close(io);
        var iterator = dir.iterate();
        while (try iterator.next(io)) |entry| {
            try std.testing.expect(!std.mem.startsWith(u8, entry.name, ".miz-oci-"));
        }
    }
}
