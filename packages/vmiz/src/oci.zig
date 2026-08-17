//! Local container image ingestion and layer flattening.
//!
//! Scope / limitations:
//!  - `load()` auto-detects OCI image-layout directories and docker/podman
//!    save tarballs on local disk.
//!  - Supports uncompressed, gzip-compressed, and zstd-compressed tar layers.
//!  - `loadLayout()` remains available for callers that explicitly require
//!    an OCI image-layout directory.
//!  - Docker save tarballs may select a manifest entry by exact `RepoTags`
//!    match via `LoadOptions.repo_tag`; otherwise the first entry is loaded.
//!  - Local loaders retain their historical single-manifest behavior.
//!    Registry reads and graph-aware layout copies are exposed through the
//!    `registry`, `copy`, and `reference` submodules.

const std = @import("std");
const Io = std.Io;
const tar = @import("tar.zig");
pub const content = @import("oci/content.zig");
pub const model = @import("oci/model.zig");

const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;

pub const reference = @import("oci/reference.zig");
pub const layout = @import("oci/layout.zig");
pub const copy = @import("oci/copy.zig");
pub const image_resolver = @import("oci/image.zig");
pub const layer = @import("oci/layer.zig");
pub const filesystem = @import("oci/filesystem.zig");
pub const runtime_config = @import("oci/runtime_config.zig");
pub const bundle = @import("oci/bundle.zig");
pub const snapshot = @import("oci/snapshot.zig");
pub const repack = @import("oci/repack.zig");
pub const auth = @import("oci/auth.zig");
pub const registry = @import("oci/registry.zig");
pub const cosign = @import("oci/cosign.zig");
pub const cosign_discovery = @import("oci/cosign_discovery.zig");
pub const Digest = content.Digest;
pub const ContentVerifier = content.Verifier;
pub const Descriptor = model.Descriptor;
pub const Platform = model.Platform;
pub const Index = model.Index;
pub const Manifest = model.Manifest;
pub const ConfigPlatform = model.ConfigPlatform;
pub const ImageConfigPlatform = model.ImageConfigPlatform;
pub const MediaTypeClass = model.MediaTypeClass;
pub const classifyMediaType = model.classifyMediaType;
pub const parseReference = reference.parse;
pub const Reference = reference.Reference;
pub const ParseMode = reference.ParseMode;
pub const LayoutSource = layout.Source;
pub const LayoutDestination = layout.Destination;
pub const copyLocalToLocal = copy.localToLocal;
pub const RegistrySource = registry.Source;
pub const RegistryDestination = registry.Destination;
pub const RegistryOptions = registry.Options;
pub const RegistryTagList = registry.TagList;
pub const RegistryInspectResult = registry.InspectResult;
pub const RegistryInspectOptions = registry.InspectOptions;
pub const RegistryPin = registry.Pin;
pub const pinRegistryImage = registry.pinReference;
pub const copyRegistryToLayout = registry.Source.copyToLayout;
pub const copyRegistryToRegistry = registry.Source.copyToRegistry;
pub const copyLayoutToRegistry = registry.copyLayoutToRegistry;

test {
    std.testing.refAllDecls(image_resolver);
    std.testing.refAllDecls(layer);
    std.testing.refAllDecls(filesystem);
    std.testing.refAllDecls(runtime_config);
    std.testing.refAllDecls(bundle);
    std.testing.refAllDecls(snapshot);
    std.testing.refAllDecls(repack);
}

pub const EntryKind = enum {
    file,
    directory,
    symlink,
    hardlink,
};

pub const Xattr = struct {
    name: []const u8,
    value: []const u8,
};

pub const FileTree = struct {
    allocator: Allocator,
    entries: []Entry,

    pub const Entry = struct {
        path: []const u8,
        kind: EntryKind,
        mode: u32,
        uid: u32 = 0,
        gid: u32 = 0,
        size: u64,
        link_name: ?[]const u8 = null,
        content: []const u8 = &.{},
        xattrs: []const Xattr = &.{},

        pub fn reader(self: Entry) Io.Reader {
            return .fixed(self.content);
        }
    };

    pub const Iterator = struct {
        entries: []const Entry,
        index: usize = 0,

        pub fn next(self: *Iterator) ?Entry {
            if (self.index >= self.entries.len) return null;
            defer self.index += 1;
            return self.entries[self.index];
        }
    };

    pub fn deinit(self: *FileTree) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.path);
            if (entry.link_name) |link_name| self.allocator.free(link_name);
            if (entry.kind == .file) self.allocator.free(entry.content);
            freeXattrs(self.allocator, entry.xattrs);
        }
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn iterator(self: FileTree) Iterator {
        return .{ .entries = self.entries };
    }

    pub fn get(self: FileTree, path: []const u8) ?Entry {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.path, path)) return entry;
        }
        return null;
    }
};

fn freeXattrs(allocator: Allocator, xattrs: []const Xattr) void {
    if (xattrs.len == 0) return;
    for (xattrs) |xattr| {
        allocator.free(xattr.name);
        allocator.free(xattr.value);
    }
    allocator.free(xattrs);
}

fn dupeTarXattrs(allocator: Allocator, xattrs: []const tar.Xattr) ![]const Xattr {
    if (xattrs.len == 0) return &.{};
    const owned = try allocator.alloc(Xattr, xattrs.len);
    var completed: usize = 0;
    errdefer {
        for (owned[0..completed]) |xattr| {
            allocator.free(xattr.name);
            allocator.free(xattr.value);
        }
        allocator.free(owned);
    }
    for (xattrs, 0..) |xattr, index| {
        const name = try allocator.dupe(u8, xattr.name);
        const value = allocator.dupe(u8, xattr.value) catch |err| {
            allocator.free(name);
            return err;
        };
        owned[index] = .{
            .name = name,
            .value = value,
        };
        completed += 1;
    }
    return owned;
}

pub const Config = struct {
    architecture: ?[]const u8 = null,
    os: ?[]const u8 = null,
    manifest_digest: []const u8,
};

pub const Image = struct {
    allocator: Allocator,
    config: Config,
    tree: FileTree,

    pub fn deinit(self: *Image) void {
        if (self.config.architecture) |architecture| self.allocator.free(architecture);
        if (self.config.os) |os| self.allocator.free(os);
        self.allocator.free(self.config.manifest_digest);
        self.tree.deinit();
        self.* = undefined;
    }

    pub fn iterator(self: Image) FileTree.Iterator {
        return self.tree.iterator();
    }

    pub fn get(self: Image, path: []const u8) ?FileTree.Entry {
        return self.tree.get(path);
    }
};

pub const LoadOptions = struct {
    /// Selects an OCI image-layout manifest by exact digest match.
    ///
    /// Docker/podman save archives do not expose per-entry manifest digests in
    /// `manifest.json`; use `repo_tag` to select those entries instead.
    manifest_digest: ?[]const u8 = null,
    /// Selects a docker/podman save manifest entry by exact `RepoTags` match.
    ///
    /// When unset, docker/podman save archives continue to load the first
    /// manifest entry for backward compatibility.
    repo_tag: ?[]const u8 = null,
    max_blob_size: usize = 64 * 1024 * 1024,
    max_layer_size: usize = 128 * 1024 * 1024,
    max_archive_size: usize = 512 * 1024 * 1024,
};

pub const LoadError = error{
    MissingOciLayout,
    MissingImageManifest,
    MissingDockerManifest,
    MissingDockerConfig,
    MissingDockerLayer,
    UnsupportedManifestList,
    UnsupportedDigestAlgorithm,
    UnsupportedLayerCompression,
    UnsupportedLayerMediaType,
    BlobTooLarge,
    LayerTooLarge,
    InvalidDigest,
    SizeMismatch,
    DigestMismatch,
    InvalidLayerPath,
    LayerDecompressionFailed,
} || model.ValidationError || Allocator.Error || Io.File.OpenError || Io.File.ReadPositionalError ||
    Io.File.StatError || Io.Dir.OpenError || std.json.ParseError(std.json.Scanner) ||
    tar.Error || error{StreamTooLong};

/// Auto-detects an OCI image-layout directory or docker/podman save tarball.
pub fn load(io: Io, allocator: Allocator, image_path: []const u8, options: LoadOptions) LoadError!Image {
    var image_dir = Io.Dir.cwd().openDir(io, image_path, .{}) catch |err| switch (err) {
        error.NotDir => return loadDockerSaveTarball(io, allocator, image_path, options),
        else => return err,
    };
    defer image_dir.close(io);
    return loadLayoutDir(io, allocator, image_dir, options);
}

/// Loads an OCI image-layout directory from local disk.
pub fn loadLayout(io: Io, allocator: Allocator, layout_path: []const u8, options: LoadOptions) LoadError!Image {
    var layout_dir = try Io.Dir.cwd().openDir(io, layout_path, .{});
    defer layout_dir.close(io);
    return loadLayoutDir(io, allocator, layout_dir, options);
}

/// Loads a docker/podman save tarball from local disk.
pub fn loadDockerSaveTarball(io: Io, allocator: Allocator, tarball_path: []const u8, options: LoadOptions) LoadError!Image {
    var tarball = try Io.Dir.cwd().openFile(io, tarball_path, .{});
    defer tarball.close(io);

    var archive = try tar.readFile(io, allocator, tarball, options.max_archive_size);
    defer archive.deinit(allocator);

    return loadDockerSaveArchive(allocator, archive.bytes, options);
}

fn loadLayoutDir(io: Io, allocator: Allocator, layout_dir: Io.Dir, options: LoadOptions) LoadError!Image {
    const layout_bytes = try readFileAtMost(io, allocator, layout_dir, "oci-layout", options.max_blob_size);
    defer allocator.free(layout_bytes);
    const parsed_layout = try std.json.parseFromSlice(LayoutFile, allocator, layout_bytes, .{ .ignore_unknown_fields = true });
    defer parsed_layout.deinit();
    if (parsed_layout.value.imageLayoutVersion.len == 0) return error.MissingOciLayout;

    const index_bytes = try readFileAtMost(io, allocator, layout_dir, "index.json", options.max_blob_size);
    defer allocator.free(index_bytes);
    const index = try std.json.parseFromSlice(IndexDocument, allocator, index_bytes, .{ .ignore_unknown_fields = true });
    defer index.deinit();
    try model.validateIndex(index.value);

    const manifest_desc = selectManifest(index.value, options.manifest_digest) orelse return error.MissingImageManifest;
    try model.validateRootDescriptor(manifest_desc);
    if (isManifestListMediaType(manifest_desc.mediaType)) return error.UnsupportedManifestList;

    const manifest_bytes = try readBlob(io, allocator, layout_dir, manifest_desc, options.max_blob_size);
    defer allocator.free(manifest_bytes);
    const manifest = try std.json.parseFromSlice(ManifestDocument, allocator, manifest_bytes, .{ .ignore_unknown_fields = true });
    defer manifest.deinit();
    try model.validateManifest(manifest.value);

    const config_bytes = try readBlob(io, allocator, layout_dir, manifest.value.config, options.max_blob_size);
    defer allocator.free(config_bytes);
    const config_doc = try std.json.parseFromSlice(ConfigDocument, allocator, config_bytes, .{ .ignore_unknown_fields = true });
    defer config_doc.deinit();

    var entry_map = StringHashMap(FileTree.Entry).init(allocator);
    var entry_map_owned = true;
    errdefer if (entry_map_owned) deinitEntryMap(&entry_map, allocator);

    for (manifest.value.layers) |layer_desc| {
        try applyLayer(io, allocator, layout_dir, &entry_map, layer_desc, options);
    }
    var tree = try finalizeTree(allocator, &entry_map);
    entry_map_owned = false;
    errdefer tree.deinit();

    return .{
        .allocator = allocator,
        .config = .{
            .architecture = if (config_doc.value.architecture) |value| try allocator.dupe(u8, value) else null,
            .os = if (config_doc.value.os) |value| try allocator.dupe(u8, value) else null,
            .manifest_digest = try allocator.dupe(u8, manifest_desc.digest),
        },
        .tree = tree,
    };
}

const LayoutFile = struct {
    imageLayoutVersion: []const u8,
};

const IndexDocument = model.Index;
const ManifestDocument = model.Manifest;

const DockerSaveManifestItem = struct {
    Config: []const u8,
    RepoTags: ?[]const []const u8 = null,
    Layers: []const []const u8,
};

const ConfigDocument = model.ConfigPlatform;

const ArchiveEntry = struct {
    kind: tar.Kind,
    content: []const u8,
};

const ArchiveIndex = struct {
    entries: StringHashMap(ArchiveEntry),

    fn init(allocator: Allocator, archive_bytes: []const u8) LoadError!ArchiveIndex {
        var entries = StringHashMap(ArchiveEntry).init(allocator);
        errdefer deinitArchiveEntries(&entries, allocator);

        var reader = tar.Reader.init(archive_bytes);
        while (try reader.next()) |entry| {
            const normalized_path = try normalizeArchivePath(allocator, entry.path);
            var path_owned = true;
            errdefer if (path_owned) allocator.free(normalized_path);

            if (entries.fetchRemove(normalized_path)) |removed| allocator.free(removed.key);
            try entries.put(normalized_path, .{
                .kind = entry.kind,
                .content = entry.content,
            });
            path_owned = false;
        }

        return .{ .entries = entries };
    }

    fn deinit(self: *ArchiveIndex, allocator: Allocator) void {
        deinitArchiveEntries(&self.entries, allocator);
        self.* = undefined;
    }

    fn getFile(self: ArchiveIndex, path: []const u8) ?ArchiveEntry {
        const entry = self.entries.get(path) orelse return null;
        return if (entry.kind == .file) entry else null;
    }
};

fn loadDockerSaveArchive(allocator: Allocator, archive_bytes: []const u8, options: LoadOptions) LoadError!Image {
    var archive = try ArchiveIndex.init(allocator, archive_bytes);
    defer archive.deinit(allocator);

    const manifest_file = archive.getFile("manifest.json") orelse return error.MissingDockerManifest;
    const manifest_doc = try std.json.parseFromSlice([]DockerSaveManifestItem, allocator, manifest_file.content, .{
        .ignore_unknown_fields = true,
    });
    defer manifest_doc.deinit();

    const manifest_entry = selectDockerSaveManifest(manifest_doc.value, options.repo_tag) orelse return error.MissingImageManifest;

    const config_path = try normalizeArchivePath(allocator, manifest_entry.Config);
    defer allocator.free(config_path);
    const config_file = archive.getFile(config_path) orelse return error.MissingDockerConfig;
    const config_doc = try std.json.parseFromSlice(ConfigDocument, allocator, config_file.content, .{
        .ignore_unknown_fields = true,
    });
    defer config_doc.deinit();

    var entry_map = StringHashMap(FileTree.Entry).init(allocator);
    var entry_map_owned = true;
    errdefer if (entry_map_owned) deinitEntryMap(&entry_map, allocator);

    for (manifest_entry.Layers) |layer_path_raw| {
        const layer_path = try normalizeArchivePath(allocator, layer_path_raw);
        defer allocator.free(layer_path);

        const layer_file = archive.getFile(layer_path) orelse return error.MissingDockerLayer;
        try applyLayerBytes(allocator, &entry_map, null, layer_file.content, options);
    }

    var tree = try finalizeTree(allocator, &entry_map);
    entry_map_owned = false;
    errdefer tree.deinit();

    const manifest_digest = try sha256DigestString(allocator, manifest_file.content);
    errdefer allocator.free(manifest_digest);

    return .{
        .allocator = allocator,
        .config = .{
            .architecture = if (config_doc.value.architecture) |value| try allocator.dupe(u8, value) else null,
            .os = if (config_doc.value.os) |value| try allocator.dupe(u8, value) else null,
            .manifest_digest = manifest_digest,
        },
        .tree = tree,
    };
}

fn selectDockerSaveManifest(
    manifests: []const DockerSaveManifestItem,
    requested_repo_tag: ?[]const u8,
) ?DockerSaveManifestItem {
    if (requested_repo_tag) |repo_tag| {
        for (manifests) |manifest| {
            const repo_tags = manifest.RepoTags orelse continue;
            for (repo_tags) |candidate| {
                if (std.mem.eql(u8, candidate, repo_tag)) return manifest;
            }
        }
        return null;
    }
    return if (manifests.len == 0) null else manifests[0];
}

fn selectManifest(index: IndexDocument, requested_digest: ?[]const u8) ?Descriptor {
    if (requested_digest) |digest| {
        for (index.manifests) |manifest| {
            if (std.mem.eql(u8, manifest.digest, digest)) return manifest;
        }
        return null;
    }
    return if (index.manifests.len == 0) null else index.manifests[0];
}

fn isManifestListMediaType(media_type: ?[]const u8) bool {
    return model.classifyMediaType(media_type).isIndex();
}

fn applyLayer(
    io: Io,
    allocator: Allocator,
    layout_dir: Io.Dir,
    entry_map: *StringHashMap(FileTree.Entry),
    layer_desc: Descriptor,
    options: LoadOptions,
) LoadError!void {
    if (layer_desc.mediaType) |media_type| {
        if (!isSupportedLayerMediaType(media_type)) return error.UnsupportedLayerMediaType;
    }
    const layer_blob = try readBlob(io, allocator, layout_dir, layer_desc, options.max_blob_size);
    defer allocator.free(layer_blob);

    try applyLayerBytes(allocator, entry_map, layer_desc.mediaType, layer_blob, options);
}

fn applyLayerBytes(
    allocator: Allocator,
    entry_map: *StringHashMap(FileTree.Entry),
    media_type: ?[]const u8,
    layer_blob: []const u8,
    options: LoadOptions,
) LoadError!void {
    const layer_bytes = switch (detectCompression(media_type, layer_blob)) {
        .none => if (layer_blob.len > options.max_layer_size) return error.LayerTooLarge else try allocator.dupe(u8, layer_blob),
        .gzip => try decompressGzip(allocator, layer_blob, options.max_layer_size),
        .zstd => try decompressZstd(allocator, layer_blob, options.max_layer_size),
    };
    defer allocator.free(layer_bytes);

    var lower_paths = std.array_list.Managed([]const u8).init(allocator);
    defer lower_paths.deinit();

    var existing_it = entry_map.iterator();
    while (existing_it.next()) |kv| {
        try lower_paths.append(kv.key_ptr.*);
    }

    var reader = tar.Reader.init(layer_bytes);
    while (try reader.next()) |layer_entry| {
        try applyLayerEntry(allocator, entry_map, lower_paths.items, layer_entry);
    }
}

const Compression = enum { none, gzip, zstd };

fn isSupportedLayerMediaType(media_type: []const u8) bool {
    return std.mem.eql(u8, media_type, "application/vnd.oci.image.layer.v1.tar") or
        std.mem.eql(u8, media_type, "application/vnd.oci.image.layer.v1.tar+gzip") or
        std.mem.eql(u8, media_type, "application/vnd.oci.image.layer.v1.tar+zstd") or
        std.mem.eql(u8, media_type, "application/vnd.oci.image.layer.nondistributable.v1.tar") or
        std.mem.eql(u8, media_type, "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip") or
        std.mem.eql(u8, media_type, "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd") or
        std.mem.eql(u8, media_type, "application/vnd.docker.image.rootfs.diff.tar") or
        std.mem.eql(u8, media_type, "application/vnd.docker.image.rootfs.diff.tar.gzip") or
        std.mem.eql(u8, media_type, "application/vnd.docker.image.rootfs.diff.tar.zstd") or
        std.mem.eql(u8, media_type, "application/vnd.docker.image.rootfs.foreign.diff.tar") or
        std.mem.eql(u8, media_type, "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip");
}

fn detectCompression(media_type: ?[]const u8, bytes: []const u8) Compression {
    if (media_type) |mt| {
        if (std.mem.indexOf(u8, mt, "+zstd") != null or std.mem.endsWith(u8, mt, ".zstd")) return .zstd;
        if (std.mem.indexOf(u8, mt, "+gzip") != null or std.mem.endsWith(u8, mt, ".gzip")) return .gzip;
    }
    if (bytes.len >= 4 and bytes[0] == 0x28 and bytes[1] == 0xb5 and bytes[2] == 0x2f and bytes[3] == 0xfd) return .zstd;
    if (bytes.len >= 2 and bytes[0] == 0x1f and bytes[1] == 0x8b) return .gzip;
    return .none;
}

fn decompressGzip(allocator: Allocator, bytes: []const u8, max_size: usize) LoadError![]u8 {
    var input = Io.Reader.fixed(bytes);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    return decompressor.reader.allocRemaining(allocator, .limited(max_size)) catch |err| switch (err) {
        error.ReadFailed => error.LayerDecompressionFailed,
        error.StreamTooLong => error.LayerTooLarge,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn decompressZstd(allocator: Allocator, bytes: []const u8, max_size: usize) LoadError![]u8 {
    var input = Io.Reader.fixed(bytes);
    // Indirect mode with an explicitly-sized window buffer -- the empty-
    // buffer "direct" mode used previously silently produced truncated/
    // corrupted output for some real, large zstd-compressed layers (see
    // packages/vmiz/src/verity_tooling.zig's decompressZstd, where the identical
    // pattern was found to misparse a real ~50+ MiB dracut-produced
    // initramfs while appearing to succeed).
    const window_len = std.compress.zstd.default_window_len;
    const window_buf = try allocator.alloc(u8, window_len + std.compress.zstd.block_size_max);
    defer allocator.free(window_buf);
    var decompressor = std.compress.zstd.Decompress.init(&input, window_buf, .{ .window_len = window_len });
    return decompressor.reader.allocRemaining(allocator, .limited(max_size)) catch |err| switch (err) {
        error.ReadFailed => error.LayerDecompressionFailed,
        error.StreamTooLong => error.LayerTooLarge,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn applyLayerEntry(
    allocator: Allocator,
    entry_map: *StringHashMap(FileTree.Entry),
    lower_paths: []const []const u8,
    layer_entry: tar.Entry,
) LoadError!void {
    const normalized_path = try normalizeLayerPath(allocator, layer_entry.path);
    defer allocator.free(normalized_path);

    if (normalized_path.len == 0) {
        if (layer_entry.kind == .directory) return;
        return error.InvalidLayerPath;
    }

    const dirname = parentPath(normalized_path);
    const basename = baseName(normalized_path);

    if (std.mem.eql(u8, basename, ".wh..wh..opq")) {
        try ensureParents(allocator, entry_map, dirname);
        if (dirname.len != 0) try ensureDirectory(allocator, entry_map, dirname, 0o755);
        try removeOpaqueLowerEntries(entry_map, allocator, lower_paths, dirname);
        return;
    }

    if (std.mem.startsWith(u8, basename, ".wh.") and basename.len > 4) {
        const target_path = try joinPath(allocator, dirname, basename[4..]);
        defer allocator.free(target_path);
        try removePathAndChildren(entry_map, allocator, target_path);
        return;
    }

    try ensureParents(allocator, entry_map, dirname);

    switch (layer_entry.kind) {
        .directory => {
            const owned_path = try allocator.dupe(u8, normalized_path);
            errdefer allocator.free(owned_path);
            const xattrs = try dupeTarXattrs(allocator, layer_entry.xattrs);
            errdefer freeXattrs(allocator, xattrs);
            try putEntry(allocator, entry_map, .{
                .path = owned_path,
                .kind = .directory,
                .mode = nonZeroMode(layer_entry.mode, 0o755),
                .uid = layer_entry.uid,
                .gid = layer_entry.gid,
                .size = 0,
                .xattrs = xattrs,
            });
        },
        .file => {
            const file_content = try allocator.dupe(u8, layer_entry.content);
            errdefer allocator.free(file_content);
            const owned_path = try allocator.dupe(u8, normalized_path);
            errdefer allocator.free(owned_path);
            const xattrs = try dupeTarXattrs(allocator, layer_entry.xattrs);
            errdefer freeXattrs(allocator, xattrs);
            try putEntry(allocator, entry_map, .{
                .path = owned_path,
                .kind = .file,
                .mode = nonZeroMode(layer_entry.mode, 0o644),
                .uid = layer_entry.uid,
                .gid = layer_entry.gid,
                .size = file_content.len,
                .content = file_content,
                .xattrs = xattrs,
            });
        },
        .symlink => {
            const link_name = try allocator.dupe(u8, layer_entry.link_name orelse return error.InvalidLayerPath);
            errdefer allocator.free(link_name);
            const owned_path = try allocator.dupe(u8, normalized_path);
            errdefer allocator.free(owned_path);
            const xattrs = try dupeTarXattrs(allocator, layer_entry.xattrs);
            errdefer freeXattrs(allocator, xattrs);
            try putEntry(allocator, entry_map, .{
                .path = owned_path,
                .kind = .symlink,
                .mode = nonZeroMode(layer_entry.mode, 0o777),
                .uid = layer_entry.uid,
                .gid = layer_entry.gid,
                .size = link_name.len,
                .link_name = link_name,
                .xattrs = xattrs,
            });
        },
        .hardlink => {
            const normalized_link_name = try normalizeLayerPath(
                allocator,
                layer_entry.link_name orelse return error.InvalidLayerPath,
            );
            defer allocator.free(normalized_link_name);
            if (normalized_link_name.len == 0) return error.InvalidLayerPath;
            const link_name = try allocator.dupe(u8, normalized_link_name);
            errdefer allocator.free(link_name);
            const owned_path = try allocator.dupe(u8, normalized_path);
            errdefer allocator.free(owned_path);
            const xattrs = try dupeTarXattrs(allocator, layer_entry.xattrs);
            errdefer freeXattrs(allocator, xattrs);
            try putEntry(allocator, entry_map, .{
                .path = owned_path,
                .kind = .hardlink,
                .mode = nonZeroMode(layer_entry.mode, 0o644),
                .uid = layer_entry.uid,
                .gid = layer_entry.gid,
                .size = 0,
                .link_name = link_name,
                .xattrs = xattrs,
            });
        },
        .character_device, .block_device, .fifo => return error.UnsupportedType,
    }
}

fn normalizeLayerPath(allocator: Allocator, raw_path: []const u8) LoadError![]u8 {
    var path = raw_path;
    while (std.mem.startsWith(u8, path, "./")) path = path[2..];
    while (path.len > 0 and path[0] == '/') path = path[1..];

    var trimmed = path;
    while (trimmed.len > 1 and trimmed[trimmed.len - 1] == '/') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }

    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();

    var first = true;
    var it = std.mem.splitScalar(u8, trimmed, '/');
    while (it.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) continue;
        if (std.mem.eql(u8, segment, "..")) return error.InvalidLayerPath;
        if (!first) out.writer.writeByte('/') catch return error.OutOfMemory;
        out.writer.writeAll(segment) catch return error.OutOfMemory;
        first = false;
    }

    return out.toOwnedSlice();
}

fn ensureParents(allocator: Allocator, entry_map: *StringHashMap(FileTree.Entry), path: []const u8) LoadError!void {
    if (path.len == 0) return;

    var cursor: usize = 0;
    while (cursor < path.len) {
        const slash = std.mem.indexOfScalarPos(u8, path, cursor, '/') orelse break;
        const parent = path[0..slash];
        try ensureDirectory(allocator, entry_map, parent, 0o755);
        cursor = slash + 1;
    }
    try ensureDirectory(allocator, entry_map, path, 0o755);
}

fn ensureDirectory(allocator: Allocator, entry_map: *StringHashMap(FileTree.Entry), path: []const u8, mode: u32) LoadError!void {
    if (path.len == 0) return;
    if (entry_map.getPtr(path)) |existing| {
        if (existing.kind == .directory) return;
    }

    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    try putEntry(allocator, entry_map, .{
        .path = owned_path,
        .kind = .directory,
        .mode = mode,
        .size = 0,
    });
}

/// On error, the caller retains ownership of every allocation in `entry`.
/// On success, `entry_map` owns the complete entry and frees it through
/// `freeEntry`. This makes allocation failures from descendant removal and
/// `entry_map.put` safe for all entry kinds and their xattrs.
fn putEntry(allocator: Allocator, entry_map: *StringHashMap(FileTree.Entry), entry: FileTree.Entry) LoadError!void {
    if (entry.kind != .directory) {
        try removeChildrenOnly(entry_map, allocator, entry.path);
    }
    if (entry_map.fetchRemove(entry.path)) |removed| {
        freeEntry(allocator, removed.value);
    }
    try entry_map.put(entry.path, entry);
}

fn removePathAndChildren(entry_map: *StringHashMap(FileTree.Entry), allocator: Allocator, path: []const u8) LoadError!void {
    var doomed = std.array_list.Managed([]const u8).init(allocator);
    defer doomed.deinit();

    var it = entry_map.iterator();
    while (it.next()) |kv| {
        const candidate = kv.key_ptr.*;
        if (std.mem.eql(u8, candidate, path) or isDescendant(candidate, path)) {
            try doomed.append(candidate);
        }
    }

    for (doomed.items) |candidate| {
        if (entry_map.fetchRemove(candidate)) |removed| freeEntry(allocator, removed.value);
    }
}

fn removeChildrenOnly(entry_map: *StringHashMap(FileTree.Entry), allocator: Allocator, path: []const u8) LoadError!void {
    var doomed = std.array_list.Managed([]const u8).init(allocator);
    defer doomed.deinit();

    var it = entry_map.iterator();
    while (it.next()) |kv| {
        const candidate = kv.key_ptr.*;
        if (isDescendant(candidate, path)) try doomed.append(candidate);
    }

    for (doomed.items) |candidate| {
        if (entry_map.fetchRemove(candidate)) |removed| freeEntry(allocator, removed.value);
    }
}

fn removeOpaqueLowerEntries(
    entry_map: *StringHashMap(FileTree.Entry),
    allocator: Allocator,
    lower_paths: []const []const u8,
    directory: []const u8,
) LoadError!void {
    for (lower_paths) |candidate| {
        if (directory.len == 0) {
            if (entry_map.fetchRemove(candidate)) |removed| freeEntry(allocator, removed.value);
            continue;
        }
        if (isDescendant(candidate, directory)) {
            if (entry_map.fetchRemove(candidate)) |removed| freeEntry(allocator, removed.value);
        }
    }
}

fn joinPath(allocator: Allocator, parent: []const u8, child: []const u8) LoadError![]u8 {
    if (parent.len == 0) return allocator.dupe(u8, child);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent, child });
}

fn isDescendant(candidate: []const u8, parent: []const u8) bool {
    return candidate.len > parent.len and
        std.mem.startsWith(u8, candidate, parent) and
        candidate[parent.len] == '/';
}

fn parentPath(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "";
    return path[0..slash];
}

fn baseName(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[slash + 1 ..];
}

fn nonZeroMode(mode: u32, fallback: u32) u32 {
    return if (mode == 0) fallback else mode;
}

fn freeEntry(allocator: Allocator, entry: FileTree.Entry) void {
    allocator.free(entry.path);
    if (entry.link_name) |link_name| allocator.free(link_name);
    if (entry.kind == .file) allocator.free(entry.content);
    freeXattrs(allocator, entry.xattrs);
}

fn deinitArchiveEntries(entries: *StringHashMap(ArchiveEntry), allocator: Allocator) void {
    var it = entries.iterator();
    while (it.next()) |kv| allocator.free(kv.key_ptr.*);
    entries.deinit();
}

fn deinitEntryMap(entry_map: *StringHashMap(FileTree.Entry), allocator: Allocator) void {
    var it = entry_map.iterator();
    while (it.next()) |kv| {
        freeEntry(allocator, kv.value_ptr.*);
    }
    entry_map.deinit();
}

fn finalizeTree(allocator: Allocator, entry_map: *StringHashMap(FileTree.Entry)) LoadError!FileTree {
    const entries = try allocator.alloc(FileTree.Entry, entry_map.count());
    errdefer allocator.free(entries);

    var iter = entry_map.iterator();
    var index_out: usize = 0;
    while (iter.next()) |kv| {
        entries[index_out] = kv.value_ptr.*;
        index_out += 1;
    }
    entry_map.deinit();
    errdefer {
        var tree = FileTree{ .allocator = allocator, .entries = entries };
        tree.deinit();
    }

    std.mem.sort(FileTree.Entry, entries, {}, struct {
        fn lessThan(_: void, a: FileTree.Entry, b: FileTree.Entry) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lessThan);

    return .{ .allocator = allocator, .entries = entries };
}

fn normalizeArchivePath(allocator: Allocator, raw_path: []const u8) LoadError![]u8 {
    return normalizeLayerPath(allocator, raw_path);
}

fn readBlob(io: Io, allocator: Allocator, layout_dir: Io.Dir, descriptor: Descriptor, max_size: usize) LoadError![]u8 {
    const digest = content.Digest.parse(descriptor.digest) catch |err| switch (err) {
        error.UnsupportedDigestAlgorithm => return error.UnsupportedDigestAlgorithm,
        error.InvalidDigest => return error.InvalidDigest,
        else => unreachable,
    };
    if (descriptor.size > max_size) return error.BlobTooLarge;
    const hex = digest.blobPathComponent();
    const path = try std.fmt.allocPrint(allocator, "blobs/sha256/{s}", .{hex});
    defer allocator.free(path);
    const bytes = try readFileAtMost(io, allocator, layout_dir, path, max_size);
    errdefer allocator.free(bytes);
    content.verifyBytes(digest, descriptor.size, bytes) catch |err| switch (err) {
        error.SizeMismatch => return error.SizeMismatch,
        error.DigestMismatch => return error.DigestMismatch,
        error.SizeOverflow => return error.SizeMismatch,
        error.InvalidDigest => unreachable,
        error.UnsupportedDigestAlgorithm => unreachable,
    };
    return bytes;
}

fn readFileAtMost(io: Io, allocator: Allocator, dir: Io.Dir, sub_path: []const u8, max_size: usize) LoadError![]u8 {
    var file = try dir.openFile(io, sub_path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.size > max_size) return error.BlobTooLarge;
    const bytes = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(bytes);
    _ = try file.readPositionalAll(io, bytes, 0);
    return bytes;
}

fn sha256DigestString(allocator: Allocator, data: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{hex});
}

test "load auto-detects OCI layouts and merges gzip layers, whiteouts, and opaque directories" {
    const io = std.testing.io;
    const fixture_root = "test-oci-layout-fixture";
    defer Io.Dir.cwd().deleteTree(io, fixture_root) catch {};

    var fixture = try createFixtureLayout(std.testing.allocator, io, fixture_root, .gzip);
    defer fixture.deinit(std.testing.allocator);

    var image = try load(io, std.testing.allocator, fixture_root, .{});
    defer image.deinit();

    try expectMergedFixtureImage(image);

    var iter = image.iterator();
    var seen: usize = 0;
    while (iter.next()) |_| seen += 1;
    try std.testing.expect(seen >= 7);
}

test "bundle unpack securely publishes a verified runtime bundle" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture_root = "test-oci-bundle-layout";
    const bundle_root = "test-oci-runtime-bundle";
    defer Io.Dir.cwd().deleteTree(io, fixture_root) catch {};
    defer Io.Dir.cwd().deleteTree(io, bundle_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, ".test-oci-runtime-bundle.vmiz-bundle.lock") catch {};

    var fixture = try createFixtureLayout(allocator, io, fixture_root, .gzip);
    defer fixture.deinit(allocator);
    const source_reference = "oci:test-oci-bundle-layout";
    const parsed = try reference.parse(source_reference, .source);
    const image_ref = switch (parsed) {
        .layout => |value| value,
        else => unreachable,
    };
    const result = try bundle.unpackLayout(
        allocator,
        io,
        source_reference,
        image_ref,
        bundle_root,
        .{ .platform = .{ .os = "linux", .architecture = "amd64" } },
    );
    try std.testing.expectEqualStrings(fixture.manifest_digest, result.digest());

    var published = try Io.Dir.cwd().openDir(io, bundle_root, .{});
    defer published.close(io);
    const hello = try published.readFileAlloc(io, "rootfs/hello.txt", allocator, .limited(1024));
    defer allocator.free(hello);
    try std.testing.expectEqualStrings("hello from top\n", hello);
    try std.testing.expectError(
        error.FileNotFound,
        published.statFile(io, "rootfs/etc/remove.txt", .{}),
    );
    _ = try published.statFile(io, "config.json", .{});
    _ = try published.statFile(io, ".vmiz/base.json", .{});
    _ = try published.statFile(io, ".vmiz/metadata.json", .{});
    try published.writeFile(io, .{ .sub_path = "stale", .data = "old" });
    published.close(io);

    try std.testing.expectError(
        error.BundleExists,
        bundle.unpackLayout(
            allocator,
            io,
            source_reference,
            image_ref,
            bundle_root,
            .{ .platform = .{ .os = "linux", .architecture = "amd64" } },
        ),
    );
    _ = try bundle.unpackLayout(
        allocator,
        io,
        source_reference,
        image_ref,
        bundle_root,
        .{
            .platform = .{ .os = "linux", .architecture = "amd64" },
            .force = true,
        },
    );
    published = try Io.Dir.cwd().openDir(io, bundle_root, .{});
    try std.testing.expectError(error.FileNotFound, published.statFile(io, "stale", .{}));
    try published.writeFile(io, .{ .sub_path = "survives-failure", .data = "old" });
    published.close(io);
    try std.testing.expectError(
        error.InjectedFailure,
        bundle.unpackLayout(
            allocator,
            io,
            source_reference,
            image_ref,
            bundle_root,
            .{
                .platform = .{ .os = "linux", .architecture = "amd64" },
                .force = true,
                .failure_point = .before_publish,
            },
        ),
    );
    published = try Io.Dir.cwd().openDir(io, bundle_root, .{});
    _ = try published.statFile(io, "survives-failure", .{});
}

test "forced bundle unpack rejects a symlink destination" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture_root = "test-oci-bundle-symlink-layout";
    const outside_root = "test-oci-bundle-symlink-outside";
    const bundle_link = "test-oci-bundle-symlink-destination";
    defer Io.Dir.cwd().deleteTree(io, fixture_root) catch {};
    defer Io.Dir.cwd().deleteTree(io, outside_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, bundle_link) catch {};
    defer Io.Dir.cwd().deleteFile(io, ".test-oci-bundle-symlink-destination.vmiz-bundle.lock") catch {};
    Io.Dir.cwd().deleteFile(io, bundle_link) catch {};
    try Io.Dir.cwd().createDir(io, outside_root, .fromMode(0o755));
    try Io.Dir.cwd().symLink(io, outside_root, bundle_link, .{});

    var fixture = try createFixtureLayout(allocator, io, fixture_root, .gzip);
    defer fixture.deinit(allocator);
    const source_text = "oci:test-oci-bundle-symlink-layout";
    const source = (try reference.parse(source_text, .source)).layout;
    try std.testing.expectError(
        error.BundleNotDirectory,
        bundle.unpackLayout(
            allocator,
            io,
            source_text,
            source,
            bundle_link,
            .{
                .platform = .{ .os = "linux", .architecture = "amd64" },
                .force = true,
            },
        ),
    );
    const outside = try Io.Dir.cwd().statFile(io, outside_root, .{});
    try std.testing.expectEqual(@as(u32, 0o755), @intFromEnum(outside.permissions) & 0o7777);
}

test "bundle repack publishes deterministic additions changes and whiteouts" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture_root = "test-oci-repack-layout";
    const bundle_root = "test-oci-repack-bundle";
    const verify_root = "test-oci-repack-verify";
    defer Io.Dir.cwd().deleteTree(io, fixture_root) catch {};
    defer Io.Dir.cwd().deleteTree(io, bundle_root) catch {};
    defer Io.Dir.cwd().deleteTree(io, verify_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, ".test-oci-repack-bundle.vmiz-bundle.lock") catch {};
    defer Io.Dir.cwd().deleteFile(io, ".test-oci-repack-verify.vmiz-bundle.lock") catch {};
    defer Io.Dir.cwd().deleteFile(io, ".test-oci-repack-layout.vmiz-oci-bootstrap.lock") catch {};

    var fixture = try createFixtureLayout(allocator, io, fixture_root, .gzip);
    defer fixture.deinit(allocator);
    const source_text = "oci:test-oci-repack-layout";
    const source = (try reference.parse(source_text, .source)).layout;
    _ = try bundle.unpackLayout(
        allocator,
        io,
        source_text,
        source,
        bundle_root,
        .{ .platform = .{ .os = "linux", .architecture = "amd64" } },
    );

    var editable = try Io.Dir.cwd().openDir(io, bundle_root ++ "/rootfs", .{});
    defer editable.close(io);
    {
        var editable_root = try Io.Dir.cwd().openFile(io, bundle_root ++ "/rootfs", .{
            .allow_directory = true,
        });
        defer editable_root.close(io);
        try editable_root.setPermissions(io, .fromMode(0o750));
    }
    try editable.writeFile(io, .{ .sub_path = "hello.txt", .data = "edited\n" });
    try editable.deleteFile(io, "etc/keep.txt");
    try editable.writeFile(io, .{ .sub_path = "added.txt", .data = "new\n" });
    if (@import("builtin").os.tag == .linux) {
        var added_file = try editable.openFile(io, "added.txt", .{});
        defer added_file.close(io);
        const xattr_result = std.os.linux.fsetxattr(
            added_file.handle,
            "user.vmiz",
            "round-trip",
            "round-trip".len,
            0,
        );
        try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(xattr_result));
    }

    const failed_target = (try reference.parse(
        "oci:test-oci-repack-layout:interrupted",
        .destination,
    )).layout;
    try std.testing.expectError(
        error.InjectedFailure,
        repack.repackLayout(allocator, io, failed_target, bundle_root, .{
            .failure_point = .before_commit,
        }),
    );
    try std.testing.expectError(
        error.RootNotFound,
        layout.Source.init(io, allocator, fixture_root).resolve(failed_target),
    );

    const target = (try reference.parse(
        "oci:test-oci-repack-layout:edited",
        .destination,
    )).layout;
    const repacked = try repack.repackLayout(allocator, io, target, bundle_root, .{});
    try std.testing.expect(!std.mem.eql(u8, fixture.manifest_digest, repacked.digest()));
    const repeated_target = (try reference.parse(
        "oci:test-oci-repack-layout:edited-again",
        .destination,
    )).layout;
    const repeated = try repack.repackLayout(allocator, io, repeated_target, bundle_root, .{});
    try std.testing.expectEqualStrings(repacked.digest(), repeated.digest());

    const original_ref = reference.LayoutReference{
        .path = fixture_root,
        .selection = .{
            .digest = try content.Digest.parse(fixture.manifest_digest),
        },
    };
    const original_root = try layout.Source.init(io, allocator, fixture_root).resolve(original_ref);
    var original = original_root;
    defer original.deinit();
    try std.testing.expectEqualStrings(fixture.manifest_digest, original.descriptor.digest);

    _ = try bundle.unpackLayout(
        allocator,
        io,
        "oci:test-oci-repack-layout:edited",
        target,
        verify_root,
        .{ .platform = .{ .os = "linux", .architecture = "amd64" } },
    );
    var verified = try Io.Dir.cwd().openDir(io, verify_root ++ "/rootfs", .{});
    defer verified.close(io);
    const edited = try verified.readFileAlloc(io, "hello.txt", allocator, .limited(32));
    defer allocator.free(edited);
    try std.testing.expectEqualStrings("edited\n", edited);
    const added = try verified.readFileAlloc(io, "added.txt", allocator, .limited(32));
    defer allocator.free(added);
    try std.testing.expectEqualStrings("new\n", added);
    if (@import("builtin").os.tag == .linux) {
        var added_file = try verified.openFile(io, "added.txt", .{});
        defer added_file.close(io);
        var value: [32]u8 = undefined;
        const xattr_result = std.os.linux.fgetxattr(
            added_file.handle,
            "user.vmiz",
            &value,
            value.len,
        );
        try std.testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(xattr_result));
        try std.testing.expectEqualStrings("round-trip", value[0..xattr_result]);
    }
    const verified_root = try verified.stat(io);
    try std.testing.expectEqual(@as(u32, 0o750), @intFromEnum(verified_root.permissions) & 0o7777);
    try std.testing.expectError(error.FileNotFound, verified.statFile(io, "etc/keep.txt", .{}));
    try verified.writeFile(io, .{ .sub_path = ".wh.reserved", .data = "not a whiteout" });
    const reserved_target = (try reference.parse(
        "oci:test-oci-repack-layout:reserved",
        .destination,
    )).layout;
    try std.testing.expectError(
        error.ReservedWhiteoutPath,
        repack.repackLayout(allocator, io, reserved_target, verify_root, .{}),
    );
}

test "load auto-detects docker save tarballs and merges whiteouts" {
    const io = std.testing.io;
    const fixture_path = "test-docker-save-fixture.tar";
    defer Io.Dir.cwd().deleteFile(io, fixture_path) catch {};

    try createDockerSaveFixture(std.testing.allocator, io, fixture_path);

    var image = try load(io, std.testing.allocator, fixture_path, .{});
    defer image.deinit();

    try std.testing.expectEqualStrings("amd64", image.config.architecture.?);
    try std.testing.expectEqualStrings("linux", image.config.os.?);
    try std.testing.expect(std.mem.startsWith(u8, image.config.manifest_digest, "sha256:"));
    try expectMergedFixtureImage(image);
}

test "load selects docker save manifest entries by repo tag and defaults to the first entry" {
    const io = std.testing.io;
    const fixture_path = "test-docker-save-multi-fixture.tar";
    defer Io.Dir.cwd().deleteFile(io, fixture_path) catch {};

    try createDockerSaveMultiManifestFixture(std.testing.allocator, io, fixture_path);

    var default_image = try load(io, std.testing.allocator, fixture_path, .{});
    defer default_image.deinit();
    try expectMergedFixtureImage(default_image);

    var selected_image = try load(io, std.testing.allocator, fixture_path, .{
        .repo_tag = "example.com/alt:latest",
    });
    defer selected_image.deinit();

    try std.testing.expectEqualStrings("arm64", selected_image.config.architecture.?);
    try std.testing.expectEqualStrings("linux", selected_image.config.os.?);
    try std.testing.expectEqualStrings("hello from alt\n", selected_image.get("hello.txt").?.content);
    try std.testing.expectEqualStrings("selected from alt\n", selected_image.get("alt.txt").?.content);
    try std.testing.expect(selected_image.get("etc/keep.txt") == null);
}

test "loadLayout merges zstd-compressed OCI layers" {
    const io = std.testing.io;
    const fixture_root = "test-oci-layout-zstd-fixture";
    defer Io.Dir.cwd().deleteTree(io, fixture_root) catch {};

    var fixture = try createFixtureLayout(std.testing.allocator, io, fixture_root, .zstd);
    defer fixture.deinit(std.testing.allocator);

    var image = try loadLayout(io, std.testing.allocator, fixture_root, .{});
    defer image.deinit();

    try expectMergedFixtureImage(image);
}

test "loadLayout rejects corrupted manifest, config, and layer blobs" {
    const io = std.testing.io;
    const fixture_root = "test-oci-layout-corruption-fixture";
    defer Io.Dir.cwd().deleteTree(io, fixture_root) catch {};

    {
        var fixture = try createFixtureLayout(std.testing.allocator, io, fixture_root, .gzip);
        defer fixture.deinit(std.testing.allocator);
        try corruptFixtureBlob(io, fixture_root, fixture.manifest_digest, fixture.manifest_json);
        try std.testing.expectError(error.DigestMismatch, loadLayout(io, std.testing.allocator, fixture_root, .{}));
    }
    try Io.Dir.cwd().deleteTree(io, fixture_root);

    {
        var fixture = try createFixtureLayout(std.testing.allocator, io, fixture_root, .gzip);
        defer fixture.deinit(std.testing.allocator);
        try corruptFixtureBlob(io, fixture_root, fixture.config_digest, fixture.config_json);
        try std.testing.expectError(error.DigestMismatch, loadLayout(io, std.testing.allocator, fixture_root, .{}));
    }
    try Io.Dir.cwd().deleteTree(io, fixture_root);

    {
        var fixture = try createFixtureLayout(std.testing.allocator, io, fixture_root, .gzip);
        defer fixture.deinit(std.testing.allocator);
        try corruptFixtureBlob(io, fixture_root, fixture.layer1_digest, fixture.layer1_blob);
        try std.testing.expectError(error.DigestMismatch, loadLayout(io, std.testing.allocator, fixture_root, .{}));
    }
}

test "loadLayout preserves digest algorithm and malformed digest errors" {
    const io = std.testing.io;
    const fixture_root = "test-oci-layout-digest-errors";
    defer Io.Dir.cwd().deleteTree(io, fixture_root) catch {};

    {
        var fixture = try createFixtureLayout(std.testing.allocator, io, fixture_root, .gzip);
        defer fixture.deinit(std.testing.allocator);
        try writeFixtureIndex(io, fixture_root,
            \\{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","size":1}]}
        );
        try std.testing.expectError(error.UnsupportedDigestAlgorithm, loadLayout(io, std.testing.allocator, fixture_root, .{}));
    }
    try Io.Dir.cwd().deleteTree(io, fixture_root);

    {
        var fixture = try createFixtureLayout(std.testing.allocator, io, fixture_root, .gzip);
        defer fixture.deinit(std.testing.allocator);
        try writeFixtureIndex(io, fixture_root,
            \\{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:not-hex","size":1}]}
        );
        try std.testing.expectError(error.InvalidDigest, loadLayout(io, std.testing.allocator, fixture_root, .{}));
    }
}

test "loadLayout validates OCI schema and descriptor media types" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const fixture_root = "test-oci-layout-model-validation";
    defer Io.Dir.cwd().deleteTree(io, fixture_root) catch {};

    {
        var fixture = try createFixtureLayout(allocator, io, fixture_root, .gzip);
        defer fixture.deinit(allocator);
        try writeFixtureIndex(io, fixture_root, "{\"schemaVersion\":1,\"manifests\":[]}");
        try std.testing.expectError(error.InvalidSchemaVersion, loadLayout(io, allocator, fixture_root, .{}));
    }
    try Io.Dir.cwd().deleteTree(io, fixture_root);

    {
        var fixture = try createFixtureLayout(allocator, io, fixture_root, .gzip);
        defer fixture.deinit(allocator);
        const index_json = try std.fmt.allocPrint(
            allocator,
            "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.docker.distribution.manifest.v1+json\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
            .{ fixture.manifest_digest, fixture.manifest_json.len },
        );
        defer allocator.free(index_json);
        try writeFixtureIndex(io, fixture_root, index_json);
        try std.testing.expectError(error.UnsupportedDescriptorMediaType, loadLayout(io, allocator, fixture_root, .{}));
    }
    try Io.Dir.cwd().deleteTree(io, fixture_root);

    {
        var fixture = try createFixtureLayout(allocator, io, fixture_root, .gzip);
        defer fixture.deinit(allocator);
        var dir = try Io.Dir.cwd().openDir(io, fixture_root, .{});
        defer dir.close(io);
        const invalid_manifest = try std.fmt.allocPrint(
            allocator,
            "{{\"schemaVersion\":1,\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[]}}",
            .{ fixture.config_digest, fixture.config_json.len },
        );
        defer allocator.free(invalid_manifest);
        const manifest_digest = try writeBlobAndDigest(allocator, io, dir, invalid_manifest);
        defer allocator.free(manifest_digest);
        const index_json = try std.fmt.allocPrint(
            allocator,
            "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
            .{ manifest_digest, invalid_manifest.len },
        );
        defer allocator.free(index_json);
        try dir.writeFile(io, .{ .sub_path = "index.json", .data = index_json });
        try std.testing.expectError(error.InvalidSchemaVersion, loadLayout(io, allocator, fixture_root, .{}));
    }
}

test "OCI layers preserve ownership and PAX xattrs across whiteouts and hardlinks" {
    const allocator = std.testing.allocator;
    const uid = try buildPaxRecord(allocator, "uid", "321");
    defer allocator.free(uid);
    const gid = try buildPaxRecord(allocator, "gid", "654");
    defer allocator.free(gid);
    const capability = try buildPaxRecord(allocator, "SCHILY.xattr.security.capability", "cap-v3");
    defer allocator.free(capability);
    const base_pax = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ uid, gid, capability });
    defer allocator.free(base_pax);

    const hardlink_uid = try buildPaxRecord(allocator, "uid", "777");
    defer allocator.free(hardlink_uid);
    const hardlink_xattr = try buildPaxRecord(allocator, "SCHILY.xattr.user.hardlink", "metadata");
    defer allocator.free(hardlink_xattr);
    const hardlink_pax = try std.fmt.allocPrint(allocator, "{s}{s}", .{ hardlink_uid, hardlink_xattr });
    defer allocator.free(hardlink_pax);

    const layer_one = try buildTarArchive(allocator, &.{
        .{ .path = "PaxHeaders/source", .mode = 0o644, .typeflag = 'x', .content = base_pax, .link_name = null },
        .{ .path = "source", .mode = 0o640, .uid = 1, .gid = 2, .typeflag = '0', .content = "source-bytes", .link_name = null },
        .{ .path = "remove-me", .mode = 0o600, .uid = 44, .gid = 55, .typeflag = '0', .content = "remove", .link_name = null },
    });
    defer allocator.free(layer_one);
    const layer_two = try buildTarArchive(allocator, &.{
        .{ .path = ".wh.remove-me", .mode = 0, .typeflag = '0', .content = "", .link_name = null },
        .{ .path = "PaxHeaders/hard", .mode = 0o644, .typeflag = 'x', .content = hardlink_pax, .link_name = null },
        .{ .path = "hard", .mode = 0o640, .gid = 888, .typeflag = '1', .content = "", .link_name = "./source" },
    });
    defer allocator.free(layer_two);

    var map = StringHashMap(FileTree.Entry).init(allocator);
    var map_owned = true;
    defer if (map_owned) deinitEntryMap(&map, allocator);
    try applyLayerBytes(allocator, &map, null, layer_one, .{});
    try applyLayerBytes(allocator, &map, null, layer_two, .{});
    var tree = try finalizeTree(allocator, &map);
    map_owned = false;
    defer tree.deinit();

    try std.testing.expect(tree.get("remove-me") == null);
    const source = tree.get("source").?;
    try std.testing.expectEqual(@as(u32, 321), source.uid);
    try std.testing.expectEqual(@as(u32, 654), source.gid);
    try std.testing.expectEqual(@as(usize, 1), source.xattrs.len);
    try std.testing.expectEqualStrings("security.capability", source.xattrs[0].name);
    const hard = tree.get("hard").?;
    try std.testing.expectEqual(EntryKind.hardlink, hard.kind);
    try std.testing.expectEqual(@as(u32, 777), hard.uid);
    try std.testing.expectEqual(@as(u32, 888), hard.gid);
    try std.testing.expectEqualStrings("source", hard.link_name.?);
    try std.testing.expectEqualStrings("user.hardlink", hard.xattrs[0].name);
}

test "OCI parent synthesis does not overwrite lower directory metadata" {
    const allocator = std.testing.allocator;
    const lower_uid = try buildPaxRecord(allocator, "uid", "444");
    defer allocator.free(lower_uid);
    const lower_gid = try buildPaxRecord(allocator, "gid", "555");
    defer allocator.free(lower_gid);
    const lower_xattr = try buildPaxRecord(allocator, "SCHILY.xattr.user.lower", "preserve");
    defer allocator.free(lower_xattr);
    const lower_pax = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ lower_uid, lower_gid, lower_xattr });
    defer allocator.free(lower_pax);
    const upper_uid = try buildPaxRecord(allocator, "uid", "0");
    defer allocator.free(upper_uid);
    const upper_xattr = try buildPaxRecord(allocator, "SCHILY.xattr.user.upper", "replace");
    defer allocator.free(upper_xattr);
    const upper_pax = try std.fmt.allocPrint(allocator, "{s}{s}", .{ upper_uid, upper_xattr });
    defer allocator.free(upper_pax);

    const lower = try buildTarArchive(allocator, &.{
        .{ .path = "PaxHeaders/private", .mode = 0o644, .typeflag = 'x', .content = lower_pax, .link_name = null },
        .{ .path = "private/", .mode = 0o700, .typeflag = '5', .content = "", .link_name = null },
    });
    defer allocator.free(lower);
    const child_only_upper = try buildTarArchive(allocator, &.{
        .{ .path = "private/child", .mode = 0o644, .typeflag = '0', .content = "child", .link_name = null },
    });
    defer allocator.free(child_only_upper);
    const explicit_upper = try buildTarArchive(allocator, &.{
        .{ .path = "PaxHeaders/private", .mode = 0o644, .typeflag = 'x', .content = upper_pax, .link_name = null },
        .{ .path = "private/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
    });
    defer allocator.free(explicit_upper);

    var map = StringHashMap(FileTree.Entry).init(allocator);
    var map_owned = true;
    defer if (map_owned) deinitEntryMap(&map, allocator);
    try applyLayerBytes(allocator, &map, null, lower, .{});
    try applyLayerBytes(allocator, &map, null, child_only_upper, .{});
    const preserved = map.get("private").?;
    try std.testing.expectEqual(@as(u32, 0o700), preserved.mode);
    try std.testing.expectEqual(@as(u32, 444), preserved.uid);
    try std.testing.expectEqual(@as(u32, 555), preserved.gid);
    try std.testing.expectEqualStrings("user.lower", preserved.xattrs[0].name);

    try applyLayerBytes(allocator, &map, null, explicit_upper, .{});
    var tree = try finalizeTree(allocator, &map);
    map_owned = false;
    defer tree.deinit();
    const replaced = tree.get("private").?;
    try std.testing.expectEqual(@as(u32, 0o755), replaced.mode);
    try std.testing.expectEqual(@as(u32, 0), replaced.uid);
    try std.testing.expectEqual(@as(usize, 1), replaced.xattrs.len);
    try std.testing.expectEqualStrings("user.upper", replaced.xattrs[0].name);
    try std.testing.expectEqualStrings("child", tree.get("private/child").?.content);
}

fn applySingleEntryForAllocationTest(allocator: Allocator, entry: tar.Entry) !void {
    var map = StringHashMap(FileTree.Entry).init(allocator);
    defer deinitEntryMap(&map, allocator);
    try applyLayerEntry(allocator, &map, &.{}, entry);
}

test "OCI putEntry callers retain ownership through allocation failures" {
    const xattrs = [_]tar.Xattr{.{ .name = "user.allocation", .value = "metadata" }};
    const entries = [_]tar.Entry{
        .{ .path = "directory", .kind = .directory, .mode = 0o700, .uid = 42, .gid = 43, .size = 0, .content = "", .xattrs = &xattrs },
        .{ .path = "file", .kind = .file, .mode = 0o640, .uid = 42, .gid = 43, .size = 7, .content = "payload", .xattrs = &xattrs },
        .{ .path = "symlink", .kind = .symlink, .mode = 0o777, .uid = 42, .gid = 43, .size = 4, .content = "", .link_name = "file", .xattrs = &xattrs },
        .{ .path = "hardlink", .kind = .hardlink, .mode = 0o640, .uid = 42, .gid = 43, .size = 0, .content = "", .link_name = "file", .xattrs = &xattrs },
    };

    for (entries) |entry| {
        var saw_success = false;
        var failure_index: usize = 0;
        while (failure_index < 64 and !saw_success) : (failure_index += 1) {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
                .fail_index = failure_index,
            });
            const allocator = failing.allocator();
            applySingleEntryForAllocationTest(allocator, entry) catch |err| {
                try std.testing.expectEqual(error.OutOfMemory, err);
                try std.testing.expect(failing.has_induced_failure);
                try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
                continue;
            };
            saw_success = true;
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        }
        try std.testing.expect(saw_success);
    }
}

fn replaceDirectoryWithFileForAllocationTest(allocator: Allocator) !void {
    var map = StringHashMap(FileTree.Entry).init(allocator);
    defer deinitEntryMap(&map, allocator);
    try applyLayerEntry(allocator, &map, &.{}, .{
        .path = "parent/child",
        .kind = .file,
        .mode = 0o644,
        .size = 5,
        .content = "child",
    });
    try applyLayerEntry(allocator, &map, &.{}, .{
        .path = "parent",
        .kind = .file,
        .mode = 0o600,
        .size = 6,
        .content = "parent",
    });
}

test "OCI putEntry retains caller cleanup through descendant removal and map insertion failures" {
    var saw_success = false;
    var failure_index: usize = 0;
    while (failure_index < 64 and !saw_success) : (failure_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
            .fail_index = failure_index,
        });
        const allocator = failing.allocator();
        replaceDirectoryWithFileForAllocationTest(allocator) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            continue;
        };
        saw_success = true;
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
    try std.testing.expect(saw_success);
}

const FixtureLayout = struct {
    layer1_tar: []u8,
    layer2_tar: []u8,
    layer1_blob: []u8,
    layer2_blob: []u8,
    config_digest: []u8,
    layer1_digest: []u8,
    layer2_digest: []u8,
    manifest_digest: []u8,
    config_json: []u8,
    manifest_json: []u8,
    index_json: []u8,

    fn deinit(self: *FixtureLayout, allocator: Allocator) void {
        allocator.free(self.layer1_tar);
        allocator.free(self.layer2_tar);
        allocator.free(self.layer1_blob);
        allocator.free(self.layer2_blob);
        allocator.free(self.config_digest);
        allocator.free(self.layer1_digest);
        allocator.free(self.layer2_digest);
        allocator.free(self.manifest_digest);
        allocator.free(self.config_json);
        allocator.free(self.manifest_json);
        allocator.free(self.index_json);
        self.* = undefined;
    }
};

const FixtureCompression = enum { gzip, zstd };

fn createFixtureLayout(allocator: Allocator, io: Io, root: []const u8, compression: FixtureCompression) !FixtureLayout {
    try Io.Dir.cwd().createDirPath(io, root);
    var dir = try Io.Dir.cwd().openDir(io, root, .{});
    defer dir.close(io);
    try dir.createDirPath(io, "blobs/sha256");

    const layer1_tar = try buildTarArchive(allocator, &.{
        .{ .path = "etc/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "etc/keep.txt", .mode = 0o644, .typeflag = '0', .content = "keep from base\n", .link_name = null },
        .{ .path = "etc/remove.txt", .mode = 0o644, .typeflag = '0', .content = "remove me\n", .link_name = null },
        .{ .path = "etc/opaque/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "etc/opaque/from-base.txt", .mode = 0o644, .typeflag = '0', .content = "base hidden\n", .link_name = null },
        .{ .path = "hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from base\n", .link_name = null },
        .{ .path = "links/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "links/config", .mode = 0o777, .typeflag = '2', .content = "", .link_name = "../etc/keep.txt" },
    });
    const layer2_tar = try buildTarArchive(allocator, &.{
        .{ .path = "etc/.wh.remove.txt", .mode = 0o000, .typeflag = '0', .content = "", .link_name = null },
        .{ .path = "etc/opaque/.wh..wh..opq", .mode = 0o000, .typeflag = '0', .content = "", .link_name = null },
        .{ .path = "etc/opaque/from-top.txt", .mode = 0o644, .typeflag = '0', .content = "top survives\n", .link_name = null },
        .{ .path = "hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from top\n", .link_name = null },
    });

    const layer1_blob = try compressFixtureLayer(allocator, compression, layer1_tar);
    const layer2_blob = try compressFixtureLayer(allocator, compression, layer2_tar);
    const layer1_diff_id = try sha256DigestString(allocator, layer1_tar);
    defer allocator.free(layer1_diff_id);
    const layer2_diff_id = try sha256DigestString(allocator, layer2_tar);
    defer allocator.free(layer2_diff_id);
    const config_json = try std.fmt.allocPrint(
        allocator,
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{s}\",\"{s}\"]}}}}",
        .{ layer1_diff_id, layer2_diff_id },
    );

    const config_digest = try writeBlobAndDigest(allocator, io, dir, config_json);
    const layer1_digest = try writeBlobAndDigest(allocator, io, dir, layer1_blob);
    const layer2_digest = try writeBlobAndDigest(allocator, io, dir, layer2_blob);
    const layer_media_type = fixtureLayerMediaType(compression);

    const manifest_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ config_digest, config_json.len, layer_media_type, layer1_digest, layer1_blob.len, layer_media_type, layer2_digest, layer2_blob.len },
    );
    const manifest_digest = try writeBlobAndDigest(allocator, io, dir, manifest_json);

    const index_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ manifest_digest, manifest_json.len },
    );

    try dir.writeFile(io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}" });
    try dir.writeFile(io, .{ .sub_path = "index.json", .data = index_json });

    return .{
        .layer1_tar = layer1_tar,
        .layer2_tar = layer2_tar,
        .layer1_blob = layer1_blob,
        .layer2_blob = layer2_blob,
        .config_digest = config_digest,
        .layer1_digest = layer1_digest,
        .layer2_digest = layer2_digest,
        .manifest_digest = manifest_digest,
        .config_json = config_json,
        .manifest_json = manifest_json,
        .index_json = index_json,
    };
}

fn createDockerSaveFixture(allocator: Allocator, io: Io, tarball_path: []const u8) !void {
    const layer1_tar = try buildTarArchive(allocator, &.{
        .{ .path = "etc/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "etc/keep.txt", .mode = 0o644, .typeflag = '0', .content = "keep from base\n", .link_name = null },
        .{ .path = "etc/remove.txt", .mode = 0o644, .typeflag = '0', .content = "remove me\n", .link_name = null },
        .{ .path = "etc/opaque/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "etc/opaque/from-base.txt", .mode = 0o644, .typeflag = '0', .content = "base hidden\n", .link_name = null },
        .{ .path = "hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from base\n", .link_name = null },
        .{ .path = "links/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "links/config", .mode = 0o777, .typeflag = '2', .content = "", .link_name = "../etc/keep.txt" },
    });
    defer allocator.free(layer1_tar);

    const layer2_tar = try buildTarArchive(allocator, &.{
        .{ .path = "etc/.wh.remove.txt", .mode = 0o000, .typeflag = '0', .content = "", .link_name = null },
        .{ .path = "etc/opaque/.wh..wh..opq", .mode = 0o000, .typeflag = '0', .content = "", .link_name = null },
        .{ .path = "etc/opaque/from-top.txt", .mode = 0o644, .typeflag = '0', .content = "top survives\n", .link_name = null },
        .{ .path = "hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from top\n", .link_name = null },
    });
    defer allocator.free(layer2_tar);

    const config_json = try std.fmt.allocPrint(
        allocator,
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[]}}}}",
        .{},
    );
    defer allocator.free(config_json);

    const repositories_json =
        "{\"example.com/test\":{\"latest\":\"2222222222222222222222222222222222222222222222222222222222222222\"}}";

    const outer_tar = try buildTarArchive(allocator, &.{
        .{ .path = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json", .mode = 0o644, .typeflag = '0', .content = config_json, .link_name = null },
        .{ .path = "1111111111111111111111111111111111111111111111111111111111111111/layer.tar", .mode = 0o644, .typeflag = '0', .content = layer1_tar, .link_name = null },
        .{ .path = "2222222222222222222222222222222222222222222222222222222222222222/layer.tar", .mode = 0o644, .typeflag = '0', .content = layer2_tar, .link_name = null },
        .{
            .path = "manifest.json",
            .mode = 0o644,
            .typeflag = '0',
            .content = "[{\"Config\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json\",\"RepoTags\":[\"example.com/test:latest\"],\"Layers\":[\"1111111111111111111111111111111111111111111111111111111111111111/layer.tar\",\"2222222222222222222222222222222222222222222222222222222222222222/layer.tar\"]}]",
            .link_name = null,
        },
        .{ .path = "repositories", .mode = 0o644, .typeflag = '0', .content = repositories_json, .link_name = null },
    });
    defer allocator.free(outer_tar);

    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tarball_path, .data = outer_tar });
}

fn createDockerSaveMultiManifestFixture(allocator: Allocator, io: Io, tarball_path: []const u8) !void {
    const base_layer1_tar = try buildTarArchive(allocator, &.{
        .{ .path = "etc/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "etc/keep.txt", .mode = 0o644, .typeflag = '0', .content = "keep from base\n", .link_name = null },
        .{ .path = "etc/remove.txt", .mode = 0o644, .typeflag = '0', .content = "remove me\n", .link_name = null },
        .{ .path = "etc/opaque/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "etc/opaque/from-base.txt", .mode = 0o644, .typeflag = '0', .content = "base hidden\n", .link_name = null },
        .{ .path = "hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from base\n", .link_name = null },
        .{ .path = "links/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "links/config", .mode = 0o777, .typeflag = '2', .content = "", .link_name = "../etc/keep.txt" },
    });
    defer allocator.free(base_layer1_tar);

    const base_layer2_tar = try buildTarArchive(allocator, &.{
        .{ .path = "etc/.wh.remove.txt", .mode = 0o000, .typeflag = '0', .content = "", .link_name = null },
        .{ .path = "etc/opaque/.wh..wh..opq", .mode = 0o000, .typeflag = '0', .content = "", .link_name = null },
        .{ .path = "etc/opaque/from-top.txt", .mode = 0o644, .typeflag = '0', .content = "top survives\n", .link_name = null },
        .{ .path = "hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from top\n", .link_name = null },
    });
    defer allocator.free(base_layer2_tar);

    const alt_layer_tar = try buildTarArchive(allocator, &.{
        .{ .path = "hello.txt", .mode = 0o644, .typeflag = '0', .content = "hello from alt\n", .link_name = null },
        .{ .path = "alt.txt", .mode = 0o644, .typeflag = '0', .content = "selected from alt\n", .link_name = null },
    });
    defer allocator.free(alt_layer_tar);

    const base_config_json = try std.fmt.allocPrint(
        allocator,
        "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[]}}}}",
        .{},
    );
    defer allocator.free(base_config_json);

    const alt_config_json = try std.fmt.allocPrint(
        allocator,
        "{{\"architecture\":\"arm64\",\"os\":\"linux\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[]}}}}",
        .{},
    );
    defer allocator.free(alt_config_json);

    const manifest_json = try std.fmt.allocPrint(
        allocator,
        \\[
        \\  {{"Config":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json","RepoTags":["example.com/test:latest"],"Layers":["1111111111111111111111111111111111111111111111111111111111111111/layer.tar","2222222222222222222222222222222222222222222222222222222222222222/layer.tar"]}},
        \\  {{"Config":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json","RepoTags":["example.com/alt:latest","example.com/alt:stable"],"Layers":["3333333333333333333333333333333333333333333333333333333333333333/layer.tar"]}}
        \\]
    ,
        .{},
    );
    defer allocator.free(manifest_json);

    const repositories_json =
        "{\"example.com/test\":{\"latest\":\"2222222222222222222222222222222222222222222222222222222222222222\"},\"example.com/alt\":{\"latest\":\"3333333333333333333333333333333333333333333333333333333333333333\",\"stable\":\"3333333333333333333333333333333333333333333333333333333333333333\"}}";

    const outer_tar = try buildTarArchive(allocator, &.{
        .{ .path = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json", .mode = 0o644, .typeflag = '0', .content = base_config_json, .link_name = null },
        .{ .path = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json", .mode = 0o644, .typeflag = '0', .content = alt_config_json, .link_name = null },
        .{ .path = "1111111111111111111111111111111111111111111111111111111111111111/layer.tar", .mode = 0o644, .typeflag = '0', .content = base_layer1_tar, .link_name = null },
        .{ .path = "2222222222222222222222222222222222222222222222222222222222222222/layer.tar", .mode = 0o644, .typeflag = '0', .content = base_layer2_tar, .link_name = null },
        .{ .path = "3333333333333333333333333333333333333333333333333333333333333333/layer.tar", .mode = 0o644, .typeflag = '0', .content = alt_layer_tar, .link_name = null },
        .{ .path = "manifest.json", .mode = 0o644, .typeflag = '0', .content = manifest_json, .link_name = null },
        .{ .path = "repositories", .mode = 0o644, .typeflag = '0', .content = repositories_json, .link_name = null },
    });
    defer allocator.free(outer_tar);

    try Io.Dir.cwd().writeFile(io, .{ .sub_path = tarball_path, .data = outer_tar });
}

fn fixtureLayerMediaType(compression: FixtureCompression) []const u8 {
    return switch (compression) {
        .gzip => "application/vnd.oci.image.layer.v1.tar+gzip",
        .zstd => "application/vnd.oci.image.layer.v1.tar+zstd",
    };
}

fn compressFixtureLayer(allocator: Allocator, compression: FixtureCompression, data: []const u8) ![]u8 {
    return switch (compression) {
        .gzip => gzipBytes(allocator, data),
        .zstd => zstdBytes(allocator, data),
    };
}

fn writeBlobAndDigest(allocator: Allocator, io: Io, dir: Io.Dir, data: []const u8) ![]u8 {
    const digest_string = try sha256DigestString(allocator, data);
    const blob_path = try std.fmt.allocPrint(allocator, "blobs/sha256/{s}", .{digest_string[7..]});
    defer allocator.free(blob_path);
    try dir.writeFile(io, .{ .sub_path = blob_path, .data = data });
    return digest_string;
}

fn corruptFixtureBlob(io: Io, root: []const u8, digest: []const u8, original: []const u8) !void {
    const mutated = try std.testing.allocator.dupe(u8, original);
    defer std.testing.allocator.free(mutated);
    mutated[0] ^= 1;
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/blobs/sha256/{s}", .{ root, digest["sha256:".len..] });
    defer std.testing.allocator.free(path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = mutated });
}

fn writeFixtureIndex(io: Io, root: []const u8, index_json: []const u8) !void {
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/index.json", .{root});
    defer std.testing.allocator.free(path);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = index_json });
}

const TarSpec = struct {
    path: []const u8,
    mode: u32,
    uid: u32 = 0,
    gid: u32 = 0,
    typeflag: u8,
    content: []const u8,
    link_name: ?[]const u8,
};

fn buildTarArchive(allocator: Allocator, specs: []const TarSpec) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, 4096);
    errdefer out.deinit();

    for (specs) |spec| try appendTarSpec(&out, spec);
    try out.writer.splatByteAll(0, 1024);
    return out.toOwnedSlice();
}

fn appendTarSpec(out: *std.Io.Writer.Allocating, spec: TarSpec) !void {
    var header: [512]u8 = [_]u8{0} ** 512;
    if (spec.path.len > 100) return error.InvalidHeader;
    @memcpy(header[0..spec.path.len], spec.path);
    try writeOctalField(header[100..108], spec.mode);
    try writeOctalField(header[108..116], spec.uid);
    try writeOctalField(header[116..124], spec.gid);
    try writeOctalField(header[124..136], spec.content.len);
    try writeOctalField(header[136..148], 0);
    @memset(header[148..156], ' ');
    header[156] = spec.typeflag;
    if (spec.link_name) |link_name| {
        if (link_name.len > 100) return error.InvalidHeader;
        @memcpy(header[157..][0..link_name.len], link_name);
    }
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");

    var checksum: u32 = 0;
    for (header) |byte| checksum += byte;
    try writeChecksumField(header[148..156], checksum);

    try out.writer.writeAll(&header);
    try out.writer.writeAll(spec.content);
    const padding = std.mem.alignForward(usize, spec.content.len, 512) - spec.content.len;
    if (padding > 0) try out.writer.splatByteAll(0, padding);
}

fn buildPaxRecord(allocator: Allocator, key: []const u8, value: []const u8) ![]u8 {
    var record_len: usize = 0;
    while (true) {
        const record = try std.fmt.allocPrint(allocator, "{d} {s}={s}\n", .{ record_len, key, value });
        if (record.len == record_len) return record;
        record_len = record.len;
        allocator.free(record);
    }
}

fn gzipBytes(allocator: Allocator, data: []const u8) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), data.len));
    errdefer out.deinit();

    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&out.writer, &history, .gzip, .default);
    try compressor.writer.writeAll(data);
    try compressor.finish();
    return out.toOwnedSlice();
}

fn zstdBytes(allocator: Allocator, data: []const u8) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, data);

    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{
            "sh",
            "-c",
            "printf '%s' \"$1\" | base64 -d | zstd -q -c",
            "sh",
            encoded,
        },
        .cwd = .{ .path = "." },
    });
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);

    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }

    allocator.free(result.stdout);
    return error.ExternalCompressionFailed;
}

fn expectMergedFixtureImage(image: Image) !void {
    try std.testing.expectEqualStrings("amd64", image.config.architecture.?);
    try std.testing.expectEqualStrings("linux", image.config.os.?);

    const hello = image.get("hello.txt").?;
    try std.testing.expectEqual(EntryKind.file, hello.kind);
    try std.testing.expectEqualStrings("hello from top\n", hello.content);

    const keep = image.get("etc/keep.txt").?;
    try std.testing.expectEqualStrings("keep from base\n", keep.content);
    try std.testing.expect(image.get("etc/remove.txt") == null);

    const opaque_dir = image.get("etc/opaque").?;
    try std.testing.expectEqual(EntryKind.directory, opaque_dir.kind);
    try std.testing.expect(image.get("etc/opaque/from-base.txt") == null);
    const opaque_top = image.get("etc/opaque/from-top.txt").?;
    try std.testing.expectEqualStrings("top survives\n", opaque_top.content);

    const symlink = image.get("links/config").?;
    try std.testing.expectEqual(EntryKind.symlink, symlink.kind);
    try std.testing.expectEqualStrings("../etc/keep.txt", symlink.link_name.?);
}

fn writeOctalField(field: []u8, value: u64) !void {
    if (field.len == 0) return;
    @memset(field, 0);
    var buf: [32]u8 = undefined;
    const octal = try std.fmt.bufPrint(&buf, "{o}", .{value});
    if (octal.len + 1 > field.len) return error.InvalidHeader;
    const digits = field.len - 1;
    @memset(field[0..digits], '0');
    const start = digits - octal.len;
    @memcpy(field[start .. start + octal.len], octal);
}

fn writeChecksumField(field: []u8, value: u32) !void {
    @memset(field, ' ');
    var buf: [16]u8 = undefined;
    const octal = try std.fmt.bufPrint(&buf, "{o}", .{value});
    if (octal.len + 2 > field.len) return error.InvalidHeader;
    const start = field.len - octal.len - 2;
    @memcpy(field[start .. start + octal.len], octal);
    field[field.len - 2] = 0;
    field[field.len - 1] = ' ';
}
