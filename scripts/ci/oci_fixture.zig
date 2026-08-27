//! Deterministic, from-scratch OCI image layouts used as `--container` /
//! `MIZ_BOOT_TEST_*_OCI` fixtures in CI, without depending on network access
//! to a container registry.
//!
//! Every layout produced here is a single tar+gzip layer over the `miz` tar
//! writer, published through the same transactional `miz.oci.layout`
//! destination the library uses for real pulls, so a fixture is validated by
//! the code that will later read it rather than by a bespoke writer.

const std = @import("std");
const miz = @import("miz");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const content = miz.oci.content;
const model = miz.oci.model;

/// Mode of every archive member: a fixture overlays plain data files, so no
/// entry carries an executable bit.
pub const file_mode: u32 = 0o644;
pub const default_architecture = "amd64";
pub const operating_system = "linux";
/// Payload ceiling for a fixture input read off the CI host's disk.
pub const max_payload_size = 512 * 1024 * 1024;

pub const minimal_archive_path = "hello.txt";
pub const minimal_content = "hello from miz CI\n";
/// `miz.bootconfig` discovers the systemd EFI stub by basename anywhere in
/// the merged tree; this path simply mirrors the conventional on-disk one.
pub const uki_stub_archive_path = "usr/lib/systemd/boot/efi/linuxx64.efi.stub";
pub const pe_magic = "MZ";

pub const Error = error{
    NoLayerFiles,
    EmptyArchivePath,
    AbsoluteArchivePath,
    UnsafeArchivePath,
    ArchivePathTooLong,
    DuplicateArchivePath,
    InvalidArchitecture,
    InvalidKernelVersion,
    OutputPathNotLayout,
};

pub const LayerFile = struct {
    path: []const u8,
    content: []const u8,
};

pub const Options = struct {
    architecture: []const u8 = default_architecture,
    mode: u32 = file_mode,
};

/// Digests of everything a caller may want to assert on, in the canonical
/// `sha256:<hex>` form the layout itself records.
pub const Summary = struct {
    diff_id: [71]u8,
    layer_digest: [71]u8,
    layer_size: u64,
    config_digest: [71]u8,
    config_size: u64,
    manifest_digest: [71]u8,
    manifest_size: u64,
};

const DescriptorDocument = struct {
    mediaType: []const u8,
    digest: []const u8,
    size: u64,
};

const RootFsDocument = struct {
    type: []const u8 = "layers",
    diff_ids: []const []const u8,
};

const ConfigDocument = struct {
    architecture: []const u8,
    os: []const u8 = operating_system,
    config: struct {} = .{},
    rootfs: RootFsDocument,
};

const ManifestDocument = struct {
    schemaVersion: u32 = 2,
    mediaType: []const u8 = model.media_type_oci_manifest,
    config: DescriptorDocument,
    layers: []const DescriptorDocument,
};

fn asDescriptor(document: DescriptorDocument) model.Descriptor {
    return .{
        .mediaType = document.mediaType,
        .digest = document.digest,
        .size = document.size,
    };
}

/// Rejects anything that would escape the layer root or collide once
/// extracted. The Python generator trusted its callers here.
pub fn validateArchivePath(path: []const u8) Error!void {
    if (path.len == 0) return error.EmptyArchivePath;
    if (path.len > 1024) return error.ArchivePathTooLong;
    if (path[0] == '/') return error.AbsoluteArchivePath;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.UnsafeArchivePath;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return error.UnsafeArchivePath;
    if (path[path.len - 1] == '/') return error.UnsafeArchivePath;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0) return error.UnsafeArchivePath;
        if (std.mem.eql(u8, component, ".")) return error.UnsafeArchivePath;
        if (std.mem.eql(u8, component, "..")) return error.UnsafeArchivePath;
    }
}

pub fn validateArchitecture(architecture: []const u8) Error!void {
    if (architecture.len == 0 or architecture.len > 64) return error.InvalidArchitecture;
    for (architecture) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        if (byte == '.' or byte == '_' or byte == '-') continue;
        return error.InvalidArchitecture;
    }
}

/// A kernel version becomes part of an archive path, so it may not carry a
/// separator or a traversal component of its own.
pub fn validateKernelVersion(version: []const u8) Error!void {
    if (version.len == 0 or version.len > 256) return error.InvalidKernelVersion;
    if (std.mem.eql(u8, version, ".") or std.mem.eql(u8, version, "..")) {
        return error.InvalidKernelVersion;
    }
    for (version) |byte| {
        if (byte == '/' or byte == '\\' or byte == 0) return error.InvalidKernelVersion;
        if (!std.ascii.isPrint(byte)) return error.InvalidKernelVersion;
    }
}

/// The ISO's own initramfs path: a container layer entry only replaces the
/// stock copy when it lands at exactly the same path.
pub fn verityArchivePath(allocator: Allocator, kernel_version: []const u8) ![]u8 {
    try validateKernelVersion(kernel_version);
    return std.fmt.allocPrint(allocator, "boot/initramfs-{s}.img", .{kernel_version});
}

pub fn validateLayerFiles(files: []const LayerFile) Error!void {
    if (files.len == 0) return error.NoLayerFiles;
    for (files, 0..) |file, index| {
        try validateArchivePath(file.path);
        for (files[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.path, file.path)) return error.DuplicateArchivePath;
        }
    }
}

/// Builds the uncompressed layer. Entry order follows `files`, and every
/// entry carries a zeroed owner and timestamp, so the tar -- and therefore
/// the diff-id -- depends only on the requested content.
pub fn buildLayerTar(allocator: Allocator, files: []const LayerFile, mode: u32) ![]u8 {
    try validateLayerFiles(files);
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, 4096);
    errdefer out.deinit();
    var writer = miz.tar.Writer.init(&out.writer);
    for (files) |file| try writer.writeFile(file.path, mode, file.content);
    try writer.finish();
    return out.toOwnedSlice();
}

/// gzip at the default level (6), with the zeroed mtime std's gzip container
/// always writes, so repeated runs over identical input agree bit for bit.
pub fn gzipBytes(allocator: Allocator, data: []const u8) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), data.len));
    errdefer out.deinit();
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&out.writer, &history, .gzip, .default);
    try compressor.writer.writeAll(data);
    try compressor.finish();
    return out.toOwnedSlice();
}

/// Builds a from-scratch OCI image layout at `output_path` holding a single
/// tar+gzip layer with `files`.
///
/// An existing layout at the path is replaced; any other existing path is
/// refused rather than written into.
pub fn buildSingleLayerLayout(
    allocator: Allocator,
    io: Io,
    output_path: []const u8,
    files: []const LayerFile,
    options: Options,
) !Summary {
    try validateLayerFiles(files);
    try validateArchitecture(options.architecture);

    const layer_tar = try buildLayerTar(allocator, files, options.mode);
    defer allocator.free(layer_tar);
    const diff_id = content.digestBytes(layer_tar).format();

    const layer_gzip = try gzipBytes(allocator, layer_tar);
    defer allocator.free(layer_gzip);
    const layer_digest = content.digestBytes(layer_gzip).format();

    const diff_ids = [_][]const u8{&diff_id};
    const config_json = try std.json.Stringify.valueAlloc(allocator, ConfigDocument{
        .architecture = options.architecture,
        .rootfs = .{ .diff_ids = &diff_ids },
    }, .{});
    defer allocator.free(config_json);
    const config_digest = content.digestBytes(config_json).format();

    const layer_document: DescriptorDocument = .{
        .mediaType = model.media_type_oci_layer_gzip,
        .digest = &layer_digest,
        .size = layer_gzip.len,
    };
    const config_document: DescriptorDocument = .{
        .mediaType = model.media_type_oci_config,
        .digest = &config_digest,
        .size = config_json.len,
    };
    const layers = [_]DescriptorDocument{layer_document};
    const manifest_json = try std.json.Stringify.valueAlloc(allocator, ManifestDocument{
        .config = config_document,
        .layers = &layers,
    }, .{});
    defer allocator.free(manifest_json);
    const manifest_digest = content.digestBytes(manifest_json).format();

    const root_document: DescriptorDocument = .{
        .mediaType = model.media_type_oci_manifest,
        .digest = &manifest_digest,
        .size = manifest_json.len,
    };
    const root = asDescriptor(root_document);
    // The index entry is written from this exact JSON rather than a
    // re-encoding of the descriptor, so the published root descriptor carries
    // no field the manifest blob does not.
    const root_json = try std.json.Stringify.valueAlloc(allocator, root_document, .{});
    defer allocator.free(root_json);

    try clearExistingLayout(io, output_path);

    var destination = try miz.oci.layout.Destination.init(io, allocator, output_path);
    defer destination.deinit();
    var counts: miz.oci.layout.Counts = .{};
    try destination.ensureBytes(asDescriptor(layer_document), layer_gzip, &counts);
    try destination.ensureBytes(asDescriptor(config_document), config_json, &counts);
    try destination.ensureBytes(root, manifest_json, &counts);
    try destination.commitExact(root, root_json, null);
    try destination.finish();

    return .{
        .diff_id = diff_id,
        .layer_digest = layer_digest,
        .layer_size = layer_gzip.len,
        .config_digest = config_digest,
        .config_size = config_json.len,
        .manifest_digest = manifest_digest,
        .manifest_size = manifest_json.len,
    };
}

/// Removes a previously generated layout so a rebuild cannot inherit stale
/// blobs or an index entry for a manifest that no longer describes it. A path
/// that is not an OCI layout is never deleted.
fn clearExistingLayout(io: Io, output_path: []const u8) !void {
    {
        var dir = Dir.cwd().openDir(io, output_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            error.NotDir => return error.OutputPathNotLayout,
            else => return err,
        };
        defer dir.close(io);
        _ = dir.statFile(io, "oci-layout", .{}) catch return error.OutputPathNotLayout;
    }
    try Dir.cwd().deleteTree(io, output_path);
}

test {
    std.testing.refAllDecls(@This());
}

test "archive paths that escape the layer root are refused" {
    try validateArchivePath("hello.txt");
    try validateArchivePath("usr/lib/systemd/boot/efi/linuxx64.efi.stub");
    try std.testing.expectError(error.EmptyArchivePath, validateArchivePath(""));
    try std.testing.expectError(error.AbsoluteArchivePath, validateArchivePath("/etc/passwd"));
    try std.testing.expectError(error.UnsafeArchivePath, validateArchivePath("../escape"));
    try std.testing.expectError(error.UnsafeArchivePath, validateArchivePath("boot/../../escape"));
    try std.testing.expectError(error.UnsafeArchivePath, validateArchivePath("boot//initramfs.img"));
    try std.testing.expectError(error.UnsafeArchivePath, validateArchivePath("boot/"));
    try std.testing.expectError(error.UnsafeArchivePath, validateArchivePath("boot\\initramfs.img"));
}

test "layer file sets are rejected when empty or ambiguous" {
    try std.testing.expectError(error.NoLayerFiles, validateLayerFiles(&.{}));
    try std.testing.expectError(error.DuplicateArchivePath, validateLayerFiles(&.{
        .{ .path = "a.txt", .content = "a" },
        .{ .path = "a.txt", .content = "b" },
    }));
    try validateLayerFiles(&.{
        .{ .path = "a.txt", .content = "a" },
        .{ .path = "b.txt", .content = "b" },
    });
}

test "architecture and kernel version inputs are constrained" {
    try validateArchitecture("amd64");
    try validateArchitecture("arm64");
    try std.testing.expectError(error.InvalidArchitecture, validateArchitecture(""));
    try std.testing.expectError(error.InvalidArchitecture, validateArchitecture("amd 64"));
    try std.testing.expectError(error.InvalidArchitecture, validateArchitecture("../amd64"));

    try validateKernelVersion("6.6.0-1.azl3.x86_64");
    try std.testing.expectError(error.InvalidKernelVersion, validateKernelVersion(""));
    try std.testing.expectError(error.InvalidKernelVersion, validateKernelVersion(".."));
    try std.testing.expectError(error.InvalidKernelVersion, validateKernelVersion("6.6.0/../../etc"));
}

test "verity archive path lands where the ISO's initramfs already is" {
    const allocator = std.testing.allocator;
    const path = try verityArchivePath(allocator, "6.6.0-1.azl3.x86_64");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("boot/initramfs-6.6.0-1.azl3.x86_64.img", path);
    try std.testing.expectError(
        error.InvalidKernelVersion,
        verityArchivePath(allocator, "../../escape"),
    );
}

const TestLayout = struct {
    temporary: std.testing.TmpDir,
    path: []u8,
    allocator: Allocator,

    fn init(allocator: Allocator, io: Io, name: []const u8) !TestLayout {
        var temporary = std.testing.tmpDir(.{});
        errdefer temporary.cleanup();
        var root_buffer: [Dir.max_path_bytes]u8 = undefined;
        const root_length = try temporary.dir.realPath(io, &root_buffer);
        const path = try std.fs.path.join(
            allocator,
            &.{ root_buffer[0..root_length], name },
        );
        return .{ .temporary = temporary, .path = path, .allocator = allocator };
    }

    fn deinit(self: *TestLayout) void {
        self.allocator.free(self.path);
        self.temporary.cleanup();
        self.* = undefined;
    }
};

/// Reads the layer back out of the published layout the way a puller would:
/// resolve the index root, verify every blob against its descriptor, and
/// return the decompressed tar so the caller can assert on entries.
fn readLayerThroughLayout(
    allocator: Allocator,
    io: Io,
    layout_path: []const u8,
    summary: Summary,
) ![]u8 {
    var source = miz.oci.layout.Source.init(io, allocator, layout_path);
    try source.validateLayout();
    var resolved = try source.resolve(.{ .path = layout_path, .selection = null });
    defer resolved.deinit();
    try std.testing.expectEqualStrings(&summary.manifest_digest, resolved.descriptor.digest);
    try std.testing.expectEqual(summary.manifest_size, resolved.descriptor.size);

    var manifest = try std.json.parseFromSlice(
        model.Manifest,
        allocator,
        resolved.bytes,
        .{ .ignore_unknown_fields = true },
    );
    defer manifest.deinit();
    try model.validateManifest(manifest.value);
    try std.testing.expectEqual(@as(usize, 1), manifest.value.layers.len);
    const layer = manifest.value.layers[0];
    try std.testing.expectEqualStrings(model.media_type_oci_layer_gzip, layer.mediaType.?);
    try std.testing.expectEqualStrings(&summary.layer_digest, layer.digest);
    try std.testing.expectEqual(summary.layer_size, layer.size);

    const config_bytes = try source.readMetadata(manifest.value.config);
    defer allocator.free(config_bytes);
    var config = try std.json.parseFromSlice(
        model.ImageConfiguration,
        allocator,
        config_bytes,
        .{ .ignore_unknown_fields = true },
    );
    defer config.deinit();
    try std.testing.expectEqualStrings("layers", config.value.rootfs.type);
    try std.testing.expectEqual(@as(usize, 1), config.value.rootfs.diff_ids.len);
    try std.testing.expectEqualStrings(&summary.diff_id, config.value.rootfs.diff_ids[0]);

    // Read the compressed layer straight off disk and hold it to both the
    // layer digest and, once expanded, the diff-id the config announces.
    var blob_path_buffer: [Dir.max_path_bytes]u8 = undefined;
    const digest = try content.Digest.parse(&summary.layer_digest);
    const blob_path = try std.fmt.bufPrint(
        &blob_path_buffer,
        "blobs/sha256/{s}",
        .{digest.blobPathComponent()},
    );
    var layout_dir = try Dir.cwd().openDir(io, layout_path, .{});
    defer layout_dir.close(io);
    const compressed = try layout_dir.readFileAlloc(
        io,
        blob_path,
        allocator,
        .limited(max_payload_size),
    );
    defer allocator.free(compressed);
    try content.verifyBytes(digest, summary.layer_size, compressed);

    var input: Io.Reader = .fixed(compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(&input, .gzip, &window);
    const layer_tar = try decompress.reader.allocRemaining(
        allocator,
        .limited(max_payload_size),
    );
    errdefer allocator.free(layer_tar);
    try content.verifyBytes(
        try content.Digest.parse(&summary.diff_id),
        layer_tar.len,
        layer_tar,
    );
    return layer_tar;
}

test "the minimal fixture is ingestible by the library's own OCI loader" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var layout = try TestLayout.init(allocator, io, "oci-minimal");
    defer layout.deinit();

    const summary = try buildSingleLayerLayout(allocator, io, layout.path, &.{.{
        .path = minimal_archive_path,
        .content = minimal_content,
    }}, .{});

    var image = try miz.oci.loadLayout(io, allocator, layout.path, .{});
    defer image.deinit();
    try std.testing.expectEqualStrings(default_architecture, image.config.architecture.?);
    try std.testing.expectEqualStrings(operating_system, image.config.os.?);
    try std.testing.expectEqualStrings(&summary.manifest_digest, image.config.manifest_digest);
    const entry = image.get(minimal_archive_path) orelse return error.MissingFixtureEntry;
    try std.testing.expectEqual(miz.oci.EntryKind.file, entry.kind);
    try std.testing.expectEqual(file_mode, entry.mode);
    try std.testing.expectEqualStrings(minimal_content, entry.content);

    const layer_tar = try readLayerThroughLayout(allocator, io, layout.path, summary);
    defer allocator.free(layer_tar);
    var reader = miz.tar.Reader.init(layer_tar);
    const first = (try reader.next()) orelse return error.MissingFixtureEntry;
    try std.testing.expectEqualStrings(minimal_archive_path, first.path);
    try std.testing.expectEqual(file_mode, first.mode);
    try std.testing.expectEqual(@as(u32, 0), first.uid);
    try std.testing.expectEqual(@as(u32, 0), first.gid);
    try std.testing.expectEqualStrings(minimal_content, first.content);
    try std.testing.expect(try reader.next() == null);
}

test "the UKI stub payload survives the layer byte for byte" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var layout = try TestLayout.init(allocator, io, "oci-uki-stub");
    defer layout.deinit();

    // A PE header, embedded NULs, and a length that is not a tar block
    // multiple: everything an EFI stub would carry through the archive.
    var stub: [1237]u8 = undefined;
    @memcpy(stub[0..2], pe_magic);
    for (stub[2..], 0..) |*byte, index| byte.* = @truncate(index *% 7);
    stub[64] = 0;
    stub[65] = 0;

    const summary = try buildSingleLayerLayout(allocator, io, layout.path, &.{.{
        .path = uki_stub_archive_path,
        .content = &stub,
    }}, .{});

    var image = try miz.oci.loadLayout(io, allocator, layout.path, .{});
    defer image.deinit();
    const entry = image.get(uki_stub_archive_path) orelse return error.MissingFixtureEntry;
    try std.testing.expectEqual(file_mode, entry.mode);
    try std.testing.expectEqual(@as(u64, stub.len), entry.size);
    try std.testing.expectEqualSlices(u8, &stub, entry.content);

    const layer_tar = try readLayerThroughLayout(allocator, io, layout.path, summary);
    defer allocator.free(layer_tar);
    var reader = miz.tar.Reader.init(layer_tar);
    const first = (try reader.next()) orelse return error.MissingFixtureEntry;
    try std.testing.expectEqualStrings(uki_stub_archive_path, first.path);
    try std.testing.expectEqualSlices(u8, &stub, first.content);
}

test "the verity initramfs lands at the ISO's own path with its bytes intact" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var layout = try TestLayout.init(allocator, io, "oci-verity-initramfs");
    defer layout.deinit();

    const kernel_version = "6.6.0-1.azl3.x86_64";
    const archive_path = try verityArchivePath(allocator, kernel_version);
    defer allocator.free(archive_path);

    var initramfs: [4096]u8 = undefined;
    for (&initramfs, 0..) |*byte, index| byte.* = @truncate(index *% 31);

    const summary = try buildSingleLayerLayout(allocator, io, layout.path, &.{.{
        .path = archive_path,
        .content = &initramfs,
    }}, .{ .architecture = "arm64" });

    var image = try miz.oci.loadLayout(io, allocator, layout.path, .{});
    defer image.deinit();
    try std.testing.expectEqualStrings("arm64", image.config.architecture.?);
    const entry = image.get(archive_path) orelse return error.MissingFixtureEntry;
    try std.testing.expectEqualSlices(u8, &initramfs, entry.content);

    const layer_tar = try readLayerThroughLayout(allocator, io, layout.path, summary);
    defer allocator.free(layer_tar);
    var reader = miz.tar.Reader.init(layer_tar);
    const first = (try reader.next()) orelse return error.MissingFixtureEntry;
    try std.testing.expectEqualStrings(archive_path, first.path);
    try std.testing.expectEqualSlices(u8, &initramfs, first.content);
}

test "identical inputs produce identical layouts" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var first = try TestLayout.init(allocator, io, "oci-first");
    defer first.deinit();
    var second = try TestLayout.init(allocator, io, "oci-second");
    defer second.deinit();

    const files = [_]LayerFile{
        .{ .path = minimal_archive_path, .content = minimal_content },
        .{ .path = "usr/share/marker", .content = "marker\n" },
    };
    const one = try buildSingleLayerLayout(allocator, io, first.path, &files, .{});
    const two = try buildSingleLayerLayout(allocator, io, second.path, &files, .{});
    try std.testing.expectEqualStrings(&one.diff_id, &two.diff_id);
    try std.testing.expectEqualStrings(&one.layer_digest, &two.layer_digest);
    try std.testing.expectEqualStrings(&one.manifest_digest, &two.manifest_digest);

    // A different architecture is a different image, not a different name for
    // the same one.
    var third = try TestLayout.init(allocator, io, "oci-third");
    defer third.deinit();
    const other = try buildSingleLayerLayout(allocator, io, third.path, &files, .{
        .architecture = "arm64",
    });
    try std.testing.expectEqualStrings(&one.diff_id, &other.diff_id);
    try std.testing.expect(!std.mem.eql(u8, &one.manifest_digest, &other.manifest_digest));
}

test "rebuilding a layout replaces it instead of accumulating manifests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var layout = try TestLayout.init(allocator, io, "oci-rebuilt");
    defer layout.deinit();

    _ = try buildSingleLayerLayout(allocator, io, layout.path, &.{.{
        .path = minimal_archive_path,
        .content = minimal_content,
    }}, .{});
    const summary = try buildSingleLayerLayout(allocator, io, layout.path, &.{.{
        .path = "second.txt",
        .content = "second\n",
    }}, .{});

    var image = try miz.oci.loadLayout(io, allocator, layout.path, .{});
    defer image.deinit();
    try std.testing.expectEqualStrings(&summary.manifest_digest, image.config.manifest_digest);
    try std.testing.expect(image.get(minimal_archive_path) == null);
    try std.testing.expect(image.get("second.txt") != null);
}

test "a destination that is not a layout is refused, not written into" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var layout = try TestLayout.init(allocator, io, "occupied");
    defer layout.deinit();

    try layout.temporary.dir.writeFile(io, .{ .sub_path = "occupied", .data = "not a layout" });
    try std.testing.expectError(error.OutputPathNotLayout, buildSingleLayerLayout(
        allocator,
        io,
        layout.path,
        &.{.{ .path = minimal_archive_path, .content = minimal_content }},
        .{},
    ));

    try layout.temporary.dir.deleteFile(io, "occupied");
    try layout.temporary.dir.createDirPath(io, "occupied/blobs");
    try std.testing.expectError(error.OutputPathNotLayout, buildSingleLayerLayout(
        allocator,
        io,
        layout.path,
        &.{.{ .path = minimal_archive_path, .content = minimal_content }},
        .{},
    ));
}

test "invalid fixture requests fail before anything is published" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var layout = try TestLayout.init(allocator, io, "unbuilt");
    defer layout.deinit();

    try std.testing.expectError(error.NoLayerFiles, buildSingleLayerLayout(
        allocator,
        io,
        layout.path,
        &.{},
        .{},
    ));
    try std.testing.expectError(error.InvalidArchitecture, buildSingleLayerLayout(
        allocator,
        io,
        layout.path,
        &.{.{ .path = minimal_archive_path, .content = minimal_content }},
        .{ .architecture = "amd 64" },
    ));
    try std.testing.expectError(error.AbsoluteArchivePath, buildSingleLayerLayout(
        allocator,
        io,
        layout.path,
        &.{.{ .path = "/etc/shadow", .content = "" }},
        .{},
    ));
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(io, layout.path, .{}),
    );
}
