//! Atomic OCI runtime bundle publication from a local image layout.
const std = @import("std");
const builtin = @import("builtin");
const filesystem = @import("filesystem.zig");
const image = @import("image.zig");
const layer = @import("layer.zig");
const layout = @import("layout.zig");
const model = @import("model.zig");
const reference = @import("reference.zig");
const runtime_config = @import("runtime_config.zig");
const snapshot = @import("snapshot.zig");

const Io = std.Io;

pub const Options = struct {
    platform: model.Platform,
    preserve_ownership: bool = false,
    force: bool = false,
    limits: layer.Limits = .{},
    failure_point: FailurePoint = .none,
};

pub const FailurePoint = enum {
    none,
    before_publish,
};

pub const Metadata = struct {
    schema_version: u32 = 1,
    source_reference: []const u8,
    layout_path: []const u8,
    platform: model.Platform,
    descriptor_path: []const model.Descriptor,
    root_digest: []const u8,
    manifest_digest: []const u8,
    config_digest: []const u8,
    rootless: bool,
    host_uid: u32,
    host_gid: u32,
};

pub const Result = struct {
    manifest_digest: [71]u8,
    manifest_digest_len: usize,
    cleanup_warning: bool = false,

    pub fn digest(self: *const Result) []const u8 {
        return self.manifest_digest[0..self.manifest_digest_len];
    }
};

pub fn unpackLayout(
    allocator: std.mem.Allocator,
    io: Io,
    source_reference: []const u8,
    image_ref: reference.LayoutReference,
    bundle_path: []const u8,
    options: Options,
) !Result {
    if (!std.mem.eql(u8, options.platform.os, "linux")) return error.UnsupportedRuntimeOs;

    var source = layout.Source.init(io, allocator, image_ref.path);
    var resolved = try image.resolveLayout(allocator, &source, image_ref, .{
        .platform = options.platform,
    });
    defer resolved.deinit();

    const parent = std.fs.path.dirname(bundle_path) orelse ".";
    const base = std.fs.path.basename(bundle_path);
    if (base.len == 0) return error.InvalidBundlePath;
    try Io.Dir.cwd().createDirPath(io, parent);
    var publication_lock = try openPublicationLock(io, allocator, parent, base);
    defer publication_lock.close(io);
    var bundle_exists = false;
    if (Io.Dir.cwd().statFile(io, bundle_path, .{ .follow_symlinks = false })) |stat| {
        if (stat.kind != .directory) return error.BundleNotDirectory;
        if (!options.force) return error.BundleExists;
        bundle_exists = true;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    if (bundle_exists and builtin.os.tag != .linux) return error.AtomicReplaceUnsupported;

    const staging_path = try createUniqueDirectory(io, allocator, parent, base);
    defer allocator.free(staging_path);
    var published = false;
    defer if (!published) Io.Dir.cwd().deleteTree(io, staging_path) catch {};

    var staging = try Io.Dir.cwd().openDir(io, staging_path, .{});
    defer staging.close(io);
    try staging.createDir(io, "rootfs", .default_dir);
    var rootfs = try staging.openDir(io, "rootfs", .{ .iterate = true });
    defer rootfs.close(io);

    var extractor = filesystem.Extractor.init(allocator, io, rootfs, .{
        .preserve_ownership = options.preserve_ownership,
    });
    defer extractor.deinit();

    const diff_ids = resolved.config.rootfs.diff_ids;
    for (resolved.manifest.layers, diff_ids) |descriptor, diff_id| {
        try extractor.beginLayer();
        try layer.processLayout(
            allocator,
            source,
            descriptor,
            diff_id,
            options.limits,
            &extractor,
            filesystem.Extractor.apply,
        );
    }
    try extractor.finish();

    const config_json = try runtime_config.generate(io, allocator, rootfs, resolved.config, .{
        .rootless = !options.preserve_ownership,
    });
    defer allocator.free(config_json);
    try writeSyncedFile(io, staging, "config.json", config_json);

    try staging.createDir(io, ".miz", .default_dir);
    var base_state = try snapshot.capture(allocator, io, rootfs);
    defer base_state.deinit();
    extractor.overlaySnapshot(base_state.entries);
    const base_json = try std.json.Stringify.valueAlloc(allocator, base_state.entries, .{});
    defer allocator.free(base_json);
    try writeSyncedFile(io, staging, ".miz/base.json", base_json);

    const descriptors = try allocator.alloc(model.Descriptor, resolved.path.len);
    defer allocator.free(descriptors);
    for (resolved.path, descriptors) |node, *descriptor| descriptor.* = node.descriptor;
    const metadata_json = try std.json.Stringify.valueAlloc(allocator, Metadata{
        .source_reference = source_reference,
        .layout_path = image_ref.path,
        .platform = resolved.platform,
        .descriptor_path = descriptors,
        .root_digest = resolved.path[0].descriptor.digest,
        .manifest_digest = resolved.manifestNode().descriptor.digest,
        .config_digest = resolved.manifest.config.digest,
        .rootless = !options.preserve_ownership,
        .host_uid = currentUid(),
        .host_gid = currentGid(),
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(metadata_json);
    try writeSyncedFile(io, staging, ".miz/metadata.json", metadata_json);
    if (options.failure_point == .before_publish) return error.InjectedFailure;

    var cleanup_warning = false;
    if (bundle_exists) {
        try exchangeDirectories(allocator, staging_path, bundle_path);
        published = true;
        makeTreeWritable(io, allocator, staging_path) catch {
            cleanup_warning = true;
        };
        if (!cleanup_warning) {
            Io.Dir.cwd().deleteTree(io, staging_path) catch {
                cleanup_warning = true;
            };
        }
    } else {
        Io.Dir.renamePreserve(Io.Dir.cwd(), staging_path, Io.Dir.cwd(), bundle_path, io) catch |err| switch (err) {
            error.PathAlreadyExists => return error.BundleExists,
            else => return err,
        };
        published = true;
    }

    const manifest_digest = resolved.manifestNode().descriptor.digest;
    if (manifest_digest.len > 71) return error.InvalidManifestDigest;
    var result: Result = .{
        .manifest_digest = undefined,
        .manifest_digest_len = manifest_digest.len,
        .cleanup_warning = cleanup_warning,
    };
    @memcpy(result.manifest_digest[0..manifest_digest.len], manifest_digest);
    return result;
}

fn currentUid() u32 {
    return if (@import("builtin").os.tag == .linux) std.os.linux.geteuid() else 0;
}

fn currentGid() u32 {
    return if (@import("builtin").os.tag == .linux) std.os.linux.getegid() else 0;
}

fn openPublicationLock(
    io: Io,
    allocator: std.mem.Allocator,
    parent: []const u8,
    base: []const u8,
) !Io.File {
    var parent_dir = try Io.Dir.cwd().openDir(io, parent, .{});
    defer parent_dir.close(io);
    const name = try std.fmt.allocPrint(allocator, ".{s}.miz-bundle.lock", .{base});
    defer allocator.free(name);
    return parent_dir.createFile(io, name, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
    });
}

fn exchangeDirectories(
    allocator: std.mem.Allocator,
    staging_path: []const u8,
    bundle_path: []const u8,
) !void {
    if (builtin.os.tag != .linux) return error.AtomicReplaceUnsupported;
    const staging_z = try allocator.dupeZ(u8, staging_path);
    defer allocator.free(staging_z);
    const bundle_z = try allocator.dupeZ(u8, bundle_path);
    defer allocator.free(bundle_z);
    const linux = std.os.linux;
    switch (linux.errno(linux.renameat2(
        linux.AT.FDCWD,
        staging_z.ptr,
        linux.AT.FDCWD,
        bundle_z.ptr,
        .{ .EXCHANGE = true },
    ))) {
        .SUCCESS => {},
        else => return error.AtomicReplaceUnsupported,
    }
}

fn makeTreeWritable(
    io: Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) !void {
    if (builtin.os.tag != .linux) return error.AtomicReplaceUnsupported;
    var root = try Io.Dir.cwd().openDir(io, path, .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer root.close(io);
    var root_file = try Io.Dir.cwd().openFile(io, path, .{
        .allow_directory = true,
        .follow_symlinks = false,
    });
    defer root_file.close(io);
    try root_file.setPermissions(io, .fromMode(0o700));
    var walker = try root.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        var directory = try entry.dir.openFile(io, entry.basename, .{
            .allow_directory = true,
            .follow_symlinks = false,
        });
        try directory.setPermissions(io, .fromMode(0o700));
        directory.close(io);
    }
}

fn writeSyncedFile(io: Io, dir: Io.Dir, sub_path: []const u8, bytes: []const u8) !void {
    var file = try dir.createFile(io, sub_path, .{ .exclusive = true });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try file.sync(io);
}

fn createUniqueDirectory(
    io: Io,
    allocator: std.mem.Allocator,
    parent: []const u8,
    base: []const u8,
) ![]u8 {
    var random: [16]u8 = undefined;
    for (0..64) |_| {
        try io.randomSecure(&random);
        const suffix = std.fmt.bytesToHex(random, .lower);
        const name = try std.fmt.allocPrint(
            allocator,
            ".{s}.miz-bundle-staging-{s}",
            .{ base, suffix },
        );
        defer allocator.free(name);
        const path = try std.fs.path.join(allocator, &.{ parent, name });
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
