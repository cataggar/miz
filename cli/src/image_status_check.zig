const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 2 and args.len != 4) {
        std.debug.print("usage: zvmi-image-status-check <bundle> [<image-basename> <output>]\n", .{});
        std.process.exit(2);
    }

    const status_path = try std.fs.path.join(allocator, &.{ args[1], "status" });
    const status = try std.Io.Dir.cwd().readFileAlloc(init.io, status_path, allocator, .limited(64));
    if (!std.mem.eql(u8, std.mem.trim(u8, status, " \r\n\t"), "success")) {
        const diagnostics_path = try std.fs.path.join(allocator, &.{ args[1], "diagnostics.json" });
        const diagnostics = std.Io.Dir.cwd().readFileAlloc(init.io, diagnostics_path, allocator, .limited(1024 * 1024)) catch
            "image generation failed without a diagnostics artifact";
        std.debug.print("{s}\n", .{diagnostics});
        std.process.exit(1);
    }
    if (args.len == 2) return;

    const image_path = try std.fs.path.join(allocator, &.{ args[1], args[2] });
    try publishImage(init.io, std.Io.Dir.cwd(), image_path, args[3]);
}

fn publishImage(io: std.Io, dir: std.Io.Dir, image_path: []const u8, output_path: []const u8) !void {
    dir.hardLink(image_path, dir, output_path, io, .{}) catch |err| switch (err) {
        error.PathAlreadyExists => try verifyPublishedImage(io, dir, image_path, output_path),
        error.CrossDevice,
        error.OperationUnsupported,
        error.AccessDenied,
        error.PermissionDenied,
        error.LinkQuotaExceeded,
        => dir.copyFile(image_path, dir, output_path, io, .{
            .replace = false,
        }) catch |copy_err| switch (copy_err) {
            error.PathAlreadyExists => try verifyPublishedImage(io, dir, image_path, output_path),
            else => return copy_err,
        },
        else => return err,
    };
}

fn verifyPublishedImage(io: std.Io, dir: std.Io.Dir, image_path: []const u8, output_path: []const u8) !void {
    const image_stat = try dir.statFile(io, image_path, .{ .follow_symlinks = false });
    const output_stat = try dir.statFile(io, output_path, .{ .follow_symlinks = false });
    if (image_stat.kind != .file or output_stat.kind != .file or image_stat.size != output_stat.size)
        return error.PathAlreadyExists;

    const image = try dir.openFile(io, image_path, .{ .follow_symlinks = false });
    defer image.close(io);
    const output = try dir.openFile(io, output_path, .{ .follow_symlinks = false });
    defer output.close(io);
    if (!fileUnchanged(image_stat, try image.stat(io)) or !fileUnchanged(output_stat, try output.stat(io)))
        return error.FileChanged;

    var image_buffer: [8192]u8 = undefined;
    var output_buffer: [8192]u8 = undefined;
    var offset: u64 = 0;
    while (offset < image_stat.size) {
        const length: usize = @intCast(@min(image_buffer.len, image_stat.size - offset));
        const image_length = try image.readPositionalAll(io, image_buffer[0..length], offset);
        const output_length = try output.readPositionalAll(io, output_buffer[0..length], offset);
        if (image_length != length or output_length != length) return error.FileChanged;
        if (!std.mem.eql(u8, image_buffer[0..length], output_buffer[0..length]))
            return error.PathAlreadyExists;
        offset += length;
    }

    if (!fileUnchanged(image_stat, try dir.statFile(io, image_path, .{ .follow_symlinks = false })) or
        !fileUnchanged(output_stat, try dir.statFile(io, output_path, .{ .follow_symlinks = false })))
        return error.FileChanged;
}

fn fileUnchanged(before: std.Io.File.Stat, after: std.Io.File.Stat) bool {
    return before.kind == after.kind and before.inode == after.inode and
        before.size == after.size and std.meta.eql(before.mtime, after.mtime);
}

test "status checker contract uses success and failure tokens" {
    try std.testing.expect(std.mem.eql(u8, std.mem.trim(u8, "success\n", " \r\n\t"), "success"));
    try std.testing.expect(!std.mem.eql(u8, std.mem.trim(u8, "failure\n", " \r\n\t"), "success"));
}

test "image publication accepts repeated hard-link and copied destinations" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "image.raw", .data = "image bytes" });
    try publishImage(io, tmp.dir, "image.raw", "linked.raw");
    try publishImage(io, tmp.dir, "image.raw", "linked.raw");

    try tmp.dir.copyFile("image.raw", tmp.dir, "copied.raw", io, .{ .replace = false });
    try publishImage(io, tmp.dir, "image.raw", "copied.raw");
    try publishImage(io, tmp.dir, "image.raw", "copied.raw");
    const bytes = try tmp.dir.readFileAlloc(io, "copied.raw", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("image bytes", bytes);
}

test "image publication verifies an existing output after the copy fallback" {
    const Fallback = struct {
        fn hardLink(_: ?*anyopaque, _: std.Io.Dir, _: []const u8, _: std.Io.Dir, _: []const u8, _: std.Io.Dir.HardLinkOptions) std.Io.Dir.HardLinkError!void {
            return error.CrossDevice;
        }
    };
    var io = std.testing.io;
    var vtable = io.vtable.*;
    vtable.dirHardLink = Fallback.hardLink;
    io.vtable = &vtable;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "image.raw", .data = "image bytes" });
    try publishImage(io, tmp.dir, "image.raw", "output.raw");
    const published = try tmp.dir.statFile(io, "output.raw", .{});
    try publishImage(io, tmp.dir, "image.raw", "output.raw");
    try std.testing.expectEqual(published.inode, (try tmp.dir.statFile(io, "output.raw", .{})).inode);
    try tmp.dir.writeFile(io, .{ .sub_path = "output.raw", .data = "conflicting bytes" });
    try std.testing.expectError(error.PathAlreadyExists, publishImage(io, tmp.dir, "image.raw", "output.raw"));
    const bytes = try tmp.dir.readFileAlloc(io, "output.raw", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("conflicting bytes", bytes);
}

test "image publication rejects equal-size conflicts beyond one comparison chunk" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const image: [8193]u8 = @splat('a');
    var conflict = image;
    conflict[conflict.len - 1] = 'b';
    try tmp.dir.writeFile(io, .{ .sub_path = "image.raw", .data = &image });
    try tmp.dir.writeFile(io, .{ .sub_path = "output.raw", .data = &conflict });
    try std.testing.expectError(error.PathAlreadyExists, publishImage(io, tmp.dir, "image.raw", "output.raw"));
    const bytes = try tmp.dir.readFileAlloc(io, "output.raw", std.testing.allocator, .limited(conflict.len + 1));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &conflict, bytes);
}

test "image publication rejects symlink and directory destinations" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "image.raw", .data = "image bytes" });
    try tmp.dir.symLink(io, "image.raw", "linked.raw", .{});
    try std.testing.expectError(error.PathAlreadyExists, publishImage(io, tmp.dir, "image.raw", "linked.raw"));
    const stat = try tmp.dir.statFile(io, "linked.raw", .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, stat.kind);
    try tmp.dir.createDir(io, "directory.raw", .default_dir);
    try std.testing.expectError(error.PathAlreadyExists, publishImage(io, tmp.dir, "image.raw", "directory.raw"));
}

test "image publication requires the source even when a destination already exists" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "output.raw", .data = "image bytes" });
    try std.testing.expectError(error.FileNotFound, publishImage(io, tmp.dir, "missing.raw", "output.raw"));
}
