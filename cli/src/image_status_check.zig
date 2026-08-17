const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 2 and args.len != 4) {
        std.debug.print("usage: vmiz-image-status-check <bundle> [<image-basename> <output>]\n", .{});
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
    const cwd = std.Io.Dir.cwd();
    cwd.hardLink(image_path, cwd, args[3], init.io, .{}) catch |err| switch (err) {
        error.CrossDevice,
        error.OperationUnsupported,
        error.AccessDenied,
        error.PermissionDenied,
        error.LinkQuotaExceeded,
        => try cwd.copyFile(image_path, cwd, args[3], init.io, .{
            .replace = false,
        }),
        else => return err,
    };
}

test "status checker contract uses success and failure tokens" {
    try std.testing.expect(std.mem.eql(u8, std.mem.trim(u8, "success\n", " \r\n\t"), "success"));
    try std.testing.expect(!std.mem.eql(u8, std.mem.trim(u8, "failure\n", " \r\n\t"), "success"));
}
