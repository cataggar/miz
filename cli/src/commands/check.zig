//! `vmiz check <file>`

const std = @import("std");
const vmiz = @import("vmiz");

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    _ = gpa;
    if (args.len != 1) {
        return fail("usage: vmiz check <file>", .{});
    }
    const path = args[0];

    var img = vmiz.Image.openPath(io, path) catch |err|
        return fail("check: failed to open '{s}': {s}", .{ path, @errorName(err) });
    defer img.close(io);

    const result = img.check(io) catch |err|
        return fail("check: failed: {s}", .{@errorName(err)});

    if (result.ok) {
        std.debug.print("No errors were found on the image.\n{s}\n", .{result.message});
        return 0;
    }
    std.debug.print("Image is corrupted: {s}\n", .{result.message});
    return 2;
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}
