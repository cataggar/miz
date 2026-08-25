//! `miz resize <file> [+|-]<size>`

const std = @import("std");
const miz = @import("miz");

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    _ = gpa;
    if (args.len != 2) {
        return fail("usage: miz resize <file> [+]<size>", .{});
    }
    const path = args[0];
    const size_arg = args[1];

    var img = miz.Image.openPath(io, path) catch |err|
        return fail("resize: failed to open '{s}': {s}", .{ path, @errorName(err) });
    defer img.close(io);

    // Reported before parsing the size so the diagnostic names the real
    // problem: a device's size comes from whatever provides the device, and
    // no size argument could make this succeed.
    if (img.device != null) {
        return fail(
            "resize: '{s}' is a block device; resize it through whatever provides it (partition table, LVM, hypervisor) instead",
            .{path},
        );
    }

    const relative = size_arg.len > 0 and size_arg[0] == '+';
    const magnitude_str = if (relative) size_arg[1..] else size_arg;
    const magnitude = miz.parseSize(magnitude_str) catch |err|
        return fail("resize: invalid size '{s}': {s}", .{ size_arg, @errorName(err) });

    const new_size = if (relative) img.virtual_size + magnitude else magnitude;

    img.resize(io, new_size) catch |err| return fail("resize: failed: {s}", .{@errorName(err)});
    std.debug.print("Image resized to {d} bytes.\n", .{new_size});
    return 0;
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}
