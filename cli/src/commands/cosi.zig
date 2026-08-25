//! `miz cosi <disk-image> -o <output.cosi>`

const std = @import("std");
const miz = @import("miz");

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    _ = gpa;

    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return fail("cosi: -o/--output requires a path", .{});
            output_path = args[i];
        } else if (input_path == null) {
            input_path = arg;
        } else {
            return fail("cosi: unexpected argument '{s}'", .{arg});
        }
    }

    const src_path = input_path orelse return fail("usage: miz cosi <disk-image> -o <output.cosi>", .{});
    const dst_path = output_path orelse return fail("cosi: -o <output.cosi> is required", .{});

    var img = miz.Image.openPath(io, src_path) catch |err|
        return fail("cosi: failed to open '{s}': {s}", .{ src_path, @errorName(err) });
    defer img.close(io);

    miz.cosi.write(img, io, std.heap.smp_allocator, dst_path) catch |err|
        return fail("cosi: failed to write '{s}': {s}", .{ dst_path, @errorName(err) });

    return 0;
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}
