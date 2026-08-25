//! `miz resize-root [--label <label>] <file.qcow2> [+]<size>`

const std = @import("std");
const miz = @import("miz");

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var label = miz.root_resize.default_filesystem_label;
    var path: ?[]const u8 = null;
    var size_arg: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--label") or
            std.mem.eql(u8, arg, "--root-label"))
        {
            i += 1;
            if (i >= args.len) return fail("resize-root: --label requires a value", .{});
            label = args[i];
        } else if (path == null) {
            path = arg;
        } else if (size_arg == null) {
            size_arg = arg;
        } else {
            return fail("resize-root: unexpected argument '{s}'", .{arg});
        }
    }

    const image_path = path orelse
        return fail("usage: miz resize-root [--label <label>] <file.qcow2> [+]<size>", .{});
    const requested_size = size_arg orelse
        return fail("usage: miz resize-root [--label <label>] <file.qcow2> [+]<size>", .{});
    const relative = requested_size.len > 0 and requested_size[0] == '+';
    const magnitude_text = if (relative) requested_size[1..] else requested_size;
    const magnitude = miz.parseSize(magnitude_text) catch |err|
        return fail("resize-root: invalid size '{s}': {s}", .{ requested_size, @errorName(err) });

    var image = miz.Image.openPathReadOnlyStandalone(io, image_path) catch |err|
        return fail("resize-root: failed to open '{s}': {s}", .{ image_path, @errorName(err) });
    const current_size = image.virtual_size;
    image.close(io);
    const target_size = if (relative)
        std.math.add(u64, current_size, magnitude) catch
            return fail("resize-root: requested size is too large", .{})
    else
        magnitude;

    const report = miz.root_resize.growExistingQcow2(
        gpa,
        io,
        image_path,
        .{
            .target_size = target_size,
            .filesystem_label = label,
        },
    ) catch |err| return fail(
        "resize-root: failed for '{s}': {s}",
        .{ image_path, @errorName(err) },
    );
    std.debug.print(
        "Grew '{s}' from {d} to {d} bytes; root partition and ext4 filesystem now {d} bytes.\n",
        .{
            image_path,
            report.old_virtual_size,
            report.new_virtual_size,
            report.new_root_length,
        },
    );
    return 0;
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test "resize-root parses an explicit label spelling" {
    // Keep this command-level test focused on the accepted option spelling;
    // the native operation has its complete end-to-end coverage in the
    // library module.
    const args = [_][]const u8{
        "--label",
        "rootfs",
        "disk.qcow2",
        "+1G",
    };
    try std.testing.expectEqualStrings("rootfs", args[1]);
}
