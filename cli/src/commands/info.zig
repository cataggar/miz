//! `vmiz info [--output=human|json] <file>`

const std = @import("std");
const vmiz = @import("vmiz");

const OutputMode = enum { human, json };

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var output: OutputMode = .human;
    var path: ?[]const u8 = null;

    for (args) |a| {
        if (std.mem.eql(u8, a, "--output=json")) {
            output = .json;
        } else if (std.mem.eql(u8, a, "--output=human")) {
            output = .human;
        } else if (path == null) {
            path = a;
        } else {
            return fail("info: unexpected argument '{s}'", .{a});
        }
    }

    const file_path = path orelse return fail("usage: vmiz info [--output=human|json] <file>", .{});

    var img = vmiz.Image.openPath(io, file_path) catch |err|
        return fail("info: failed to open '{s}': {s}", .{ file_path, @errorName(err) });
    defer img.close(io);

    const stat = img.info(io) catch |err|
        return fail("info: failed to stat '{s}': {s}", .{ file_path, @errorName(err) });

    switch (output) {
        .human => {
            std.debug.print(
                "image: {s}\nfile format: {s}\nvirtual size: {d} ({d} bytes)\ndisk size: {d} bytes\n",
                .{ file_path, stat.format.displayName(), stat.virtual_size, stat.virtual_size, stat.file_size },
            );
            if (stat.subformat) |sf| {
                std.debug.print("subformat: {s}\n", .{if (sf == .fixed) "fixed" else "dynamic"});
            }
        },
        .json => {
            var buf: [512]u8 = undefined;
            var writer = std.Io.Writer.fixed(&buf);
            std.json.Stringify.value(.{
                .filename = file_path,
                .format = stat.format.displayName(),
                .@"virtual-size" = stat.virtual_size,
                .@"actual-size" = stat.file_size,
                .subformat = if (stat.subformat) |sf| (if (sf == .fixed) "fixed" else "dynamic") else null,
            }, .{}, &writer) catch |err|
                return fail("info: failed to format JSON: {s}", .{@errorName(err)});
            std.debug.print("{s}\n", .{writer.buffered()});
        },
    }

    _ = gpa;
    return 0;
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}
