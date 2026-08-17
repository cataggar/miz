const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 2) {
        std.debug.print("usage: vmiz-input-validator <oci-layout>\n", .{});
        std.process.exit(2);
    }

    var dir = std.Io.Dir.cwd().openDir(init.io, args[1], .{ .iterate = true }) catch |err| {
        std.debug.print("vmiz-input-validator: cannot open '{s}': {t}\n", .{ args[1], err });
        std.process.exit(1);
    };
    defer dir.close(init.io);

    validateDirectory(init.gpa, init.io, dir) catch |err| {
        if (err == error.UnsupportedEntry) {
            std.debug.print("vmiz-input-validator: OCI layout '{s}' contains a symlink or special file; only regular files and directories are supported\n", .{args[1]});
        } else {
            std.debug.print("vmiz-input-validator: cannot validate '{s}': {t}\n", .{ args[1], err });
        }
        std.process.exit(1);
    };
}

fn validateDirectory(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file and entry.kind != .directory) {
            return error.UnsupportedEntry;
        }
    }
}

test "OCI layout validation accepts files and rejects symlinks" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var file = try tmp.dir.createFile(std.testing.io, "blob", .{});
    file.close(std.testing.io);
    try validateDirectory(std.testing.allocator, std.testing.io, tmp.dir);

    try tmp.dir.symLink(std.testing.io, "blob", "linked-blob", .{});
    try std.testing.expectError(
        error.UnsupportedEntry,
        validateDirectory(std.testing.allocator, std.testing.io, tmp.dir),
    );
}
