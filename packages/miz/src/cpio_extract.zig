//! Extract selected regular files from a newc cpio archive without invoking
//! the host `cpio` utility.  CI uses this only to unpack pinned kernel RPM
//! fixtures; production initramfs code uses the same reader.

const std = @import("std");
const cpio = @import("cpio.zig");

const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    if (argv.len < 4) return error.Usage;

    const archive = try Io.Dir.cwd().readFileAlloc(
        io,
        argv[1],
        allocator,
        .limited(256 * 1024 * 1024),
    );
    defer allocator.free(archive);

    const requested = argv[3..];
    const found = try allocator.alloc(bool, requested.len);
    defer allocator.free(found);
    @memset(found, false);
    for (requested) |wanted| {
        if (!cpio.isSafePath(wanted)) return error.InvalidPath;
    }

    var reader = cpio.Reader.init(archive);
    while (try reader.next()) |entry| {
        if (entry.kind != .file) continue;
        for (requested, 0..) |wanted, index| {
            if (!std.mem.eql(u8, normalized(entry.path), normalized(wanted))) continue;
            if (found[index]) return error.DuplicateMember;
            found[index] = true;
            const output_path = try std.fs.path.join(
                allocator,
                &.{ argv[2], normalized(wanted) },
            );
            defer allocator.free(output_path);
            if (std.fs.path.dirname(output_path)) |parent| {
                try Io.Dir.cwd().createDirPath(io, parent);
            }
            try Io.Dir.cwd().writeFile(io, .{
                .sub_path = output_path,
                .data = entry.content,
            });
        }
    }
    try reader.finish();
    for (found) |present| if (!present) return error.MemberNotFound;
}

fn normalized(path: []const u8) []const u8 {
    var result = path;
    while (std.mem.startsWith(u8, result, "./")) result = result[2..];
    return result;
}

test "normalizes safe cpio member names" {
    try std.testing.expectEqualStrings("boot/vmlinuz", normalized("./boot/vmlinuz"));
    try std.testing.expectEqualStrings("boot/vmlinuz", normalized("boot/vmlinuz"));
}
