//! Stands in for `rpm` inside the guest that `tests/vm_real_boot.zig` boots.
//!
//! It is a program of its own, rather than the test binary re-entered under a
//! different name, because a cross-architecture run puts a foreign-architecture
//! guest on the other side of the emulator: the test cannot execute there. It
//! is built for every guest architecture and embedded into the test, which
//! plants the matching one in the image it customizes.
//!
//! Writing a file the host can later find in the published image is the whole
//! point. Its presence proves the guest booted the image's own kernel, found
//! the root filesystem, mounted it writable, and executed a binary out of it.

const std = @import("std");

pub const marker_path = "/var/lib/zvmi-vm/booted";
pub const marker_bytes = "guest reached the target root\n";
pub const installed_nevra = "vm-boot-package-0:1.0-1.noarch";
pub const version_line = "RPM version vm-boot-1";

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const io = init.io;
    const argv = try init.minimal.args.toSlice(allocator);

    for (argv[1..]) |argument| {
        if (std.mem.eql(u8, argument, "--version")) {
            std.debug.print("{s}\n", .{version_line});
            return;
        }
    }

    const cwd = Io.Dir.cwd();
    cwd.createDir(io, std.fs.path.dirname(marker_path).?, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const file = try cwd.createFile(io, marker_path, .{});
    defer file.close(io);
    try file.writePositionalAll(io, marker_bytes, 0);

    // The agent parses this the way it parses real `rpm -qa` output, so the
    // inventory it reports back is exercised rather than assumed.
    std.debug.print("{s}\n", .{installed_nevra});
}

const Io = std.Io;
