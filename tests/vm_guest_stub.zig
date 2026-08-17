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
//!
//! A second copy is planted as `hook_interpreter_path`, and a hook script whose
//! `#!` line names it makes this the same proof for the script channel: a
//! caller's script is carried into a guest the host cannot run and executed by
//! the guest's own interpreter, against the guest's own root.

const std = @import("std");

pub const marker_path = "/var/lib/vmiz-vm/booted";
pub const marker_bytes = "guest reached the target root\n";
pub const installed_nevra = "vm-boot-package-0:1.0-1.noarch";
pub const version_line = "RPM version vm-boot-1";

/// Where the test plants the second copy, and what the hook script's `#!` line
/// therefore has to say.
pub const hook_interpreter_path = "/usr/bin/vmiz-hook-interpreter";
pub const hook_marker_path = "/var/lib/vmiz-vm/hook";

/// The guest writes the hook's own arguments here, so the marker proves not
/// only that the script ran but that what the caller declared reached it.
pub const hook_marker_bytes = "hook ran: --marker guest\n";
pub const hook_arguments = [_][]const u8{ "--marker", "guest" };

/// The kernel hands a `#!` interpreter the script's path in `argv[1]`, and the
/// guest derives that path from the hook's position rather than from anything
/// the caller said. Recognising the prefix is how this binary tells a hook run
/// from an `rpm` run.
const hook_script_prefix = "/run/vmiz-hook-";

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
    if (argv.len >= 2 and std.mem.startsWith(u8, argv[1], hook_script_prefix)) {
        return runAsHookInterpreter(allocator, io, cwd, argv[2..]);
    }

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

fn runAsHookInterpreter(
    allocator: std.mem.Allocator,
    io: Io,
    cwd: Io.Dir,
    arguments: []const []const u8,
) !void {
    var line: std.ArrayList(u8) = .empty;
    try line.appendSlice(allocator, "hook ran:");
    for (arguments) |argument| {
        try line.append(allocator, ' ');
        try line.appendSlice(allocator, argument);
    }
    try line.append(allocator, '\n');

    cwd.createDir(io, std.fs.path.dirname(hook_marker_path).?, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const file = try cwd.createFile(io, hook_marker_path, .{});
    defer file.close(io);
    try file.writePositionalAll(io, line.items, 0);

    // Streamed to the guest console, where a failing run leaves it in the log.
    std.debug.print("{s}", .{line.items});
}

const Io = std.Io;
