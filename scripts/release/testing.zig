//! Test-only support for the release foundation.
//!
//! The helpers under test resolve paths against the process working directory,
//! and several test binaries include this module and run concurrently under
//! `zig build`. A fixture named in the working directory is therefore shared
//! between processes, and one test's cleanup is another test's missing file.
//! `TempTree` gives every test its own directory instead, while still handing
//! back working-directory-relative paths so the helpers are exercised exactly
//! as production callers use them.

const std = @import("std");

const Dir = std.Io.Dir;

pub const TempTree = struct {
    tmp: std.testing.TmpDir,

    /// Longest fixture name a test may ask for. Fixture names here are short
    /// and descriptive; the bound keeps `path` allocation-free.
    pub const max_name_len = 96;
    /// `.zig-cache/tmp/<random>/` plus a name, with room to spare.
    pub const max_path_len = 256;

    pub fn create() TempTree {
        return .{ .tmp = std.testing.tmpDir(.{}) };
    }

    pub fn deinit(self: *TempTree) void {
        self.tmp.cleanup();
        self.* = undefined;
    }

    /// A working-directory-relative path to `name` inside this tree.
    pub fn path(
        self: *const TempTree,
        buffer: *[max_path_len]u8,
        name: []const u8,
    ) []const u8 {
        std.debug.assert(name.len <= max_name_len);
        return std.fmt.bufPrint(buffer, ".zig-cache/tmp/{s}/{s}", .{
            self.tmp.sub_path,
            name,
        }) catch unreachable;
    }
};

test "each tree is private and disappears with the test" {
    const io = std.testing.io;
    var first = TempTree.create();
    var first_alive = true;
    defer if (first_alive) first.deinit();
    var second = TempTree.create();
    defer second.deinit();

    var first_buffer: [TempTree.max_path_len]u8 = undefined;
    var second_buffer: [TempTree.max_path_len]u8 = undefined;
    const first_path = first.path(&first_buffer, "fixture.bin");
    const second_path = second.path(&second_buffer, "fixture.bin");
    try std.testing.expect(!std.mem.eql(u8, first_path, second_path));

    try Dir.cwd().writeFile(io, .{ .sub_path = first_path, .data = "x" });
    try std.testing.expectEqual(
        @as(u64, 1),
        (try Dir.cwd().statFile(io, first_path, .{})).size,
    );
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(io, second_path, .{}),
    );

    first.deinit();
    first_alive = false;
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(io, first_path, .{}),
    );
}
