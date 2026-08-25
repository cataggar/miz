const std = @import("std");
const builtin = @import("builtin");
const miz = @import("miz");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

pub fn writeAtomic(
    io: Io,
    allocator: Allocator,
    destination: []const u8,
    bytes: []const u8,
) !void {
    return writeAtomicProtected(io, allocator, destination, bytes, null);
}

pub fn writeAtomicProtected(
    io: Io,
    allocator: Allocator,
    destination: []const u8,
    bytes: []const u8,
    protected_file: ?Io.File,
) !void {
    _ = allocator;
    var stage = try Dir.cwd().createFileAtomic(io, destination, .{
        .permissions = privateFilePermissions(),
        .replace = true,
    });
    defer stage.deinit(io);
    if (protected_file) |protected| {
        if (try aliasesProtectedFile(io, stage.dir, stage.dest_sub_path, protected))
            return error.OutputAliasesInput;
    }
    try stage.file.writePositionalAll(io, bytes, 0);
    try stage.file.sync(io);
    try stage.replace(io);
}

fn privateFilePermissions() Io.File.Permissions {
    return switch (builtin.os.tag) {
        .windows => .default_file,
        else => .fromMode(0o600),
    };
}

fn aliasesProtectedFile(
    io: Io,
    destination_dir: Dir,
    destination_basename: []const u8,
    protected_file: Io.File,
) !bool {
    const destination_stat = destination_dir.statFile(
        io,
        destination_basename,
        .{ .follow_symlinks = false },
    ) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    if (destination_stat.kind != .file) return false;
    const destination_file = try destination_dir.openFile(
        io,
        destination_basename,
        .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
        },
    );
    defer destination_file.close(io);
    return miz.artifact_pipeline.sameFileIdentity(
        io,
        protected_file,
        destination_file,
    );
}

test "atomic replacement never uses a predictable sibling path" {
    const io = std.testing.io;
    const destination = "test-atomic-output.pem";
    const sibling = destination ++ ".miz-output";
    defer Dir.cwd().deleteFile(io, destination) catch {};
    defer Dir.cwd().deleteFile(io, sibling) catch {};
    try Dir.cwd().writeFile(io, .{ .sub_path = destination, .data = "old" });
    try Dir.cwd().writeFile(io, .{ .sub_path = sibling, .data = "input" });

    try writeAtomic(io, std.testing.allocator, destination, "new");
    const output = try Dir.cwd().readFileAlloc(
        io,
        destination,
        std.testing.allocator,
        .limited(16),
    );
    defer std.testing.allocator.free(output);
    const untouched = try Dir.cwd().readFileAlloc(
        io,
        sibling,
        std.testing.allocator,
        .limited(16),
    );
    defer std.testing.allocator.free(untouched);
    try std.testing.expectEqualStrings("new", output);
    try std.testing.expectEqualStrings("input", untouched);
}

test "protected output rejects an alias through a symlinked directory" {
    const io = std.testing.io;
    const cwd = Dir.cwd();
    const real_dir = "test-atomic-output-real";
    const alias_dir = "test-atomic-output-alias";
    const input_path = real_dir ++ "/disk.img";
    const output_path = alias_dir ++ "/disk.img";
    defer cwd.deleteFile(io, alias_dir) catch {};
    defer cwd.deleteTree(io, real_dir) catch {};
    try cwd.createDir(io, real_dir, .default_dir);
    try cwd.writeFile(io, .{ .sub_path = input_path, .data = "disk image" });
    try cwd.symLink(io, real_dir, alias_dir, .{ .is_directory = true });
    const input_file = try cwd.openFile(io, input_path, .{
        .mode = .read_only,
    });
    defer input_file.close(io);

    try std.testing.expectError(
        error.OutputAliasesInput,
        writeAtomicProtected(
            io,
            std.testing.allocator,
            output_path,
            "certificate",
            input_file,
        ),
    );
    const input = try cwd.readFileAlloc(
        io,
        input_path,
        std.testing.allocator,
        .limited(32),
    );
    defer std.testing.allocator.free(input);
    try std.testing.expectEqualStrings("disk image", input);
}
