//! `miz info [--output=human|json] <file>`

const std = @import("std");
const miz = @import("miz");

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

    const file_path = path orelse return fail("usage: miz info [--output=human|json] <file>", .{});

    var img = miz.Image.openPath(io, file_path) catch |err|
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
            if (img.qcow2) |q| {
                std.debug.print("compression type: {s}\n", .{qcow2CompressionName(q.compression_type)});
                if (q.backing_file_len > 0) {
                    std.debug.print("backing file: {s}\n", .{q.backing_file_path[0..q.backing_file_len]});
                }
            }
        },
        .json => {
            // Mirror the subset of qemu-img's `info --output=json` schema that
            // downstream release tooling consumes, so native metadata can
            // replace `qemu-img info` as the publication input.
            const backing_filename: ?[]const u8 = if (img.qcow2) |q|
                (if (q.backing_file_len > 0) q.backing_file_path[0..q.backing_file_len] else null)
            else
                null;
            const format_specific: ?FormatSpecific = if (img.qcow2) |q| .{
                .type = "qcow2",
                .data = .{
                    .@"compression-type" = qcow2CompressionName(q.compression_type),
                    .compat = if (q.version >= 3) "1.1" else "0.10",
                },
            } else null;

            var buf: [4096]u8 = undefined;
            var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buf);
            const writer = &file_writer.interface;
            std.json.Stringify.value(.{
                .filename = file_path,
                .format = stat.format.displayName(),
                .@"virtual-size" = stat.virtual_size,
                .@"actual-size" = stat.file_size,
                .subformat = if (stat.subformat) |sf| (if (sf == .fixed) "fixed" else "dynamic") else null,
                .@"backing-filename" = backing_filename,
                .@"format-specific" = format_specific,
            }, .{}, writer) catch |err|
                return fail("info: failed to format JSON: {s}", .{@errorName(err)});
            writer.writeByte('\n') catch |err|
                return fail("info: failed to write JSON: {s}", .{@errorName(err)});
            writer.flush() catch |err|
                return fail("info: failed to flush JSON: {s}", .{@errorName(err)});
        },
    }

    _ = gpa;
    return 0;
}

const Qcow2FormatData = struct {
    @"compression-type": []const u8,
    compat: []const u8,
};

const FormatSpecific = struct {
    type: []const u8,
    data: Qcow2FormatData,
};

/// Maps a qcow2 header compression_type byte to qemu-img's reported name.
fn qcow2CompressionName(compression_type: u8) []const u8 {
    return switch (compression_type) {
        0 => "zlib",
        1 => "zstd",
        else => "unknown",
    };
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test "qcow2CompressionName maps header bytes to qemu-img names" {
    try std.testing.expectEqualStrings("zlib", qcow2CompressionName(0));
    try std.testing.expectEqualStrings("zstd", qcow2CompressionName(1));
    try std.testing.expectEqualStrings("unknown", qcow2CompressionName(2));
}

test "info emits native zstd metadata compatible with the release validator" {
    const io = std.testing.io;
    const cs: u64 = 65536;
    const clusters: u64 = 4;
    const virtual_size = cs * clusters;
    const path = "test-info-native-zstd.qcow2";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    // Emit a real standalone zstd qcow2 with the native writer, then confirm
    // the Image + info metadata report exactly what the release gate checks.
    const data = try std.testing.allocator.alloc(u8, @intCast(virtual_size));
    defer std.testing.allocator.free(data);
    @memset(data, 0);
    for (data[0..@intCast(cs)], 0..) |*b, i| b.* = @intCast('A' + (i % 7));

    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    var src = TestSliceSource{ .data = data };
    _ = try miz.qcow2.writeStandaloneCompressed(
        std.testing.allocator,
        io,
        file,
        virtual_size,
        src.reader(),
        .{},
    );
    file.close(io);

    var img = try miz.Image.openPathReadOnlyStandalone(io, path);
    defer img.close(io);
    try std.testing.expectEqual(miz.Format.qcow2, img.format);
    try std.testing.expectEqual(virtual_size, img.virtual_size);
    const q = img.qcow2.?;
    try std.testing.expectEqualStrings("zstd", qcow2CompressionName(q.compression_type));
    try std.testing.expectEqual(@as(u16, 0), q.backing_file_len);
}

const TestSliceSource = struct {
    data: []const u8,

    fn reader(self: *const TestSliceSource) miz.qcow2.SourceReader {
        return .{ .context = self, .readFn = read };
    }

    fn read(context: *const anyopaque, io: std.Io, offset: u64, buffer: []u8) anyerror!void {
        _ = io;
        const self: *const TestSliceSource = @ptrCast(@alignCast(context));
        const available: usize = if (offset >= self.data.len)
            0
        else
            @intCast(@min(@as(u64, buffer.len), self.data.len - offset));
        if (available > 0) @memcpy(buffer[0..available], self.data[@intCast(offset)..][0..available]);
        if (available < buffer.len) @memset(buffer[available..], 0);
    }
};
