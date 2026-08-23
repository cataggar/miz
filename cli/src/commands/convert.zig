//! `vmiz convert -f <src_format> -O <dst_format> [-o subformat=fixed|dynamic|-] [--compress-level <1-9>] <src> <dst>`

const std = @import("std");
const vmiz = @import("vmiz");
const opts = @import("opts.zig");

const usage_text = "usage: vmiz convert -f <src_format> -O <dst_format> [-o subformat=fixed|dynamic] [--compress-level <1-9>] <src> <dst|->";

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var dst_spec: ?vmiz.output.Spec = null;
    var options: vmiz.CreateOptions = .{};
    var level: ?vmiz.output.Level = null;
    var stdout_requested = false;
    var positional: [2][]const u8 = undefined;
    var positional_count: usize = 0;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-f")) {
            // Source format is auto-detected by Image.openPath; -f is
            // accepted (like qemu-img) but only used as a sanity check.
            i += 1;
            if (i >= args.len) return fail("convert: -f requires a format argument", .{});
            if (vmiz.Format.parseName(args[i]) == null)
                return fail("convert: unknown source format '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, a, "-O")) {
            i += 1;
            if (i >= args.len) return fail("convert: -O requires a format argument", .{});
            dst_spec = vmiz.output.Spec.parseName(args[i]) orelse
                return fail("convert: unknown destination format '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, a, "-o")) {
            i += 1;
            if (i >= args.len) return fail("convert: -o requires an option list", .{});
            // `-o -` is the pipe spelling asked for by the compressed-output
            // proposal. It can never be a `key=value` list, so there is
            // nothing to disambiguate against.
            if (std.mem.eql(u8, args[i], "-")) {
                stdout_requested = true;
            } else {
                options = opts.parseVhdCreateOptions(args[i]) orelse return 1;
            }
        } else if (std.mem.eql(u8, a, "--compress-level")) {
            i += 1;
            if (i >= args.len) return fail("convert: --compress-level requires a value", .{});
            level = vmiz.output.parseLevel(args[i]) catch
                return fail("convert: invalid --compress-level '{s}' (expected 1 fastest through 9 smallest)", .{args[i]});
        } else if (positional_count < positional.len) {
            positional[positional_count] = a;
            positional_count += 1;
        } else {
            return fail("convert: unexpected argument '{s}'", .{a});
        }
    }

    const spec = dst_spec orelse return fail("convert: -O <format> is required", .{});
    if (positional_count == 0 or (positional_count == 1 and !stdout_requested)) {
        return fail(usage_text, .{});
    }
    const src_path = positional[0];
    const destination: vmiz.output.Destination = if (positional_count == 2) blk: {
        if (std.mem.eql(u8, positional[1], "-")) break :blk .stdout;
        if (stdout_requested)
            return fail("convert: -o - writes to stdout, so '{s}' cannot also be the destination", .{positional[1]});
        break :blk .{ .path = positional[1] };
    } else .stdout;

    vmiz.output.validate(spec, destination, level) catch |err|
        return fail("convert: -O {s}: {s}", .{ spec.displayName(), opts.describeOutputError(err) });

    var src = vmiz.Image.openPathReadOnly(io, src_path) catch |err|
        return fail("convert: failed to open '{s}': {s}", .{ src_path, @errorName(err) });
    defer src.close(io);

    // An uncompressed file destination keeps the create-then-copy path: it
    // lets sparse destination formats allocate only the blocks that hold
    // data, which a forward-only stream cannot express.
    if (spec.compression == .none and destination == .path) {
        const dst_path = destination.path;
        var dst = vmiz.Image.create(io, dst_path, spec.format, src.virtual_size, options) catch |err|
            return fail("convert: failed to create '{s}': {s}", .{ dst_path, @errorName(err) });
        defer dst.close(io);

        vmiz.copyAll(io, src, &dst, gpa) catch |err|
            return fail("convert: copy failed: {s}", .{@errorName(err)});
        return 0;
    }

    vmiz.output.writeImageTo(gpa, io, src, destination, .{
        .compression = spec.compression,
        .level = level orelse vmiz.output.default_level,
    }) catch |err|
        return fail("convert: writing {s} output failed: {s}", .{ spec.displayName(), @errorName(err) });

    return 0;
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test "convert still refuses a block-device destination through Image.create" {
    const io = std.testing.io;
    const destination = blockDevicePathForTest(io) orelse return error.SkipZigTest;
    const source = "test-convert-device-source.raw";
    defer std.Io.Dir.cwd().deleteFile(io, source) catch {};

    var src = try vmiz.Image.create(io, source, .raw, 4096, .{});
    src.close(io);

    try std.testing.expectEqual(
        @as(u8, 1),
        run(std.testing.allocator, io, &.{ "-f", "raw", "-O", "raw", source, destination }),
    );
    try std.testing.expectEqual(
        std.Io.File.Kind.block_device,
        (try std.Io.Dir.cwd().statFile(io, destination, .{})).kind,
    );
}

fn blockDevicePathForTest(io: std.Io) ?[]const u8 {
    for ([_][]const u8{ "/dev/loop0", "/dev/sda", "/dev/vda", "/dev/nvme0n1" }) |path| {
        const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch continue;
        if (stat.kind == .block_device) return path;
    }
    return null;
}
