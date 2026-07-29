//! `zvmi azure derive --input-sha256 <hex> <input.qcow2> <output.vhd>`
//! `zvmi azure fixup [--generation 1|2] <file>`
//! `zvmi azure deprovision [--user <username>] [--allow-device-write] <file>`
//!
//! Fixed VHD inputs are updated in place. Other supported image formats are
//! converted to a sibling fixed VHD named `<input-basename>.vhd`.
//! Generation 2 is the default; pass `--generation 1` for legacy BIOS images.

const std = @import("std");
const zvmi = @import("zvmi");

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    if (args.len < 1) return fail(usage, .{});
    if (std.mem.eql(u8, args[0], "derive")) return runDerive(gpa, io, args[1..]);
    if (std.mem.eql(u8, args[0], "fixup")) return runFixup(gpa, io, args[1..]);
    if (std.mem.eql(u8, args[0], "deprovision")) return runDeprovision(gpa, io, args[1..]);
    return fail(usage, .{});
}

const usage = "usage: zvmi azure derive --input-sha256 <hex> [--expected-virtual-size <size>] [--max-input-size <size>] [--max-virtual-size <size>] [--max-output-size <size>] <input.qcow2> <output.vhd>\n" ++
    "       zvmi azure fixup [--generation 1|2] <file>\n" ++
    "       zvmi azure deprovision [--user <username>] [--allow-device-write] <file>";

fn runDerive(gpa: std.mem.Allocator, io: std.Io, rest: []const []const u8) u8 {
    var input_sha256: ?zvmi.artifact_pipeline.Digest = null;
    var expected_virtual_size: ?u64 = null;
    var max_input_size: u64 = 64 * 1024 * 1024 * 1024;
    var max_virtual_size: u64 = 64 * 1024 * 1024 * 1024;
    var max_output_size: u64 = 64 * 1024 * 1024 * 1024 + 512;
    var positional: [2][]const u8 = undefined;
    var positional_count: usize = 0;

    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const argument = rest[i];
        if (std.mem.eql(u8, argument, "--input-sha256")) {
            i += 1;
            if (i >= rest.len) {
                return fail("azure derive: --input-sha256 requires an argument", .{});
            }
            input_sha256 = zvmi.artifact_pipeline.parseSha256(rest[i]) catch
                return fail("azure derive: invalid SHA-256 '{s}'", .{rest[i]});
        } else if (std.mem.eql(u8, argument, "--expected-virtual-size")) {
            i += 1;
            expected_virtual_size = parseSizeArgument(rest, i, argument) orelse
                return 1;
        } else if (std.mem.eql(u8, argument, "--max-input-size")) {
            i += 1;
            max_input_size = parseSizeArgument(rest, i, argument) orelse
                return 1;
        } else if (std.mem.eql(u8, argument, "--max-virtual-size")) {
            i += 1;
            max_virtual_size = parseSizeArgument(rest, i, argument) orelse
                return 1;
        } else if (std.mem.eql(u8, argument, "--max-output-size")) {
            i += 1;
            max_output_size = parseSizeArgument(rest, i, argument) orelse
                return 1;
        } else if (positional_count < positional.len) {
            positional[positional_count] = argument;
            positional_count += 1;
        } else {
            return fail("azure derive: unexpected argument '{s}'", .{argument});
        }
    }
    const digest = input_sha256 orelse
        return fail("azure derive: --input-sha256 <hex> is required", .{});
    if (positional_count != positional.len) return fail(usage, .{});

    const result = zvmi.azure.deriveFixedVhd(
        gpa,
        io,
        .{
            .input_path = positional[0],
            .expected_input_sha256 = digest,
            .max_input_size = max_input_size,
            .expected_virtual_size = expected_virtual_size,
            .max_virtual_size = max_virtual_size,
            .output_path = positional[1],
            .max_output_size = max_output_size,
        },
    ) catch |err| return fail("azure derive: failed: {s}", .{@errorName(err)});

    const output_sha256 =
        zvmi.artifact_pipeline.formatSha256(result.artifact.sha256);
    std.debug.print(
        "Derived fixed VHD '{s}': data size {d} -> {d} bytes, file size {d} bytes, {d} partitions, backup GPT LBA {d} -> {d}, SHA-256 {s}\n",
        .{
            positional[1],
            result.source_virtual_size,
            result.virtual_size,
            result.artifact.size,
            result.partition_count,
            result.relocation.old_backup_lba,
            result.relocation.new_backup_lba,
            &output_sha256,
        },
    );
    return 0;
}

fn parseSizeArgument(
    args: []const []const u8,
    index: usize,
    option: []const u8,
) ?u64 {
    if (index >= args.len) {
        _ = fail("azure derive: {s} requires an argument", .{option});
        return null;
    }
    return zvmi.parseSize(args[index]) catch {
        _ = fail(
            "azure derive: invalid size '{s}' for {s}",
            .{ args[index], option },
        );
        return null;
    };
}

fn runFixup(gpa: std.mem.Allocator, io: std.Io, rest: []const []const u8) u8 {
    const fixup_usage = "usage: zvmi azure fixup [--generation 1|2] <file>";
    var generation: zvmi.azure.Generation = .gen2;
    var path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const a = rest[i];
        if (std.mem.eql(u8, a, "--generation")) {
            i += 1;
            if (i >= rest.len) return fail("azure fixup: --generation requires an argument (1 or 2)", .{});
            if (std.mem.eql(u8, rest[i], "1")) {
                generation = .gen1;
            } else if (std.mem.eql(u8, rest[i], "2")) {
                generation = .gen2;
            } else {
                return fail("azure fixup: invalid --generation '{s}' (expected 1 or 2)", .{rest[i]});
            }
        } else if (path == null) {
            path = a;
        } else {
            return fail("azure fixup: unexpected argument '{s}'", .{a});
        }
    }

    const input_path = path orelse return fail(fixup_usage, .{});

    var src = zvmi.Image.openPath(io, input_path) catch |err|
        return fail("azure fixup: failed to open '{s}': {s}", .{ input_path, @errorName(err) });
    defer src.close(io);

    if (src.format == .vhd) {
        return finishFixup(&src, io, gpa, generation, input_path).exit_code;
    }

    const src_format = src.format;
    const src_virtual_size = src.virtual_size;
    const output_path = derivedVhdPath(gpa, input_path) catch |err|
        return fail("azure fixup: failed to derive output path: {s}", .{@errorName(err)});
    defer gpa.free(output_path);

    const initial_vhd_size = if (src_virtual_size % 512 == 0)
        src_virtual_size
    else
        zvmi.azure.alignSizeToMibChecked(src_virtual_size) catch |err|
            return fail("azure fixup: failed to align source size: {s}", .{@errorName(err)});

    var dst = zvmi.Image.createExclusive(io, output_path, .vhd, initial_vhd_size, .{
        .vhd_subformat = .fixed,
    }) catch |err| {
        if (err == error.PathAlreadyExists) {
            return fail(
                "azure fixup: output '{s}' already exists; refusing to overwrite it",
                .{output_path},
            );
        }
        return fail("azure fixup: failed to create '{s}': {s}", .{ output_path, @errorName(err) });
    };
    var keep_output = false;
    defer {
        dst.close(io);
        if (!keep_output) {
            std.Io.Dir.cwd().deleteFile(io, output_path) catch |err| {
                std.debug.print(
                    "azure fixup: failed to remove incomplete output '{s}': {s}\n",
                    .{ output_path, @errorName(err) },
                );
            };
        }
    }

    zvmi.copyAll(io, src, &dst, gpa) catch |err|
        return fail("azure fixup: conversion failed: {s}", .{@errorName(err)});

    const outcome = finishFixup(&dst, io, gpa, generation, output_path);
    keep_output = outcome.fixup_succeeded;
    if (keep_output) {
        std.debug.print(
            "Converted '{s}' ({s}) to fixed VHD '{s}'.\n",
            .{ input_path, src_format.displayName(), output_path },
        );
        if (initial_vhd_size != src_virtual_size) {
            std.debug.print(
                "Padded virtual size from {d} to {d} bytes for sector alignment.\n",
                .{ src_virtual_size, initial_vhd_size },
            );
        }
    }
    return outcome.exit_code;
}

const FixupOutcome = struct {
    exit_code: u8,
    fixup_succeeded: bool,
};

fn finishFixup(
    img: *zvmi.Image,
    io: std.Io,
    allocator: std.mem.Allocator,
    generation: zvmi.azure.Generation,
    file_path: []const u8,
) FixupOutcome {
    const report = zvmi.azure.checkPartitionStyle(img.*, io, allocator, generation) catch |err| return .{
        .exit_code = fail("azure fixup: failed to check partition style: {s}", .{@errorName(err)}),
        .fixup_succeeded = false,
    };
    const gen_name: []const u8 = if (generation == .gen1) "Gen1" else "Gen2";
    if (!report.ok) {
        std.debug.print("Partition style check FAILED for {s}: {s}\n", .{ gen_name, report.message });
        return .{ .exit_code = 2, .fixup_succeeded = false };
    }

    const align_result = zvmi.azure.alignFixedVhd(img, io) catch |err| {
        if (err == error.GptRelocationRequired) {
            return .{
                .exit_code = fail(
                    "azure fixup: GPT growth requires transactional relocation; use 'zvmi azure derive --input-sha256 <hex> <input.qcow2> <output.vhd>'",
                    .{},
                ),
                .fixup_succeeded = false,
            };
        }
        return .{
            .exit_code = fail(
                "azure fixup: {s} (Azure managed-disk upload requires a *fixed* .vhd; convert first with " ++
                    "'zvmi convert -O vhd -o subformat=fixed <src> {s}')",
                .{ @errorName(err), file_path },
            ),
            .fixup_succeeded = false,
        };
    };
    if (align_result.was_resized) {
        std.debug.print("Padded virtual size from {d} to {d} bytes (1 MiB alignment).\n", .{ align_result.old_size, align_result.new_size });
    } else {
        std.debug.print("Virtual size {d} bytes is already 1 MiB-aligned.\n", .{align_result.new_size});
    }

    std.debug.print("Partition style OK for {s}: {s}\n", .{ gen_name, report.message });
    return .{ .exit_code = 0, .fixup_succeeded = true };
}

fn derivedVhdPath(allocator: std.mem.Allocator, input_path: []const u8) std.mem.Allocator.Error![]u8 {
    const extension = std.fs.path.extension(input_path);
    return std.fmt.allocPrint(
        allocator,
        "{s}.vhd",
        .{input_path[0 .. input_path.len - extension.len]},
    );
}

fn runDeprovision(gpa: std.mem.Allocator, io: std.Io, rest: []const []const u8) u8 {
    var username: ?[]const u8 = null;
    var allow_device_write = false;
    var path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < rest.len) : (i += 1) {
        const a = rest[i];
        if (std.mem.eql(u8, a, "--user")) {
            i += 1;
            if (i >= rest.len) return fail("azure deprovision: --user requires an argument", .{});
            username = rest[i];
        } else if (std.mem.eql(u8, a, "--allow-device-write")) {
            allow_device_write = true;
        } else if (path == null) {
            path = a;
        } else {
            return fail("azure deprovision: unexpected argument '{s}'", .{a});
        }
    }

    const file_path = path orelse return fail(
        "usage: zvmi azure deprovision [--user <username>] [--allow-device-write] <file>",
        .{},
    );

    // Deprovisioning an installed system in place is the one workflow here
    // that legitimately writes to a live disk, so it is where the
    // block-device write opt-in is offered. Without it a `/dev/...` target
    // opens read-only and the first write fails.
    var img = zvmi.Image.openPathWithOptions(io, file_path, .{
        .allow_device_write = allow_device_write,
    }) catch |err|
        return fail("azure deprovision: failed to open '{s}': {s}", .{ file_path, @errorName(err) });
    defer img.close(io);

    const offset = zvmi.deprovision.findRootExt4Offset(gpa, img, io) catch |err|
        return fail("azure deprovision: failed to locate the root ext4 filesystem: {s}", .{@errorName(err)});

    zvmi.deprovision.deprovision(gpa, img, io, offset, .{ .username = username }) catch |err|
        return fail("azure deprovision: failed: {s}", .{@errorName(err)});

    if (username) |u| {
        std.debug.print("Deprovisioned '{s}' (hostname reset, SSH host keys/machine-id/DHCP state cleared, user '{s}' removed).\n", .{ file_path, u });
    } else {
        std.debug.print("Deprovisioned '{s}' (hostname reset, SSH host keys/machine-id/DHCP state cleared).\n", .{file_path});
    }
    return 0;
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test "derivedVhdPath replaces the input extension" {
    const allocator = std.testing.allocator;

    const qcow2_path = try derivedVhdPath(allocator, "images/disk.test.qcow2");
    defer allocator.free(qcow2_path);
    try std.testing.expectEqualStrings("images/disk.test.vhd", qcow2_path);

    const extensionless_path = try derivedVhdPath(allocator, "images/disk");
    defer allocator.free(extensionless_path);
    try std.testing.expectEqualStrings("images/disk.vhd", extensionless_path);
}

test "azure fixup defaults to Gen2 when converting qcow2 to fixed VHD" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const src_path = "test-azure-fixup-convert.qcow2";
    const dst_path = "test-azure-fixup-convert.vhd";
    defer std.Io.Dir.cwd().deleteFile(io, src_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, dst_path) catch {};

    const src_size: u64 = 8 * 1024 * 1024;
    var src = try zvmi.Image.create(io, src_path, .qcow2, src_size, .{});
    const specs = [_]zvmi.gpt.PartitionSpec{
        .{
            .type_guid = zvmi.guid.esp,
            .unique_guid = zvmi.guid.parse("88888888-8888-8888-8888-888888888888"),
            .size_sectors = 2048,
        },
    };
    var placements: [specs.len]zvmi.gpt.Placement = undefined;
    try zvmi.gpt.writeGpt(
        &src,
        io,
        zvmi.guid.parse("99999999-9999-9999-9999-999999999999"),
        &specs,
        &placements,
    );
    try src.pwrite(io, "qcow2 payload", 2 * 1024 * 1024);
    src.close(io);

    try std.testing.expectEqual(
        @as(u8, 0),
        run(allocator, io, &.{ "fixup", src_path }),
    );

    var converted = try zvmi.Image.openPath(io, dst_path);
    defer converted.close(io);
    try std.testing.expectEqual(zvmi.Format.vhd, converted.format);
    try std.testing.expect(converted.dynamic == null);
    try std.testing.expectEqual(src_size, converted.virtual_size);

    var payload: [13]u8 = undefined;
    _ = try converted.pread(io, &payload, 2 * 1024 * 1024);
    try std.testing.expectEqualSlices(u8, "qcow2 payload", &payload);
}
