//! `miz build-efi-application --efi <application.efi> [-O raw|vhd] -o <output>`

const std = @import("std");
const miz = @import("miz");

const help_text =
    \\usage: miz build-efi-application --efi <application.efi>
    \\           [--architecture auto|x86_64|aarch64]
    \\           [--esp-size <size>] [--disk-size <size>]
    \\           [--max-efi-size <size>] [-O raw|vhd] -o <output>
    \\
    \\Packages one standalone PE32+ UEFI application in a deterministic GPT
    \\disk whose FAT32 ESP contains the architecture fallback path
    \\EFI/BOOT/BOOTX64.EFI or EFI/BOOT/BOOTAA64.EFI. VHD output is always
    \\native fixed VHD with a whole-MiB virtual size for Azure Gen2.
    \\
    \\The default ESP is 64M. The disk defaults to the smallest whole-MiB
    \\size that contains the 1M-aligned ESP and both GPT copies. Existing
    \\outputs are never overwritten. VHDX, qcow2, compression, and stdout
    \\are intentionally unsupported for this Azure-oriented artifact.
;

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var efi_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var output_format: ?miz.Format = null;
    var architecture: ?miz.efi_application_image.Architecture = null;
    var esp_size = miz.efi_application_image.default_esp_size;
    var disk_size: ?u64 = null;
    var max_efi_size = miz.efi_application_image.default_max_efi_size;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}\n", .{help_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--efi")) {
            i += 1;
            if (i >= args.len) return fail("build-efi-application: --efi requires a path", .{});
            efi_path = args[i];
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return fail("build-efi-application: -o/--output requires a path", .{});
            if (std.mem.eql(u8, args[i], "-")) {
                return fail("build-efi-application: stdout output is not supported", .{});
            }
            output_path = args[i];
        } else if (std.mem.eql(u8, arg, "-O")) {
            i += 1;
            if (i >= args.len) return fail("build-efi-application: -O requires raw or vhd", .{});
            const spec = miz.output.Spec.parseName(args[i]) orelse
                return fail("build-efi-application: unknown output format '{s}'", .{args[i]});
            if (spec.compression != .none) {
                return fail("build-efi-application: compressed output is not supported", .{});
            }
            output_format = spec.format;
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i >= args.len) return fail("build-efi-application: --architecture requires auto, x86_64, or aarch64", .{});
            if (std.mem.eql(u8, args[i], "auto")) {
                architecture = null;
            } else if (std.mem.eql(u8, args[i], "x86_64")) {
                architecture = .x86_64;
            } else if (std.mem.eql(u8, args[i], "aarch64")) {
                architecture = .aarch64;
            } else {
                return fail("build-efi-application: invalid architecture '{s}'", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--esp-size")) {
            i += 1;
            esp_size = parseSize(args, i, arg) orelse return 1;
        } else if (std.mem.eql(u8, arg, "--disk-size")) {
            i += 1;
            disk_size = parseSize(args, i, arg) orelse return 1;
        } else if (std.mem.eql(u8, arg, "--max-efi-size")) {
            i += 1;
            max_efi_size = parseSize(args, i, arg) orelse return 1;
        } else {
            return fail("build-efi-application: unexpected argument '{s}'", .{arg});
        }
    }

    const input = efi_path orelse
        return fail("build-efi-application: --efi is required", .{});
    const output = output_path orelse
        return fail("build-efi-application: -o/--output is required", .{});
    const format = output_format orelse inferFormat(output) orelse
        return fail("build-efi-application: cannot infer raw or vhd from output '{s}'; pass -O", .{output});
    if (format != .raw and format != .vhd) {
        return fail("build-efi-application: {s} output is unsupported; use raw or fixed vhd", .{format.displayName()});
    }

    const report = miz.efi_application_image.build(gpa, io, .{
        .efi_path = input,
        .output_path = output,
        .output_format = format,
        .architecture = architecture,
        .esp_size = esp_size,
        .disk_size = disk_size,
        .max_efi_size = max_efi_size,
    }) catch |err| {
        if (err == error.PathAlreadyExists) {
            return fail(
                "build-efi-application: output or scratch path already exists; refusing to overwrite it",
                .{},
            );
        }
        return fail("build-efi-application: failed: {s}", .{@errorName(err)});
    };

    const digest = std.fmt.bytesToHex(report.input_sha256, .lower);
    std.debug.print(
        "Built {s} EFI application image '{s}': {s}, boot path /{s}, " ++
            "virtual size {d}, ESP {d}+{d}, input SHA-256 {s}\n",
        .{
            report.output_format.displayName(),
            output,
            @tagName(report.architecture),
            report.boot_path,
            report.virtual_size,
            report.esp_offset_bytes,
            report.esp_length_bytes,
            &digest,
        },
    );
    return 0;
}

fn inferFormat(path: []const u8) ?miz.Format {
    const spec = miz.output.Spec.inferFromPath(path) orelse return null;
    if (spec.compression != .none) return null;
    return spec.format;
}

fn parseSize(args: []const []const u8, index: usize, option: []const u8) ?u64 {
    if (index >= args.len) {
        _ = fail("build-efi-application: {s} requires a size", .{option});
        return null;
    }
    return miz.parseSize(args[index]) catch {
        _ = fail("build-efi-application: invalid size '{s}' for {s}", .{ args[index], option });
        return null;
    };
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test "build-efi-application help and format inference" {
    try std.testing.expectEqual(@as(u8, 0), run(std.testing.allocator, std.testing.io, &.{"--help"}));
    try std.testing.expectEqual(miz.Format.raw, inferFormat("disk.img").?);
    try std.testing.expectEqual(miz.Format.vhd, inferFormat("disk.vhd").?);
    try std.testing.expect(inferFormat("disk.qcow2") == .qcow2);
    try std.testing.expect(inferFormat("disk.raw.gz") == null);
}
