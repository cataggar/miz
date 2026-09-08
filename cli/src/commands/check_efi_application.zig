//! `miz check-efi-application [options] <image.vhd>`

const std = @import("std");
const miz = @import("miz");

const OutputMode = enum { human, json };

const help_text =
    \\usage: miz check-efi-application [--output=human|json]
    \\           [--architecture x86_64|aarch64]
    \\           [--expected-efi-sha256 <hex>]
    \\           [--expected-virtual-size <size>]
    \\           [--max-efi-size <size>] <image.vhd>
    \\
    \\Read-only preflight for the deterministic ESP-only fixed VHD emitted by
    \\`miz build-efi-application`. Success requires a valid fixed VHD footer,
    \\whole-MiB virtual size, protective MBR plus matching GPT copies, exactly
    \\one aligned FAT32 ESP, and exactly one architecture fallback EFI
    \\application. Optional expected values pin the deployment input.
;

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var output_mode: OutputMode = .human;
    var architecture: ?miz.efi_application_image.Architecture = null;
    var expected_sha256: ?[32]u8 = null;
    var expected_virtual_size: ?u64 = null;
    var max_efi_size = miz.efi_application_image.default_max_efi_size;
    var image_path: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}\n", .{help_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--output=human")) {
            output_mode = .human;
        } else if (std.mem.eql(u8, arg, "--output=json")) {
            output_mode = .json;
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i >= args.len) return fail("check-efi-application: --architecture requires x86_64 or aarch64", .{});
            architecture = std.meta.stringToEnum(miz.efi_application_image.Architecture, args[i]) orelse
                return fail("check-efi-application: invalid architecture '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--expected-efi-sha256")) {
            i += 1;
            if (i >= args.len) return fail("check-efi-application: --expected-efi-sha256 requires a digest", .{});
            expected_sha256 = miz.artifact_pipeline.parseSha256(args[i]) catch
                return fail("check-efi-application: invalid SHA-256 '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--expected-virtual-size")) {
            i += 1;
            expected_virtual_size = parseSize(args, i, arg) orelse return 1;
        } else if (std.mem.eql(u8, arg, "--max-efi-size")) {
            i += 1;
            max_efi_size = parseSize(args, i, arg) orelse return 1;
        } else if (image_path == null) {
            image_path = arg;
        } else {
            return fail("check-efi-application: unexpected argument '{s}'", .{arg});
        }
    }

    const path = image_path orelse
        return fail("check-efi-application: an image path is required", .{});
    const report = miz.efi_application_image.validateFixedVhd(gpa, io, .{
        .path = path,
        .architecture = architecture,
        .expected_efi_sha256 = expected_sha256,
        .expected_virtual_size = expected_virtual_size,
        .max_efi_size = max_efi_size,
    }) catch |err| {
        std.debug.print("EFI application image validation failed: {s}\n", .{@errorName(err)});
        return 2;
    };

    const digest = miz.artifact_pipeline.formatSha256(report.boot_file_sha256);
    var disk_guid: [36]u8 = undefined;
    var esp_guid: [36]u8 = undefined;
    const disk_guid_text = miz.guid.formatLower(&disk_guid, report.disk_guid);
    const esp_guid_text = miz.guid.formatLower(&esp_guid, report.esp_partition_guid);

    switch (output_mode) {
        .human => std.debug.print(
            "EFI application image is valid.\n" ++
                "format: vhd\nsubformat: fixed\ngeneration: 2\n" ++
                "virtual size: {d}\nfile size: {d}\narchitecture: {s}\n" ++
                "boot path: /{s}\nboot file size: {d}\nboot file SHA-256: {s}\n" ++
                "disk GUID: {s}\nESP partition GUID: {s}\n" ++
                "ESP offset: {d}\nESP length: {d}\nESP volume ID: {x:0>8}\n",
            .{
                report.virtual_size,
                report.file_size,
                @tagName(report.architecture),
                report.boot_path,
                report.boot_file_size,
                &digest,
                disk_guid_text,
                esp_guid_text,
                report.esp_offset_bytes,
                report.esp_length_bytes,
                report.esp_volume_id,
            },
        ),
        .json => {
            var buffer: [4096]u8 = undefined;
            var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
            const writer = &file_writer.interface;
            std.json.Stringify.value(.{
                .@"schema-version" = 1,
                .contract = "miz.efi-application-image",
                .valid = true,
                .format = "vhd",
                .subformat = "fixed",
                .generation = 2,
                .@"virtual-size" = report.virtual_size,
                .@"file-size" = report.file_size,
                .architecture = @tagName(report.architecture),
                .@"boot-path" = report.boot_path,
                .@"boot-file-size" = report.boot_file_size,
                .@"boot-file-sha256" = &digest,
                .@"disk-guid" = disk_guid_text,
                .@"esp-partition-guid" = esp_guid_text,
                .@"esp-offset" = report.esp_offset_bytes,
                .@"esp-length" = report.esp_length_bytes,
                .@"esp-volume-id" = report.esp_volume_id,
            }, .{}, writer) catch |err|
                return fail("check-efi-application: failed to format JSON: {s}", .{@errorName(err)});
            writer.writeByte('\n') catch |err|
                return fail("check-efi-application: failed to write JSON: {s}", .{@errorName(err)});
            writer.flush() catch |err|
                return fail("check-efi-application: failed to flush JSON: {s}", .{@errorName(err)});
        },
    }
    return 0;
}

fn parseSize(args: []const []const u8, index: usize, option: []const u8) ?u64 {
    if (index >= args.len) {
        _ = fail("check-efi-application: {s} requires a size", .{option});
        return null;
    }
    return miz.parseSize(args[index]) catch {
        _ = fail("check-efi-application: invalid size '{s}' for {s}", .{ args[index], option });
        return null;
    };
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test "check-efi-application help" {
    try std.testing.expectEqual(@as(u8, 0), run(std.testing.allocator, std.testing.io, &.{"--help"}));
}
