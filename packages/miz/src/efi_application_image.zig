//! Packages one standalone UEFI application as a bootable ESP-only disk.
//!
//! This is intentionally separate from `build_image`: a UEFI application is
//! already the complete guest payload, so inventing a Linux root filesystem,
//! kernel command line, or distro bootloader around it would be misleading.

const std = @import("std");
const Io = std.Io;

const azure = @import("azure.zig");
const fat32 = @import("fat32.zig");
const Format = @import("formats.zig").Format;
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const default_esp_size: u64 = 64 * azure.one_mib;
pub const default_max_efi_size: u64 = 512 * azure.one_mib;
pub const maximum_esp_size: u64 = 8 * 1024 * azure.one_mib;
pub const esp_offset: u64 = azure.one_mib;
pub const fallback_x86_64 = "EFI/BOOT/BOOTX64.EFI";
pub const fallback_aarch64 = "EFI/BOOT/BOOTAA64.EFI";

pub const Architecture = enum {
    x86_64,
    aarch64,

    pub fn fallbackPath(self: Architecture) []const u8 {
        return switch (self) {
            .x86_64 => fallback_x86_64,
            .aarch64 => fallback_aarch64,
        };
    }
};

pub const Options = struct {
    efi_path: []const u8,
    output_path: []const u8,
    output_format: Format,
    architecture: ?Architecture = null,
    esp_size: u64 = default_esp_size,
    /// Null selects the smallest whole-MiB disk that can contain the aligned
    /// ESP plus the backup GPT metadata.
    disk_size: ?u64 = null,
    max_efi_size: u64 = default_max_efi_size,
};

pub const Report = struct {
    output_format: Format,
    architecture: Architecture,
    boot_path: []const u8,
    input_size: u64,
    input_sha256: [Sha256.digest_length]u8,
    virtual_size: u64,
    esp_offset_bytes: u64,
    esp_length_bytes: u64,
    disk_guid: guid.Guid,
    esp_partition_guid: guid.Guid,
    esp_volume_id: u32,
};

pub const Error = error{
    InvalidEfiImage,
    UnsupportedEfiArchitecture,
    EfiArchitectureMismatch,
    NotEfiApplication,
    EfiFileExceedsLimit,
    EfiFileTooLarge,
    EfiInputChanged,
    InvalidEfiSizeLimit,
    UnsupportedOutputFormat,
    InvalidOutputPath,
    EspSizeNotMibAligned,
    EspTooSmall,
    EspTooLarge,
    DiskSizeNotMibAligned,
    DiskTooSmall,
    SizeOverflow,
    OutputImageCheckFailed,
    OutputVerificationFailed,
};

const Inspection = struct {
    architecture: Architecture,
    size: u64,
    sha256: [Sha256.digest_length]u8,
};

const Identity = struct {
    disk_guid: guid.Guid,
    esp_partition_guid: guid.Guid,
    esp_volume_id: u32,
    vhd_unique_id: [16]u8,
};

pub fn build(
    allocator: std.mem.Allocator,
    io: Io,
    options: Options,
) !Report {
    if (options.output_path.len == 0) return error.InvalidOutputPath;
    if (options.output_format != .raw and options.output_format != .vhd) {
        return error.UnsupportedOutputFormat;
    }
    if (options.max_efi_size == 0 or options.max_efi_size > std.math.maxInt(u32)) {
        return error.InvalidEfiSizeLimit;
    }
    if (options.esp_size % azure.one_mib != 0) return error.EspSizeNotMibAligned;
    if (options.esp_size > maximum_esp_size) return error.EspTooLarge;

    const input = try Io.Dir.cwd().openFile(io, options.efi_path, .{ .mode = .read_only });
    defer input.close(io);
    const inspection = try inspect(input, io, options.architecture, options.max_efi_size);
    const boot_path = inspection.architecture.fallbackPath();

    const minimum_esp_size = try minimumEspSize(inspection.size, boot_path);
    if (options.esp_size < minimum_esp_size) return error.EspTooSmall;

    const minimum_disk_size = try minimumDiskSize(options.esp_size);
    const disk_size = options.disk_size orelse minimum_disk_size;
    if (disk_size % azure.one_mib != 0) return error.DiskSizeNotMibAligned;
    if (disk_size < minimum_disk_size) return error.DiskTooSmall;

    const identity = deriveIdentity(
        inspection.sha256,
        inspection.architecture,
        options.esp_size,
        disk_size,
    );

    const raw_path = if (options.output_format == .raw)
        options.output_path
    else
        try std.fmt.allocPrint(allocator, "{s}.build-efi-application.raw", .{options.output_path});
    defer if (options.output_format != .raw) allocator.free(raw_path);

    var raw = try Image.createExclusive(io, raw_path, .raw, disk_size, .{});
    var raw_open = true;
    var keep_raw = false;
    defer {
        if (raw_open) raw.close(io);
        if (!keep_raw) Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    }

    const esp_first_lba = esp_offset / gpt.sector_size;
    const esp_sectors = options.esp_size / gpt.sector_size;
    try gpt.writeGptPlaced(&raw, io, identity.disk_guid, &.{.{
        .type_guid = guid.esp,
        .unique_guid = identity.esp_partition_guid,
        .placement = .{
            .first_lba = esp_first_lba,
            .last_lba = esp_first_lba + esp_sectors - 1,
        },
        .name_utf16le = gpt.asciiName("EFI System Partition"),
    }});

    try fat32.format(&raw, io, .{
        .partition_offset = esp_offset,
        .partition_len = options.esp_size,
        .hidden_sectors = @intCast(esp_first_lba),
        .volume_id = identity.esp_volume_id,
        .volume_label = "MIZ EFI APP".*,
    });
    var filesystem = try fat32.open(&raw, io, .{
        .offset = esp_offset,
        .length = options.esp_size,
    });
    try filesystem.createDir(io, "EFI/BOOT");
    const copied_sha256 = try copyInputToEsp(input, io, inspection.size, &filesystem, boot_path);
    if (!std.crypto.timing_safe.eql(
        [Sha256.digest_length]u8,
        copied_sha256,
        inspection.sha256,
    )) return error.EfiInputChanged;

    raw.close(io);
    raw_open = false;

    if (options.output_format == .vhd) {
        var source = try Image.openPathReadOnly(io, raw_path);
        defer source.close(io);
        var destination = try Image.createExclusive(io, options.output_path, .vhd, disk_size, .{
            .vhd_subformat = .fixed,
            .unique_id = identity.vhd_unique_id,
            .timestamp_unix = @import("vhd.zig").timestamp_base,
        });
        var destination_open = true;
        var keep_output = false;
        defer {
            if (destination_open) destination.close(io);
            if (!keep_output) Io.Dir.cwd().deleteFile(io, options.output_path) catch {};
        }
        _ = try image_mod.copyAll(io, source, &destination, allocator);
        destination.close(io);
        destination_open = false;
        const verified = try verifyOutput(
            allocator,
            io,
            options.output_path,
            .vhd,
            inspection.sha256,
            inspection.size,
            boot_path,
            disk_size,
            options.esp_size,
            identity,
        );
        if (!verified) return error.OutputVerificationFailed;
        keep_output = true;
    } else {
        const verified = try verifyOutput(
            allocator,
            io,
            options.output_path,
            .raw,
            inspection.sha256,
            inspection.size,
            boot_path,
            disk_size,
            options.esp_size,
            identity,
        );
        if (!verified) return error.OutputVerificationFailed;
        keep_raw = true;
    }

    return .{
        .output_format = options.output_format,
        .architecture = inspection.architecture,
        .boot_path = boot_path,
        .input_size = inspection.size,
        .input_sha256 = inspection.sha256,
        .virtual_size = disk_size,
        .esp_offset_bytes = esp_offset,
        .esp_length_bytes = options.esp_size,
        .disk_guid = identity.disk_guid,
        .esp_partition_guid = identity.esp_partition_guid,
        .esp_volume_id = identity.esp_volume_id,
    };
}

fn inspect(
    file: Io.File,
    io: Io,
    expected_architecture: ?Architecture,
    max_size: u64,
) !Inspection {
    const stat = try file.stat(io);
    if (stat.size > std.math.maxInt(u32)) return error.EfiFileTooLarge;
    if (stat.size > max_size) return error.EfiFileExceedsLimit;
    if (stat.size < 64) return error.InvalidEfiImage;

    var dos: [64]u8 = undefined;
    try readExact(file, io, &dos, 0);
    if (!std.mem.eql(u8, dos[0..2], "MZ")) return error.InvalidEfiImage;
    const pe_offset: u64 = std.mem.readInt(u32, dos[0x3c..0x40], .little);
    const coff_end = std.math.add(u64, pe_offset, 24) catch return error.InvalidEfiImage;
    if (coff_end > stat.size) return error.InvalidEfiImage;

    var coff: [24]u8 = undefined;
    try readExact(file, io, &coff, pe_offset);
    if (!std.mem.eql(u8, coff[0..4], "PE\x00\x00")) return error.InvalidEfiImage;
    const architecture: Architecture = switch (std.mem.readInt(u16, coff[4..6], .little)) {
        0x8664 => .x86_64,
        0xaa64 => .aarch64,
        else => return error.UnsupportedEfiArchitecture,
    };
    if (expected_architecture) |expected| {
        if (architecture != expected) return error.EfiArchitectureMismatch;
    }

    const optional_size = std.mem.readInt(u16, coff[20..22], .little);
    if (optional_size < 70) return error.InvalidEfiImage;
    const optional_offset = coff_end;
    const optional_end = std.math.add(u64, optional_offset, optional_size) catch
        return error.InvalidEfiImage;
    if (optional_end > stat.size) return error.InvalidEfiImage;
    var optional_prefix: [70]u8 = undefined;
    try readExact(file, io, &optional_prefix, optional_offset);
    if (std.mem.readInt(u16, optional_prefix[0..2], .little) != 0x20b) {
        return error.InvalidEfiImage;
    }
    if (std.mem.readInt(u16, optional_prefix[68..70], .little) != 10) {
        return error.NotEfiApplication;
    }

    return .{
        .architecture = architecture,
        .size = stat.size,
        .sha256 = try hashFile(file, io, stat.size),
    };
}

fn minimumEspSize(file_size: u64, boot_path: []const u8) !u64 {
    const boot_name = std.fs.path.basename(boot_path);
    const file_sizes = [_]u64{file_size};
    const directory_slots = [_]u32{
        fat32.root_directory_overhead_slots + try fat32.nameSlotCount("EFI"),
        fat32.subdirectory_overhead_slots + try fat32.nameSlotCount("BOOT"),
        fat32.subdirectory_overhead_slots + try fat32.nameSlotCount(boot_name),
    };
    return fat32.minimumVolumeLength(.{
        .file_sizes = &file_sizes,
        .directory_slots = &directory_slots,
    }, .{
        .alignment = azure.one_mib,
        .max_length = maximum_esp_size,
    });
}

fn minimumDiskSize(esp_size: u64) !u64 {
    const trailing_gpt_bytes = (gpt.partition_array_sectors + 1) * gpt.sector_size;
    const after_esp = std.math.add(u64, esp_offset, esp_size) catch return error.SizeOverflow;
    const unaligned = std.math.add(u64, after_esp, trailing_gpt_bytes) catch
        return error.SizeOverflow;
    return azure.alignSizeToMibChecked(unaligned);
}

fn copyInputToEsp(
    input: Io.File,
    io: Io,
    expected_size: u64,
    filesystem: *fat32.FileSystem,
    boot_path: []const u8,
) ![Sha256.digest_length]u8 {
    var writer = try filesystem.beginFile(io, boot_path);
    var writer_open = true;
    defer if (writer_open) writer.abort(io) catch {};

    var hasher = Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < expected_size) {
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), expected_size - offset));
        const got = try input.readPositional(io, &.{buffer[0..wanted]}, offset);
        if (got == 0) return error.EfiInputChanged;
        hasher.update(buffer[0..got]);
        try writer.writeChunk(io, buffer[0..got]);
        offset += got;
    }
    var extra: [1]u8 = undefined;
    if (try input.readPositional(io, &.{&extra}, expected_size) != 0) {
        return error.EfiInputChanged;
    }
    try writer.endFile(io);
    writer_open = false;

    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn verifyOutput(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    format: Format,
    expected_sha256: [Sha256.digest_length]u8,
    expected_size: u64,
    boot_path: []const u8,
    disk_size: u64,
    esp_size: u64,
    identity: Identity,
) !bool {
    var image = try Image.openPathReadOnly(io, path);
    defer image.close(io);
    const info = try image.info(io);
    if (info.format != format or info.virtual_size != disk_size) return false;
    if (format == .vhd) {
        if (info.subformat != .fixed or disk_size % azure.one_mib != 0) return false;
        const alignment = try azure.alignFixedVhd(&image, io);
        if (alignment.was_resized or alignment.new_size != disk_size) return false;
    }
    const image_check = try image.check(io);
    if (!image_check.ok) return error.OutputImageCheckFailed;

    const partition_style = try azure.checkPartitionStyle(image, io, allocator, .gen2);
    if (!partition_style.ok) return false;
    var table = try gpt.readVerifiedGpt(image, io, allocator, gpt.default_max_partition_array_bytes);
    defer table.deinit(allocator);
    if (table.partitions.len != 1 or
        !std.mem.eql(u8, &table.primary_header.disk_guid, &identity.disk_guid))
    {
        return false;
    }
    const partition = table.partitions[0];
    if (!std.mem.eql(u8, &partition.partition_type_guid, &guid.esp) or
        !std.mem.eql(u8, &partition.unique_partition_guid, &identity.esp_partition_guid) or
        partition.first_lba * gpt.sector_size != esp_offset or
        (partition.last_lba - partition.first_lba + 1) * gpt.sector_size != esp_size)
    {
        return false;
    }

    var filesystem = try fat32.open(&image, io, .{
        .offset = esp_offset,
        .length = esp_size,
    });
    if (filesystem.volumeMetadata().volume_id != identity.esp_volume_id) return false;
    var tree = try fat32.scanTree(&filesystem, io, allocator, .{
        .max_nodes = 3,
        .max_file_bytes = expected_size,
        .max_total_bytes = expected_size,
    });
    defer tree.deinit();
    if (tree.nodeCount() != 3) return false;

    var found = false;
    for (0..tree.nodeCount()) |index| {
        const entry = tree.entryAt(index);
        if (!std.mem.eql(u8, entry.path, boot_path)) continue;
        if (entry.kind != .file) return false;
        const content = entry.content orelse return false;
        var hasher = Sha256.init(.{});
        var buffer: [256 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < entry.size) {
            const got = try content.readAt(&buffer, offset);
            if (got == 0) return false;
            hasher.update(buffer[0..got]);
            offset += got;
        }
        var actual: [Sha256.digest_length]u8 = undefined;
        hasher.final(&actual);
        if (!std.crypto.timing_safe.eql(
            [Sha256.digest_length]u8,
            actual,
            expected_sha256,
        )) return false;
        found = true;
    }
    return found;
}

fn hashFile(file: Io.File, io: Io, size: u64) ![Sha256.digest_length]u8 {
    var hasher = Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), size - offset));
        const got = try file.readPositional(io, &.{buffer[0..wanted]}, offset);
        if (got == 0) return error.EfiInputChanged;
        hasher.update(buffer[0..got]);
        offset += got;
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn readExact(file: Io.File, io: Io, buffer: []u8, offset: u64) !void {
    if (try file.readPositional(io, &.{buffer}, offset) != buffer.len) {
        return error.InvalidEfiImage;
    }
}

fn deriveIdentity(
    input_sha256: [Sha256.digest_length]u8,
    architecture: Architecture,
    esp_size: u64,
    disk_size: u64,
) Identity {
    var seed_hash = Sha256.init(.{});
    seed_hash.update("miz-efi-application-image-v1\x00");
    seed_hash.update(&input_sha256);
    seed_hash.update(@tagName(architecture));
    var sizes: [16]u8 = undefined;
    std.mem.writeInt(u64, sizes[0..8], esp_size, .little);
    std.mem.writeInt(u64, sizes[8..16], disk_size, .little);
    seed_hash.update(&sizes);
    var seed: [Sha256.digest_length]u8 = undefined;
    seed_hash.final(&seed);

    var volume_hash = derive(seed, "fat-volume");
    var volume_id = std.mem.readInt(u32, volume_hash[0..4], .little);
    if (volume_id == 0) volume_id = 1;
    return .{
        .disk_guid = derivedGuid(seed, "gpt-disk"),
        .esp_partition_guid = derivedGuid(seed, "gpt-esp"),
        .esp_volume_id = volume_id,
        .vhd_unique_id = derivedUuid(seed, "vhd-footer"),
    };
}

fn derive(seed: [Sha256.digest_length]u8, label: []const u8) [Sha256.digest_length]u8 {
    var hasher = Sha256.init(.{});
    hasher.update("miz-efi-application-identity-v1\x00");
    hasher.update(label);
    hasher.update("\x00");
    hasher.update(&seed);
    var result: [Sha256.digest_length]u8 = undefined;
    hasher.final(&result);
    return result;
}

fn derivedGuid(seed: [Sha256.digest_length]u8, label: []const u8) guid.Guid {
    const digest = derive(seed, label);
    var result: guid.Guid = digest[0..16].*;
    result[7] = (result[7] & 0x0f) | 0x50;
    result[8] = (result[8] & 0x3f) | 0x80;
    return result;
}

fn derivedUuid(seed: [Sha256.digest_length]u8, label: []const u8) [16]u8 {
    const digest = derive(seed, label);
    var result: [16]u8 = digest[0..16].*;
    result[6] = (result[6] & 0x0f) | 0x50;
    result[8] = (result[8] & 0x3f) | 0x80;
    return result;
}

fn makeTestEfi(machine: u16, subsystem: u16) [512]u8 {
    var bytes: [512]u8 = [_]u8{0} ** 512;
    bytes[0..2].* = "MZ".*;
    std.mem.writeInt(u32, bytes[0x3c..0x40], 0x80, .little);
    bytes[0x80..0x84].* = "PE\x00\x00".*;
    std.mem.writeInt(u16, bytes[0x84..0x86], machine, .little);
    std.mem.writeInt(u16, bytes[0x86..0x88], 1, .little);
    std.mem.writeInt(u16, bytes[0x94..0x96], 0xf0, .little);
    std.mem.writeInt(u16, bytes[0x98..0x9a], 0x20b, .little);
    std.mem.writeInt(u16, bytes[0xdc..0xde], subsystem, .little);
    return bytes;
}

fn hashPath(io: Io, path: []const u8) ![Sha256.digest_length]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    return hashFile(file, io, (try file.stat(io)).size);
}

test "inspect validates EFI application architecture" {
    const io = std.testing.io;
    const path = "test-efi-application-input.efi";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = &makeTestEfi(0x8664, 10),
    });
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const valid = try inspect(file, io, .x86_64, 1024);
    try std.testing.expectEqual(Architecture.x86_64, valid.architecture);
    try std.testing.expectError(error.EfiFileExceedsLimit, inspect(file, io, null, 511));
    try std.testing.expectError(
        error.EfiArchitectureMismatch,
        inspect(file, io, .aarch64, 1024),
    );
}

test "inspect rejects invalid PE, unsupported architecture, and non-application subsystem" {
    const io = std.testing.io;
    const path = "test-efi-application-invalid.efi";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var bytes = makeTestEfi(0x014c, 10);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = &bytes });
    var file = try Io.Dir.cwd().openFile(io, path, .{});
    try std.testing.expectError(error.UnsupportedEfiArchitecture, inspect(file, io, null, 1024));
    file.close(io);

    bytes = makeTestEfi(0x8664, 11);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = &bytes });
    file = try Io.Dir.cwd().openFile(io, path, .{});
    try std.testing.expectError(error.NotEfiApplication, inspect(file, io, null, 1024));
    file.close(io);

    bytes[0] = 0;
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = &bytes });
    file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    try std.testing.expectError(error.InvalidEfiImage, inspect(file, io, null, 1024));
}

test "build emits deterministic raw GPT and Azure-ready fixed VHD" {
    const io = std.testing.io;
    const input_path = "test-efi-application-build.efi";
    const raw_a_path = "test-efi-application-a.raw";
    const raw_b_path = "test-efi-application-b.raw";
    const vhd_path = "test-efi-application.vhd";
    defer Io.Dir.cwd().deleteFile(io, input_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_a_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_b_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, vhd_path) catch {};
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = input_path,
        .data = &makeTestEfi(0x8664, 10),
    });

    const report_a = try build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = raw_a_path,
        .output_format = .raw,
    });
    const report_b = try build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = raw_b_path,
        .output_format = .raw,
    });
    try std.testing.expectEqualSlices(u8, &report_a.disk_guid, &report_b.disk_guid);
    try std.testing.expectEqualSlices(u8, &(try hashPath(io, raw_a_path)), &(try hashPath(io, raw_b_path)));

    const vhd_report = try build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = vhd_path,
        .output_format = .vhd,
    });
    try std.testing.expectEqual(@as(u64, 0), vhd_report.virtual_size % azure.one_mib);
    var vhd_image = try Image.openPathReadOnly(io, vhd_path);
    defer vhd_image.close(io);
    const info = try vhd_image.info(io);
    try std.testing.expectEqual(image_mod.VhdSubformat.fixed, info.subformat.?);
    try std.testing.expectEqual(vhd_report.virtual_size + @import("vhd.zig").footer_size, info.file_size);
}

test "build refuses unsafe sizing, formats, and existing output" {
    const io = std.testing.io;
    const input_path = "test-efi-application-refusal.efi";
    const output_path = "test-efi-application-existing.raw";
    defer Io.Dir.cwd().deleteFile(io, input_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = input_path,
        .data = &makeTestEfi(0x8664, 10),
    });

    try std.testing.expectError(error.UnsupportedOutputFormat, build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = output_path,
        .output_format = .qcow2,
    }));
    try std.testing.expectError(error.EspSizeNotMibAligned, build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = output_path,
        .output_format = .raw,
        .esp_size = default_esp_size + 512,
    }));
    try std.testing.expectError(error.EspTooLarge, build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = output_path,
        .output_format = .raw,
        .esp_size = maximum_esp_size + azure.one_mib,
    }));
    try std.testing.expectError(error.EspTooSmall, build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = output_path,
        .output_format = .raw,
        .esp_size = azure.one_mib,
    }));
    try std.testing.expectError(error.DiskSizeNotMibAligned, build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = output_path,
        .output_format = .raw,
        .disk_size = 128 * azure.one_mib + 512,
    }));

    try Io.Dir.cwd().writeFile(io, .{ .sub_path = output_path, .data = "keep" });
    try std.testing.expectError(error.PathAlreadyExists, build(std.testing.allocator, io, .{
        .efi_path = input_path,
        .output_path = output_path,
        .output_format = .raw,
    }));
    const preserved = try Io.Dir.cwd().readFileAlloc(io, output_path, std.testing.allocator, .limited(16));
    defer std.testing.allocator.free(preserved);
    try std.testing.expectEqualStrings("keep", preserved);
}
