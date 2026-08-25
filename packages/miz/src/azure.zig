//! Azure managed-disk VHD readiness checks/fixups: forcing fixed format,
//! 1 MiB size alignment, and sanity-checking the partition style matches
//! the target Hyper-V generation (Gen1 => MBR, Gen2 => GPT + protective
//! MBR). Backs the `miz azure fixup` CLI command.
//!
//! Requirements verified against Microsoft's "Upload a VHD to Azure"
//! documentation: fixed VHD only, `.vhd` (not `.vhdx`), and the VHD's data
//! region must be a multiple of 1 MiB (1,048,576 bytes).

const std = @import("std");
const Io = std.Io;
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const mbr = @import("mbr.zig");
const gpt = @import("gpt.zig");
const artifact_pipeline = @import("artifact_pipeline.zig");

pub const one_mib: u64 = 1024 * 1024;

pub const Generation = enum { gen1, gen2 };

pub const FixupError = error{
    NotAFixedVhd,
    GptRelocationRequired,
    SizeOverflow,
} || Image.ResizeError || Image.PreadError || gpt.VerifyError ||
    mbr.Mbr.DecodeError;

pub const FixupResult = struct {
    old_size: u64,
    new_size: u64,
    /// True if `new_size` differs from `old_size` (i.e. padding was needed).
    was_resized: bool,
};

/// Rounds `size` up to the next 1 MiB boundary (a no-op if already aligned).
pub fn alignSizeToMib(size: u64) u64 {
    return (size + one_mib - 1) / one_mib * one_mib;
}

pub fn alignSizeToMibChecked(size: u64) error{SizeOverflow}!u64 {
    const rounded = std.math.add(u64, size, one_mib - 1) catch
        return error.SizeOverflow;
    return rounded / one_mib * one_mib;
}

pub const DeriveFixedVhdOptions = artifact_pipeline.DeriveFixedVhdOptions;
pub const DerivedFixedVhd = artifact_pipeline.DerivedFixedVhd;
pub const deriveFixedVhd = artifact_pipeline.deriveFixedVhd;

/// Pads `img` (which must already be a fixed vhd) up to a 1 MiB-aligned
/// size. GPT images that need growth are rejected before mutation because
/// their backup table must be relocated transactionally with `deriveFixedVhd`.
pub fn alignFixedVhd(img: *Image, io: Io) FixupError!FixupResult {
    if (img.format != .vhd or img.dynamic != null) return error.NotAFixedVhd;

    const old_size = img.virtual_size;
    const new_size = try alignSizeToMibChecked(old_size);
    if (new_size != old_size) {
        var mbr_buf: [mbr.sector_size]u8 = undefined;
        _ = try img.pread(io, &mbr_buf, 0);
        if (mbr.Mbr.decode(&mbr_buf)) |boot_record| {
            for (boot_record.entries) |entry| {
                if (entry.partition_type == .gpt_protective) {
                    return error.GptRelocationRequired;
                }
            }
        } else |_| {}
        try img.resize(io, new_size);
    }
    return .{ .old_size = old_size, .new_size = new_size, .was_resized = new_size != old_size };
}

pub const PartitionStyleReport = struct {
    generation: Generation,
    ok: bool,
    message: []const u8,
};

/// Sanity-checks that `img`'s partition style (MBR vs. protective-MBR+GPT)
/// matches what the given Hyper-V `generation` expects: Gen1 VMs boot BIOS
/// + a plain MBR; Gen2 VMs boot UEFI + a protective MBR followed by a GPT.
pub fn checkPartitionStyle(img: Image, io: Io, allocator: std.mem.Allocator, generation: Generation) FixupError!PartitionStyleReport {
    var mbr_buf: [mbr.sector_size]u8 = undefined;
    _ = try img.pread(io, &mbr_buf, 0);
    const boot_record = mbr.Mbr.decode(&mbr_buf) catch |err| return .{
        .generation = generation,
        .ok = false,
        .message = switch (err) {
            error.BadBootSignature => "no valid MBR boot signature (0x55AA) found at LBA 0",
        },
    };

    const has_protective_entry = for (boot_record.entries) |entry| {
        if (entry.partition_type == .gpt_protective) break true;
    } else false;

    switch (generation) {
        .gen2 => {
            if (!has_protective_entry) {
                return .{ .generation = generation, .ok = false, .message = "Gen2 requires a GPT protective MBR (0xEE partition), but none was found" };
            }
            var parsed = gpt.readVerifiedGpt(
                img,
                io,
                allocator,
                1024 * 1024,
            ) catch |err| return .{
                .generation = generation,
                .ok = false,
                .message = switch (err) {
                    error.BadSignature => "GPT header signature ('EFI PART') not found at LBA 1",
                    error.BadHeaderChecksum => "GPT header checksum mismatch",
                    error.BadPartitionArrayChecksum => "GPT partition array checksum mismatch",
                    error.UnsupportedPartitionEntrySize => "GPT partition entry size is not the expected 128 bytes",
                    error.PartitionArrayMismatch => "primary and backup GPT partition arrays differ",
                    error.HeaderMismatch => "primary and backup GPT headers differ",
                    error.InvalidHeaderGeometry => "GPT header locations or usable bounds are invalid",
                    error.InvalidPartitionBounds => "GPT partition extent is outside the usable range",
                    error.OverlappingPartitions => "GPT partitions overlap",
                    else => "failed to read GPT",
                },
            };
            parsed.deinit(allocator);
            return .{ .generation = generation, .ok = true, .message = "valid protective MBR + GPT found" };
        },
        .gen1 => {
            if (has_protective_entry) {
                return .{ .generation = generation, .ok = false, .message = "Gen1 expects a plain MBR, but found a GPT protective MBR (0xEE partition) -- this image looks Gen2-partitioned" };
            }
            return .{ .generation = generation, .ok = true, .message = "valid plain MBR found" };
        },
    }
}

test "alignSizeToMib rounds up correctly" {
    try std.testing.expectEqual(@as(u64, 1024 * 1024), alignSizeToMib(1));
    try std.testing.expectEqual(@as(u64, 1024 * 1024), alignSizeToMib(1024 * 1024));
    try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024), alignSizeToMib(1024 * 1024 + 1));
}

test "alignFixedVhd pads an unaligned fixed vhd up to 1 MiB" {
    const io = std.testing.io;
    const path = "test-azure-align.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // 3 MiB + 4096 bytes -- not 1 MiB aligned.
    const size: u64 = 3 * 1024 * 1024 + 4096;
    var img = try Image.create(io, path, .vhd, size, .{ .vhd_subformat = .fixed });
    defer img.close(io);

    const result = try alignFixedVhd(&img, io);
    try std.testing.expect(result.was_resized);
    try std.testing.expectEqual(@as(u64, 4 * 1024 * 1024), result.new_size);
    try std.testing.expectEqual(@as(u64, 4 * 1024 * 1024), img.virtual_size);
}

test "alignFixedVhd rejects dynamic vhd and raw" {
    const io = std.testing.io;
    {
        const path = "test-azure-reject-dynamic.vhd";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};
        var img = try Image.create(io, path, .vhd, 4 * 1024 * 1024, .{ .vhd_subformat = .dynamic });
        defer img.close(io);
        try std.testing.expectError(error.NotAFixedVhd, alignFixedVhd(&img, io));
    }
    {
        const path = "test-azure-reject-raw.img";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};
        var img = try Image.create(io, path, .raw, 4 * 1024 * 1024, .{});
        defer img.close(io);
        try std.testing.expectError(error.NotAFixedVhd, alignFixedVhd(&img, io));
    }
}

test "alignFixedVhd rejects unaligned GPT before mutation" {
    const io = std.testing.io;
    const path = "test-azure-align-gpt.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const size: u64 = 16 * 1024 * 1024 - gpt.sector_size;
    var img = try Image.create(io, path, .vhd, size, .{
        .vhd_subformat = .fixed,
    });
    defer img.close(io);
    const guid = @import("guid.zig");
    const specs = [_]gpt.PartitionSpec{.{
        .type_guid = guid.esp,
        .unique_guid = guid.parse("55555555-5555-5555-5555-555555555555"),
        .size_sectors = 2048,
    }};
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(
        &img,
        io,
        guid.parse("44444444-4444-4444-4444-444444444444"),
        &specs,
        &placements,
    );

    try std.testing.expectError(
        error.GptRelocationRequired,
        alignFixedVhd(&img, io),
    );
    try std.testing.expectEqual(size, img.virtual_size);
    try std.testing.expectEqual(
        size + @import("vhd.zig").footer_size,
        (try img.info(io)).file_size,
    );
}

test "checkPartitionStyle validates Gen2 GPT layout" {
    const io = std.testing.io;
    const path = "test-azure-gen2.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const guid = @import("guid.zig");
    const size: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .vhd, size, .{ .vhd_subformat = .fixed });
    defer img.close(io);

    const specs = [_]gpt.PartitionSpec{
        .{ .type_guid = guid.esp, .unique_guid = guid.parse("66666666-6666-6666-6666-666666666666"), .size_sectors = 4096 },
    };
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(&img, io, guid.parse("77777777-7777-7777-7777-777777777777"), &specs, &placements);

    const report = try checkPartitionStyle(img, io, std.testing.allocator, .gen2);
    try std.testing.expect(report.ok);

    // The same disk should fail a Gen1 check (it's GPT-protective, not plain MBR).
    const gen1_report = try checkPartitionStyle(img, io, std.testing.allocator, .gen1);
    try std.testing.expect(!gen1_report.ok);
}

test "checkPartitionStyle validates Gen1 plain MBR layout" {
    const io = std.testing.io;
    const path = "test-azure-gen1.vhd";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const size: u64 = 16 * 1024 * 1024;
    var img = try Image.create(io, path, .vhd, size, .{ .vhd_subformat = .fixed });
    defer img.close(io);

    const single = mbr.singleLinuxPartitionMbr(2048, 16384).encode();
    try img.pwrite(io, &single, 0);

    const report = try checkPartitionStyle(img, io, std.testing.allocator, .gen1);
    try std.testing.expect(report.ok);

    const gen2_report = try checkPartitionStyle(img, io, std.testing.allocator, .gen2);
    try std.testing.expect(!gen2_report.ok);
}
