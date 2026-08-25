//! `miz map [--output=human|json] <file>`

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
            return fail("map: unexpected argument '{s}'", .{a});
        }
    }

    const file_path = path orelse return fail("usage: miz map [--output=human|json] <file>", .{});

    var img = miz.Image.openPath(io, file_path) catch |err|
        return fail("map: failed to open '{s}': {s}", .{ file_path, @errorName(err) });
    defer img.close(io);

    const extents = img.mapExtents(io, gpa) catch |err|
        return fail("map: failed: {s}", .{@errorName(err)});
    defer gpa.free(extents);

    // A disk whose root filesystem lives on a logical volume shows only an
    // opaque partition in the extent list, so the volume groups are read as
    // well. Scanning is read-only and happens after the extents so a broken
    // volume group still leaves the allocation map visible.
    var lvm_scan = miz.lvm.scan(gpa, img, io) catch |err|
        return fail("map: failed to read LVM metadata: {s}", .{@errorName(err)});
    defer lvm_scan.deinit();

    switch (output) {
        .human => {
            std.debug.print("{s: <12} {s: <12} {s}\n", .{ "Offset", "Length", "Mapped" });
            for (extents) |e| {
                std.debug.print("0x{x: <10} 0x{x: <10} {s}\n", .{ e.offset, e.length, if (e.allocated) "true" else "false" });
            }
            printVolumeGroups(lvm_scan.groups);
        },
        .json => {
            std.debug.print("{{\"extents\":[", .{});
            var buf: [256]u8 = undefined;
            for (extents, 0..) |e, idx| {
                var writer = std.Io.Writer.fixed(&buf);
                std.json.Stringify.value(.{
                    .start = e.offset,
                    .length = e.length,
                    .data = e.allocated,
                }, .{}, &writer) catch |err|
                    return fail("map: failed to format JSON: {s}", .{@errorName(err)});
                std.debug.print("{s}{s}", .{ writer.buffered(), if (idx + 1 < extents.len) "," else "" });
            }
            std.debug.print("],\"volume_groups\":[", .{});
            if (writeVolumeGroupsJson(gpa, lvm_scan.groups)) |_| {} else |err| {
                return fail("map: failed to format JSON: {s}", .{@errorName(err)});
            }
            std.debug.print("]}}\n", .{});
        },
    }

    return 0;
}

fn printVolumeGroups(groups: []const miz.lvm.VolumeGroup) void {
    if (groups.len == 0) return;
    for (groups) |*group| {
        std.debug.print(
            "\nVolume group {s} (seqno {d}, {d} MiB extents)\n",
            .{ group.name, group.seqno, group.extentSizeBytes() / (1024 * 1024) },
        );
        for (group.physical_volumes) |pv| {
            if (pv.region) |region| {
                std.debug.print("  pv {s: <8} 0x{x} ({s})\n", .{
                    pv.key,
                    region.offset,
                    locationText(region.location),
                });
            } else {
                // Named by the metadata but on a disk nobody supplied, which
                // is why a volume living there cannot be mapped.
                std.debug.print("  pv {s: <8} missing\n", .{pv.key});
            }
        }
        std.debug.print("{s: <12} {s: <12} {s: <12} {s}\n", .{ "Offset", "Length", "Type", "Volume" });
        for (group.logical_volumes) |*lv| {
            if (miz.lvm.contiguousRange(group, lv)) |range| {
                std.debug.print("0x{x: <10} 0x{x: <10} {s: <12} {s}\n", .{
                    range.offset,
                    range.length,
                    lv.segments[0].type_name,
                    lv.name,
                });
            } else |err| {
                // The volume is still listed: knowing it is there and why it
                // cannot be reached beats it not appearing at all.
                std.debug.print("{s: <12} 0x{x: <10} {s: <12} {s} ({s})\n", .{
                    "-",
                    lv.extent_count * group.extentSizeBytes(),
                    if (lv.segments.len == 0) "-" else lv.segments[0].type_name,
                    lv.name,
                    @errorName(err),
                });
            }
        }
    }
}

/// Shapes for the JSON form. `start` and `length` are absent for a volume
/// that has no single byte range, which carries `unmappable` instead naming
/// the reason -- an unsupported segment type, a physical volume this image
/// does not contain, or a volume split into several runs.
const PhysicalVolumeJson = struct {
    key: []const u8,
    id: []const u8,
    offset: ?u64,
};

const LogicalVolumeJson = struct {
    name: []const u8,
    id: []const u8,
    size: u64,
    type: []const u8,
    start: ?u64 = null,
    length: ?u64 = null,
    unmappable: ?[]const u8 = null,
};

const VolumeGroupJson = struct {
    name: []const u8,
    id: []const u8,
    seqno: u64,
    extent_size: u64,
    complete: bool,
    physical_volumes: []const PhysicalVolumeJson,
    logical_volumes: []const LogicalVolumeJson,
};

fn writeVolumeGroupsJson(gpa: std.mem.Allocator, groups: []const miz.lvm.VolumeGroup) !void {
    for (groups, 0..) |*group, index| {
        const pvs = try gpa.alloc(PhysicalVolumeJson, group.physical_volumes.len);
        defer gpa.free(pvs);
        for (group.physical_volumes, pvs) |pv, *slot| {
            slot.* = .{
                .key = pv.key,
                .id = pv.id,
                .offset = if (pv.region) |region| region.offset else null,
            };
        }

        const lvs = try gpa.alloc(LogicalVolumeJson, group.logical_volumes.len);
        defer gpa.free(lvs);
        for (group.logical_volumes, lvs) |*lv, *slot| {
            slot.* = .{
                .name = lv.name,
                .id = lv.id,
                .size = lv.extent_count * group.extentSizeBytes(),
                .type = if (lv.segments.len == 0) "" else lv.segments[0].type_name,
            };
            if (miz.lvm.contiguousRange(group, lv)) |range| {
                slot.start = range.offset;
                slot.length = range.length;
            } else |err| {
                slot.unmappable = @errorName(err);
            }
        }

        const json = try std.json.Stringify.valueAlloc(gpa, VolumeGroupJson{
            .name = group.name,
            .id = group.id,
            .seqno = group.seqno,
            .extent_size = group.extentSizeBytes(),
            .complete = group.complete(),
            .physical_volumes = pvs,
            .logical_volumes = lvs,
        }, .{ .emit_null_optional_fields = false });
        defer gpa.free(json);
        std.debug.print("{s}{s}", .{ json, if (index + 1 < groups.len) "," else "" });
    }
}

fn locationText(location: miz.lvm.Location) []const u8 {
    return switch (location) {
        .whole_disk => "whole disk",
        .gpt_partition => "GPT partition",
        .mbr_partition => "MBR partition",
    };
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}
