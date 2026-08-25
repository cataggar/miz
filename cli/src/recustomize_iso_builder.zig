//! Host-native entry point used by the exported `build/iso.zig` `addRecustomize`
//! helper. Parses a `recustomize-iso` request and drives
//! `miz.recustomize_iso.build`, writing the recustomized ISO and a
//! machine-readable preservation report into a result bundle directory.
//!
//! On a strict refusal it emits the structured diagnostic (kind, path, catalog
//! index, detail) and exits non-zero; no output or scratch is published.

const std = @import("std");
const customization_loader = @import("customization_loader.zig");
const miz = @import("miz");

const ParsedArgs = struct {
    iso_path: []const u8,
    container_path: []const u8,
    rootfs_size: u64,
    bundle_output_path: []const u8,
    iso_basename: []const u8,
    rootfs_path_in_iso: ?[]const u8 = null,
    nested_rootfs_path: []const u8 = miz.recustomize_iso.default_nested_rootfs_path,
    squashfs_compression: miz.squashfs.WriterCompression = .zstd,
    skip_iso_rootfs: bool = false,
    architecture: ?miz.bootconfig.Architecture = null,
    ext4_label: []const u8 = "rootfs",
    journal: miz.ext4.JournalOptions = .{},
    root_selinux_label: ?[]const u8 = null,
    source_date_epoch: ?u32 = null,
    customization_config: ?[]const u8 = null,
    customization_sources: []const []const u8 = &.{},
    limits: miz.limits.ImportLimits = .{},
    verbose: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(arena);

    const args = parseArgs(arena, argv[1..]) catch |err| {
        std.debug.print("miz-recustomize-iso-builder: {t}\n", .{err});
        std.process.exit(2);
    };

    std.Io.Dir.cwd().createDirPath(io, args.bundle_output_path) catch |err| {
        std.debug.print("miz-recustomize-iso-builder: cannot create result bundle: {t}\n", .{err});
        std.process.exit(1);
    };
    const output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, args.iso_basename });
    const report_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "report.json" });

    const customization = customization_loader.load(
        arena,
        io,
        args.customization_config,
        args.customization_sources,
    ) catch |err| {
        std.debug.print("miz-recustomize-iso-builder: cannot load customization: {t}\n", .{err});
        std.process.exit(1);
    };

    const determinism: ?miz.recustomize_iso.Determinism = if (args.source_date_epoch) |epoch| .{
        .filesystem_timestamp = epoch,
        .root_filesystem_uuid = deriveUuid(epoch),
    } else null;

    var diagnostic = miz.recustomize_iso.RecustomizeDiagnostic{ .kind = .boot_image_unmapped };
    defer diagnostic.deinit(gpa);

    var report = miz.recustomize_iso.build(gpa, io, .{
        .iso_path = args.iso_path,
        .container_path = args.container_path,
        .output_path = output_path,
        .rootfs_size = args.rootfs_size,
        .rootfs_path_in_iso = args.rootfs_path_in_iso,
        .nested_rootfs_path = args.nested_rootfs_path,
        .skip_iso_rootfs = args.skip_iso_rootfs,
        .os = customization.os,
        .generalization = customization.generalization,
        .architecture = args.architecture,
        .ext4_label = args.ext4_label,
        .ext4_journal = args.journal,
        .root_selinux_label = args.root_selinux_label,
        .squashfs_compression = args.squashfs_compression,
        .limits = args.limits.tree(),
        .diagnostic = &diagnostic,
        .determinism = determinism,
        .verbose = args.verbose,
    }) catch |err| {
        switch (err) {
            error.SourceNotRewritable,
            error.UnsupportedBootPlatform,
            error.DuplicateBootPlatform,
            error.BootSelectionCriteria,
            => std.debug.print(
                "miz-recustomize-iso-builder: refused: {s}{s}{s}{s}\n",
                .{
                    diagnostic.kind.describe(),
                    if (diagnostic.path.len > 0) " at " else "",
                    diagnostic.path,
                    formatCatalogSuffix(arena, diagnostic),
                },
            ),
            else => std.debug.print("miz-recustomize-iso-builder: build failed: {t}\n", .{err}),
        }
        std.process.exit(1);
    };
    defer report.deinit(gpa);

    writeReport(gpa, io, report_path, report) catch |err| {
        std.debug.print("miz-recustomize-iso-builder: cannot write report: {t}\n", .{err});
        std.process.exit(1);
    };
}

fn formatCatalogSuffix(arena: std.mem.Allocator, diagnostic: miz.recustomize_iso.RecustomizeDiagnostic) []const u8 {
    if (diagnostic.catalog_index) |index| {
        return std.fmt.allocPrint(arena, " (boot catalog entry #{d}) [{s}]", .{ index, diagnostic.detail }) catch "";
    }
    if (diagnostic.detail.len > 0) {
        return std.fmt.allocPrint(arena, " [{s}]", .{diagnostic.detail}) catch "";
    }
    return "";
}

fn deriveUuid(epoch: u32) [16]u8 {
    var digest: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("miz-recustomize-iso-rootfs-uuid\x00");
    var epoch_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &epoch_bytes, epoch, .little);
    hasher.update(&epoch_bytes);
    hasher.final(&digest);
    return digest[0..16].*;
}

const VolumeJson = struct {
    volume_id: []const u8,
    system_id: []const u8,
    volume_set_id: []const u8,
    publisher_id: []const u8,
    preparer_id: []const u8,
    application_id: []const u8,
};

const BootEntryJson = struct {
    platform: []const u8,
    image_path: []const u8,
    load_segment: u16,
    system_type: u8,
    load_sectors: u16,
    bootable: bool,
};

const ReportJson = struct {
    architecture: []const u8,
    strict_inspection_clean: bool,
    rootfs_path_in_iso: []const u8,
    nested_rootfs_path: []const u8,
    rootfs_size: u64,
    root_tree_digest: ?[]const u8,
    preserved_node_count: usize,
    source_size: u64,
    source_sha256: []const u8,
    output_size: u64,
    output_sha256: []const u8,
    source_volume: VolumeJson,
    output_volume: VolumeJson,
    boot_entries: []const BootEntryJson,
};

fn volumeJson(v: miz.iso9660.VolumeMetadata) VolumeJson {
    return .{
        .volume_id = v.volume_id,
        .system_id = v.system_id,
        .volume_set_id = v.volume_set_id,
        .publisher_id = v.publisher_id,
        .preparer_id = v.preparer_id,
        .application_id = v.application_id,
    };
}

fn writeReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    report: miz.recustomize_iso.RecustomizeIsoReport,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const boot_entries = try arena.alloc(BootEntryJson, report.boot_entries.len);
    for (report.boot_entries, 0..) |entry, index| boot_entries[index] = .{
        .platform = entry.platform.displayName(),
        .image_path = entry.image_path,
        .load_segment = entry.load_segment,
        .system_type = entry.system_type,
        .load_sectors = entry.load_sectors,
        .bootable = entry.bootable,
    };

    const digest_hex: ?[]const u8 = if (report.root_tree_digest) |digest|
        try arena.dupe(u8, &std.fmt.bytesToHex(digest, .lower))
    else
        null;

    const json = try std.json.Stringify.valueAlloc(arena, ReportJson{
        .architecture = switch (report.architecture) {
            .x86_64 => "x86_64",
            .aarch64 => "aarch64",
        },
        .strict_inspection_clean = report.strict_inspection_clean,
        .rootfs_path_in_iso = report.rootfs_path_in_iso,
        .nested_rootfs_path = report.nested_rootfs_path,
        .rootfs_size = report.rootfs_size,
        .root_tree_digest = digest_hex,
        .preserved_node_count = report.preserved_node_count,
        .source_size = report.source_size,
        .source_sha256 = try arena.dupe(u8, &std.fmt.bytesToHex(report.source_sha256, .lower)),
        .output_size = report.output_size,
        .output_sha256 = try arena.dupe(u8, &std.fmt.bytesToHex(report.output_sha256, .lower)),
        .source_volume = volumeJson(report.source_volume),
        .output_volume = volumeJson(report.output_volume),
        .boot_entries = boot_entries,
    }, .{ .whitespace = .indent_2 });

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = json });
}

fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !ParsedArgs {
    var iso_path: ?[]const u8 = null;
    var container_path: ?[]const u8 = null;
    var rootfs_size: ?u64 = null;
    var bundle_output_path: ?[]const u8 = null;
    var iso_basename: ?[]const u8 = null;
    var result = ParsedArgs{
        .iso_path = undefined,
        .container_path = undefined,
        .rootfs_size = undefined,
        .bundle_output_path = undefined,
        .iso_basename = undefined,
    };
    var sources = std.array_list.Managed([]const u8).init(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--iso")) {
            i += 1;
            iso_path = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--container")) {
            i += 1;
            container_path = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--rootfs-size")) {
            i += 1;
            rootfs_size = try miz.parseSize(try nextArg(args, i));
        } else if (std.mem.eql(u8, arg, "--bundle-output")) {
            i += 1;
            bundle_output_path = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--iso-basename")) {
            i += 1;
            iso_basename = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--rootfs-path")) {
            i += 1;
            result.rootfs_path_in_iso = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--nested-rootfs-path")) {
            i += 1;
            result.nested_rootfs_path = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--squashfs-compression")) {
            i += 1;
            const value = try nextArg(args, i);
            if (std.mem.eql(u8, value, "zstd")) {
                result.squashfs_compression = .zstd;
            } else if (std.mem.eql(u8, value, "none")) {
                result.squashfs_compression = .none;
            } else return error.InvalidSquashfsCompression;
        } else if (std.mem.eql(u8, arg, "--skip-iso-rootfs")) {
            result.skip_iso_rootfs = true;
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            const value = try nextArg(args, i);
            if (std.mem.eql(u8, value, "auto")) {
                result.architecture = null;
            } else if (std.mem.eql(u8, value, "x86_64") or std.mem.eql(u8, value, "amd64")) {
                result.architecture = .x86_64;
            } else if (std.mem.eql(u8, value, "aarch64") or std.mem.eql(u8, value, "arm64")) {
                result.architecture = .aarch64;
            } else return error.InvalidArchitecture;
        } else if (std.mem.eql(u8, arg, "--ext4-label")) {
            i += 1;
            result.ext4_label = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--journal")) {
            result.journal.enabled = true;
        } else if (std.mem.eql(u8, arg, "--journal-size")) {
            i += 1;
            result.journal.size_bytes = try miz.parseSize(try nextArg(args, i));
            result.journal.enabled = true;
        } else if (std.mem.eql(u8, arg, "--root-selinux-label")) {
            i += 1;
            result.root_selinux_label = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--source-date-epoch")) {
            i += 1;
            result.source_date_epoch = try std.fmt.parseInt(u32, try nextArg(args, i), 10);
        } else if (std.mem.eql(u8, arg, "--customization-config")) {
            i += 1;
            result.customization_config = try nextArg(args, i);
        } else if (std.mem.eql(u8, arg, "--customization-source")) {
            i += 1;
            try sources.append(try nextArg(args, i));
        } else if (std.mem.eql(u8, arg, "--verbose")) {
            result.verbose = true;
        } else if (miz.limits.limitForFlag(arg) != null) {
            i += 1;
            _ = try result.limits.parseFlag(arg, try nextArg(args, i));
        } else {
            return error.UnexpectedArgument;
        }
    }

    result.iso_path = iso_path orelse return error.MissingIso;
    result.container_path = container_path orelse return error.MissingContainer;
    result.rootfs_size = rootfs_size orelse return error.MissingRootfsSize;
    result.bundle_output_path = bundle_output_path orelse return error.MissingBundleOutput;
    result.iso_basename = iso_basename orelse return error.MissingIsoBasename;
    result.customization_sources = try sources.toOwnedSlice();
    return result;
}

fn nextArg(args: []const []const u8, index: usize) ![]const u8 {
    if (index >= args.len) return error.MissingArgumentValue;
    return args[index];
}

test "deriveUuid is stable for a given epoch" {
    try std.testing.expectEqual(deriveUuid(42), deriveUuid(42));
    try std.testing.expect(!std.mem.eql(u8, &deriveUuid(1), &deriveUuid(2)));
}
