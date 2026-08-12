//! `zvmi build-iso --iso <file.iso> --container <oci-layout> --rootfs-size <size> -o <output.iso>`:
//! regenerate a customized LiveOS ISO. The source ISO's directory tree and
//! boot files are retained; its LiveOS payload is replaced by a native SquashFS
//! wrapping a deterministic ext4 rootfs.img built from the customized root tree.

const std = @import("std");
const zvmi = @import("zvmi");

const help_text =
    \\usage: zvmi build-iso --iso <file.iso> --container <oci-layout> --rootfs-size <size> -o <output.iso>
    \\                      [--rootfs-path <path>] [--nested-rootfs-path <path>] [--volume-id <id>]
    \\                      [--uefi-boot-image <path>] [--bios-boot-image <path>]
    \\                      [--squashfs-compression zstd|none] [--skip-iso-rootfs]
    \\                      [--architecture auto|x86_64|aarch64] [--ext4-label <label>]
    \\                      [--journal|--no-journal] [--journal-size <size>] [--root-selinux-label <context>]
    \\                      [--source-date-epoch <seconds>] [--max-oci-blob-size <size>]
    \\                      [--max-oci-layer-size <size>] [--max-oci-archive-size <size>] [--dry-run] [-v]
    \\
    \\Generates a LiveOS ISO. The customized root tree (source ISO LiveOS payload
    \\flattened, OCI layers overlaid, OS customization and generalization applied)
    \\is written to a deterministic ext4 rootfs.img, wrapped in a native zstd
    \\SquashFS at the source's LiveOS payload path, and folded back into a
    \\regenerated ISO whose boot files and configuration are retained verbatim.
    \\El Torito boot entries are recreated with the native writer.
    \\
    \\Options:
    \\  --iso <path>               Source LiveOS ISO (required).
    \\  --container <oci-layout>   OCI image-layout directory or save archive (required).
    \\  --rootfs-size <size>       ext4 rootfs.img size before SquashFS wrapping (required).
    \\                              Rounded up to the 4K block size; must fit the tree.
    \\  -o, --output <path>        Output ISO path (required). Published atomically.
    \\  --rootfs-path <path>       LiveOS payload path in the source ISO to replace.
    \\                              Defaults to the best-scoring squashfs/rootfs candidate.
    \\  --nested-rootfs-path <path>
    \\                              Path of the ext4 image inside the SquashFS
    \\                              (default LiveOS/rootfs.img).
    \\  --volume-id <id>           Output ISO volume identifier (default: the source's).
    \\  --uefi-boot-image <path>   El Torito UEFI boot image path in the output ISO tree.
    \\  --bios-boot-image <path>   El Torito BIOS boot image path in the output ISO tree.
    \\                              When neither is given, common source layouts are probed;
    \\                              at least one entry (UEFI-only is fine) must resolve.
    \\  --squashfs-compression zstd|none
    \\                              SquashFS block compression (default zstd).
    \\  --skip-iso-rootfs          Use the container as the root filesystem; keep only
    \\                              boot-critical files from the ISO/squashfs.
    \\  --architecture auto|x86_64|aarch64
    \\                              Target architecture (default: inferred from the container).
    \\  --ext4-label <label>       Root ext4 filesystem label (default rootfs).
    \\  --journal, --no-journal    Create a JBD2 journal on the root filesystem, or not
    \\                              (default --no-journal).
    \\  --journal-size <size>      Journal size (a whole number of 4K blocks). Implies --journal.
    \\  --root-selinux-label <context>
    \\                              SELinux context for the implicit ext4 root inode.
    \\  --source-date-epoch <seconds>
    \\                              Stamp this POSIX timestamp into the ext4, SquashFS, and
    \\                              ISO, and derive a fixed root filesystem UUID from it, for
    \\                              a byte-for-byte reproducible ISO.
    \\  --max-oci-blob-size <size> Maximum compressed OCI blob size (default 64M).
    \\  --max-oci-layer-size <size>
    \\                              Maximum decompressed OCI layer size (default 128M).
    \\  --max-oci-archive-size <size>
    \\                              Maximum docker/podman save archive size (default 512M).
    \\  --dry-run                  Resolve inputs and boot images, then report without writing.
    \\  -v, --verbose              Print each build step.
    \\
    \\Import limits (guardrails on the imported root tree; size them from a --dry-run):
    \\  --max-nodes, --max-path-bytes, --max-component-bytes, --max-file-bytes,
    \\  --max-total-bytes, --max-spool-bytes, --max-xattrs-per-node, --max-xattr-bytes-per-node
    \\
;

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var iso_path: ?[]const u8 = null;
    var container_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var rootfs_size: ?u64 = null;
    var rootfs_path: ?[]const u8 = null;
    var nested_rootfs_path: []const u8 = zvmi.build_iso.default_nested_rootfs_path;
    var volume_id: ?[]const u8 = null;
    var uefi_boot_image: ?[]const u8 = null;
    var bios_boot_image: ?[]const u8 = null;
    var squashfs_compression: zvmi.squashfs.WriterCompression = .zstd;
    var skip_iso_rootfs = false;
    var architecture: ?zvmi.bootconfig.Architecture = null;
    var ext4_label: []const u8 = "rootfs";
    var journal = zvmi.ext4.JournalOptions{};
    var root_selinux_label: ?[]const u8 = null;
    var source_date_epoch: ?u32 = null;
    var oci_load_options = zvmi.oci.LoadOptions{};
    var limits: zvmi.limits.ImportLimits = .{};
    var dry_run = false;
    var verbose = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--iso")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --iso requires a path", .{});
            iso_path = args[i];
        } else if (std.mem.eql(u8, arg, "--container")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --container requires a path", .{});
            container_path = args[i];
        } else if (std.mem.eql(u8, arg, "--rootfs-size")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --rootfs-size requires a value", .{});
            rootfs_size = zvmi.parseSize(args[i]) catch |err|
                return fail("build-iso: invalid --rootfs-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: -o/--output requires a path", .{});
            output_path = args[i];
        } else if (std.mem.eql(u8, arg, "--rootfs-path")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --rootfs-path requires a path", .{});
            rootfs_path = args[i];
        } else if (std.mem.eql(u8, arg, "--nested-rootfs-path")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --nested-rootfs-path requires a path", .{});
            nested_rootfs_path = args[i];
        } else if (std.mem.eql(u8, arg, "--volume-id")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --volume-id requires a value", .{});
            volume_id = args[i];
        } else if (std.mem.eql(u8, arg, "--uefi-boot-image")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --uefi-boot-image requires a path", .{});
            uefi_boot_image = args[i];
        } else if (std.mem.eql(u8, arg, "--bios-boot-image")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --bios-boot-image requires a path", .{});
            bios_boot_image = args[i];
        } else if (std.mem.eql(u8, arg, "--squashfs-compression")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --squashfs-compression requires zstd or none", .{});
            if (std.mem.eql(u8, args[i], "zstd")) {
                squashfs_compression = .zstd;
            } else if (std.mem.eql(u8, args[i], "none")) {
                squashfs_compression = .none;
            } else {
                return fail("build-iso: invalid --squashfs-compression '{s}' (expected zstd or none)", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--skip-iso-rootfs")) {
            skip_iso_rootfs = true;
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --architecture requires auto, x86_64, or aarch64", .{});
            if (std.mem.eql(u8, args[i], "auto")) {
                architecture = null;
            } else if (std.mem.eql(u8, args[i], "x86_64") or std.mem.eql(u8, args[i], "amd64")) {
                architecture = .x86_64;
            } else if (std.mem.eql(u8, args[i], "aarch64") or std.mem.eql(u8, args[i], "arm64")) {
                architecture = .aarch64;
            } else {
                return fail("build-iso: invalid --architecture '{s}' (expected auto, x86_64, or aarch64)", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--ext4-label")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --ext4-label requires a value", .{});
            ext4_label = args[i];
        } else if (std.mem.eql(u8, arg, "--journal")) {
            journal.enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-journal")) {
            journal.enabled = false;
        } else if (std.mem.eql(u8, arg, "--journal-size")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --journal-size requires a value", .{});
            journal.size_bytes = zvmi.parseSize(args[i]) catch |err|
                return fail("build-iso: invalid --journal-size '{s}': {s}", .{ args[i], @errorName(err) });
            journal.enabled = true;
        } else if (std.mem.eql(u8, arg, "--root-selinux-label")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --root-selinux-label requires a value", .{});
            root_selinux_label = args[i];
        } else if (std.mem.eql(u8, arg, "--source-date-epoch")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --source-date-epoch requires a value", .{});
            source_date_epoch = std.fmt.parseInt(u32, args[i], 10) catch
                return fail("build-iso: invalid --source-date-epoch '{s}' (expected a POSIX seconds count)", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--max-oci-blob-size")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --max-oci-blob-size requires a value", .{});
            oci_load_options.max_blob_size = parseOciLimit(args[i]) catch |err|
                return fail("build-iso: invalid --max-oci-blob-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--max-oci-layer-size")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --max-oci-layer-size requires a value", .{});
            oci_load_options.max_layer_size = parseOciLimit(args[i]) catch |err|
                return fail("build-iso: invalid --max-oci-layer-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--max-oci-archive-size")) {
            i += 1;
            if (i >= args.len) return fail("build-iso: --max-oci-archive-size requires a value", .{});
            oci_load_options.max_archive_size = parseOciLimit(args[i]) catch |err|
                return fail("build-iso: invalid --max-oci-archive-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{help_text});
            return 0;
        } else if (zvmi.limits.limitForFlag(arg) != null) {
            i += 1;
            if (i >= args.len) return fail("build-iso: {s} requires a value", .{arg});
            _ = limits.parseFlag(arg, args[i]) catch |err|
                return fail("build-iso: invalid {s} '{s}': {s}", .{ arg, args[i], @errorName(err) });
        } else {
            return fail("build-iso: unexpected argument '{s}'", .{arg});
        }
    }

    var boot_images_buf: [2]zvmi.build_iso.BootImage = undefined;
    var boot_images_len: usize = 0;
    if (uefi_boot_image) |path| {
        boot_images_buf[boot_images_len] = .{ .platform = .uefi, .image_path = path };
        boot_images_len += 1;
    }
    if (bios_boot_image) |path| {
        boot_images_buf[boot_images_len] = .{ .platform = .bios, .image_path = path };
        boot_images_len += 1;
    }

    const determinism: ?zvmi.build_iso.Determinism = if (source_date_epoch) |epoch| .{
        .filesystem_timestamp = epoch,
        .root_filesystem_uuid = deriveUuid(epoch),
    } else null;

    var limit_sink = zvmi.limits.Diagnostic{};
    var report = zvmi.build_iso.build(gpa, io, .{
        .iso_path = iso_path orelse return fail("build-iso: --iso is required", .{}),
        .container_path = container_path orelse return fail("build-iso: --container is required", .{}),
        .oci_load_options = oci_load_options,
        .output_path = output_path orelse return fail("build-iso: -o/--output is required", .{}),
        .rootfs_size = rootfs_size orelse return fail("build-iso: --rootfs-size is required", .{}),
        .rootfs_path_in_iso = rootfs_path,
        .nested_rootfs_path = nested_rootfs_path,
        .skip_iso_rootfs = skip_iso_rootfs,
        .architecture = architecture,
        .ext4_label = ext4_label,
        .ext4_journal = journal,
        .root_selinux_label = root_selinux_label,
        .squashfs_compression = squashfs_compression,
        .volume_id = volume_id,
        .boot_images = boot_images_buf[0..boot_images_len],
        .limits = limits.tree(),
        .limit_diagnostic = &limit_sink,
        .determinism = determinism,
        .dry_run = dry_run,
        .verbose = verbose,
    }) catch |err| {
        const message = describeFailure(gpa, err, limit_sink.exceeded) catch
            return fail("build-iso: failed: {s}", .{@errorName(err)});
        defer gpa.free(message);
        return fail("{s}", .{message});
    };
    defer report.deinit(gpa);

    printReport(report, dry_run);
    return 0;
}

/// Derives a stable root filesystem UUID from the source-date epoch, so a
/// reproducible run needs only `--source-date-epoch` rather than a separately
/// specified UUID.
fn deriveUuid(epoch: u32) [16]u8 {
    var digest: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("zvmi-build-iso-rootfs-uuid\x00");
    var epoch_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &epoch_bytes, epoch, .little);
    hasher.update(&epoch_bytes);
    hasher.final(&digest);
    return digest[0..16].*;
}

fn parseOciLimit(value: []const u8) !usize {
    const size = try zvmi.parseSize(value);
    if (size == 0) return error.ZeroOciLimit;
    return std.math.cast(usize, size) orelse error.OciLimitTooLarge;
}

fn printReport(report: zvmi.build_iso.BuildIsoReport, dry_run: bool) void {
    const arch_text = switch (report.architecture) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
    };
    const compression_text = switch (report.squashfs_compression) {
        .zstd => "zstd",
        .none => "none",
    };
    if (dry_run) {
        std.debug.print(
            "Dry run OK: arch={s} rootfs={s} rootfs-size={d} volume-id={s} squashfs={s}\n",
            .{ arch_text, report.rootfs_path_in_iso, report.rootfs_size, report.volume_id, compression_text },
        );
    } else {
        std.debug.print(
            "Built ISO: arch={s} rootfs={s} rootfs-size={d} volume-id={s} squashfs={s} size={d}\n",
            .{ arch_text, report.rootfs_path_in_iso, report.rootfs_size, report.volume_id, compression_text, report.output_size },
        );
        const hex = std.fmt.bytesToHex(report.output_sha256, .lower);
        std.debug.print("  sha256: {s}\n", .{hex});
    }
    if (report.root_tree_digest) |digest| {
        const hex = std.fmt.bytesToHex(digest, .lower);
        std.debug.print("  root-tree-digest: {s}\n", .{hex});
    }
    std.debug.print("  nested-rootfs: {s}\n", .{report.nested_rootfs_path});
    for (report.boot_entries) |entry| {
        std.debug.print("  boot ({s}): {s}\n", .{ entry.platform.displayName(), entry.image_path });
    }
}

fn describeFailure(
    allocator: std.mem.Allocator,
    err: anyerror,
    limit_exceeded: ?zvmi.limits.Exceeded,
) std.mem.Allocator.Error![]u8 {
    if (limit_exceeded) |breach| {
        var message_buffer: [zvmi.limits.Exceeded.max_message_bytes]u8 = undefined;
        var remediation_buffer: [zvmi.limits.Exceeded.max_remediation_bytes]u8 = undefined;
        if (breach.limit.err() == err) {
            return std.fmt.allocPrint(
                allocator,
                "build-iso: failed: {s}\n{s}, or import less content.",
                .{
                    breach.describe(&message_buffer) catch unreachable,
                    breach.remediation(&remediation_buffer) catch unreachable,
                },
            );
        }
    }
    return switch (err) {
        error.NoBootImage => allocator.dupe(
            u8,
            "build-iso: failed: no El Torito boot image was found. Pass --uefi-boot-image and/or --bios-boot-image naming a boot image file inside the output ISO tree (at least one UEFI or BIOS boot image must resolve).",
        ),
        error.BootImageNotFound => allocator.dupe(
            u8,
            "build-iso: failed: a requested boot image path does not name a regular file in the output ISO tree. Check --uefi-boot-image/--bios-boot-image against the source ISO's layout.",
        ),
        error.DuplicateBootPlatform => allocator.dupe(
            u8,
            "build-iso: failed: at most one boot image per platform is supported.",
        ),
        error.SourcePathConflict => allocator.dupe(
            u8,
            "build-iso: failed: the output path or a scratch path overlaps an input path. Choose an output outside the ISO/container source directories.",
        ),
        error.RootfsNotFound => allocator.dupe(
            u8,
            "build-iso: failed: no LiveOS rootfs payload was found in the source ISO. Pass --rootfs-path naming the squashfs/rootfs payload.",
        ),
        else => std.fmt.allocPrint(allocator, "build-iso: failed: {s}", .{@errorName(err)}),
    };
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test {
    _ = deriveUuid(1_700_000_000);
}
