//! `zvmi recustomize-iso --iso <source.iso> --container <oci> --rootfs-size <size> -o <output.iso>`:
//! a strict ISO-in -> customized ISO-out recustomization product. The source
//! ISO is authoritative -- its directory tree, node metadata/timestamps, volume
//! metadata, and El Torito catalog are all preserved -- and only its LiveOS
//! payload is replaced by a native SquashFS wrapping a customized ext4
//! rootfs.img.
//!
//! Unlike `build-iso`, this command exposes no boot-image or volume-id
//! overrides: it preserves the source catalog and volume metadata, or refuses
//! with a precise diagnostic when the source uses a feature the native writer
//! cannot losslessly reproduce. There is no best-effort fallback. PXE is not
//! part of this feature.

const std = @import("std");
const zvmi = @import("zvmi");

const help_text =
    \\usage: zvmi recustomize-iso --iso <source.iso> --container <oci-layout> --rootfs-size <size> -o <output.iso>
    \\                            [--rootfs-path <path>] [--nested-rootfs-path <path>]
    \\                            [--squashfs-compression zstd|none] [--skip-iso-rootfs]
    \\                            [--architecture auto|x86_64|aarch64] [--ext4-label <label>]
    \\                            [--journal|--no-journal] [--journal-size <size>] [--root-selinux-label <context>]
    \\                            [--source-date-epoch <seconds>] [--max-oci-blob-size <size>]
    \\                            [--max-oci-layer-size <size>] [--max-oci-archive-size <size>] [--dry-run] [-v]
    \\
    \\Recustomizes a LiveOS ISO. The source ISO is treated as authoritative: its
    \\directory tree, node metadata/timestamps, primary volume metadata, and El
    \\Torito boot catalog are preserved. The customized root tree (source ISO
    \\LiveOS payload flattened, OCI layers overlaid, OS customization and
    \\generalization applied) is written to a deterministic ext4 rootfs.img,
    \\wrapped in a native zstd SquashFS at the source's LiveOS payload path, and
    \\folded back into the preserved tree with only that payload replaced.
    \\
    \\Strict refusal: before any scratch or output is created the source is run
    \\through the strict rewrite gate. If it carries any feature the native
    \\writer cannot losslessly reproduce -- an unmapped boot extent, floppy/hard-
    \\disk El Torito emulation, Rock Ridge CL/PL/RE relocation, an unmodeled SUSP
    \\record, an interleaved/extended-attribute/multi-extent-directory record,
    \\ambiguous duplicate names, a boot platform other than BIOS/UEFI, more than
    \\one entry per platform, or selection criteria -- the command refuses with a
    \\precise diagnostic instead of producing a lossy ISO.
    \\
    \\This command deliberately exposes no --uefi-boot-image/--bios-boot-image or
    \\--volume-id overrides: it preserves the source catalog and volume metadata
    \\or refuses. PXE is not part of this feature.
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
    \\                              regenerated payload, and derive a fixed root filesystem
    \\                              UUID from it, for a byte-for-byte reproducible ISO.
    \\  --max-oci-blob-size <size> Maximum compressed OCI blob size (default 64M).
    \\  --max-oci-layer-size <size>
    \\                              Maximum decompressed OCI layer size (default 128M).
    \\  --max-oci-archive-size <size>
    \\                              Maximum docker/podman save archive size (default 512M).
    \\  --dry-run                  Inspect the source, model the preservation plan, and
    \\                              report without writing.
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
    var nested_rootfs_path: []const u8 = zvmi.recustomize_iso.default_nested_rootfs_path;
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
            if (i >= args.len) return fail("recustomize-iso: --iso requires a path", .{});
            iso_path = args[i];
        } else if (std.mem.eql(u8, arg, "--container")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --container requires a path", .{});
            container_path = args[i];
        } else if (std.mem.eql(u8, arg, "--rootfs-size")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --rootfs-size requires a value", .{});
            rootfs_size = zvmi.parseSize(args[i]) catch |err|
                return fail("recustomize-iso: invalid --rootfs-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: -o/--output requires a path", .{});
            output_path = args[i];
        } else if (std.mem.eql(u8, arg, "--rootfs-path")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --rootfs-path requires a path", .{});
            rootfs_path = args[i];
        } else if (std.mem.eql(u8, arg, "--nested-rootfs-path")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --nested-rootfs-path requires a path", .{});
            nested_rootfs_path = args[i];
        } else if (std.mem.eql(u8, arg, "--squashfs-compression")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --squashfs-compression requires zstd or none", .{});
            if (std.mem.eql(u8, args[i], "zstd")) {
                squashfs_compression = .zstd;
            } else if (std.mem.eql(u8, args[i], "none")) {
                squashfs_compression = .none;
            } else {
                return fail("recustomize-iso: invalid --squashfs-compression '{s}' (expected zstd or none)", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--skip-iso-rootfs")) {
            skip_iso_rootfs = true;
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --architecture requires auto, x86_64, or aarch64", .{});
            if (std.mem.eql(u8, args[i], "auto")) {
                architecture = null;
            } else if (std.mem.eql(u8, args[i], "x86_64") or std.mem.eql(u8, args[i], "amd64")) {
                architecture = .x86_64;
            } else if (std.mem.eql(u8, args[i], "aarch64") or std.mem.eql(u8, args[i], "arm64")) {
                architecture = .aarch64;
            } else {
                return fail("recustomize-iso: invalid --architecture '{s}' (expected auto, x86_64, or aarch64)", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--ext4-label")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --ext4-label requires a value", .{});
            ext4_label = args[i];
        } else if (std.mem.eql(u8, arg, "--journal")) {
            journal.enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-journal")) {
            journal.enabled = false;
        } else if (std.mem.eql(u8, arg, "--journal-size")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --journal-size requires a value", .{});
            journal.size_bytes = zvmi.parseSize(args[i]) catch |err|
                return fail("recustomize-iso: invalid --journal-size '{s}': {s}", .{ args[i], @errorName(err) });
            journal.enabled = true;
        } else if (std.mem.eql(u8, arg, "--root-selinux-label")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --root-selinux-label requires a value", .{});
            root_selinux_label = args[i];
        } else if (std.mem.eql(u8, arg, "--source-date-epoch")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --source-date-epoch requires a value", .{});
            source_date_epoch = std.fmt.parseInt(u32, args[i], 10) catch
                return fail("recustomize-iso: invalid --source-date-epoch '{s}' (expected a POSIX seconds count)", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--max-oci-blob-size")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --max-oci-blob-size requires a value", .{});
            oci_load_options.max_blob_size = parseOciLimit(args[i]) catch |err|
                return fail("recustomize-iso: invalid --max-oci-blob-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--max-oci-layer-size")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --max-oci-layer-size requires a value", .{});
            oci_load_options.max_layer_size = parseOciLimit(args[i]) catch |err|
                return fail("recustomize-iso: invalid --max-oci-layer-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--max-oci-archive-size")) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: --max-oci-archive-size requires a value", .{});
            oci_load_options.max_archive_size = parseOciLimit(args[i]) catch |err|
                return fail("recustomize-iso: invalid --max-oci-archive-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{help_text});
            return 0;
        } else if (zvmi.limits.limitForFlag(arg) != null) {
            i += 1;
            if (i >= args.len) return fail("recustomize-iso: {s} requires a value", .{arg});
            _ = limits.parseFlag(arg, args[i]) catch |err|
                return fail("recustomize-iso: invalid {s} '{s}': {s}", .{ arg, args[i], @errorName(err) });
        } else {
            return fail("recustomize-iso: unexpected argument '{s}'", .{arg});
        }
    }

    const determinism: ?zvmi.recustomize_iso.Determinism = if (source_date_epoch) |epoch| .{
        .filesystem_timestamp = epoch,
        .root_filesystem_uuid = deriveUuid(epoch),
    } else null;

    var limit_sink = zvmi.limits.Diagnostic{};
    var diagnostic = zvmi.recustomize_iso.RecustomizeDiagnostic{ .kind = .boot_image_unmapped };
    defer diagnostic.deinit(gpa);
    var report = zvmi.recustomize_iso.build(gpa, io, .{
        .iso_path = iso_path orelse return fail("recustomize-iso: --iso is required", .{}),
        .container_path = container_path orelse return fail("recustomize-iso: --container is required", .{}),
        .oci_load_options = oci_load_options,
        .output_path = output_path orelse return fail("recustomize-iso: -o/--output is required", .{}),
        .rootfs_size = rootfs_size orelse return fail("recustomize-iso: --rootfs-size is required", .{}),
        .rootfs_path_in_iso = rootfs_path,
        .nested_rootfs_path = nested_rootfs_path,
        .skip_iso_rootfs = skip_iso_rootfs,
        .architecture = architecture,
        .ext4_label = ext4_label,
        .ext4_journal = journal,
        .root_selinux_label = root_selinux_label,
        .squashfs_compression = squashfs_compression,
        .limits = limits.tree(),
        .limit_diagnostic = &limit_sink,
        .diagnostic = &diagnostic,
        .determinism = determinism,
        .dry_run = dry_run,
        .verbose = verbose,
    }) catch |err| {
        const message = describeFailure(gpa, err, limit_sink.exceeded, diagnostic) catch
            return fail("recustomize-iso: failed: {s}", .{@errorName(err)});
        defer gpa.free(message);
        return fail("{s}", .{message});
    };
    defer report.deinit(gpa);

    printReport(report, dry_run);
    return 0;
}

/// Derives a stable root filesystem UUID from the source-date epoch, so a
/// reproducible run needs only `--source-date-epoch`.
fn deriveUuid(epoch: u32) [16]u8 {
    var digest: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("zvmi-recustomize-iso-rootfs-uuid\x00");
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

fn printReport(report: zvmi.recustomize_iso.RecustomizeIsoReport, dry_run: bool) void {
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
            "Dry run OK (strict inspection {s}): arch={s} rootfs={s} rootfs-size={d} volume-id={s} squashfs={s}\n",
            .{
                if (report.strict_inspection_clean) "clean" else "blocked",
                arch_text,
                report.rootfs_path_in_iso,
                report.rootfs_size,
                report.source_volume.volume_id,
                compression_text,
            },
        );
    } else {
        std.debug.print(
            "Recustomized ISO (strict inspection {s}): arch={s} rootfs={s} rootfs-size={d} volume-id={s} squashfs={s} size={d}\n",
            .{
                if (report.strict_inspection_clean) "clean" else "blocked",
                arch_text,
                report.rootfs_path_in_iso,
                report.rootfs_size,
                report.output_volume.volume_id,
                compression_text,
                report.output_size,
            },
        );
        std.debug.print("  source sha256: {s}\n", .{std.fmt.bytesToHex(report.source_sha256, .lower)});
        std.debug.print("  output sha256: {s}\n", .{std.fmt.bytesToHex(report.output_sha256, .lower)});
    }
    if (report.root_tree_digest) |digest| {
        std.debug.print("  root-tree-digest: {s}\n", .{std.fmt.bytesToHex(digest, .lower)});
    }
    std.debug.print("  preserved nodes: {d}\n", .{report.preserved_node_count});
    std.debug.print("  nested-rootfs: {s}\n", .{report.nested_rootfs_path});
    std.debug.print("  volume: id={s} system={s} set={s} publisher={s} preparer={s} app={s}\n", .{
        report.source_volume.volume_id,
        report.source_volume.system_id,
        report.source_volume.volume_set_id,
        report.source_volume.publisher_id,
        report.source_volume.preparer_id,
        report.source_volume.application_id,
    });
    for (report.boot_entries) |entry| {
        std.debug.print("  boot ({s}): {s}\n", .{ entry.platform.displayName(), entry.image_path });
    }
}

fn describeFailure(
    allocator: std.mem.Allocator,
    err: anyerror,
    limit_exceeded: ?zvmi.limits.Exceeded,
    diagnostic: zvmi.recustomize_iso.RecustomizeDiagnostic,
) std.mem.Allocator.Error![]u8 {
    if (limit_exceeded) |breach| {
        var message_buffer: [zvmi.limits.Exceeded.max_message_bytes]u8 = undefined;
        var remediation_buffer: [zvmi.limits.Exceeded.max_remediation_bytes]u8 = undefined;
        if (breach.limit.err() == err) {
            return std.fmt.allocPrint(
                allocator,
                "recustomize-iso: failed: {s}\n{s}, or import less content.",
                .{
                    breach.describe(&message_buffer) catch unreachable,
                    breach.remediation(&remediation_buffer) catch unreachable,
                },
            );
        }
    }
    switch (err) {
        error.SourceNotRewritable,
        error.UnsupportedBootPlatform,
        error.DuplicateBootPlatform,
        error.BootSelectionCriteria,
        => return describeRefusal(allocator, diagnostic),
        error.SourcePathConflict => return allocator.dupe(
            u8,
            "recustomize-iso: failed: the output path or a scratch path overlaps an input path. Choose an output outside the ISO/container source directories.",
        ),
        error.RootfsNotFound => return allocator.dupe(
            u8,
            "recustomize-iso: failed: no LiveOS rootfs payload was found in the source ISO. Pass --rootfs-path naming the squashfs/rootfs payload.",
        ),
        else => return std.fmt.allocPrint(allocator, "recustomize-iso: failed: {s}", .{@errorName(err)}),
    }
}

fn describeRefusal(
    allocator: std.mem.Allocator,
    diagnostic: zvmi.recustomize_iso.RecustomizeDiagnostic,
) std.mem.Allocator.Error![]u8 {
    const at_path: []u8 = if (diagnostic.path.len > 0)
        try std.fmt.allocPrint(allocator, " at '{s}'", .{diagnostic.path})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(at_path);
    const at_index: []u8 = if (diagnostic.catalog_index) |index|
        try std.fmt.allocPrint(allocator, " (boot catalog entry #{d})", .{index})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(at_index);
    const detail: []u8 = if (diagnostic.detail.len > 0)
        try std.fmt.allocPrint(allocator, " [{s}]", .{diagnostic.detail})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(detail);

    return std.fmt.allocPrint(
        allocator,
        "recustomize-iso: refused: the source ISO uses {s}{s}{s}{s}, which the native writer cannot losslessly preserve. " ++
            "recustomize-iso preserves the source or refuses; it does not produce a lossy ISO.",
        .{ diagnostic.kind.describe(), at_path, at_index, detail },
    );
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test {
    _ = deriveUuid(1_700_000_000);
    try std.testing.expectEqual(deriveUuid(7), deriveUuid(7));
    try std.testing.expect(!std.mem.eql(u8, &deriveUuid(1), &deriveUuid(2)));
}

// Minimal ISO fixture used by the CLI-level refusal test. The strict gate runs
// before the container is even loaded, so a refusal needs only a source ISO
// with a boot catalog to corrupt -- no OCI layout or LiveOS payload.
const CliFixtureNode = struct {
    path: []const u8,
    kind: zvmi.iso9660.SourceKind,
    bytes: []const u8 = &.{},
};

const CliFixtureSource = struct {
    nodes: []const CliFixtureNode,
    fn source(self: *const CliFixtureSource) zvmi.iso9660.TreeSource {
        return .{ .context = self, .vtable = &vtable };
    }
    const vtable = zvmi.iso9660.TreeSource.VTable{ .root = rootFn, .count = countFn, .node = nodeFn, .read = readFn };
    fn ctx(context: *const anyopaque) *const CliFixtureSource {
        return @ptrCast(@alignCast(context));
    }
    fn rootFn(_: *const anyopaque) zvmi.iso9660.SourceRoot {
        return .{ .mode = 0o755 };
    }
    fn countFn(context: *const anyopaque) usize {
        return ctx(context).nodes.len;
    }
    fn nodeFn(context: *const anyopaque, index: usize) anyerror!zvmi.iso9660.SourceNode {
        const n = ctx(context).nodes[index];
        return .{ .path = n.path, .kind = n.kind, .mode = if (n.kind == .directory) 0o755 else 0o644, .size = n.bytes.len };
    }
    fn readFn(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        const data = ctx(context).nodes[index].bytes;
        if (offset >= data.len) return 0;
        const start: usize = @intCast(offset);
        const n = @min(buffer.len, data.len - start);
        @memcpy(buffer[0..n], data[start..][0..n]);
        return n;
    }
};

test "recustomize-iso CLI refuses a source the strict gate rejects and writes no output" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    const iso_path = "test-recustomize-cli-refuse-src.iso";
    const output_path = "test-recustomize-cli-refuse-out.iso";
    defer std.Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const nodes = [_]CliFixtureNode{
        .{ .path = "boot", .kind = .directory },
        .{ .path = "boot/bios.img", .kind = .file, .bytes = "BIOS-BOOT-IMAGE" },
    };
    const src = CliFixtureSource{ .nodes = &nodes };
    _ = try zvmi.iso9660.writeImagePath(gpa, io, iso_path, src.source(), .{
        .volume_id = "ZVMI_SRC",
        .boot_entries = &.{.{ .platform = .bios, .image_path = "boot/bios.img" }},
    });

    // Corrupt the default entry's media byte to hard-disk emulation, which the
    // strict gate refuses. The boot catalog validation checksum is unaffected.
    {
        const file = try std.Io.Dir.cwd().openFile(io, iso_path, .{ .mode = .read_write });
        defer file.close(io);
        var sector: [2048]u8 = undefined;
        var lba: u32 = 16;
        const cat_lba: u32 = while (true) : (lba += 1) {
            _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * 2048);
            if (sector[0] == 0 and std.mem.startsWith(u8, sector[7..], "EL TORITO SPECIFICATION")) {
                break std.mem.readInt(u32, sector[71..75], .little);
            }
            if (sector[0] == 255) return error.NoBootRecord;
        };
        try file.writePositionalAll(io, &[_]u8{4}, @as(u64, cat_lba) * 2048 + 33);
    }

    // The container path need not exist: the gate refuses before it is loaded.
    const code = run(gpa, io, &.{
        "--iso",         iso_path,
        "--container",   "test-recustomize-cli-refuse-missing-oci",
        "--rootfs-size", "8M",
        "-o",            output_path,
    });
    try std.testing.expectEqual(@as(u8, 1), code);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, output_path, .{}));
}
