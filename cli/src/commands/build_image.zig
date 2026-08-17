//! `vmiz build-image --iso <file.iso> --container <oci-layout> [--generation 1|2] --size <size> -o <output.{raw|vhd|vhdx|qcow2}|-> [-O raw.gz] [--compress-level <1-9>] [--skip-iso-rootfs] [--verity] [--extra-kernel-options <opts>] [--boot-mode bls|uki|both] [--stub-source-path <path>]`

const std = @import("std");
const vmiz = @import("vmiz");
const opts = @import("opts.zig");

const help_text =
    \\usage: vmiz build-image --iso <file.iso> --container <oci-layout> [--generation 1|2] --size <size> -o <output.{{raw|vhd|vhdx|qcow2}}|-> [-O raw|raw.gz|raw.zst|vhd|vhdx|qcow2] [--compress-level <1-9>] [--rootfs-path <path>] [--skip-iso-rootfs] [--max-oci-blob-size <size>] [--max-oci-layer-size <size>] [--max-oci-archive-size <size>] [--esp-size <size>] [--ext4-label <label>] [--root-filesystem ext4|xfs] [--journal|--no-journal] [--journal-size <size>] [--root-selinux-label <context>] [--stub-source-path <path>] [--os-release-source-path <path>] [--splash-source-path <path>] [--uki-output-directory <path>] [--verity] [--extra-kernel-options <opts>] [--boot-mode bls|uki|both] [--dry-run] [-v]
    \\
    \\Options:
    \\  -o <path>|-                Output path, or - to stream the image to stdout.
    \\  -O <format>                Output format. raw.gz/raw.zst compress while the image
    \\                              is written instead of afterwards; both are streamable.
    \\  --compress-level <1-9>     gzip level for raw.gz (default 1, the fastest). A
    \\                              mostly-zero image is almost all runs of zeros, which
    \\                              every level collapses, so higher levels mostly cost time.
    \\  --boot-mode bls|uki|both   Gen2 boot files: GRUB+BLS only (default), UKI only, or both.
    \\  --esp-size <size>          ESP size (default 96M). UKI/both commonly need 512M or larger.
    \\  --generation 1|2           Azure VM generation (default 2).
    \\  --ext4-label <label>       Root ext4 filesystem label (default rootfs). For an
    \\                              XFS root this is the volume label and must be <=12 bytes.
    \\  --root-filesystem ext4|xfs Filesystem for the root partition (default ext4). xfs
    \\                              selects the bounded native XFS v5 writer; the ESP stays
    \\                              FAT32. xfs is incompatible with --journal and --verity.
    \\  --journal, --no-journal    Create a JBD2 journal on the root filesystem, or not
    \\                              (default --no-journal, matching every earlier build).
    \\                              Use --journal for an image that boots into a mutable
    \\                              root filesystem: without one, an unclean shutdown
    \\                              leaves nothing to replay and the next boot faces a
    \\                              full fsck. Incompatible with --verity, whose root is
    \\                              read-only and has nothing to journal.
    \\  --journal-size <size>      Journal size, a whole number of 4K blocks between 4M
    \\                              and half the filesystem. Implies --journal. Defaults
    \\                              to mke2fs's own scale: 4M below 128M, 16M below 1G,
    \\                              32M below 2G, 64M below 16G, up to 1G.
    \\  --root-selinux-label <context>
    \\                              SELinux context for the implicit root inode.
    \\  --skip-iso-rootfs          Use the container as the root filesystem; keep only boot-critical files from the ISO/squashfs.
    \\  --max-oci-blob-size <size> Maximum compressed OCI blob size (default 64M).
    \\  --max-oci-layer-size <size>
    \\                              Maximum decompressed OCI layer size (default 128M).
    \\  --max-oci-archive-size <size>
    \\                              Maximum docker/podman save archive size (default 512M).
    \\
    \\Import limits (guardrails on the imported root tree; raise them for a large
    \\installed root filesystem, and size them from a --dry-run report):
    \\  --max-nodes <count>        Imported inodes (default 1000000).
    \\  --max-path-bytes <size>    Longest imported path (default 4096).
    \\  --max-component-bytes <size>
    \\                              Longest single path component (default 255).
    \\  --max-file-bytes <size>    Largest single imported file (default 16G).
    \\  --max-total-bytes <size>   Total imported content (default 64G).
    \\  --max-spool-bytes <size>   Spool file holding the imported content (default 128G).
    \\  --max-xattrs-per-node <count>
    \\                              Extended attributes on one inode (default 256).
    \\  --max-xattr-bytes-per-node <size>
    \\                              Extended attribute bytes on one inode (default 1M).
    \\  --stub-source-path <path>  UKI/both only: use this systemd EFI stub path from the merged source tree.
    \\  --os-release-source-path <path>
    \\                              UKI/both only: use this os-release path from the merged source tree.
    \\  --splash-source-path <path>
    \\                              UKI/both only: embed this splash image from the merged source tree.
    \\  --uki-output-directory <path>
    \\                              UKI/both only: ESP destination directory (default EFI/Linux).
    \\  --verity                   Append a dm-verity hash tree and wire the matching kernel arguments.
    \\  --extra-kernel-options     Extra kernel command-line arguments appended after root=...
    \\
    \\UKI notes:
    \\  A systemd EFI stub such as linuxx64.efi.stub, systemd-stubx64.efi, or the
    \\  matching aa64 variant must exist in the merged ISO/squashfs/container source tree,
    \\  usually via the systemd-boot-unsigned package.
    \\  If the base OS image does not ship it, inject that package via an extra container
    \\  layer or point --stub-source-path at the non-standard path you added.
    \\
    \\--verity notes:
    \\  The source initramfs (boot/initrd*/boot/initramfs* in the merged source tree)
    \\  must already include dm-verity userspace tooling (systemd-veritysetup-generator,
    \\  systemd-veritysetup, or veritysetup, e.g. built with dracut --add veritysetup).
    \\  Without it, the built image will hang at boot waiting on /dev/mapper/root.
    \\  build-image checks for this and fails fast when it can conclusively tell the
    \\  tooling is missing.
;

const BuildImageFailureContext = struct {
    boot_mode: vmiz.bootconfig.BootMode = .bls_only,
    stub_source_path: ?[]const u8 = null,
    /// The breach that stopped the import, when one did. It carries the
    /// observed value, the configured limit, and the flag that raises it,
    /// which is everything the caller needs to retry successfully.
    limit_exceeded: ?vmiz.limits.Exceeded = null,
};

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var iso_path: ?[]const u8 = null;
    var container_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var output_format: ?vmiz.Format = null;
    var output_compression: ?vmiz.output.Compression = null;
    var compression_level: ?vmiz.output.Level = null;
    var stream_to_stdout = false;
    var rootfs_path: ?[]const u8 = null;
    var skip_iso_rootfs = false;
    var oci_load_options = vmiz.oci.LoadOptions{};
    var generation: vmiz.azure.Generation = .gen2;
    var size: ?u64 = null;
    var esp_size: ?u64 = null;
    var ext4_label: []const u8 = "rootfs";
    var root_filesystem: vmiz.layout.FilesystemKind = .ext4;
    var journal = vmiz.ext4.JournalOptions{};
    var root_selinux_label: ?[]const u8 = null;
    var stub_source_path: ?[]const u8 = null;
    var os_release_source_path: ?[]const u8 = null;
    var splash_source_path: ?[]const u8 = null;
    var uki_output_directory: []const u8 = "EFI/Linux";
    var enable_verity = false;
    var extra_kernel_options: []const u8 = "";
    var boot_mode: vmiz.bootconfig.BootMode = .bls_only;
    var dry_run = false;
    var verbose = false;
    var limits: vmiz.limits.ImportLimits = .{};

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--iso")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --iso requires a path", .{});
            iso_path = args[i];
        } else if (std.mem.eql(u8, arg, "--container")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --container requires a path", .{});
            container_path = args[i];
        } else if (std.mem.eql(u8, arg, "--generation")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --generation requires 1 or 2", .{});
            if (std.mem.eql(u8, args[i], "1") or std.mem.eql(u8, args[i], "gen1")) {
                generation = .gen1;
            } else if (std.mem.eql(u8, args[i], "2") or std.mem.eql(u8, args[i], "gen2")) {
                generation = .gen2;
            } else {
                return fail("build-image: invalid --generation '{s}' (expected 1 or 2)", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--size")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --size requires a value", .{});
            size = vmiz.parseSize(args[i]) catch |err|
                return fail("build-image: invalid --size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--esp-size")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --esp-size requires a value", .{});
            esp_size = vmiz.parseSize(args[i]) catch |err|
                return fail("build-image: invalid --esp-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--ext4-label")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --ext4-label requires a value", .{});
            ext4_label = args[i];
        } else if (std.mem.eql(u8, arg, "--root-filesystem")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --root-filesystem requires a value", .{});
            if (std.mem.eql(u8, args[i], "ext4")) {
                root_filesystem = .ext4;
            } else if (std.mem.eql(u8, args[i], "xfs")) {
                root_filesystem = .xfs;
            } else {
                return fail("build-image: invalid --root-filesystem '{s}': expected ext4 or xfs", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--journal")) {
            journal.enabled = true;
        } else if (std.mem.eql(u8, arg, "--no-journal")) {
            // Only `enabled` is cleared: an explicit --journal-size that
            // follows still means what it says, and one that preceded it was
            // just overruled.
            journal.enabled = false;
        } else if (std.mem.eql(u8, arg, "--journal-size")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --journal-size requires a value", .{});
            journal.size_bytes = vmiz.parseSize(args[i]) catch |err|
                return fail("build-image: invalid --journal-size '{s}': {s}", .{ args[i], @errorName(err) });
            journal.enabled = true;
        } else if (std.mem.eql(u8, arg, "--root-selinux-label")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --root-selinux-label requires a value", .{});
            root_selinux_label = args[i];
        } else if (std.mem.eql(u8, arg, "--stub-source-path")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --stub-source-path requires a path", .{});
            stub_source_path = args[i];
        } else if (std.mem.eql(u8, arg, "--os-release-source-path")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --os-release-source-path requires a path", .{});
            os_release_source_path = args[i];
        } else if (std.mem.eql(u8, arg, "--splash-source-path")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --splash-source-path requires a path", .{});
            splash_source_path = args[i];
        } else if (std.mem.eql(u8, arg, "--uki-output-directory")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --uki-output-directory requires a path", .{});
            uki_output_directory = args[i];
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return fail("build-image: -o/--output requires a path", .{});
            if (std.mem.eql(u8, args[i], "-")) {
                stream_to_stdout = true;
            } else {
                output_path = args[i];
            }
        } else if (std.mem.eql(u8, arg, "-O")) {
            i += 1;
            if (i >= args.len) return fail("build-image: -O requires a format", .{});
            const spec = vmiz.output.Spec.parseName(args[i]) orelse
                return fail("build-image: unknown output format '{s}'", .{args[i]});
            output_format = spec.format;
            output_compression = spec.compression;
        } else if (std.mem.eql(u8, arg, "--compress-level")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --compress-level requires a value", .{});
            compression_level = vmiz.output.parseLevel(args[i]) catch
                return fail("build-image: invalid --compress-level '{s}' (expected 1 fastest through 9 smallest)", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--rootfs-path")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --rootfs-path requires a path", .{});
            rootfs_path = args[i];
        } else if (std.mem.eql(u8, arg, "--skip-iso-rootfs")) {
            skip_iso_rootfs = true;
        } else if (std.mem.eql(u8, arg, "--max-oci-blob-size")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --max-oci-blob-size requires a value", .{});
            oci_load_options.max_blob_size = parseOciLimit(args[i]) catch |err|
                return fail("build-image: invalid --max-oci-blob-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--max-oci-layer-size")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --max-oci-layer-size requires a value", .{});
            oci_load_options.max_layer_size = parseOciLimit(args[i]) catch |err|
                return fail("build-image: invalid --max-oci-layer-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--max-oci-archive-size")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --max-oci-archive-size requires a value", .{});
            oci_load_options.max_archive_size = parseOciLimit(args[i]) catch |err|
                return fail("build-image: invalid --max-oci-archive-size '{s}': {s}", .{ args[i], @errorName(err) });
        } else if (std.mem.eql(u8, arg, "--verity")) {
            enable_verity = true;
        } else if (std.mem.eql(u8, arg, "--extra-kernel-options")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --extra-kernel-options requires a value", .{});
            extra_kernel_options = args[i];
        } else if (std.mem.eql(u8, arg, "--boot-mode")) {
            i += 1;
            if (i >= args.len) return fail("build-image: --boot-mode requires bls, uki, or both", .{});
            if (std.mem.eql(u8, args[i], "bls")) {
                boot_mode = .bls_only;
            } else if (std.mem.eql(u8, args[i], "uki")) {
                boot_mode = .uki_only;
            } else if (std.mem.eql(u8, args[i], "both")) {
                boot_mode = .bls_and_uki;
            } else {
                return fail("build-image: invalid --boot-mode '{s}' (expected bls, uki, or both)", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return fail(help_text, .{});
        } else if (vmiz.limits.limitForFlag(arg) != null) {
            i += 1;
            if (i >= args.len) return fail("build-image: {s} requires a value", .{arg});
            _ = limits.parseFlag(arg, args[i]) catch |err|
                return fail("build-image: invalid {s} '{s}': {s}", .{ arg, args[i], @errorName(err) });
        } else {
            return fail("build-image: unexpected argument '{s}'", .{arg});
        }
    }

    // The sink outlives the build so a failure can name the limit that
    // stopped it and a success can report how close the import came.
    var limit_sink = vmiz.limits.Diagnostic{};
    var report = blk: {
        const built = vmiz.build_image.build(gpa, io, .{
            .iso_path = iso_path orelse return fail("build-image: --iso is required", .{}),
            .container_path = container_path orelse return fail("build-image: --container is required", .{}),
            .oci_load_options = oci_load_options,
            .output_path = if (stream_to_stdout) "" else output_path orelse return fail("build-image: -o/--output is required", .{}),
            .size = size orelse return fail("build-image: --size is required", .{}),
            .generation = generation,
            .output_format = output_format,
            .output_compression = output_compression,
            .compression_level = compression_level,
            .stream_to_stdout = stream_to_stdout,
            .rootfs_path_in_iso = rootfs_path,
            .skip_iso_rootfs = skip_iso_rootfs,
            .esp_size = esp_size orelse vmiz.build_image.default_esp_size,
            .ext4_label = ext4_label,
            .root_filesystem = root_filesystem,
            .ext4_journal = journal,
            .root_selinux_label = root_selinux_label,
            .verity = enable_verity,
            .extra_kernel_options = extra_kernel_options,
            .boot_mode = boot_mode,
            .uki = .{
                .stub_source_path = stub_source_path,
                .os_release_source_path = os_release_source_path,
                .splash_source_path = splash_source_path,
                .output_directory = uki_output_directory,
            },
            .limits = limits.tree(),
            .limit_diagnostic = &limit_sink,
            .dry_run = dry_run,
            .verbose = verbose,
        }) catch |err| {
            const message = describeBuildImageFailure(gpa, err, .{
                .boot_mode = boot_mode,
                .stub_source_path = stub_source_path,
                .limit_exceeded = limit_sink.exceeded,
            }) catch return fail("build-image: failed: {s}", .{@errorName(err)});
            defer gpa.free(message);
            return fail("{s}", .{message});
        };
        break :blk built;
    };
    defer report.deinit(gpa);

    printReport(report, dry_run);
    printLimitPeaks(report.limit_peaks, limits);
    return 0;
}

/// Prints what the import actually needed, so the next run can be sized from a
/// --dry-run instead of from a guess. A limit the import never touched stays
/// at zero and is left out.
fn printLimitPeaks(peaks: vmiz.limits.Peaks, configured: vmiz.limits.ImportLimits) void {
    inline for (comptime std.enums.values(vmiz.limits.Limit)) |limit| {
        const peak = peaks.value(limit);
        if (peak != 0) {
            std.debug.print(
                "  peak {s}: {d} of {d} ({s})\n",
                .{ limit.unit(), peak, configured.value(limit), limit.flag() },
            );
        }
    }
}

fn parseOciLimit(value: []const u8) !usize {
    const size = try vmiz.parseSize(value);
    if (size == 0) return error.ZeroOciLimit;
    return std.math.cast(usize, size) orelse error.OciLimitTooLarge;
}

fn printReport(report: vmiz.build_image.BuildImageReport, dry_run: bool) void {
    const output_text = (vmiz.output.Spec{
        .format = report.output_format,
        .compression = report.output_compression,
    }).displayName();
    const gen_text = if (report.generation == .gen1) "Gen1" else "Gen2";
    const arch_text = switch (report.architecture) {
        .x86_64 => "x86_64",
        .aarch64 => "aarch64",
    };

    if (dry_run) {
        std.debug.print(
            "Dry run OK: format={s} generation={s} arch={s} size={d} rootfs={s}\n",
            .{ output_text, gen_text, arch_text, report.disk_size, report.rootfs_path_in_iso },
        );
    } else {
        std.debug.print(
            "Built image: format={s} generation={s} arch={s} size={d} rootfs={s}\n",
            .{ output_text, gen_text, arch_text, report.disk_size, report.rootfs_path_in_iso },
        );
    }

    for (report.planned_partitions) |partition| {
        std.debug.print(
            "  {s}: offset={d} length={d}\n",
            .{ partition.planned.name, partition.planned.offset_bytes, partition.planned.length_bytes },
        );
    }

    if (report.vhd_alignment) |alignment| {
        std.debug.print(
            "  vhd-alignment: old={d} new={d} resized={any}\n",
            .{ alignment.old_size, alignment.new_size, alignment.was_resized },
        );
    }
    if (report.partition_style) |style| {
        std.debug.print("  partition-style: {s}\n", .{style.message});
    }
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return if (std.mem.startsWith(u8, format, "usage:")) 0 else 1;
}

fn describeBuildImageFailure(
    allocator: std.mem.Allocator,
    err: anyerror,
    context: BuildImageFailureContext,
) std.mem.Allocator.Error![]u8 {
    const uki_mode_text = switch (context.boot_mode) {
        .uki_only => "--boot-mode uki",
        .bls_and_uki => "--boot-mode both",
        .bls_only => "UKI mode",
    };

    if (context.limit_exceeded) |breach| {
        // The error name alone says nothing actionable; the breach knows the
        // value that was observed and the flag that admits it.
        var message_buffer: [vmiz.limits.Exceeded.max_message_bytes]u8 = undefined;
        var remediation_buffer: [vmiz.limits.Exceeded.max_remediation_bytes]u8 = undefined;
        if (breach.limit.err() == err) {
            return std.fmt.allocPrint(
                allocator,
                "build-image: failed: {s}\n{s}, or import less content.",
                .{
                    breach.describe(&message_buffer) catch unreachable,
                    breach.remediation(&remediation_buffer) catch unreachable,
                },
            );
        }
    }

    return switch (err) {
        error.MissingUkiStub => if (context.stub_source_path) |path|
            std.fmt.allocPrint(
                allocator,
                "build-image: failed: no systemd EFI stub was found at --stub-source-path {s} while preparing UKI boot files.\nExpected a stub such as linuxx64.efi.stub, systemd-stubx64.efi, or the matching aa64 variant, typically from the systemd-boot-unsigned package.\nInstall or inject that package into the merged source content, or update --stub-source-path to the correct in-tree location.",
                .{path},
            )
        else
            std.fmt.allocPrint(
                allocator,
                "build-image: failed: {s} was requested, but no systemd EFI stub was found in the merged ISO/squashfs/container source tree.\nExpected a stub such as linuxx64.efi.stub, systemd-stubx64.efi, or the matching aa64 variant, typically from the systemd-boot-unsigned package.\nInstall or inject that package into the source content (for example via an extra container layer), or pass --stub-source-path <path> if the stub already exists at a non-standard path.",
                .{uki_mode_text},
            ),
        error.EspTooSmallForBootArtifacts => allocator.dupe(
            u8,
            "build-image: failed: the ESP partition ran out of space while populating boot files.\nUKI mode stores large kernel/initrd payloads inside EFI binaries; try increasing --esp-size (512M is a good starting point for real distro images).",
        ),
        error.InitramfsMissingVerityTooling => allocator.dupe(
            u8,
            "build-image: failed: --verity was requested, but the source initramfs (boot/initrd*/boot/initramfs* in the merged ISO/squashfs/container tree) does not include dm-verity userspace tooling (systemd-veritysetup-generator, systemd-veritysetup, or veritysetup).\nWithout it, systemd-veritysetup-generator never runs and the built image will hang at boot waiting on /dev/mapper/root (see https://github.com/cataggar/vmiz/issues/77).\nRebuild the initramfs with that tooling included (e.g. dracut --add veritysetup, or the equivalent module/package for the base OS's initramfs generator) before using --verity.",
        ),
        error.JournalWithVerityRoot => allocator.dupe(
            u8,
            "build-image: failed: --journal and --verity cannot be combined.\nA dm-verity root is mounted read-only over a hash tree computed from its exact bytes, so it is never written to and has nothing to journal; the journal would only consume space and imply a durability property the image does not have.\nDrop --journal for a verity image, or drop --verity for a mutable journalled root.",
        ),
        error.Ext4JournalWithXfsRoot => allocator.dupe(
            u8,
            "build-image: failed: --journal cannot be combined with --root-filesystem xfs.\nXFS keeps its own internal metadata log rather than an ext4-style JBD2 journal, so a --journal request cannot describe it.\nDrop --journal for an XFS root, or select --root-filesystem ext4 to journal an ext4 root.",
        ),
        error.VerityWithXfsRoot => allocator.dupe(
            u8,
            "build-image: failed: --verity cannot be combined with --root-filesystem xfs.\nThe dm-verity split and hash tree are computed on ext4 block geometry and the bounded XFS writer fills a buffer rounded down to whole allocation groups, so a verified XFS root cannot be sealed here.\nDrop --verity for an XFS root, or select --root-filesystem ext4 for a verity root.",
        ),
        error.UnsupportedRootFilesystem => allocator.dupe(
            u8,
            "build-image: failed: the selected root filesystem cannot be written as a bootable root.\nOnly ext4 and xfs are valid roots; the ESP is always FAT32 and planned separately.",
        ),
        error.FilesystemTooSmallForJournal => allocator.dupe(
            u8,
            "build-image: failed: --journal was requested, but the root filesystem is smaller than the 8M minimum a JBD2 journal needs.\nIncrease --size, or drop --journal.",
        ),
        error.JournalSizeTooSmall => allocator.dupe(
            u8,
            "build-image: failed: --journal-size is below the 4M JBD2 minimum that mke2fs also enforces.\nPass at least 4M, or omit --journal-size to use the default scaled to the filesystem size.",
        ),
        error.JournalSizeTooLarge => allocator.dupe(
            u8,
            "build-image: failed: --journal-size exceeds what the root filesystem can carry: a journal may be at most half the filesystem, and at most 40G.\nReduce --journal-size, increase --size, or omit --journal-size to use the default scaled to the filesystem size.",
        ),
        error.UnalignedJournalSize => allocator.dupe(
            u8,
            "build-image: failed: --journal-size must be a non-zero whole number of 4K filesystem blocks.\nRound it to a multiple of 4K, for example 32M.",
        ),
        error.CompressionRequiresRawFormat => outputConstraintMessage(allocator, error.CompressionRequiresRawFormat),
        error.FormatRequiresSeekableOutput => outputConstraintMessage(allocator, error.FormatRequiresSeekableOutput),
        error.CompressionLevelNotSupportedForZstd => outputConstraintMessage(allocator, error.CompressionLevelNotSupportedForZstd),
        error.CompressionLevelOutOfRange => outputConstraintMessage(allocator, error.CompressionLevelOutOfRange),
        else => std.fmt.allocPrint(allocator, "build-image: failed: {s}", .{@errorName(err)}),
    };
}

fn outputConstraintMessage(
    allocator: std.mem.Allocator,
    err: vmiz.output.SpecError,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "build-image: failed: {s}",
        .{opts.describeOutputError(err)},
    );
}

test "describeBuildImageFailure explains an unstreamable output format" {
    const message = try describeBuildImageFailure(
        std.testing.allocator,
        error.FormatRequiresSeekableOutput,
        .{},
    );
    defer std.testing.allocator.free(message);

    try std.testing.expect(std.mem.indexOf(u8, message, "stdout") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "raw.gz") != null);
}

test "describeBuildImageFailure explains why a journal and verity cannot be combined" {
    const message = try describeBuildImageFailure(std.testing.allocator, error.JournalWithVerityRoot, .{});
    defer std.testing.allocator.free(message);

    try std.testing.expect(std.mem.indexOf(u8, message, "--journal") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "--verity") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "read-only") != null);
}

test "describeBuildImageFailure names the xfs root incompatibilities" {
    const journal = try describeBuildImageFailure(std.testing.allocator, error.Ext4JournalWithXfsRoot, .{});
    defer std.testing.allocator.free(journal);
    try std.testing.expect(std.mem.indexOf(u8, journal, "--journal") != null);
    try std.testing.expect(std.mem.indexOf(u8, journal, "xfs") != null);

    const verity = try describeBuildImageFailure(std.testing.allocator, error.VerityWithXfsRoot, .{});
    defer std.testing.allocator.free(verity);
    try std.testing.expect(std.mem.indexOf(u8, verity, "--verity") != null);
    try std.testing.expect(std.mem.indexOf(u8, verity, "xfs") != null);

    const unsupported = try describeBuildImageFailure(std.testing.allocator, error.UnsupportedRootFilesystem, .{});
    defer std.testing.allocator.free(unsupported);
    try std.testing.expect(std.mem.indexOf(u8, unsupported, "ext4") != null);
    try std.testing.expect(std.mem.indexOf(u8, unsupported, "FAT32") != null);
}

test "describeBuildImageFailure names the journal size that was refused" {
    const too_small = try describeBuildImageFailure(std.testing.allocator, error.JournalSizeTooSmall, .{});
    defer std.testing.allocator.free(too_small);
    try std.testing.expect(std.mem.indexOf(u8, too_small, "--journal-size") != null);
    try std.testing.expect(std.mem.indexOf(u8, too_small, "4M") != null);

    const unaligned = try describeBuildImageFailure(std.testing.allocator, error.UnalignedJournalSize, .{});
    defer std.testing.allocator.free(unaligned);
    try std.testing.expect(std.mem.indexOf(u8, unaligned, "4K") != null);

    const too_small_fs = try describeBuildImageFailure(std.testing.allocator, error.FilesystemTooSmallForJournal, .{});
    defer std.testing.allocator.free(too_small_fs);
    try std.testing.expect(std.mem.indexOf(u8, too_small_fs, "--size") != null);
}

test "describeBuildImageFailure explains MissingUkiStub" {
    const message = try describeBuildImageFailure(std.testing.allocator, error.MissingUkiStub, .{
        .boot_mode = .uki_only,
    });
    defer std.testing.allocator.free(message);

    try std.testing.expect(std.mem.indexOf(u8, message, "systemd-boot-unsigned") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "--stub-source-path") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "--boot-mode uki") != null);
}

test "describeBuildImageFailure mentions explicit stub path" {
    const message = try describeBuildImageFailure(std.testing.allocator, error.MissingUkiStub, .{
        .boot_mode = .bls_and_uki,
        .stub_source_path = "custom/linuxx64.efi.stub",
    });
    defer std.testing.allocator.free(message);

    try std.testing.expect(std.mem.indexOf(u8, message, "custom/linuxx64.efi.stub") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "systemd-boot-unsigned") != null);
}

test "describeBuildImageFailure explains small ESP for UKI artifacts" {
    const message = try describeBuildImageFailure(std.testing.allocator, error.EspTooSmallForBootArtifacts, .{});
    defer std.testing.allocator.free(message);

    try std.testing.expect(std.mem.indexOf(u8, message, "--esp-size") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "512M") != null);
}

test "describeBuildImageFailure explains missing initramfs verity tooling" {
    const message = try describeBuildImageFailure(std.testing.allocator, error.InitramfsMissingVerityTooling, .{});
    defer std.testing.allocator.free(message);

    try std.testing.expect(std.mem.indexOf(u8, message, "--verity") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "systemd-veritysetup-generator") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "dracut --add veritysetup") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "issues/77") != null);
}

test "OCI limit parsing accepts bounded sizes" {
    try std.testing.expectEqual(@as(usize, 512 * 1024 * 1024), try parseOciLimit("512M"));
    try std.testing.expectError(error.ZeroOciLimit, parseOciLimit("0"));
}

test "describeBuildImageFailure names the limit, the value seen, and the flag" {
    const message = try describeBuildImageFailure(
        std.testing.allocator,
        error.NodeLimitExceeded,
        .{ .limit_exceeded = .{ .limit = .nodes, .observed = 1_000_001, .configured = 1_000_000 } },
    );
    defer std.testing.allocator.free(message);

    try std.testing.expect(std.mem.indexOf(u8, message, "NodeLimitExceeded") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "1000001") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "1000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "--max-nodes") != null);
}

test "a failure unrelated to the recorded breach keeps its own explanation" {
    // A breach recorded by an earlier probe must not relabel a later,
    // different failure.
    const message = try describeBuildImageFailure(
        std.testing.allocator,
        error.EspTooSmallForBootArtifacts,
        .{ .limit_exceeded = .{ .limit = .nodes, .observed = 2, .configured = 1 } },
    );
    defer std.testing.allocator.free(message);

    try std.testing.expect(std.mem.indexOf(u8, message, "--esp-size") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "--max-nodes") == null);
}
