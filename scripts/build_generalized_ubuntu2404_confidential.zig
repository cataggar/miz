//! Build a generalized Ubuntu 24.04 x86_64 QCOW2 for Azure Confidential VMs.
//!
//! Canonical's immutable Azure VHD is already generalized and carries the
//! stock Microsoft/Canonical Secure Boot chain. This builder authenticates
//! that publication, validates the guest and disk contracts required for AMD
//! SEV-SNP, normalizes its legacy backup-GPT location, and converts the guest
//! bytes to standalone QCOW2.

const std = @import("std");
const miz = @import("miz");
const release_support = @import("release");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const artifact_pipeline = miz.artifact_pipeline;
const confidential = release_support.azure_confidential_vm;

const publication = "20260826";
const publication_base =
    "https://cloud-images.ubuntu.com/releases/noble/release-" ++ publication;
const archive_name = "ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz";
const archive_sha256 =
    "843d243792abb05b50e1a7f5e614e1184d8fc7195c119747cbb3038520258a22";
const archive_size: u64 = 603_960_567;
const manifest_name = "ubuntu-24.04-server-cloudimg-amd64-azure.vhd.manifest";
const manifest_sha256 =
    "b32ea30aeb683b8f7ff3287b03638ce9f0fffcc792bb832a869585cf21c065b8";
const sums_name = "SHA256SUMS";
const sums_sha256 =
    "ee5d4762c360593bc480ad345cbb78eee0e70dbf6bd2301c8bfc8b2007d4c7b3";
const signature_name = "SHA256SUMS.gpg";
const signature_sha256 =
    "303cceab0ff0aa69faa03df5c657c91d84e0e24ceac71b1f1f0b1fb860040242";
const archive_member = "livecd.ubuntu-cpc.azure.vhd";
const source_vhd_file_size: u64 = 32_213_303_808;
const source_vhd_virtual_size: u64 = source_vhd_file_size - miz.vhd.footer_size;
const source_gpt_virtual_size: u64 = 3584 * 1024 * 1024;
const canonical_fingerprint = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
const canonical_key_armor = @embedFile("fixtures/canonical-ubuntu-cloud-image-key.asc");
const canonical_key_armor_sha256 = [_]u8{
    0xe5, 0x81, 0xb3, 0x9f, 0xac, 0x6b, 0xfc, 0x19,
    0x9e, 0x92, 0x17, 0x88, 0xc3, 0xc0, 0x7a, 0xc5,
    0x40, 0x6f, 0xe8, 0x8d, 0xb4, 0x87, 0xc7, 0xbd,
    0xcf, 0x1e, 0x1d, 0x2f, 0x78, 0xfb, 0xcf, 0x05,
};

const default_output = "Ubuntu-24.04-x86_64.confidential.qcow2";
const default_work_dir = ".scratch/ubuntu2404-confidential";
const source_archive_max_size: u64 = 700 * 1024 * 1024;
const metadata_max_size: u64 = 4 * 1024 * 1024;
const efi_binary_max_size: u64 = 32 * 1024 * 1024;
const command_output_max_size: usize = 64 * 1024;
const pe_machine_x86_64: u16 = 0x8664;

const required_manifest_packages = [_][]const u8{
    "cloud-guest-utils",
    "cloud-init",
    "grub-efi-amd64-signed",
    "libtss2-esys-3.0.2-0t64",
    "linux-azure",
    "linux-base-sgx",
    "linux-image-azure",
    "shim-signed",
    "tpm-udev",
    "walinuxagent",
};

const required_kernel_options = [_][]const u8{
    "CONFIG_AMD_MEM_ENCRYPT",
    "CONFIG_EFI",
    "CONFIG_EFI_STUB",
    "CONFIG_HYPERV",
    "CONFIG_HYPERV_BALLOON",
    "CONFIG_HYPERV_NET",
    "CONFIG_HYPERV_STORAGE",
    "CONFIG_HYPERV_UTILS",
    "CONFIG_SECURITY_LOCKDOWN_LSM",
    "CONFIG_SEV_GUEST",
    "CONFIG_TCG_CRB",
    "CONFIG_TCG_TPM",
};

const efi_paths = [_][]const u8{
    "EFI/BOOT/BOOTX64.EFI",
    "EFI/ubuntu/shimx64.efi",
    "EFI/ubuntu/grubx64.efi",
};

const Args = struct {
    output: []const u8 = default_output,
    work_dir: []const u8 = default_work_dir,
    provenance: ?[]const u8 = null,
    proxy: ?[]const u8 = null,
    gpg: []const u8 = "gpg",
    gpgv: []const u8 = "gpgv",
    tar: []const u8 = "tar",
    offline: bool = false,
};

const help_text =
    \\Usage: build_generalized_ubuntu2404_confidential [options]
    \\
    \\  --output <path>       Output standalone QCOW2
    \\  --work-dir <dir>      Download and extraction cache
    \\  --provenance <path>   Output provenance JSON (default: <output>.provenance.json)
    \\  --proxy <url>         Explicit HTTP/HTTPS proxy for native downloads
    \\  --gpg <path>          gpg executable used to dearmor the pinned key
    \\  --gpgv <path>         gpgv executable used to verify SHA256SUMS
    \\  --tar <path>          GNU tar executable used for sparse extraction
    \\  --offline             Require every downloaded input in the work-dir cache
    \\
    \\Preferred invocation: zig build generalized-ubuntu2404-confidential -- [options]
    \\
;

const ManifestContract = struct {
    kernel_release: []const u8,
    kernel_version: []const u8,
};

const BootEvidence = struct {
    path: []const u8,
    sha256: [64]u8,
    signer_certificate_sha256: [64]u8,
};

const ImageContract = struct {
    kernel_release: []const u8,
    boot: [efi_paths.len]BootEvidence,
};

fn nextValue(argv: []const []const u8, index: *usize) ![]const u8 {
    index.* += 1;
    if (index.* >= argv.len) return error.MissingValue;
    return argv[index.*];
}

fn parseArgs(argv: []const []const u8) !Args {
    var args = Args{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const arg = argv[index];
        if (std.mem.eql(u8, arg, "--output")) {
            args.output = try nextValue(argv, &index);
        } else if (std.mem.eql(u8, arg, "--work-dir")) {
            args.work_dir = try nextValue(argv, &index);
        } else if (std.mem.eql(u8, arg, "--provenance")) {
            args.provenance = try nextValue(argv, &index);
        } else if (std.mem.eql(u8, arg, "--proxy")) {
            args.proxy = try nextValue(argv, &index);
        } else if (std.mem.eql(u8, arg, "--gpg")) {
            args.gpg = try nextValue(argv, &index);
        } else if (std.mem.eql(u8, arg, "--gpgv")) {
            args.gpgv = try nextValue(argv, &index);
        } else if (std.mem.eql(u8, arg, "--tar")) {
            args.tar = try nextValue(argv, &index);
        } else if (std.mem.eql(u8, arg, "--offline")) {
            args.offline = true;
        } else if (std.mem.eql(u8, arg, "--help") or
            std.mem.eql(u8, arg, "-h"))
        {
            std.debug.print("{s}", .{help_text});
            std.process.exit(0);
        } else {
            return error.UnexpectedArgument;
        }
    }
    if (args.output.len == 0 or args.work_dir.len == 0 or
        (args.provenance != null and args.provenance.?.len == 0))
    {
        return error.EmptyPath;
    }
    return args;
}

fn joinedPath(allocator: Allocator, parent: []const u8, child: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ parent, child });
}

fn publicationUrl(allocator: Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ publication_base, name });
}

fn requireMetadata(
    io: Io,
    path: []const u8,
    expected_sha256: artifact_pipeline.Digest,
    max_size: u64,
) !artifact_pipeline.Metadata {
    const metadata = try artifact_pipeline.hashFile(io, path);
    if (metadata.size > max_size) return error.ArtifactTooLarge;
    if (!std.mem.eql(u8, &metadata.sha256, &expected_sha256))
        return error.ChecksumMismatch;
    return metadata;
}

fn acquireInput(
    allocator: Allocator,
    io: Io,
    downloader: artifact_pipeline.Downloader,
    work_dir: []const u8,
    name: []const u8,
    expected_text: []const u8,
    expected_size: ?u64,
    max_size: u64,
    offline: bool,
) !artifact_pipeline.Metadata {
    const expected = try artifact_pipeline.parseSha256(expected_text);
    const path = try joinedPath(allocator, work_dir, name);
    defer allocator.free(path);
    const metadata = if (offline)
        try requireMetadata(io, path, expected, max_size)
    else blk: {
        const url = try publicationUrl(allocator, name);
        defer allocator.free(url);
        break :blk (try artifact_pipeline.acquireVerified(
            allocator,
            io,
            .{
                .url = url,
                .destination_path = path,
                .expected_sha256 = expected,
                .max_size = max_size,
            },
            downloader,
        )).artifact;
    };
    if (expected_size) |size| {
        if (metadata.size != size) return error.UnexpectedArtifactSize;
    }
    return .{
        .path = try allocator.dupe(u8, path),
        .sha256 = metadata.sha256,
        .size = metadata.size,
    };
}

fn freeMetadataPath(allocator: Allocator, metadata: artifact_pipeline.Metadata) void {
    allocator.free(metadata.path);
}

fn packageName(line: []const u8) ?[]const u8 {
    const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return null;
    if (tab == 0 or tab + 1 == line.len or
        std.mem.indexOfScalarPos(u8, line, tab + 1, '\t') != null)
    {
        return null;
    }
    const raw = line[0..tab];
    return if (std.mem.indexOfScalar(u8, raw, ':')) |colon| raw[0..colon] else raw;
}

fn packageVersion(line: []const u8) ?[]const u8 {
    const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return null;
    if (tab == 0 or tab + 1 == line.len or
        std.mem.indexOfScalarPos(u8, line, tab + 1, '\t') != null)
    {
        return null;
    }
    return line[tab + 1 ..];
}

fn findPackageVersion(manifest: []const u8, expected: []const u8) ![]const u8 {
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, manifest, '\n');
    while (lines.next()) |line| {
        const name = packageName(line) orelse continue;
        if (!std.mem.eql(u8, name, expected)) continue;
        if (found != null) return error.DuplicateManifestPackage;
        found = packageVersion(line) orelse return error.InvalidManifestLine;
    }
    return found orelse error.RequiredPackageMissing;
}

fn findKernelPackage(manifest: []const u8) !struct {
    release: []const u8,
    version: []const u8,
} {
    const prefix = "linux-image-";
    const suffix = "-azure";
    var release_name: ?[]const u8 = null;
    var version: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, manifest, '\n');
    while (lines.next()) |line| {
        const name = packageName(line) orelse continue;
        if (!std.mem.startsWith(u8, name, prefix) or
            !std.mem.endsWith(u8, name, suffix) or
            std.mem.eql(u8, name, "linux-image-azure"))
        {
            continue;
        }
        if (release_name != null) return error.AmbiguousKernelPackage;
        release_name = name[prefix.len..];
        version = packageVersion(line) orelse return error.InvalidManifestLine;
    }
    return .{
        .release = release_name orelse return error.KernelPackageMissing,
        .version = version.?,
    };
}

fn kernelVersionAtLeast(release_name: []const u8, minimum_major: u32, minimum_minor: u32) bool {
    var fields = std.mem.splitScalar(u8, release_name, '.');
    const major = std.fmt.parseUnsigned(u32, fields.next() orelse return false, 10) catch
        return false;
    const minor = std.fmt.parseUnsigned(u32, fields.next() orelse return false, 10) catch
        return false;
    return major > minimum_major or
        (major == minimum_major and minor >= minimum_minor);
}

fn validateManifest(
    allocator: Allocator,
    manifest: []const u8,
) !ManifestContract {
    if (manifest.len == 0 or !std.mem.endsWith(u8, manifest, "\n"))
        return error.InvalidManifest;
    if (std.mem.indexOf(u8, manifest, ":arm64\t") != null)
        return error.ForeignArchitecturePackage;
    for (&required_manifest_packages) |name| {
        _ = try findPackageVersion(manifest, name);
    }
    const kernel = try findKernelPackage(manifest);
    if (!kernelVersionAtLeast(kernel.release, 5, 15))
        return error.UnsupportedKernelVersion;
    const modules_name = try std.fmt.allocPrint(
        allocator,
        "linux-modules-{s}",
        .{kernel.release},
    );
    defer allocator.free(modules_name);
    const modules_version = try findPackageVersion(manifest, modules_name);
    if (!std.mem.eql(u8, modules_version, kernel.version))
        return error.KernelPackageVersionMismatch;
    const image_meta_version = try findPackageVersion(manifest, "linux-image-azure");
    if (!std.mem.eql(u8, image_meta_version, kernel.version))
        return error.KernelPackageVersionMismatch;
    return .{
        .kernel_release = kernel.release,
        .kernel_version = kernel.version,
    };
}

fn requireSignedEntry(
    sums: []const u8,
    name: []const u8,
    expected_sha256: []const u8,
) !void {
    var matches: usize = 0;
    var lines = std.mem.splitScalar(u8, sums, '\n');
    while (lines.next()) |line| {
        if (line.len < 67) continue;
        if ((!std.mem.eql(u8, line[64..66], " *") and
            !std.mem.eql(u8, line[64..66], "  ")) or
            !std.mem.eql(u8, line[66..], name))
        {
            continue;
        }
        matches += 1;
        if (!std.ascii.eqlIgnoreCase(line[0..64], expected_sha256))
            return error.SignedDigestMismatch;
    }
    if (matches != 1) return error.SignedEntryMissingOrDuplicate;
}

fn runCommand(
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
    failure: anyerror,
) !struct { stdout: []u8, stderr: []u8 } {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(command_output_max_size),
        .stderr_limit = .limited(command_output_max_size),
    });
    errdefer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }
    switch (result.term) {
        .exited => |code| if (code != 0) return failure,
        else => return failure,
    }
    return .{ .stdout = result.stdout, .stderr = result.stderr };
}

fn hasValidSignatureStatus(status: []const u8) bool {
    var lines = std.mem.splitScalar(u8, status, '\n');
    var valid_count: usize = 0;
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "[GNUPG:] VALIDSIG ")) continue;
        const rest = line["[GNUPG:] VALIDSIG ".len..];
        const fingerprint = std.mem.sliceTo(rest, ' ');
        if (!std.mem.eql(u8, fingerprint, canonical_fingerprint)) return false;
        valid_count += 1;
    }
    return valid_count == 1;
}

fn verifyPublication(
    allocator: Allocator,
    io: Io,
    args: Args,
    sums_path: []const u8,
    signature_path: []const u8,
) !void {
    const key_digest = artifact_pipeline.sha256Bytes(canonical_key_armor);
    if (!std.mem.eql(u8, &key_digest, &canonical_key_armor_sha256))
        return error.CanonicalKeyPinMismatch;

    const gpg_home = try joinedPath(allocator, args.work_dir, "gnupg");
    defer allocator.free(gpg_home);
    try Dir.cwd().createDirPath(io, gpg_home);
    const armor_path = try joinedPath(allocator, gpg_home, "canonical.asc");
    defer allocator.free(armor_path);
    const keyring_path = try joinedPath(allocator, gpg_home, "canonical.gpg");
    defer allocator.free(keyring_path);
    try release_support.file.writeAtomic(io, armor_path, canonical_key_armor);
    Dir.cwd().deleteFile(io, keyring_path) catch {};

    const dearmor = try runCommand(allocator, io, &.{
        args.gpg,
        "--batch",
        "--no-options",
        "--homedir",
        gpg_home,
        "--yes",
        "--dearmor",
        "--output",
        keyring_path,
        armor_path,
    }, error.GpgDearmorFailed);
    defer allocator.free(dearmor.stdout);
    defer allocator.free(dearmor.stderr);

    const verification = try runCommand(allocator, io, &.{
        args.gpgv,
        "--homedir",
        gpg_home,
        "--status-fd=1",
        "--keyring",
        keyring_path,
        signature_path,
        sums_path,
    }, error.CanonicalSignatureInvalid);
    defer allocator.free(verification.stdout);
    defer allocator.free(verification.stderr);
    if (!hasValidSignatureStatus(verification.stdout))
        return error.CanonicalSignatureInvalid;
}

fn validateTarListing(listing: []const u8) !void {
    var lines = std.mem.splitScalar(u8, listing, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        count += 1;
        if (!std.mem.eql(u8, line, archive_member))
            return error.UnexpectedArchiveMember;
    }
    if (count != 1) return error.UnexpectedArchiveMemberCount;
}

fn extractSourceVhd(
    allocator: Allocator,
    io: Io,
    args: Args,
    archive_path: []const u8,
) ![]u8 {
    const listing = try runCommand(allocator, io, &.{
        args.tar,
        "--gzip",
        "--list",
        "--file",
        archive_path,
    }, error.TarListFailed);
    defer allocator.free(listing.stdout);
    defer allocator.free(listing.stderr);
    try validateTarListing(listing.stdout);

    const extract_dir = try joinedPath(allocator, args.work_dir, "extracted");
    defer allocator.free(extract_dir);
    Dir.cwd().deleteTree(io, extract_dir) catch {};
    try Dir.cwd().createDirPath(io, extract_dir);
    const extraction = try runCommand(allocator, io, &.{
        args.tar,
        "--gzip",
        "--extract",
        "--sparse",
        "--no-same-owner",
        "--no-same-permissions",
        "--file",
        archive_path,
        "--directory",
        extract_dir,
        "--",
        archive_member,
    }, error.TarExtractionFailed);
    defer allocator.free(extraction.stdout);
    defer allocator.free(extraction.stderr);

    const vhd_path = try joinedPath(allocator, extract_dir, archive_member);
    errdefer allocator.free(vhd_path);
    const stat = try Dir.cwd().statFile(io, vhd_path, .{ .follow_symlinks = false });
    if (stat.kind != .file or stat.nlink != 1 or stat.size != source_vhd_file_size)
        return error.InvalidExtractedVhd;
    return vhd_path;
}

fn partitionRegion(partition: miz.gpt.PartitionEntry) !miz.fat32.Region {
    if (partition.last_lba < partition.first_lba)
        return error.InvalidPartitionBounds;
    const sectors = std.math.add(
        u64,
        partition.last_lba - partition.first_lba,
        1,
    ) catch return error.InvalidPartitionBounds;
    return .{
        .offset = std.math.mul(
            u64,
            partition.first_lba,
            miz.gpt.sector_size,
        ) catch return error.InvalidPartitionBounds,
        .length = std.math.mul(
            u64,
            sectors,
            miz.gpt.sector_size,
        ) catch return error.InvalidPartitionBounds,
    };
}

fn findPartition(
    partitions: []const miz.gpt.PartitionEntry,
    type_guid: miz.guid.Guid,
) !miz.gpt.PartitionEntry {
    var found: ?miz.gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (!std.mem.eql(u8, &partition.partition_type_guid, &type_guid))
            continue;
        if (found != null) return error.AmbiguousPartition;
        found = partition;
    }
    return found orelse error.RequiredPartitionMissing;
}

fn readImageGpt(
    allocator: Allocator,
    io: Io,
    image: miz.Image,
    legacy_source: bool,
) !miz.gpt.VerifiedGpt {
    if (!legacy_source) {
        return miz.gpt.readVerifiedGpt(
            image,
            io,
            allocator,
            1024 * 1024,
        );
    }
    const primary = try miz.gpt.readGpt(image, io, allocator);
    defer allocator.free(primary.partitions);
    const legacy_sectors = std.math.add(
        u64,
        primary.header.backup_lba,
        1,
    ) catch return error.InvalidSourceGptGeometry;
    const legacy_size = std.math.mul(
        u64,
        legacy_sectors,
        miz.gpt.sector_size,
    ) catch return error.InvalidSourceGptGeometry;
    if (legacy_size != source_gpt_virtual_size or legacy_size >= image.virtual_size)
        return error.InvalidSourceGptGeometry;
    var legacy_view = image;
    legacy_view.virtual_size = legacy_size;
    return miz.gpt.readVerifiedGpt(
        legacy_view,
        io,
        allocator,
        1024 * 1024,
    );
}

fn imageReadAt(
    context: *const anyopaque,
    io: Io,
    buffer: []u8,
    offset: u64,
) anyerror!usize {
    const image: *const miz.Image = @ptrCast(@alignCast(context));
    return image.pread(io, buffer, offset);
}

fn requirePathAbsent(root: *const miz.ext4.Reader, io: Io, path: []const u8) !void {
    _ = root.statPath(io, path) catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    return error.BakedIdentityState;
}

fn requireEmptyDirectory(
    allocator: Allocator,
    root: *const miz.ext4.Reader,
    io: Io,
    path: []const u8,
) !void {
    const entries = root.listDir(io, allocator, path) catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    defer miz.ext4.freeDirEntries(allocator, entries);
    if (entries.len != 0) return error.BakedProvisioningState;
}

fn kernelOptionEnabled(config: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, config, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, name) or
            line.len != name.len + 2 or line[name.len] != '=')
        {
            continue;
        }
        return line[name.len + 1] == 'y' or line[name.len + 1] == 'm';
    }
    return false;
}

fn validateKernelConfig(config: []const u8) !void {
    for (&required_kernel_options) |option| {
        if (!kernelOptionEnabled(config, option))
            return error.RequiredKernelOptionMissing;
    }
}

fn validateGeneralizedRoot(
    allocator: Allocator,
    io: Io,
    image: *const miz.Image,
    root_partition: miz.gpt.PartitionEntry,
) !void {
    const region = try partitionRegion(root_partition);
    var root = try miz.ext4.openReadOnlySource(
        io,
        image.file,
        .{ .ctx = image, .read_at_fn = imageReadAt },
        allocator,
        .{ .offset = region.offset },
    );
    defer root.deinit();

    const os_release = try root.readFileAlloc(
        io,
        allocator,
        "usr/lib/os-release",
    );
    defer allocator.free(os_release);
    if (std.mem.indexOf(u8, os_release, "ID=ubuntu\n") == null or
        (std.mem.indexOf(u8, os_release, "VERSION_ID=\"24.04\"\n") == null and
            std.mem.indexOf(u8, os_release, "VERSION_ID=24.04\n") == null))
    {
        return error.UnexpectedOperatingSystem;
    }
    _ = try root.statPath(io, "usr/bin/cloud-init");
    if (root.statPath(io, "usr/sbin/waagent")) |_| {} else |first_error| {
        if (first_error != error.NotFound) return first_error;
        _ = try root.statPath(io, "usr/bin/waagent");
    }

    const machine_id = try root.statPath(io, "etc/machine-id");
    if (machine_id.kind != .file or machine_id.size != 0)
        return error.BakedIdentityState;
    for (&[_][]const u8{
        "var/lib/dbus/machine-id",
        "var/lib/cloud/instance",
        "var/lib/azagent/provisioned",
        "etc/ssh/ssh_host_rsa_key",
        "etc/ssh/ssh_host_rsa_key.pub",
        "etc/ssh/ssh_host_ecdsa_key",
        "etc/ssh/ssh_host_ecdsa_key.pub",
        "etc/ssh/ssh_host_ed25519_key",
        "etc/ssh/ssh_host_ed25519_key.pub",
        "etc/ssh/ssh_host_dsa_key",
        "etc/ssh/ssh_host_dsa_key.pub",
        "root/.ssh/authorized_keys",
    }) |path| try requirePathAbsent(&root, io, path);
    try requireEmptyDirectory(allocator, &root, io, "var/lib/cloud/instances");
    try requireEmptyDirectory(allocator, &root, io, "var/lib/waagent");
}

fn validateBootPartition(
    allocator: Allocator,
    io: Io,
    image: *const miz.Image,
    boot_partition: miz.gpt.PartitionEntry,
    manifest_contract: ManifestContract,
) !void {
    const region = try partitionRegion(boot_partition);
    var boot = try miz.ext4.openReadOnlySource(
        io,
        image.file,
        .{ .ctx = image, .read_at_fn = imageReadAt },
        allocator,
        .{ .offset = region.offset },
    );
    defer boot.deinit();
    const boot_config_path = try std.fmt.allocPrint(
        allocator,
        "config-{s}",
        .{manifest_contract.kernel_release},
    );
    defer allocator.free(boot_config_path);
    const config = try boot.readFileAlloc(io, allocator, boot_config_path);
    defer allocator.free(config);
    try validateKernelConfig(config);
    for (&[_][]const u8{ "vmlinuz-", "initrd.img-" }) |prefix| {
        const path = try std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ prefix, manifest_contract.kernel_release },
        );
        defer allocator.free(path);
        const stat = try boot.statPath(io, path);
        if (stat.kind != .file or stat.size == 0)
            return error.RequiredBootArtifactMissing;
    }
}

fn validateSecureBootChain(
    allocator: Allocator,
    io: Io,
    image: *miz.Image,
    esp_partition: miz.gpt.PartitionEntry,
) ![efi_paths.len]BootEvidence {
    const region = try partitionRegion(esp_partition);
    var filesystem = try miz.fat32.open(image, io, region);
    var evidence: [efi_paths.len]BootEvidence = undefined;
    for (&efi_paths, 0..) |path, index| {
        const bytes = try filesystem.readFileAlloc(io, allocator, path);
        defer allocator.free(bytes);
        if (bytes.len == 0 or bytes.len > efi_binary_max_size)
            return error.InvalidEfiBinarySize;
        const signer = miz.authenticode.verifyRsaSha256(bytes) catch |err| {
            std.debug.print(
                "Secure Boot signature validation failed for {s}: {s}\n",
                .{ path, @errorName(err) },
            );
            return err;
        };
        if (signer.machine != pe_machine_x86_64)
            return error.EfiArchitectureMismatch;
        evidence[index] = .{
            .path = path,
            .sha256 = artifact_pipeline.formatSha256(
                artifact_pipeline.sha256Bytes(bytes),
            ),
            .signer_certificate_sha256 = artifact_pipeline.formatSha256(
                artifact_pipeline.sha256Bytes(signer.certificate_der),
            ),
        };
    }
    return evidence;
}

fn validateImageContract(
    allocator: Allocator,
    io: Io,
    image: *miz.Image,
    manifest_contract: ManifestContract,
    legacy_source_gpt: bool,
) !ImageContract {
    var gpt = try readImageGpt(
        allocator,
        io,
        image.*,
        legacy_source_gpt,
    );
    defer gpt.deinit(allocator);
    const esp = try findPartition(gpt.partitions, miz.guid.esp);
    const root = try findPartition(
        gpt.partitions,
        miz.guid.linux_filesystem_data,
    );
    const boot = try findPartition(gpt.partitions, miz.guid.linux_xbootldr);
    if (root.table_index != 0) {
        return error.UnexpectedRootPartition;
    }
    try validateGeneralizedRoot(
        allocator,
        io,
        image,
        root,
    );
    try validateBootPartition(
        allocator,
        io,
        image,
        boot,
        manifest_contract,
    );
    return .{
        .kernel_release = manifest_contract.kernel_release,
        .boot = try validateSecureBootChain(allocator, io, image, esp),
    };
}

fn validateSourceVhd(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    metadata: artifact_pipeline.Metadata,
    manifest_contract: ManifestContract,
) !ImageContract {
    var image = try miz.Image.openPathReadOnlyStandalone(io, path);
    defer image.close(io);
    if (image.format != .vhd or image.dynamic != null)
        return error.SourceNotFixedVhd;
    const info = try image.info(io);
    if (metadata.size != source_vhd_file_size or
        info.file_size != source_vhd_file_size or
        image.virtual_size != source_vhd_virtual_size)
    {
        return error.UnexpectedSourceVhdGeometry;
    }
    var diagnostic = release_support.Diagnostic{};
    confidential.validateVhdSize(
        image.virtual_size,
        image.virtual_size,
        info.file_size,
        &diagnostic,
    ) catch |err| {
        std.debug.print("error: {s}\n", .{diagnostic.message()});
        return err;
    };
    return validateImageContract(
        allocator,
        io,
        &image,
        manifest_contract,
        true,
    );
}

fn publishQcow2(
    allocator: Allocator,
    io: Io,
    source_path: []const u8,
    output_path: []const u8,
) !miz.gpt.RelocationResult {
    const stage_path = try std.fmt.allocPrint(
        allocator,
        "{s}.miz-stage",
        .{output_path},
    );
    defer allocator.free(stage_path);
    Dir.cwd().deleteFile(io, stage_path) catch {};
    errdefer Dir.cwd().deleteFile(io, stage_path) catch {};

    var source = try miz.Image.openPathReadOnlyStandalone(io, source_path);
    defer source.close(io);
    var output = try miz.Image.createExclusive(
        io,
        stage_path,
        .qcow2,
        source.virtual_size,
        .{},
    );
    var output_open = true;
    errdefer if (output_open) output.close(io);
    _ = try miz.copyAll(io, source, &output, allocator);
    var legacy_gpt = try readImageGpt(allocator, io, output, true);
    defer legacy_gpt.deinit(allocator);
    const relocation = try miz.gpt.relocateBackup(
        &output,
        io,
        allocator,
        legacy_gpt,
    );
    if (!relocation.was_relocated or
        relocation.new_backup_lba != output.virtual_size / miz.gpt.sector_size - 1)
    {
        return error.GptNormalizationFailed;
    }
    try output.file.sync(io);
    output.close(io);
    output_open = false;

    var staged = try miz.Image.openPathReadOnlyStandalone(io, stage_path);
    const check = staged.check(io) catch |err| {
        staged.close(io);
        return err;
    };
    staged.close(io);
    if (!check.ok) return error.FinalImageInvalid;
    try Dir.cwd().rename(stage_path, Dir.cwd(), output_path, io);
    return relocation;
}

fn sameBootEvidence(
    before: [efi_paths.len]BootEvidence,
    after: [efi_paths.len]BootEvidence,
) bool {
    for (before, after) |expected, actual| {
        if (!std.mem.eql(u8, expected.path, actual.path) or
            !std.mem.eql(u8, &expected.sha256, &actual.sha256) or
            !std.mem.eql(
                u8,
                &expected.signer_certificate_sha256,
                &actual.signer_certificate_sha256,
            ))
        {
            return false;
        }
    }
    return true;
}

fn writeProvenance(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    archive: artifact_pipeline.Metadata,
    sums: artifact_pipeline.Metadata,
    signature: artifact_pipeline.Metadata,
    manifest: artifact_pipeline.Metadata,
    source_vhd: artifact_pipeline.Metadata,
    output: artifact_pipeline.Metadata,
    contract: ImageContract,
    kernel_version: []const u8,
    relocation: miz.gpt.RelocationResult,
) !void {
    const archive_hex = artifact_pipeline.formatSha256(archive.sha256);
    const sums_hex = artifact_pipeline.formatSha256(sums.sha256);
    const signature_hex = artifact_pipeline.formatSha256(signature.sha256);
    const manifest_hex = artifact_pipeline.formatSha256(manifest.sha256);
    const vhd_hex = artifact_pipeline.formatSha256(source_vhd.sha256);
    const output_hex = artifact_pipeline.formatSha256(output.sha256);
    const boot_evidence = [_]struct {
        path: []const u8,
        sha256: []const u8,
        signer_certificate_sha256: []const u8,
    }{
        .{
            .path = contract.boot[0].path,
            .sha256 = &contract.boot[0].sha256,
            .signer_certificate_sha256 = &contract.boot[0].signer_certificate_sha256,
        },
        .{
            .path = contract.boot[1].path,
            .sha256 = &contract.boot[1].sha256,
            .signer_certificate_sha256 = &contract.boot[1].signer_certificate_sha256,
        },
        .{
            .path = contract.boot[2].path,
            .sha256 = &contract.boot[2].sha256,
            .signer_certificate_sha256 = &contract.boot[2].signer_certificate_sha256,
        },
    };
    const body = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = 1,
        .type = "miz-ubuntu2404-confidential-build-provenance",
        .release = "24.04",
        .architecture = "x86_64",
        .tee = "AMD SEV-SNP",
        .publication = .{
            .id = "release-" ++ publication,
            .base_url = publication_base ++ "/",
            .canonical_key_fingerprint = canonical_fingerprint,
            .sha256sums_signature_verified = true,
        },
        .inputs = .{
            .archive = .{
                .name = archive_name,
                .sha256 = archive_hex[0..],
                .size = archive.size,
            },
            .manifest = .{
                .name = manifest_name,
                .sha256 = manifest_hex[0..],
                .size = manifest.size,
            },
            .sha256sums = .{
                .name = sums_name,
                .sha256 = sums_hex[0..],
                .size = sums.size,
            },
            .sha256sums_signature = .{
                .name = signature_name,
                .sha256 = signature_hex[0..],
                .size = signature.size,
            },
        },
        .source_vhd = .{
            .member = archive_member,
            .sha256 = vhd_hex[0..],
            .file_size = source_vhd.size,
            .virtual_size = source_vhd_virtual_size,
            .format = "fixed-vhd",
            .legacy_gpt_virtual_size = source_gpt_virtual_size,
        },
        .guest_contract = .{
            .kernel_release = contract.kernel_release,
            .kernel_package_version = kernel_version,
            .secure_boot_chain = boot_evidence,
            .generalized = true,
        },
        .candidate = .{
            .path = output.path,
            .sha256 = output_hex[0..],
            .size = output.size,
            .virtual_size = source_vhd_virtual_size,
            .format = "standalone-qcow2",
            .gpt_normalization = .{
                .old_backup_lba = relocation.old_backup_lba,
                .new_backup_lba = relocation.new_backup_lba,
                .old_last_usable_lba = relocation.old_last_usable_lba,
                .new_last_usable_lba = relocation.new_last_usable_lba,
            },
        },
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(body);
    const document = try std.mem.concat(allocator, u8, &.{ body, "\n" });
    defer allocator.free(document);
    try release_support.file.writeAtomic(io, path, document);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = parseArgs(argv[1..]) catch |err| {
        std.debug.print("error: {s}\n{s}", .{ @errorName(err), help_text });
        std.process.exit(1);
    };
    try Dir.cwd().createDirPath(io, args.work_dir);
    if (std.fs.path.dirname(args.output)) |parent|
        try Dir.cwd().createDirPath(io, parent);

    var native_downloader = if (args.proxy) |proxy|
        try artifact_pipeline.NativeHttpsDownloader.initProxied(
            allocator,
            io,
            proxy,
        )
    else
        artifact_pipeline.NativeHttpsDownloader.init(allocator, io);
    defer native_downloader.deinit();
    const downloader = native_downloader.downloader();

    const archive = try acquireInput(
        allocator,
        io,
        downloader,
        args.work_dir,
        archive_name,
        archive_sha256,
        archive_size,
        source_archive_max_size,
        args.offline,
    );
    defer freeMetadataPath(allocator, archive);
    const sums = try acquireInput(
        allocator,
        io,
        downloader,
        args.work_dir,
        sums_name,
        sums_sha256,
        null,
        metadata_max_size,
        args.offline,
    );
    defer freeMetadataPath(allocator, sums);
    const signature = try acquireInput(
        allocator,
        io,
        downloader,
        args.work_dir,
        signature_name,
        signature_sha256,
        null,
        metadata_max_size,
        args.offline,
    );
    defer freeMetadataPath(allocator, signature);
    const manifest = try acquireInput(
        allocator,
        io,
        downloader,
        args.work_dir,
        manifest_name,
        manifest_sha256,
        null,
        metadata_max_size,
        args.offline,
    );
    defer freeMetadataPath(allocator, manifest);

    try verifyPublication(
        allocator,
        io,
        args,
        sums.path,
        signature.path,
    );
    const sums_bytes = try Dir.cwd().readFileAlloc(
        io,
        sums.path,
        allocator,
        .limited(metadata_max_size),
    );
    defer allocator.free(sums_bytes);
    const observed_sums_digest = artifact_pipeline.sha256Bytes(sums_bytes);
    if (!std.mem.eql(u8, &observed_sums_digest, &sums.sha256))
        return error.InputChanged;
    try requireSignedEntry(sums_bytes, archive_name, archive_sha256);
    try requireSignedEntry(sums_bytes, manifest_name, manifest_sha256);

    const manifest_bytes = try Dir.cwd().readFileAlloc(
        io,
        manifest.path,
        allocator,
        .limited(metadata_max_size),
    );
    defer allocator.free(manifest_bytes);
    const observed_manifest_digest = artifact_pipeline.sha256Bytes(manifest_bytes);
    if (!std.mem.eql(u8, &observed_manifest_digest, &manifest.sha256))
        return error.InputChanged;
    const manifest_contract = try validateManifest(allocator, manifest_bytes);

    const vhd_path = try extractSourceVhd(
        allocator,
        io,
        args,
        archive.path,
    );
    defer allocator.free(vhd_path);
    const archive_after_extract = try requireMetadata(
        io,
        archive.path,
        archive.sha256,
        source_archive_max_size,
    );
    if (archive_after_extract.size != archive.size)
        return error.InputChanged;
    const vhd_metadata = try artifact_pipeline.hashFile(io, vhd_path);
    const source_contract = try validateSourceVhd(
        allocator,
        io,
        vhd_path,
        vhd_metadata,
        manifest_contract,
    );

    const relocation = try publishQcow2(
        allocator,
        io,
        vhd_path,
        args.output,
    );
    var candidate = try miz.Image.openPathReadOnlyStandalone(io, args.output);
    if (candidate.format != .qcow2 or
        candidate.virtual_size != source_vhd_virtual_size)
    {
        candidate.close(io);
        return error.InvalidFinalQcow2;
    }
    const candidate_contract = validateImageContract(
        allocator,
        io,
        &candidate,
        manifest_contract,
        false,
    ) catch |err| {
        candidate.close(io);
        return err;
    };
    candidate.close(io);
    if (!sameBootEvidence(source_contract.boot, candidate_contract.boot))
        return error.SecureBootChainChanged;
    const output_metadata = try artifact_pipeline.hashFile(io, args.output);

    const provenance_path = if (args.provenance) |path|
        try allocator.dupe(u8, path)
    else
        try std.fmt.allocPrint(allocator, "{s}.provenance.json", .{args.output});
    defer allocator.free(provenance_path);
    if (std.fs.path.dirname(provenance_path)) |parent|
        try Dir.cwd().createDirPath(io, parent);
    try writeProvenance(
        allocator,
        io,
        provenance_path,
        archive,
        sums,
        signature,
        manifest,
        vhd_metadata,
        output_metadata,
        candidate_contract,
        manifest_contract.kernel_version,
        relocation,
    );

    const output_hex = artifact_pipeline.formatSha256(output_metadata.sha256);
    std.debug.print(
        "built {s}\nsha256={s}\nprovenance={s}\n",
        .{ args.output, &output_hex, provenance_path },
    );
}

test "source profile pins one immutable signed Azure VHD publication" {
    _ = try artifact_pipeline.parseSha256(archive_sha256);
    _ = try artifact_pipeline.parseSha256(manifest_sha256);
    _ = try artifact_pipeline.parseSha256(sums_sha256);
    _ = try artifact_pipeline.parseSha256(signature_sha256);
    try std.testing.expect(std.mem.indexOf(u8, publication_base, "release-") != null);
    try std.testing.expect(std.mem.endsWith(u8, archive_name, "-azure.vhd.tar.gz"));
    try std.testing.expect(source_vhd_virtual_size % (1024 * 1024) == 0);
    try std.testing.expect(source_vhd_virtual_size < confidential.maximum_vhd_current_size);
    try std.testing.expect(source_gpt_virtual_size < source_vhd_virtual_size);
}

const valid_manifest =
    "cloud-guest-utils\t0.33-1\n" ++
    "cloud-init\t26.1\n" ++
    "grub-efi-amd64-signed\t1.202\n" ++
    "libtss2-esys-3.0.2-0t64:amd64\t4.0.1\n" ++
    "linux-azure\t6.17.0-1022.22\n" ++
    "linux-base-sgx\t4.5\n" ++
    "linux-image-6.17.0-1022-azure\t6.17.0-1022.22\n" ++
    "linux-image-azure\t6.17.0-1022.22\n" ++
    "linux-modules-6.17.0-1022-azure\t6.17.0-1022.22\n" ++
    "shim-signed\t1.58\n" ++
    "tpm-udev\t0.6\n" ++
    "walinuxagent\t2.15\n";

test "manifest requires the x86 Azure confidential guest closure" {
    const contract = try validateManifest(std.testing.allocator, valid_manifest);
    try std.testing.expectEqualStrings("6.17.0-1022-azure", contract.kernel_release);
    try std.testing.expectEqualStrings("6.17.0-1022.22", contract.kernel_version);
    try std.testing.expectError(
        error.ForeignArchitecturePackage,
        validateManifest(
            std.testing.allocator,
            valid_manifest ++ "foreign:arm64\t1\n",
        ),
    );
    try std.testing.expectError(
        error.RequiredPackageMissing,
        validateManifest(
            std.testing.allocator,
            valid_manifest["cloud-guest-utils\t0.33-1\n".len..],
        ),
    );
}

test "kernel baseline rejects releases older than Ubuntu confidential support" {
    try std.testing.expect(kernelVersionAtLeast("5.15.0-1001-azure", 5, 15));
    try std.testing.expect(kernelVersionAtLeast("6.8.0-1001-azure", 5, 15));
    try std.testing.expect(!kernelVersionAtLeast("5.14.0-1001-azure", 5, 15));
    try std.testing.expect(!kernelVersionAtLeast("invalid", 5, 15));
}

test "signed checksum entry must be unique and exact" {
    const good = archive_sha256 ++ " *" ++ archive_name ++ "\n";
    try requireSignedEntry(good, archive_name, archive_sha256);
    try std.testing.expectError(
        error.SignedDigestMismatch,
        requireSignedEntry("0" ** 64 ++ " *" ++ archive_name ++ "\n", archive_name, archive_sha256),
    );
    try std.testing.expectError(
        error.SignedEntryMissingOrDuplicate,
        requireSignedEntry(good ++ good, archive_name, archive_sha256),
    );
}

test "sparse archive must contain exactly the expected VHD member" {
    try validateTarListing(archive_member ++ "\n");
    try std.testing.expectError(
        error.UnexpectedArchiveMember,
        validateTarListing("../escape.vhd\n"),
    );
    try std.testing.expectError(
        error.UnexpectedArchiveMemberCount,
        validateTarListing(""),
    );
}

test "gpg status binds the signature to the pinned Canonical fingerprint" {
    try std.testing.expect(hasValidSignatureStatus(
        "[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG " ++ canonical_fingerprint ++ " 2026 0 4 0 1 10 00 " ++ canonical_fingerprint ++ "\n",
    ));
    try std.testing.expect(!hasValidSignatureStatus(
        "[GNUPG:] VALIDSIG 0000000000000000000000000000000000000000 2026\n",
    ));
    try std.testing.expect(!hasValidSignatureStatus(
        "[GNUPG:] VALIDSIG " ++ canonical_fingerprint ++ " 2026\n" ++
            "[GNUPG:] VALIDSIG " ++ canonical_fingerprint ++ " 2026\n",
    ));
}

test "kernel config requires Hyper-V TPM Secure Boot and SEV-SNP support" {
    const config =
        "CONFIG_AMD_MEM_ENCRYPT=y\n" ++
        "CONFIG_EFI=y\n" ++
        "CONFIG_EFI_STUB=y\n" ++
        "CONFIG_HYPERV=y\n" ++
        "CONFIG_HYPERV_BALLOON=m\n" ++
        "CONFIG_HYPERV_NET=m\n" ++
        "CONFIG_HYPERV_STORAGE=m\n" ++
        "CONFIG_HYPERV_UTILS=m\n" ++
        "CONFIG_SECURITY_LOCKDOWN_LSM=y\n" ++
        "CONFIG_SEV_GUEST=m\n" ++
        "CONFIG_TCG_CRB=m\n" ++
        "CONFIG_TCG_TPM=y\n";
    try validateKernelConfig(config);
    try std.testing.expectError(
        error.RequiredKernelOptionMissing,
        validateKernelConfig(config["CONFIG_AMD_MEM_ENCRYPT=y\n".len..]),
    );
}

test "arguments keep the source immutable and permit operational overrides" {
    const defaults = try parseArgs(&.{});
    try std.testing.expectEqualStrings(default_output, defaults.output);
    try std.testing.expectEqualStrings(default_work_dir, defaults.work_dir);
    const args = try parseArgs(&.{
        "--output",     "/d/out.qcow2",
        "--work-dir",   "/d/cache",
        "--provenance", "/d/out.json",
        "--proxy",      "http://127.0.0.1:3128",
        "--gpg",        "/usr/bin/gpg",
        "--gpgv",       "/usr/bin/gpgv",
        "--tar",        "/usr/bin/tar",
        "--offline",
    });
    try std.testing.expectEqualStrings("/d/out.qcow2", args.output);
    try std.testing.expectEqualStrings("/d/cache", args.work_dir);
    try std.testing.expect(args.offline);
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{"--source"}));
    try std.testing.expectError(error.MissingValue, parseArgs(&.{"--output"}));
}

test {
    std.testing.refAllDecls(@This());
}
