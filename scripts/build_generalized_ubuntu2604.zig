//! Build a generalized Ubuntu 26.04 Gen2 QCOW2 image from Canonical's
//! immutable 20260731 cloud-image publication.
//!
//! The official cloud disk is the authoritative filesystem/package input.
//! Its detached signature, signer fingerprint, checksum document, image, and
//! package manifest are all pinned. A native offline-root transaction then
//! switches the guest to the immutable Ubuntu snapshot, installs the Azure
//! kernel/agent closure, writes an exact dpkg inventory, and generalizes the
//! machine. The UKI is assembled and signed on the host so private signing
//! material is never copied into the guest disk.

const std = @import("std");
const vmiz = @import("vmiz");
const uki_signing = @import("uki_signing.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const artifact_pipeline = vmiz.artifact_pipeline;
const offline_root = vmiz.offline_root;
const package_family = vmiz.package_family;
const guid = vmiz.guid;
const ImageFormat = vmiz.Format;

const release = "20260731";
const release_base = "https://cloud-images.ubuntu.com/releases/26.04/release-" ++ release;
const snapshot_base = "https://snapshot.ubuntu.com/ubuntu/20260731T000000Z";
const canonical_fingerprint = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
const canonical_fingerprint_lower = "d2eb44626fddc30b513d5bb71a5d6c4c7db87c81";
const canonical_fingerprint_bytes = [_]u8{
    0xd2, 0xeb, 0x44, 0x62, 0x6f, 0xdd, 0xc3, 0x0b, 0x51, 0x3d,
    0x5b, 0xb7, 0x1a, 0x5d, 0x6c, 0x4c, 0x7d, 0xb8, 0x7c, 0x81,
};
const canonical_key_armor = @embedFile("fixtures/canonical-ubuntu-cloud-image-key.asc");
const canonical_key_armor_sha256 = [_]u8{
    0xe5, 0x81, 0xb3, 0x9f, 0xac, 0x6b, 0xfc, 0x19, 0x9e, 0x92, 0x17, 0x88, 0xc3, 0xc0, 0x7a, 0xc5,
    0x40, 0x6f, 0xe8, 0x8d, 0xb4, 0x87, 0xc7, 0xbd, 0xcf, 0x1e, 0x1d, 0x2f, 0x78, 0xfb, 0xcf, 0x05,
};
const sums_sha256 = "d562d59dac70f68d67d00e994db5cd89e49e9d93f7f80b4cb868a5eeb057ec36";
const sums_signature_sha256 = "2bf5fae8be0c79cc30c5c10223f1d4790b6ef541240896bfe48c7ac57c3404ed";
const default_virtual_size: u64 = 5 * 1024 * 1024 * 1024;
const source_max_size: u64 = 2 * 1024 * 1024 * 1024;
const manifest_max_size: u64 = 256 * 1024;
const sums_max_size: u64 = 64 * 1024;
const signature_max_size: u64 = 16 * 1024;
const public_key_max_size: usize = 4 * 1024;

const Architecture = enum {
    x86_64,
    aarch64,

    fn parse(value: []const u8) ?Architecture {
        if (std.mem.eql(u8, value, "x86_64") or std.mem.eql(u8, value, "amd64")) return .x86_64;
        if (std.mem.eql(u8, value, "aarch64") or std.mem.eql(u8, value, "arm64")) return .aarch64;
        return null;
    }
};

fn validateFinalQcow2(io: Io, path: []const u8, expected_size: u64) !void {
    var image = try vmiz.Image.openPathReadOnlyStandalone(io, path);
    defer image.close(io);
    if (image.format != .qcow2) return error.InvalidFinalQcow2;
    if (image.virtual_size != expected_size) return error.UnexpectedVirtualSize;
    const check = try image.check(io);
    if (!check.ok) return error.InvalidFinalQcow2;
}

fn finalizeCompressedQcow2(
    allocator: Allocator,
    io: Io,
    mutable: []const u8,
    output: []const u8,
) !void {
    // Emit the standalone zstd-compressed release artifact natively. vmiz
    // reads the mutable qcow2's guest bytes and re-encodes them into
    // compressed qcow2 v3 clusters, so the Ubuntu release path no longer
    // shells out to qemu-img/qemu-utils.
    const staged_output = try std.fmt.allocPrint(
        allocator,
        "{s}.vmiz-finalize-stage",
        .{output},
    );
    defer allocator.free(staged_output);
    Dir.cwd().deleteFile(io, staged_output) catch {};
    errdefer Dir.cwd().deleteFile(io, staged_output) catch {};

    var source = try vmiz.Image.openPathReadOnlyStandalone(io, mutable);
    defer source.close(io);
    if (source.format != .qcow2) return error.InvalidFinalQcow2;
    const expected_size = source.virtual_size;
    const source_ctx = vmiz.qcow2.Qcow2SourceContext{
        .file = source.file,
        .info = &source.qcow2.?,
    };

    const staged_file = try Dir.cwd().createFile(io, staged_output, .{ .read = true, .truncate = true });
    {
        errdefer staged_file.close(io);
        _ = try vmiz.qcow2.writeStandaloneCompressed(
            allocator,
            io,
            staged_file,
            expected_size,
            source_ctx.reader(),
            .{},
        );
    }
    staged_file.close(io);

    try validateFinalQcow2(io, staged_output, expected_size);
    try Dir.cwd().rename(staged_output, Dir.cwd(), output, io);
}

const Profile = struct {
    architecture: Architecture,
    ubuntu_architecture: []const u8,
    source_name: []const u8,
    source_sha256: []const u8,
    manifest_name: []const u8,
    manifest_sha256: []const u8,
    output: []const u8,
    work_dir: []const u8,
    efi_fallback: []const u8,
    serial_console: []const u8,
    pe_machine: u16,
    root_partition_table_index: u32,
    root_partition_type_guid: guid.Guid,
};

const profiles = [_]Profile{
    .{
        .architecture = .x86_64,
        .ubuntu_architecture = "amd64",
        .source_name = "ubuntu-26.04-server-cloudimg-amd64.img",
        .source_sha256 = "9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05",
        .manifest_name = "ubuntu-26.04-server-cloudimg-amd64.manifest",
        .manifest_sha256 = "05129d9e221665e0009b7c3a4e62b30040c6b4bf5368d622ea44141c06921514",
        .output = "Ubuntu-26.04-x86_64.qcow2",
        .work_dir = ".scratch/ubuntu2604-x86_64",
        .efi_fallback = "BOOTX64.EFI",
        .serial_console = "console=ttyS0,115200n8",
        .pe_machine = 0x8664,
        .root_partition_table_index = 0,
        .root_partition_type_guid = guid.linux_root_x86_64,
    },
    .{
        .architecture = .aarch64,
        .ubuntu_architecture = "arm64",
        .source_name = "ubuntu-26.04-server-cloudimg-arm64.img",
        .source_sha256 = "3e113fdd41f39e13729375173bb2ae793f87dc6db4294e5251ff2476971788ba",
        .manifest_name = "ubuntu-26.04-server-cloudimg-arm64.manifest",
        .manifest_sha256 = "2889120db0432e8029f8f01622efb40ce964e434ba2c81e98937ad1e2616e4f5",
        .output = "Ubuntu-26.04-aarch64.qcow2",
        .work_dir = ".scratch/ubuntu2604-aarch64",
        .efi_fallback = "BOOTAA64.EFI",
        .serial_console = "console=ttyAMA0,115200n8",
        .pe_machine = 0xaa64,
        .root_partition_table_index = 0,
        .root_partition_type_guid = guid.linux_root_aarch64,
    },
};

const required_manifest_packages = [_][]const u8{
    "cloud-init",
    "cloud-guest-utils",
    "openssh-server",
    "sudo",
    "systemd",
    "netplan.io",
};

const debz_packages = [_][]const u8{ "linux-azure", "walinuxagent" };

const Args = struct {
    architecture: ?Architecture = null,
    source: ?[]const u8 = null,
    output: ?[]const u8 = null,
    work_dir: ?[]const u8 = null,
    provenance_dir: ?[]const u8 = null,
    size: u64 = default_virtual_size,
    signing_certificate: ?[]const u8 = null,
    signing_certificate_sha256: ?[]const u8 = null,
    signing_key: ?[]const u8 = null,
    signing_command: ?[]const u8 = null,
    signing_command_arg: ?[]const u8 = null,
    preflight_only: bool = false,
};

const help =
    \\Usage: zig build generalized-ubuntu2604 -Dubuntu2604-arch=<x86_64|aarch64> -- [options]
    \\  --source <path>                         verified local Canonical .img
    \\  --output <path>                         output QCOW2
    \\  --work-dir <path>                       persistent download/work cache
    \\  --provenance-dir <path>                 release provenance sidecars
    \\  --size <size>                           virtual size (default 5G)
    \\  --uki-signing-certificate <path>        Secure Boot certificate
    \\  --uki-signing-certificate-sha256 <hex>  DER certificate SHA-256
    \\  --uki-signing-key <path>                local signing key
    \\  --uki-sign-command <absolute-path>       external production signer
    \\  --uki-sign-command-arg <argument>        external signer argument
    \\  --preflight-only                        verify pins/tools without building
    \\
;

fn profileFor(architecture: Architecture) *const Profile {
    for (&profiles) |*profile| if (profile.architecture == architecture) return profile;
    unreachable;
}

fn packageFamilyRequest(
    operation: package_family.Operation,
    profile: *const Profile,
    package: []const u8,
    root_stage: []const u8,
    published_root: []const u8,
    source_config_path: []const u8,
    keyring_path: []const u8,
    cache_path: []const u8,
    state_path: []const u8,
    lock_path: []const u8,
) package_family.Request {
    return .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = operation,
        .packages = &.{package},
        .inputs = .{
            .root_stage = root_stage,
            .published_root = published_root,
            .architecture = switch (profile.architecture) {
                .x86_64 => .amd64,
                .aarch64 => .arm64,
            },
            .source_paths = &.{},
            .keyring_paths = &.{keyring_path},
            .config_paths = &.{source_config_path},
            .cache_path = cache_path,
            .state_path = state_path,
            .lock_input_path = if (operation == .resolve_lock) null else lock_path,
            .lock_output_path = if (operation == .resolve_lock) lock_path else null,
            .cache_mode = .online,
            .repository_policy = .strict_priority,
            .recommends = false,
            .allow_downgrade = false,
            .conffile = .keep_existing,
            .installed_baseline = .require_locked,
            .deadline_ms = 30 * 60 * 1000,
        },
    };
}

fn parseArgs(argv: []const []const u8) !Args {
    var args = Args{};
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.architecture = Architecture.parse(argv[i]) orelse return error.InvalidArchitecture;
        } else if (std.mem.eql(u8, arg, "--source")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.source = argv[i];
        } else if (std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.output = argv[i];
        } else if (std.mem.eql(u8, arg, "--work-dir")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.work_dir = argv[i];
        } else if (std.mem.eql(u8, arg, "--provenance-dir")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.provenance_dir = argv[i];
        } else if (std.mem.eql(u8, arg, "--size")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.size = try vmiz.parseSize(argv[i]);
        } else if (std.mem.eql(u8, arg, "--uki-signing-certificate")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.signing_certificate = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-signing-certificate-sha256")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.signing_certificate_sha256 = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-signing-key")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.signing_key = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-sign-command")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.signing_command = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-sign-command-arg")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.signing_command_arg = argv[i];
        } else if (std.mem.eql(u8, arg, "--preflight-only")) {
            args.preflight_only = true;
        } else if (std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{help});
            std.process.exit(0);
        } else return error.UnknownArgument;
    }

    if (args.size < default_virtual_size) return error.ImageTooSmall;
    return args;
}

fn signingConfig(args: Args) !uki_signing.Config {
    const certificate = args.signing_certificate orelse return error.SigningConfigurationRequired;
    const certificate_sha256 = args.signing_certificate_sha256 orelse return error.SigningConfigurationRequired;
    if ((args.signing_key == null) == (args.signing_command == null)) return error.SigningModeRequired;
    if (args.signing_command == null and args.signing_command_arg != null) return error.SigningCommandRequired;
    const mode: uki_signing.Mode = if (args.signing_key) |key|
        .{ .local_key = .{ .private_key_path = key } }
    else blk: {
        const command = args.signing_command.?;
        if (!std.fs.path.isAbsolute(command)) return error.SigningCommandMustBeAbsolute;
        break :blk .{ .external_command = .{
            .executable_path = command,
            .argument = args.signing_command_arg,
        } };
    };
    return .{
        .certificate_path = certificate,
        .expected_certificate_sha256 = try uki_signing.parseFingerprint(certificate_sha256),
        .mode = mode,
    };
}

fn run(allocator: Allocator, io: Io, argv: []const []const u8) !void {
    _ = allocator;
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
}

fn capture(allocator: Allocator, io: Io, argv: []const []const u8) ![]u8 {
    const result = try std.process.run(allocator, io, .{ .argv = argv });
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            allocator.free(result.stdout);
            return error.CommandFailed;
        },
        else => {
            allocator.free(result.stdout);
            return error.CommandFailed;
        },
    }
    return result.stdout;
}

fn requireTool(allocator: Allocator, io: Io, name: []const u8) !void {
    const path = try capture(allocator, io, &.{ "sh", "-c", "command -v \"$1\"", "vmiz-tool", name });
    defer allocator.free(path);
    if (std.mem.trim(u8, path, " \t\r\n").len == 0) return error.RequiredToolMissing;
}

fn acquire(
    allocator: Allocator,
    io: Io,
    url: []const u8,
    path: []const u8,
    sha256: []const u8,
    max_size: u64,
    downloader: artifact_pipeline.Downloader,
) !void {
    _ = try artifact_pipeline.acquireVerified(allocator, io, .{
        .url = url,
        .destination_path = path,
        .expected_sha256 = try artifact_pipeline.parseSha256(sha256),
        .max_size = max_size,
    }, downloader);
}

fn copyBoundedFile(
    allocator: Allocator,
    io: Io,
    source: []const u8,
    destination: []const u8,
    limit: u64,
) !void {
    const bytes = try Dir.cwd().readFileAlloc(io, source, allocator, .limited(limit));
    defer allocator.free(bytes);
    try Dir.cwd().writeFile(io, .{ .sub_path = destination, .data = bytes });
}

fn validateManifest(bytes: []const u8, profile: *const Profile) !void {
    for (&required_manifest_packages) |name| {
        const needle = try std.fmt.allocPrint(std.testing.allocator, "{s}\t", .{name});
        defer std.testing.allocator.free(needle);
        if (std.mem.indexOf(u8, bytes, needle) == null) return error.RequiredPackageMissing;
    }
    const foreign = switch (profile.architecture) {
        .x86_64 => ":arm64\t",
        .aarch64 => ":amd64\t",
    };
    if (std.mem.indexOf(u8, bytes, foreign) != null) return error.ForeignArchitecturePackage;
}

fn validateManifestRuntime(allocator: Allocator, bytes: []const u8, profile: *const Profile) !void {
    for (&required_manifest_packages) |name| {
        const needle = try std.fmt.allocPrint(allocator, "{s}\t", .{name});
        defer allocator.free(needle);
        if (std.mem.indexOf(u8, bytes, needle) == null) return error.RequiredPackageMissing;
    }
    const foreign = switch (profile.architecture) {
        .x86_64 => ":arm64\t",
        .aarch64 => ":amd64\t",
    };
    if (std.mem.indexOf(u8, bytes, foreign) != null) return error.ForeignArchitecturePackage;
}

fn requireSha256SumsEntry(bytes: []const u8, filename: []const u8, digest: []const u8) !void {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var matches: usize = 0;
    while (lines.next()) |line| {
        if (line.len < 67) continue;
        const separator = line[64..66];
        if (!std.mem.eql(u8, separator, " *") and !std.mem.eql(u8, separator, "  ")) continue;
        if (!std.mem.eql(u8, line[66..], filename)) continue;
        matches += 1;
        if (!std.ascii.eqlIgnoreCase(line[0..64], digest)) return error.SignedDigestMismatch;
    }
    if (matches != 1) return error.SignedEntryMissingOrDuplicate;
}

const ArmorKind = enum {
    public_key,
    signature,

    fn begin(self: ArmorKind) []const u8 {
        return switch (self) {
            .public_key => "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            .signature => "-----BEGIN PGP SIGNATURE-----",
        };
    }

    fn end(self: ArmorKind) []const u8 {
        return switch (self) {
            .public_key => "-----END PGP PUBLIC KEY BLOCK-----",
            .signature => "-----END PGP SIGNATURE-----",
        };
    }
};

const OpenPgpPacket = struct {
    tag: u8,
    body: []const u8,
};

const OpenPgpPacketReader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn take(self: *OpenPgpPacketReader, count: usize) ![]const u8 {
        if (count > self.bytes.len -| self.offset) return error.TruncatedOpenPgpPacket;
        const result = self.bytes[self.offset .. self.offset + count];
        self.offset += count;
        return result;
    }

    fn takeByte(self: *OpenPgpPacketReader) !u8 {
        return (try self.take(1))[0];
    }

    fn next(self: *OpenPgpPacketReader) !?OpenPgpPacket {
        if (self.offset == self.bytes.len) return null;
        const ctb = try self.takeByte();
        if ((ctb & 0x80) == 0) return error.InvalidOpenPgpPacketHeader;

        var tag: u8 = undefined;
        var body_length: usize = undefined;
        if ((ctb & 0x40) != 0) {
            tag = ctb & 0x3f;
            const first_length = try self.takeByte();
            body_length = switch (first_length) {
                0...191 => first_length,
                192...223 => blk: {
                    const second_length = try self.takeByte();
                    break :blk ((@as(usize, first_length) - 192) << 8) + second_length + 192;
                },
                255 => blk: {
                    const encoded = try self.take(4);
                    const value = std.mem.readInt(u32, encoded[0..4], .big);
                    if (value < 8384) return error.NonCanonicalOpenPgpLength;
                    break :blk value;
                },
                else => return error.PartialOpenPgpPacketsUnsupported,
            };
        } else {
            tag = (ctb >> 2) & 0x0f;
            body_length = switch (ctb & 0x03) {
                0 => try self.takeByte(),
                1 => std.mem.readInt(u16, (try self.take(2))[0..2], .big),
                2 => std.mem.readInt(u32, (try self.take(4))[0..4], .big),
                else => return error.IndeterminateOpenPgpPacketsUnsupported,
            };
        }
        return .{ .tag = tag, .body = try self.take(body_length) };
    }
};

const OpenPgpMpi = struct {
    bits: u16,
    bytes: []const u8,
};

fn parseOpenPgpMpi(bytes: []const u8, offset: *usize) !OpenPgpMpi {
    if (bytes.len -| offset.* < 2) return error.TruncatedOpenPgpMpi;
    const bits = std.mem.readInt(u16, bytes[offset.*..][0..2], .big);
    offset.* += 2;
    if (bits == 0) return error.InvalidOpenPgpMpi;
    const byte_count = (@as(usize, bits) + 7) / 8;
    if (byte_count > bytes.len -| offset.*) return error.TruncatedOpenPgpMpi;
    const value = bytes[offset.* .. offset.* + byte_count];
    offset.* += byte_count;
    const unused_bits: u4 = @intCast((8 - (bits % 8)) % 8);
    const first_significant_bit: u3 = @intCast(7 - unused_bits);
    if (value[0] == 0 or
        (unused_bits != 0 and value[0] >> @as(u3, @intCast(8 - unused_bits)) != 0) or
        (value[0] & (@as(u8, 1) << first_significant_bit)) == 0)
        return error.NonCanonicalOpenPgpMpi;
    return .{ .bits = bits, .bytes = value };
}

fn crc24(bytes: []const u8) u32 {
    var crc: u32 = 0xb704ce;
    for (bytes) |byte| {
        crc ^= @as(u32, byte) << 16;
        for (0..8) |_| {
            crc = (crc << 1) ^ if ((crc & 0x800000) != 0) @as(u32, 0x1864cfb) else 0;
            crc &= 0xffffff;
        }
    }
    return crc;
}

fn validateArmorHeader(line: []const u8) !void {
    const separator = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidOpenPgpArmorHeader;
    if (separator == 0 or separator + 1 >= line.len) return error.InvalidOpenPgpArmorHeader;
    for (line) |byte|
        if (byte < 0x20 or byte > 0x7e) return error.InvalidOpenPgpArmorHeader;
}

fn decodeOpenPgpArmorAlloc(
    allocator: Allocator,
    armored: []const u8,
    kind: ArmorKind,
    max_size: usize,
) ![]u8 {
    if (!std.mem.endsWith(u8, armored, "\n")) return error.InvalidOpenPgpArmor;
    var lines = std.mem.splitScalar(u8, armored, '\n');
    if (!std.mem.eql(u8, lines.next() orelse return error.InvalidOpenPgpArmor, kind.begin()))
        return error.InvalidOpenPgpArmor;

    var encoded = try allocator.alloc(u8, armored.len);
    defer allocator.free(encoded);
    var encoded_length: usize = 0;
    var previous_line_length: ?usize = null;
    var saw_body = false;
    var saw_separator = false;
    var expected_crc: ?u32 = null;

    while (lines.next()) |line| {
        if (!saw_separator) {
            if (line.len == 0) {
                saw_separator = true;
            } else {
                try validateArmorHeader(line);
            }
            continue;
        }
        if (std.mem.startsWith(u8, line, "=")) {
            if (!saw_body or line.len != 5) return error.InvalidOpenPgpArmor;
            var crc_bytes: [3]u8 = undefined;
            try std.base64.standard.Decoder.decode(&crc_bytes, line[1..]);
            expected_crc = std.mem.readInt(u24, &crc_bytes, .big);
            break;
        }
        if (line.len == 0 or line.len > 64) return error.InvalidOpenPgpArmor;
        if (previous_line_length) |length|
            if (length != 64) return error.NonCanonicalOpenPgpArmor;
        for (line) |byte|
            if (!(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '/' or byte == '='))
                return error.InvalidOpenPgpArmor;
        @memcpy(encoded[encoded_length .. encoded_length + line.len], line);
        encoded_length += line.len;
        previous_line_length = line.len;
        saw_body = true;
    }

    const crc = expected_crc orelse return error.InvalidOpenPgpArmor;
    if (previous_line_length == null or encoded_length % 4 != 0) return error.InvalidOpenPgpArmor;
    if (!std.mem.eql(u8, lines.next() orelse return error.InvalidOpenPgpArmor, kind.end()))
        return error.InvalidOpenPgpArmor;
    if (lines.next()) |trailing|
        if (trailing.len != 0 or lines.next() != null) return error.TrailingOpenPgpArmorData;

    const decoded_length = try std.base64.standard.Decoder.calcSizeForSlice(encoded[0..encoded_length]);
    if (decoded_length == 0 or decoded_length > max_size) return error.OpenPgpArmorTooLarge;
    const decoded = try allocator.alloc(u8, decoded_length);
    errdefer allocator.free(decoded);
    try std.base64.standard.Decoder.decode(decoded, encoded[0..encoded_length]);
    if (crc24(decoded) != crc) return error.OpenPgpArmorCrcMismatch;
    return decoded;
}

const ParsedOpenPgpPublicKey = struct {
    fingerprint: [20]u8,
    created_at: u32,
    rsa: std.crypto.Certificate.rsa.PublicKey,
};

fn parseOpenPgpPublicKeyPacket(body: []const u8) !ParsedOpenPgpPublicKey {
    if (body.len < 8 or body[0] != 4) return error.UnsupportedOpenPgpPublicKeyVersion;
    if (body[5] != 1) return error.UnsupportedOpenPgpPublicKeyAlgorithm;
    var offset: usize = 6;
    const modulus = try parseOpenPgpMpi(body, &offset);
    const exponent = try parseOpenPgpMpi(body, &offset);
    if (offset != body.len) return error.TrailingOpenPgpPublicKeyData;
    if (modulus.bits != 4096 or modulus.bytes.len != 512 or !std.mem.eql(u8, exponent.bytes, "\x01\x00\x01"))
        return error.WeakOrUnsupportedOpenPgpRsaKey;

    var fingerprint: [20]u8 = undefined;
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update("\x99");
    var length: [2]u8 = undefined;
    std.mem.writeInt(u16, &length, @intCast(body.len), .big);
    hasher.update(&length);
    hasher.update(body);
    hasher.final(&fingerprint);

    return .{
        .fingerprint = fingerprint,
        .created_at = std.mem.readInt(u32, body[1..5], .big),
        .rsa = try std.crypto.Certificate.rsa.PublicKey.fromBytes(exponent.bytes, modulus.bytes),
    };
}

fn parseSingleOpenPgpPublicKeyPacket(packet_bytes: []const u8) !ParsedOpenPgpPublicKey {
    var reader = OpenPgpPacketReader{ .bytes = packet_bytes };
    const packet = try reader.next() orelse return error.OpenPgpPublicKeyMissing;
    if (packet.tag != 6) return error.OpenPgpPublicKeyMissing;
    if (try reader.next() != null) return error.AmbiguousOpenPgpPublicKeyPackets;
    return parseOpenPgpPublicKeyPacket(packet.body);
}

fn parseCanonicalPublicKey(allocator: Allocator) !ParsedOpenPgpPublicKey {
    var armor_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical_key_armor, &armor_digest, .{});
    if (!std.mem.eql(u8, &armor_digest, &canonical_key_armor_sha256)) return error.CanonicalKeyArmorPinMismatch;

    const decoded = try decodeOpenPgpArmorAlloc(allocator, canonical_key_armor, .public_key, public_key_max_size);
    defer allocator.free(decoded);
    var reader = OpenPgpPacketReader{ .bytes = decoded };
    const primary = try reader.next() orelse return error.OpenPgpPublicKeyMissing;
    if (primary.tag != 6) return error.OpenPgpPublicKeyMissing;
    const key = try parseOpenPgpPublicKeyPacket(primary.body);
    // The entire armored transfer is source-pinned above; parse its remaining
    // packets only to reject malformed or unsupported trailing data.
    while (try reader.next()) |packet| {
        switch (packet.tag) {
            2, 13 => if (packet.body.len == 0) return error.InvalidOpenPgpCanonicalKeyPacket,
            else => return error.UnsupportedOpenPgpCanonicalKeyPacket,
        }
    }
    if (!std.mem.eql(u8, &key.fingerprint, &canonical_fingerprint_bytes))
        return error.CanonicalFingerprintMismatch;
    return key;
}

const SignatureSubpackets = struct {
    creation_time: ?u32 = null,
    issuer_fingerprint: bool = false,
    issuer_key_id: bool = false,
};

fn readOpenPgpSubpacketLength(bytes: []const u8, offset: *usize) !usize {
    if (offset.* == bytes.len) return error.TruncatedOpenPgpSubpacket;
    const first = bytes[offset.*];
    offset.* += 1;
    return switch (first) {
        0...191 => first,
        192...223 => blk: {
            if (offset.* == bytes.len) return error.TruncatedOpenPgpSubpacket;
            const second = bytes[offset.*];
            offset.* += 1;
            break :blk ((@as(usize, first) - 192) << 8) + second + 192;
        },
        255 => blk: {
            if (bytes.len -| offset.* < 4) return error.TruncatedOpenPgpSubpacket;
            const result = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
            offset.* += 4;
            if (result < 8384) return error.NonCanonicalOpenPgpLength;
            break :blk result;
        },
        else => return error.PartialOpenPgpPacketsUnsupported,
    };
}

fn parseSignatureSubpackets(
    bytes: []const u8,
    hashed: bool,
    key: *const ParsedOpenPgpPublicKey,
    result: *SignatureSubpackets,
) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const length = try readOpenPgpSubpacketLength(bytes, &offset);
        if (length == 0 or length > bytes.len -| offset) return error.InvalidOpenPgpSubpacket;
        const packet = bytes[offset .. offset + length];
        offset += length;
        if ((packet[0] & 0x80) != 0) return error.UnsupportedCriticalOpenPgpSubpacket;
        const body = packet[1..];
        switch (packet[0]) {
            2 => {
                if (!hashed or result.creation_time != null or body.len != 4)
                    return error.InvalidOpenPgpSignatureCreationTime;
                result.creation_time = std.mem.readInt(u32, body[0..4], .big);
            },
            16 => {
                if (hashed or result.issuer_key_id or body.len != 8 or
                    !std.mem.eql(u8, body, key.fingerprint[key.fingerprint.len - 8 ..]))
                    return error.InvalidOpenPgpIssuer;
                result.issuer_key_id = true;
            },
            33 => {
                if (!hashed or result.issuer_fingerprint or body.len != 21 or body[0] != 4 or
                    !std.mem.eql(u8, body[1..], &key.fingerprint))
                    return error.InvalidOpenPgpIssuer;
                result.issuer_fingerprint = true;
            },
            else => return error.UnsupportedOpenPgpSignatureSubpacket,
        }
    }
}

fn verifyOpenPgpDetachedSignature(
    allocator: Allocator,
    io: Io,
    content: []const u8,
    encoded_signature: []const u8,
    key: *const ParsedOpenPgpPublicKey,
) !void {
    const signature_bytes = if (std.mem.startsWith(u8, encoded_signature, "-----BEGIN PGP SIGNATURE-----"))
        try decodeOpenPgpArmorAlloc(allocator, encoded_signature, .signature, signature_max_size)
    else
        try allocator.dupe(u8, encoded_signature);
    defer allocator.free(signature_bytes);

    var reader = OpenPgpPacketReader{ .bytes = signature_bytes };
    const packet = try reader.next() orelse return error.OpenPgpDetachedSignatureMissing;
    if (packet.tag != 2) return error.OpenPgpDetachedSignatureMissing;
    if (try reader.next() != null) return error.AmbiguousOpenPgpDetachedSignature;
    const body = packet.body;
    if (body.len < 10 or body[0] != 4 or body[1] != 0 or body[2] != 1 or body[3] != 10)
        return error.UnsupportedOpenPgpDetachedSignature;

    const hashed_length = std.mem.readInt(u16, body[4..6], .big);
    const hashed_end = 6 + @as(usize, hashed_length);
    if (hashed_end > body.len -| 2) return error.TruncatedOpenPgpDetachedSignature;
    var subpackets = SignatureSubpackets{};
    try parseSignatureSubpackets(body[6..hashed_end], true, key, &subpackets);

    const unhashed_length = std.mem.readInt(u16, body[hashed_end..][0..2], .big);
    const unhashed_end = hashed_end + 2 + @as(usize, unhashed_length);
    if (unhashed_end > body.len -| 4) return error.TruncatedOpenPgpDetachedSignature;
    try parseSignatureSubpackets(body[hashed_end + 2 .. unhashed_end], false, key, &subpackets);
    const creation_time = subpackets.creation_time orelse return error.OpenPgpSignatureCreationTimeMissing;
    if (!subpackets.issuer_fingerprint or !subpackets.issuer_key_id) return error.OpenPgpSignatureIssuerMissing;
    if (creation_time < key.created_at or @as(i64, creation_time) > Io.Timestamp.now(io, .real).toSeconds())
        return error.InvalidOpenPgpSignatureTime;

    const left_hash = body[unhashed_end..][0..2];
    var signature_offset = unhashed_end + 2;
    const signature_mpi = try parseOpenPgpMpi(body, &signature_offset);
    if (signature_offset != body.len or signature_mpi.bits != 4096 or signature_mpi.bytes.len != 512)
        return error.WeakOrMalformedOpenPgpSignature;

    var trailer: [6]u8 = undefined;
    trailer[0] = 4;
    trailer[1] = 0xff;
    std.mem.writeInt(u32, trailer[2..6], @intCast(hashed_end), .big);
    var digest: [64]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    hasher.update(content);
    hasher.update(body[0..hashed_end]);
    hasher.update(&trailer);
    hasher.final(&digest);
    if (!std.mem.eql(u8, left_hash, digest[0..2])) return error.OpenPgpSignatureHashPrefixMismatch;

    var signature: [512]u8 = undefined;
    @memcpy(&signature, signature_mpi.bytes);
    try std.crypto.Certificate.rsa.PKCS1v1_5Signature.concatVerify(
        512,
        signature,
        &.{ content, body[0..hashed_end], &trailer },
        key.rsa,
        std.crypto.hash.sha2.Sha512,
    );
}

fn verifyCanonicalPublication(
    allocator: Allocator,
    io: Io,
    sums_path: []const u8,
    signature_path: []const u8,
) !void {
    const sums = try Dir.cwd().readFileAlloc(io, sums_path, allocator, .limited(sums_max_size));
    defer allocator.free(sums);
    const signature = try Dir.cwd().readFileAlloc(io, signature_path, allocator, .limited(signature_max_size));
    defer allocator.free(signature);
    const key = try parseCanonicalPublicKey(allocator);
    try verifyOpenPgpDetachedSignature(allocator, io, sums, signature, &key);
}

fn peMachine(bytes: []const u8) !u16 {
    if (bytes.len < 0x40 or !std.mem.eql(u8, bytes[0..2], "MZ")) return error.InvalidPeImage;
    const pe_offset = std.mem.readInt(u32, bytes[0x3c..0x40], .little);
    if (pe_offset > bytes.len -| 6) return error.InvalidPeImage;
    const offset: usize = @intCast(pe_offset);
    if (!std.mem.eql(u8, bytes[offset .. offset + 4], "PE\x00\x00")) return error.InvalidPeImage;
    const machine: *const [2]u8 = @ptrCast(bytes[offset + 4 ..].ptr);
    return std.mem.readInt(u16, machine, .little);
}

fn validateExactLock(bytes: []const u8, profile: *const Profile) !void {
    for (&[_][]const u8{ "linux-azure\t", "walinuxagent\t", "cloud-init\t", "openssh-server\t" }) |needle|
        if (std.mem.indexOf(u8, bytes, needle) == null) return error.ExactLockIncomplete;
    const expected_arch = try std.fmt.allocPrint(std.testing.allocator, "\t{s}\n", .{profile.ubuntu_architecture});
    defer std.testing.allocator.free(expected_arch);
    if (std.mem.indexOf(u8, bytes, expected_arch) == null) return error.ExactLockArchitectureMissing;
    const foreign_arch = switch (profile.architecture) {
        .x86_64 => "\tarm64\n",
        .aarch64 => "\tamd64\n",
    };
    if (std.mem.indexOf(u8, bytes, foreign_arch) != null) return error.ForeignArchitecturePackage;
}

fn validateExactLockRuntime(allocator: Allocator, bytes: []const u8, profile: *const Profile) !void {
    for (&[_][]const u8{ "linux-azure\t", "walinuxagent\t", "cloud-init\t", "openssh-server\t" }) |needle|
        if (std.mem.indexOf(u8, bytes, needle) == null) return error.ExactLockIncomplete;
    const expected_arch = try std.fmt.allocPrint(allocator, "\t{s}\n", .{profile.ubuntu_architecture});
    defer allocator.free(expected_arch);
    if (std.mem.indexOf(u8, bytes, expected_arch) == null) return error.ExactLockArchitectureMissing;
    const foreign_arch = switch (profile.architecture) {
        .x86_64 => "\tarm64\n",
        .aarch64 => "\tamd64\n",
    };
    if (std.mem.indexOf(u8, bytes, foreign_arch) != null) return error.ForeignArchitecturePackage;
}

const DebzEvidence = struct {
    package: []const u8,
    lock_path: []u8,
    lock_sha256: [64]u8,
    lock_digest_sha256: [64]u8,
    provenance_path: []u8,
    provenance_sha256: [64]u8,
    provenance_digest_sha256: [64]u8,
    provenance_lock_sha256: [64]u8,

    fn deinit(self: *DebzEvidence, allocator: Allocator) void {
        allocator.free(self.lock_path);
        allocator.free(self.provenance_path);
        self.* = undefined;
    }
};

const DebzCustomization = struct {
    root_path: []u8,
    evidence: [debz_packages.len]DebzEvidence,

    fn deinit(self: *DebzCustomization, allocator: Allocator) void {
        allocator.free(self.root_path);
        for (&self.evidence) |*item| item.deinit(allocator);
        self.* = undefined;
    }
};

const NativeRoot = struct {
    allocator: Allocator,
    io: Io,
    mutable_image: []const u8,
    raw_path: []u8,
    image: vmiz.Image,
    filesystem: vmiz.ext4_mountless.FileSystem,
    image_open: bool = true,
    filesystem_open: bool = true,

    fn deinit(self: *NativeRoot) void {
        if (self.filesystem_open) {
            self.filesystem.deinit();
            self.filesystem_open = false;
        }
        if (self.image_open) {
            self.image.close(self.io);
            self.image_open = false;
        }
        Dir.cwd().deleteFile(self.io, self.raw_path) catch {};
        self.allocator.free(self.raw_path);
        self.* = undefined;
    }

    fn finish(self: *NativeRoot) !void {
        var commit_result = self.filesystem.commit() catch |err| {
            if (self.filesystem.recoveryArtifactPath()) |path| {
                std.debug.print(
                    "native ext4 commit failed: {s}; recovery artifact retained at {s}\n",
                    .{ @errorName(err), path },
                );
            } else {
                std.debug.print("native ext4 commit failed: {s}\n", .{@errorName(err)});
            }
            return err;
        };
        defer commit_result.deinit();
        std.debug.print(
            "native ext4 recovery artifact retained at {s}\n",
            .{commit_result.recovery_path},
        );
        self.filesystem.deinit();
        self.filesystem_open = false;
        self.image.close(self.io);
        self.image_open = false;
        try publishNativeQcow2(
            self.allocator,
            self.io,
            self.raw_path,
            self.mutable_image,
        );
        Dir.cwd().deleteFile(self.io, self.raw_path) catch {};
    }
};

fn copyNativeImage(
    allocator: Allocator,
    io: Io,
    source_path: []const u8,
    destination_path: []const u8,
    format: ImageFormat,
) !void {
    var source = try vmiz.Image.openPathReadOnlyStandalone(io, source_path);
    defer source.close(io);
    var destination = try vmiz.Image.createExclusive(
        io,
        destination_path,
        format,
        source.virtual_size,
        .{},
    );
    var destination_open = true;
    errdefer {
        if (destination_open) destination.close(io);
        Dir.cwd().deleteFile(io, destination_path) catch {};
    }
    try vmiz.copyAll(io, source, &destination, allocator);
    try destination.file.sync(io);
    destination.close(io);
    destination_open = false;
}

fn publishNativeQcow2(
    allocator: Allocator,
    io: Io,
    raw_path: []const u8,
    destination_path: []const u8,
) !void {
    const staged_path = try std.fmt.allocPrint(
        allocator,
        "{s}.vmiz-native-stage",
        .{destination_path},
    );
    defer allocator.free(staged_path);
    Dir.cwd().deleteFile(io, staged_path) catch {};
    errdefer Dir.cwd().deleteFile(io, staged_path) catch {};
    try copyNativeImage(allocator, io, raw_path, staged_path, .qcow2);
    var staged = try vmiz.Image.openPathReadOnlyStandalone(io, staged_path);
    const check = staged.check(io) catch |err| {
        staged.close(io);
        return err;
    };
    staged.close(io);
    if (!check.ok) return error.FinalImageInvalid;
    try Dir.cwd().rename(staged_path, Dir.cwd(), destination_path, io);
}

fn partitionNameEquals(partition: vmiz.gpt.PartitionEntry, expected: []const u8) bool {
    if (expected.len > partition.name_utf16le.len) return false;
    for (expected, 0..) |byte, index| {
        if (partition.name_utf16le[index] != byte) return false;
    }
    for (partition.name_utf16le[expected.len..]) |code_unit| {
        if (code_unit != 0) return false;
    }
    return true;
}

fn findNamedRootPartition(partitions: []const vmiz.gpt.PartitionEntry) !vmiz.gpt.PartitionEntry {
    var found: ?vmiz.gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (!partitionNameEquals(partition, "cloudimg-rootfs")) continue;
        if (found != null) return error.AmbiguousRootPartition;
        found = partition;
    }
    return found orelse error.RootPartitionNotFound;
}

fn partitionOffsetLength(partition: vmiz.gpt.PartitionEntry) !struct { offset: u64, length: u64 } {
    const offset = std.math.mul(u64, partition.first_lba, vmiz.gpt.sector_size) catch
        return error.InvalidPartitionBounds;
    const sectors = std.math.add(u64, partition.last_lba - partition.first_lba, 1) catch
        return error.InvalidPartitionBounds;
    return .{
        .offset = offset,
        .length = std.math.mul(u64, sectors, vmiz.gpt.sector_size) catch
            return error.InvalidPartitionBounds,
    };
}

fn rootPartitionGuid(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    profile: *const Profile,
) !guid.Guid {
    var image = try vmiz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    const parsed = try vmiz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    const partition = try findNamedRootPartition(parsed.partitions);
    if (!std.mem.eql(u8, &partition.partition_type_guid, &profile.root_partition_type_guid))
        return error.RootPartitionTypeMismatch;
    if (std.mem.eql(u8, &partition.unique_partition_guid, &guid.nil))
        return error.InvalidRootPartitionGuid;
    return partition.unique_partition_guid;
}

fn ukiCmdline(
    allocator: Allocator,
    root_guid: guid.Guid,
    profile: *const Profile,
) ![]u8 {
    var root_guid_text: [36]u8 = undefined;
    const root_guid_value = guid.formatLower(&root_guid_text, root_guid);
    return std.fmt.allocPrint(
        allocator,
        "root=PARTUUID={s} {s}",
        .{ root_guid_value, profile.serial_console },
    );
}

fn labelEquals(label: [16]u8, expected: []const u8) bool {
    if (expected.len > label.len) return false;
    if (!std.mem.eql(u8, label[0..expected.len], expected)) return false;
    for (label[expected.len..]) |byte| if (byte != 0) return false;
    return true;
}

fn openNativeRoot(
    allocator: Allocator,
    io: Io,
    mutable_image: []const u8,
    work_dir: []const u8,
) !NativeRoot {
    const raw_path = try std.fs.path.join(allocator, &.{ work_dir, "customized.native.raw" });
    errdefer allocator.free(raw_path);
    errdefer Dir.cwd().deleteFile(io, raw_path) catch {};
    Dir.cwd().deleteFile(io, raw_path) catch {};
    try copyNativeImage(allocator, io, mutable_image, raw_path, .raw);
    var image = try vmiz.Image.openPath(io, raw_path);
    errdefer image.close(io);
    const partitions = try vmiz.gpt.readGpt(image, io, allocator);
    defer allocator.free(partitions.partitions);
    const partition = try findNamedRootPartition(partitions.partitions);
    const geometry = try partitionOffsetLength(partition);
    const spool_path = try std.fs.path.join(allocator, &.{ work_dir, "customized.native.spool" });
    defer allocator.free(spool_path);
    Dir.cwd().deleteFile(io, spool_path) catch {};
    var filesystem = try vmiz.ext4_mountless.FileSystem.open(allocator, io, image.file, .{
        .offset = geometry.offset,
        .length = geometry.length,
        .spool_path = spool_path,
        .atomic_path = raw_path,
    });
    if (!labelEquals(filesystem.filesystemIdentity().label, "cloudimg-rootfs")) {
        filesystem.deinit();
        return error.RootFilesystemLabelMismatch;
    }
    return .{
        .allocator = allocator,
        .io = io,
        .mutable_image = mutable_image,
        .raw_path = raw_path,
        .image = image,
        .filesystem = filesystem,
    };
}

fn requireSucceeded(result: package_family.Result) !void {
    if (!result.succeeded or result.diagnostic != null) {
        if (result.diagnostic) |diagnostic| {
            std.debug.print("debz {s}: {s}", .{ @tagName(diagnostic.id), diagnostic.message });
            if (diagnostic.backend_exit_status) |status|
                std.debug.print(" (exit status {d})", .{status});
            std.debug.print("\n", .{});
        }
        return error.DebzTransactionFailed;
    }
}

fn requireJsonSha256Field(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    field: []const u8,
) ![64]u8 {
    const bytes = try Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024 * 1024));
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const value = parsed.value.object.get(field) orelse return error.DebzEvidenceFieldMissing;
    if (value != .string) return error.DebzEvidenceFieldMissing;
    return artifact_pipeline.formatSha256(try artifact_pipeline.parseSha256(value.string));
}

fn lessLine(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn sortedPackageLock(allocator: Allocator, bytes: []const u8) ![]u8 {
    var lines = std.array_list.Managed([]const u8).init(allocator);
    defer lines.deinit();
    var iterator = std.mem.splitScalar(u8, bytes, '\n');
    while (iterator.next()) |line| {
        if (line.len != 0) try lines.append(line);
    }
    std.mem.sort([]const u8, lines.items, {}, lessLine);
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    for (lines.items) |line| {
        try output.writer.writeAll(line);
        try output.writer.writeByte('\n');
    }
    return output.toOwnedSlice();
}

fn runOfflineCommand(
    executor: *offline_root.Executor,
    command: offline_root.Command,
) !offline_root.CommandResult {
    return executor.execute(command);
}

fn validateNativeBootArtifacts(
    allocator: Allocator,
    root: *offline_root.Root,
    release_name: []const u8,
) !void {
    const modules_path = try std.fmt.allocPrint(allocator, "/lib/modules/{s}", .{release_name});
    defer allocator.free(modules_path);
    const modules = try root.discover(modules_path, "*");
    defer root.freeFound(modules);
    if (modules.len == 0) return error.AzureKernelModulesMissing;
    const modules_dep_path = try std.fmt.allocPrint(allocator, "{s}/modules.dep", .{modules_path});
    defer allocator.free(modules_dep_path);
    const modules_dep = root.inspect(modules_dep_path) catch |err| switch (err) {
        error.PathNotFound => return error.KernelModulesDependencyMissing,
        else => return err,
    };
    defer allocator.free(modules_dep.path);
    if (modules_dep.kind != .file) return error.KernelModulesDependencyMissing;
    const initrd_path = try std.fmt.allocPrint(allocator, "/boot/initrd.img-{s}", .{release_name});
    defer allocator.free(initrd_path);
    const initrd = root.inspect(initrd_path) catch |err| switch (err) {
        error.PathNotFound => return error.InitramfsMissing,
        else => return err,
    };
    defer allocator.free(initrd.path);
    if (initrd.kind != .file or initrd.size == 0) return error.InitramfsMissing;
}

fn validateUkiBytes(
    fallback_bytes: []const u8,
    named_bytes: []const u8,
    profile: *const Profile,
) !void {
    if (!std.mem.eql(u8, fallback_bytes, named_bytes)) return error.FinalUkiMissing;
    if (try peMachine(fallback_bytes) != profile.pe_machine) return error.WrongUkiArchitecture;
}

fn customizeOfflineRoot(
    allocator: Allocator,
    io: Io,
    profile: *const Profile,
    root_path: []const u8,
    provenance_dir: []const u8,
) ![]u8 {
    var root = try offline_root.Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    const release_name = try root.activeKernelRelease();
    errdefer allocator.free(release_name);
    try root.validateArchitecture(switch (profile.architecture) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
    });

    var executor = try offline_root.Executor.init(allocator, io, .{
        .root = &root,
        .architecture = switch (profile.architecture) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .timeout_ms = 30 * 60 * 1000,
    });
    defer executor.deinit();

    const directories = [_]offline_root.Operation{
        .{ .create_directory = .{ .path = "/etc/ssh/sshd_config.d", .mode = 0o755 } },
        .{ .create_directory = .{ .path = "/etc/cloud/cloud.cfg.d", .mode = 0o755 } },
        .{ .create_directory = .{ .path = "/etc/netplan", .mode = 0o755 } },
        .{ .create_directory = .{ .path = "/var/lib/vmiz", .mode = 0o755 } },
    };
    try root.apply(&directories);

    const ssh_config =
        "PasswordAuthentication no\n" ++
        "KbdInteractiveAuthentication no\n" ++
        "PermitRootLogin prohibit-password\n";
    const cloud_config =
        "datasource_list: [ Azure ]\n" ++
        "datasource:\n" ++
        "  Azure:\n" ++
        "    apply_network_config: true\n" ++
        "growpart:\n" ++
        "  mode: auto\n" ++
        "  devices: ['/']\n" ++
        "resize_rootfs: true\n";
    const netplan =
        "network:\n" ++
        "  version: 2\n" ++
        "  renderer: networkd\n" ++
        "  ethernets:\n" ++
        "    all:\n" ++
        "      match:\n" ++
        "        name: \"e*\"\n" ++
        "      dhcp4: true\n" ++
        "      dhcp6: true\n";
    const waagent =
        "Provisioning.Enabled=n\n" ++
        "Provisioning.Agent=auto\n" ++
        "Provisioning.DeleteRootPassword=y\n" ++
        "OS.EnableFIPS=n\n" ++
        "OS.RootDeviceScsiTimeout=300\n" ++
        "ResourceDisk.Format=n\n" ++
        "ResourceDisk.EnableSwap=n\n" ++
        "Logs.Verbose=n\n" ++
        "Extensions.Enabled=y\n" ++
        "AutoUpdate.Enabled=y\n";
    try root.apply(&.{
        .{ .write_file = .{ .path = "/etc/ssh/sshd_config.d/10-vmiz-generalized.conf", .source = .{ .inline_bytes = ssh_config } } },
        .{ .write_file = .{ .path = "/etc/cloud/cloud.cfg.d/90-azure.cfg", .source = .{ .inline_bytes = cloud_config } } },
        .{ .write_file = .{ .path = "/etc/netplan/50-cloud-init.yaml", .source = .{ .inline_bytes = netplan } } },
        .{ .write_file = .{ .path = "/etc/waagent.conf", .source = .{ .inline_bytes = waagent } } },
        .{ .replace_symlink = .{ .path = "/etc/resolv.conf", .target = "/run/systemd/resolve/stub-resolv.conf" } },
    });

    try validateNativeBootArtifacts(allocator, &root, release_name);

    var initramfs = try runOfflineCommand(&executor, .{ .update_initramfs = release_name });
    defer initramfs.deinit(allocator);

    var package_query = try runOfflineCommand(&executor, .dpkg_query);
    defer package_query.deinit(allocator);
    const lock = try sortedPackageLock(allocator, package_query.stdout);
    defer allocator.free(lock);
    try root.apply(&.{
        .{ .write_file = .{
            .path = "/var/lib/vmiz/ubuntu2604-package-lock.tsv",
            .source = .{ .inline_bytes = lock },
        } },
        .{ .write_file = .{
            .path = "/var/lib/vmiz/source-release",
            .source = .{ .inline_bytes = release ++ "\n" },
        } },
        .{ .write_file = .{
            .path = "/etc/machine-id",
            .source = .{ .inline_bytes = "" },
            .mode = 0o444,
        } },
    });

    var cloud_init = try runOfflineCommand(&executor, .{ .cloud_init_clean = .{ .logs = true } });
    defer cloud_init.deinit(allocator);
    try root.apply(&.{
        .{ .remove = "/var/lib/dbus/machine-id" },
        .{ .remove = "/var/lib/systemd/random-seed" },
        .{ .cleanup = .{ .directory = "/etc/ssh", .pattern = "ssh_host_*" } },
        .{ .cleanup = .{ .directory = "/var/lib/cloud", .pattern = "*" } },
        .{ .cleanup = .{ .directory = "/var/lib/waagent", .pattern = "*" } },
        .{ .cleanup = .{ .directory = "/var/log/azure", .pattern = "*" } },
        .{ .cleanup = .{ .directory = "/var/log/journal", .pattern = "*" } },
        .{ .cleanup = .{ .directory = "/tmp", .pattern = "*" } },
        .{ .cleanup = .{ .directory = "/var/tmp", .pattern = "*" } },
    });

    const modules_path = try std.fmt.allocPrint(allocator, "/lib/modules/{s}", .{release_name});
    defer allocator.free(modules_path);
    const initrd_path = try std.fmt.allocPrint(allocator, "/boot/initrd.img-{s}", .{release_name});
    defer allocator.free(initrd_path);
    for ([_][]const u8{
        "/etc/ssh/ssh_host_*",
        "/var/lib/cloud/*",
        "/var/lib/waagent/*",
        "/var/log/azure/*",
        "/var/log/journal/*",
        "/tmp/*",
        "/var/tmp/*",
    }) |pattern| {
        const slash = std.mem.lastIndexOfScalar(u8, pattern, '/') orelse return error.InvalidCleanupPattern;
        const directory = pattern[0..slash];
        const basename = pattern[slash + 1 ..];
        const remaining = root.discover(directory, basename) catch |err| switch (err) {
            error.FileNotFound => &.{},
            else => return err,
        };
        defer root.freeFound(remaining);
        if (remaining.len != 0) return error.CleanupIncomplete;
    }

    const evidence_path = try std.fs.path.join(allocator, &.{ provenance_dir, "ubuntu2604-boot-input-evidence.json" });
    defer allocator.free(evidence_path);
    var lock_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(lock, &lock_hash, .{});
    const lock_sha256 = artifact_pipeline.formatSha256(lock_hash);
    const kernel_path = try std.fmt.allocPrint(allocator, "/boot/vmlinuz-{s}", .{release_name});
    defer allocator.free(kernel_path);
    const evidence = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = 1,
        .type = "vmiz-ubuntu2604-boot-input-evidence",
        .architecture = @tagName(profile.architecture),
        .kernel_release = release_name,
        .kernel = kernel_path,
        .initramfs = initrd_path,
        .modules = modules_path,
        .package_lock = "/var/lib/vmiz/ubuntu2604-package-lock.tsv",
        .package_lock_sha256 = @as([]const u8, &lock_sha256),
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(evidence);
    try Dir.cwd().writeFile(io, .{ .sub_path = evidence_path, .data = evidence });
    return release_name;
}

fn customizeRootWithDebz(
    allocator: Allocator,
    io: Io,
    profile: *const Profile,
    mutable_image: []const u8,
    work_dir: []const u8,
    provenance_dir: []const u8,
) !DebzCustomization {
    const extraction = try std.fs.path.join(allocator, &.{ work_dir, "official-root" });
    defer allocator.free(extraction);
    try Dir.cwd().deleteTree(io, extraction);
    try Dir.cwd().createDirPath(io, extraction);
    var native_root = try openNativeRoot(allocator, io, mutable_image, work_dir);
    defer native_root.deinit();
    var host_manifest = vmiz.ext4_mountless.HostTreeManifest.init(allocator);
    defer host_manifest.deinit();
    try native_root.filesystem.validateCommitProfile();
    try native_root.filesystem.exportHostTreeWithManifest(extraction, .{}, &host_manifest);

    const direct_etc = try std.fs.path.join(allocator, &.{ extraction, "etc" });
    defer allocator.free(direct_etc);
    const nested_root = try std.fs.path.join(allocator, &.{ extraction, "root" });
    defer allocator.free(nested_root);
    const nested_etc = try std.fs.path.join(allocator, &.{ nested_root, "etc" });
    defer allocator.free(nested_etc);
    var current = if (Dir.cwd().statFile(io, direct_etc, .{})) |_|
        try allocator.dupe(u8, extraction)
    else |_| if (Dir.cwd().statFile(io, nested_etc, .{})) |_|
        try allocator.dupe(u8, nested_root)
    else |_|
        return error.OfficialRootExtractionFailed;
    errdefer allocator.free(current);

    for (&[_][]const u8{ "dev", "proc", "run", "sys" }) |name| {
        const mountpoint = try std.fs.path.join(allocator, &.{ current, name });
        defer allocator.free(mountpoint);
        try Dir.cwd().createDirPath(io, mountpoint);
    }

    const trusted_keyring = try std.fs.path.join(allocator, &.{ current, "usr/share/keyrings/ubuntu-archive-keyring.gpg" });
    defer allocator.free(trusted_keyring);
    const absolute_keyring = try Dir.cwd().realPathFileAlloc(io, trusted_keyring, allocator);
    defer allocator.free(absolute_keyring);
    const source_path = try std.fs.path.join(allocator, &.{ work_dir, "ubuntu-snapshot.sources" });
    defer allocator.free(source_path);
    const source_document = try std.fmt.allocPrint(allocator,
        \\Types: deb
        \\URIs: {s}
        \\Suites: resolute resolute-updates resolute-security
        \\Components: main restricted universe multiverse
        \\Architectures: {s}
        \\Signed-By: {s}
        \\
    , .{ snapshot_base, profile.ubuntu_architecture, absolute_keyring });
    defer allocator.free(source_document);
    try Dir.cwd().writeFile(io, .{ .sub_path = source_path, .data = source_document });
    const absolute_source = try Dir.cwd().realPathFileAlloc(io, source_path, allocator);
    defer allocator.free(absolute_source);
    const source_config_path = try std.fs.path.join(allocator, &.{ work_dir, "ubuntu-snapshot.json" });
    defer allocator.free(source_config_path);
    const source_config = try std.json.Stringify.valueAlloc(allocator, .{
        .source_path = absolute_source,
        .immutable = true,
    }, .{});
    defer allocator.free(source_config);
    try Dir.cwd().writeFile(io, .{ .sub_path = source_config_path, .data = source_config });
    const absolute_source_config = try Dir.cwd().realPathFileAlloc(io, source_config_path, allocator);
    defer allocator.free(absolute_source_config);

    var evidence: [debz_packages.len]DebzEvidence = undefined;
    var evidence_count: usize = 0;
    errdefer {
        for (evidence[0..evidence_count]) |*item| item.deinit(allocator);
    }

    for (&debz_packages, 0..) |package, index| {
        const transaction_dir = try std.fmt.allocPrint(allocator, "{s}/debz-{s}", .{ work_dir, package });
        defer allocator.free(transaction_dir);
        try Dir.cwd().deleteTree(io, transaction_dir);
        try Dir.cwd().createDirPath(io, transaction_dir);
        const cache = try std.fs.path.join(allocator, &.{ transaction_dir, "cache" });
        defer allocator.free(cache);
        const state = try std.fs.path.join(allocator, &.{ transaction_dir, "state" });
        defer allocator.free(state);
        try Dir.cwd().createDirPath(io, cache);
        try Dir.cwd().createDirPath(io, state);

        const absolute_cache = try Dir.cwd().realPathFileAlloc(io, cache, allocator);
        defer allocator.free(absolute_cache);
        const absolute_state = try Dir.cwd().realPathFileAlloc(io, state, allocator);
        defer allocator.free(absolute_state);
        const absolute_resolve_root = try Dir.cwd().realPathFileAlloc(io, current, allocator);
        defer allocator.free(absolute_resolve_root);
        const absolute_transaction = try Dir.cwd().realPathFileAlloc(io, transaction_dir, allocator);
        defer allocator.free(absolute_transaction);
        const absolute_dummy = try std.fs.path.join(allocator, &.{ absolute_transaction, "resolve-published-unused" });
        defer allocator.free(absolute_dummy);
        const absolute_lock = try std.fs.path.join(allocator, &.{ absolute_transaction, "exact-lock.json" });
        defer allocator.free(absolute_lock);

        const resolved = try package_family.execute(allocator, io, .{}, packageFamilyRequest(
            .resolve_lock,
            profile,
            package,
            absolute_resolve_root,
            absolute_dummy,
            absolute_source_config,
            absolute_keyring,
            absolute_cache,
            absolute_state,
            absolute_lock,
        ));
        try requireSucceeded(resolved);
        if (resolved.lock_path == null or !std.mem.eql(u8, resolved.lock_path.?, absolute_lock))
            return error.DebzLockMismatch;

        const stage = try std.fmt.allocPrint(allocator, "{s}/root-stage-{d}", .{ work_dir, index });
        defer allocator.free(stage);
        const published = try std.fmt.allocPrint(allocator, "{s}/root-debz-{d}", .{ work_dir, index });
        defer allocator.free(published);
        try Dir.cwd().deleteTree(io, stage);
        try Dir.cwd().deleteTree(io, published);
        try Dir.cwd().createDirPath(io, stage);
        const current_contents = try std.fmt.allocPrint(allocator, "{s}/.", .{current});
        defer allocator.free(current_contents);
        const restricted_permissions = try copyRootStage(allocator, io, current, current_contents, stage);
        const absolute_stage = try Dir.cwd().realPathFileAlloc(io, stage, allocator);
        defer allocator.free(absolute_stage);
        const absolute_published = if (std.fs.path.isAbsolute(published))
            try allocator.dupe(u8, published)
        else blk: {
            const absolute_work = try Dir.cwd().realPathFileAlloc(io, work_dir, allocator);
            defer allocator.free(absolute_work);
            break :blk try std.fs.path.join(allocator, &.{ absolute_work, std.fs.path.basename(published) });
        };
        var published_transferred = false;
        errdefer if (!published_transferred) allocator.free(absolute_published);

        const customized = try package_family.execute(allocator, io, .{}, packageFamilyRequest(
            .customize,
            profile,
            package,
            absolute_stage,
            absolute_published,
            absolute_source_config,
            absolute_keyring,
            absolute_cache,
            absolute_state,
            absolute_lock,
        ));
        try requireSucceeded(customized);
        if (!customized.published or customized.provenance_path == null)
            return error.DebzProvenanceMissing;
        defer allocator.free(customized.provenance_path.?);
        try restoreRestrictedRootEntry(allocator, io, absolute_published, restricted_permissions);
        const expected_provenance = try std.fs.path.join(allocator, &.{ absolute_state, "transaction-result.json" });
        defer allocator.free(expected_provenance);
        if (!std.mem.eql(u8, customized.provenance_path.?, expected_provenance))
            return error.DebzProvenanceMismatch;

        const lock_metadata = try artifact_pipeline.hashFile(io, absolute_lock);
        const provenance_metadata = try artifact_pipeline.hashFile(io, expected_provenance);
        const lock_filename = try std.fmt.allocPrint(
            allocator,
            "debz-exact-lock-{s}-{s}.json",
            .{ package, profile.ubuntu_architecture },
        );
        defer allocator.free(lock_filename);
        const provenance_filename = try std.fmt.allocPrint(
            allocator,
            "debz-transaction-provenance-{s}-{s}.json",
            .{ package, profile.ubuntu_architecture },
        );
        defer allocator.free(provenance_filename);
        const stable_lock = try std.fs.path.join(allocator, &.{ provenance_dir, lock_filename });
        defer allocator.free(stable_lock);
        const stable_provenance = try std.fs.path.join(allocator, &.{ provenance_dir, provenance_filename });
        defer allocator.free(stable_provenance);
        try Dir.cwd().copyFile(absolute_lock, Dir.cwd(), stable_lock, io, .{});
        try Dir.cwd().copyFile(expected_provenance, Dir.cwd(), stable_provenance, io, .{});
        evidence[index] = .{
            .package = package,
            .lock_path = try allocator.dupe(u8, stable_lock),
            .lock_sha256 = artifact_pipeline.formatSha256(lock_metadata.sha256),
            .lock_digest_sha256 = try requireJsonSha256Field(allocator, io, stable_lock, "digest_sha256"),
            .provenance_path = try allocator.dupe(u8, stable_provenance),
            .provenance_sha256 = artifact_pipeline.formatSha256(provenance_metadata.sha256),
            .provenance_digest_sha256 = try requireJsonSha256Field(allocator, io, stable_provenance, "digest_sha256"),
            .provenance_lock_sha256 = try requireJsonSha256Field(allocator, io, stable_provenance, "lock_sha256"),
        };
        if (!std.mem.eql(u8, &evidence[index].lock_digest_sha256, &evidence[index].provenance_lock_sha256))
            return error.DebzProvenanceLockMismatch;
        evidence_count += 1;
        allocator.free(current);
        current = absolute_published;
        published_transferred = true;
    }

    const release_name = try customizeOfflineRoot(
        allocator,
        io,
        profile,
        current,
        provenance_dir,
    );
    allocator.free(release_name);
    try native_root.filesystem.importHostTreeWithManifest(current, .{}, &host_manifest);
    try native_root.filesystem.applyCustomization(.{
        .services = &.{
            .{ .name = "systemd-networkd.service", .state = .enabled },
            .{ .name = "systemd-resolved.service", .state = .enabled },
            .{ .name = "ssh.service", .state = .enabled },
            .{ .name = "walinuxagent.service", .state = .enabled },
        },
    }, 0);
    try native_root.filesystem.generalize(.{ .azure = .{
        .reset_hostname = false,
        .clear_machine_id = false,
        .remove_ssh_host_keys = false,
        .remove_agent_state = false,
        .remove_dhcp_leases = false,
        .remove_resolver_configuration = false,
        .clear_random_seed = false,
        .remove_users = &.{"ubuntu"},
    } });
    if (native_root.filesystem.stat("/home/ubuntu")) |_| {
        return error.UserCleanupIncomplete;
    } else |err| switch (err) {
        error.PathNotFound => {},
        else => return error.UserCleanupIncomplete,
    }
    try native_root.finish();
    return .{ .root_path = current, .evidence = evidence };
}

const restricted_root_entry = "var/lib/snapd/void";

fn copyRootStage(
    allocator: Allocator,
    io: Io,
    source_root: []const u8,
    source_contents: []const u8,
    stage: []const u8,
) !?std.Io.File.Permissions {
    _ = source_contents;
    const source_entry = try std.fs.path.join(allocator, &.{ source_root, restricted_root_entry });
    defer allocator.free(source_entry);
    const original = Dir.cwd().statFile(io, source_entry, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            try copyHostTree(allocator, io, source_root, stage);
            return null;
        },
        else => return err,
    };
    const required_mode: std.posix.mode_t = if (original.kind == .directory) 0o500 else 0o400;
    const readable = std.Io.File.Permissions.fromMode(original.permissions.toMode() | required_mode);
    const needs_readable = original.permissions.toMode() & required_mode != required_mode;
    if (needs_readable) try Dir.cwd().setFilePermissions(io, source_entry, readable, .{});
    defer if (needs_readable) Dir.cwd().setFilePermissions(io, source_entry, original.permissions, .{}) catch {};
    try copyHostTree(allocator, io, source_root, stage);
    if (needs_readable) {
        const stage_entry = try std.fs.path.join(allocator, &.{ stage, restricted_root_entry });
        defer allocator.free(stage_entry);
        try Dir.cwd().setFilePermissions(io, stage_entry, readable, .{});
        return original.permissions;
    }
    return null;
}

fn copyHostTree(
    allocator: Allocator,
    io: Io,
    source: []const u8,
    destination: []const u8,
) !void {
    try Dir.cwd().createDirPath(io, destination);
    const directory_stat = try Dir.cwd().statFile(io, source, .{});
    const original_permissions = directory_stat.permissions;
    if (directory_stat.permissions.toMode() & 0o700 != 0o700) {
        try Dir.cwd().setFilePermissions(
            io,
            source,
            std.Io.File.Permissions.fromMode(directory_stat.permissions.toMode() | 0o700),
            .{},
        );
        defer Dir.cwd().setFilePermissions(io, source, original_permissions, .{}) catch {};
    }
    var directory = try Dir.cwd().openDir(io, source, .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        const source_path = try std.fs.path.join(allocator, &.{ source, entry.name });
        defer allocator.free(source_path);
        const destination_path = try std.fs.path.join(allocator, &.{ destination, entry.name });
        defer allocator.free(destination_path);
        switch (entry.kind) {
            .directory => try copyHostTree(allocator, io, source_path, destination_path),
            .file => {
                const source_stat = try Dir.cwd().statFile(io, source_path, .{});
                try Dir.cwd().copyFile(
                    source_path,
                    Dir.cwd(),
                    destination_path,
                    io,
                    .{ .permissions = .fromMode(source_stat.permissions.toMode() | 0o400) },
                );
            },
            .sym_link => {
                var target: [4096]u8 = undefined;
                const length = try Dir.cwd().readLink(io, source_path, &target);
                try Dir.cwd().symLink(io, target[0..length], destination_path, .{});
            },
            else => {},
        }
    }
}

fn restoreRestrictedRootEntry(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    permissions: ?std.Io.File.Permissions,
) !void {
    const value = permissions orelse return;
    const path = try std.fs.path.join(allocator, &.{ root, restricted_root_entry });
    defer allocator.free(path);
    try Dir.cwd().setFilePermissions(io, path, value, .{});
}

fn writeProvenance(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    profile: *const Profile,
    source_digest: [64]u8,
    evidence: *const [debz_packages.len]DebzEvidence,
) !void {
    const document = try std.fmt.allocPrint(allocator,
        \\{{"schema":1,"type":"vmiz-ubuntu2604-build-provenance","architecture":"{s}","release":"26.04","snapshot":{{"id":"release-{s}","base_url":"{s}/"}},"canonical_key_fingerprint":"{s}","sha256sums_signature_verified":true,"artifacts":{{"sha256sums":{{"filename":"SHA256SUMS","sha256":"{s}"}},"sha256sums_signature":{{"filename":"SHA256SUMS.gpg","sha256":"{s}"}},"source_image":{{"filename":"{s}","sha256":"{s}"}},"image_manifest":{{"filename":"{s}","sha256":"{s}"}}}},"debz":{{"api_commit":"{s}","baseline":{{"source":"canonical-image-dpkg-status","enforcement":"exact-final-closure"}},"transactions":[{{"package":"{s}","exact_lock":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}"}},"transaction_provenance":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}","lock_sha256":"{s}"}}}},{{"package":"{s}","exact_lock":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}"}},"transaction_provenance":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}","lock_sha256":"{s}"}}}}]}}}}
        \\
    , .{
        @tagName(profile.architecture),
        release,
        release_base,
        canonical_fingerprint_lower,
        sums_sha256,
        sums_signature_sha256,
        profile.source_name,
        source_digest,
        profile.manifest_name,
        profile.manifest_sha256,
        package_family.debz_api_commit,
        evidence[0].package,
        std.fs.path.basename(evidence[0].lock_path),
        evidence[0].lock_sha256,
        evidence[0].lock_digest_sha256,
        std.fs.path.basename(evidence[0].provenance_path),
        evidence[0].provenance_sha256,
        evidence[0].provenance_digest_sha256,
        evidence[0].provenance_lock_sha256,
        evidence[1].package,
        std.fs.path.basename(evidence[1].lock_path),
        evidence[1].lock_sha256,
        evidence[1].lock_digest_sha256,
        std.fs.path.basename(evidence[1].provenance_path),
        evidence[1].provenance_sha256,
        evidence[1].provenance_digest_sha256,
        evidence[1].provenance_lock_sha256,
    });
    defer allocator.free(document);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = document });
}

fn writeSigningProvenance(
    allocator: Allocator,
    io: Io,
    provenance_dir: []const u8,
    profile: *const Profile,
    config: uki_signing.Config,
    certificate: *const uki_signing.Certificate,
    signed: *const uki_signing.SignedUki,
) !void {
    const metadata = signed.provider_metadata;
    var provider_fingerprint: [64]u8 = undefined;
    const provider = if (metadata) |value| blk: {
        provider_fingerprint = artifact_pipeline.formatSha256(value.signing_certificate_sha256);
        break :blk .{
            .name = value.provider,
            .endpoint = value.endpoint,
            .account = value.account,
            .profile = value.profile,
            .signing_certificate_sha256 = @as([]const u8, &provider_fingerprint),
        };
    } else null;
    const unsigned_hex = artifact_pipeline.formatSha256(signed.unsigned_sha256);
    const signed_hex = artifact_pipeline.formatSha256(signed.signed_sha256);
    const operation_id: ?[]const u8 = if (metadata) |value| value.operation_id else null;
    const signing_fingerprint: ?[]const u8 = if (metadata != null) &provider_fingerprint else null;
    const fallback_path = try std.fmt.allocPrint(allocator, "EFI/BOOT/{s}", .{profile.efi_fallback});
    defer allocator.free(fallback_path);
    const named_path = try std.fmt.allocPrint(allocator, "EFI/Linux/{s}", .{profile.efi_fallback});
    defer allocator.free(named_path);
    const Record = struct {
        path: []const u8,
        unsigned_sha256: []const u8,
        signed_sha256: []const u8,
        finalized_sha256: []const u8,
        signed_bytes: usize,
        signing_operation_id: ?[]const u8,
        signing_certificate_sha256: ?[]const u8,
    };
    const records = [_]Record{
        .{
            .path = named_path,
            .unsigned_sha256 = &unsigned_hex,
            .signed_sha256 = &signed_hex,
            .finalized_sha256 = &signed_hex,
            .signed_bytes = signed.bytes.len,
            .signing_operation_id = operation_id,
            .signing_certificate_sha256 = signing_fingerprint,
        },
        .{
            .path = fallback_path,
            .unsigned_sha256 = &unsigned_hex,
            .signed_sha256 = &signed_hex,
            .finalized_sha256 = &signed_hex,
            .signed_bytes = signed.bytes.len,
            .signing_operation_id = operation_id,
            .signing_certificate_sha256 = signing_fingerprint,
        },
    };
    const certificate_hex = artifact_pipeline.formatSha256(certificate.sha256);
    const certificate_base64 = try allocator.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(certificate.der.len),
    );
    defer allocator.free(certificate_base64);
    _ = std.base64.standard.Encoder.encode(certificate_base64, certificate.der);
    const document = .{
        .schema = 1,
        .type = "vmiz-uki-signing",
        .architecture = @tagName(profile.architecture),
        .flavor = "full",
        .signer_mode = config.mode.name(),
        .certificate_sha256 = @as([]const u8, &certificate_hex),
        .certificate_der_base64 = certificate_base64,
        .certificate_details = certificate.details,
        .provider = provider,
        .signature_verification = "success",
        .files = &records,
    };
    const json = try std.json.Stringify.valueAlloc(allocator, document, .{ .whitespace = .indent_2 });
    defer allocator.free(json);
    const filename = try std.fmt.allocPrint(
        allocator,
        "uki-signing-full-{s}.json",
        .{@tagName(profile.architecture)},
    );
    defer allocator.free(filename);
    const path = try std.fs.path.join(allocator, &.{ provenance_dir, filename });
    defer allocator.free(path);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = json });
}

fn extractNativeBootInputs(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    work_dir: []const u8,
    extract_dir: []const u8,
    profile: *const Profile,
) ![]u8 {
    var native_root = try openNativeRoot(allocator, io, image_path, work_dir);
    defer native_root.deinit();
    const lock_bytes = try native_root.filesystem.read(
        allocator,
        "/var/lib/vmiz/ubuntu2604-package-lock.tsv",
        4 * 1024 * 1024,
    );
    defer allocator.free(lock_bytes);
    try validateExactLockRuntime(allocator, lock_bytes, profile);

    const boot_entries = try native_root.filesystem.list(allocator, "/boot", 4096);
    defer allocator.free(boot_entries);
    var release_name: ?[]u8 = null;
    for (boot_entries) |entry| {
        const name = std.fs.path.basename(entry.path);
        if (std.mem.startsWith(u8, name, "vmlinuz-") and
            std.mem.endsWith(u8, name, "-azure"))
        {
            if (release_name != null) return error.MultipleAzureKernels;
            release_name = try allocator.dupe(u8, name["vmlinuz-".len..]);
        }
    }
    const kernel_release = release_name orelse return error.AzureKernelMissing;
    errdefer allocator.free(kernel_release);
    const modules_guest = try std.fmt.allocPrint(allocator, "/lib/modules/{s}", .{kernel_release});
    defer allocator.free(modules_guest);
    const modules = try native_root.filesystem.list(allocator, modules_guest, 4096);
    defer allocator.free(modules);
    if (modules.len == 0) return error.AzureKernelModulesMissing;

    try Dir.cwd().deleteTree(io, extract_dir);
    try Dir.cwd().createDirPath(io, extract_dir);
    const kernel_guest = try std.fmt.allocPrint(allocator, "/boot/vmlinuz-{s}", .{kernel_release});
    defer allocator.free(kernel_guest);
    const initrd_guest = try std.fmt.allocPrint(allocator, "/boot/initrd.img-{s}", .{kernel_release});
    defer allocator.free(initrd_guest);
    const kernel = try native_root.filesystem.read(allocator, kernel_guest, 256 * 1024 * 1024);
    defer allocator.free(kernel);
    const initrd = try native_root.filesystem.read(allocator, initrd_guest, 256 * 1024 * 1024);
    defer allocator.free(initrd);
    const os_release = try native_root.filesystem.read(allocator, "/usr/lib/os-release", 64 * 1024);
    defer allocator.free(os_release);
    const kernel_host = try std.fmt.allocPrint(allocator, "{s}/vmlinuz-{s}", .{ extract_dir, kernel_release });
    defer allocator.free(kernel_host);
    const initrd_host = try std.fmt.allocPrint(allocator, "{s}/initrd.img-{s}", .{ extract_dir, kernel_release });
    defer allocator.free(initrd_host);
    const os_release_host = try std.fs.path.join(allocator, &.{ extract_dir, "os-release" });
    defer allocator.free(os_release_host);
    try Dir.cwd().writeFile(io, .{ .sub_path = kernel_host, .data = kernel });
    try Dir.cwd().writeFile(io, .{ .sub_path = initrd_host, .data = initrd });
    try Dir.cwd().writeFile(io, .{ .sub_path = os_release_host, .data = os_release });
    return kernel_release;
}

fn espPartition(partitions: []const vmiz.gpt.PartitionEntry) !vmiz.gpt.PartitionEntry {
    var found: ?vmiz.gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (!std.mem.eql(u8, &partition.partition_type_guid, &guid.esp)) continue;
        if (found != null) return error.AmbiguousEspPartition;
        found = partition;
    }
    return found orelse error.MissingEspPartition;
}

fn insertSignedUki(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    signed_path: []const u8,
    profile: *const Profile,
) !void {
    var image = try vmiz.Image.openPath(io, image_path);
    defer image.close(io);
    const parsed = try vmiz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    const esp = try espPartition(parsed.partitions);
    var filesystem = try vmiz.fat32.open(&image, io, .{
        .offset = esp.first_lba * vmiz.gpt.sector_size,
        .length = (esp.last_lba - esp.first_lba + 1) * vmiz.gpt.sector_size,
    });
    try filesystem.createDir(io, "EFI/Linux");
    try filesystem.createDir(io, "EFI/BOOT");
    const signed = try Dir.cwd().readFileAlloc(io, signed_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(signed);
    const named = try std.fmt.allocPrint(allocator, "EFI/Linux/{s}", .{profile.efi_fallback});
    defer allocator.free(named);
    const fallback = try std.fmt.allocPrint(allocator, "EFI/BOOT/{s}", .{profile.efi_fallback});
    defer allocator.free(fallback);
    filesystem.deletePath(io, named) catch |err| switch (err) {
        error.PathNotFound => {},
        else => return err,
    };
    filesystem.deletePath(io, fallback) catch |err| switch (err) {
        error.PathNotFound => {},
        else => return err,
    };
    try filesystem.writeFile(io, named, signed);
    try filesystem.writeFile(io, fallback, signed);
}

fn validateFinalNativeImage(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    work_dir: []const u8,
    profile: *const Profile,
) !void {
    var image = try vmiz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    const parsed = try vmiz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    const esp = try espPartition(parsed.partitions);
    var filesystem = try vmiz.fat32.open(&image, io, .{
        .offset = esp.first_lba * vmiz.gpt.sector_size,
        .length = (esp.last_lba - esp.first_lba + 1) * vmiz.gpt.sector_size,
    });
    const fallback = try std.fmt.allocPrint(allocator, "EFI/BOOT/{s}", .{profile.efi_fallback});
    defer allocator.free(fallback);
    const named = try std.fmt.allocPrint(allocator, "EFI/Linux/{s}", .{profile.efi_fallback});
    defer allocator.free(named);
    const fallback_bytes = try filesystem.readFileAlloc(io, allocator, fallback);
    defer allocator.free(fallback_bytes);
    const named_bytes = try filesystem.readFileAlloc(io, allocator, named);
    defer allocator.free(named_bytes);
    try validateUkiBytes(fallback_bytes, named_bytes, profile);
    _ = work_dir;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = parseArgs(argv[1..]) catch |err| {
        std.debug.print("error: {s}\n{s}", .{ @errorName(err), help });
        std.process.exit(1);
    };
    const architecture = args.architecture orelse {
        std.debug.print("error: --architecture is required\n", .{});
        std.process.exit(1);
    };
    const profile = profileFor(architecture);
    const work_dir = args.work_dir orelse profile.work_dir;
    const output = args.output orelse profile.output;
    try Dir.cwd().createDirPath(io, work_dir);
    const allocated_provenance_dir = if (args.provenance_dir == null)
        try std.fs.path.join(allocator, &.{ work_dir, "internal-provenance" })
    else
        null;
    defer if (allocated_provenance_dir) |path| allocator.free(path);
    const provenance_dir = args.provenance_dir orelse allocated_provenance_dir.?;
    try Dir.cwd().deleteTree(io, provenance_dir);
    try Dir.cwd().createDirPath(io, provenance_dir);

    var https = artifact_pipeline.NativeHttpsDownloader.init(allocator, io);
    defer https.deinit();
    const downloader = https.downloader();

    const sums_path = try std.fs.path.join(allocator, &.{ work_dir, "SHA256SUMS" });
    defer allocator.free(sums_path);
    const signature_path = try std.fs.path.join(allocator, &.{ work_dir, "SHA256SUMS.gpg" });
    defer allocator.free(signature_path);
    try acquire(allocator, io, release_base ++ "/SHA256SUMS", sums_path, sums_sha256, sums_max_size, downloader);
    try acquire(allocator, io, release_base ++ "/SHA256SUMS.gpg", signature_path, sums_signature_sha256, signature_max_size, downloader);
    try verifyCanonicalPublication(allocator, io, sums_path, signature_path);
    const sums = try Dir.cwd().readFileAlloc(io, sums_path, allocator, .limited(sums_max_size));
    defer allocator.free(sums);
    try requireSha256SumsEntry(sums, profile.source_name, profile.source_sha256);
    try requireSha256SumsEntry(sums, profile.manifest_name, profile.manifest_sha256);

    const manifest_path = try std.fs.path.join(allocator, &.{ work_dir, profile.manifest_name });
    defer allocator.free(manifest_path);
    const manifest_url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ release_base, profile.manifest_name });
    defer allocator.free(manifest_url);
    try acquire(allocator, io, manifest_url, manifest_path, profile.manifest_sha256, manifest_max_size, downloader);
    const manifest = try Dir.cwd().readFileAlloc(io, manifest_path, allocator, .limited(manifest_max_size));
    defer allocator.free(manifest);
    try validateManifestRuntime(allocator, manifest, profile);
    const provenance_sums = try std.fs.path.join(allocator, &.{ provenance_dir, "SHA256SUMS" });
    defer allocator.free(provenance_sums);
    const provenance_signature = try std.fs.path.join(allocator, &.{ provenance_dir, "SHA256SUMS.gpg" });
    defer allocator.free(provenance_signature);
    const provenance_manifest = try std.fs.path.join(allocator, &.{ provenance_dir, profile.manifest_name });
    defer allocator.free(provenance_manifest);
    try copyBoundedFile(allocator, io, sums_path, provenance_sums, sums_max_size);
    try copyBoundedFile(allocator, io, signature_path, provenance_signature, signature_max_size);
    try copyBoundedFile(allocator, io, manifest_path, provenance_manifest, manifest_max_size);

    const source_path = if (args.source) |source| source else blk: {
        const path = try std.fs.path.join(allocator, &.{ work_dir, profile.source_name });
        const url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ release_base, profile.source_name });
        defer allocator.free(url);
        try acquire(allocator, io, url, path, profile.source_sha256, source_max_size, downloader);
        break :blk path;
    };
    defer if (args.source == null) allocator.free(source_path);
    const source_metadata = try artifact_pipeline.hashFile(io, source_path);
    if (!std.mem.eql(u8, &source_metadata.sha256, &(try artifact_pipeline.parseSha256(profile.source_sha256))))
        return error.ChecksumMismatch;
    if (args.preflight_only) return;

    for (&[_][]const u8{ "ukify", "sbverify", "unshare", "mount", "umount", "chroot", "mknod", "timeout", "setsid" }) |tool|
        try requireTool(allocator, io, tool);
    const config = try signingConfig(args);

    const mutable = try std.fs.path.join(allocator, &.{ work_dir, "customized.qcow2" });
    defer allocator.free(mutable);
    Dir.cwd().deleteFile(io, mutable) catch {};
    var source_image = try vmiz.Image.openPathReadOnlyStandalone(io, source_path);
    defer source_image.close(io);
    var mutable_image = try vmiz.Image.createExclusive(
        io,
        mutable,
        .qcow2,
        source_image.virtual_size,
        .{},
    );
    try vmiz.copyAll(io, source_image, &mutable_image, allocator);
    mutable_image.close(io);
    _ = try vmiz.root_resize.growExistingQcow2(
        allocator,
        io,
        mutable,
        .{
            .target_size = args.size,
            .filesystem_label = vmiz.root_resize.default_filesystem_label,
        },
    );
    var debz_customization = try customizeRootWithDebz(allocator, io, profile, mutable, work_dir, provenance_dir);
    defer debz_customization.deinit(allocator);

    const extract_dir = try std.fs.path.join(allocator, &.{ work_dir, "uki-input" });
    defer allocator.free(extract_dir);
    const release_name = try extractNativeBootInputs(
        allocator,
        io,
        mutable,
        work_dir,
        extract_dir,
        profile,
    );
    defer allocator.free(release_name);

    const kernel_host = try std.fmt.allocPrint(allocator, "{s}/vmlinuz-{s}", .{ extract_dir, release_name });
    defer allocator.free(kernel_host);
    const initrd_host = try std.fmt.allocPrint(allocator, "{s}/initrd.img-{s}", .{ extract_dir, release_name });
    defer allocator.free(initrd_host);
    const os_release_host = try std.fs.path.join(allocator, &.{ extract_dir, "os-release" });
    defer allocator.free(os_release_host);
    const os_release_argument = try std.fmt.allocPrint(allocator, "@{s}", .{os_release_host});
    defer allocator.free(os_release_argument);
    const root_partition_guid = try rootPartitionGuid(allocator, io, mutable, profile);
    const cmdline = try ukiCmdline(allocator, root_partition_guid, profile);
    defer allocator.free(cmdline);
    const unsigned_uki = try std.fs.path.join(allocator, &.{ work_dir, "ubuntu2604.unsigned.efi" });
    defer allocator.free(unsigned_uki);
    try run(allocator, io, &.{
        "ukify",        "build",
        "--linux",      kernel_host,
        "--initrd",     initrd_host,
        "--os-release", os_release_argument,
        "--cmdline",    cmdline,
        "--output",     unsigned_uki,
    });

    const signing_scratch = try std.fs.path.join(allocator, &.{ work_dir, "signing" });
    defer allocator.free(signing_scratch);
    try uki_signing.prepareScratchDirectory(io, signing_scratch);
    var certificate = try uki_signing.prepareCertificate(allocator, io, config, signing_scratch);
    defer certificate.deinit(allocator);
    const unsigned_bytes = try Dir.cwd().readFileAlloc(io, unsigned_uki, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(unsigned_bytes);
    var signed = try uki_signing.signUkiAlloc(
        allocator,
        io,
        config,
        signing_scratch,
        init.environ_map,
        0,
        @tagName(profile.architecture),
        "full",
        unsigned_bytes,
    );
    defer signed.deinit(allocator);
    const signed_path = try std.fs.path.join(allocator, &.{ work_dir, profile.efi_fallback });
    defer allocator.free(signed_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = signed_path, .data = signed.bytes });
    try uki_signing.verifyBytes(allocator, io, config, signing_scratch, 0, signed.bytes);

    try insertSignedUki(allocator, io, mutable, signed_path, profile);
    try finalizeCompressedQcow2(allocator, io, mutable, output);
    try validateFinalQcow2(io, output, args.size);
    try validateFinalNativeImage(allocator, io, output, work_dir, profile);
    var final_root = try openNativeRoot(allocator, io, output, work_dir);
    defer final_root.deinit();
    const os_release = try final_root.filesystem.read(allocator, "/etc/os-release", 64 * 1024);
    defer allocator.free(os_release);
    if (std.mem.indexOf(u8, os_release, "VERSION_ID=\"26.04\"") == null) return error.WrongGuestRelease;
    const final_lock = try final_root.filesystem.read(allocator, "/var/lib/vmiz/ubuntu2604-package-lock.tsv", 4 * 1024 * 1024);
    defer allocator.free(final_lock);
    try validateExactLockRuntime(allocator, final_lock, profile);
    if (try peMachine(signed.bytes) != profile.pe_machine) return error.WrongUkiArchitecture;
    try writeSigningProvenance(allocator, io, provenance_dir, profile, config, &certificate, &signed);

    const provenance_path = try std.fs.path.join(allocator, &.{ provenance_dir, "ubuntu2604-build-provenance.json" });
    defer allocator.free(provenance_path);
    try writeProvenance(
        allocator,
        io,
        provenance_path,
        profile,
        artifact_pipeline.formatSha256(source_metadata.sha256),
        &debz_customization.evidence,
    );
}

fn findAzureKernelRelease(listing: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, listing, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "vmlinuz-") and std.mem.endsWith(u8, line, "-azure"))
            return line["vmlinuz-".len..];
    }
    return null;
}

const ProfileNativeHttpsTransport = struct {
    expected_names: []const []const u8,
    calls: usize = 0,

    fn get(
        context_ptr: ?*anyopaque,
        _: Allocator,
        _: Io,
        url: []const u8,
        max_size: u64,
        output: *Io.Writer,
    ) !artifact_pipeline.NativeHttpsResponse {
        const context: *ProfileNativeHttpsTransport = @ptrCast(@alignCast(context_ptr.?));
        if (context.calls == context.expected_names.len or
            !std.mem.endsWith(u8, url, context.expected_names[context.calls]) or
            max_size != 1024)
        {
            return error.UnexpectedProfileAcquisition;
        }
        context.calls += 1;
        try output.writeAll("profile artifact\n");
        return .{
            .status = 200,
            .content_length = "profile artifact\n".len,
        };
    }
};

test "profiles pin immutable official sources for both architectures" {
    try std.testing.expectEqual(@as(usize, 2), profiles.len);
    for (&profiles) |*profile| {
        _ = try artifact_pipeline.parseSha256(profile.source_sha256);
        _ = try artifact_pipeline.parseSha256(profile.manifest_sha256);
        try std.testing.expect(std.mem.indexOf(u8, profile.source_name, "26.04") != null);
    }
    try std.testing.expectEqual(@as(u64, 5 * 1024 * 1024 * 1024), default_virtual_size);
    try std.testing.expectEqual(@as(u32, 0), profiles[0].root_partition_table_index);
    try std.testing.expectEqual(@as(u32, 0), profiles[1].root_partition_table_index);
    try std.testing.expectEqualSlices(u8, &guid.linux_root_x86_64, &profiles[0].root_partition_type_guid);
    try std.testing.expectEqualSlices(u8, &guid.linux_root_aarch64, &profiles[1].root_partition_type_guid);
}

test "both architecture profiles acquire through the shared native HTTPS downloader" {
    const io = std.testing.io;
    const payload = "profile artifact\n";
    const expected_digest = artifact_pipeline.sha256Bytes(payload);
    const digest = artifact_pipeline.formatSha256(expected_digest);
    var transport = ProfileNativeHttpsTransport{
        .expected_names = &.{ profiles[0].source_name, profiles[1].source_name },
    };
    var https = artifact_pipeline.NativeHttpsDownloader{
        .transport = .{ .context = &transport, .getFn = ProfileNativeHttpsTransport.get },
    };
    for (&profiles, 0..) |profile, index| {
        const output_path = switch (index) {
            0 => "test-ubuntu2604-native-amd64.img",
            1 => "test-ubuntu2604-native-arm64.img",
            else => unreachable,
        };
        Dir.cwd().deleteFile(io, output_path) catch {};
        defer Dir.cwd().deleteFile(io, output_path) catch {};
        const url = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}/{s}",
            .{ release_base, profile.source_name },
        );
        defer std.testing.allocator.free(url);
        try acquire(
            std.testing.allocator,
            io,
            url,
            output_path,
            &digest,
            1024,
            https.downloader(),
        );
        const metadata = try artifact_pipeline.hashFile(io, output_path);
        try std.testing.expectEqualSlices(u8, &expected_digest, &metadata.sha256);
    }
    try std.testing.expectEqual(profiles.len, transport.calls);
}

test "native OpenPGP verifies the pinned Canonical release fixture" {
    const key = try parseCanonicalPublicKey(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &canonical_fingerprint_bytes, &key.fingerprint);
    try verifyOpenPgpDetachedSignature(
        std.testing.allocator,
        std.testing.io,
        @embedFile("fixtures/openpgp/canonical-SHA256SUMS"),
        @embedFile("fixtures/openpgp/canonical-SHA256SUMS.gpg"),
        &key,
    );
}

test "native OpenPGP cross-validates an independently generated RSA fixture" {
    const armored_key = @embedFile("fixtures/openpgp/cross-validation-public-key.asc");
    const packet_key = try decodeOpenPgpArmorAlloc(
        std.testing.allocator,
        armored_key,
        .public_key,
        public_key_max_size,
    );
    defer std.testing.allocator.free(packet_key);
    const key = try parseSingleOpenPgpPublicKeyPacket(packet_key);
    try verifyOpenPgpDetachedSignature(
        std.testing.allocator,
        std.testing.io,
        @embedFile("fixtures/openpgp/cross-validation-message.txt"),
        @embedFile("fixtures/openpgp/cross-validation-signature.asc"),
        &key,
    );
}

test "native OpenPGP verification rejects modified and ambiguous inputs" {
    const armored_key = @embedFile("fixtures/openpgp/cross-validation-public-key.asc");
    const packet_key = try decodeOpenPgpArmorAlloc(
        std.testing.allocator,
        armored_key,
        .public_key,
        public_key_max_size,
    );
    defer std.testing.allocator.free(packet_key);
    const key = try parseSingleOpenPgpPublicKeyPacket(packet_key);
    const message = @embedFile("fixtures/openpgp/cross-validation-message.txt");
    const armored_signature = @embedFile("fixtures/openpgp/cross-validation-signature.asc");
    const packet_signature = try decodeOpenPgpArmorAlloc(
        std.testing.allocator,
        armored_signature,
        .signature,
        signature_max_size,
    );
    defer std.testing.allocator.free(packet_signature);

    var modified_message = try std.testing.allocator.dupe(u8, message);
    defer std.testing.allocator.free(modified_message);
    modified_message[0] ^= 1;
    try std.testing.expectError(
        error.OpenPgpSignatureHashPrefixMismatch,
        verifyOpenPgpDetachedSignature(std.testing.allocator, std.testing.io, modified_message, armored_signature, &key),
    );

    var modified_signature = try std.testing.allocator.dupe(u8, packet_signature);
    defer std.testing.allocator.free(modified_signature);
    modified_signature[modified_signature.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSignature,
        verifyOpenPgpDetachedSignature(std.testing.allocator, std.testing.io, message, modified_signature, &key),
    );

    var unsupported = try std.testing.allocator.dupe(u8, packet_signature);
    defer std.testing.allocator.free(unsupported);
    unsupported[5] = 3;
    try std.testing.expectError(
        error.UnsupportedOpenPgpDetachedSignature,
        verifyOpenPgpDetachedSignature(std.testing.allocator, std.testing.io, message, unsupported, &key),
    );

    const ambiguous = try std.testing.allocator.alloc(u8, packet_signature.len + 2);
    defer std.testing.allocator.free(ambiguous);
    @memcpy(ambiguous[0..packet_signature.len], packet_signature);
    ambiguous[packet_signature.len] = 0xc2;
    ambiguous[packet_signature.len + 1] = 0;
    try std.testing.expectError(
        error.AmbiguousOpenPgpDetachedSignature,
        verifyOpenPgpDetachedSignature(std.testing.allocator, std.testing.io, message, ambiguous, &key),
    );

    var weak_key = try std.testing.allocator.dupe(u8, packet_key);
    defer std.testing.allocator.free(weak_key);
    weak_key[8] = 3;
    try std.testing.expectError(error.UnsupportedOpenPgpPublicKeyAlgorithm, parseSingleOpenPgpPublicKeyPacket(weak_key));

    const canonical_key = try parseCanonicalPublicKey(std.testing.allocator);
    try std.testing.expectError(
        error.InvalidOpenPgpIssuer,
        verifyOpenPgpDetachedSignature(std.testing.allocator, std.testing.io, message, armored_signature, &canonical_key),
    );
}

test "native OpenPGP parsers reject every fixture truncation" {
    const allocator = std.testing.allocator;
    const armored_key = @embedFile("fixtures/openpgp/cross-validation-public-key.asc");
    const armored_signature = @embedFile("fixtures/openpgp/cross-validation-signature.asc");

    var cut: usize = 0;
    while (cut < armored_key.len) : (cut += 1) {
        if (decodeOpenPgpArmorAlloc(allocator, armored_key[0..cut], .public_key, public_key_max_size)) |decoded| {
            defer allocator.free(decoded);
            return error.TruncatedOpenPgpArmorAccepted;
        } else |_| {}
    }
    cut = 0;
    while (cut < armored_signature.len) : (cut += 1) {
        if (decodeOpenPgpArmorAlloc(allocator, armored_signature[0..cut], .signature, signature_max_size)) |decoded| {
            defer allocator.free(decoded);
            return error.TruncatedOpenPgpArmorAccepted;
        } else |_| {}
    }

    const packet_key = try decodeOpenPgpArmorAlloc(allocator, armored_key, .public_key, public_key_max_size);
    defer allocator.free(packet_key);
    const key = try parseSingleOpenPgpPublicKeyPacket(packet_key);
    cut = 0;
    while (cut < packet_key.len) : (cut += 1) {
        if (parseSingleOpenPgpPublicKeyPacket(packet_key[0..cut])) |_| {
            return error.TruncatedOpenPgpPublicKeyAccepted;
        } else |_| {}
    }

    const packet_signature = try decodeOpenPgpArmorAlloc(allocator, armored_signature, .signature, signature_max_size);
    defer allocator.free(packet_signature);
    const message = @embedFile("fixtures/openpgp/cross-validation-message.txt");
    cut = 0;
    while (cut < packet_signature.len) : (cut += 1) {
        if (verifyOpenPgpDetachedSignature(allocator, std.testing.io, message, packet_signature[0..cut], &key)) |_| {
            return error.TruncatedOpenPgpSignatureAccepted;
        } else |_| {}
    }
}

test "package-family resolve and customize requests are exact-lock operations" {
    const amd64 = packageFamilyRequest(
        .resolve_lock,
        profileFor(.x86_64),
        "linux-azure",
        "/root-stage",
        "/published",
        "/inputs/ubuntu.sources",
        "/inputs/ubuntu.gpg",
        "/cache",
        "/state",
        "/state/linux-azure.lock",
    );
    try std.testing.expectEqual(package_family.Family.debian, amd64.family);
    try std.testing.expectEqual(package_family.Distribution.ubuntu_26_04, amd64.distribution);
    try std.testing.expectEqual(package_family.Operation.resolve_lock, amd64.operation);
    try std.testing.expectEqual(package_family.Architecture.amd64, amd64.inputs.architecture);
    try std.testing.expectEqual(
        package_family.InstalledBaselinePolicy.require_locked,
        amd64.inputs.installed_baseline,
    );
    try std.testing.expectEqual(@as(usize, 0), amd64.inputs.source_paths.len);
    try std.testing.expectEqualStrings("/inputs/ubuntu.sources", amd64.inputs.config_paths[0]);
    try std.testing.expectEqualStrings("/state/linux-azure.lock", amd64.inputs.lock_output_path.?);
    try std.testing.expect(amd64.inputs.lock_input_path == null);
    const arm64 = packageFamilyRequest(
        .customize,
        profileFor(.aarch64),
        "walinuxagent",
        "/root-stage",
        "/published",
        "/inputs/ubuntu.sources",
        "/inputs/ubuntu.gpg",
        "/cache",
        "/state",
        "/state/walinuxagent.lock",
    );
    try std.testing.expectEqual(package_family.Architecture.arm64, arm64.inputs.architecture);
    try std.testing.expectEqual(
        package_family.InstalledBaselinePolicy.require_locked,
        arm64.inputs.installed_baseline,
    );
    try std.testing.expectEqual(@as(usize, 0), arm64.inputs.source_paths.len);
    try std.testing.expectEqualStrings("/inputs/ubuntu.sources", arm64.inputs.config_paths[0]);
    try std.testing.expectEqualStrings("/state/walinuxagent.lock", arm64.inputs.lock_input_path.?);
    try std.testing.expect(arm64.inputs.lock_output_path == null);
}

test "root staging preserves intentionally inaccessible snapd directory" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    try temporary.dir.createDirPath(io, "source/var/lib/snapd/void");
    try temporary.dir.createDirPath(io, "stage");
    try temporary.dir.setFilePermissions(
        io,
        "source/var/lib/snapd/void",
        std.Io.File.Permissions.fromMode(0),
        .{},
    );

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    const source = try std.fs.path.join(allocator, &.{ root_buffer[0..root_length], "source" });
    defer allocator.free(source);
    const source_contents = try std.fs.path.join(allocator, &.{ source, "." });
    defer allocator.free(source_contents);
    const stage = try std.fs.path.join(allocator, &.{ root_buffer[0..root_length], "stage" });
    defer allocator.free(stage);

    const permissions = try copyRootStage(allocator, io, source, source_contents, stage);
    try std.testing.expect(permissions != null);
    try std.testing.expectEqual(
        @as(std.posix.mode_t, 0),
        (try temporary.dir.statFile(io, "source/var/lib/snapd/void", .{})).permissions.toMode() & 0o777,
    );
    try std.testing.expectEqual(
        @as(std.posix.mode_t, 0o500),
        (try temporary.dir.statFile(io, "stage/var/lib/snapd/void", .{})).permissions.toMode() & 0o777,
    );

    try restoreRestrictedRootEntry(allocator, io, stage, permissions);
    try std.testing.expectEqual(
        @as(std.posix.mode_t, 0),
        (try temporary.dir.statFile(io, "stage/var/lib/snapd/void", .{})).permissions.toMode() & 0o777,
    );
}

test "native image conversion round trips and cleans failed publication stages" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    const root = root_buffer[0..root_length];
    const raw_path = try std.fs.path.join(allocator, &.{ root, "source.raw" });
    defer allocator.free(raw_path);
    const qcow_path = try std.fs.path.join(allocator, &.{ root, "converted.qcow2" });
    defer allocator.free(qcow_path);
    const roundtrip_path = try std.fs.path.join(allocator, &.{ root, "roundtrip.raw" });
    defer allocator.free(roundtrip_path);

    var raw = try vmiz.Image.create(io, raw_path, .raw, 1024 * 1024, .{});
    try raw.pwrite(io, "native-ubuntu-builder", 4096);
    raw.close(io);
    try copyNativeImage(allocator, io, raw_path, qcow_path, .qcow2);
    try copyNativeImage(allocator, io, qcow_path, roundtrip_path, .raw);
    var roundtrip = try vmiz.Image.openPathReadOnly(io, roundtrip_path);
    defer roundtrip.close(io);
    var bytes: [21]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try roundtrip.pread(io, &bytes, 4096));
    try std.testing.expectEqualStrings("native-ubuntu-builder", &bytes);

    const blocked_destination = try std.fs.path.join(allocator, &.{ root, "blocked" });
    defer allocator.free(blocked_destination);
    try Dir.cwd().createDirPath(io, blocked_destination);
    try std.testing.expectError(
        error.IsDir,
        publishNativeQcow2(allocator, io, raw_path, blocked_destination),
    );
    const staged = try std.fmt.allocPrint(
        allocator,
        "{s}.vmiz-native-stage",
        .{blocked_destination},
    );
    defer allocator.free(staged);
    try std.testing.expectError(error.FileNotFound, Dir.cwd().statFile(io, staged, .{}));
}

test "arguments accept Ubuntu and project architecture spellings" {
    try std.testing.expectEqual(Architecture.x86_64, (try parseArgs(&.{ "--architecture", "amd64" })).architecture.?);
    try std.testing.expectEqual(Architecture.aarch64, (try parseArgs(&.{ "--architecture", "aarch64" })).architecture.?);
    try std.testing.expectEqualStrings(
        "candidate/internal-provenance",
        (try parseArgs(&.{ "--provenance-dir", "candidate/internal-provenance" })).provenance_dir.?,
    );
    try std.testing.expectError(error.ImageTooSmall, parseArgs(&.{ "--size", "4G" }));
}

test "UKI signing configuration supports local and external modes exclusively" {
    const fingerprint = "1111111111111111111111111111111111111111111111111111111111111111";
    const local = try signingConfig(.{
        .signing_certificate = "release.crt",
        .signing_certificate_sha256 = fingerprint,
        .signing_key = "release.key",
    });
    try std.testing.expectEqualStrings("local-key", local.mode.name());
    const external = try signingConfig(.{
        .signing_certificate = "release.crt",
        .signing_certificate_sha256 = fingerprint,
        .signing_command = "/usr/local/bin/sign-uki",
        .signing_command_arg = "sign",
    });
    try std.testing.expectEqualStrings("external-command", external.mode.name());
    try std.testing.expectError(error.SigningModeRequired, signingConfig(.{
        .signing_certificate = "release.crt",
        .signing_certificate_sha256 = fingerprint,
        .signing_key = "release.key",
        .signing_command = "/usr/local/bin/sign-uki",
    }));
}

test "signed source manifest contract rejects missing packages and foreign architecture" {
    const good =
        "cloud-init\t1\ncloud-guest-utils\t1\nopenssh-server\t1\nsudo\t1\nsystemd\t1\nnetplan.io\t1\nlibc6:amd64\t1\n";
    try validateManifest(good, profileFor(.x86_64));
    try std.testing.expectError(error.ForeignArchitecturePackage, validateManifest(
        good ++ "libc6:arm64\t1\n",
        profileFor(.x86_64),
    ));
    try std.testing.expectError(error.RequiredPackageMissing, validateManifest("cloud-init\t1\n", profileFor(.x86_64)));
}

test "signed checksum entries bind exact filenames and digests" {
    const digest = "1111111111111111111111111111111111111111111111111111111111111111";
    const sums = digest ++ " *ubuntu.img\n" ++
        "2222222222222222222222222222222222222222222222222222222222222222 *ubuntu.manifest\n";
    try requireSha256SumsEntry(sums, "ubuntu.img", digest);
    try std.testing.expectError(error.SignedDigestMismatch, requireSha256SumsEntry(
        sums,
        "ubuntu.img",
        "3333333333333333333333333333333333333333333333333333333333333333",
    ));
    try std.testing.expectError(error.SignedEntryMissingOrDuplicate, requireSha256SumsEntry(sums, "missing.img", digest));
    try std.testing.expectError(error.SignedEntryMissingOrDuplicate, requireSha256SumsEntry(
        sums ++ digest ++ " *ubuntu.img\n",
        "ubuntu.img",
        digest,
    ));
}

test "Azure kernel discovery is architecture-neutral and exact" {
    try std.testing.expectEqualStrings(
        "7.0.0-1001-azure",
        findAzureKernelRelease("config\nvmlinuz-7.0.0-1001-azure\n").?,
    );
    try std.testing.expect(findAzureKernelRelease("vmlinuz-7.0.0-28-generic\n") == null);
}

test "UKI cmdline binds final root PARTUUID and native serial console" {
    const root_guid = guid.parse("11111111-2222-3333-4444-555555555555");
    const x86_cmdline = try ukiCmdline(std.testing.allocator, root_guid, profileFor(.x86_64));
    defer std.testing.allocator.free(x86_cmdline);
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 console=ttyS0,115200n8",
        x86_cmdline,
    );
    const arm_cmdline = try ukiCmdline(std.testing.allocator, root_guid, profileFor(.aarch64));
    defer std.testing.allocator.free(arm_cmdline);
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 console=ttyAMA0,115200n8",
        arm_cmdline,
    );
    try std.testing.expect(std.mem.indexOf(u8, x86_cmdline, "LABEL=") == null);
    try std.testing.expect(std.mem.indexOf(u8, arm_cmdline, "ttyS0") == null);
}

test "native boot validation rejects missing modules.dep and initramfs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, ".scratch/ubuntu-native-boot-validation" });
    defer allocator.free(root_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDirPath(io, root_path);
    var root = try offline_root.Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    try root.createDirectory("/lib/modules/7.0.0-1001-azure", 0o755);
    try root.createDirectory("/boot", 0o755);
    try root.writeFile(.{
        .path = "/lib/modules/7.0.0-1001-azure/kernel",
        .source = .{ .inline_bytes = "module" },
    });
    try root.writeFile(.{
        .path = "/boot/initrd.img-7.0.0-1001-azure",
        .source = .{ .inline_bytes = "initrd" },
    });
    try std.testing.expectError(
        error.KernelModulesDependencyMissing,
        validateNativeBootArtifacts(allocator, &root, "7.0.0-1001-azure"),
    );
    try root.writeFile(.{
        .path = "/lib/modules/7.0.0-1001-azure/modules.dep",
        .source = .{ .inline_bytes = "" },
    });
    try validateNativeBootArtifacts(allocator, &root, "7.0.0-1001-azure");
    try root.remove("/lib/modules/7.0.0-1001-azure/modules.dep", false);
    try std.testing.expectError(
        error.KernelModulesDependencyMissing,
        validateNativeBootArtifacts(allocator, &root, "7.0.0-1001-azure"),
    );
    try root.writeFile(.{
        .path = "/lib/modules/7.0.0-1001-azure/modules.dep",
        .source = .{ .inline_bytes = "" },
    });
    try root.remove("/boot/initrd.img-7.0.0-1001-azure", false);
    try std.testing.expectError(
        error.InitramfsMissing,
        validateNativeBootArtifacts(allocator, &root, "7.0.0-1001-azure"),
    );
}

test "native ESP UKI validation preserves exact signed bytes and machine" {
    var uki: [0x86]u8 = @splat(0);
    @memcpy(uki[0..2], "MZ");
    std.mem.writeInt(u32, uki[0x3c..0x40], 0x80, .little);
    @memcpy(uki[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, uki[0x84..0x86], 0x8664, .little);
    try validateUkiBytes(&uki, &uki, profileFor(.x86_64));
    var different = uki;
    different[0x85] ^= 1;
    try std.testing.expectError(error.FinalUkiMissing, validateUkiBytes(&uki, &different, profileFor(.x86_64)));
    std.mem.writeInt(u16, uki[0x84..0x86], 0xaa64, .little);
    try std.testing.expectError(error.WrongUkiArchitecture, validateUkiBytes(&uki, &uki, profileFor(.x86_64)));
}

test "UKI architecture validation parses the PE machine field" {
    var x86: [0x86]u8 = @splat(0);
    @memcpy(x86[0..2], "MZ");
    std.mem.writeInt(u32, x86[0x3c..0x40], 0x80, .little);
    @memcpy(x86[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, x86[0x84..0x86], 0x8664, .little);
    try std.testing.expectEqual(@as(u16, 0x8664), try peMachine(&x86));
    std.mem.writeInt(u16, x86[0x84..0x86], 0xaa64, .little);
    try std.testing.expectEqual(@as(u16, 0xaa64), try peMachine(&x86));
    x86[0] = 0;
    try std.testing.expectError(error.InvalidPeImage, peMachine(&x86));
}

test "exact lock requires coherent Azure and provisioning packages" {
    const amd64_lock =
        "cloud-init\t26.1\tall\n" ++
        "linux-azure\t7.0\tamd64\n" ++
        "openssh-server\t10.2\tamd64\n" ++
        "walinuxagent\t2.15\tall\n";
    try validateExactLock(amd64_lock, profileFor(.x86_64));
    try std.testing.expectError(error.ForeignArchitecturePackage, validateExactLock(
        amd64_lock ++ "libc6\t2.43\tarm64\n",
        profileFor(.x86_64),
    ));
    try std.testing.expectError(error.ExactLockIncomplete, validateExactLock("linux-azure\t7.0\tamd64\n", profileFor(.x86_64)));
}

test "final native qcow2 validation covers the exact release size" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    const path = try std.fs.path.join(
        std.testing.allocator,
        &.{ root_buffer[0..root_length], "release.qcow2" },
    );
    defer std.testing.allocator.free(path);
    var image = try vmiz.Image.create(
        std.testing.io,
        path,
        .qcow2,
        default_virtual_size,
        .{},
    );
    image.close(std.testing.io);
    try validateFinalQcow2(std.testing.io, path, default_virtual_size);
    try std.testing.expectError(
        error.UnexpectedVirtualSize,
        validateFinalQcow2(std.testing.io, path, default_virtual_size - 512),
    );
}

test "production builder contains no libguestfs or qemu-img command surface" {
    const source = @embedFile("build_generalized_ubuntu2604.zig");
    const tests_begin = std.mem.indexOf(u8, source, "test \"profiles pin") orelse
        return error.TestBoundaryMissing;
    const production = source[0..tests_begin];
    for (&[_][]const u8{
        "\"libguestfs\"",
        "\"guestfish\"",
        "\"virt-resize\"",
        "\"virt-customize\"",
        "\"virt-copy-in\"",
        "\"virt-copy-out\"",
        "\"virt-cat\"",
        "\"virt-ls\"",
        "\"virt-filesystems\"",
        "\"virt-tar-in\"",
        "\"virt-tar-out\"",
        "\"supermin\"",
        "\"LIBGUESTFS_BACKEND_SETTINGS\"",
        // Acceptance #1: production finalization must not invoke qemu tooling;
        // compressed qcow2 clusters are emitted natively by vmiz.qcow2.
        "\"qemu-img\"",
        "\"qemu-utils\"",
        "\"qemu-nbd\"",
    }) |forbidden| {
        try std.testing.expect(std.mem.indexOf(u8, production, forbidden) == null);
    }
}

test "provenance binds signed source metadata and validated debz evidence" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root_buffer[0..root_length], "provenance.json" });
    defer std.testing.allocator.free(path);
    var evidence = [2]DebzEvidence{
        .{
            .package = "linux-azure",
            .lock_path = try std.testing.allocator.dupe(u8, "/state/linux.lock"),
            .lock_sha256 = @splat('1'),
            .lock_digest_sha256 = @splat('a'),
            .provenance_path = try std.testing.allocator.dupe(u8, "/state/linux.transaction.json"),
            .provenance_sha256 = @splat('2'),
            .provenance_digest_sha256 = @splat('b'),
            .provenance_lock_sha256 = @splat('a'),
        },
        .{
            .package = "walinuxagent",
            .lock_path = try std.testing.allocator.dupe(u8, "/state/waagent.lock"),
            .lock_sha256 = @splat('3'),
            .lock_digest_sha256 = @splat('c'),
            .provenance_path = try std.testing.allocator.dupe(u8, "/state/waagent.transaction.json"),
            .provenance_sha256 = @splat('4'),
            .provenance_digest_sha256 = @splat('d'),
            .provenance_lock_sha256 = @splat('c'),
        },
    };
    defer for (&evidence) |*item| item.deinit(std.testing.allocator);
    try writeProvenance(
        std.testing.allocator,
        std.testing.io,
        path,
        profileFor(.x86_64),
        @splat('5'),
        &evidence,
    );
    const document = try Dir.cwd().readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(document);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, document, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 9), parsed.value.object.count());
    try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("schema").?.integer);
    try std.testing.expectEqualStrings("vmiz-ubuntu2604-build-provenance", parsed.value.object.get("type").?.string);
    try std.testing.expectEqualStrings(
        profileFor(.x86_64).manifest_sha256,
        parsed.value.object.get("artifacts").?.object.get("image_manifest").?.object.get("sha256").?.string,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        parsed.value.object.get("debz").?.object.get("transactions").?.array.items.len,
    );
    try std.testing.expectEqual(@as(usize, 3), parsed.value.object.get("debz").?.object.count());
    try std.testing.expectEqualStrings(
        "canonical-image-dpkg-status",
        parsed.value.object.get("debz").?.object.get("baseline").?.object.get("source").?.string,
    );
    try std.testing.expectEqual(@as(usize, 4), parsed.value.object.get("artifacts").?.object.count());
}
