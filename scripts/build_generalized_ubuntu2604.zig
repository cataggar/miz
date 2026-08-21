//! Build a generalized Ubuntu 26.04 Gen2 QCOW2 image from Canonical's
//! immutable 20260731 cloud-image publication.
//!
//! The official cloud disk is the authoritative filesystem/package input.
//! Its detached signature, signer fingerprint, checksum document, image, and
//! package manifest are all pinned.  A confined libguestfs customization then
//! switches the guest to the immutable Ubuntu snapshot, installs the Azure
//! kernel/agent closure, writes an exact dpkg inventory, and generalizes the
//! machine.  The UKI is assembled and signed on the host so private signing
//! material is never copied into the guest disk.

const std = @import("std");
const vmiz = @import("vmiz");
const uki_signing = @import("uki_signing.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const artifact_pipeline = vmiz.artifact_pipeline;
const package_family = vmiz.package_family;
const guid = vmiz.guid;

const release = "20260731";
const release_base = "https://cloud-images.ubuntu.com/releases/26.04/release-" ++ release;
const snapshot_base = "https://snapshot.ubuntu.com/ubuntu/20260731T000000Z";
const canonical_fingerprint = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
const canonical_fingerprint_lower = "d2eb44626fddc30b513d5bb71a5d6c4c7db87c81";
const sums_sha256 = "d562d59dac70f68d67d00e994db5cd89e49e9d93f7f80b4cb868a5eeb057ec36";
const sums_signature_sha256 = "2bf5fae8be0c79cc30c5c10223f1d4790b6ef541240896bfe48c7ac57c3404ed";
const default_virtual_size: u64 = 5 * 1024 * 1024 * 1024;
const source_max_size: u64 = 2 * 1024 * 1024 * 1024;
const manifest_max_size: u64 = 256 * 1024;

const Architecture = enum {
    x86_64,
    aarch64,

    fn parse(value: []const u8) ?Architecture {
        if (std.mem.eql(u8, value, "x86_64") or std.mem.eql(u8, value, "amd64")) return .x86_64;
        if (std.mem.eql(u8, value, "aarch64") or std.mem.eql(u8, value, "arm64")) return .aarch64;
        return null;
    }
};

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
        .pe_machine = 0x8664,
        .root_partition_table_index = 3,
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
        .pe_machine = 0xaa64,
        .root_partition_table_index = 2,
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
) !void {
    var curl = artifact_pipeline.CurlDownloader{ .executable_path = "curl", .retries = 5 };
    _ = try artifact_pipeline.acquireVerified(allocator, io, .{
        .url = url,
        .destination_path = path,
        .expected_sha256 = try artifact_pipeline.parseSha256(sha256),
        .max_size = max_size,
    }, curl.downloader());
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

fn validateQcow2Info(allocator: Allocator, bytes: []const u8, expected_size: u64) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    const format = object.get("format") orelse return error.InvalidFinalQcow2;
    if (format != .string or !std.mem.eql(u8, format.string, "qcow2")) return error.InvalidFinalQcow2;
    if (object.get("backing-filename") != null or object.get("data-file") != null) return error.NonStandaloneQcow2;
    const virtual_size = object.get("virtual-size") orelse return error.InvalidFinalQcow2;
    if (virtual_size != .integer or virtual_size.integer != expected_size) return error.UnexpectedVirtualSize;
}

fn customizationScript(allocator: Allocator, profile: *const Profile) ![]u8 {
    _ = profile;
    return std.fmt.allocPrint(allocator,
        \\#!/bin/sh
        \\set -eux
        \\export DEBIAN_FRONTEND=noninteractive
        \\kernel="$(basename "$(readlink -f /boot/vmlinuz)")"
        \\kernel="${{kernel#vmlinuz-}}"
        \\case "$kernel" in *-azure) ;; *) echo "linux-azure did not become active" >&2; exit 1;; esac
        \\update-initramfs -c -k "$kernel"
        \\install -d -m 0755 /etc/ssh/sshd_config.d /etc/cloud/cloud.cfg.d /etc/netplan /var/lib/vmiz
        \\cat > /etc/ssh/sshd_config.d/10-vmiz-generalized.conf <<'EOF'
        \\PasswordAuthentication no
        \\KbdInteractiveAuthentication no
        \\PermitRootLogin prohibit-password
        \\EOF
        \\cat > /etc/cloud/cloud.cfg.d/90-azure.cfg <<'EOF'
        \\datasource_list: [ Azure ]
        \\datasource:
        \\  Azure:
        \\    apply_network_config: true
        \\growpart:
        \\  mode: auto
        \\  devices: ['/']
        \\resize_rootfs: true
        \\EOF
        \\cat > /etc/netplan/50-cloud-init.yaml <<'EOF'
        \\network:
        \\  version: 2
        \\  renderer: networkd
        \\  ethernets:
        \\    all:
        \\      match:
        \\        name: "e*"
        \\      dhcp4: true
        \\      dhcp6: true
        \\EOF
        \\cat > /etc/waagent.conf <<'EOF'
        \\Provisioning.Enabled=n
        \\Provisioning.Agent=auto
        \\Provisioning.DeleteRootPassword=y
        \\OS.EnableFIPS=n
        \\OS.RootDeviceScsiTimeout=300
        \\ResourceDisk.Format=n
        \\ResourceDisk.EnableSwap=n
        \\Logs.Verbose=n
        \\Extensions.Enabled=y
        \\AutoUpdate.Enabled=y
        \\EOF
        \\systemctl enable systemd-networkd.service systemd-resolved.service ssh.service walinuxagent.service
        \\ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
        \\dpkg-query -W -f='${{binary:Package}}\t${{Version}}\t${{Architecture}}\n' | LC_ALL=C sort > /var/lib/vmiz/ubuntu2604-package-lock.tsv
        \\printf '%s\n' '{s}' > /var/lib/vmiz/source-release
        \\userdel -r ubuntu 2>/dev/null || true
        \\cloud-init clean --logs
        \\rm -f /etc/machine-id
        \\: > /etc/machine-id
        \\rm -f /var/lib/dbus/machine-id /etc/ssh/ssh_host_* /var/lib/systemd/random-seed
        \\rm -rf /var/lib/cloud/* /var/lib/waagent/* /var/log/azure/* /var/log/journal/* /tmp/* /var/tmp/*
        \\sync
        \\
    , .{release});
}

fn verifyCanonicalPublication(
    allocator: Allocator,
    io: Io,
    work_dir: []const u8,
    sums_path: []const u8,
    signature_path: []const u8,
) !void {
    const gnupg = try std.fs.path.join(allocator, &.{ work_dir, "gnupg" });
    defer allocator.free(gnupg);
    try prepareCanonicalKeyring(io, gnupg);

    const key_url = try std.fmt.allocPrint(
        allocator,
        "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{s}",
        .{canonical_fingerprint},
    );
    defer allocator.free(key_url);
    const key_path = try std.fs.path.join(allocator, &.{ work_dir, "canonical-cloud-image-key.asc" });
    defer allocator.free(key_path);
    try run(allocator, io, &.{ "curl", "--fail", "--location", "--proto", "=https", "--tlsv1.2", "--output", key_path, key_url });
    try run(allocator, io, &.{ "gpg", "--batch", "--homedir", gnupg, "--import", key_path });
    const fingerprints = try capture(allocator, io, &.{ "gpg", "--batch", "--homedir", gnupg, "--with-colons", "--fingerprint", canonical_fingerprint });
    defer allocator.free(fingerprints);
    if (std.mem.indexOf(u8, fingerprints, canonical_fingerprint) == null) return error.CanonicalFingerprintMismatch;
    try run(allocator, io, &.{ "gpg", "--batch", "--homedir", gnupg, "--verify", signature_path, sums_path });
}

fn prepareCanonicalKeyring(io: Io, gnupg: []const u8) !void {
    try Dir.cwd().deleteTree(io, gnupg);
    try Dir.cwd().createDirPath(io, gnupg);
    var directory = try Dir.cwd().openDir(io, gnupg, .{ .iterate = true });
    defer directory.close(io);
    try directory.setPermissions(io, .fromMode(0o700));
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

fn extractGuestRoot(
    io: Io,
    mutable_image: []const u8,
    extraction: []const u8,
) !void {
    var archive = try std.process.spawn(io, .{
        .argv = &.{ "virt-tar-out", "-a", mutable_image, "/", "-" },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    defer archive.kill(io);

    var extract = try std.process.spawn(io, .{
        .argv = &.{
            "tar",
            "--extract",
            "--file=-",
            "--directory",
            extraction,
            "--exclude=./dev/*",
            "--exclude=./proc/*",
            "--exclude=./run/*",
            "--exclude=./sys/*",
        },
        .stdin = .pipe,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    defer extract.kill(io);

    var archive_buffer: [64 * 1024]u8 = undefined;
    var archive_reader = archive.stdout.?.readerStreaming(io, &archive_buffer);
    var extract_buffer: [64 * 1024]u8 = undefined;
    var extract_writer = extract.stdin.?.writerStreaming(io, &extract_buffer);
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = try archive_reader.interface.readSliceShort(&buffer);
        if (count == 0) break;
        try extract_writer.interface.writeAll(buffer[0..count]);
    }
    try extract_writer.interface.flush();
    extract.stdin.?.close(io);
    extract.stdin = null;

    switch (try archive.wait(io)) {
        .exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
    switch (try extract.wait(io)) {
        .exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
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
    try extractGuestRoot(io, mutable_image, extraction);

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
        const resolve_root = try std.fs.path.join(allocator, &.{ transaction_dir, "resolve-root" });
        defer allocator.free(resolve_root);
        try Dir.cwd().createDirPath(io, cache);
        try Dir.cwd().createDirPath(io, state);
        try Dir.cwd().createDirPath(io, resolve_root);
        try prepareEmptyDpkgRoot(allocator, io, resolve_root);

        const absolute_cache = try Dir.cwd().realPathFileAlloc(io, cache, allocator);
        defer allocator.free(absolute_cache);
        const absolute_state = try Dir.cwd().realPathFileAlloc(io, state, allocator);
        defer allocator.free(absolute_state);
        const absolute_resolve_root = try Dir.cwd().realPathFileAlloc(io, resolve_root, allocator);
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

fn prepareEmptyDpkgRoot(allocator: Allocator, io: Io, root: []const u8) !void {
    const dpkg_dir = try std.fs.path.join(allocator, &.{ root, "var/lib/dpkg" });
    defer allocator.free(dpkg_dir);
    try Dir.cwd().createDirPath(io, dpkg_dir);
    const status = try std.fs.path.join(allocator, &.{ dpkg_dir, "status" });
    defer allocator.free(status);
    try Dir.cwd().writeFile(io, .{ .sub_path = status, .data = "" });
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
        \\{{"schema":1,"type":"vmiz-ubuntu2604-build-provenance","architecture":"{s}","release":"26.04","snapshot":{{"id":"release-{s}","base_url":"{s}/"}},"canonical_key_fingerprint":"{s}","sha256sums_signature_verified":true,"artifacts":{{"sha256sums":{{"filename":"SHA256SUMS","sha256":"{s}"}},"sha256sums_signature":{{"filename":"SHA256SUMS.gpg","sha256":"{s}"}},"source_image":{{"filename":"{s}","sha256":"{s}"}},"image_manifest":{{"filename":"{s}","sha256":"{s}"}}}},"debz":{{"api_commit":"{s}","transactions":[{{"package":"{s}","exact_lock":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}"}},"transaction_provenance":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}","lock_sha256":"{s}"}}}},{{"package":"{s}","exact_lock":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}"}},"transaction_provenance":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}","lock_sha256":"{s}"}}}}]}}}}
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

    for (&[_][]const u8{ "curl", "gpg" }) |tool|
        try requireTool(allocator, io, tool);

    const sums_path = try std.fs.path.join(allocator, &.{ work_dir, "SHA256SUMS" });
    defer allocator.free(sums_path);
    const signature_path = try std.fs.path.join(allocator, &.{ work_dir, "SHA256SUMS.gpg" });
    defer allocator.free(signature_path);
    try acquire(allocator, io, release_base ++ "/SHA256SUMS", sums_path, sums_sha256, 64 * 1024);
    try acquire(allocator, io, release_base ++ "/SHA256SUMS.gpg", signature_path, sums_signature_sha256, 16 * 1024);
    try verifyCanonicalPublication(allocator, io, work_dir, sums_path, signature_path);
    const sums = try Dir.cwd().readFileAlloc(io, sums_path, allocator, .limited(64 * 1024));
    defer allocator.free(sums);
    try requireSha256SumsEntry(sums, profile.source_name, profile.source_sha256);
    try requireSha256SumsEntry(sums, profile.manifest_name, profile.manifest_sha256);

    const manifest_path = try std.fs.path.join(allocator, &.{ work_dir, profile.manifest_name });
    defer allocator.free(manifest_path);
    const manifest_url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ release_base, profile.manifest_name });
    defer allocator.free(manifest_url);
    try acquire(allocator, io, manifest_url, manifest_path, profile.manifest_sha256, manifest_max_size);
    const manifest = try Dir.cwd().readFileAlloc(io, manifest_path, allocator, .limited(manifest_max_size));
    defer allocator.free(manifest);
    try validateManifestRuntime(allocator, manifest, profile);
    const provenance_sums = try std.fs.path.join(allocator, &.{ provenance_dir, "SHA256SUMS" });
    defer allocator.free(provenance_sums);
    const provenance_signature = try std.fs.path.join(allocator, &.{ provenance_dir, "SHA256SUMS.gpg" });
    defer allocator.free(provenance_signature);
    const provenance_manifest = try std.fs.path.join(allocator, &.{ provenance_dir, profile.manifest_name });
    defer allocator.free(provenance_manifest);
    try copyBoundedFile(allocator, io, sums_path, provenance_sums, 64 * 1024);
    try copyBoundedFile(allocator, io, signature_path, provenance_signature, 16 * 1024);
    try copyBoundedFile(allocator, io, manifest_path, provenance_manifest, manifest_max_size);

    const source_path = if (args.source) |source| source else blk: {
        const path = try std.fs.path.join(allocator, &.{ work_dir, profile.source_name });
        const url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ release_base, profile.source_name });
        defer allocator.free(url);
        try acquire(allocator, io, url, path, profile.source_sha256, source_max_size);
        break :blk path;
    };
    defer if (args.source == null) allocator.free(source_path);
    const source_metadata = try artifact_pipeline.hashFile(io, source_path);
    if (!std.mem.eql(u8, &source_metadata.sha256, &(try artifact_pipeline.parseSha256(profile.source_sha256))))
        return error.ChecksumMismatch;
    if (args.preflight_only) return;

    for (&[_][]const u8{ "qemu-img", "virt-customize", "virt-copy-in", "virt-cat", "virt-ls", "virt-filesystems", "virt-tar-in", "virt-tar-out", "guestfish", "tar", "cp", "ukify", "sbverify" }) |tool|
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
    const growth = try vmiz.root_resize.growExistingQcow2(
        allocator,
        io,
        mutable,
        .{
            .target_size = args.size,
            .filesystem_label = vmiz.root_resize.default_filesystem_label,
        },
    );
    const destination_root = try std.fmt.allocPrint(
        allocator,
        "/dev/sda{d}",
        .{growth.root_table_index + 1},
    );
    defer allocator.free(destination_root);

    var debz_customization = try customizeRootWithDebz(allocator, io, profile, mutable, work_dir, provenance_dir);
    defer debz_customization.deinit(allocator);
    const root_tar = try std.fs.path.join(allocator, &.{ work_dir, "debz-customized-root.tar" });
    defer allocator.free(root_tar);
    Dir.cwd().deleteFile(io, root_tar) catch {};
    try run(allocator, io, &.{
        "tar", "--xattrs",                   "--acls", "--numeric-owner",
        "-C",  debz_customization.root_path, "-cf",    root_tar,
        ".",
    });
    const guestfish_script = try std.fs.path.join(allocator, &.{ work_dir, "replace-root.guestfish" });
    defer allocator.free(guestfish_script);
    const guestfish_commands = try std.fmt.allocPrint(allocator,
        \\add-drive-opts {s} format:qcow2
        \\run
        \\mount {s} /
        \\rm-rf /
        \\
    , .{ mutable, destination_root });
    defer allocator.free(guestfish_commands);
    try Dir.cwd().writeFile(io, .{ .sub_path = guestfish_script, .data = guestfish_commands });
    try run(allocator, io, &.{ "guestfish", "-f", guestfish_script });
    try run(allocator, io, &.{ "virt-tar-in", "-a", mutable, root_tar, "/" });

    const script_path = try std.fs.path.join(allocator, &.{ work_dir, "customize.sh" });
    defer allocator.free(script_path);
    const script = try customizationScript(allocator, profile);
    defer allocator.free(script);
    try Dir.cwd().writeFile(io, .{ .sub_path = script_path, .data = script });
    try run(allocator, io, &.{ "virt-customize", "--no-logfile", "-a", mutable, "--run", script_path });

    const lock_dir = try std.fs.path.join(allocator, &.{ work_dir, "lock" });
    defer allocator.free(lock_dir);
    try Dir.cwd().deleteTree(io, lock_dir);
    try Dir.cwd().createDirPath(io, lock_dir);
    try run(allocator, io, &.{ "virt-copy-out", "-a", mutable, "/var/lib/vmiz/ubuntu2604-package-lock.tsv", lock_dir });
    const lock_path = try std.fs.path.join(allocator, &.{ lock_dir, "ubuntu2604-package-lock.tsv" });
    defer allocator.free(lock_path);
    const lock_bytes = try Dir.cwd().readFileAlloc(io, lock_path, allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(lock_bytes);
    try validateExactLockRuntime(allocator, lock_bytes, profile);
    const kernel_listing = try capture(allocator, io, &.{ "virt-ls", "-a", mutable, "/boot" });
    defer allocator.free(kernel_listing);
    const release_name = findAzureKernelRelease(kernel_listing) orelse return error.AzureKernelMissing;
    const extract_dir = try std.fs.path.join(allocator, &.{ work_dir, "uki-input" });
    defer allocator.free(extract_dir);
    try Dir.cwd().deleteTree(io, extract_dir);
    try Dir.cwd().createDirPath(io, extract_dir);
    const kernel_guest = try std.fmt.allocPrint(allocator, "/boot/vmlinuz-{s}", .{release_name});
    defer allocator.free(kernel_guest);
    const initrd_guest = try std.fmt.allocPrint(allocator, "/boot/initrd.img-{s}", .{release_name});
    defer allocator.free(initrd_guest);
    const modules_guest = try std.fmt.allocPrint(allocator, "/lib/modules/{s}", .{release_name});
    defer allocator.free(modules_guest);
    const modules_listing = try capture(allocator, io, &.{ "virt-ls", "-a", mutable, modules_guest });
    defer allocator.free(modules_listing);
    if (std.mem.trim(u8, modules_listing, " \t\r\n").len == 0) return error.AzureKernelModulesMissing;
    try run(allocator, io, &.{ "virt-copy-out", "-a", mutable, kernel_guest, initrd_guest, "/usr/lib/os-release", extract_dir });

    const kernel_host = try std.fmt.allocPrint(allocator, "{s}/vmlinuz-{s}", .{ extract_dir, release_name });
    defer allocator.free(kernel_host);
    const initrd_host = try std.fmt.allocPrint(allocator, "{s}/initrd.img-{s}", .{ extract_dir, release_name });
    defer allocator.free(initrd_host);
    const os_release_host = try std.fs.path.join(allocator, &.{ extract_dir, "os-release" });
    defer allocator.free(os_release_host);
    const os_release_argument = try std.fmt.allocPrint(allocator, "@{s}", .{os_release_host});
    defer allocator.free(os_release_argument);
    const unsigned_uki = try std.fs.path.join(allocator, &.{ work_dir, "ubuntu2604.unsigned.efi" });
    defer allocator.free(unsigned_uki);
    try run(allocator, io, &.{
        "ukify",        "build",
        "--linux",      kernel_host,
        "--initrd",     initrd_host,
        "--os-release", os_release_argument,
        "--cmdline",    "root=LABEL=cloudimg-rootfs ro console=tty1 console=ttyS0 earlyprintk=ttyS0 panic=-1",
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

    try run(allocator, io, &.{ "virt-customize", "--no-logfile", "-a", mutable, "--mkdir", "/boot/efi/EFI/Linux", "--mkdir", "/boot/efi/EFI/BOOT" });
    try run(allocator, io, &.{ "virt-copy-in", "-a", mutable, signed_path, "/boot/efi/EFI/Linux" });
    try run(allocator, io, &.{ "virt-copy-in", "-a", mutable, signed_path, "/boot/efi/EFI/BOOT" });
    try run(allocator, io, &.{ "qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", "-o", "compat=1.1,compression_type=zstd", "-c", mutable, output });
    const info = try capture(allocator, io, &.{ "qemu-img", "info", "--output=json", output });
    defer allocator.free(info);
    try validateQcow2Info(allocator, info, args.size);
    const partitions = try capture(allocator, io, &.{ "virt-filesystems", "--partitions", "-a", output });
    defer allocator.free(partitions);
    if (std.mem.indexOf(u8, partitions, destination_root) == null)
        return error.InvalidGen2PartitionLayout;
    const fallback_listing = try capture(allocator, io, &.{ "virt-ls", "-a", output, "/boot/efi/EFI/BOOT" });
    defer allocator.free(fallback_listing);
    if (std.mem.indexOf(u8, fallback_listing, profile.efi_fallback) == null) return error.FinalUkiMissing;
    const named_listing = try capture(allocator, io, &.{ "virt-ls", "-a", output, "/boot/efi/EFI/Linux" });
    defer allocator.free(named_listing);
    if (std.mem.indexOf(u8, named_listing, profile.efi_fallback) == null) return error.FinalUkiMissing;
    const os_release = try capture(allocator, io, &.{ "virt-cat", "-a", output, "/etc/os-release" });
    defer allocator.free(os_release);
    if (std.mem.indexOf(u8, os_release, "VERSION_ID=\"26.04\"") == null) return error.WrongGuestRelease;
    const final_lock = try capture(allocator, io, &.{ "virt-cat", "-a", output, "/var/lib/vmiz/ubuntu2604-package-lock.tsv" });
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

test "profiles pin immutable official sources for both architectures" {
    try std.testing.expectEqual(@as(usize, 2), profiles.len);
    for (&profiles) |*profile| {
        _ = try artifact_pipeline.parseSha256(profile.source_sha256);
        _ = try artifact_pipeline.parseSha256(profile.manifest_sha256);
        try std.testing.expect(std.mem.indexOf(u8, profile.source_name, "26.04") != null);
    }
    try std.testing.expectEqual(@as(u64, 5 * 1024 * 1024 * 1024), default_virtual_size);
    try std.testing.expectEqual(@as(u32, 3), profiles[0].root_partition_table_index);
    try std.testing.expectEqual(@as(u32, 2), profiles[1].root_partition_table_index);
    try std.testing.expectEqualSlices(u8, &guid.linux_root_x86_64, &profiles[0].root_partition_type_guid);
    try std.testing.expectEqualSlices(u8, &guid.linux_root_aarch64, &profiles[1].root_partition_type_guid);
}

test "Canonical keyring preparation uses a chmod-capable directory handle" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    const path = try std.fs.path.join(
        std.testing.allocator,
        &.{ root_buffer[0..root_length], "gnupg" },
    );
    defer std.testing.allocator.free(path);

    try prepareCanonicalKeyring(std.testing.io, path);
    try prepareCanonicalKeyring(std.testing.io, path);
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
    try std.testing.expectEqual(@as(usize, 0), arm64.inputs.source_paths.len);
    try std.testing.expectEqualStrings("/inputs/ubuntu.sources", arm64.inputs.config_paths[0]);
    try std.testing.expectEqualStrings("/state/walinuxagent.lock", arm64.inputs.lock_input_path.?);
    try std.testing.expect(arm64.inputs.lock_output_path == null);
}

test "empty lock-resolution roots contain a valid dpkg database" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);

    try prepareEmptyDpkgRoot(
        std.testing.allocator,
        std.testing.io,
        root_buffer[0..root_length],
    );
    const status = try temporary.dir.statFile(std.testing.io, "var/lib/dpkg/status", .{});
    try std.testing.expectEqual(@as(u64, 0), status.size);
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

test "final qcow2 validation rejects backing files and wrong sizes" {
    try validateQcow2Info(std.testing.allocator, "{\"format\":\"qcow2\",\"virtual-size\":5368709120}", default_virtual_size);
    try std.testing.expectError(error.NonStandaloneQcow2, validateQcow2Info(
        std.testing.allocator,
        "{\"format\":\"qcow2\",\"virtual-size\":5368709120,\"backing-filename\":\"base\"}",
        default_virtual_size,
    ));
    try std.testing.expectError(error.UnexpectedVirtualSize, validateQcow2Info(
        std.testing.allocator,
        "{\"format\":\"qcow2\",\"virtual-size\":1}",
        default_virtual_size,
    ));
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
    try std.testing.expectEqual(@as(usize, 2), parsed.value.object.get("debz").?.object.count());
    try std.testing.expectEqual(@as(usize, 4), parsed.value.object.get("artifacts").?.object.count());
}
