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

const release = "20260731";
const release_base = "https://cloud-images.ubuntu.com/releases/26.04/release-" ++ release;
const snapshot_base = "https://snapshot.ubuntu.com/ubuntu/20260731T000000Z";
const canonical_fingerprint = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";
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
    pe_machine: []const u8,
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
        .pe_machine = "Advanced Micro Devices X86-64",
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
        .pe_machine = "Aarch64",
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

const azure_packages =
    "linux-azure linux-tools-azure linux-cloud-tools-azure " ++
    "walinuxagent cloud-init cloud-guest-utils openssh-server sudo " ++
    "systemd-resolved netplan.io sbsigntool";

const Args = struct {
    architecture: ?Architecture = null,
    source: ?[]const u8 = null,
    output: ?[]const u8 = null,
    work_dir: ?[]const u8 = null,
    size: u64 = default_virtual_size,
    signing_certificate: ?[]const u8 = null,
    signing_certificate_sha256: ?[]const u8 = null,
    signing_key: ?[]const u8 = null,
    preflight_only: bool = false,
};

const help =
    \\Usage: zig build generalized-ubuntu2604 -Dubuntu2604-arch=<x86_64|aarch64> -- [options]
    \\  --source <path>                         verified local Canonical .img
    \\  --output <path>                         output QCOW2
    \\  --work-dir <path>                       persistent download/work cache
    \\  --size <size>                           virtual size (default 5G)
    \\  --uki-signing-certificate <path>        Secure Boot certificate
    \\  --uki-signing-certificate-sha256 <hex>  DER certificate SHA-256
    \\  --uki-signing-key <path>                local signing key
    \\  --preflight-only                        verify pins/tools without building
    \\
;

fn profileFor(architecture: Architecture) *const Profile {
    for (&profiles) |*profile| if (profile.architecture == architecture) return profile;
    unreachable;
}

fn packageFamilyInspectRequest(profile: *const Profile, root: []const u8) package_family.Request {
    return .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = .inspect,
        .inputs = .{
            .root_stage = root,
            .published_root = root,
            .architecture = switch (profile.architecture) {
                .x86_64 => .amd64,
                .aarch64 => .arm64,
            },
            .source_paths = &.{},
            .keyring_paths = &.{},
            .cache_path = ".",
            .state_path = ".",
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
        \\cat > /etc/apt/sources.list.d/ubuntu.sources <<'EOF'
        \\Types: deb
        \\URIs: {s}
        \\Suites: resolute resolute-updates resolute-security
        \\Components: main restricted universe multiverse
        \\Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
        \\Check-Valid-Until: no
        \\EOF
        \\rm -f /etc/apt/sources.list
        \\apt-get update
        \\apt-get install -y --no-install-recommends {s}
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
        \\apt-get clean
        \\rm -rf /var/lib/apt/lists/*
        \\sync
        \\
    , .{ snapshot_base, azure_packages, release });
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
    try Dir.cwd().deleteTree(io, gnupg);
    try Dir.cwd().createDirPath(io, gnupg);
    var directory = try Dir.cwd().openDir(io, gnupg, .{});
    defer directory.close(io);
    try directory.setPermissions(io, .fromMode(0o700));

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

fn writeProvenance(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    profile: *const Profile,
    source_digest: [64]u8,
    lock_digest: [64]u8,
) !void {
    const document = try std.fmt.allocPrint(allocator,
        \\{{"schema":"io.github.cataggar.vmiz.ubuntu2604-provenance.v1","release":"{s}","architecture":"{s}","source":{{"url":"{s}/{s}","sha256":"{s}","sha256sums_sha256":"{s}","signature_sha256":"{s}","canonical_fingerprint":"{s}"}},"packages":{{"distribution":"ubuntu_26_04","snapshot":"{s}","package_family_schema":"{s}","package_family_version":{d},"debz_commit":"{s}","exact_inventory_sha256":"{s}"}}}}
        \\
    , .{
        release,
        @tagName(profile.architecture),
        release_base,
        profile.source_name,
        source_digest,
        sums_sha256,
        sums_signature_sha256,
        canonical_fingerprint,
        snapshot_base,
        package_family.request_schema,
        package_family.api_version,
        package_family.debz_api_commit,
        lock_digest,
    });
    defer allocator.free(document);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = document });
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

    for (&[_][]const u8{ "curl", "gpg" }) |tool|
        try requireTool(allocator, io, tool);

    const sums_path = try std.fs.path.join(allocator, &.{ work_dir, "SHA256SUMS" });
    defer allocator.free(sums_path);
    const signature_path = try std.fs.path.join(allocator, &.{ work_dir, "SHA256SUMS.gpg" });
    defer allocator.free(signature_path);
    try acquire(allocator, io, release_base ++ "/SHA256SUMS", sums_path, sums_sha256, 64 * 1024);
    try acquire(allocator, io, release_base ++ "/SHA256SUMS.gpg", signature_path, sums_signature_sha256, 16 * 1024);
    try verifyCanonicalPublication(allocator, io, work_dir, sums_path, signature_path);

    const manifest_path = try std.fs.path.join(allocator, &.{ work_dir, profile.manifest_name });
    defer allocator.free(manifest_path);
    const manifest_url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ release_base, profile.manifest_name });
    defer allocator.free(manifest_url);
    try acquire(allocator, io, manifest_url, manifest_path, profile.manifest_sha256, manifest_max_size);
    const manifest = try Dir.cwd().readFileAlloc(io, manifest_path, allocator, .limited(manifest_max_size));
    defer allocator.free(manifest);
    try validateManifestRuntime(allocator, manifest, profile);

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

    for (&[_][]const u8{ "qemu-img", "virt-resize", "virt-customize", "virt-copy-out", "virt-copy-in", "virt-cat", "virt-ls", "virt-filesystems", "ukify", "file", "sbverify" }) |tool|
        try requireTool(allocator, io, tool);
    if (args.signing_certificate == null or args.signing_certificate_sha256 == null or args.signing_key == null)
        return error.SigningConfigurationRequired;

    const mutable = try std.fs.path.join(allocator, &.{ work_dir, "customized.qcow2" });
    defer allocator.free(mutable);
    const size_text = try std.fmt.allocPrint(allocator, "{d}", .{args.size});
    defer allocator.free(size_text);
    Dir.cwd().deleteFile(io, mutable) catch {};
    try run(allocator, io, &.{ "qemu-img", "create", "-f", "qcow2", mutable, size_text });
    try run(allocator, io, &.{ "virt-resize", "--expand", "/dev/sda1", source_path, mutable });

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
    const lock_metadata = try artifact_pipeline.hashFile(io, lock_path);

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
    const config = uki_signing.Config{
        .certificate_path = args.signing_certificate.?,
        .expected_certificate_sha256 = try uki_signing.parseFingerprint(args.signing_certificate_sha256.?),
        .mode = .{ .local_key = .{ .private_key_path = args.signing_key.? } },
    };
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
        "server",
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
    if (std.mem.indexOf(u8, partitions, "/dev/sda1") == null or
        std.mem.indexOf(u8, partitions, "/dev/sda15") == null) return error.InvalidGen2PartitionLayout;
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
    const machine = try capture(allocator, io, &.{ "file", signed_path });
    defer allocator.free(machine);
    if (std.mem.indexOf(u8, machine, profile.pe_machine) == null) return error.WrongUkiArchitecture;

    const provenance_path = try std.fmt.allocPrint(allocator, "{s}.provenance.json", .{output});
    defer allocator.free(provenance_path);
    try writeProvenance(
        allocator,
        io,
        provenance_path,
        profile,
        artifact_pipeline.formatSha256(source_metadata.sha256),
        artifact_pipeline.formatSha256(lock_metadata.sha256),
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
}

test "package-family inspection is explicitly Ubuntu 26.04 and architecture-correct" {
    const amd64 = packageFamilyInspectRequest(profileFor(.x86_64), "/root");
    try std.testing.expectEqual(package_family.Family.debian, amd64.family);
    try std.testing.expectEqual(package_family.Distribution.ubuntu_26_04, amd64.distribution);
    try std.testing.expectEqual(package_family.Operation.inspect, amd64.operation);
    try std.testing.expectEqual(package_family.Architecture.amd64, amd64.inputs.architecture);
    const arm64 = packageFamilyInspectRequest(profileFor(.aarch64), "/root");
    try std.testing.expectEqual(package_family.Architecture.arm64, arm64.inputs.architecture);
}

test "arguments accept Ubuntu and project architecture spellings" {
    try std.testing.expectEqual(Architecture.x86_64, (try parseArgs(&.{ "--architecture", "amd64" })).architecture.?);
    try std.testing.expectEqual(Architecture.aarch64, (try parseArgs(&.{ "--architecture", "aarch64" })).architecture.?);
    try std.testing.expectError(error.ImageTooSmall, parseArgs(&.{ "--size", "4G" }));
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

test "Azure kernel discovery is architecture-neutral and exact" {
    try std.testing.expectEqualStrings(
        "7.0.0-1001-azure",
        findAzureKernelRelease("config\nvmlinuz-7.0.0-1001-azure\n").?,
    );
    try std.testing.expect(findAzureKernelRelease("vmlinuz-7.0.0-28-generic\n") == null);
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
