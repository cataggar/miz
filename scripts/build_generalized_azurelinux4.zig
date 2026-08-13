//! Build a generalized Azure Linux 4 Gen2 QCOW2 image.
//!
//! Equivalent to scripts/build-generalized-azurelinux4.py but implemented as
//! native Zig 0.16 code. Invoked via `zig build generalized-azurelinux4 -- [args]`
//! rather than directly; the build system passes pre-built tool paths so this
//! binary does not invoke `zig build` internally.
//!
//! CLI arguments accepted:
//!   --architecture <arch> Azure Linux guest architecture (injected by build.zig)
//!   --flavor <core|full>  Image flavor (core is the compatible default)
//!   --iso <path>        Architecture-matched Azure Linux 4 ISO (downloaded if omitted)
//!   --output <path>     Output QCOW2 path (architecture/flavor-specific default)
//!   --size <size>       Disk size (flavor-specific default)
//!   --work-dir <dir>    Working directory (architecture/flavor-specific default)
//!
//! Arguments injected automatically by build.zig:
//!   --zvmi <path>       Built native zvmi executable
//!   --zvminit <path>    Built guest zvminit binary
//!   --azagent <path>    Built guest azagent binary
//!   --preload <path>    Built zstd_max_preload.so shared library

const std = @import("std");
const builtin = @import("builtin");
const zvmi = @import("zvmi");
const uki_signing = @import("uki_signing.zig");
const oci = zvmi.oci;
const artifact_pipeline = zvmi.artifact_pipeline;

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const linux = std.os.linux;

// ─── constants ───────────────────────────────────────────────────────────────

const base_image = "azurelinux-beta/base/core";
const base_tag = "4.0";
const mcr_base = "https://mcr.microsoft.com/v2";
const AzureLinuxArchitecture = zvmi.bootconfig.Architecture;
const dnf_repository_id = "zvmi-azurelinux-base";

/// The full image package manifest is vendored from this exact upstream KIWI
/// profile.  KIWI itself is deliberately not part of the build: DNF consumes
/// this encoded package closure against the pinned Azure Linux repomd.xml.
const vm_base_upstream_repository = "https://github.com/microsoft/azurelinux";
const vm_base_upstream_commit = "5b41bff6ebaf7e8fc78637b564efee23b66e7d67";
const vm_base_profile_blob = "8c870852e711273275c83f0b94ecd914ff709af8";
const vm_base_profile_path = "base/images/vm-base/vm-base.kiwi";
const vm_base_profile_name = "vm-base";

const Flavor = enum {
    core,
    full,
};

const Pid1 = enum {
    zvminit,
    systemd,
};

const Provisioner = enum {
    zvminit_azagent,
    cloud_init_waagent,
};

/// Azure Linux 4 vm-base's architecture-neutral `<packages type="image">`
/// group plus its selected `vm-base` runtime repositories package.  The
/// x86_64/AArch64 EFI packages from the upstream bootstrap group are supplied
/// separately by `ArchitectureDescriptor.full_efi_packages`.
const vm_base_packages = [_][]const u8{
    // vm-base's bootstrap group.  DNF resolves this exactly once together
    // with the image group below, rather than through a separate transaction.
    "filesystem",
    "azurelinux-release-cloud",
    "bash",
    "ca-certificates",
    "coreutils",
    "acl",
    "attr",
    "audit",
    "bash-completion",
    "bind-utils",
    "brotli",
    "bzip2",
    "chkconfig",
    "chrony",
    "cloud-init",
    "cloud-utils-growpart",
    "cracklib-dicts",
    "cronie",
    "cryptsetup",
    "cyrus-sasl",
    "device-mapper-event",
    "dnf5",
    "dnf5-plugins",
    "efibootmgr",
    "file",
    "firewalld",
    "glibc",
    "glibc-langpack-en",
    "grub2",
    "grubby",
    "gzip",
    "hostname",
    "iproute",
    "iputils",
    "irqbalance",
    "kernel",
    "lvm2",
    "lz4",
    "man-db",
    "nano",
    "ncurses",
    "ncurses-term",
    "net-tools",
    "nftables",
    "nvme-cli",
    "openssh-clients",
    "openssh-server",
    "rootfiles",
    "rsync",
    "selinux-policy-targeted",
    "setup",
    "shadow-utils",
    "sudo",
    "systemd",
    "systemd-networkd",
    "systemd-resolved",
    "tar",
    "tpm2-tss",
    "unzip",
    "util-linux",
    "vim-minimal",
    "wget",
    "which",
    "zchunk",
    "zlib",
    "WALinuxAgent",
    "azure-vm-utils",
    "hyperv-daemons",
    "kernel-modules",
    "azurelinux-repos",
};

const core_packages = [_][]const u8{
    "openssh-server",
    "sudo",
};

const core_required_rootfs_paths = [_][]const u8{
    "usr/bin/bash",
    "usr/bin/azagent",
    "usr/bin/zvminit",
    "usr/bin/sshd",
};

const full_required_rootfs_paths = [_][]const u8{
    "usr/bin/bash",
    "usr/bin/cloud-init",
    "usr/bin/rpm",
    "usr/bin/setfiles",
    "usr/bin/sshd",
    "usr/bin/waagent",
    "usr/lib/systemd/systemd",
    "usr/lib/systemd/system/chronyd.service",
    "usr/lib/sysusers.d/chrony.conf",
    "etc/systemd/network/20-wired.network",
    "etc/waagent.conf",
};

const core_forbidden_rootfs_paths = [_][]const u8{};
const full_forbidden_rootfs_paths = [_][]const u8{
    // Azure Linux uses merged-/usr aliases; validate their canonical targets
    // because the ext4 reader deliberately does not follow symlinks.
    "usr/bin/zvminit",
    "usr/bin/azagent",
    "etc/ssh/sshd_config.d/10-zvminit.conf",
    "var/lib/azagent/provisioned",
    // Offline labeling replaces the first-boot relabel marker.
    ".autorelabel",
};

const full_required_systemd_units = [_][]const u8{
    "cloud-init-local.service",
    "cloud-init-main.service",
    "cloud-init-network.service",
    "cloud-config.service",
    "cloud-final.service",
    "waagent.service",
    "sshd.service",
    "systemd-networkd.service",
};

const full_enabled_systemd_units = [_][]const u8{
    "cloud-init-local.service",
    "cloud-init-main.service",
    "cloud-init-network.service",
    "cloud-config.service",
    "cloud-final.service",
    "waagent.service",
    "sshd.service",
    "systemd-networkd.service",
};

const full_networkd_config =
    \\[Match]
    \\Kind=!*
    \\Type=ether
    \\
    \\[Network]
    \\DHCP=yes
    \\
;

const full_root_selinux_label = "system_u:object_r:root_t:s0";

const FlavorDescriptor = struct {
    flavor: Flavor,
    default_size: []const u8,
    esp_size_bytes: u64,
    esp_size_arg: []const u8,
    minimum_root_free_bytes: u64,
    required_rootfs_paths: []const []const u8,
    forbidden_rootfs_paths: []const []const u8,
    required_packages: []const []const u8,
    forbidden_packages: []const []const u8,
    pid1: Pid1,
    provisioner: Provisioner,
    oci_entrypoint: []const u8,
    oci_provenance_kind: []const u8,
    max_oci_layer_bytes: u64,
};

const core = FlavorDescriptor{
    .flavor = .core,
    .default_size = "1184M",
    .esp_size_bytes = 512 * 1024 * 1024,
    .esp_size_arg = "512M",
    .minimum_root_free_bytes = 128 * 1024 * 1024,
    .required_rootfs_paths = &core_required_rootfs_paths,
    .forbidden_rootfs_paths = &core_forbidden_rootfs_paths,
    .required_packages = &core_packages,
    .forbidden_packages = &.{},
    .pid1 = .zvminit,
    .provisioner = .zvminit_azagent,
    .oci_entrypoint = "/sbin/zvminit",
    .oci_provenance_kind = "pinned-core-oci",
    .max_oci_layer_bytes = 128 * 1024 * 1024,
};

const full = FlavorDescriptor{
    .flavor = .full,
    // vm-base.kiwi explicitly sets a 5 GiB fixed-size image.  This builder
    // retains that size despite emitting QCOW2 and uses a larger ESP for UKIs.
    .default_size = "5G",
    .esp_size_bytes = 512 * 1024 * 1024,
    .esp_size_arg = "512M",
    .minimum_root_free_bytes = 1024 * 1024 * 1024,
    .required_rootfs_paths = &full_required_rootfs_paths,
    .forbidden_rootfs_paths = &full_forbidden_rootfs_paths,
    .required_packages = &vm_base_packages,
    .forbidden_packages = &.{ "zvminit", "azagent" },
    .pid1 = .systemd,
    .provisioner = .cloud_init_waagent,
    .oci_entrypoint = "/usr/lib/systemd/systemd",
    .oci_provenance_kind = "pinned-vm-base-profile-repomd-nevra",
    .max_oci_layer_bytes = 512 * 1024 * 1024,
};

fn flavorDescriptor(flavor: Flavor) *const FlavorDescriptor {
    return switch (flavor) {
        .core => &core,
        .full => &full,
    };
}

fn ociLayerPlanCount(flavor: *const FlavorDescriptor) usize {
    return switch (flavor.flavor) {
        .core => 3,
        .full => 7,
    };
}

fn ociLoadOptionsForFlavor(flavor: *const FlavorDescriptor) oci.LoadOptions {
    return .{
        .max_blob_size = @intCast(flavor.max_oci_layer_bytes),
        .max_layer_size = @intCast(flavor.max_oci_layer_bytes),
        .max_archive_size = @intCast(flavor.max_oci_layer_bytes * 8),
    };
}

/// All target-dependent Azure Linux core-image inputs and output conventions.
/// Keeping them together prevents a guest architecture from being selected in
/// one stage while another stage silently retains x86_64 defaults.
const ArchitectureDescriptor = struct {
    architecture: AzureLinuxArchitecture,
    target_cpu: std.Target.Cpu.Arch,
    oci_architecture: []const u8,
    dnf_architecture: []const u8,
    iso_url: []const u8,
    iso_name: []const u8,
    iso_sha256: []const u8,
    iso_squashfs_path: []const u8,
    iso_nested_rootfs_path: []const u8,
    base_manifest_digest: []const u8,
    repository_base_url: []const u8,
    repomd_url: []const u8,
    repomd_sha256: []const u8,
    signing_key_path: []const u8,
    systemd_boot_rpm_name: []const u8,
    systemd_boot_rpm_url: []const u8,
    systemd_boot_rpm_sha256: []const u8,
    systemd_boot_stub_path: []const u8,
    fallback_efi_path: []const u8,
    uki_pe_machine: u16,
    root_role: zvmi.layout.PartitionRole,
    root_type_guid: zvmi.guid.Guid,
    serial_console: []const u8,
    extra_kernel_options: []const u8,
    binfmt_registration_name: []const u8,
    binfmt_registration_path: [:0]const u8,
    binfmt_static_name: []const u8,
    elf_file_marker: []const u8,
    full_efi_packages: []const []const u8,
    full_kernel_package: []const u8,
    full_kernel_modules_package: []const u8,
    full_kernel_release: []const u8,
};

const x86_64 = ArchitectureDescriptor{
    .architecture = .x86_64,
    .target_cpu = .x86_64,
    .oci_architecture = "amd64",
    .dnf_architecture = "x86_64",
    .iso_url = "https://aka.ms/azurelinux-4.0-x86_64.iso",
    .iso_name = "AzureLinux-4.0-x86_64.iso",
    // Official Azure Linux checksum resolved from the aka.ms endpoint on
    // 2026-07-17. Pinning it prevents a moving endpoint changing the recipe.
    .iso_sha256 = "d98f7d1ffaa916de7c9f66ffdadb150c174da691509e760835709ffa7829ca48",
    .iso_squashfs_path = "LiveOS/squashfs.img",
    .iso_nested_rootfs_path = "LiveOS/rootfs.img",
    .base_manifest_digest = "sha256:9070b05147f01e5a4bac47723c95f2555e11b9d3324c1df1910ff3545b7ce319",
    .repository_base_url = "https://packages.microsoft.com/azurelinux/4.0/beta/base/x86_64",
    .repomd_url = "https://packages.microsoft.com/azurelinux/4.0/beta/base/x86_64/repodata/repomd.xml",
    .repomd_sha256 = "5f888b701b5b548944bb9079b01c948c3a0c73c33a6cea7d1179c1d746292151",
    .signing_key_path = "etc/pki/rpm-gpg/RPM-GPG-KEY-azurelinux-4.0-x86_64",
    .systemd_boot_rpm_name = "systemd-boot-unsigned-258.4-4.azl4.x86_64.rpm",
    .systemd_boot_rpm_url = "https://packages.microsoft.com/azurelinux/4.0/beta/base/x86_64/Packages/s/systemd-boot-unsigned-258.4-4.azl4.x86_64.rpm",
    .systemd_boot_rpm_sha256 = "85dd3ac0c532bceb09fc0a85c6568c51fc4ee84e0c478d1302b7a2d84e1bea5c",
    .systemd_boot_stub_path = "usr/lib/systemd/boot/efi/linuxx64.efi.stub",
    .fallback_efi_path = "EFI/BOOT/BOOTX64.EFI",
    .uki_pe_machine = 0x8664,
    .root_role = .root_x86_64,
    .root_type_guid = zvmi.guid.linux_root_x86_64,
    .serial_console = "console=ttyS0,115200n8",
    .extra_kernel_options = "init=/sbin/zvminit zvminit.mode=persistent zvminit.azure=auto console=tty0 console=ttyS0,115200n8",
    .binfmt_registration_name = "qemu-x86_64",
    .binfmt_registration_path = "/proc/sys/fs/binfmt_misc/qemu-x86_64",
    .binfmt_static_name = "qemu-x86_64-static",
    .elf_file_marker = "x86-64",
    .full_efi_packages = &.{ "grub2-efi-x64-modules", "grub2-efi-x64", "shim" },
    // The checksum-pinned ISO's LiveOS rootfs supplies this exact boot release.
    .full_kernel_package = "kernel-6.18.31-1.3.azl4",
    .full_kernel_modules_package = "kernel-modules-6.18.31-1.3.azl4",
    .full_kernel_release = "6.18.31-1.3.azl4.x86_64",
};

const aarch64 = ArchitectureDescriptor{
    .architecture = .aarch64,
    .target_cpu = .aarch64,
    .oci_architecture = "arm64",
    .dnf_architecture = "aarch64",
    .iso_url = "https://aka.ms/azurelinux-4.0-aarch64.iso",
    .iso_name = "AzureLinux-4.0-aarch64.iso",
    // Official Azure Linux checksum resolved from the aka.ms endpoint on
    // 2026-07-17. Pinning it prevents a moving endpoint changing the recipe.
    .iso_sha256 = "762039fde64a59806750ee86ca98132fad4f9df02e7684490017cdfda0c55157",
    .iso_squashfs_path = "LiveOS/squashfs.img",
    .iso_nested_rootfs_path = "LiveOS/rootfs.img",
    .base_manifest_digest = "sha256:e541db83a8511c25fa1dd989161263874b7395ddd588f5caaa25453ea4e23263",
    .repository_base_url = "https://packages.microsoft.com/azurelinux/4.0/beta/base/aarch64",
    .repomd_url = "https://packages.microsoft.com/azurelinux/4.0/beta/base/aarch64/repodata/repomd.xml",
    .repomd_sha256 = "158cd3d70fa51fdddde3e529af41d375db1b40e54f9ab8c5cc14afc8c2e81214",
    .signing_key_path = "etc/pki/rpm-gpg/RPM-GPG-KEY-azurelinux-4.0-aarch64",
    .systemd_boot_rpm_name = "systemd-boot-unsigned-258.4-4.azl4.aarch64.rpm",
    .systemd_boot_rpm_url = "https://packages.microsoft.com/azurelinux/4.0/beta/base/aarch64/Packages/s/systemd-boot-unsigned-258.4-4.azl4.aarch64.rpm",
    .systemd_boot_rpm_sha256 = "65aefdef9bc55f71f43c18b738fc1a61eeedd9fea7d803f0b0b06467fb748991",
    .systemd_boot_stub_path = "usr/lib/systemd/boot/efi/linuxaa64.efi.stub",
    .fallback_efi_path = "EFI/BOOT/BOOTAA64.EFI",
    .uki_pe_machine = 0xaa64,
    .root_role = .root_aarch64,
    .root_type_guid = zvmi.guid.linux_root_aarch64,
    .serial_console = "console=ttyAMA0,115200n8",
    .extra_kernel_options = "init=/sbin/zvminit zvminit.mode=persistent zvminit.azure=auto console=tty0 console=ttyAMA0,115200n8",
    .binfmt_registration_name = "qemu-aarch64",
    .binfmt_registration_path = "/proc/sys/fs/binfmt_misc/qemu-aarch64",
    .binfmt_static_name = "qemu-aarch64-static",
    .elf_file_marker = "aarch64",
    .full_efi_packages = &.{ "grub2-efi-aa64-modules", "grub2-efi-aa64", "shim" },
    // The checksum-pinned ISO's LiveOS rootfs supplies this exact boot release.
    .full_kernel_package = "kernel-6.18.31-1.3.azl4",
    .full_kernel_modules_package = "kernel-modules-6.18.31-1.3.azl4",
    .full_kernel_release = "6.18.31-1.3.azl4.aarch64",
};

fn architectureDescriptor(architecture: AzureLinuxArchitecture) *const ArchitectureDescriptor {
    return switch (architecture) {
        .x86_64 => &x86_64,
        .aarch64 => &aarch64,
    };
}

fn requireArchitecture(
    architecture: ?AzureLinuxArchitecture,
) error{MissingArchitecture}!*const ArchitectureDescriptor {
    return architectureDescriptor(architecture orelse return error.MissingArchitecture);
}

fn defaultOutputPath(architecture: AzureLinuxArchitecture, flavor: Flavor) []const u8 {
    return switch (flavor) {
        .core => switch (architecture) {
            .x86_64 => "AzureLinux-4.0-x86_64.core.qcow2",
            .aarch64 => "AzureLinux-4.0-aarch64.core.qcow2",
        },
        .full => switch (architecture) {
            .x86_64 => "AzureLinux-4.0-x86_64.qcow2",
            .aarch64 => "AzureLinux-4.0-aarch64.qcow2",
        },
    };
}

fn defaultWorkDir(architecture: AzureLinuxArchitecture, flavor: Flavor) []const u8 {
    return switch (flavor) {
        .core => switch (architecture) {
            .x86_64 => ".scratch/azurelinux4-core-x86_64",
            .aarch64 => ".scratch/azurelinux4-core-aarch64",
        },
        .full => switch (architecture) {
            .x86_64 => ".scratch/azurelinux4-full-x86_64",
            .aarch64 => ".scratch/azurelinux4-full-aarch64",
        },
    };
}

const systemd_boot_unsigned_rpm_max_bytes: u64 = 16 * 1024 * 1024;
const dnf_minrate_opt = "--setopt=minrate=1";
const dnf_timeout_opt = "--setopt=timeout=300";
const dnf_retries_opt = "--setopt=retries=20";
const oci_manifest_type = "application/vnd.oci.image.manifest.v1+json";
const oci_index_type = "application/vnd.oci.image.index.v1+json";
const docker_manifest_type = "application/vnd.docker.distribution.manifest.v2+json";
const docker_index_type = "application/vnd.docker.distribution.manifest.list.v2+json";
const iso_max_bytes: u64 = 2 * 1024 * 1024 * 1024;
const repomd_max_bytes: usize = 1024 * 1024;
const accept_header = oci_index_type ++ ", " ++ docker_index_type ++ ", " ++ oci_manifest_type ++ ", " ++ docker_manifest_type;
const zvminit_symlink_paths = [_][]const u8{
    "usr/bin/init",
    "usr/bin/poweroff",
    "usr/bin/reboot",
    "usr/bin/shutdown",
};

// ─── subprocess helpers ──────────────────────────────────────────────────────

/// Print "+  argv[0] argv[1] ..." then run the command inheriting stdin/stdout/stderr.
fn run(gpa: Allocator, io: Io, argv: []const []const u8) !void {
    var line: std.Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    try line.writer.print("+ ", .{});
    for (argv, 0..) |a, i| {
        if (i > 0) try line.writer.print(" ", .{});
        try line.writer.print("{s}", .{a});
    }
    const s = try line.toOwnedSlice();
    defer gpa.free(s);
    std.debug.print("{s}\n", .{s});

    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("error: '{s}' exited with code {d}\n", .{ argv[0], code });
            return error.CommandFailed;
        },
        else => {
            std.debug.print("error: '{s}' terminated abnormally\n", .{argv[0]});
            return error.CommandFailed;
        },
    }
}

/// Like `run` but prepends "sudo".
fn sudo(gpa: Allocator, io: Io, argv: []const []const u8) !void {
    const command = try gpa.alloc([]const u8, argv.len + 1);
    defer gpa.free(command);
    command[0] = "sudo";
    @memcpy(command[1..], argv);
    try run(gpa, io, command);
}

/// Run command, capture stdout. Returns owned bytes (caller frees).
/// Fails if exit code is non-zero.
fn capture(gpa: Allocator, io: Io, argv: []const []const u8) ![]u8 {
    const result = try std.process.run(gpa, io, .{ .argv = argv });
    defer gpa.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            gpa.free(result.stdout);
            std.debug.print("error: '{s}' exited with code {d}\n", .{ argv[0], code });
            return error.CommandFailed;
        },
        else => {
            gpa.free(result.stdout);
            return error.CommandFailed;
        },
    }
    return result.stdout;
}

fn readPseudoFile(gpa: Allocator, path: [:0]const u8) ![]u8 {
    const open_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(open_rc) != .SUCCESS) return error.PseudoFileOpenFailed;
    const fd: linux.fd_t = @intCast(open_rc);
    defer _ = linux.close(fd);

    var content = std.array_list.Managed(u8).init(gpa);
    errdefer content.deinit();
    var buf: [4096]u8 = undefined;
    while (true) {
        const read_rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(read_rc) != .SUCCESS) return error.PseudoFileReadFailed;
        if (read_rc == 0) break;
        try content.appendSlice(buf[0..read_rc]);
    }
    return content.toOwnedSlice();
}

// ─── sha256 helpers ──────────────────────────────────────────────────────────

/// SHA-256 of `bytes`, returned as lowercase hex (64 chars).
pub fn sha256Bytes(bytes: []const u8) [64]u8 {
    return artifact_pipeline.formatSha256(
        artifact_pipeline.sha256Bytes(bytes),
    );
}

/// SHA-256 hex of the file at `path`.  Streams in 64 KiB chunks.
fn sha256File(io: Io, path: []const u8) ![64]u8 {
    return artifact_pipeline.formatSha256(
        (try artifact_pipeline.hashFile(io, path)).sha256,
    );
}

fn systemdBootRpmCachePath(
    gpa: Allocator,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/downloads/{s}", .{ work_dir, architecture.systemd_boot_rpm_name });
}

fn isRegularNonemptyFile(kind: Io.File.Kind, size: u64) bool {
    return kind == .file and size != 0;
}

// ─── path safety ─────────────────────────────────────────────────────────────

/// Strip leading "./" and "/" from an OCI tar member name and validate that
/// no ".." components remain.  Returns null for empty/root entries.
pub fn safeLayerPath(name: []const u8) error{UnsafeLayerPath}!?[]const u8 {
    var s = name;
    if (std.mem.startsWith(u8, s, "./")) s = s[2..];
    while (std.mem.startsWith(u8, s, "/")) s = s[1..];
    if (s.len == 0) return null;
    var it = std.mem.splitScalar(u8, s, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return error.UnsafeLayerPath;
    }
    return s;
}

/// Parse a "sha256:<hex>" or bare 64-char hex digest.
/// Returns the 64-char hex portion (not owned — points into `digest`).
pub fn parseDigestHex(digest: []const u8) error{InvalidDigest}![]const u8 {
    const hex = if (std.mem.startsWith(u8, digest, "sha256:"))
        digest["sha256:".len..]
    else
        digest;
    _ = artifact_pipeline.parseSha256(digest) catch
        return error.InvalidDigest;
    return hex;
}

// ─── OCI manifest resolution ─────────────────────────────────────────────────

/// Walk the parsed JSON index and return an owned copy of the requested Linux
/// platform manifest digest.
pub fn selectLinuxManifest(
    gpa: Allocator,
    index_doc: std.json.Value,
    oci_architecture: []const u8,
) ![]u8 {
    const manifests_val = switch (index_doc) {
        .object => |obj| obj.get("manifests") orelse return error.NoLinuxArchitectureManifest,
        else => return error.NoLinuxArchitectureManifest,
    };
    const items = switch (manifests_val) {
        .array => |a| a.items,
        else => return error.NoLinuxArchitectureManifest,
    };
    for (items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };
        const platform = switch (obj.get("platform") orelse continue) {
            .object => |p| p,
            else => continue,
        };
        const os_str = switch (platform.get("os") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        const arch_str = switch (platform.get("architecture") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        if (!std.mem.eql(u8, os_str, "linux")) continue;
        if (!std.mem.eql(u8, arch_str, oci_architecture)) continue;
        const dig = switch (obj.get("digest") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        return gpa.dupe(u8, dig);
    }
    return error.NoLinuxArchitectureManifest;
}

/// Fetch `url` with optional `Accept:` header via curl.
/// Returns owned stdout bytes on HTTP 200; caller frees.
fn fetchBytes(gpa: Allocator, io: Io, url: []const u8, accept: ?[]const u8) ![]u8 {
    if (accept) |a| {
        const hdr = try std.fmt.allocPrint(gpa, "Accept: {s}", .{a});
        defer gpa.free(hdr);
        return capture(gpa, io, &.{ "curl", "-fsSL", "-H", hdr, url });
    }
    return capture(gpa, io, &.{ "curl", "-fsSL", url });
}

/// Resolve `repository:reference` on MCR, following an index to the requested
/// Linux architecture if needed.
/// Returns manifest JSON bytes and the manifest's sha256 digest (both caller-owned).
fn resolveManifest(
    gpa: Allocator,
    io: Io,
    repository: []const u8,
    reference: []const u8,
    architecture: *const ArchitectureDescriptor,
) !struct { bytes: []u8, digest: []u8 } {
    const url = try std.fmt.allocPrint(gpa, "{s}/{s}/manifests/{s}", .{ mcr_base, repository, reference });
    defer gpa.free(url);

    const manifest_bytes = try fetchBytes(gpa, io, url, accept_header);
    var return_manifest_bytes = false;
    defer if (!return_manifest_bytes) gpa.free(manifest_bytes);

    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, manifest_bytes, .{});
    defer parsed.deinit();

    const media_type: []const u8 = switch (parsed.value) {
        .object => |obj| switch (obj.get("mediaType") orelse .null) {
            .string => |s| s,
            else => "",
        },
        else => "",
    };

    const is_index = std.mem.eql(u8, media_type, oci_index_type) or
        std.mem.eql(u8, media_type, docker_index_type);

    if (!is_index) {
        const hex = sha256Bytes(manifest_bytes);
        const digest = try std.fmt.allocPrint(gpa, "sha256:{s}", .{&hex});
        return_manifest_bytes = true;
        return .{ .bytes = manifest_bytes, .digest = digest };
    }

    // It's an index — find and fetch the requested Linux platform manifest.
    const platform_digest = try selectLinuxManifest(gpa, parsed.value, architecture.oci_architecture);
    defer gpa.free(platform_digest);

    const m_url = try std.fmt.allocPrint(gpa, "{s}/{s}/manifests/{s}", .{ mcr_base, repository, platform_digest });
    defer gpa.free(m_url);

    const platform_bytes = try fetchBytes(gpa, io, m_url, accept_header);
    errdefer gpa.free(platform_bytes);

    const actual_hex = sha256Bytes(platform_bytes);
    const actual_digest = try std.fmt.allocPrint(gpa, "sha256:{s}", .{&actual_hex});
    defer gpa.free(actual_digest);

    if (!std.mem.eql(u8, actual_digest, platform_digest)) {
        std.debug.print("error: manifest digest mismatch: expected {s}, got {s}\n", .{ platform_digest, actual_digest });
        return error.DigestMismatch;
    }

    const return_digest = try std.fmt.allocPrint(gpa, "sha256:{s}", .{&actual_hex});
    return .{ .bytes = platform_bytes, .digest = return_digest };
}

/// Download a single OCI blob to `dest_path`, verifying sha256.
/// Skips if the file already exists with the correct digest.
fn downloadBlob(
    gpa: Allocator,
    io: Io,
    repository: []const u8,
    digest: []const u8,
    dest_path: []const u8,
) !void {
    const expected = try parseDigestHex(digest);

    // Create parent directory.
    if (std.fs.path.dirname(dest_path)) |parent| {
        Dir.cwd().createDirPath(io, parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    const url = try std.fmt.allocPrint(gpa, "{s}/{s}/blobs/{s}", .{ mcr_base, repository, digest });
    defer gpa.free(url);

    const expected_digest = artifact_pipeline.parseSha256(digest) catch
        return error.InvalidDigest;
    var curl = artifact_pipeline.CurlDownloader{
        .executable_path = "curl",
    };
    const acquired = artifact_pipeline.acquireVerified(
        gpa,
        io,
        .{
            .url = url,
            .destination_path = dest_path,
            .expected_sha256 = expected_digest,
            .max_size = core.max_oci_layer_bytes,
        },
        curl.downloader(),
    ) catch |err| switch (err) {
        error.ChecksumMismatch => {
            std.debug.print("error: blob digest mismatch: expected {s}\n", .{expected});
            return error.DigestMismatch;
        },
        else => return err,
    };
    if (acquired.reused_cache) {
        std.debug.print("  blob {s}...: cached\n", .{expected[0..12]});
    } else {
        std.debug.print("  blob {s}...: verified\n", .{expected[0..12]});
    }
}

/// Acquire the pinned systemd UKI stub RPM in the work-directory cache.
fn acquireSystemdBootRpm(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) ![:0]u8 {
    const cache_path = try systemdBootRpmCachePath(gpa, work_dir, architecture);
    defer gpa.free(cache_path);
    const cache_dir = std.fs.path.dirname(cache_path) orelse return error.InvalidCachePath;
    try Dir.cwd().createDirPath(io, cache_dir);

    const expected_digest = artifact_pipeline.parseSha256(architecture.systemd_boot_rpm_sha256) catch
        return error.InvalidSystemdBootRpmChecksum;
    var curl = artifact_pipeline.CurlDownloader{
        .executable_path = "curl",
    };
    const acquired = try artifact_pipeline.acquireVerified(
        gpa,
        io,
        .{
            .url = architecture.systemd_boot_rpm_url,
            .destination_path = cache_path,
            .expected_sha256 = expected_digest,
            .max_size = systemd_boot_unsigned_rpm_max_bytes,
        },
        curl.downloader(),
    );
    if (acquired.reused_cache) {
        std.debug.print("Systemd boot RPM cached at {s}\n", .{cache_path});
    } else {
        std.debug.print("Systemd boot RPM downloaded and verified: {s}\n", .{cache_path});
    }
    return Dir.cwd().realPathFileAlloc(io, cache_path, gpa);
}

// ─── layer extraction ────────────────────────────────────────────────────────

/// Extract OCI layer `layer_path` into `rootfs_path`, applying whiteouts.
fn extractLayer(gpa: Allocator, io: Io, layer_path: []const u8, rootfs_path: []const u8) !void {
    // List the layer members to find whiteout entries.
    const listing = try capture(gpa, io, &.{ "tar", "-tzf", layer_path });
    defer gpa.free(listing);

    var lines = std.mem.splitScalar(u8, listing, '\n');
    while (lines.next()) |raw_name| {
        if (raw_name.len == 0) continue;
        const rel = (try safeLayerPath(raw_name)) orelse continue;
        const basename = std.fs.path.basename(rel);

        if (std.mem.eql(u8, basename, ".wh..wh..opq")) {
            // Opaque whiteout: remove all children of the parent directory.
            const parent_rel = std.fs.path.dirname(rel) orelse ".";
            const target = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ rootfs_path, parent_rel });
            defer gpa.free(target);
            if (Dir.cwd().statFile(io, target, .{})) |_| {
                try sudo(gpa, io, &.{
                    "find",  target, "-mindepth", "1",  "-maxdepth", "1",
                    "-exec", "rm",   "-rf",       "--", "{}",        "+",
                });
            } else |_| {}
        } else if (std.mem.startsWith(u8, basename, ".wh.")) {
            const real_name = basename[".wh.".len..];
            const parent_rel = std.fs.path.dirname(rel) orelse ".";
            const target = if (std.mem.eql(u8, parent_rel, "."))
                try std.fmt.allocPrint(gpa, "{s}/{s}", .{ rootfs_path, real_name })
            else
                try std.fmt.allocPrint(gpa, "{s}/{s}/{s}", .{ rootfs_path, parent_rel, real_name });
            defer gpa.free(target);
            try sudo(gpa, io, &.{ "rm", "-rf", "--", target });
        }
    }

    try sudo(gpa, io, &.{ "tar", "-xzf", layer_path, "-C", rootfs_path, "--numeric-owner" });
    try sudo(gpa, io, &.{ "find", rootfs_path, "-name", ".wh.*", "-delete" });
}

// ─── rootfs pull ─────────────────────────────────────────────────────────────

/// Pull base image layers into `rootfs_path`.  Returns owned manifest digest.
fn pullRootfs(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    rootfs_path: []const u8,
    architecture: *const ArchitectureDescriptor,
) ![]u8 {
    std.debug.print("Resolving mcr.microsoft.com/{s}:{s}...\n", .{ base_image, base_tag });
    const manifest = try resolveManifest(gpa, io, base_image, base_tag, architecture);
    defer gpa.free(manifest.bytes);
    std.debug.print("Resolved to {s}\n", .{manifest.digest});
    if (!std.mem.eql(u8, manifest.digest, architecture.base_manifest_digest)) {
        std.debug.print(
            "error: {s} {s} manifest changed: expected {s}, got {s}\n",
            .{ architecture.oci_architecture, base_tag, architecture.base_manifest_digest, manifest.digest },
        );
        return error.BaseManifestDigestMismatch;
    }

    if (Dir.cwd().statFile(io, rootfs_path, .{})) |_| {
        try sudo(gpa, io, &.{ "rm", "-rf", "--", rootfs_path });
    } else |_| {}
    try Dir.cwd().createDirPath(io, rootfs_path);

    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, manifest.bytes, .{});
    defer parsed.deinit();

    const layers_val = switch (parsed.value) {
        .object => |obj| obj.get("layers") orelse return error.MissingLayers,
        else => return error.MissingLayers,
    };
    const layers = switch (layers_val) {
        .array => |a| a.items,
        else => return error.MissingLayers,
    };

    const blobs_dir = try std.fmt.allocPrint(gpa, "{s}/downloads/blobs", .{work_dir});
    defer gpa.free(blobs_dir);
    try Dir.cwd().createDirPath(io, blobs_dir);

    for (layers) |layer_item| {
        const layer_obj = switch (layer_item) {
            .object => |o| o,
            else => return error.InvalidLayer,
        };
        const digest = switch (layer_obj.get("digest") orelse return error.MissingDigest) {
            .string => |s| s,
            else => return error.MissingDigest,
        };
        const hex = try parseDigestHex(digest);
        const layer_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ blobs_dir, hex });
        defer gpa.free(layer_path);
        try downloadBlob(gpa, io, base_image, digest, layer_path);
        std.debug.print("Extracting layer {s}...\n", .{hex[0..12]});
        try extractLayer(gpa, io, layer_path, rootfs_path);
    }

    return manifest.digest;
}

// ─── guest content installation ──────────────────────────────────────────────

/// Write a file owned by root inside `rootfs_path`.
fn writeRootFile(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    work_dir: []const u8,
    relative_path: []const u8,
    content: []const u8,
    mode: []const u8,
) !void {
    const basename = std.fs.path.basename(relative_path);
    const tmp_path = try std.fmt.allocPrint(gpa, "{s}/{s}.tmp", .{ work_dir, basename });
    defer gpa.free(tmp_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = tmp_path, .data = content });
    const dest = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ rootfs_path, relative_path });
    defer gpa.free(dest);
    try sudo(gpa, io, &.{ "install", "-D", "-o", "root", "-g", "root", "-m", mode, tmp_path, dest });
    Dir.cwd().deleteFile(io, tmp_path) catch {};
}

fn repositoryMetadataMatches(
    metadata: []const u8,
    architecture: *const ArchitectureDescriptor,
) bool {
    const actual = sha256Bytes(metadata);
    return metadata.len <= repomd_max_bytes and
        std.mem.eql(u8, &actual, architecture.repomd_sha256);
}

/// Fetch the moving repository endpoint into a bounded temporary cache entry.
/// Deleting the entry first intentionally bypasses reusable download caching,
/// so both checks observe the repository's current repomd.xml rather than a
/// previously verified local copy.
fn verifyRemoteRepositoryMetadata(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) !void {
    const metadata_path = try std.fmt.allocPrint(
        gpa,
        "{s}/downloads/repomd-{s}.xml",
        .{ work_dir, architecture.dnf_architecture },
    );
    defer gpa.free(metadata_path);
    const parent = std.fs.path.dirname(metadata_path) orelse return error.InvalidCachePath;
    try Dir.cwd().createDirPath(io, parent);
    Dir.cwd().deleteFile(io, metadata_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    const expected_digest = artifact_pipeline.parseSha256(architecture.repomd_sha256) catch
        return error.InvalidRepositoryMetadataChecksum;
    var curl = artifact_pipeline.CurlDownloader{
        .executable_path = "curl",
    };
    _ = artifact_pipeline.acquireVerified(
        gpa,
        io,
        .{
            .url = architecture.repomd_url,
            .destination_path = metadata_path,
            .expected_sha256 = expected_digest,
            .max_size = repomd_max_bytes,
        },
        curl.downloader(),
    ) catch |err| switch (err) {
        error.ChecksumMismatch => {
            std.debug.print(
                "error: repository metadata mismatch for {s}: expected {s}\n",
                .{ architecture.repomd_url, architecture.repomd_sha256 },
            );
            return error.RepositoryMetadataMismatch;
        },
        else => return err,
    };
}

fn verifyRepositoryMetadataFile(
    io: Io,
    path: []const u8,
    architecture: *const ArchitectureDescriptor,
) !void {
    const actual = try sha256File(io, path);
    if (!std.mem.eql(u8, &actual, architecture.repomd_sha256)) {
        std.debug.print(
            "error: repository metadata mismatch for {s}: expected {s}, got {s}\n",
            .{ path, architecture.repomd_sha256, &actual },
        );
        return error.RepositoryMetadataMismatch;
    }
}

/// DNF hashes cache-directory names. Find its sole repomd.xml in an isolated
/// cache and ensure it is the same pin checked from the remote endpoint.
fn verifyCachedRepositoryMetadata(
    gpa: Allocator,
    io: Io,
    cache_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) !void {
    const matches = try capture(gpa, io, &.{
        "find", cache_dir, "-type", "f", "-path", "*/repodata/repomd.xml", "-print",
    });
    defer gpa.free(matches);

    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, matches, '\n');
    while (lines.next()) |line| {
        const path = std.mem.trim(u8, line, "\r\t ");
        if (path.len == 0) continue;
        if (found != null) return error.AmbiguousCachedRepositoryMetadata;
        found = path;
    }
    try verifyRepositoryMetadataFile(
        io,
        found orelse return error.MissingCachedRepositoryMetadata,
        architecture,
    );
}

const DnfCachePaths = struct {
    // Guest-visible cache used by the installroot transaction.
    cache_dir: []u8,
    persist_dir: []u8,
    cache_opt: []u8,
    persist_opt: []u8,
    // Host cache used only to acquire and verify pinned repository metadata
    // before it is copied into the guest-visible cache.
    metadata_cache_dir: []u8,
    metadata_persist_dir: []u8,
    metadata_cache_opt: []u8,
    metadata_persist_opt: []u8,

    fn deinit(self: *DnfCachePaths, gpa: Allocator) void {
        gpa.free(self.cache_dir);
        gpa.free(self.persist_dir);
        gpa.free(self.cache_opt);
        gpa.free(self.persist_opt);
        gpa.free(self.metadata_cache_dir);
        gpa.free(self.metadata_persist_dir);
        gpa.free(self.metadata_cache_opt);
        gpa.free(self.metadata_persist_opt);
        self.* = undefined;
    }
};

fn prepareDnfCache(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) !DnfCachePaths {
    const cache_guest_dir = try std.fmt.allocPrint(
        gpa,
        "/var/cache/zvmi-dnf-{s}-{s}",
        .{ @tagName(flavor.flavor), architecture.dnf_architecture },
    );
    defer gpa.free(cache_guest_dir);
    const persist_guest_dir = try std.fmt.allocPrint(
        gpa,
        "/var/lib/zvmi-dnf-{s}-{s}",
        .{ @tagName(flavor.flavor), architecture.dnf_architecture },
    );
    defer gpa.free(persist_guest_dir);
    const cache_dir = try std.fmt.allocPrint(gpa, "{s}{s}", .{ rootfs_path, cache_guest_dir });
    errdefer gpa.free(cache_dir);
    const persist_dir = try std.fmt.allocPrint(gpa, "{s}{s}", .{ rootfs_path, persist_guest_dir });
    errdefer gpa.free(persist_dir);
    const cache_opt = try std.fmt.allocPrint(gpa, "--setopt=cachedir={s}", .{cache_guest_dir});
    errdefer gpa.free(cache_opt);
    const persist_opt = try std.fmt.allocPrint(gpa, "--setopt=persistdir={s}", .{persist_guest_dir});
    errdefer gpa.free(persist_opt);
    const metadata_cache_dir = try std.fmt.allocPrint(
        gpa,
        "{s}/dnf-metadata-{s}-{s}",
        .{ work_dir, @tagName(flavor.flavor), architecture.dnf_architecture },
    );
    errdefer gpa.free(metadata_cache_dir);
    const metadata_persist_dir = try std.fmt.allocPrint(
        gpa,
        "{s}/dnf-metadata-persist-{s}-{s}",
        .{ work_dir, @tagName(flavor.flavor), architecture.dnf_architecture },
    );
    errdefer gpa.free(metadata_persist_dir);
    const metadata_cache_opt = try std.fmt.allocPrint(gpa, "--setopt=cachedir={s}", .{metadata_cache_dir});
    errdefer gpa.free(metadata_cache_opt);
    const metadata_persist_opt = try std.fmt.allocPrint(gpa, "--setopt=persistdir={s}", .{metadata_persist_dir});
    errdefer gpa.free(metadata_persist_opt);

    // DNF runs under sudo, so remove stale root-owned directories explicitly
    // before making fresh, flavor-scoped metadata and installroot stores.
    try sudo(gpa, io, &.{ "rm", "-rf", "--", cache_dir, persist_dir, metadata_cache_dir, metadata_persist_dir });
    try sudo(gpa, io, &.{ "install", "-d", "-m", "0755", cache_dir, persist_dir });
    try Dir.cwd().createDirPath(io, metadata_cache_dir);
    try Dir.cwd().createDirPath(io, metadata_persist_dir);
    return .{
        .cache_dir = cache_dir,
        .persist_dir = persist_dir,
        .cache_opt = cache_opt,
        .persist_opt = persist_opt,
        .metadata_cache_dir = metadata_cache_dir,
        .metadata_persist_dir = metadata_persist_dir,
        .metadata_cache_opt = metadata_cache_opt,
        .metadata_persist_opt = metadata_persist_opt,
    };
}

fn captureInstalledNevras(gpa: Allocator, io: Io, rootfs_path: []const u8) ![]u8 {
    return capture(gpa, io, &.{
        "sudo",
        "chroot",
        rootfs_path,
        "/usr/bin/rpm",
        "-qa",
        "--qf",
        "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n",
    });
}

/// Emit packages newly installed by the package transactions in stable
/// lexical NEVRA order, independent of RPM database iteration order.
fn formatInstalledNevraClosure(
    gpa: Allocator,
    before: []const u8,
    after: []const u8,
) ![]u8 {
    var prior = std.StringHashMap(void).init(gpa);
    defer prior.deinit();
    var before_lines = std.mem.splitScalar(u8, before, '\n');
    while (before_lines.next()) |raw| {
        const nevra = std.mem.trim(u8, raw, "\r\t ");
        if (nevra.len != 0) try prior.put(nevra, {});
    }

    var emitted = std.StringHashMap(void).init(gpa);
    defer emitted.deinit();
    var closure = std.array_list.Managed([]u8).init(gpa);
    defer {
        for (closure.items) |nevra| gpa.free(nevra);
        closure.deinit();
    }
    var after_lines = std.mem.splitScalar(u8, after, '\n');
    while (after_lines.next()) |raw| {
        const nevra = std.mem.trim(u8, raw, "\r\t ");
        if (nevra.len == 0 or prior.contains(nevra) or emitted.contains(nevra)) continue;
        try emitted.put(nevra, {});
        try closure.append(try gpa.dupe(u8, nevra));
    }
    std.mem.sortUnstable([]u8, closure.items, {}, struct {
        fn lessThan(_: void, lhs: []u8, rhs: []u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    }.lessThan);

    var output: std.Io.Writer.Allocating = .init(gpa);
    errdefer output.deinit();
    for (closure.items) |nevra| try output.writer.print("{s}\n", .{nevra});
    return output.toOwnedSlice();
}

fn writeNevraProvenance(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
    closure: []const u8,
) !void {
    const provenance_dir = try std.fmt.allocPrint(gpa, "{s}/provenance", .{work_dir});
    defer gpa.free(provenance_dir);
    try Dir.cwd().createDirPath(io, provenance_dir);
    const provenance_path = try std.fmt.allocPrint(
        gpa,
        "{s}/installed-nevra-{s}-{s}.txt",
        .{ provenance_dir, @tagName(flavor.flavor), architecture.dnf_architecture },
    );
    defer gpa.free(provenance_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = provenance_path, .data = closure });
    std.debug.print("Installed NEVRA closure ({s}/{s}) written to {s}:\n{s}", .{
        @tagName(flavor.flavor),
        architecture.dnf_architecture,
        provenance_path,
        closure,
    });
}

/// Install from an already verified DNF metadata cache. `metadata_expire=never`
/// prevents a refresh while deliberately omitting `-C`: package payloads that
/// are referenced by the cached primary metadata may still be downloaded.
fn dnfInstallArgs(
    gpa: Allocator,
    rootfs_path: []const u8,
    forcearch_opt: []const u8,
    repofrompath_opt: []const u8,
    gpgkey_opt: []const u8,
    baseurl_opt: []const u8,
    metalink_opt: []const u8,
    mirrorlist_opt: []const u8,
    metadata_expire_all_opt: []const u8,
    metadata_expire_repo_opt: []const u8,
    keepcache_opt: []const u8,
    gpgcheck_opt: []const u8,
    cache_opt: []const u8,
    persist_opt: []const u8,
    packages: []const []const u8,
) ![]const []const u8 {
    var args = std.array_list.Managed([]const u8).init(gpa);
    errdefer args.deinit();
    try args.appendSlice(&.{
        "dnf",
        "-y",
        "--installroot",
        rootfs_path,
        "--releasever=4.0",
        forcearch_opt,
        "--disablerepo=*",
        repofrompath_opt,
        "--enablerepo=" ++ dnf_repository_id,
        gpgkey_opt,
        baseurl_opt,
        metalink_opt,
        mirrorlist_opt,
        metadata_expire_all_opt,
        metadata_expire_repo_opt,
        keepcache_opt,
        gpgcheck_opt,
        cache_opt,
        persist_opt,
        dnf_minrate_opt,
        dnf_timeout_opt,
        dnf_retries_opt,
        "--setopt=install_weak_deps=False",
        "install",
    });
    try args.appendSlice(packages);
    return args.toOwnedSlice();
}

fn dnfSeedMakecacheArgs(
    forcearch_opt: []const u8,
    repofrompath_opt: []const u8,
    gpgkey_opt: []const u8,
    baseurl_opt: []const u8,
    metalink_opt: []const u8,
    mirrorlist_opt: []const u8,
    metadata_expire_all_opt: []const u8,
    metadata_expire_repo_opt: []const u8,
    keepcache_opt: []const u8,
    gpgcheck_opt: []const u8,
    cache_opt: []const u8,
    persist_opt: []const u8,
) [21][]const u8 {
    return .{
        "dnf",
        "-y",
        "--releasever=4.0",
        forcearch_opt,
        "--disablerepo=*",
        repofrompath_opt,
        "--enablerepo=" ++ dnf_repository_id,
        gpgkey_opt,
        baseurl_opt,
        metalink_opt,
        mirrorlist_opt,
        metadata_expire_all_opt,
        metadata_expire_repo_opt,
        keepcache_opt,
        gpgcheck_opt,
        cache_opt,
        persist_opt,
        dnf_minrate_opt,
        dnf_timeout_opt,
        dnf_retries_opt,
        "makecache",
    };
}

const InitialNevraState = enum {
    query_existing_installroot,
    empty_fresh_installroot,
};

fn initialNevraState(flavor: *const FlavorDescriptor) InitialNevraState {
    return switch (flavor.flavor) {
        .core => .query_existing_installroot,
        .full => .empty_fresh_installroot,
    };
}

fn initialInstalledNevras(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    flavor: *const FlavorDescriptor,
) ![]u8 {
    return switch (initialNevraState(flavor)) {
        .query_existing_installroot => captureInstalledNevras(gpa, io, rootfs_path),
        .empty_fresh_installroot => gpa.dupe(u8, ""),
    };
}

fn argvContains(argv: []const []const u8, needle: []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, needle)) return true;
    }
    return false;
}

fn argvIndex(argv: []const []const u8, needle: []const u8) ?usize {
    for (argv, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, needle)) return index;
    }
    return null;
}

fn packagesForFlavor(
    gpa: Allocator,
    flavor: *const FlavorDescriptor,
    architecture: *const ArchitectureDescriptor,
) ![][]const u8 {
    const efi_len: usize = if (flavor.flavor == .full) architecture.full_efi_packages.len else 0;
    const packages = try gpa.alloc([]const u8, flavor.required_packages.len + efi_len);
    @memcpy(packages[0..flavor.required_packages.len], flavor.required_packages);
    if (efi_len != 0) {
        @memcpy(packages[flavor.required_packages.len..], architecture.full_efi_packages);
    }
    return packages;
}

fn packagesForInstall(
    gpa: Allocator,
    flavor: *const FlavorDescriptor,
    architecture: *const ArchitectureDescriptor,
) ![][]const u8 {
    const packages = try packagesForFlavor(gpa, flavor, architecture);
    for (flavor.required_packages, 0..) |package, index| {
        packages[index] = if (flavor.flavor == .full and std.mem.eql(u8, package, "kernel"))
            architecture.full_kernel_package
        else if (flavor.flavor == .full and std.mem.eql(u8, package, "kernel-modules"))
            architecture.full_kernel_modules_package
        else
            package;
    }
    return packages;
}

fn validateRequiredPackages(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    packages: []const []const u8,
) !void {
    var argv = std.array_list.Managed([]const u8).init(gpa);
    defer argv.deinit();
    try argv.appendSlice(&.{ "sudo", "chroot", rootfs_path, "/usr/bin/rpm", "-q", "--whatprovides" });
    try argv.appendSlice(packages);
    try run(gpa, io, argv.items);
}

fn validateForbiddenPackages(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    packages: []const []const u8,
) !void {
    for (packages) |package| {
        const result = std.process.run(gpa, io, .{
            .argv = &.{ "sudo", "chroot", rootfs_path, "/usr/bin/rpm", "-q", package },
        }) catch return error.CommandFailed;
        defer {
            gpa.free(result.stdout);
            gpa.free(result.stderr);
        }
        switch (result.term) {
            .exited => |code| if (code == 0) return error.ForbiddenPackageInstalled,
            else => return error.ForbiddenPackageInstalled,
        }
    }
}

fn rootfsPath(rootfs_path: []const u8, gpa: Allocator, relative_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ rootfs_path, relative_path });
}

fn validateFlavorPaths(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    flavor: *const FlavorDescriptor,
) !void {
    for (flavor.required_rootfs_paths) |relative_path| {
        const path = try rootfsPath(rootfs_path, gpa, relative_path);
        defer gpa.free(path);
        const stat = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch {
            std.debug.print("error: {s} rootfs is missing /{s}\n", .{ @tagName(flavor.flavor), relative_path });
            return error.IncompleteFlavorRootfs;
        };
        if (stat.kind != .file) return error.IncompleteFlavorRootfs;
    }
    for (flavor.forbidden_rootfs_paths) |relative_path| {
        const path = try rootfsPath(rootfs_path, gpa, relative_path);
        defer gpa.free(path);
        if (Dir.cwd().statFile(io, path, .{ .follow_symlinks = false })) |_| {
            std.debug.print("error: {s} rootfs contains forbidden /{s}\n", .{ @tagName(flavor.flavor), relative_path });
            return error.ForbiddenFlavorRootfsPath;
        } else |_| {}
    }
}

const azurelinux_signing_key_sha256 = "1092f37ec429e58bf9c7f898df17c3c32eb2ce3c4c037afb8ffe2d2b42e16e89";
const azurelinux_signing_key_fingerprint = "2BC94FFF7015A5F28F1537AD0CD9FED33135CE90";

fn trustedSigningKeyPath(
    gpa: Allocator,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "{s}/trusted-rpm-gpg-{s}.asc",
        .{ work_dir, architecture.dnf_architecture },
    );
}

fn canonicalTrustedSigningKeyPath(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) ![:0]u8 {
    const path = try trustedSigningKeyPath(gpa, work_dir, architecture);
    defer gpa.free(path);
    return Dir.cwd().realPathFileAlloc(io, path, gpa);
}

fn fileUriFromAbsolutePath(gpa: Allocator, path: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(path)) return error.RelativeFileUriPath;
    var uri: std.Io.Writer.Allocating = .init(gpa);
    errdefer uri.deinit();
    try uri.writer.writeAll("file://");
    for (path) |byte| {
        const is_unreserved = std.ascii.isAlphanumeric(byte) or
            std.mem.indexOfScalar(u8, "-._~/", byte) != null;
        if (is_unreserved) {
            try uri.writer.writeByte(byte);
        } else {
            try uri.writer.print("%{X:0>2}", .{byte});
        }
    }
    return uri.toOwnedSlice();
}

fn validateTrustedSigningKey(
    gpa: Allocator,
    io: Io,
    key_path: []const u8,
) !void {
    const actual = try sha256File(io, key_path);
    if (!std.mem.eql(u8, &actual, azurelinux_signing_key_sha256)) {
        std.debug.print("error: Azure Linux RPM signing key checksum mismatch\n", .{});
        return error.InvalidAzureLinuxSigningKey;
    }
    const key_listing = try capture(gpa, io, &.{ "gpg", "--show-keys", "--with-colons", key_path });
    defer gpa.free(key_listing);
    if (std.mem.indexOf(u8, key_listing, "fpr:::::::::" ++ azurelinux_signing_key_fingerprint ++ ":") == null) {
        std.debug.print("error: Azure Linux RPM signing key fingerprint mismatch\n", .{});
        return error.InvalidAzureLinuxSigningKey;
    }
}

/// Extract only the verified signing key from the pinned core OCI rootfs.
/// Full images discard this rootfs immediately after extraction and never
/// publish a core filesystem layer.
fn extractTrustedSigningKey(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) ![:0]u8 {
    const signing_key_guest = try std.fmt.allocPrint(
        gpa,
        "{s}/{s}",
        .{ rootfs_path, architecture.signing_key_path },
    );
    defer gpa.free(signing_key_guest);
    const host_key = try trustedSigningKeyPath(gpa, work_dir, architecture);
    defer gpa.free(host_key);
    try sudo(gpa, io, &.{ "install", "-m", "0644", signing_key_guest, host_key });
    const canonical_key = try canonicalTrustedSigningKeyPath(gpa, io, work_dir, architecture);
    errdefer gpa.free(canonical_key);
    try validateTrustedSigningKey(gpa, io, canonical_key);
    return canonical_key;
}

fn bootstrapFullRootfs(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    rootfs_path: []const u8,
    architecture: *const ArchitectureDescriptor,
) ![]u8 {
    const key_source_path = try std.fmt.allocPrint(gpa, "{s}/core-key-source", .{work_dir});
    defer gpa.free(key_source_path);
    const core_digest = try pullRootfs(gpa, io, work_dir, key_source_path, architecture);
    errdefer gpa.free(core_digest);
    const key_path = try extractTrustedSigningKey(gpa, io, key_source_path, work_dir, architecture);
    gpa.free(key_path);
    try sudo(gpa, io, &.{ "rm", "-rf", "--", key_source_path });
    if (Dir.cwd().statFile(io, rootfs_path, .{})) |_| {
        try sudo(gpa, io, &.{ "rm", "-rf", "--", rootfs_path });
    } else |_| {}
    try Dir.cwd().createDirPath(io, rootfs_path);
    return core_digest;
}

/// DNF creates the RPM database itself.  A full rootfs is intentionally empty
/// here (apart from these directories and a temporary binfmt interpreter), so
/// no guest `rpm` command may run before the first package transaction.
fn initializeFreshFullInstallroot(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
) !void {
    const rpm_db = try std.fmt.allocPrint(gpa, "{s}/var/lib/rpm", .{rootfs_path});
    defer gpa.free(rpm_db);
    const dnf_state = try std.fmt.allocPrint(gpa, "{s}/var/lib/dnf", .{rootfs_path});
    defer gpa.free(dnf_state);
    const etc = try std.fmt.allocPrint(gpa, "{s}/etc", .{rootfs_path});
    defer gpa.free(etc);
    try sudo(gpa, io, &.{ "install", "-d", "-m", "0755", rootfs_path, etc, rpm_db, dnf_state });
}

fn configValueEquals(content: []const u8, key: []const u8, expected: []const u8) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "#")) continue;
        const equal = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        if (std.mem.eql(u8, std.mem.trim(u8, trimmed[0..equal], " \t"), key)) {
            return std.mem.eql(u8, std.mem.trim(u8, trimmed[equal + 1 ..], " \t"), expected);
        }
    }
    return false;
}

fn sysusersDefinesHome(content: []const u8, user: []const u8, home: []const u8) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or std.mem.startsWith(u8, trimmed, "#")) continue;
        var fields = std.mem.tokenizeAny(u8, trimmed, " \t");
        if (!std.mem.eql(u8, fields.next() orelse continue, "u")) continue;
        if (!std.mem.eql(u8, fields.next() orelse continue, user)) continue;
        while (fields.next()) |field| {
            if (std.mem.eql(u8, field, home)) return true;
        }
    }
    return false;
}

fn chronyStateContractMatches(service: []const u8, sysusers: []const u8) bool {
    return configValueEquals(service, "User", "chrony") and
        configValueEquals(service, "StateDirectory", "chrony") and
        configValueEquals(service, "StateDirectoryMode", "0750") and
        sysusersDefinesHome(sysusers, "chrony", "/var/lib/chrony");
}

fn selinuxLabelIsUsable(label: []const u8) bool {
    return std.mem.indexOf(u8, label, ":object_r:") != null and
        std.mem.indexOf(u8, label, ":unlabeled_t:") == null;
}

fn setRootConfigValue(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    work_dir: []const u8,
    relative_path: []const u8,
    key: []const u8,
    value: []const u8,
) !void {
    const path = try rootfsPath(rootfs_path, gpa, relative_path);
    defer gpa.free(path);
    const existing = capture(gpa, io, &.{ "sudo", "cat", path }) catch |err| switch (err) {
        error.CommandFailed => try gpa.dupe(u8, ""),
        else => return err,
    };
    defer gpa.free(existing);

    var output: std.Io.Writer.Allocating = .init(gpa);
    defer output.deinit();
    var found = false;
    var lines = std.mem.splitScalar(u8, existing, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        const equal = std.mem.indexOfScalar(u8, trimmed, '=');
        if (equal) |index| {
            if (std.mem.eql(u8, std.mem.trim(u8, trimmed[0..index], " \t"), key)) {
                if (!found) try output.writer.print("{s}={s}\n", .{ key, value });
                found = true;
                continue;
            }
        }
        if (line.len != 0) try output.writer.print("{s}\n", .{line});
    }
    if (!found) try output.writer.print("{s}={s}\n", .{ key, value });
    const content = try output.toOwnedSlice();
    defer gpa.free(content);
    try writeRootFile(gpa, io, rootfs_path, work_dir, relative_path, content, "0644");
}

fn validateFullServiceFiles(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
) !void {
    for (full_required_systemd_units) |unit| {
        const path = try std.fmt.allocPrint(gpa, "{s}/usr/lib/systemd/system/{s}", .{ rootfs_path, unit });
        defer gpa.free(path);
        const stat = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch {
            std.debug.print("error: full rootfs is missing systemd unit {s}\n", .{unit});
            return error.MissingFullServiceUnit;
        };
        if (stat.kind != .file and stat.kind != .sym_link) return error.MissingFullServiceUnit;
    }
}

fn validateFullMergedUsrLayout(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
) !void {
    const expected_links = [_]struct {
        path: []const u8,
        target: []const u8,
    }{
        .{ .path = "sbin", .target = "usr/sbin" },
        .{ .path = "lib", .target = "usr/lib" },
        .{ .path = "lib64", .target = "usr/lib64" },
        .{ .path = "usr/bin/init", .target = "../lib/systemd/systemd" },
    };
    for (expected_links) |expected| {
        const path = try rootfsPath(rootfs_path, gpa, expected.path);
        defer gpa.free(path);
        const stat = try Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
        if (stat.kind != .sym_link) return error.InvalidMergedUsrLayout;
        const target = try capture(gpa, io, &.{ "sudo", "readlink", path });
        defer gpa.free(target);
        if (!std.mem.eql(u8, std.mem.trim(u8, target, " \t\r\n"), expected.target)) {
            return error.InvalidMergedUsrLayout;
        }
    }
    const systemd = try rootfsPath(rootfs_path, gpa, "usr/lib/systemd/systemd");
    defer gpa.free(systemd);
    const systemd_stat = try Dir.cwd().statFile(io, systemd, .{ .follow_symlinks = false });
    if (!isRegularNonemptyFile(systemd_stat.kind, systemd_stat.size)) return error.InvalidMergedUsrLayout;
}

fn configureFullGuest(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    work_dir: []const u8,
) !void {
    // The vm-base profile delegates account/key provisioning to cloud-init.
    // WALinuxAgent remains responsible for Ready status and extensions.
    try setRootConfigValue(gpa, io, rootfs_path, work_dir, "etc/waagent.conf", "Provisioning.Agent", "auto");
    try setRootConfigValue(gpa, io, rootfs_path, work_dir, "etc/waagent.conf", "ResourceDisk.Format", "n");
    try setRootConfigValue(gpa, io, rootfs_path, work_dir, "etc/waagent.conf", "ResourceDisk.EnableSwap", "n");
    try writeRootFile(
        gpa,
        io,
        rootfs_path,
        work_dir,
        "etc/systemd/network/20-wired.network",
        full_networkd_config,
        "0644",
    );
    try writeRootFile(gpa, io, rootfs_path, work_dir, "etc/ssh/sshd_config.d/20-zvmi-full.conf", "PasswordAuthentication no\n" ++
        "PermitEmptyPasswords no\n" ++
        "PubkeyAuthentication yes\n" ++
        "KbdInteractiveAuthentication no\n", "0600");
    const waagent_version = try capture(gpa, io, &.{
        "sudo", "chroot", rootfs_path, "/usr/bin/rpm", "-q", "--qf", "%{VERSION}", "WALinuxAgent",
    });
    defer gpa.free(waagent_version);
    if (!std.mem.startsWith(u8, std.mem.trim(u8, waagent_version, " \t\r\n"), "2.15.")) {
        return error.UnsupportedWALinuxAgentVersion;
    }
    try validateFullServiceFiles(gpa, io, rootfs_path);
    try sudo(gpa, io, &.{ "systemctl", "--root", rootfs_path, "preset-all" });
    var enable_argv = std.array_list.Managed([]const u8).init(gpa);
    defer enable_argv.deinit();
    try enable_argv.appendSlice(&.{ "systemctl", "--root", rootfs_path, "enable" });
    try enable_argv.appendSlice(&full_enabled_systemd_units);
    try sudo(gpa, io, enable_argv.items);
    for (full_enabled_systemd_units) |unit| {
        const enabled = try capture(gpa, io, &.{ "systemctl", "--root", rootfs_path, "is-enabled", unit });
        defer gpa.free(enabled);
        if (!std.mem.eql(u8, std.mem.trim(u8, enabled, " \t\r\n"), "enabled")) {
            return error.FullServiceNotEnabled;
        }
    }
    try sudo(gpa, io, &.{ "chroot", rootfs_path, "/usr/bin/ssh-keygen", "-A" });
    try sudo(gpa, io, &.{ "chroot", rootfs_path, "/usr/bin/sshd", "-t" });
}

fn labelFullRootfs(gpa: Allocator, io: Io, rootfs_path: []const u8) !void {
    try sudo(gpa, io, &.{
        "chroot",
        rootfs_path,
        "/usr/sbin/setfiles",
        "-F",
        "/etc/selinux/targeted/contexts/files/file_contexts",
        "/",
    });
}

fn configureCoreGuest(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    work_dir: []const u8,
    zvminit_path: []const u8,
    azagent_path: []const u8,
) !void {
    const sbin_zvminit = try std.fmt.allocPrint(gpa, "{s}/sbin/zvminit", .{rootfs_path});
    defer gpa.free(sbin_zvminit);
    try sudo(gpa, io, &.{ "install", "-m", "0755", zvminit_path, sbin_zvminit });
    for (&[_][]const u8{ "init", "poweroff", "reboot", "shutdown" }) |cmd| {
        const link = try std.fmt.allocPrint(gpa, "{s}/sbin/{s}", .{ rootfs_path, cmd });
        defer gpa.free(link);
        try sudo(gpa, io, &.{ "rm", "-f", link });
        try sudo(gpa, io, &.{ "ln", "-s", "zvminit", link });
    }
    const azagent_dest = try std.fmt.allocPrint(gpa, "{s}/usr/sbin/azagent", .{rootfs_path});
    defer gpa.free(azagent_dest);
    try sudo(gpa, io, &.{ "install", "-m", "0755", azagent_path, azagent_dest });
    try writeRootFile(gpa, io, rootfs_path, work_dir, "etc/ssh/sshd_config.d/10-zvminit.conf", "PasswordAuthentication no\n" ++
        "PermitEmptyPasswords no\n" ++
        "PubkeyAuthentication yes\n", "0600");
    try writeRootFile(gpa, io, rootfs_path, work_dir, "etc/waagent.conf", "ResourceDisk.Format=y\n" ++
        "ResourceDisk.Filesystem=ext4\n" ++
        "ResourceDisk.MountPoint=/d\n" ++
        "ResourceDisk.EnableSwap=n\n" ++
        "DataDisk.Mount=y\n", "0644");
    try sudo(gpa, io, &.{ "chroot", rootfs_path, "/usr/bin/ssh-keygen", "-A" });
    try sudo(gpa, io, &.{ "chroot", rootfs_path, "/usr/sbin/sshd", "-t" });
    try run(gpa, io, &.{ "file", sbin_zvminit, azagent_dest });
}

fn generalizeRootfs(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    flavor: *const FlavorDescriptor,
) !void {
    const etc_ssh = try std.fmt.allocPrint(gpa, "{s}/etc/ssh", .{rootfs_path});
    defer gpa.free(etc_ssh);
    const machine_id = try std.fmt.allocPrint(gpa, "{s}/etc/machine-id", .{rootfs_path});
    defer gpa.free(machine_id);
    const hostname = try std.fmt.allocPrint(gpa, "{s}/etc/hostname", .{rootfs_path});
    defer gpa.free(hostname);
    const dbus_machine_id = try std.fmt.allocPrint(gpa, "{s}/var/lib/dbus/machine-id", .{rootfs_path});
    defer gpa.free(dbus_machine_id);
    const cloud_state = try std.fmt.allocPrint(gpa, "{s}/var/lib/cloud", .{rootfs_path});
    defer gpa.free(cloud_state);
    const waagent_state = try std.fmt.allocPrint(gpa, "{s}/var/lib/waagent", .{rootfs_path});
    defer gpa.free(waagent_state);
    const azagent_state = try std.fmt.allocPrint(gpa, "{s}/var/lib/azagent", .{rootfs_path});
    defer gpa.free(azagent_state);
    const random_seed = try std.fmt.allocPrint(gpa, "{s}/var/lib/systemd/random-seed", .{rootfs_path});
    defer gpa.free(random_seed);
    const leases = try std.fmt.allocPrint(gpa, "{s}/var/lib/NetworkManager", .{rootfs_path});
    defer gpa.free(leases);
    try sudo(gpa, io, &.{ "find", etc_ssh, "-maxdepth", "1", "-name", "ssh_host_*", "-delete" });
    try sudo(gpa, io, &.{ "find", rootfs_path, "-type", "f", "-name", "authorized_keys", "-delete" });
    try sudo(gpa, io, &.{ "rm", "-f", hostname, dbus_machine_id, random_seed });
    try sudo(gpa, io, &.{ "rm", "-rf", cloud_state, waagent_state, azagent_state, leases });
    if (flavor.flavor == .full) {
        try sudo(gpa, io, &.{ "install", "-d", "-m", "0755", cloud_state });
        try sudo(gpa, io, &.{ "install", "-d", "-o", "root", "-g", "root", "-m", "0700", waagent_state });
    }
    try sudo(gpa, io, &.{ "truncate", "-s", "0", machine_id });
}

fn waagentStateContractMatches(uid: u32, gid: u32, mode: u16) bool {
    return uid == 0 and gid == 0 and mode == 0o700;
}

fn validateFullWaagentState(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
) !void {
    const path = try rootfsPath(rootfs_path, gpa, "var/lib/waagent");
    defer gpa.free(path);
    const stat = try capture(gpa, io, &.{ "sudo", "stat", "-c", "%u:%g:%a", path });
    defer gpa.free(stat);
    if (!std.mem.eql(u8, std.mem.trim(u8, stat, " \t\r\n"), "0:0:700")) {
        return error.InvalidWALinuxAgentStateMetadata;
    }
}

fn validateGeneralizedRootfs(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    flavor: *const FlavorDescriptor,
) !void {
    try validateFlavorPaths(gpa, io, rootfs_path, flavor);
    const machine_id = try rootfsPath(rootfs_path, gpa, "etc/machine-id");
    defer gpa.free(machine_id);
    const machine_id_stat = try Dir.cwd().statFile(io, machine_id, .{});
    if (machine_id_stat.size != 0) return error.GeneratedMachineId;
    const generated = try capture(gpa, io, &.{
        "sudo",   "find",            rootfs_path, "-type", "f",          "(",
        "-name",  "authorized_keys", "-o",        "-name", "ssh_host_*", ")",
        "-print",
    });
    defer gpa.free(generated);
    if (std.mem.trim(u8, generated, " \t\r\n").len != 0) return error.BakedIdentityState;
    const state_paths = [_][]const u8{
        "var/lib/cloud/instance",
        "var/lib/waagent",
        "var/lib/azagent/provisioned",
    };
    for (state_paths) |relative_path| {
        const path = try rootfsPath(rootfs_path, gpa, relative_path);
        defer gpa.free(path);
        if (Dir.cwd().statFile(io, path, .{ .follow_symlinks = false })) |stat| {
            if (stat.kind == .directory) {
                const entries = try capture(gpa, io, &.{
                    "sudo", "find", path, "-mindepth", "1", "-print", "-quit",
                });
                defer gpa.free(entries);
                if (std.mem.trim(u8, entries, " \t\r\n").len == 0) continue;
            }
            return error.BakedProvisioningState;
        } else |_| {}
    }
    if (flavor.flavor == .full) {
        try validateFullWaagentState(gpa, io, rootfs_path);
        const waagent_conf = try rootfsPath(rootfs_path, gpa, "etc/waagent.conf");
        defer gpa.free(waagent_conf);
        const content = try capture(gpa, io, &.{ "sudo", "cat", waagent_conf });
        defer gpa.free(content);
        if (!configValueEquals(content, "Provisioning.Agent", "auto") or
            !configValueEquals(content, "ResourceDisk.Format", "n"))
        {
            return error.InvalidFullProvisioningConfiguration;
        }
    }
}
/// Install the flavor's pinned package closure and configuration into rootfs.
/// The returned NEVRA closure is retained by OCI provenance construction.
fn installGuestContent(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    work_dir: []const u8,
    trusted_key_path: []const u8,
    zvminit_path: ?[]const u8,
    azagent_path: ?[]const u8,
    systemd_boot_rpm_path: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) ![]u8 {
    if (flavor.flavor == .full) {
        try initializeFreshFullInstallroot(gpa, io, rootfs_path);
    }

    // On a non-native builder, put the registered static interpreter in the
    // target root just for RPM scriptlets, then remove it before layering.
    const target_is_native = builtin.target.cpu.arch == architecture.target_cpu;
    var binfmt_interpreter: ?[]u8 = null;
    defer if (binfmt_interpreter) |b| gpa.free(b);

    if (!target_is_native) {
        const reg = readPseudoFile(gpa, architecture.binfmt_registration_path) catch |err| {
            std.debug.print(
                "error: {s} binfmt not available ({s}); install {s}\n",
                .{ architecture.binfmt_registration_name, @errorName(err), architecture.binfmt_static_name },
            );
            return error.BinfmtMissing;
        };
        defer gpa.free(reg);
        var reg_lines = std.mem.splitScalar(u8, reg, '\n');
        if (!std.mem.eql(u8, reg_lines.next() orelse "", "enabled")) {
            std.debug.print("error: {s} binfmt registration is disabled\n", .{architecture.binfmt_registration_name});
            return error.BinfmtDisabled;
        }
        var interp_path: ?[]const u8 = null;
        while (reg_lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "interpreter ")) {
                interp_path = line["interpreter ".len..];
                break;
            }
        }
        const interp = interp_path orelse {
            std.debug.print("error: no interpreter line in binfmt registration\n", .{});
            return error.BinfmtMissing;
        };
        binfmt_interpreter = try gpa.dupe(u8, interp);

        const qemu_static_bytes = try capture(gpa, io, &.{ "which", architecture.binfmt_static_name });
        defer gpa.free(qemu_static_bytes);
        const qemu_static = std.mem.trimEnd(u8, qemu_static_bytes, "\n\r ");
        const interp_rel = std.mem.trimStart(u8, interp, "/");
        const guest_interp = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ rootfs_path, interp_rel });
        defer gpa.free(guest_interp);
        try sudo(gpa, io, &.{ "install", "-D", "-m", "0755", qemu_static, guest_interp });
    }

    try validateTrustedSigningKey(gpa, io, trusted_key_path);
    const signing_key_uri = try fileUriFromAbsolutePath(gpa, trusted_key_path);
    defer gpa.free(signing_key_uri);
    const gpgkey_opt = try std.fmt.allocPrint(
        gpa,
        "--setopt=" ++ dnf_repository_id ++ ".gpgkey={s}",
        .{signing_key_uri},
    );
    defer gpa.free(gpgkey_opt);
    const forcearch_opt = try std.fmt.allocPrint(gpa, "--forcearch={s}", .{architecture.dnf_architecture});
    defer gpa.free(forcearch_opt);

    // Resolve only against a new, private cache. First pin the live endpoint,
    // then populate and verify DNF's copy. The installation keeps that metadata
    // non-expiring while allowing payload downloads checked by the pinned
    // primary metadata and configured RPM signing key.
    try verifyRemoteRepositoryMetadata(gpa, io, work_dir, architecture);
    var dnf_cache = try prepareDnfCache(gpa, io, rootfs_path, work_dir, architecture, flavor);
    defer dnf_cache.deinit(gpa);
    const baseurl_opt = try std.fmt.allocPrint(
        gpa,
        "--setopt=" ++ dnf_repository_id ++ ".baseurl={s}",
        .{architecture.repository_base_url},
    );
    defer gpa.free(baseurl_opt);
    const repofrompath_opt = try std.fmt.allocPrint(
        gpa,
        "--repofrompath=" ++ dnf_repository_id ++ ",{s}",
        .{architecture.repository_base_url},
    );
    defer gpa.free(repofrompath_opt);
    const metadata_expire_all_opt = "--setopt=metadata_expire=never";
    const metadata_expire_repo_opt = "--setopt=" ++ dnf_repository_id ++ ".metadata_expire=never";
    const metalink_opt = "--setopt=" ++ dnf_repository_id ++ ".metalink=";
    const mirrorlist_opt = "--setopt=" ++ dnf_repository_id ++ ".mirrorlist=";
    const keepcache_opt = "--setopt=keepcache=True";
    const gpgcheck_opt = "--setopt=" ++ dnf_repository_id ++ ".gpgcheck=True";
    const makecache_argv = dnfSeedMakecacheArgs(
        forcearch_opt,
        repofrompath_opt,
        gpgkey_opt,
        baseurl_opt,
        metalink_opt,
        mirrorlist_opt,
        metadata_expire_all_opt,
        metadata_expire_repo_opt,
        keepcache_opt,
        gpgcheck_opt,
        dnf_cache.metadata_cache_opt,
        dnf_cache.metadata_persist_opt,
    );
    try sudo(gpa, io, &makecache_argv);
    try verifyCachedRepositoryMetadata(gpa, io, dnf_cache.metadata_cache_dir, architecture);
    const metadata_cache_contents = try std.fmt.allocPrint(gpa, "{s}/.", .{dnf_cache.metadata_cache_dir});
    defer gpa.free(metadata_cache_contents);
    const metadata_persist_contents = try std.fmt.allocPrint(gpa, "{s}/.", .{dnf_cache.metadata_persist_dir});
    defer gpa.free(metadata_persist_contents);
    const cache_contents = try std.fmt.allocPrint(gpa, "{s}/.", .{dnf_cache.cache_dir});
    defer gpa.free(cache_contents);
    const persist_contents = try std.fmt.allocPrint(gpa, "{s}/.", .{dnf_cache.persist_dir});
    defer gpa.free(persist_contents);
    try sudo(gpa, io, &.{ "cp", "-a", metadata_cache_contents, cache_contents });
    try sudo(gpa, io, &.{ "cp", "-a", metadata_persist_contents, persist_contents });
    try verifyCachedRepositoryMetadata(gpa, io, dnf_cache.cache_dir, architecture);

    const installed_before = try initialInstalledNevras(gpa, io, rootfs_path, flavor);
    defer gpa.free(installed_before);
    const flavor_packages = try packagesForFlavor(gpa, flavor, architecture);
    defer gpa.free(flavor_packages);
    const install_packages = try packagesForInstall(gpa, flavor, architecture);
    defer gpa.free(install_packages);
    const package_install_argv = try dnfInstallArgs(
        gpa,
        rootfs_path,
        forcearch_opt,
        repofrompath_opt,
        gpgkey_opt,
        baseurl_opt,
        metalink_opt,
        mirrorlist_opt,
        metadata_expire_all_opt,
        metadata_expire_repo_opt,
        keepcache_opt,
        gpgcheck_opt,
        dnf_cache.cache_opt,
        dnf_cache.persist_opt,
        install_packages,
    );
    defer gpa.free(package_install_argv);
    try sudo(gpa, io, package_install_argv);

    // Install the pinned local RPM in a separate, repository-free transaction.
    try sudo(gpa, io, &.{
        "dnf",               "-y",
        "--installroot",     rootfs_path,
        "--releasever=4.0",  forcearch_opt,
        dnf_cache.cache_opt, dnf_cache.persist_opt,
        "--disablerepo=*",   "--setopt=install_weak_deps=False",
        "install",           systemd_boot_rpm_path,
    });
    try verifyCachedRepositoryMetadata(gpa, io, dnf_cache.cache_dir, architecture);
    const installed_after = try captureInstalledNevras(gpa, io, rootfs_path);
    defer gpa.free(installed_after);
    const installed_closure = try formatInstalledNevraClosure(gpa, installed_before, installed_after);
    errdefer gpa.free(installed_closure);
    try writeNevraProvenance(gpa, io, work_dir, architecture, flavor, installed_closure);

    // Re-fetch the moving endpoint before proceeding to OCI publication. A
    // changed repomd.xml means the package transaction is no longer provably
    // reproducible, even though non-expiring cached metadata prevented it from
    // changing this transaction's resolved package set.
    try verifyRemoteRepositoryMetadata(gpa, io, work_dir, architecture);
    try sudo(gpa, io, &.{
        "rm",                           "-rf",                 "--",
        dnf_cache.cache_dir,            dnf_cache.persist_dir, dnf_cache.metadata_cache_dir,
        dnf_cache.metadata_persist_dir,
    });

    const stub_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ rootfs_path, architecture.systemd_boot_stub_path });
    defer gpa.free(stub_path);
    const stub_stat = try Dir.cwd().statFile(io, stub_path, .{ .follow_symlinks = false });
    if (!isRegularNonemptyFile(stub_stat.kind, stub_stat.size)) {
        std.debug.print("error: installed systemd boot stub is not a nonempty regular file: {s}\n", .{stub_path});
        return error.InvalidSystemdBootStub;
    }
    try validateRequiredPackages(gpa, io, rootfs_path, flavor_packages);
    try validateForbiddenPackages(gpa, io, rootfs_path, flavor.forbidden_packages);
    if (flavor.flavor == .full) {
        try validateFullMergedUsrLayout(gpa, io, rootfs_path);
    }

    switch (flavor.pid1) {
        .zvminit => try configureCoreGuest(
            gpa,
            io,
            rootfs_path,
            work_dir,
            zvminit_path orelse return error.MissingZvminitArtifact,
            azagent_path orelse return error.MissingAzagentArtifact,
        ),
        .systemd => try configureFullGuest(gpa, io, rootfs_path, work_dir),
    }
    try generalizeRootfs(gpa, io, rootfs_path, flavor);

    // Remove binfmt interpreter from guest.
    if (binfmt_interpreter) |interp| {
        const interp_rel = std.mem.trimStart(u8, interp, "/");
        const guest_interp = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ rootfs_path, interp_rel });
        defer gpa.free(guest_interp);
        try sudo(gpa, io, &.{ "rm", "-f", guest_interp });
    }

    // Clean any cache or log that a DNF version still places in the install
    // root despite the isolated cache/persist options above.
    const rootfs_dnf_cache = try std.fmt.allocPrint(gpa, "{s}/var/cache/dnf", .{rootfs_path});
    defer gpa.free(rootfs_dnf_cache);
    const dnf_log = try std.fmt.allocPrint(gpa, "{s}/var/log/dnf.log", .{rootfs_path});
    defer gpa.free(dnf_log);
    try sudo(gpa, io, &.{ "rm", "-rf", rootfs_dnf_cache });
    try sudo(gpa, io, &.{ "rm", "-f", dnf_log });

    if (flavor.flavor == .full) {
        try labelFullRootfs(gpa, io, rootfs_path);
    }
    try validateGeneralizedRootfs(gpa, io, rootfs_path, flavor);
    return installed_closure;
}

// ─── OCI layout creation ─────────────────────────────────────────────────────

/// Write `bytes` as a blob under `blobs_dir`.  Returns heap-allocated "sha256:<hex>".
fn writeBlobBytesAlloc(gpa: Allocator, io: Io, blobs_dir: []const u8, bytes: []const u8) ![]u8 {
    const hex = sha256Bytes(bytes);
    const blob_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ blobs_dir, &hex });
    defer gpa.free(blob_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = blob_path, .data = bytes });
    return std.fmt.allocPrint(gpa, "sha256:{s}", .{&hex});
}

fn formatOciHistoryComment(
    gpa: Allocator,
    source_digest: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
    installed_closure: []const u8,
) ![]u8 {
    const closure_sha256 = sha256Bytes(installed_closure);
    return switch (flavor.flavor) {
        .core => std.fmt.allocPrint(gpa, "Based on mcr.microsoft.com/{s}:{s} ({s})", .{
            base_image, base_tag, source_digest,
        }),
        .full => std.fmt.allocPrint(
            gpa,
            "Based on {s}@{s} {s} ({s}, blob {s}); repomd/{s}={s}; installed-nevra-sha256={s}",
            .{
                vm_base_upstream_repository,
                vm_base_upstream_commit,
                vm_base_profile_path,
                vm_base_profile_name,
                vm_base_profile_blob,
                architecture.dnf_architecture,
                architecture.repomd_sha256,
                &closure_sha256,
            },
        ),
    };
}

/// Create a gzip-compressed, deterministic tar layer from a rootfs subset.
/// Returns the diff_id ("sha256:<hex>", caller frees) and writes the
/// compressed blob to `blobs_dir`.
/// Also returns the layer descriptor as a heap-allocated JSON object (caller frees strings).
const LayerResult = struct {
    diff_id: []u8, // sha256 of uncompressed tar
    compressed_digest: []u8, // sha256 of gz
    compressed_size: u64,
};

fn gzipFile(io: Io, source_path: []const u8, output_path: []const u8) !u64 {
    var source_file = try Dir.cwd().openFile(io, source_path, .{});
    defer source_file.close(io);

    var output_file = try Dir.cwd().createFile(io, output_path, .{});
    errdefer {
        output_file.close(io);
        Dir.cwd().deleteFile(io, output_path) catch {};
    }
    defer output_file.close(io);

    var write_buf: [65536]u8 = undefined;
    var output_writer = output_file.writer(io, &write_buf);
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&output_writer.interface, &history, .gzip, .level_9);

    var read_buf: [65536]u8 = undefined;
    var source_reader = source_file.reader(io, &read_buf);
    const streamed = try source_reader.interface.streamRemaining(&compressor.writer);
    try compressor.finish();
    try output_writer.interface.flush();
    return @intCast(streamed);
}

fn createOciLayer(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    rootfs_path: []const u8,
    blobs_dir: []const u8,
    index: usize,
    includes: []const []const u8,
    excludes: []const []const u8,
    max_layer_bytes: u64,
) !LayerResult {
    var tar_path_buf: [512]u8 = undefined;
    var gz_path_buf: [512]u8 = undefined;
    const layer_tar = try std.fmt.bufPrint(&tar_path_buf, "{s}/rootfs-{d}.tar", .{ work_dir, index });
    const layer_gz = try std.fmt.bufPrint(&gz_path_buf, "{s}/rootfs-{d}.tar.gz", .{ work_dir, index });

    // Build tar command (requires sudo because rootfs has root-owned files).
    var argv = std.array_list.Managed([]const u8).init(gpa);
    defer argv.deinit();
    try argv.appendSlice(&.{
        "tar",          "--sort=name", "--mtime=@0",         "--numeric-owner",
        "--format=pax", "--xattrs",    "--xattrs-include=*", "--pax-option=delete=atime,delete=ctime",
    });
    for (excludes) |e| {
        const flag = try std.fmt.allocPrint(gpa, "--exclude={s}", .{e});
        defer gpa.free(flag);
        try argv.append(try gpa.dupe(u8, flag));
    }
    try argv.appendSlice(&.{ "-C", rootfs_path, "-cf", layer_tar });
    try argv.appendSlice(includes);
    try sudo(gpa, io, argv.items);

    // Free the --exclude=... strings we duped.
    const exclude_start = 8; // after the fixed args
    for (argv.items[exclude_start .. exclude_start + excludes.len]) |s| gpa.free(s);

    // Re-own the tar so we can read it.
    {
        var uid_buf: [32]u8 = undefined;
        var gid_buf: [32]u8 = undefined;
        const uid_str = try std.fmt.bufPrint(&uid_buf, "{d}", .{std.os.linux.getuid()});
        const gid_str = try std.fmt.bufPrint(&gid_buf, "{d}", .{std.os.linux.getgid()});
        const own = try std.fmt.allocPrint(gpa, "{s}:{s}", .{ uid_str, gid_str });
        defer gpa.free(own);
        try sudo(gpa, io, &.{ "chown", own, layer_tar });
    }

    // Keep per-layer input bounded even for the official full profile.
    const tar_stat = try Dir.cwd().statFile(io, layer_tar, .{});
    if (tar_stat.size > max_layer_bytes) {
        std.debug.print("error: layer {d} ({d} B) exceeds zvmi's {d}-B limit\n", .{
            index, tar_stat.size, max_layer_bytes,
        });
        return error.LayerTooLarge;
    }

    // diff_id = sha256 of uncompressed tar.
    const diff_hex = try sha256File(io, layer_tar);
    const diff_id = try std.fmt.allocPrint(gpa, "sha256:{s}", .{&diff_hex});
    errdefer gpa.free(diff_id);

    // Zig's Reader.stream() copies only one chunk. Use streamRemaining() so
    // the OCI layer contains the complete tar rather than its first 64 KiB.
    const streamed = try gzipFile(io, layer_tar, layer_gz);
    if (streamed != tar_stat.size) return error.IncompleteOciLayer;

    const gz_hex = try sha256File(io, layer_gz);
    const compressed_digest = try std.fmt.allocPrint(gpa, "sha256:{s}", .{&gz_hex});
    errdefer gpa.free(compressed_digest);
    const gz_stat = try Dir.cwd().statFile(io, layer_gz, .{});

    // Copy blob to blobs_dir.
    const blob_dest = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ blobs_dir, &gz_hex });
    defer gpa.free(blob_dest);
    try Dir.copyFile(Dir.cwd(), layer_gz, Dir.cwd(), blob_dest, io, .{});

    return .{
        .diff_id = diff_id,
        .compressed_digest = compressed_digest,
        .compressed_size = gz_stat.size,
    };
}

/// Build the OCI image layout directory.  Returns the layout path (caller frees).
fn createOciLayout(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    rootfs_path: []const u8,
    source_digest: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
    installed_closure: []const u8,
) ![]u8 {
    const layout_dir = try std.fmt.allocPrint(gpa, "{s}/oci-generalized", .{work_dir});

    // Remove stale layout.
    if (Dir.cwd().statFile(io, layout_dir, .{})) |_| {
        try run(gpa, io, &.{ "rm", "-rf", "--", layout_dir });
    } else |_| {}
    const blobs_dir = try std.fmt.allocPrint(gpa, "{s}/blobs/sha256", .{layout_dir});
    defer gpa.free(blobs_dir);
    try Dir.cwd().createDirPath(io, blobs_dir);

    // List top-level rootfs entries, sorted.
    var entry_names = std.array_list.Managed([]u8).init(gpa);
    defer {
        for (entry_names.items) |e| gpa.free(e);
        entry_names.deinit();
    }
    {
        var root_dir = try Dir.cwd().openDir(io, rootfs_path, .{ .iterate = true });
        defer root_dir.close(io);
        var iter = root_dir.iterate();
        while (try iter.next(io)) |entry| {
            try entry_names.append(try gpa.dupe(u8, entry.name));
        }
    }
    std.mem.sortUnstable([]u8, entry_names.items, {}, struct {
        fn lt(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    // Split the full package profile more finely while retaining an explicit,
    // bounded cap for every uncompressed tar stream.
    const LayerSpec = struct {
        includes: []const []const u8,
        excludes: []const []const u8,
    };
    const core_layer_specs: []const LayerSpec = &.{
        .{ .includes = entry_names.items, .excludes = &.{ "usr/share", "usr/lib64" } },
        .{ .includes = &.{"usr/share"}, .excludes = &.{} },
        .{ .includes = &.{"usr/lib64"}, .excludes = &.{} },
    };
    const full_layer_specs: []const LayerSpec = &.{
        .{ .includes = entry_names.items, .excludes = &.{ "usr/bin", "usr/sbin", "usr/lib", "usr/lib64", "usr/share", "var" } },
        .{ .includes = &.{"usr/bin"}, .excludes = &.{} },
        .{ .includes = &.{"usr/sbin"}, .excludes = &.{} },
        .{ .includes = &.{"usr/lib"}, .excludes = &.{} },
        .{ .includes = &.{"usr/lib64"}, .excludes = &.{} },
        .{ .includes = &.{"usr/share"}, .excludes = &.{} },
        .{ .includes = &.{"var"}, .excludes = &.{} },
    };
    const layer_specs = if (flavor.flavor == .core) core_layer_specs else full_layer_specs;
    std.debug.assert(layer_specs.len == ociLayerPlanCount(flavor));

    var layer_descriptors = std.array_list.Managed(struct {
        digest: []u8,
        size: u64,
    }).init(gpa);
    defer {
        for (layer_descriptors.items) |d| gpa.free(d.digest);
        layer_descriptors.deinit();
    }
    var diff_ids = std.array_list.Managed([]u8).init(gpa);
    defer {
        for (diff_ids.items) |d| gpa.free(d);
        diff_ids.deinit();
    }

    for (layer_specs, 0..) |spec, i| {
        std.debug.print("Creating OCI layer {d}...\n", .{i});
        const lr = try createOciLayer(
            gpa,
            io,
            work_dir,
            rootfs_path,
            blobs_dir,
            i,
            spec.includes,
            spec.excludes,
            flavor.max_oci_layer_bytes,
        );
        try layer_descriptors.append(.{ .digest = lr.compressed_digest, .size = lr.compressed_size });
        try diff_ids.append(lr.diff_id);
    }

    // Build timestamp.
    const ts = std.Io.Clock.real.now(io);
    const secs: u64 = @intCast(@divTrunc(ts.nanoseconds, 1_000_000_000));
    const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = epoch.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = epoch.getDaySeconds();
    const created_ts = try std.fmt.allocPrint(gpa, "{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,              md.month.numeric(),      md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
    defer gpa.free(created_ts);

    const closure_sha256 = sha256Bytes(installed_closure);
    const history_comment = try formatOciHistoryComment(
        gpa,
        source_digest,
        architecture,
        flavor,
        installed_closure,
    );
    defer gpa.free(history_comment);

    // Collect diff_id strings for the config.
    const diff_ids_slice = try gpa.alloc([]const u8, diff_ids.items.len);
    defer gpa.free(diff_ids_slice);
    for (diff_ids.items, diff_ids_slice) |s, *d| d.* = s;

    // Config JSON.
    const config = .{
        .architecture = architecture.oci_architecture,
        .config = .{
            .Entrypoint = &[_][]const u8{flavor.oci_entrypoint},
            .Env = &[_][]const u8{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
            .Labels = .{
                .@"io.github.zvmi.flavor" = @tagName(flavor.flavor),
                .@"io.github.zvmi.provenance" = flavor.oci_provenance_kind,
                .@"io.github.zvmi.source.digest" = source_digest,
                .@"io.github.zvmi.vm-base.commit" = vm_base_upstream_commit,
                .@"io.github.zvmi.vm-base.profile-blob" = vm_base_profile_blob,
                .@"io.github.zvmi.repomd.sha256" = architecture.repomd_sha256,
                .@"io.github.zvmi.installed-nevra.sha256" = &closure_sha256,
            },
        },
        .created = created_ts,
        .history = &[_]struct {
            comment: []const u8,
            created: []const u8,
            created_by: []const u8,
        }{
            .{
                .comment = history_comment,
                .created = created_ts,
                .created_by = "scripts/build_generalized_azurelinux4.zig",
            },
        },
        .os = @as([]const u8, "linux"),
        .rootfs = .{
            .diff_ids = diff_ids_slice,
            .type = @as([]const u8, "layers"),
        },
    };
    const config_json = try std.json.Stringify.valueAlloc(gpa, config, .{});
    defer gpa.free(config_json);
    const config_digest = try writeBlobBytesAlloc(gpa, io, blobs_dir, config_json);
    defer gpa.free(config_digest);

    // Build layer array for the manifest.
    const LayerDesc = struct {
        digest: []const u8,
        mediaType: []const u8,
        size: u64,
    };
    const layers_json_arr = try gpa.alloc(LayerDesc, layer_descriptors.items.len);
    defer gpa.free(layers_json_arr);
    for (layer_descriptors.items, layers_json_arr) |ld, *jl| {
        jl.* = .{
            .digest = ld.digest,
            .mediaType = "application/vnd.oci.image.layer.v1.tar+gzip",
            .size = ld.size,
        };
    }

    // Manifest JSON.
    const manifest = .{
        .config = .{
            .digest = config_digest,
            .mediaType = @as([]const u8, "application/vnd.oci.image.config.v1+json"),
            .size = config_json.len,
        },
        .layers = layers_json_arr,
        .mediaType = @as([]const u8, oci_manifest_type),
        .schemaVersion = @as(u64, 2),
    };
    const manifest_json = try std.json.Stringify.valueAlloc(gpa, manifest, .{});
    defer gpa.free(manifest_json);
    const manifest_digest = try writeBlobBytesAlloc(gpa, io, blobs_dir, manifest_json);
    defer gpa.free(manifest_digest);

    // oci-layout file.
    const oci_layout_path = try std.fmt.allocPrint(gpa, "{s}/oci-layout", .{layout_dir});
    defer gpa.free(oci_layout_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = oci_layout_path,
        .data = "{\"imageLayoutVersion\":\"1.0.0\"}\n",
    });

    // index.json.
    const index = .{
        .manifests = &[_]struct {
            annotations: struct {
                @"org.opencontainers.image.ref.name": []const u8,
            },
            digest: []const u8,
            mediaType: []const u8,
            size: usize,
        }{
            .{
                .annotations = .{ .@"org.opencontainers.image.ref.name" = "generalized" },
                .digest = manifest_digest,
                .mediaType = oci_manifest_type,
                .size = manifest_json.len,
            },
        },
        .schemaVersion = @as(u64, 2),
    };
    var index_buf: std.Io.Writer.Allocating = .init(gpa);
    defer index_buf.deinit();
    try std.json.Stringify.value(index, .{}, &index_buf.writer);
    try index_buf.writer.writeByte('\n');
    const index_json = try index_buf.toOwnedSlice();
    defer gpa.free(index_json);

    const index_path = try std.fmt.allocPrint(gpa, "{s}/index.json", .{layout_dir});
    defer gpa.free(index_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = index_path, .data = index_json });

    return layout_dir;
}

fn validateOsRelease(image: anytype) !void {
    const os_release = image.get("etc/os-release") orelse {
        std.debug.print("error: generated OCI layout is missing required rootfs path: /etc/os-release\n", .{});
        return error.IncompleteOciRootfs;
    };
    switch (os_release.kind) {
        .file => {},
        .symlink => {
            const target = os_release.link_name orelse "";
            if (!std.mem.eql(u8, target, "../usr/lib/os-release") and
                !std.mem.eql(u8, target, "/usr/lib/os-release"))
            {
                std.debug.print("error: generated OCI rootfs has unexpected /etc/os-release target: {s}\n", .{target});
                return error.IncompleteOciRootfs;
            }
            const target_entry = image.get("usr/lib/os-release") orelse {
                std.debug.print("error: generated OCI rootfs is missing /usr/lib/os-release\n", .{});
                return error.IncompleteOciRootfs;
            };
            if (target_entry.kind != .file) {
                std.debug.print("error: generated OCI rootfs path is not a file: /usr/lib/os-release\n", .{});
                return error.IncompleteOciRootfs;
            }
        },
        else => {
            std.debug.print("error: generated OCI rootfs path is not a file or symlink: /etc/os-release\n", .{});
            return error.IncompleteOciRootfs;
        },
    }
}

fn ociConfigArchitectureMatches(
    config_architecture: ?[]const u8,
    architecture: *const ArchitectureDescriptor,
) bool {
    return if (config_architecture) |value|
        std.mem.eql(u8, value, architecture.oci_architecture)
    else
        false;
}

fn validateGeneralizedOciLayout(
    gpa: Allocator,
    io: Io,
    layout_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) !void {
    var image = try oci.loadLayout(io, gpa, layout_dir, ociLoadOptionsForFlavor(flavor));
    defer image.deinit();

    const config_architecture = image.config.architecture orelse return error.MissingOciArchitecture;
    if (!ociConfigArchitectureMatches(config_architecture, architecture)) {
        std.debug.print(
            "error: generated OCI config has architecture {s}, expected {s}\n",
            .{ config_architecture, architecture.oci_architecture },
        );
        return error.UnexpectedOciArchitecture;
    }
    try validateOsRelease(image);

    // Azure Linux uses merged-/usr symlinks, so OCI records physical paths.
    for (flavor.required_rootfs_paths) |path| {
        const entry = image.get(path) orelse {
            std.debug.print("error: generated OCI layout is missing required rootfs path: /{s}\n", .{path});
            return error.IncompleteOciRootfs;
        };
        if (entry.kind != .file) {
            std.debug.print("error: generated OCI rootfs path is not a file: /{s}\n", .{path});
            return error.IncompleteOciRootfs;
        }
    }
    const stub = image.get(architecture.systemd_boot_stub_path) orelse {
        std.debug.print(
            "error: generated OCI layout is missing required UKI stub: /{s}\n",
            .{architecture.systemd_boot_stub_path},
        );
        return error.IncompleteOciRootfs;
    };
    if (stub.kind != .file) return error.IncompleteOciRootfs;
    for (flavor.forbidden_rootfs_paths) |path| {
        if (image.get(path) != null) {
            std.debug.print("error: generated OCI layout contains forbidden rootfs path: /{s}\n", .{path});
            return error.ForbiddenFlavorRootfsPath;
        }
    }
    if (flavor.pid1 == .zvminit) {
        for (zvminit_symlink_paths) |path| {
            const entry = image.get(path) orelse {
                std.debug.print("error: generated OCI layout is missing required zvminit symlink: /{s}\n", .{path});
                return error.IncompleteOciRootfs;
            };
            if (entry.kind != .symlink or !std.mem.eql(u8, entry.link_name orelse "", "zvminit")) {
                std.debug.print("error: generated OCI rootfs path is not a relative symlink to zvminit: /{s}\n", .{path});
                return error.IncompleteOciRootfs;
            }
        }
    }
}

const GeneralizedImageValidationReport = struct {
    virtual_size: u64,
    esp_size: u64,
    root_size: u64,
    uki_size: usize,
};

const UkiSigningRecord = struct {
    path: []u8,
    unsigned_sha256: artifact_pipeline.Digest,
    signed_sha256: artifact_pipeline.Digest,
    signed_size: usize,
    provider_metadata: ?uki_signing.ProviderMetadata,

    fn deinit(self: *UkiSigningRecord, allocator: Allocator) void {
        allocator.free(self.path);
        if (self.provider_metadata) |*metadata| metadata.deinit(allocator);
        self.* = undefined;
    }
};

const UkiSigningReport = struct {
    records: []UkiSigningRecord,

    fn deinit(self: *UkiSigningReport, allocator: Allocator) void {
        for (self.records) |*record| record.deinit(allocator);
        allocator.free(self.records);
        self.* = undefined;
    }
};

fn sameProviderIdentity(
    first: ?uki_signing.ProviderMetadata,
    next: ?uki_signing.ProviderMetadata,
) bool {
    if (first == null or next == null) return first == null and next == null;
    const a = first.?;
    const b = next.?;
    return std.mem.eql(u8, a.provider, b.provider) and
        std.mem.eql(u8, a.endpoint, b.endpoint) and
        std.mem.eql(u8, a.account, b.account) and
        std.mem.eql(u8, a.profile, b.profile) and
        std.mem.eql(
            u8,
            &a.signing_certificate_sha256,
            &b.signing_certificate_sha256,
        ) and
        std.mem.eql(
            u8,
            &a.enrolled_certificate_sha256,
            &b.enrolled_certificate_sha256,
        );
}

fn isEfiFile(name: []const u8) bool {
    return name.len > 4 and std.ascii.eqlIgnoreCase(name[name.len - 4 ..], ".efi");
}

fn signGeneralizedImage(
    gpa: Allocator,
    io: Io,
    image_path: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
    config: uki_signing.Config,
    scratch_path: []const u8,
    environ_map: *const std.process.Environ.Map,
) !UkiSigningReport {
    var image = try zvmi.Image.openPath(io, image_path);
    defer image.close(io);
    const parsed = try zvmi.gpt.readGpt(image, io, gpa);
    defer gpa.free(parsed.partitions);
    if (parsed.partitions.len < 1 or
        !std.mem.eql(u8, &parsed.partitions[0].partition_type_guid, &zvmi.guid.esp))
    {
        return error.MissingEspPartition;
    }
    const esp_partition = parsed.partitions[0];
    var esp = try zvmi.fat32.open(&image, io, .{
        .offset = esp_partition.first_lba * zvmi.gpt.sector_size,
        .length = (esp_partition.last_lba - esp_partition.first_lba + 1) *
            zvmi.gpt.sector_size,
    });

    const fallback_unsigned = try esp.readFileAlloc(
        io,
        gpa,
        architecture.fallback_efi_path,
    );
    defer gpa.free(fallback_unsigned);
    const linux_entries = try esp.listDirAlloc(io, gpa, "EFI/Linux");
    defer zvmi.fat32.freeDirEntries(gpa, linux_entries);

    var records: std.ArrayListUnmanaged(UkiSigningRecord) = .empty;
    errdefer {
        for (records.items) |*record| record.deinit(gpa);
        records.deinit(gpa);
    }
    var fallback_signed: ?[]u8 = null;
    defer if (fallback_signed) |bytes| gpa.free(bytes);
    var fallback_provider_metadata: ?uki_signing.ProviderMetadata = null;
    defer if (fallback_provider_metadata) |*metadata| metadata.deinit(gpa);
    var signer_index: usize = 0;

    for (linux_entries) |entry| {
        if (entry.kind != .file or !isEfiFile(entry.name)) continue;
        const path = try std.fmt.allocPrint(gpa, "EFI/Linux/{s}", .{entry.name});
        errdefer gpa.free(path);
        const unsigned = try esp.readFileAlloc(io, gpa, path);
        defer gpa.free(unsigned);

        var signed = try uki_signing.signUkiAlloc(
            gpa,
            io,
            config,
            scratch_path,
            environ_map,
            signer_index,
            @tagName(architecture.architecture),
            @tagName(flavor.flavor),
            unsigned,
        );
        defer signed.deinit(gpa);
        signer_index += 1;
        if (records.items.len > 0 and !sameProviderIdentity(
            records.items[0].provider_metadata,
            signed.provider_metadata,
        )) {
            return error.SigningProviderIdentityChanged;
        }

        if (std.mem.eql(u8, fallback_unsigned, unsigned)) {
            if (fallback_signed == null) {
                fallback_signed = try gpa.dupe(u8, signed.bytes);
                if (signed.provider_metadata) |metadata| {
                    fallback_provider_metadata = try metadata.clone(gpa);
                }
            }
        }
        try esp.deletePath(io, path);
        try esp.writeFile(io, path, signed.bytes);
        try records.append(gpa, .{
            .path = path,
            .unsigned_sha256 = signed.unsigned_sha256,
            .signed_sha256 = signed.signed_sha256,
            .signed_size = signed.bytes.len,
            .provider_metadata = signed.provider_metadata,
        });
        signed.provider_metadata = null;
    }

    const signed_fallback = fallback_signed orelse return error.FallbackUkiMismatch;
    try esp.deletePath(io, architecture.fallback_efi_path);
    try esp.writeFile(io, architecture.fallback_efi_path, signed_fallback);
    try records.append(gpa, .{
        .path = try gpa.dupe(u8, architecture.fallback_efi_path),
        .unsigned_sha256 = artifact_pipeline.sha256Bytes(fallback_unsigned),
        .signed_sha256 = artifact_pipeline.sha256Bytes(signed_fallback),
        .signed_size = signed_fallback.len,
        .provider_metadata = fallback_provider_metadata,
    });
    fallback_provider_metadata = null;

    if (records.items.len < 2) return error.MissingNamedUki;
    return .{ .records = try records.toOwnedSlice(gpa) };
}

fn verifySignedGeneralizedImage(
    gpa: Allocator,
    io: Io,
    image_path: []const u8,
    config: uki_signing.Config,
    scratch_path: []const u8,
    report: *const UkiSigningReport,
) !void {
    var image = try zvmi.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    const parsed = try zvmi.gpt.readGpt(image, io, gpa);
    defer gpa.free(parsed.partitions);
    if (parsed.partitions.len < 1 or
        !std.mem.eql(u8, &parsed.partitions[0].partition_type_guid, &zvmi.guid.esp))
    {
        return error.MissingEspPartition;
    }
    const esp_partition = parsed.partitions[0];
    var esp = try zvmi.fat32.open(&image, io, .{
        .offset = esp_partition.first_lba * zvmi.gpt.sector_size,
        .length = (esp_partition.last_lba - esp_partition.first_lba + 1) *
            zvmi.gpt.sector_size,
    });

    for (report.records, 0..) |record, index| {
        const bytes = try esp.readFileAlloc(io, gpa, record.path);
        defer gpa.free(bytes);
        if (bytes.len != record.signed_size or
            !std.mem.eql(
                u8,
                &artifact_pipeline.sha256Bytes(bytes),
                &record.signed_sha256,
            ))
        {
            return error.FinalizedUkiDigestMismatch;
        }
        try uki_signing.verifyBytes(gpa, io, config, scratch_path, index, bytes);
    }
}

fn writeSigningProvenance(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
    config: uki_signing.Config,
    certificate: *const uki_signing.Certificate,
    report: *const UkiSigningReport,
) !void {
    const JsonRecord = struct {
        path: []const u8,
        unsigned_sha256: []const u8,
        signed_sha256: []const u8,
        finalized_sha256: []const u8,
        signed_bytes: usize,
        signing_operation_id: ?[]const u8,
        signing_certificate_sha256: ?[]const u8,
    };
    const JsonProvider = struct {
        name: []const u8,
        endpoint: []const u8,
        account: []const u8,
        profile: []const u8,
        signing_certificate_sha256: []const u8,
    };
    const json_records = try gpa.alloc(JsonRecord, report.records.len);
    defer gpa.free(json_records);
    const unsigned_hex = try gpa.alloc([64]u8, report.records.len);
    defer gpa.free(unsigned_hex);
    const signed_hex = try gpa.alloc([64]u8, report.records.len);
    defer gpa.free(signed_hex);
    const provider_certificate_hex = try gpa.alloc([64]u8, report.records.len);
    defer gpa.free(provider_certificate_hex);
    for (report.records, 0..) |record, index| {
        unsigned_hex[index] = artifact_pipeline.formatSha256(record.unsigned_sha256);
        signed_hex[index] = artifact_pipeline.formatSha256(record.signed_sha256);
        const operation_id: ?[]const u8 = if (record.provider_metadata) |metadata|
            metadata.operation_id
        else
            null;
        const provider_fingerprint: ?[]const u8 = if (record.provider_metadata) |metadata| p: {
            provider_certificate_hex[index] = artifact_pipeline.formatSha256(
                metadata.signing_certificate_sha256,
            );
            break :p &provider_certificate_hex[index];
        } else null;
        json_records[index] = .{
            .path = record.path,
            .unsigned_sha256 = &unsigned_hex[index],
            .signed_sha256 = &signed_hex[index],
            .finalized_sha256 = &signed_hex[index],
            .signed_bytes = record.signed_size,
            .signing_operation_id = operation_id,
            .signing_certificate_sha256 = provider_fingerprint,
        };
    }
    const certificate_hex = artifact_pipeline.formatSha256(certificate.sha256);
    const certificate_base64 = try gpa.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(certificate.der.len),
    );
    defer gpa.free(certificate_base64);
    _ = std.base64.standard.Encoder.encode(certificate_base64, certificate.der);
    var provider_hex: [64]u8 = undefined;
    const provider: ?JsonProvider = if (report.records[0].provider_metadata) |metadata| p: {
        provider_hex = artifact_pipeline.formatSha256(
            metadata.signing_certificate_sha256,
        );
        break :p .{
            .name = metadata.provider,
            .endpoint = metadata.endpoint,
            .account = metadata.account,
            .profile = metadata.profile,
            .signing_certificate_sha256 = &provider_hex,
        };
    } else null;
    const document = .{
        .schema = 1,
        .type = "zvmi-uki-signing",
        .architecture = @tagName(architecture.architecture),
        .flavor = @tagName(flavor.flavor),
        .signer_mode = config.mode.name(),
        .certificate_sha256 = &certificate_hex,
        .certificate_der_base64 = certificate_base64,
        .certificate_details = certificate.details,
        .provider = provider,
        .signature_verification = "success",
        .files = json_records,
    };
    const json = try std.json.Stringify.valueAlloc(
        gpa,
        document,
        .{ .whitespace = .indent_2 },
    );
    defer gpa.free(json);

    const provenance_dir = try std.fmt.allocPrint(gpa, "{s}/provenance", .{work_dir});
    defer gpa.free(provenance_dir);
    try Dir.cwd().createDirPath(io, provenance_dir);
    const path = try signingProvenancePath(gpa, work_dir, architecture, flavor);
    defer gpa.free(path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = json,
        .flags = .{ .truncate = true },
    });
}

fn signingProvenancePath(
    allocator: Allocator,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}/provenance/uki-signing-{s}-{s}.json",
        .{ work_dir, @tagName(flavor.flavor), architecture.dnf_architecture },
    );
}

fn planGeneralizedGen2Layout(
    gpa: Allocator,
    virtual_size: u64,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) ![]zvmi.layout.PlannedPartition {
    const requests = [_]zvmi.layout.PartitionRequest{
        .{ .name = "ESP", .role = .esp, .filesystem = .fat32, .size = .{ .fixed = flavor.esp_size_bytes } },
        .{
            .name = "root",
            .role = architecture.root_role,
            .filesystem = .ext4,
            .size = .{ .percent = 100.0 },
            .type_guid = architecture.root_type_guid,
        },
    };
    return zvmi.layout.planLayout(gpa, virtual_size, &requests, null);
}

fn validatePartitionLayout(
    partitions: []const zvmi.gpt.PartitionEntry,
    expected: []const zvmi.layout.PlannedPartition,
) !void {
    if (partitions.len != expected.len) return error.UnexpectedPartitionCount;
    for (partitions, expected) |partition, planned| {
        if (!std.mem.eql(u8, &partition.partition_type_guid, &planned.type_guid)) {
            return error.UnexpectedPartitionType;
        }
        if (partition.first_lba != planned.firstLba() or partition.last_lba != planned.lastLba()) {
            return error.UnexpectedPartitionLayout;
        }
        if (partition.last_lba < partition.first_lba) return error.UnexpectedPartitionLayout;
        const offset_bytes = partition.first_lba * zvmi.gpt.sector_size;
        const length_bytes = (partition.last_lba - partition.first_lba + 1) * zvmi.gpt.sector_size;
        if (offset_bytes != planned.offset_bytes or length_bytes != planned.length_bytes) {
            return error.UnexpectedPartitionLayout;
        }
    }
}

fn rootFreeSpaceIsSufficient(root_size: u64, rootfs_bytes: u64, minimum_free_bytes: u64) bool {
    const needed = std.math.add(u64, rootfs_bytes, minimum_free_bytes) catch return false;
    return root_size >= needed;
}

fn rootfsApparentBytes(gpa: Allocator, io: Io, rootfs_path: []const u8) !u64 {
    const output = try capture(gpa, io, &.{ "sudo", "du", "--apparent-size", "-s", "-B1", rootfs_path });
    defer gpa.free(output);
    const bytes_text = std.mem.trim(u8, std.mem.sliceTo(output, '\t'), " \r\n");
    return std.fmt.parseInt(u64, bytes_text, 10) catch error.InvalidRootfsSize;
}

fn enforceMinimumRootFreeSpace(
    gpa: Allocator,
    io: Io,
    rootfs_path: []const u8,
    virtual_size: u64,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) !void {
    const layout = try planGeneralizedGen2Layout(gpa, virtual_size, architecture, flavor);
    defer gpa.free(layout);
    const rootfs_bytes = try rootfsApparentBytes(gpa, io, rootfs_path);
    const root_size = layout[1].length_bytes;
    if (!rootFreeSpaceIsSufficient(root_size, rootfs_bytes, flavor.minimum_root_free_bytes)) {
        std.debug.print(
            "error: {s} rootfs uses {d} bytes; root partition {d} bytes cannot retain required {d} bytes free\n",
            .{ @tagName(flavor.flavor), rootfs_bytes, root_size, flavor.minimum_root_free_bytes },
        );
        return error.InsufficientRootFreeSpace;
    }
}

fn requireAbsentFile(esp: *zvmi.fat32.FileSystem, gpa: Allocator, io: Io, path: []const u8) !void {
    const bytes = esp.readFileAlloc(io, gpa, path) catch |err| switch (err) {
        error.PathNotFound => return,
        else => return err,
    };
    gpa.free(bytes);
    return error.UnexpectedGeneratedBootConfig;
}

fn requireNoBlsEntries(esp: *zvmi.fat32.FileSystem, gpa: Allocator, io: Io) !void {
    const entries = esp.listDirAlloc(io, gpa, "loader/entries") catch |err| switch (err) {
        error.PathNotFound => return,
        else => return err,
    };
    defer zvmi.fat32.freeDirEntries(gpa, entries);
    for (entries) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".conf")) {
            return error.UnexpectedGeneratedBootConfig;
        }
    }
}

fn requireNoGeneratedGrubConfigs(esp: *zvmi.fat32.FileSystem, gpa: Allocator, io: Io) !void {
    try requireAbsentFile(esp, gpa, io, "EFI/BOOT/grub.cfg");

    const efi_entries = try esp.listDirAlloc(io, gpa, "EFI");
    defer zvmi.fat32.freeDirEntries(gpa, efi_entries);
    for (efi_entries) |entry| {
        if (entry.kind != .directory or std.ascii.eqlIgnoreCase(entry.name, "BOOT")) continue;
        const path = try std.fmt.allocPrint(gpa, "EFI/{s}/grub.cfg", .{entry.name});
        defer gpa.free(path);
        try requireAbsentFile(esp, gpa, io, path);
    }
}

fn expectedUkiCmdline(
    gpa: Allocator,
    root_guid: zvmi.guid.Guid,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) ![]u8 {
    var root_guid_text: [36]u8 = undefined;
    return switch (flavor.pid1) {
        .zvminit => std.fmt.allocPrint(
            gpa,
            "root=PARTUUID={s} {s}",
            .{ zvmi.guid.formatLower(&root_guid_text, root_guid), architecture.extra_kernel_options },
        ),
        .systemd => std.fmt.allocPrint(
            gpa,
            "root=PARTUUID={s} {s}",
            .{ zvmi.guid.formatLower(&root_guid_text, root_guid), architecture.serial_console },
        ),
    };
}

fn ukiExtraKernelOptions(
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) []const u8 {
    return switch (flavor.pid1) {
        .zvminit => architecture.extra_kernel_options,
        .systemd => architecture.serial_console,
    };
}

fn requireNonemptyUkiSection(inspection: *const zvmi.uki.Inspection, name: []const u8) ![]const u8 {
    const section = inspection.findSection(name) orelse return error.MissingUkiSection;
    if (section.contents.len == 0) return error.EmptyUkiSection;
    return section.contents;
}

fn imageRootfsReadAt(
    context: *const anyopaque,
    io: Io,
    buffer: []u8,
    offset: u64,
) anyerror!usize {
    const image: *const zvmi.Image = @ptrCast(@alignCast(context));
    return image.pread(io, buffer, offset);
}

fn requireImageRootfsPathAbsent(
    rootfs: *const zvmi.ext4.Reader,
    io: Io,
    path: []const u8,
) !void {
    _ = rootfs.statPath(io, path) catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    return error.BakedIdentityState;
}

fn requireUsableSelinuxLabel(
    rootfs: *const zvmi.ext4.Reader,
    gpa: Allocator,
    io: Io,
    path: []const u8,
) !void {
    const label = rootfs.readXattrAlloc(
        io,
        gpa,
        path,
        "security.selinux",
    ) catch |err| switch (err) {
        error.XattrNotFound => return error.MissingSelinuxLabel,
        else => return err,
    };
    defer gpa.free(label);
    if (!selinuxLabelIsUsable(label)) return error.InvalidSelinuxLabel;
}

fn validateFinalizedImageRootfs(
    gpa: Allocator,
    io: Io,
    image: *const zvmi.Image,
    image_path: []const u8,
    root_partition: zvmi.gpt.PartitionEntry,
    flavor: *const FlavorDescriptor,
) !void {
    var backing_file = try Dir.cwd().openFile(io, image_path, .{});
    defer backing_file.close(io);
    const root_offset = root_partition.first_lba * zvmi.gpt.sector_size;
    var rootfs = try zvmi.ext4.openReadOnlySource(io, backing_file, .{
        .ctx = image,
        .read_at_fn = imageRootfsReadAt,
    }, gpa, .{ .offset = root_offset });
    defer rootfs.deinit();

    for (flavor.required_rootfs_paths) |path| _ = try rootfs.statPath(io, path);
    for (flavor.forbidden_rootfs_paths) |path| try requireImageRootfsPathAbsent(&rootfs, io, path);
    for (&[_][]const u8{
        "etc/hostname",
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
    }) |path| try requireImageRootfsPathAbsent(&rootfs, io, path);
    const homes: ?[]zvmi.ext4.DirEntry = rootfs.listDir(io, gpa, "home") catch |err| switch (err) {
        error.NotFound => null,
        else => return err,
    };
    defer if (homes) |entries| zvmi.ext4.freeDirEntries(gpa, entries);
    for (homes orelse &.{}) |home| {
        if (home.kind != .directory) continue;
        const authorized_keys = try std.fmt.allocPrint(gpa, "home/{s}/.ssh/authorized_keys", .{home.name});
        defer gpa.free(authorized_keys);
        try requireImageRootfsPathAbsent(&rootfs, io, authorized_keys);
    }
    const machine_id = try rootfs.statPath(io, "etc/machine-id");
    if (machine_id.size != 0) return error.GeneratedMachineId;
    if (flavor.flavor == .full) {
        const networkd_config = try rootfs.readFileAlloc(
            io,
            gpa,
            "etc/systemd/network/20-wired.network",
        );
        defer gpa.free(networkd_config);
        if (!std.mem.eql(u8, networkd_config, full_networkd_config)) {
            return error.InvalidFullNetworkConfiguration;
        }
        for (&[_][]const u8{
            "/",
            "bin",
            "usr/lib/systemd/systemd",
            "usr/lib/systemd/system/systemd-networkd.service",
            "usr/bin/cloud-init",
            "usr/bin/waagent",
            "usr/bin/sshd",
            "etc/waagent.conf",
            "etc/systemd/network/20-wired.network",
        }) |path| try requireUsableSelinuxLabel(&rootfs, gpa, io, path);
        const chrony_service = try rootfs.readFileAlloc(
            io,
            gpa,
            "usr/lib/systemd/system/chronyd.service",
        );
        defer gpa.free(chrony_service);
        const chrony_sysusers = try rootfs.readFileAlloc(
            io,
            gpa,
            "usr/lib/sysusers.d/chrony.conf",
        );
        defer gpa.free(chrony_sysusers);
        if (!chronyStateContractMatches(chrony_service, chrony_sysusers)) {
            return error.InvalidChronyStateContract;
        }
        const waagent_metadata = try rootfs.statPath(io, "var/lib/waagent");
        if (!waagentStateContractMatches(waagent_metadata.uid, waagent_metadata.gid, waagent_metadata.mode)) {
            return error.InvalidWALinuxAgentStateMetadata;
        }
        const waagent_state = rootfs.listDir(io, gpa, "var/lib/waagent") catch |err| switch (err) {
            error.NotFound => return error.BakedProvisioningState,
            else => return err,
        };
        defer zvmi.ext4.freeDirEntries(gpa, waagent_state);
        if (waagent_state.len != 0) return error.BakedProvisioningState;
    }
}

fn validateGeneralizedImage(
    gpa: Allocator,
    io: Io,
    image_path: []const u8,
    expected_virtual_size: u64,
    architecture: *const ArchitectureDescriptor,
    flavor: *const FlavorDescriptor,
) !GeneralizedImageValidationReport {
    var image = try zvmi.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    if (image.virtual_size != expected_virtual_size) return error.UnexpectedVirtualSize;

    const expected_layout = try planGeneralizedGen2Layout(gpa, image.virtual_size, architecture, flavor);
    defer gpa.free(expected_layout);
    const parsed = try zvmi.gpt.readGpt(image, io, gpa);
    defer gpa.free(parsed.partitions);
    try validatePartitionLayout(parsed.partitions, expected_layout);

    const esp_partition = parsed.partitions[0];
    const root_partition = parsed.partitions[1];
    if (std.mem.eql(u8, &root_partition.unique_partition_guid, &zvmi.guid.nil)) {
        return error.InvalidRootPartitionGuid;
    }
    try validateFinalizedImageRootfs(gpa, io, &image, image_path, root_partition, flavor);
    var esp = try zvmi.fat32.open(&image, io, .{
        .offset = esp_partition.first_lba * zvmi.gpt.sector_size,
        .length = (esp_partition.last_lba - esp_partition.first_lba + 1) * zvmi.gpt.sector_size,
    });

    const fallback_uki = try esp.readFileAlloc(io, gpa, architecture.fallback_efi_path);
    defer gpa.free(fallback_uki);
    const linux_entries = try esp.listDirAlloc(io, gpa, "EFI/Linux");
    defer zvmi.fat32.freeDirEntries(gpa, linux_entries);

    var found_named_uki = false;
    var fallback_matches_named_uki = false;
    for (linux_entries) |entry| {
        if (entry.kind != .file or entry.name.len < 4 or
            !std.ascii.eqlIgnoreCase(entry.name[entry.name.len - 4 ..], ".efi")) continue;
        found_named_uki = true;
        const path = try std.fmt.allocPrint(gpa, "EFI/Linux/{s}", .{entry.name});
        defer gpa.free(path);
        const bytes = try esp.readFileAlloc(io, gpa, path);
        defer gpa.free(bytes);
        if (std.mem.eql(u8, fallback_uki, bytes)) {
            fallback_matches_named_uki = true;
            break;
        }
    }
    if (!found_named_uki) return error.MissingNamedUki;
    if (!fallback_matches_named_uki) return error.FallbackUkiMismatch;

    var inspection = try zvmi.uki.inspect(gpa, fallback_uki);
    defer inspection.deinit(gpa);
    if (inspection.machine != architecture.uki_pe_machine) return error.UnexpectedUkiMachine;
    if (inspection.subsystem != 10) return error.UnexpectedUkiSubsystem;
    _ = try requireNonemptyUkiSection(&inspection, ".linux");
    _ = try requireNonemptyUkiSection(&inspection, ".initrd");
    const cmdline = try requireNonemptyUkiSection(&inspection, ".cmdline");
    _ = try requireNonemptyUkiSection(&inspection, ".osrel");
    _ = try requireNonemptyUkiSection(&inspection, ".uname");

    const expected_cmdline = try expectedUkiCmdline(gpa, root_partition.unique_partition_guid, architecture, flavor);
    defer gpa.free(expected_cmdline);
    if (!std.mem.eql(u8, cmdline, expected_cmdline)) return error.UnexpectedUkiCmdline;

    try requireAbsentFile(&esp, gpa, io, "loader/loader.conf");
    try requireNoBlsEntries(&esp, gpa, io);
    try requireNoGeneratedGrubConfigs(&esp, gpa, io);

    return .{
        .virtual_size = image.virtual_size,
        .esp_size = expected_layout[0].length_bytes,
        .root_size = expected_layout[1].length_bytes,
        .uki_size = fallback_uki.len,
    };
}

// ─── ISO download ─────────────────────────────────────────────────────────────

fn isoChecksumMatches(
    actual: [64]u8,
    architecture: *const ArchitectureDescriptor,
) bool {
    return std.mem.eql(u8, &actual, architecture.iso_sha256);
}

fn validateIso(io: Io, iso_path: []const u8, architecture: *const ArchitectureDescriptor) !void {
    const stat = try Dir.cwd().statFile(io, iso_path, .{});
    if (!isRegularNonemptyFile(stat.kind, stat.size) or stat.size > iso_max_bytes) {
        return error.InvalidIso;
    }
    _ = artifact_pipeline.parseSha256(architecture.iso_sha256) catch return error.InvalidIsoChecksum;
    const actual = try sha256File(io, iso_path);
    if (!isoChecksumMatches(actual, architecture)) {
        std.debug.print(
            "error: ISO checksum mismatch for {s}: expected {s}, got {s}\n",
            .{ iso_path, architecture.iso_sha256, &actual },
        );
        return error.IsoChecksumMismatch;
    }
}

fn isoKernelAssetsMatchInstalledModules(
    iso_kernel_names: []const u8,
    iso_initramfs_names: []const u8,
    installed_kernel_nevras: []const u8,
    expected_kernel_release: []const u8,
) bool {
    var installed = std.mem.splitScalar(u8, installed_kernel_nevras, '\n');
    var installed_release_found = false;
    while (installed.next()) |raw| {
        if (std.mem.eql(u8, std.mem.trim(u8, raw, " \r\t"), expected_kernel_release)) {
            installed_release_found = true;
            break;
        }
    }
    if (!installed_release_found) return false;

    var initramfs = std.mem.splitScalar(u8, iso_initramfs_names, '\n');
    var initramfs_release_found = false;
    while (initramfs.next()) |raw| {
        const name = std.mem.trim(u8, raw, " \r\t");
        const release = if (std.mem.startsWith(u8, name, "initramfs-"))
            name["initramfs-".len..]
        else if (std.mem.startsWith(u8, name, "initrd-"))
            name["initrd-".len..]
        else
            continue;
        if (std.mem.eql(u8, release, expected_kernel_release) or
            (std.mem.startsWith(u8, release, expected_kernel_release) and
                std.mem.eql(u8, release[expected_kernel_release.len..], ".img")))
        {
            initramfs_release_found = true;
            break;
        }
    }
    if (!initramfs_release_found) return false;

    var kernels = std.mem.splitScalar(u8, iso_kernel_names, '\n');
    while (kernels.next()) |kernel_name| {
        const release = std.mem.trim(u8, kernel_name, " \r\t");
        if (!std.mem.startsWith(u8, release, "vmlinuz-")) continue;
        const kernel_release = release["vmlinuz-".len..];
        if (std.mem.eql(u8, kernel_release, expected_kernel_release)) return true;
    }
    return false;
}

/// The ISO contributes only boot assets to both flavors.  A full rootfs is
/// independently DNF-materialized, so refuse a kernel/initramfs whose release
/// cannot be matched to the installed kernel-core/kernel-modules closure.
fn validateFullIsoKernelCompatibility(
    gpa: Allocator,
    io: Io,
    iso_path: []const u8,
    rootfs_path: []const u8,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) !void {
    const iso_mount_path = try std.fmt.allocPrint(gpa, "{s}/iso-boot-assets", .{work_dir});
    defer gpa.free(iso_mount_path);
    const squashfs_mount_path = try std.fmt.allocPrint(gpa, "{s}/iso-live-squashfs", .{work_dir});
    defer gpa.free(squashfs_mount_path);
    const nested_rootfs_mount_path = try std.fmt.allocPrint(gpa, "{s}/iso-live-rootfs", .{work_dir});
    defer gpa.free(nested_rootfs_mount_path);
    try Dir.cwd().createDirPath(io, iso_mount_path);
    try Dir.cwd().createDirPath(io, squashfs_mount_path);
    try Dir.cwd().createDirPath(io, nested_rootfs_mount_path);

    try sudo(gpa, io, &.{ "mount", "-o", "loop,ro", iso_path, iso_mount_path });
    defer sudo(gpa, io, &.{ "umount", iso_mount_path }) catch {};
    const squashfs_path = try std.fmt.allocPrint(
        gpa,
        "{s}/{s}",
        .{ iso_mount_path, architecture.iso_squashfs_path },
    );
    defer gpa.free(squashfs_path);
    try sudo(gpa, io, &.{ "mount", "-t", "squashfs", "-o", "loop,ro", squashfs_path, squashfs_mount_path });
    defer sudo(gpa, io, &.{ "umount", squashfs_mount_path }) catch {};
    const nested_rootfs_path = try std.fmt.allocPrint(
        gpa,
        "{s}/{s}",
        .{ squashfs_mount_path, architecture.iso_nested_rootfs_path },
    );
    defer gpa.free(nested_rootfs_path);
    try sudo(gpa, io, &.{ "mount", "-t", "ext4", "-o", "loop,ro", nested_rootfs_path, nested_rootfs_mount_path });
    defer sudo(gpa, io, &.{ "umount", nested_rootfs_mount_path }) catch {};
    const nested_boot_path = try std.fmt.allocPrint(gpa, "{s}/boot", .{nested_rootfs_mount_path});
    defer gpa.free(nested_boot_path);

    const iso_kernels = try capture(gpa, io, &.{
        "sudo", "find", nested_boot_path, "-type", "f", "-name", "vmlinuz-*", "-printf", "%f\n",
    });
    defer gpa.free(iso_kernels);
    const iso_initrds = try capture(gpa, io, &.{
        "sudo", "find", nested_boot_path, "-type", "f", "(", "-name", "initramfs-*", "-o", "-name", "initrd-*", ")", "-printf", "%f\n",
    });
    defer gpa.free(iso_initrds);
    const installed = try capture(gpa, io, &.{
        "sudo",                            "chroot",      rootfs_path,      "/usr/bin/rpm", "-q", "--qf",
        "%{VERSION}-%{RELEASE}.%{ARCH}\n", "kernel-core", "kernel-modules",
    });
    defer gpa.free(installed);
    if (!isoKernelAssetsMatchInstalledModules(
        iso_kernels,
        iso_initrds,
        installed,
        architecture.full_kernel_release,
    )) {
        std.debug.print(
            "error: ISO kernel/initramfs does not match installed kernel-core/kernel-modules release {s}; refusing incoherent full image\n",
            .{architecture.full_kernel_release},
        );
        return error.IncompatibleIsoKernelModules;
    }
}

fn downloadIso(
    gpa: Allocator,
    io: Io,
    work_dir: []const u8,
    architecture: *const ArchitectureDescriptor,
) ![]u8 {
    const iso_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ work_dir, architecture.iso_name });
    errdefer gpa.free(iso_path);

    const expected_digest = artifact_pipeline.parseSha256(architecture.iso_sha256) catch
        return error.InvalidIsoChecksum;
    var curl = artifact_pipeline.CurlDownloader{
        .executable_path = "curl",
    };
    const acquired = artifact_pipeline.acquireVerified(
        gpa,
        io,
        .{
            .url = architecture.iso_url,
            .destination_path = iso_path,
            .expected_sha256 = expected_digest,
            .max_size = iso_max_bytes,
        },
        curl.downloader(),
    ) catch |err| switch (err) {
        error.ChecksumMismatch => return error.IsoChecksumMismatch,
        else => return err,
    };
    if (acquired.reused_cache) {
        std.debug.print("ISO cached at {s}\n", .{iso_path});
    } else {
        std.debug.print("ISO downloaded: {s}\n", .{iso_path});
    }
    try validateIso(io, iso_path, architecture);
    return iso_path;
}

// ─── tool check ──────────────────────────────────────────────────────────────

fn requireTool(gpa: Allocator, io: Io, name: []const u8) bool {
    const bytes = capture(gpa, io, &.{ "which", name }) catch return false;
    gpa.free(bytes);
    return true;
}

fn guestArtifactMatchesArchitecture(
    file_description: []const u8,
    architecture: *const ArchitectureDescriptor,
) bool {
    return std.mem.indexOf(u8, file_description, architecture.elf_file_marker) != null;
}

fn validateGuestArtifact(
    gpa: Allocator,
    io: Io,
    path: []const u8,
    architecture: *const ArchitectureDescriptor,
) !void {
    const description = try capture(gpa, io, &.{ "file", "-b", path });
    defer gpa.free(description);
    if (!guestArtifactMatchesArchitecture(description, architecture)) {
        std.debug.print(
            "error: guest artifact {s} does not match requested {s}: {s}",
            .{ path, @tagName(architecture.architecture), description },
        );
        return error.GuestArtifactArchitectureMismatch;
    }
}

// ─── args ─────────────────────────────────────────────────────────────────────

const Args = struct {
    architecture: ?AzureLinuxArchitecture = null,
    flavor: Flavor = .core,
    iso: ?[]const u8 = null,
    output: ?[]const u8 = null,
    size: ?[]const u8 = null,
    work_dir: ?[]const u8 = null,
    zvmi_path: ?[]const u8 = null,
    zvminit_path: ?[]const u8 = null,
    azagent_path: ?[]const u8 = null,
    preload_path: ?[]const u8 = null,
    uki_signing_certificate: ?[]const u8 = null,
    uki_signing_certificate_sha256: ?[]const u8 = null,
    uki_signing_key: ?[]const u8 = null,
    uki_sign_command: ?[]const u8 = null,
    uki_sign_command_arg: ?[]const u8 = null,
    sbsign: []const u8 = "sbsign",
    sbverify: []const u8 = "sbverify",
    openssl: []const u8 = "openssl",
};

const help_text =
    \\Usage: build_generalized_azurelinux4 [options]
    \\
    \\  --architecture <arch> x86_64 or aarch64 (injected by build.zig)
    \\  --flavor <core|full> Image flavor (default: core)
    \\  --iso <path>        Architecture-matched Azure Linux 4 ISO (downloaded if omitted)
    \\  --output <path>     Output QCOW2 (architecture/flavor-specific default)
    \\  --size <size>       Disk size (flavor-specific default)
    \\  --work-dir <dir>    Working directory (architecture/flavor-specific default)
    \\  --zvmi <path>       zvmi executable (injected by build.zig)
    \\  --zvminit <path>    guest zvminit binary (injected by build.zig)
    \\  --azagent <path>    guest azagent binary (injected by build.zig)
    \\  --preload <path>    zstd_max_preload.so (injected by build.zig)
    \\  --uki-signing-certificate <path>
    \\                      Public certificate used to verify signed UKIs
    \\  --uki-signing-certificate-sha256 <hex>
    \\                      Expected SHA-256 of the canonical DER certificate
    \\  --uki-signing-key <path>
    \\                      Local development private key
    \\  --uki-sign-command <absolute-path>
    \\                      External production signer executable
    \\  --uki-sign-command-arg <argument>
    \\                      Optional fixed signer subcommand
    \\  --sbsign <path>     sbsign executable for local-key mode
    \\  --sbverify <path>   sbverify executable (default: sbverify)
    \\  --openssl <path>    OpenSSL executable (default: openssl)
    \\
    \\Preferred invocation: zig build generalized-azurelinux4 -- [user options]
    \\
;

pub fn parseArchitecture(value: []const u8) error{UnsupportedArchitecture}!AzureLinuxArchitecture {
    if (std.mem.eql(u8, value, "x86_64")) return .x86_64;
    if (std.mem.eql(u8, value, "aarch64")) return .aarch64;
    return error.UnsupportedArchitecture;
}

pub fn parseFlavor(value: []const u8) error{UnsupportedFlavor}!Flavor {
    if (std.mem.eql(u8, value, "core")) return .core;
    if (std.mem.eql(u8, value, "full")) return .full;
    return error.UnsupportedFlavor;
}

fn parseArgs(argv: []const []const u8) !Args {
    var a = Args{};
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.architecture = try parseArchitecture(argv[i]);
        } else if (std.mem.eql(u8, arg, "--flavor")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.flavor = try parseFlavor(argv[i]);
        } else if (std.mem.eql(u8, arg, "--iso")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.iso = argv[i];
        } else if (std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.output = argv[i];
        } else if (std.mem.eql(u8, arg, "--size")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.size = argv[i];
        } else if (std.mem.eql(u8, arg, "--work-dir")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.work_dir = argv[i];
        } else if (std.mem.eql(u8, arg, "--zvmi")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.zvmi_path = argv[i];
        } else if (std.mem.eql(u8, arg, "--zvminit")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.zvminit_path = argv[i];
        } else if (std.mem.eql(u8, arg, "--azagent")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.azagent_path = argv[i];
        } else if (std.mem.eql(u8, arg, "--preload")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.preload_path = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-signing-certificate")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.uki_signing_certificate = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-signing-certificate-sha256")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.uki_signing_certificate_sha256 = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-signing-key")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.uki_signing_key = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-sign-command")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.uki_sign_command = argv[i];
        } else if (std.mem.eql(u8, arg, "--uki-sign-command-arg")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.uki_sign_command_arg = argv[i];
        } else if (std.mem.eql(u8, arg, "--sbsign")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.sbsign = argv[i];
        } else if (std.mem.eql(u8, arg, "--sbverify")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.sbverify = argv[i];
        } else if (std.mem.eql(u8, arg, "--openssl")) {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            a.openssl = argv[i];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("{s}", .{help_text});
            std.process.exit(0);
        } else {
            std.debug.print("error: unexpected argument '{s}'\n", .{arg});
            return error.UnexpectedArgument;
        }
    }
    return a;
}

fn signingConfig(args: Args) !?uki_signing.Config {
    const has_any_signing_option = args.uki_signing_certificate != null or
        args.uki_signing_certificate_sha256 != null or
        args.uki_signing_key != null or
        args.uki_sign_command != null or
        args.uki_sign_command_arg != null;
    if (!has_any_signing_option) return null;

    const certificate_path = args.uki_signing_certificate orelse
        return error.MissingUkiSigningCertificate;
    const expected_sha256 = try uki_signing.parseFingerprint(
        args.uki_signing_certificate_sha256 orelse
            return error.MissingUkiSigningCertificateSha256,
    );
    if ((args.uki_signing_key == null) == (args.uki_sign_command == null)) {
        return error.InvalidUkiSignerSelection;
    }
    if (args.uki_sign_command == null and args.uki_sign_command_arg != null) {
        return error.InvalidUkiSignerSelection;
    }
    const mode: uki_signing.Mode = if (args.uki_signing_key) |key_path|
        .{ .local_key = .{
            .private_key_path = key_path,
            .sbsign_path = args.sbsign,
        } }
    else blk: {
        const command_path = args.uki_sign_command.?;
        if (!std.fs.path.isAbsolute(command_path)) {
            return error.UkiSignCommandMustBeAbsolute;
        }
        break :blk .{ .external_command = .{
            .executable_path = command_path,
            .argument = args.uki_sign_command_arg,
        } };
    };
    return .{
        .certificate_path = certificate_path,
        .expected_certificate_sha256 = expected_sha256,
        .sbverify_path = args.sbverify,
        .openssl_path = args.openssl,
        .mode = mode,
    };
}

// ─── main ─────────────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);

    const args = parseArgs(argv[1..]) catch |err| {
        std.debug.print("error: {s}\n{s}", .{ @errorName(err), help_text });
        std.process.exit(1);
    };
    const signing_config = signingConfig(args) catch |err| {
        std.debug.print("error: invalid UKI signing options ({s})\n", .{@errorName(err)});
        std.process.exit(1);
    };
    const architecture = requireArchitecture(args.architecture) catch {
        std.debug.print("error: --architecture is required (provided by zig build)\n", .{});
        std.process.exit(1);
    };
    const flavor = flavorDescriptor(args.flavor);
    const output_path = args.output orelse defaultOutputPath(architecture.architecture, flavor.flavor);
    const work_dir = args.work_dir orelse defaultWorkDir(architecture.architecture, flavor.flavor);
    const size_arg = args.size orelse flavor.default_size;
    const requested_size = zvmi.parseSize(size_arg) catch |err| {
        std.debug.print("error: invalid --size ({s})\n", .{@errorName(err)});
        std.process.exit(1);
    };
    const max_qcow2_file_size = std.math.add(
        u64,
        requested_size,
        requested_size / 64 + 64 * 1024 * 1024,
    ) catch {
        std.debug.print("error: --size is too large\n", .{});
        std.process.exit(1);
    };

    const zvmi_path = args.zvmi_path orelse {
        std.debug.print("error: --zvmi is required (provided by zig build)\n", .{});
        std.process.exit(1);
    };
    const zvminit_path = args.zvminit_path;
    const azagent_path = args.azagent_path;
    const preload_path = args.preload_path orelse {
        std.debug.print("error: --preload is required (provided by zig build)\n", .{});
        std.process.exit(1);
    };

    // Check required external tools.
    var tools_ok = true;
    for (&[_][]const u8{ "sudo", "tar", "dnf", "curl", "qemu-img", "file", "find", "gpg", "systemctl", "du", "mount", "umount", "readlink" }) |tool| {
        if (!requireTool(gpa, io, tool)) {
            std.debug.print("error: required tool '{s}' not found in PATH\n", .{tool});
            tools_ok = false;
        }
    }
    if (signing_config) |config| {
        const certificate_stat = Dir.cwd().statFile(io, config.certificate_path, .{}) catch |err| {
            std.debug.print(
                "error: cannot read UKI signing certificate '{s}' ({s})\n",
                .{ config.certificate_path, @errorName(err) },
            );
            std.process.exit(1);
        };
        if (!isRegularNonemptyFile(certificate_stat.kind, certificate_stat.size)) {
            std.debug.print(
                "error: UKI signing certificate is not a nonempty regular file: {s}\n",
                .{config.certificate_path},
            );
            std.process.exit(1);
        }
        if (config.mode == .local_key) {
            const key_path = config.mode.local_key.private_key_path;
            const key_stat = Dir.cwd().statFile(io, key_path, .{}) catch |err| {
                std.debug.print(
                    "error: cannot read local UKI signing key '{s}' ({s})\n",
                    .{ key_path, @errorName(err) },
                );
                std.process.exit(1);
            };
            if (!isRegularNonemptyFile(key_stat.kind, key_stat.size)) {
                std.debug.print(
                    "error: local UKI signing key is not a nonempty regular file: {s}\n",
                    .{key_path},
                );
                std.process.exit(1);
            }
        }
        const signing_tools = switch (config.mode) {
            .local_key => |local| [_][]const u8{
                config.openssl_path,
                config.sbverify_path,
                local.sbsign_path,
            },
            .external_command => |external| [_][]const u8{
                config.openssl_path,
                config.sbverify_path,
                external.executable_path,
            },
        };
        for (signing_tools) |tool| {
            if (!requireTool(gpa, io, tool)) {
                std.debug.print("error: required signing tool '{s}' not found\n", .{tool});
                tools_ok = false;
            }
        }
    }
    if (!tools_ok) std.process.exit(1);
    if (flavor.pid1 == .zvminit) {
        try validateGuestArtifact(gpa, io, zvminit_path orelse return error.MissingZvminitArtifact, architecture);
        try validateGuestArtifact(gpa, io, azagent_path orelse return error.MissingAzagentArtifact, architecture);
    }

    try Dir.cwd().createDirPath(io, work_dir);
    const signing_provenance_path = try signingProvenancePath(
        gpa,
        work_dir,
        architecture,
        flavor,
    );
    defer gpa.free(signing_provenance_path);
    Dir.cwd().deleteFile(io, signing_provenance_path) catch {};
    const signing_scratch = if (signing_config != null)
        try std.fmt.allocPrint(gpa, "{s}/uki-signing-scratch", .{work_dir})
    else
        null;
    defer if (signing_scratch) |path| gpa.free(path);
    defer if (signing_scratch) |path| Dir.cwd().deleteTree(io, path) catch {};
    var signing_certificate: ?uki_signing.Certificate = null;
    defer if (signing_certificate) |*certificate| certificate.deinit(gpa);
    if (signing_config) |config| {
        try uki_signing.prepareScratchDirectory(io, signing_scratch.?);
        signing_certificate = try uki_signing.prepareCertificate(
            gpa,
            io,
            config,
            signing_scratch.?,
        );
    }

    const downloaded_iso_path = if (args.iso == null) try downloadIso(gpa, io, work_dir, architecture) else null;
    defer if (downloaded_iso_path) |path| gpa.free(path);
    const iso_path = args.iso orelse downloaded_iso_path.?;
    _ = Dir.cwd().statFile(io, iso_path, .{}) catch |err| {
        std.debug.print("error: ISO not found: {s} ({s})\n", .{ iso_path, @errorName(err) });
        std.process.exit(1);
    };
    try validateIso(io, iso_path, architecture);

    const rootfs_path = try std.fmt.allocPrint(gpa, "{s}/rootfs", .{work_dir});
    defer gpa.free(rootfs_path);

    const core_digest = switch (flavor.flavor) {
        .core => try pullRootfs(gpa, io, work_dir, rootfs_path, architecture),
        .full => try bootstrapFullRootfs(gpa, io, work_dir, rootfs_path, architecture),
    };
    defer gpa.free(core_digest);
    const trusted_key_path = switch (flavor.flavor) {
        .core => try extractTrustedSigningKey(gpa, io, rootfs_path, work_dir, architecture),
        .full => try canonicalTrustedSigningKeyPath(gpa, io, work_dir, architecture),
    };
    defer gpa.free(trusted_key_path);

    const systemd_boot_rpm_path = try acquireSystemdBootRpm(gpa, io, work_dir, architecture);
    defer gpa.free(systemd_boot_rpm_path);
    const installed_closure = try installGuestContent(
        gpa,
        io,
        rootfs_path,
        work_dir,
        trusted_key_path,
        zvminit_path,
        azagent_path,
        systemd_boot_rpm_path,
        architecture,
        flavor,
    );
    defer gpa.free(installed_closure);
    if (flavor.flavor == .full) {
        try validateFullIsoKernelCompatibility(gpa, io, iso_path, rootfs_path, work_dir, architecture);
    }
    try enforceMinimumRootFreeSpace(gpa, io, rootfs_path, requested_size, architecture, flavor);

    const source_identity = switch (flavor.flavor) {
        .core => core_digest,
        .full => vm_base_profile_blob,
    };
    const layout_dir = try createOciLayout(
        gpa,
        io,
        work_dir,
        rootfs_path,
        source_identity,
        architecture,
        flavor,
        installed_closure,
    );
    defer gpa.free(layout_dir);
    try validateGeneralizedOciLayout(gpa, io, layout_dir, architecture, flavor);

    // Ensure output parent directory exists.
    if (std.fs.path.dirname(output_path)) |parent| {
        Dir.cwd().createDirPath(io, parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    // Build the raw QCOW2 first (no compression).
    const raw_qcow2 = try std.fmt.allocPrint(gpa, "{s}.raw.qcow2", .{output_path});
    defer gpa.free(raw_qcow2);
    Dir.cwd().deleteFile(io, raw_qcow2) catch {};
    const oci_load_options = ociLoadOptionsForFlavor(flavor);
    const max_oci_blob_size_arg = try std.fmt.allocPrint(gpa, "{d}", .{oci_load_options.max_blob_size});
    defer gpa.free(max_oci_blob_size_arg);
    const max_oci_layer_size_arg = try std.fmt.allocPrint(gpa, "{d}", .{oci_load_options.max_layer_size});
    defer gpa.free(max_oci_layer_size_arg);
    const max_oci_archive_size_arg = try std.fmt.allocPrint(gpa, "{d}", .{oci_load_options.max_archive_size});
    defer gpa.free(max_oci_archive_size_arg);

    std.debug.print("Building disk image...\n", .{});
    var build_args = std.array_list.Managed([]const u8).init(gpa);
    defer build_args.deinit();
    try build_args.appendSlice(&.{
        zvmi_path,
        "build-image",
        "--iso",
        iso_path,
        "--container",
        layout_dir,
        "--max-oci-blob-size",
        max_oci_blob_size_arg,
        "--max-oci-layer-size",
        max_oci_layer_size_arg,
        "--max-oci-archive-size",
        max_oci_archive_size_arg,
        "--generation",
        "2",
        "--size",
        size_arg,
        "--skip-iso-rootfs",
    });
    if (flavor.flavor == .full) {
        try build_args.appendSlice(&.{
            "--root-selinux-label",
            full_root_selinux_label,
        });
    }
    try build_args.appendSlice(&.{
        "--boot-mode",
        "uki",
        "--stub-source-path",
        architecture.systemd_boot_stub_path,
        "--esp-size",
        flavor.esp_size_arg,
        "--extra-kernel-options",
        ukiExtraKernelOptions(architecture, flavor),
        "-o",
        raw_qcow2,
        "-O",
        "qcow2",
        "-v",
    });
    try run(gpa, io, build_args.items);

    var signing_report: ?UkiSigningReport = null;
    defer if (signing_report) |*report| report.deinit(gpa);
    if (signing_config) |config| {
        std.debug.print("Signing UKIs...\n", .{});
        signing_report = try signGeneralizedImage(
            gpa,
            io,
            raw_qcow2,
            architecture,
            flavor,
            config,
            signing_scratch.?,
            init.environ_map,
        );
    }

    // Compress to maximum-zstd QCOW2 via the LD_PRELOAD intercept library.
    std.debug.print("Compressing to maximum-zstd QCOW2...\n", .{});
    var env_map = try init.environ_map.clone(gpa);
    defer env_map.deinit();
    try env_map.put("LD_PRELOAD", preload_path);

    const staged_qcow2 = try std.fmt.allocPrint(gpa, "{s}.validated-stage", .{output_path});
    defer gpa.free(staged_qcow2);
    const raw_metadata = try artifact_pipeline.hashFile(io, raw_qcow2);
    const finalized = artifact_pipeline.finalizeQcow2(
        gpa,
        io,
        .{
            .input_path = raw_qcow2,
            .expected_input_sha256 = raw_metadata.sha256,
            .max_input_size = max_qcow2_file_size,
            .source_format = .qcow2,
            .expected_virtual_size = requested_size,
            .max_virtual_size = requested_size,
            .output_path = staged_qcow2,
            .max_output_size = max_qcow2_file_size,
            .qemu_img_path = "qemu-img",
            .compression = .zstd,
            .convert_environ_map = &env_map,
        },
    ) catch |err| {
        std.debug.print(
            "error: QCOW2 finalization failed ({s}); keeping {s}\n",
            .{ @errorName(err), raw_qcow2 },
        );
        return err;
    };

    const validation = validateGeneralizedImage(gpa, io, staged_qcow2, requested_size, architecture, flavor) catch |err| {
        std.debug.print(
            "error: generalized image structural validation failed ({s}); keeping {s} and {s}\n",
            .{ @errorName(err), raw_qcow2, staged_qcow2 },
        );
        return err;
    };
    std.debug.print(
        "Validated generalized QCOW2: virtual {d} bytes, ESP {d} bytes, root {d} bytes, UKI {d} bytes\n",
        .{ validation.virtual_size, validation.esp_size, validation.root_size, validation.uki_size },
    );
    if (signing_config) |config| {
        verifySignedGeneralizedImage(
            gpa,
            io,
            staged_qcow2,
            config,
            signing_scratch.?,
            &signing_report.?,
        ) catch |err| {
            std.debug.print(
                "error: finalized UKI signature verification failed ({s}); keeping {s} and {s}\n",
                .{ @errorName(err), raw_qcow2, staged_qcow2 },
            );
            return err;
        };
        try writeSigningProvenance(
            gpa,
            io,
            work_dir,
            architecture,
            flavor,
            config,
            &signing_certificate.?,
            &signing_report.?,
        );
        std.debug.print("Verified signed UKIs in finalized QCOW2.\n", .{});
    }

    Dir.cwd().rename(staged_qcow2, Dir.cwd(), output_path, io) catch |err| {
        std.debug.print(
            "error: could not publish validated image {s} as {s} ({s}); keeping {s}\n",
            .{ staged_qcow2, output_path, @errorName(err), raw_qcow2 },
        );
        return err;
    };

    // Remove the intermediate uncompressed QCOW2 on success.
    Dir.cwd().deleteFile(io, raw_qcow2) catch |err| {
        std.debug.print("warning: could not remove {s}: {s}\n", .{ raw_qcow2, @errorName(err) });
    };

    std.debug.print(
        "Built {s} ({d} bytes, virtual size {d})\n",
        .{ output_path, finalized.artifact.size, finalized.virtual_size },
    );
}

// ─── unit tests ──────────────────────────────────────────────────────────────

test "validateOsRelease accepts the standard Azure Linux symlink" {
    var entries = [_]oci.FileTree.Entry{
        .{
            .path = "etc/os-release",
            .kind = .symlink,
            .mode = 0o777,
            .size = 0,
            .link_name = "../usr/lib/os-release",
        },
        .{
            .path = "usr/lib/os-release",
            .kind = .file,
            .mode = 0o644,
            .size = 0,
        },
    };
    const image: oci.FileTree = .{
        .allocator = std.testing.allocator,
        .entries = &entries,
    };

    try validateOsRelease(image);
}

test "safeLayerPath strips ./ prefix" {
    try std.testing.expectEqualStrings("etc/passwd", (try safeLayerPath("./etc/passwd")).?);
}

test "safeLayerPath strips leading /" {
    try std.testing.expectEqualStrings("usr/bin/sh", (try safeLayerPath("/usr/bin/sh")).?);
}

test "safeLayerPath returns null for root" {
    try std.testing.expect((try safeLayerPath("./")) == null);
    try std.testing.expect((try safeLayerPath("")) == null);
    try std.testing.expect((try safeLayerPath("/")) == null);
}

test "safeLayerPath rejects .." {
    try std.testing.expectError(error.UnsafeLayerPath, safeLayerPath("../../etc/passwd"));
    try std.testing.expectError(error.UnsafeLayerPath, safeLayerPath("./etc/../../../passwd"));
    try std.testing.expectError(error.UnsafeLayerPath, safeLayerPath("a/../b"));
}

test "parseDigestHex accepts sha256: prefix" {
    const hex = try parseDigestHex("sha256:" ++ "a" ** 64);
    try std.testing.expectEqualStrings("a" ** 64, hex);
}

test "parseDigestHex accepts bare hex" {
    try std.testing.expectEqualStrings("b" ** 64, try parseDigestHex("b" ** 64));
}

test "parseDigestHex rejects short and invalid chars" {
    try std.testing.expectError(error.InvalidDigest, parseDigestHex("sha256:short"));
    try std.testing.expectError(error.InvalidDigest, parseDigestHex("sha256:" ++ "g" ** 64));
    try std.testing.expectError(error.InvalidDigest, parseDigestHex("notahex"));
}

test "selectLinuxManifest picks each requested Linux platform" {
    const gpa = std.testing.allocator;
    const json_text =
        \\{"manifests":[
        \\  {"platform":{"os":"linux","architecture":"arm64"},"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},
        \\  {"platform":{"os":"linux","architecture":"amd64"},"digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}
        \\]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, json_text, .{});
    defer parsed.deinit();
    const arm64_digest = try selectLinuxManifest(gpa, parsed.value, aarch64.oci_architecture);
    defer gpa.free(arm64_digest);
    try std.testing.expectEqualStrings("sha256:1111111111111111111111111111111111111111111111111111111111111111", arm64_digest);
    const amd64_digest = try selectLinuxManifest(gpa, parsed.value, x86_64.oci_architecture);
    defer gpa.free(amd64_digest);
    try std.testing.expectEqualStrings("sha256:2222222222222222222222222222222222222222222222222222222222222222", amd64_digest);
}

test "selectLinuxManifest rejects an unavailable platform" {
    const gpa = std.testing.allocator;
    const json_text =
        \\{"manifests":[{"platform":{"os":"linux","architecture":"arm64"},"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}]}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, json_text, .{});
    defer parsed.deinit();
    try std.testing.expectError(
        error.NoLinuxArchitectureManifest,
        selectLinuxManifest(gpa, parsed.value, x86_64.oci_architecture),
    );
}

test "sha256Bytes produces known digest" {
    const hex = sha256Bytes("hello");
    // echo -n hello | sha256sum => 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    try std.testing.expectEqualStrings("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", &hex);
}

test "architecture and flavor descriptors pin inputs and output namespaces" {
    const gpa = std.testing.allocator;
    const cases = [_]*const ArchitectureDescriptor{ &x86_64, &aarch64 };
    for (cases) |architecture| {
        const cache_path = try systemdBootRpmCachePath(gpa, ".scratch/work", architecture);
        defer gpa.free(cache_path);
        const expected_cache_path = try std.fmt.allocPrint(
            gpa,
            ".scratch/work/downloads/{s}",
            .{architecture.systemd_boot_rpm_name},
        );
        defer gpa.free(expected_cache_path);
        try std.testing.expectEqualStrings(expected_cache_path, cache_path);
        _ = try artifact_pipeline.parseSha256(architecture.iso_sha256);
        _ = try artifact_pipeline.parseSha256(architecture.base_manifest_digest);
        _ = try artifact_pipeline.parseSha256(architecture.repomd_sha256);
        _ = try artifact_pipeline.parseSha256(architecture.systemd_boot_rpm_sha256);
        try std.testing.expectEqualStrings("LiveOS/squashfs.img", architecture.iso_squashfs_path);
        try std.testing.expectEqualStrings("LiveOS/rootfs.img", architecture.iso_nested_rootfs_path);
        try std.testing.expectEqual(architecture.root_type_guid, architecture.root_role.defaultTypeGuid());
    }
    try std.testing.expectEqual(@as(u64, 16 * 1024 * 1024), systemd_boot_unsigned_rpm_max_bytes);

    try std.testing.expectEqualStrings("https://aka.ms/azurelinux-4.0-x86_64.iso", x86_64.iso_url);
    try std.testing.expectEqualStrings("https://aka.ms/azurelinux-4.0-aarch64.iso", aarch64.iso_url);
    try std.testing.expectEqualStrings("AzureLinux-4.0-x86_64.iso", x86_64.iso_name);
    try std.testing.expectEqualStrings("AzureLinux-4.0-aarch64.iso", aarch64.iso_name);
    try std.testing.expectEqualStrings(
        "d98f7d1ffaa916de7c9f66ffdadb150c174da691509e760835709ffa7829ca48",
        x86_64.iso_sha256,
    );
    try std.testing.expectEqualStrings(
        "762039fde64a59806750ee86ca98132fad4f9df02e7684490017cdfda0c55157",
        aarch64.iso_sha256,
    );
    try std.testing.expectEqualStrings(
        "sha256:9070b05147f01e5a4bac47723c95f2555e11b9d3324c1df1910ff3545b7ce319",
        x86_64.base_manifest_digest,
    );
    try std.testing.expectEqualStrings(
        "sha256:e541db83a8511c25fa1dd989161263874b7395ddd588f5caaa25453ea4e23263",
        aarch64.base_manifest_digest,
    );
    try std.testing.expectEqualStrings(
        "5f888b701b5b548944bb9079b01c948c3a0c73c33a6cea7d1179c1d746292151",
        x86_64.repomd_sha256,
    );
    try std.testing.expectEqualStrings(
        "158cd3d70fa51fdddde3e529af41d375db1b40e54f9ab8c5cc14afc8c2e81214",
        aarch64.repomd_sha256,
    );
    try std.testing.expectEqualStrings("AzureLinux-4.0-x86_64.core.qcow2", defaultOutputPath(.x86_64, .core));
    try std.testing.expectEqualStrings("AzureLinux-4.0-aarch64.core.qcow2", defaultOutputPath(.aarch64, .core));
    try std.testing.expectEqualStrings("AzureLinux-4.0-x86_64.qcow2", defaultOutputPath(.x86_64, .full));
    try std.testing.expectEqualStrings("AzureLinux-4.0-aarch64.qcow2", defaultOutputPath(.aarch64, .full));
    try std.testing.expectEqualStrings(".scratch/azurelinux4-core-x86_64", defaultWorkDir(.x86_64, .core));
    try std.testing.expectEqualStrings(".scratch/azurelinux4-core-aarch64", defaultWorkDir(.aarch64, .core));
    try std.testing.expectEqualStrings(".scratch/azurelinux4-full-x86_64", defaultWorkDir(.x86_64, .full));
    try std.testing.expectEqualStrings(".scratch/azurelinux4-full-aarch64", defaultWorkDir(.aarch64, .full));
    try std.testing.expectEqualStrings("5G", full.default_size);
    try std.testing.expectEqual(@as(u64, 1024 * 1024 * 1024), full.minimum_root_free_bytes);
}

test "architecture descriptors select RPMs, stubs, EFI paths, and binfmt" {
    try std.testing.expectEqualStrings(
        "systemd-boot-unsigned-258.4-4.azl4.x86_64.rpm",
        x86_64.systemd_boot_rpm_name,
    );
    try std.testing.expectEqualStrings(
        "systemd-boot-unsigned-258.4-4.azl4.aarch64.rpm",
        aarch64.systemd_boot_rpm_name,
    );
    try std.testing.expectEqualStrings("x86_64", x86_64.dnf_architecture);
    try std.testing.expectEqualStrings("aarch64", aarch64.dnf_architecture);
    try std.testing.expectEqual(std.Target.Cpu.Arch.x86_64, x86_64.target_cpu);
    try std.testing.expectEqual(std.Target.Cpu.Arch.aarch64, aarch64.target_cpu);
    try std.testing.expectEqualStrings(
        "85dd3ac0c532bceb09fc0a85c6568c51fc4ee84e0c478d1302b7a2d84e1bea5c",
        x86_64.systemd_boot_rpm_sha256,
    );
    try std.testing.expectEqualStrings(
        "65aefdef9bc55f71f43c18b738fc1a61eeedd9fea7d803f0b0b06467fb748991",
        aarch64.systemd_boot_rpm_sha256,
    );
    try std.testing.expectEqualStrings(
        "etc/pki/rpm-gpg/RPM-GPG-KEY-azurelinux-4.0-x86_64",
        x86_64.signing_key_path,
    );
    try std.testing.expectEqualStrings(
        "etc/pki/rpm-gpg/RPM-GPG-KEY-azurelinux-4.0-aarch64",
        aarch64.signing_key_path,
    );
    try std.testing.expectEqualStrings(
        "usr/lib/systemd/boot/efi/linuxx64.efi.stub",
        x86_64.systemd_boot_stub_path,
    );
    try std.testing.expectEqualStrings(
        "usr/lib/systemd/boot/efi/linuxaa64.efi.stub",
        aarch64.systemd_boot_stub_path,
    );
    try std.testing.expectEqualStrings("EFI/BOOT/BOOTX64.EFI", x86_64.fallback_efi_path);
    try std.testing.expectEqualStrings("EFI/BOOT/BOOTAA64.EFI", aarch64.fallback_efi_path);
    try std.testing.expectEqual(@as(u16, 0x8664), x86_64.uki_pe_machine);
    try std.testing.expectEqual(@as(u16, 0xaa64), aarch64.uki_pe_machine);
    try std.testing.expectEqual(zvmi.layout.PartitionRole.root_x86_64, x86_64.root_role);
    try std.testing.expectEqual(zvmi.layout.PartitionRole.root_aarch64, aarch64.root_role);
    try std.testing.expectEqual(zvmi.guid.linux_root_x86_64, x86_64.root_type_guid);
    try std.testing.expectEqual(zvmi.guid.linux_root_aarch64, aarch64.root_type_guid);
    try std.testing.expectEqualStrings("qemu-x86_64-static", x86_64.binfmt_static_name);
    try std.testing.expectEqualStrings("qemu-aarch64-static", aarch64.binfmt_static_name);
    try std.testing.expectEqualStrings("/proc/sys/fs/binfmt_misc/qemu-x86_64", x86_64.binfmt_registration_path);
    try std.testing.expectEqualStrings("/proc/sys/fs/binfmt_misc/qemu-aarch64", aarch64.binfmt_registration_path);
    try std.testing.expectEqualStrings("kernel-6.18.31-1.3.azl4", x86_64.full_kernel_package);
    try std.testing.expectEqualStrings("kernel-modules-6.18.31-1.3.azl4", x86_64.full_kernel_modules_package);
    try std.testing.expectEqualStrings("6.18.31-1.3.azl4.x86_64", x86_64.full_kernel_release);
    try std.testing.expectEqualStrings("kernel-6.18.31-1.3.azl4", aarch64.full_kernel_package);
    try std.testing.expectEqualStrings("kernel-modules-6.18.31-1.3.azl4", aarch64.full_kernel_modules_package);
    try std.testing.expectEqualStrings("6.18.31-1.3.azl4.aarch64", aarch64.full_kernel_release);
}

test "full flavor encodes the pinned official vm-base package profile" {
    try std.testing.expectEqualStrings("https://github.com/microsoft/azurelinux", vm_base_upstream_repository);
    try std.testing.expectEqualStrings("5b41bff6ebaf7e8fc78637b564efee23b66e7d67", vm_base_upstream_commit);
    try std.testing.expectEqualStrings("8c870852e711273275c83f0b94ecd914ff709af8", vm_base_profile_blob);
    try std.testing.expectEqualStrings("base/images/vm-base/vm-base.kiwi", vm_base_profile_path);
    try std.testing.expectEqualStrings("vm-base", vm_base_profile_name);
    for (&[_][]const u8{
        "systemd",
        "filesystem",
        "cloud-init",
        "WALinuxAgent",
        "openssh-server",
        "openssh-clients",
        "azure-vm-utils",
        "hyperv-daemons",
        "kernel",
        "kernel-modules",
        "systemd-networkd",
        "sudo",
        "azurelinux-repos",
    }) |package| {
        try std.testing.expect(argvContains(&vm_base_packages, package));
    }
    try std.testing.expect(argvContains(x86_64.full_efi_packages, "grub2-efi-x64"));
    try std.testing.expect(argvContains(aarch64.full_efi_packages, "grub2-efi-aa64"));
    try std.testing.expect(argvContains(x86_64.full_efi_packages, "shim"));
    try std.testing.expect(argvContains(aarch64.full_efi_packages, "shim"));

    const x86_packages = try packagesForInstall(std.testing.allocator, &full, &x86_64);
    defer std.testing.allocator.free(x86_packages);
    try std.testing.expect(argvContains(x86_packages, x86_64.full_kernel_package));
    try std.testing.expect(argvContains(x86_packages, x86_64.full_kernel_modules_package));
    try std.testing.expect(!argvContains(x86_packages, "kernel"));
    try std.testing.expect(!argvContains(x86_packages, "kernel-modules"));
}

test "flavor contracts keep full systemd-only and core zvminit-only" {
    try std.testing.expectEqual(Pid1.zvminit, core.pid1);
    try std.testing.expectEqual(Pid1.systemd, full.pid1);
    try std.testing.expectEqual(Provisioner.zvminit_azagent, core.provisioner);
    try std.testing.expectEqual(Provisioner.cloud_init_waagent, full.provisioner);
    try std.testing.expectEqualStrings("/sbin/zvminit", core.oci_entrypoint);
    try std.testing.expectEqualStrings("/usr/lib/systemd/systemd", full.oci_entrypoint);
    for (&[_][]const u8{ "usr/bin/zvminit", "usr/bin/azagent", "etc/ssh/sshd_config.d/10-zvminit.conf" }) |path| {
        try std.testing.expect(argvContains(full.forbidden_rootfs_paths, path));
    }
    try std.testing.expect(!argvContains(full.forbidden_rootfs_paths, "sbin/zvminit"));
    try std.testing.expect(!argvContains(full.forbidden_rootfs_paths, "usr/sbin/azagent"));
    try std.testing.expect(argvContains(full.required_rootfs_paths, "usr/lib/systemd/systemd"));
    try std.testing.expect(argvContains(full.required_rootfs_paths, "usr/bin/sshd"));
    try std.testing.expect(argvContains(full.required_rootfs_paths, "usr/bin/waagent"));
    try std.testing.expect(argvContains(full.required_rootfs_paths, "usr/bin/rpm"));
    try std.testing.expect(argvContains(full.required_rootfs_paths, "usr/bin/setfiles"));
    try std.testing.expect(argvContains(full.required_rootfs_paths, "usr/lib/systemd/system/chronyd.service"));
    try std.testing.expect(argvContains(full.required_rootfs_paths, "usr/lib/sysusers.d/chrony.conf"));
    try std.testing.expect(argvContains(full.required_rootfs_paths, "etc/systemd/network/20-wired.network"));
    try std.testing.expect(!argvContains(full.required_rootfs_paths, ".autorelabel"));
    try std.testing.expect(argvContains(full.forbidden_rootfs_paths, ".autorelabel"));
    try std.testing.expect(!argvContains(full.required_rootfs_paths, "usr/sbin/waagent"));
    try std.testing.expect(!argvContains(&full_required_systemd_units, "cloud-init.service"));
    try std.testing.expect(argvContains(&full_required_systemd_units, "cloud-init-main.service"));
    try std.testing.expect(argvContains(&full_required_systemd_units, "cloud-init-network.service"));
    try std.testing.expectEqualSlices([]const u8, &full_required_systemd_units, &full_enabled_systemd_units);
    try std.testing.expect(full.max_oci_layer_bytes > core.max_oci_layer_bytes);
    const core_oci_limits = ociLoadOptionsForFlavor(&core);
    try std.testing.expectEqual(@as(usize, 128 * 1024 * 1024), core_oci_limits.max_blob_size);
    try std.testing.expectEqual(@as(usize, 128 * 1024 * 1024), core_oci_limits.max_layer_size);
    const full_oci_limits = ociLoadOptionsForFlavor(&full);
    try std.testing.expectEqual(@as(usize, 512 * 1024 * 1024), full_oci_limits.max_blob_size);
    try std.testing.expectEqual(@as(usize, 512 * 1024 * 1024), full_oci_limits.max_layer_size);
    try std.testing.expectEqual(@as(usize, 4 * 1024 * 1024 * 1024), full_oci_limits.max_archive_size);
    try std.testing.expectEqual(@as(usize, 3), ociLayerPlanCount(&core));
    try std.testing.expectEqual(@as(usize, 7), ociLayerPlanCount(&full));
}

test "full network and SELinux boot contracts are fail closed" {
    try std.testing.expect(std.mem.indexOf(u8, full_networkd_config, "Type=ether") != null);
    try std.testing.expect(std.mem.indexOf(u8, full_networkd_config, "DHCP=yes") != null);
    try std.testing.expect(selinuxLabelIsUsable(full_root_selinux_label));
    try std.testing.expect(selinuxLabelIsUsable("system_u:object_r:init_exec_t:s0"));
    try std.testing.expect(!selinuxLabelIsUsable(""));
    try std.testing.expect(!selinuxLabelIsUsable("system_u:object_r:unlabeled_t:s0"));
}

test "full key URI and package-state contracts are canonical" {
    const gpa = std.testing.allocator;
    const uri = try fileUriFromAbsolutePath(gpa, "/work/key space#?.asc");
    defer gpa.free(uri);
    try std.testing.expectEqualStrings("file:///work/key%20space%23%3F.asc", uri);
    try std.testing.expectError(error.RelativeFileUriPath, fileUriFromAbsolutePath(gpa, ".scratch/key.asc"));
    try std.testing.expect(waagentStateContractMatches(0, 0, 0o700));
    try std.testing.expect(!waagentStateContractMatches(1, 0, 0o700));
    try std.testing.expect(!waagentStateContractMatches(0, 0, 0o755));
}

test "chrony state is created at boot with the package user" {
    const service =
        \\[Service]
        \\User=chrony
        \\StateDirectory=chrony
        \\StateDirectoryMode=0750
    ;
    const sysusers =
        \\#Type Name ID GECOS Home Shell
        \\u chrony - "chrony system user" /var/lib/chrony /sbin/nologin
    ;
    try std.testing.expect(chronyStateContractMatches(service, sysusers));
    try std.testing.expect(!chronyStateContractMatches(
        "User=root\nStateDirectory=chrony\nStateDirectoryMode=0750\n",
        sysusers,
    ));
    try std.testing.expect(!chronyStateContractMatches(
        service,
        "u chrony - \"chrony system user\" /run/chrony /sbin/nologin\n",
    ));
}

test "full OCI provenance records profile repomd and NEVRA closure" {
    const gpa = std.testing.allocator;
    const history = try formatOciHistoryComment(
        gpa,
        vm_base_profile_blob,
        &aarch64,
        &full,
        "WALinuxAgent-0:2.15.0.1-2.azl4.noarch\nsystemd-0:258.4-4.azl4.aarch64\n",
    );
    defer gpa.free(history);
    for (&[_][]const u8{
        vm_base_upstream_commit,
        vm_base_profile_blob,
        vm_base_profile_path,
        aarch64.repomd_sha256,
        "installed-nevra-sha256=",
    }) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, history, needle) != null);
    }
}

test "OCI config architecture is required to match the descriptor" {
    try std.testing.expect(ociConfigArchitectureMatches("amd64", &x86_64));
    try std.testing.expect(ociConfigArchitectureMatches("arm64", &aarch64));
    try std.testing.expect(!ociConfigArchitectureMatches("arm64", &x86_64));
    try std.testing.expect(!ociConfigArchitectureMatches(null, &aarch64));
}

test "isRegularNonemptyFile accepts only nonempty regular files" {
    try std.testing.expect(isRegularNonemptyFile(.file, 1));
    try std.testing.expect(!isRegularNonemptyFile(.file, 0));
    try std.testing.expect(!isRegularNonemptyFile(.directory, 1));
    try std.testing.expect(!isRegularNonemptyFile(.sym_link, 1));
}

test "supplied ISO checksum must match the selected architecture" {
    const wrong_checksum = sha256Bytes("not an Azure Linux ISO");
    try std.testing.expect(!isoChecksumMatches(wrong_checksum, &x86_64));
    try std.testing.expect(!isoChecksumMatches(wrong_checksum, &aarch64));
}

test "repository metadata mismatch is rejected for both architectures" {
    const moving_metadata = "<repomd>different transaction</repomd>";
    try std.testing.expect(!repositoryMetadataMatches(moving_metadata, &x86_64));
    try std.testing.expect(!repositoryMetadataMatches(moving_metadata, &aarch64));
}

test "trusted signing key is pinned by checksum and fingerprint" {
    _ = try artifact_pipeline.parseSha256(azurelinux_signing_key_sha256);
    try std.testing.expectEqualStrings("2BC94FFF7015A5F28F1537AD0CD9FED33135CE90", azurelinux_signing_key_fingerprint);
}

test "DNF install permits payload downloads without refreshing verified metadata" {
    const gpa = std.testing.allocator;
    const argv = try dnfInstallArgs(
        gpa,
        "/target-root",
        "--forcearch=x86_64",
        "--repofrompath=zvmi-azurelinux-base,https://example.invalid/base",
        "--setopt=azurelinux-base.gpgkey=file:///key",
        "--setopt=azurelinux-base.baseurl=https://example.invalid/base",
        "--setopt=azurelinux-base.metalink=",
        "--setopt=azurelinux-base.mirrorlist=",
        "--setopt=metadata_expire=never",
        "--setopt=azurelinux-base.metadata_expire=never",
        "--setopt=keepcache=True",
        "--setopt=azurelinux-base.gpgcheck=True",
        "--setopt=cachedir=/private/cache",
        "--setopt=persistdir=/private/persist",
        &.{ "openssh-server", "sudo" },
    );
    defer gpa.free(argv);
    try std.testing.expect(!argvContains(argv, "-C"));
    try std.testing.expect(!argvContains(argv, "--cacheonly"));
    try std.testing.expect(argvContains(argv, "--setopt=metadata_expire=never"));
    try std.testing.expect(argvContains(argv, "--setopt=azurelinux-base.metadata_expire=never"));
    try std.testing.expect(argvContains(argv, "--setopt=cachedir=/private/cache"));
    try std.testing.expect(argvContains(argv, "--setopt=persistdir=/private/persist"));
    try std.testing.expect(argvContains(argv, "--setopt=azurelinux-base.gpgcheck=True"));
    try std.testing.expect(argvContains(argv, dnf_minrate_opt));
    try std.testing.expect(argvContains(argv, dnf_timeout_opt));
    try std.testing.expect(argvContains(argv, dnf_retries_opt));
    try std.testing.expect(argvContains(argv, "--disablerepo=*"));
    try std.testing.expect(argvContains(argv, "--enablerepo=zvmi-azurelinux-base"));
    try std.testing.expectEqualStrings("install", argv[23]);
    try std.testing.expectEqualStrings("openssh-server", argv[24]);
    try std.testing.expectEqualStrings("sudo", argv[25]);
}

test "fresh full installroot defines the repository before transactions" {
    const repofrompath = "--repofrompath=zvmi-azurelinux-base,https://example.invalid/base";
    const makecache = dnfSeedMakecacheArgs(
        "--forcearch=x86_64",
        repofrompath,
        "--setopt=azurelinux-base.gpgkey=file:///key",
        "--setopt=azurelinux-base.baseurl=https://example.invalid/base",
        "--setopt=azurelinux-base.metalink=",
        "--setopt=azurelinux-base.mirrorlist=",
        "--setopt=metadata_expire=never",
        "--setopt=azurelinux-base.metadata_expire=never",
        "--setopt=keepcache=True",
        "--setopt=azurelinux-base.gpgcheck=True",
        "--setopt=cachedir=/private/cache",
        "--setopt=persistdir=/private/persist",
    );
    const install = try dnfInstallArgs(
        std.testing.allocator,
        "/fresh-root",
        "--forcearch=x86_64",
        repofrompath,
        "--setopt=azurelinux-base.gpgkey=file:///key",
        "--setopt=azurelinux-base.baseurl=https://example.invalid/base",
        "--setopt=azurelinux-base.metalink=",
        "--setopt=azurelinux-base.mirrorlist=",
        "--setopt=metadata_expire=never",
        "--setopt=azurelinux-base.metadata_expire=never",
        "--setopt=keepcache=True",
        "--setopt=azurelinux-base.gpgcheck=True",
        "--setopt=cachedir=/private/cache",
        "--setopt=persistdir=/private/persist",
        &.{"systemd"},
    );
    defer std.testing.allocator.free(install);
    for (&[_][]const []const u8{ &makecache, install }) |argv| {
        const repo = argvIndex(argv, repofrompath).?;
        const action = argvIndex(argv, if (std.mem.eql(u8, argv[argv.len - 1], "makecache")) "makecache" else "install").?;
        try std.testing.expect(repo < action);
        try std.testing.expect(!argvContains(argv, "chroot"));
        try std.testing.expect(!argvContains(argv, "/usr/bin/rpm"));
    }
    try std.testing.expectEqual(InitialNevraState.empty_fresh_installroot, initialNevraState(&full));
    try std.testing.expectEqual(InitialNevraState.query_existing_installroot, initialNevraState(&core));
}

test "installed NEVRA closure is deterministically sorted" {
    const gpa = std.testing.allocator;
    const closure = try formatInstalledNevraClosure(
        gpa,
        "bash-0:5.2-1.x86_64\nzlib-0:1.3-1.x86_64\n",
        "zlib-0:1.3-1.x86_64\nsudo-0:1.9-2.x86_64\nopenssh-0:9.9-1.x86_64\nbash-0:5.2-1.x86_64\n",
    );
    defer gpa.free(closure);
    try std.testing.expectEqualStrings(
        "openssh-0:9.9-1.x86_64\nsudo-0:1.9-2.x86_64\n",
        closure,
    );
}

test "architecture and argument parsing accepts only supported values" {
    try std.testing.expectEqual(AzureLinuxArchitecture.x86_64, try parseArchitecture("x86_64"));
    try std.testing.expectEqual(AzureLinuxArchitecture.aarch64, try parseArchitecture("aarch64"));
    try std.testing.expectError(error.UnsupportedArchitecture, parseArchitecture("amd64"));
    try std.testing.expectError(error.UnsupportedArchitecture, parseArchitecture("arm64"));
    try std.testing.expectError(error.MissingArchitecture, requireArchitecture(null));
    try std.testing.expectEqual(Flavor.core, (try parseArgs(&.{})).flavor);
    try std.testing.expect((try parseArgs(&.{})).size == null);
    try std.testing.expectEqualStrings("2G", (try parseArgs(&.{ "--size", "2G" })).size.?);
    try std.testing.expectEqual(Flavor.full, (try parseArgs(&.{ "--flavor", "full" })).flavor);
    try std.testing.expectError(error.UnsupportedFlavor, parseFlavor("minimal"));
    try std.testing.expectEqual(
        AzureLinuxArchitecture.aarch64,
        (try parseArgs(&.{ "--architecture", "aarch64" })).architecture.?,
    );
    try std.testing.expectEqualStrings(
        "zig-out/bin/zvminit",
        (try parseArgs(&.{ "--zvminit", "zig-out/bin/zvminit" })).zvminit_path.?,
    );
    try std.testing.expectEqualStrings(
        "/usr/local/bin/sign-uki",
        (try parseArgs(&.{
            "--uki-signing-certificate",
            "release.crt",
            "--uki-signing-certificate-sha256",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "--uki-sign-command",
            "/usr/local/bin/sign-uki",
            "--uki-sign-command-arg",
            "sign",
        })).uki_sign_command.?,
    );
    try std.testing.expectEqualStrings(
        "sign",
        (try parseArgs(&.{
            "--uki-sign-command-arg",
            "sign",
        })).uki_sign_command_arg.?,
    );
}

test "UKI signer configuration is complete and mutually exclusive" {
    try std.testing.expect((try signingConfig(.{})) == null);
    try std.testing.expectError(
        error.MissingUkiSigningCertificate,
        signingConfig(.{
            .uki_signing_key = "release.key",
        }),
    );
    try std.testing.expectError(
        error.MissingUkiSigningCertificateSha256,
        signingConfig(.{
            .uki_signing_certificate = "release.crt",
            .uki_signing_key = "release.key",
        }),
    );
    try std.testing.expectError(
        error.InvalidUkiSignerSelection,
        signingConfig(.{
            .uki_signing_certificate = "release.crt",
            .uki_signing_certificate_sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
        }),
    );
    try std.testing.expectError(
        error.InvalidUkiSignerSelection,
        signingConfig(.{
            .uki_signing_certificate = "release.crt",
            .uki_signing_certificate_sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
            .uki_signing_key = "release.key",
            .uki_sign_command = "/usr/local/bin/sign-uki",
        }),
    );
    try std.testing.expectError(
        error.UkiSignCommandMustBeAbsolute,
        signingConfig(.{
            .uki_signing_certificate = "release.crt",
            .uki_signing_certificate_sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
            .uki_sign_command = "sign-uki",
        }),
    );
    try std.testing.expectError(
        error.InvalidUkiSignerSelection,
        signingConfig(.{
            .uki_signing_certificate = "release.crt",
            .uki_signing_certificate_sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
            .uki_signing_key = "release.key",
            .uki_sign_command_arg = "sign",
        }),
    );

    const local = (try signingConfig(.{
        .uki_signing_certificate = "release.crt",
        .uki_signing_certificate_sha256 = "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        .uki_signing_key = "release.key",
    })).?;
    try std.testing.expectEqualStrings("local-key", local.mode.name());
    try std.testing.expectEqualStrings("release.key", local.mode.local_key.private_key_path);

    const external = (try signingConfig(.{
        .uki_signing_certificate = "release.crt",
        .uki_signing_certificate_sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
        .uki_sign_command = "/usr/local/bin/sign-uki",
        .uki_sign_command_arg = "sign",
    })).?;
    try std.testing.expectEqualStrings("external-command", external.mode.name());
    try std.testing.expectEqualStrings(
        "sign",
        external.mode.external_command.argument.?,
    );
}

test "guest artifact architecture validation rejects mismatches" {
    try std.testing.expect(guestArtifactMatchesArchitecture(
        "ELF 64-bit LSB executable, x86-64, version 1 (SYSV)",
        &x86_64,
    ));
    try std.testing.expect(guestArtifactMatchesArchitecture(
        "ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV)",
        &aarch64,
    ));
    try std.testing.expect(!guestArtifactMatchesArchitecture(
        "ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV)",
        &x86_64,
    ));
}

test "zvminit rootfs layout requires relative command symlinks" {
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "usr/bin/init", "usr/bin/poweroff", "usr/bin/reboot", "usr/bin/shutdown" },
        &zvminit_symlink_paths,
    );
}

test "generalized Gen2 layout uses the descriptor root role and GUID" {
    const gpa = std.testing.allocator;
    const disk_size = try zvmi.parseSize("1184M");
    const cases = [_]*const ArchitectureDescriptor{ &x86_64, &aarch64 };
    for (cases) |architecture| {
        const planned = try planGeneralizedGen2Layout(gpa, disk_size, architecture, &core);
        defer gpa.free(planned);

        try std.testing.expectEqual(@as(usize, 2), planned.len);
        try std.testing.expectEqual(core.esp_size_bytes, planned[0].length_bytes);
        try std.testing.expectEqual(@as(u64, 670 * 1024 * 1024), planned[1].length_bytes);
        try std.testing.expectEqual(architecture.root_role, planned[1].role);
        try std.testing.expectEqual(architecture.root_type_guid, planned[1].type_guid);

        var actual = [_]zvmi.gpt.PartitionEntry{
            .{
                .partition_type_guid = planned[0].type_guid,
                .first_lba = planned[0].firstLba(),
                .last_lba = planned[0].lastLba(),
            },
            .{
                .partition_type_guid = planned[1].type_guid,
                .first_lba = planned[1].firstLba(),
                .last_lba = planned[1].lastLba(),
            },
        };
        try validatePartitionLayout(&actual, planned);
        actual[1].last_lba -= 1;
        try std.testing.expectError(error.UnexpectedPartitionLayout, validatePartitionLayout(&actual, planned));
    }
    try std.testing.expectEqual(disk_size, @as(u64, 1184 * 1024 * 1024));

    const full_size = try zvmi.parseSize(full.default_size);
    for (cases) |architecture| {
        const planned = try planGeneralizedGen2Layout(gpa, full_size, architecture, &full);
        defer gpa.free(planned);
        try std.testing.expectEqual(full.esp_size_bytes, planned[0].length_bytes);
        try std.testing.expect(rootFreeSpaceIsSufficient(
            planned[1].length_bytes,
            planned[1].length_bytes - full.minimum_root_free_bytes,
            full.minimum_root_free_bytes,
        ));
        try std.testing.expect(!rootFreeSpaceIsSufficient(
            planned[1].length_bytes,
            planned[1].length_bytes,
            full.minimum_root_free_bytes,
        ));
    }
}

test "generalized UKI command lines preserve core and constrain full" {
    const gpa = std.testing.allocator;
    const root_guid = zvmi.guid.parse("11111111-2222-3333-4444-555555555555");
    const x86_cmdline = try expectedUkiCmdline(gpa, root_guid, &x86_64, &core);
    defer gpa.free(x86_cmdline);
    const arm_cmdline = try expectedUkiCmdline(gpa, root_guid, &aarch64, &core);
    defer gpa.free(arm_cmdline);
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 init=/sbin/zvminit zvminit.mode=persistent zvminit.azure=auto console=tty0 console=ttyS0,115200n8",
        x86_cmdline,
    );
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 init=/sbin/zvminit zvminit.mode=persistent zvminit.azure=auto console=tty0 console=ttyAMA0,115200n8",
        arm_cmdline,
    );
    try std.testing.expectEqualStrings("console=ttyS0,115200n8", x86_64.serial_console);
    try std.testing.expectEqualStrings("console=ttyAMA0,115200n8", aarch64.serial_console);
    try std.testing.expect(std.mem.indexOf(u8, x86_cmdline, "zvminit.shell=on") == null);
    try std.testing.expect(std.mem.indexOf(u8, arm_cmdline, "zvminit.shell=on") == null);
    try std.testing.expectEqualStrings("512M", core.esp_size_arg);

    const full_x86_cmdline = try expectedUkiCmdline(gpa, root_guid, &x86_64, &full);
    defer gpa.free(full_x86_cmdline);
    const full_arm_cmdline = try expectedUkiCmdline(gpa, root_guid, &aarch64, &full);
    defer gpa.free(full_arm_cmdline);
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 console=ttyS0,115200n8",
        full_x86_cmdline,
    );
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 console=ttyAMA0,115200n8",
        full_arm_cmdline,
    );
    try std.testing.expect(std.mem.indexOf(u8, full_x86_cmdline, "init=") == null);
    try std.testing.expect(std.mem.indexOf(u8, full_x86_cmdline, "zvminit.") == null);
    try std.testing.expect(std.mem.indexOf(u8, full_arm_cmdline, "zvminit.") == null);
}

test "kernel asset compatibility requires matching ISO and installed releases" {
    try std.testing.expect(isoKernelAssetsMatchInstalledModules(
        "vmlinuz-6.6.87.1-1.azl4.x86_64\n",
        "initramfs-6.6.87.1-1.azl4.x86_64.img\n",
        "6.6.87.1-1.azl4.x86_64\n",
        "6.6.87.1-1.azl4.x86_64",
    ));
    try std.testing.expect(!isoKernelAssetsMatchInstalledModules(
        "vmlinuz-6.6.87.1-1.azl4.x86_64\n",
        "initramfs-6.6.87.1-1.azl4.x86_64.img\n",
        "6.6.88.1-1.azl4.x86_64\n",
        "6.6.87.1-1.azl4.x86_64",
    ));
    try std.testing.expect(!isoKernelAssetsMatchInstalledModules(
        "vmlinuz-6.6.87.1-1.azl4.x86_64\n",
        "initramfs-6.6.88.1-1.azl4.x86_64.img\n",
        "6.6.87.1-1.azl4.x86_64\n",
        "6.6.87.1-1.azl4.x86_64",
    ));
    try std.testing.expect(!isoKernelAssetsMatchInstalledModules(
        "vmlinuz-6.6.87.1-1.azl4.x86_64\n",
        "initramfs-6.6.87.1-1.azl4.x86_64.img\n",
        "6.6.87.1-1.azl4.x86_64\n",
        "6.6.87.1-2.azl4.x86_64",
    ));
}

test "gzipFile streams the complete source" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const source_path = "test-generalized-azurelinux4-gzip-source";
    const output_path = "test-generalized-azurelinux4-gzip-output";
    defer Dir.cwd().deleteFile(io, source_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};

    const payload = try gpa.alloc(u8, 192 * 1024 + 17);
    defer gpa.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @intCast(index % 251);
    try Dir.cwd().writeFile(io, .{ .sub_path = source_path, .data = payload });

    try std.testing.expectEqual(@as(u64, payload.len), try gzipFile(io, source_path, output_path));

    const compressed = try Dir.cwd().readFileAlloc(io, output_path, gpa, .limited(payload.len + 1024));
    defer gpa.free(compressed);
    var compressed_reader = Io.Reader.fixed(compressed);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&compressed_reader, .gzip, &window);
    const actual = try decompressor.reader.allocRemaining(gpa, .limited(payload.len + 1));
    defer gpa.free(actual);
    try std.testing.expectEqualSlices(u8, payload, actual);
}
