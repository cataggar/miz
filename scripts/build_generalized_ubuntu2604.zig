//! Build a generalized Ubuntu 26.04 Gen2 QCOW2 image from Canonical's
//! immutable 20260731 cloud-image publication.
//!
//! The full flavor keeps the official cloud disk as its authoritative
//! filesystem/package input. The core flavor uses the same signed disk only
//! as its pinned GPT/ESP substrate and creates a fresh ubuntu-minimal root
//! through embedded debz. Both flavors pin the detached signature, signer,
//! checksum document, image, manifest, snapshot transactions, exact locks,
//! and provenance. The UKI is assembled and signed on the host so private
//! signing material is never copied into the guest disk.

const std = @import("std");
const miz = @import("miz");
const image_phase_timing = @import("image_phase_timing.zig");
const uki_kernel_payload = @import("ubuntu2604_kernel_payload.zig");
const uki_signing = @import("uki_signing.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const artifact_pipeline = miz.artifact_pipeline;
const offline_root = miz.offline_root;
const package_family = miz.package_family;
const guid = miz.guid;
const ImageFormat = miz.Format;

test {
    std.testing.refAllDecls(image_phase_timing);
}

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
// Both pinned Canonical QCOW2 inputs are exactly 3.5 GiB. Reusing that signed
// GPT/ESP substrate without growing it gives core a 30% smaller virtual disk
// than full while the fresh debz root leaves at least this much writable room.
const core_virtual_size: u64 = 3584 * 1024 * 1024;
const core_minimum_root_free_bytes: u64 = 768 * 1024 * 1024;
const distro_bytes_per_inode: u32 = 16 * 1024;
const minimum_root_free_inodes: u32 = 4096;
// Bare metal carries the NVIDIA BaseOS kernel's modules -- about 183 MB
// installed against core's 3.5 GiB -- and an initramfs built with
// `MODULES=most` rather than a dependency-pruned one, because the machine it
// boots is not the virtual machine core was measured on.
const baremetal_virtual_size: u64 = 5 * 1024 * 1024 * 1024;
const source_max_size: u64 = 2 * 1024 * 1024 * 1024;
const manifest_max_size: u64 = 256 * 1024;
const sums_max_size: u64 = 64 * 1024;
const signature_max_size: u64 = 16 * 1024;
const public_key_max_size: usize = 4 * 1024;
const keyring_max_size: usize = 1024 * 1024;
const exact_lock_max_size: u64 = 16 * 1024 * 1024;

/// The Ubuntu kernel flavors this builder knows how to boot. The suffix is
/// how the finished root is searched for its kernel, so naming the wrong one
/// fails the build rather than shipping a kernel nobody asked for.
const azure_kernel_suffix = "-azure";
const nvidia_bos_kernel_suffix = "-nvidia-bos-64k";

const Architecture = uki_kernel_payload.Architecture;

const PartitionGeometry = struct {
    table_index: u32,
    first_lba: u64,
    last_lba: u64,
};

// Linux partition names are one-based, while miz.gpt.PartitionEntry.table_index
// is the zero-based on-disk array slot: /dev/sda13 is table index 12 and
// /dev/sda15 is table index 14.
const arm64_source_xbootldr = PartitionGeometry{
    .table_index = 12,
    .first_lba = 206_848,
    .last_lba = 2_097_152,
};
const arm64_source_esp = PartitionGeometry{
    .table_index = 14,
    .first_lba = 2_048,
    .last_lba = 204_800,
};
const arm64_final_esp = PartitionGeometry{
    .table_index = 14,
    .first_lba = 2_048,
    .last_lba = 1_050_623,
};
const arm64_root_first_lba: u64 = 2_099_200;
const arm64_source_xbootldr_unique_guid =
    guid.parse("f497ce52-b19b-4373-86a0-889acfa3b014");
const arm64_source_xbootldr_filesystem_uuid = [_]u8{
    0x3b, 0xcc, 0x3c, 0xc1, 0x48, 0x52, 0x4c, 0x15,
    0xb4, 0x6d, 0xa6, 0xf3, 0x1d, 0xe7, 0xc1, 0x80,
};

const Flavor = enum {
    full,
    core,
    /// `core` aimed at a physical machine instead of an Azure VM: the NVIDIA
    /// BaseOS kernel, an initramfs that carries the drivers this hardware
    /// actually needs, and an administrator key baked in, because bare metal
    /// has no OVF media to receive one from at boot.
    baremetal,

    fn parse(value: []const u8) ?Flavor {
        if (std.mem.eql(u8, value, "full")) return .full;
        if (std.mem.eql(u8, value, "core")) return .core;
        if (std.mem.eql(u8, value, "baremetal")) return .baremetal;
        return null;
    }

    fn defaultSize(self: Flavor) u64 {
        return switch (self) {
            .full => default_virtual_size,
            .core => core_virtual_size,
            .baremetal => baremetal_virtual_size,
        };
    }

    /// Whether the root is built from scratch with debz rather than inherited
    /// from Canonical's cloud root. This, not the flavor name, is what the
    /// build's structure actually turns on.
    fn freshRoot(self: Flavor) bool {
        return self != .full;
    }

    /// Whether the image expects to find Azure underneath it. Bare metal has
    /// no IMDS, no OVF media, and no provisioning agent to wait for.
    fn azure(self: Flavor) bool {
        return self != .baremetal;
    }

    /// The Ubuntu kernel flavor this image boots. The builder refuses any
    /// other kernel, so this is also the assertion that the right one was
    /// installed.
    fn kernelSuffix(self: Flavor) []const u8 {
        return switch (self) {
            .full, .core => azure_kernel_suffix,
            .baremetal => nvidia_bos_kernel_suffix,
        };
    }

    fn debzPackages(self: Flavor) []const []const u8 {
        return switch (self) {
            .full => &full_debz_packages,
            .core => &core_debz_packages,
            .baremetal => &baremetal_debz_packages,
        };
    }
};

fn validateRootHeadroom(flavor: Flavor, free_bytes: u64, free_inodes: u32) !void {
    if (flavor.freshRoot() and free_bytes < core_minimum_root_free_bytes)
        return error.CoreRootFreeSpaceTooSmall;
    if (free_inodes < minimum_root_free_inodes) return error.RootFreeInodesTooSmall;
}

fn validateFinalQcow2(io: Io, path: []const u8, expected_size: u64) !void {
    var image = try miz.Image.openPathReadOnlyStandalone(io, path);
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
    // Emit the standalone zstd-compressed release artifact natively. miz
    // reads the mutable qcow2's guest bytes and re-encodes them into
    // compressed qcow2 v3 clusters, so the Ubuntu release path no longer
    // shells out to qemu-img/qemu-utils.
    const staged_output = try std.fmt.allocPrint(
        allocator,
        "{s}.miz-finalize-stage",
        .{output},
    );
    defer allocator.free(staged_output);
    Dir.cwd().deleteFile(io, staged_output) catch {};
    errdefer Dir.cwd().deleteFile(io, staged_output) catch {};

    var source = try miz.Image.openPathReadOnlyStandalone(io, mutable);
    defer source.close(io);
    if (source.format != .qcow2) return error.InvalidFinalQcow2;
    const expected_size = source.virtual_size;
    const source_ctx = miz.qcow2.Qcow2SourceContext{
        .file = source.file,
        .info = &source.qcow2.?,
    };

    const staged_file = try Dir.cwd().createFile(io, staged_output, .{ .read = true, .truncate = true });
    {
        errdefer staged_file.close(io);
        _ = try miz.qcow2.writeStandaloneCompressed(
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
    uki_stub_host_path: []const u8,
    serial_console: []const u8,
    pe_machine: u16,
    root_partition_table_index: u32,
    root_partition_type_guid: guid.Guid,

    fn outputFor(self: *const Profile, flavor: Flavor) []const u8 {
        return switch (flavor) {
            .full => self.output,
            .core => switch (self.architecture) {
                .x86_64 => "Ubuntu-26.04-x86_64.core.qcow2",
                .aarch64 => "Ubuntu-26.04-aarch64.core.qcow2",
            },
            .baremetal => switch (self.architecture) {
                .x86_64 => "Ubuntu-26.04-x86_64.baremetal.qcow2",
                .aarch64 => "Ubuntu-26.04-aarch64.baremetal.qcow2",
            },
        };
    }

    fn workDirFor(self: *const Profile, flavor: Flavor) []const u8 {
        return switch (flavor) {
            .full => self.work_dir,
            .core => switch (self.architecture) {
                .x86_64 => ".scratch/ubuntu2604-x86_64-core",
                .aarch64 => ".scratch/ubuntu2604-aarch64-core",
            },
            .baremetal => switch (self.architecture) {
                .x86_64 => ".scratch/ubuntu2604-x86_64-baremetal",
                .aarch64 => ".scratch/ubuntu2604-aarch64-baremetal",
            },
        };
    }
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
        .uki_stub_host_path = "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
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
        .uki_stub_host_path = "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub",
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

const full_debz_packages = [_][]const u8{ "linux-azure", "walinuxagent" };
const core_debz_packages = [_][]const u8{
    "ubuntu-minimal",
    "linux-azure",
    // The versioned Azure kernel only recommends `dracut |
    // linux-initramfs-tool`; recommends are outside the exact debz closure.
    // Name the generator that customization executes instead of assuming the
    // kernel transaction supplied `/usr/sbin/update-initramfs`.
    "initramfs-tools",
    "openssh-server",
    "sudo",
    // No required dependency above supplies the TLS trust store. Keep it a
    // package root so the finished image's HTTPS clients are usable.
    "ca-certificates",
};

// The official in-tree module name Ubuntu packages Android Binder support
// as. `linux-azure` pulls it in transitively through
// `linux-modules-extra-*-azure`, so no additional debz package root is
// needed -- only validating that the module, its kernel config, and its
// signature are what core actually ships.
const android_binder_module_name = "binder_linux";

// The `linux-azure` kernel config lines core's signed Binder support depends
// on. `CONFIG_ANDROID_BINDER_IPC`/`CONFIG_ANDROID_BINDERFS` must be built as
// modules (not builtin, not absent) so `binder_linux` ships as the loadable,
// signed module mizinit loads; `CONFIG_ANDROID_BINDER_DEVICES=""` keeps the
// kernel from creating any binder device itself, since device creation is
// mizinit's job through binderfs, not a kernel command-line default; and
// `CONFIG_MODULE_DECOMPRESS=y` is what lets mizinit ask the kernel to
// decompress and verify the packaged `.ko.zst` through `finit_module()`
// without ever touching the signed bytes itself.
const core_required_kernel_config = [_][]const u8{
    "CONFIG_ANDROID_BINDER_IPC=m",
    "CONFIG_ANDROID_BINDERFS=m",
    "CONFIG_ANDROID_BINDER_DEVICES=\"\"",
    "CONFIG_MODULE_DECOMPRESS=y",
};

// There is no `linux-nvidia-bos` meta package in the pinned snapshot -- the
// only ones published are for builds that postdate it -- so the versioned
// binary package is named directly. That name *is* the kernel release, which
// is why no separate version pin is needed.
const baremetal_kernel_release = "7.0.0-2015" ++ nvidia_bos_kernel_suffix;
const baremetal_image_package = "linux-image-" ++ baremetal_kernel_release;
const baremetal_modules_package = "linux-modules-" ++ baremetal_kernel_release;
const baremetal_debz_packages = [_][]const u8{
    "ubuntu-minimal",
    baremetal_image_package,
    baremetal_modules_package,
    // The generator this flavor configures and then runs. Kernel packages only
    // recommend an initramfs implementation, so every fresh-root flavor names
    // the implementation it executes.
    "initramfs-tools",
    "openssh-server",
    "sudo",
    // The trust store is explicit for every fresh root: none of their required
    // package dependencies supplies it.
    "ca-certificates",
};
const max_debz_packages = baremetal_debz_packages.len;

const core_required_packages = [_][]const u8{
    "ubuntu-minimal",
    "linux-azure",
    "initramfs-tools",
    "openssh-server",
    "openssh-client",
    "sudo",
    "ca-certificates",
};

const baremetal_required_packages = [_][]const u8{
    "ubuntu-minimal",
    baremetal_image_package,
    baremetal_modules_package,
    "initramfs-tools",
    "openssh-server",
    "openssh-client",
    "sudo",
    "ca-certificates",
};

const core_forbidden_packages = [_][]const u8{
    "cloud-init",
    "walinuxagent",
    "ubuntu-server",
    "ubuntu-server-minimal",
    // Out-of-tree Binder implementations: core's Binder workload must run
    // only the official in-tree, signed module resolved above, never a
    // DKMS-built shadow copy layered on top of it.
    "anbox-modules-dkms",
    "anbox-modules",
};

// Bare metal forbids everything core does, and `linux-azure` besides: pulling
// it in would leave two kernels in `/boot` and make the release the UKI is
// built from ambiguous.
const baremetal_forbidden_packages = [_][]const u8{
    "cloud-init",
    "walinuxagent",
    "ubuntu-server",
    "ubuntu-server-minimal",
    "anbox-modules-dkms",
    "anbox-modules",
    "linux-azure",
};

const core_required_paths = [_][]const u8{
    "/usr/sbin/mizinit",
    "/usr/sbin/azagent",
    "/usr/sbin/sshd",
    "/usr/bin/ssh-keygen",
    "/etc/ssh/sshd_config.d/10-mizinit.conf",
    "/etc/waagent.conf",
    "/var/lib/miz/ubuntu2604-package-lock.tsv",
    "/var/lib/miz/ubuntu2604-core-provenance.json",
    "/var/lib/miz/source-release",
};

const core_forbidden_paths = [_][]const u8{
    "/usr/bin/cloud-init",
    "/usr/sbin/waagent",
    "/usr/bin/waagent",
    "/var/lib/cloud",
    "/var/lib/waagent",
    "/var/lib/azagent/provisioned",
    "/var/lib/dbus/machine-id",
    "/etc/systemd/system/multi-user.target.wants/ssh.service",
    "/etc/systemd/system/ssh.service",
    "/etc/systemd/system/sockets.target.wants/ssh.socket",
};

const full_service_policy = [_]miz.os_customization.Service{
    .{ .name = "systemd-networkd.service", .state = .enabled },
    .{ .name = "systemd-resolved.service", .state = .enabled },
    .{ .name = "ssh.service", .state = .enabled },
    .{ .name = "walinuxagent.service", .state = .enabled },
    // Firmware boots the signed UKI directly, so this GRUB state mutator has
    // no bootloader state to maintain and can race grub2-common on reboot.
    .{ .name = "grub-initrd-fallback.service", .state = .disabled },
};

const core_ssh_config =
    "PasswordAuthentication no\n" ++
    "KbdInteractiveAuthentication no\n" ++
    "PermitEmptyPasswords no\n" ++
    "PermitRootLogin prohibit-password\n" ++
    "PubkeyAuthentication yes\n";

const core_azagent_config =
    "ResourceDisk.Format=y\n" ++
    "ResourceDisk.Filesystem=xfs\n" ++
    "ResourceDisk.MountPoint=/d\n" ++
    "ResourceDisk.EnableSwap=n\n" ++
    "DataDisk.Mount=y\n";

// Requests `binder_linux` explicitly rather than relying on `MODULES=most`'s
// heuristics: an Android-container Binder workload needs it in the initramfs
// module set `update-initramfs` builds, and this is checked below by both
// `validateCoreKernelModules` (against the tree's `modules.dep`) and
// `requireInitramfsModules` (against the generated initramfs itself, once it
// exists).
const core_initramfs_modules = android_binder_module_name ++ "\n";

// An Azure VM's root is virtio or SCSI and its NIC is netvsc, so a
// dependency-pruned initramfs built in that context carries neither the NVMe
// driver this machine's root lives behind nor the USB-attached Realtek NIC it
// is reached through. `MODULES=most` is the safe default; the explicit list
// below then states the four that must be there regardless of what `most`
// decides, so a change in that heuristic cannot silently strand the machine.
const baremetal_initramfs_conf =
    "MODULES=most\n" ++
    "BUSYBOX=auto\n" ++
    "COMPRESS=zstd\n" ++
    "DEVICE=\n" ++
    "NFS=no\n" ++
    "RUNSIZE=10%\n";

// `r8152` is the Realtek RTL8153 the management NIC actually is -- it is USB
// attached, not PCI, so the USB host controller and the usbnet layer have to
// come with it.
const baremetal_initramfs_modules =
    "nvme\n" ++
    "nvme_core\n" ++
    "xhci_hcd\n" ++
    "xhci_pci\n" ++
    "usbnet\n" ++
    "mii\n" ++
    "r8152\n";

/// The one account a bare-metal image ships with.
const baremetal_admin_user = "g";

/// mizinit's documented replacement for its default access provider.
const baremetal_access_provider_path = "/usr/local/sbin/mizinit-access";

// mizinit starts sshd only once provisioning has written its sentinel,
// because on Azure provisioning is what installs the administrator's key: an
// sshd started earlier listens on an image nobody can authenticate to. Bare
// metal inverts that -- the key is baked in at build time, so the wait is for
// something that already happened, and azagent, which would otherwise both
// write the sentinel and generate the host keys, never runs.
//
// This is the extension point mizinit documents for exactly that case: a
// provider that brings its own credential path and is started without waiting.
// The root is expanded before access starts, using azagent's resize-only mode
// so no Azure provisioning or disk setup is attempted. Resize is best-effort
// at this boundary, but `set -e` still protects every other provider step.
// Host keys are still not baked, because they must differ per machine, so they
// are generated here on first boot. `/run/sshd` is created here too: mizinit
// creates it only on the path this replaces.
const baremetal_access_provider =
    "#!/bin/sh\n" ++
    "set -e\n" ++
    "if ! /usr/sbin/azagent --resize-root-only; then\n" ++
    "    echo \"mizinit-access: warning: root resize failed; continuing boot\" >&2\n" ++
    "fi\n" ++
    "[ -f /etc/ssh/ssh_host_ed25519_key ] || /usr/bin/ssh-keygen -A\n" ++
    "mkdir -p /run/sshd\n" ++
    "exec /usr/sbin/sshd -D -e\n";

const Args = struct {
    architecture: ?Architecture = null,
    flavor: Flavor = .full,
    source: ?[]const u8 = null,
    output: ?[]const u8 = null,
    work_dir: ?[]const u8 = null,
    provenance_dir: ?[]const u8 = null,
    size: u64 = default_virtual_size,
    size_explicit: bool = false,
    mizinit: ?[]const u8 = null,
    azagent: ?[]const u8 = null,
    signing_certificate: ?[]const u8 = null,
    signing_certificate_sha256: ?[]const u8 = null,
    signing_key: ?[]const u8 = null,
    signing_command: ?[]const u8 = null,
    signing_command_arg: ?[]const u8 = null,
    uki_stub: ?[]const u8 = null,
    proxy: ?[]const u8 = null,
    authorized_key: ?[]const u8 = null,
    raw_output: ?[]const u8 = null,
    timing_output: ?[]const u8 = null,
    debz_cache: ?[]const u8 = null,
    debz_input_dir: ?[]const u8 = null,
    debz_lock_dir: ?[]const u8 = null,
    offline: bool = false,
    preflight_only: bool = false,
};

const help =
    \\Usage: zig build generalized-ubuntu2604 -Dubuntu2604-arch=<x86_64|aarch64> -Dubuntu2604-flavor=<full|core|baremetal> -- [options]
    \\  --flavor <full|core|baremetal>          image flavor (default full)
    \\  --source <path>                         verified local Canonical .img
    \\  --output <path>                         output QCOW2
    \\  --work-dir <path>                       persistent download/work cache
    \\  --provenance-dir <path>                 release provenance sidecars
    \\  --size <size>                           virtual size (full 5G, core 3584M, baremetal 5G)
    \\  --mizinit <path>                       static guest PID 1 (core, baremetal)
    \\  --azagent <path>                        static guest provisioning agent (core, baremetal)
    \\  --authorized-key <path>                 administrator public key (baremetal only)
    \\  --raw-output <path>                     additional raw copy, for writing to a disk
    \\  --timing-output <path>                  write opt-in machine-readable phase timing JSON
    \\  --debz-cache <path>                     shared content-addressed debz cache
    \\  --debz-input-dir <path>                 stable repository documents/keyring directory
    \\  --debz-lock-dir <path>                  fixed exact-lock inputs, one per package root
    \\  --offline                               require local pinned inputs and cache-only debz
    \\  --proxy <url>                           reach the archive through this HTTP proxy
    \\  --uki-signing-certificate <path>        Secure Boot certificate
    \\  --uki-signing-certificate-sha256 <hex>  DER certificate SHA-256
    \\  --uki-signing-key <path>                local signing key
    \\  --uki-sign-command <absolute-path>       external production signer
    \\  --uki-sign-command-arg <argument>        external signer argument
    \\  --uki-stub <path>                        systemd-boot EFI stub (default: host systemd-boot-efi)
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
    packages: []const []const u8,
    root_stage: []const u8,
    published_root: []const u8,
    config_paths: []const []const u8,
    keyring_paths: []const []const u8,
    cache_path: []const u8,
    state_path: []const u8,
    lock_path: []const u8,
    installed_baseline: package_family.InstalledBaselinePolicy,
    proxy: ?[]const u8,
    offline: bool,
) package_family.Request {
    return .{
        .family = .debian,
        .distribution = .ubuntu_26_04,
        .operation = operation,
        .packages = packages,
        .inputs = .{
            .root_stage = root_stage,
            .published_root = published_root,
            .architecture = switch (profile.architecture) {
                .x86_64 => .amd64,
                .aarch64 => .arm64,
            },
            .source_paths = &.{},
            .keyring_paths = keyring_paths,
            .config_paths = config_paths,
            .cache_path = cache_path,
            .state_path = state_path,
            .lock_input_path = if (operation == .resolve_lock) null else lock_path,
            .lock_output_path = if (operation == .resolve_lock) lock_path else null,
            .proxy = proxy,
            .cache_mode = if (offline) .offline else .online,
            .repository_policy = .strict_priority,
            .recommends = false,
            .allow_downgrade = false,
            .conffile = .keep_existing,
            .installed_baseline = installed_baseline,
        },
    };
}

/// Assert a package-family request keeps every source, config, keyring, cache,
/// state, and lock path outside both `root_stage` and `published_root` before
/// it is dispatched. The policy lives in `package_family`, so resolve and
/// customize requests are validated with the boundary's own rules instead of a
/// duplicated copy here.
fn assertRequestSeparation(request: package_family.Request) !void {
    if (package_family.requestViolation(request)) |message| {
        std.debug.print("package-family separation violation: {s}\n", .{message});
        return error.PackageFamilySeparationViolation;
    }
}

fn privateCacheDirPermissions() std.Io.File.Permissions {
    return if (@import("builtin").os.tag == .windows) .default_dir else .fromMode(0o700);
}

fn privateCacheFilePermissions() std.Io.File.Permissions {
    return if (@import("builtin").os.tag == .windows) .default_file else .fromMode(0o600);
}

/// Remove only abandoned debz staging files from a persistent shared cache.
/// Each namespace's writer lock prevents cleanup from racing another build;
/// verified objects and metadata manifests are deliberately left untouched.
fn cleanupSharedDebzCacheStaging(io: Io, cache_path: []const u8) !void {
    var cache = try Dir.cwd().openDir(io, cache_path, .{ .follow_symlinks = false });
    defer cache.close(io);

    for (&[_][]const u8{ "metadata-v1", "packages-v1" }) |namespace_name| {
        var namespace = cache.openDir(io, namespace_name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer namespace.close(io);

        namespace.createDir(io, "locks", privateCacheDirPermissions()) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        var locks = try namespace.openDir(io, "locks", .{ .follow_symlinks = false });
        defer locks.close(io);
        const writer_lock = try locks.createFile(io, "writer.lock", .{
            .read = true,
            .truncate = false,
            .lock = .exclusive,
            .lock_nonblocking = true,
            .permissions = privateCacheFilePermissions(),
        });
        defer writer_lock.close(io);

        try namespace.deleteTree(io, "staging");
        try namespace.createDir(io, "staging", privateCacheDirPermissions());
    }
}

const TrustedKeyring = struct {
    /// Absolute host path of the validated keyring copy.
    path: [:0]u8,
    /// SHA-256 of the trusted bytes, used to prove the copy never changes.
    sha256: [32]u8,

    fn deinit(self: *TrustedKeyring, allocator: Allocator) void {
        allocator.free(self.path);
    }
};

/// Copy the guest Ubuntu archive keyring to a bounded, read-only host file
/// outside every debz `root_stage` and `published_root`, then validate the copy
/// so debz `keyring_paths` and the generated `Signed-By` configuration consume
/// exactly those trusted bytes. The guest source is read as a bounded regular
/// file without following symlinks, and the materialized copy is re-stat'd and
/// re-hashed so later guest mutation cannot redirect or alter the trusted path.
fn materializeTrustedKeyring(
    allocator: Allocator,
    io: Io,
    guest_keyring: []const u8,
    destination: []const u8,
) !TrustedKeyring {
    const source_stat = try Dir.cwd().statFile(io, guest_keyring, .{ .follow_symlinks = false });
    if (source_stat.kind != .file) return error.TrustedKeyringNotRegularFile;
    if (source_stat.size == 0) return error.TrustedKeyringEmpty;
    if (source_stat.size > keyring_max_size) return error.TrustedKeyringTooLarge;

    var source_file = try Dir.cwd().openFile(io, guest_keyring, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer source_file.close(io);
    var source_reader = source_file.reader(io, &.{});
    const bytes = try source_reader.interface.allocRemaining(allocator, .limited(keyring_max_size));
    defer allocator.free(bytes);
    if (bytes.len == 0) return error.TrustedKeyringEmpty;
    const expected = artifact_pipeline.sha256Bytes(bytes);

    Dir.cwd().deleteFile(io, destination) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = destination,
        .data = bytes,
        .flags = .{ .exclusive = true },
    });
    try Dir.cwd().setFilePermissions(
        io,
        destination,
        std.Io.File.Permissions.fromMode(0o400),
        .{},
    );

    const copy_stat = try Dir.cwd().statFile(io, destination, .{ .follow_symlinks = false });
    if (copy_stat.kind != .file) return error.TrustedKeyringNotRegularFile;
    if (copy_stat.nlink != 1) return error.TrustedKeyringAmbiguousLink;
    if (copy_stat.size != source_stat.size) return error.TrustedKeyringSizeMismatch;
    const materialized = try artifact_pipeline.hashFile(io, destination);
    if (!std.mem.eql(u8, &materialized.sha256, &expected))
        return error.TrustedKeyringDigestMismatch;

    const absolute_path = try Dir.cwd().realPathFileAlloc(io, destination, allocator);
    errdefer allocator.free(absolute_path);
    return .{ .path = absolute_path, .sha256 = expected };
}

/// Re-hash the materialized keyring and confirm it still matches the digest
/// captured at copy time. Proves that no debz resolve/customize transaction
/// mutated the trusted host copy.
fn assertTrustedKeyringUnchanged(io: Io, keyring: TrustedKeyring) !void {
    const stat = try Dir.cwd().statFile(io, keyring.path, .{ .follow_symlinks = false });
    if (stat.kind != .file) return error.TrustedKeyringNotRegularFile;
    if (stat.nlink != 1) return error.TrustedKeyringAmbiguousLink;
    const current = try artifact_pipeline.hashFile(io, keyring.path);
    if (!std.mem.eql(u8, &current.sha256, &keyring.sha256))
        return error.TrustedKeyringDigestMismatch;
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
        } else if (std.mem.eql(u8, arg, "--flavor")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.flavor = Flavor.parse(argv[i]) orelse return error.InvalidFlavor;
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
            args.size = try miz.parseSize(argv[i]);
            args.size_explicit = true;
        } else if (std.mem.eql(u8, arg, "--mizinit")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.mizinit = argv[i];
        } else if (std.mem.eql(u8, arg, "--azagent")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.azagent = argv[i];
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
        } else if (std.mem.eql(u8, arg, "--uki-stub")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.uki_stub = argv[i];
        } else if (std.mem.eql(u8, arg, "--proxy")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            // Validated here rather than at first use, so a malformed proxy
            // fails before the build downloads anything.
            _ = try artifact_pipeline.parseProxy(argv[i]);
            args.proxy = argv[i];
        } else if (std.mem.eql(u8, arg, "--authorized-key")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.authorized_key = argv[i];
        } else if (std.mem.eql(u8, arg, "--raw-output")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.raw_output = argv[i];
        } else if (std.mem.eql(u8, arg, "--timing-output")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.timing_output = argv[i];
        } else if (std.mem.eql(u8, arg, "--debz-cache")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.debz_cache = argv[i];
        } else if (std.mem.eql(u8, arg, "--debz-input-dir")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.debz_input_dir = argv[i];
        } else if (std.mem.eql(u8, arg, "--debz-lock-dir")) {
            i += 1;
            if (i == argv.len) return error.MissingArgument;
            args.debz_lock_dir = argv[i];
        } else if (std.mem.eql(u8, arg, "--offline")) {
            args.offline = true;
        } else if (std.mem.eql(u8, arg, "--preflight-only")) {
            args.preflight_only = true;
        } else if (std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{help});
            std.process.exit(0);
        } else return error.UnknownArgument;
    }

    if (!args.size_explicit) args.size = args.flavor.defaultSize();
    if (args.size < args.flavor.defaultSize()) return error.ImageTooSmall;
    // The key is the only way into a bare-metal image, so a missing one is a
    // build that produces an unreachable machine. It is equally an error to
    // offer a key to a flavor that would refuse to bake it: silently ignoring
    // it would leave the caller believing an image is reachable when it is not.
    if (args.flavor == .baremetal and args.authorized_key == null)
        return error.AuthorizedKeyRequired;
    if (args.flavor != .baremetal and args.authorized_key != null)
        return error.AuthorizedKeyNotSupported;
    if (args.offline and args.source == null)
        return error.OfflineSourceRequired;
    if (args.offline and args.proxy != null)
        return error.OfflineProxyNotSupported;
    return args;
}

/// Reads and sanity-checks an OpenSSH public key given on the command line.
///
/// The check is deliberately shallow -- one line, a known key type, no
/// terminator hiding a second entry -- because its purpose is to catch the
/// path being wrong (a private key, a whole `known_hosts`, an empty file), not
/// to re-verify the key material.
fn readAuthorizedKey(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    const bytes = Dir.cwd().readFileAlloc(io, path, allocator, .limited(16 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return error.AuthorizedKeyMissing,
        else => return err,
    };
    defer allocator.free(bytes);
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidAuthorizedKey;
    if (std.mem.indexOfAny(u8, trimmed, "\r\n") != null) return error.InvalidAuthorizedKey;
    const accepted = [_][]const u8{ "ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-nistp", "sk-ssh-ed25519@", "sk-ecdsa-sha2-nistp" };
    for (&accepted) |prefix| {
        if (std.mem.startsWith(u8, trimmed, prefix)) return allocator.dupe(u8, trimmed);
    }
    return error.InvalidAuthorizedKey;
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

fn readUkiStub(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    return Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(miz.uki.limits.max_stub_size),
    ) catch |err| switch (err) {
        error.FileNotFound => return error.UkiStubMissing,
        else => return err,
    };
}

fn acquire(
    allocator: Allocator,
    io: Io,
    url: []const u8,
    path: []const u8,
    sha256: []const u8,
    max_size: u64,
    downloader: artifact_pipeline.Downloader,
    offline: bool,
) !void {
    if (offline) {
        const stat = Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| return switch (err) {
            error.FileNotFound => error.OfflineInputMissing,
            else => err,
        };
        if (stat.kind != .file) return error.OfflineInputNotRegularFile;
        if (stat.size == 0 or stat.size > max_size) return error.OfflineInputSizeInvalid;
        const metadata = try artifact_pipeline.hashFile(io, path);
        const expected = try artifact_pipeline.parseSha256(sha256);
        if (!std.mem.eql(u8, &metadata.sha256, &expected))
            return error.ChecksumMismatch;
        return;
    }
    _ = try artifact_pipeline.acquireVerified(allocator, io, .{
        .url = url,
        .destination_path = path,
        .expected_sha256 = try artifact_pipeline.parseSha256(sha256),
        .max_size = max_size,
    }, downloader);
}

fn copyExactLockInput(
    allocator: Allocator,
    io: Io,
    source: []const u8,
    destination: []const u8,
) !void {
    const stat = Dir.cwd().statFile(io, source, .{ .follow_symlinks = false }) catch |err| return switch (err) {
        error.FileNotFound => error.DebzExactLockMissing,
        else => err,
    };
    if (stat.kind != .file) return error.DebzExactLockNotRegularFile;
    if (stat.size == 0 or stat.size > exact_lock_max_size)
        return error.DebzExactLockSizeInvalid;
    var file = try Dir.cwd().openFile(io, source, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    const bytes = try reader.interface.allocRemaining(
        allocator,
        .limited(exact_lock_max_size),
    );
    defer allocator.free(bytes);
    try Dir.cwd().writeFile(io, .{ .sub_path = destination, .data = bytes });
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

const peMachine = uki_kernel_payload.peMachine;

fn requiredPackages(flavor: Flavor) []const []const u8 {
    return switch (flavor) {
        .full => &.{ "linux-azure", "walinuxagent", "cloud-init", "openssh-server" },
        .core => &core_required_packages,
        .baremetal => &baremetal_required_packages,
    };
}

/// Packages whose presence in the finished closure is a build failure. `full`
/// inherits Canonical's cloud root and has no such list.
fn forbiddenPackages(flavor: Flavor) []const []const u8 {
    return switch (flavor) {
        .full => &.{},
        .core => &core_forbidden_packages,
        .baremetal => &baremetal_forbidden_packages,
    };
}

fn validateExactLock(bytes: []const u8, profile: *const Profile, flavor: Flavor) !void {
    for (requiredPackages(flavor)) |package| {
        const needle = try std.fmt.allocPrint(std.testing.allocator, "{s}\t", .{package});
        defer std.testing.allocator.free(needle);
        if (std.mem.indexOf(u8, bytes, needle) == null) return error.ExactLockIncomplete;
    }
    const expected_arch = try std.fmt.allocPrint(std.testing.allocator, "\t{s}\n", .{profile.ubuntu_architecture});
    defer std.testing.allocator.free(expected_arch);
    if (std.mem.indexOf(u8, bytes, expected_arch) == null) return error.ExactLockArchitectureMissing;
    const foreign_arch = switch (profile.architecture) {
        .x86_64 => "\tarm64\n",
        .aarch64 => "\tamd64\n",
    };
    if (std.mem.indexOf(u8, bytes, foreign_arch) != null) return error.ForeignArchitecturePackage;
    for (forbiddenPackages(flavor)) |package| {
        const needle = try std.fmt.allocPrint(std.testing.allocator, "{s}\t", .{package});
        defer std.testing.allocator.free(needle);
        if (std.mem.indexOf(u8, bytes, needle) != null) return error.ForbiddenCorePackage;
    }
}

fn validateExactLockRuntime(
    allocator: Allocator,
    bytes: []const u8,
    profile: *const Profile,
    flavor: Flavor,
) !void {
    for (requiredPackages(flavor)) |package| {
        const needle = try std.fmt.allocPrint(allocator, "{s}\t", .{package});
        defer allocator.free(needle);
        if (std.mem.indexOf(u8, bytes, needle) == null) return error.ExactLockIncomplete;
    }
    const expected_arch = try std.fmt.allocPrint(allocator, "\t{s}\n", .{profile.ubuntu_architecture});
    defer allocator.free(expected_arch);
    if (std.mem.indexOf(u8, bytes, expected_arch) == null) return error.ExactLockArchitectureMissing;
    const foreign_arch = switch (profile.architecture) {
        .x86_64 => "\tarm64\n",
        .aarch64 => "\tamd64\n",
    };
    if (std.mem.indexOf(u8, bytes, foreign_arch) != null) return error.ForeignArchitecturePackage;
    for (forbiddenPackages(flavor)) |package| {
        const needle = try std.fmt.allocPrint(allocator, "{s}\t", .{package});
        defer allocator.free(needle);
        if (std.mem.indexOf(u8, bytes, needle) != null) return error.ForbiddenCorePackage;
    }
}

fn validateInventoryAgainstExactLock(
    allocator: Allocator,
    inventory: []const u8,
    exact_lock: []const u8,
    profile: *const Profile,
) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, exact_lock, .{});
    defer parsed.deinit();
    const target = parsed.value.object.get("target_architecture") orelse
        return error.ExactLockIncomplete;
    if (target != .string or !std.mem.eql(u8, target.string, profile.ubuntu_architecture))
        return error.ExactLockArchitectureMissing;
    const package_value = parsed.value.object.get("packages") orelse
        return error.ExactLockIncomplete;
    if (package_value != .array) return error.ExactLockIncomplete;

    var inventory_count: usize = 0;
    var lines = std.mem.splitScalar(u8, inventory, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const name = fields.next() orelse return error.InvalidPackageInventory;
        const version = fields.next() orelse return error.InvalidPackageInventory;
        const architecture = fields.next() orelse return error.InvalidPackageInventory;
        if (fields.next() != null) return error.InvalidPackageInventory;
        const normalized_name = if (std.mem.lastIndexOfScalar(u8, name, ':')) |separator|
            if (std.mem.eql(u8, name[separator + 1 ..], architecture))
                name[0..separator]
            else
                name
        else
            name;
        var found = false;
        for (package_value.array.items) |item| {
            if (item != .object) return error.ExactLockIncomplete;
            const locked_name = item.object.get("name") orelse return error.ExactLockIncomplete;
            const locked_version = item.object.get("version") orelse return error.ExactLockIncomplete;
            const locked_architecture = item.object.get("architecture") orelse return error.ExactLockIncomplete;
            if (locked_name != .string or locked_version != .string or locked_architecture != .string)
                return error.ExactLockIncomplete;
            if (std.mem.eql(u8, normalized_name, locked_name.string) and
                std.mem.eql(u8, version, locked_version.string) and
                std.mem.eql(u8, architecture, locked_architecture.string))
            {
                found = true;
                break;
            }
        }
        if (!found) return error.UnexpectedCorePackage;
        inventory_count += 1;
    }
    if (inventory_count != package_value.array.items.len) return error.UnexpectedCorePackage;
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
    evidence: [max_debz_packages]DebzEvidence,
    evidence_count: usize,
    root_free_bytes: u64,

    fn deinit(self: *DebzCustomization, allocator: Allocator) void {
        allocator.free(self.root_path);
        for (self.evidence[0..self.evidence_count]) |*item| item.deinit(allocator);
        self.* = undefined;
    }
};

const NativeQcow2Publisher = struct {
    context: ?*anyopaque = null,
    publish: *const fn (
        allocator: Allocator,
        io: Io,
        raw_path: []const u8,
        destination_path: []const u8,
        context: ?*anyopaque,
    ) anyerror!void,
};

fn optionalBytes(buffer: []u8, value: ?u64) []const u8 {
    const bytes = value orelse return "unknown";
    return std.fmt.bufPrint(buffer, "{d}", .{bytes}) catch "unknown";
}

fn optionalUsage(buffer: []u8, path: ?[]const u8) []const u8 {
    const usage = miz.free_space.fileUsage(path orelse return "unknown") orelse return "unknown";
    return std.fmt.bufPrint(
        buffer,
        "{d}/{d}",
        .{ usage.logical_bytes, usage.allocated_bytes },
    ) catch "unknown";
}

fn logNativeCapacity(
    phase: []const u8,
    workspace_path: []const u8,
    raw_path: []const u8,
    artifact_path: ?[]const u8,
) void {
    const probe_path = std.fs.path.dirname(workspace_path) orelse ".";
    var available_buffer: [32]u8 = undefined;
    var raw_buffer: [64]u8 = undefined;
    var artifact_buffer: [64]u8 = undefined;
    std.debug.print(
        "native storage phase={s} host_available_bytes={s} raw_logical/allocated_bytes={s} artifact_logical/allocated_bytes={s}\n",
        .{
            phase,
            optionalBytes(&available_buffer, miz.free_space.availableBytes(probe_path)),
            optionalUsage(&raw_buffer, raw_path),
            optionalUsage(&artifact_buffer, artifact_path),
        },
    );
}

const NativeRoot = struct {
    allocator: Allocator,
    io: Io,
    mutable_image: []const u8,
    raw_path: []u8,
    image: miz.Image,
    filesystem: miz.ext4_mountless.FileSystem,
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

    fn finish(self: *NativeRoot) !miz.ext4.FilesystemInfo {
        logNativeCapacity(
            "mountless-commit-start",
            self.mutable_image,
            self.raw_path,
            null,
        );
        var commit_result = self.filesystem.commit() catch |err| {
            logNativeCapacity(
                "mountless-commit-failed",
                self.mutable_image,
                self.raw_path,
                self.filesystem.recoveryArtifactPath(),
            );
            if (self.filesystem.recoveryArtifactPath()) |path| {
                std.debug.print(
                    "native ext4 commit failed: {s}; recovery artifact retained at {s}\n",
                    .{ @errorName(err), path },
                );
            } else {
                std.debug.print("native ext4 commit failed: {s}\n", .{@errorName(err)});
            }
            return switch (err) {
                error.NotEnoughSpace => {
                    std.debug.print(
                        "guest ext4 capacity exhausted during mountless commit\n",
                        .{},
                    );
                    return error.GuestExt4NotEnoughSpace;
                },
                error.NoSpaceLeft => {
                    std.debug.print(
                        "host filesystem capacity exhausted while staging mountless commit\n",
                        .{},
                    );
                    return error.HostMountlessCommitNoSpace;
                },
                else => err,
            };
        };
        defer commit_result.deinit();
        std.debug.print("native ext4 recovery artifact staged at {s}\n", .{commit_result.recovery_path});
        const filesystem_info = commit_result.filesystem;
        self.filesystem.deinit();
        self.filesystem_open = false;
        self.image.close(self.io);
        self.image_open = false;
        logNativeCapacity(
            "mountless-commit-complete",
            self.mutable_image,
            self.raw_path,
            commit_result.recovery_path,
        );
        try disposeRecoveryAndPublishNativeQcow2(
            self.allocator,
            self.io,
            self.raw_path,
            self.mutable_image,
            commit_result.recovery_path,
            .{ .publish = callPublishNativeQcow2 },
        );
        Dir.cwd().deleteFile(self.io, self.raw_path) catch {};
        return filesystem_info;
    }
};

fn copyNativeImage(
    allocator: Allocator,
    io: Io,
    source_path: []const u8,
    destination_path: []const u8,
    format: ImageFormat,
) !void {
    var source = try miz.Image.openPathReadOnlyStandalone(io, source_path);
    defer source.close(io);
    var destination = try miz.Image.createExclusive(
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
    _ = try miz.copyAll(io, source, &destination, allocator);
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
        "{s}.miz-native-stage",
        .{destination_path},
    );
    defer allocator.free(staged_path);
    Dir.cwd().deleteFile(io, staged_path) catch {};
    errdefer Dir.cwd().deleteFile(io, staged_path) catch {};
    try copyNativeImage(allocator, io, raw_path, staged_path, .qcow2);
    var staged = try miz.Image.openPathReadOnlyStandalone(io, staged_path);
    const check = staged.check(io) catch |err| {
        staged.close(io);
        return err;
    };
    staged.close(io);
    if (!check.ok) return error.FinalImageInvalid;
    try Dir.cwd().rename(staged_path, Dir.cwd(), destination_path, io);
}

fn callPublishNativeQcow2(
    allocator: Allocator,
    io: Io,
    raw_path: []const u8,
    destination_path: []const u8,
    context: ?*anyopaque,
) !void {
    _ = context;
    try publishNativeQcow2(allocator, io, raw_path, destination_path);
}

fn disposeRecoveryAndPublishNativeQcow2(
    allocator: Allocator,
    io: Io,
    raw_path: []const u8,
    destination_path: []const u8,
    recovery_path: []const u8,
    publisher: NativeQcow2Publisher,
) !void {
    const recovery_image = try std.fs.path.join(allocator, &.{ recovery_path, "stage" });
    defer allocator.free(recovery_image);
    logNativeCapacity(
        "recovery-disposal-start",
        destination_path,
        raw_path,
        recovery_image,
    );
    Dir.cwd().deleteTree(io, recovery_path) catch |err| {
        logNativeCapacity(
            "recovery-disposal-failed",
            destination_path,
            raw_path,
            recovery_image,
        );
        std.debug.print(
            "native ext4 recovery disposal failed before QCOW2 publication: {s}; path={s}\n",
            .{ @errorName(err), recovery_path },
        );
        return err;
    };
    logNativeCapacity(
        "recovery-disposal-complete",
        destination_path,
        raw_path,
        null,
    );
    logNativeCapacity(
        "qcow2-publication-start",
        destination_path,
        raw_path,
        null,
    );
    publisher.publish(
        allocator,
        io,
        raw_path,
        destination_path,
        publisher.context,
    ) catch |err| {
        logNativeCapacity(
            "qcow2-publication-failed",
            destination_path,
            raw_path,
            null,
        );
        std.debug.print(
            "native QCOW2 publication failed: {s}; no staged candidate was published\n",
            .{@errorName(err)},
        );
        if (err == error.NoSpaceLeft) return error.HostNativeQcow2NoSpace;
        return err;
    };
    logNativeCapacity(
        "qcow2-publication-complete",
        destination_path,
        raw_path,
        null,
    );
}

fn partitionNameEquals(partition: miz.gpt.PartitionEntry, expected: []const u8) bool {
    if (expected.len > partition.name_utf16le.len) return false;
    for (expected, 0..) |byte, index| {
        if (partition.name_utf16le[index] != byte) return false;
    }
    for (partition.name_utf16le[expected.len..]) |code_unit| {
        if (code_unit != 0) return false;
    }
    return true;
}

fn findNamedRootPartition(partitions: []const miz.gpt.PartitionEntry) !miz.gpt.PartitionEntry {
    var found: ?miz.gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (!partitionNameEquals(partition, "cloudimg-rootfs")) continue;
        if (found != null) return error.AmbiguousRootPartition;
        found = partition;
    }
    return found orelse error.RootPartitionNotFound;
}

fn partitionOffsetLength(partition: miz.gpt.PartitionEntry) !struct { offset: u64, length: u64 } {
    const offset = std.math.mul(u64, partition.first_lba, miz.gpt.sector_size) catch
        return error.InvalidPartitionBounds;
    const sectors = std.math.add(u64, partition.last_lba - partition.first_lba, 1) catch
        return error.InvalidPartitionBounds;
    return .{
        .offset = offset,
        .length = std.math.mul(u64, sectors, miz.gpt.sector_size) catch
            return error.InvalidPartitionBounds,
    };
}

fn rootPartitionGuid(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    profile: *const Profile,
) !guid.Guid {
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    const parsed = try miz.gpt.readGpt(image, io, allocator);
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
    flavor: Flavor,
) ![]u8 {
    var root_guid_text: [36]u8 = undefined;
    return switch (flavor) {
        .full => std.fmt.allocPrint(
            allocator,
            "root=PARTUUID={s} {s}",
            .{ guid.formatLower(&root_guid_text, root_guid), profile.serial_console },
        ),
        .core => std.fmt.allocPrint(
            allocator,
            "root=PARTUUID={s} init=/sbin/mizinit mizinit.mode=persistent mizinit.azure=auto console=tty0 {s}",
            .{ guid.formatLower(&root_guid_text, root_guid), profile.serial_console },
        ),
        // `azure=off` rather than an omitted option: the default is `auto`,
        // which probes for evidence that is never coming and then decides the
        // same thing more slowly. The serial console is kept alongside
        // `tty0` because this firmware's console has not been confirmed, and
        // a boot nobody can watch is a boot nobody can diagnose.
        .baremetal => std.fmt.allocPrint(
            allocator,
            "root=PARTUUID={s} init=/sbin/mizinit mizinit.mode=persistent mizinit.azure=off console=tty0 {s}",
            .{ guid.formatLower(&root_guid_text, root_guid), profile.serial_console },
        ),
    };
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
    var image = try miz.Image.openPath(io, raw_path);
    errdefer image.close(io);
    const partitions = try miz.gpt.readGpt(image, io, allocator);
    defer allocator.free(partitions.partitions);
    const partition = try findNamedRootPartition(partitions.partitions);
    const geometry = try partitionOffsetLength(partition);
    const spool_path = try std.fs.path.join(allocator, &.{ work_dir, "customized.native.spool" });
    defer allocator.free(spool_path);
    Dir.cwd().deleteFile(io, spool_path) catch {};
    var filesystem = try miz.ext4_mountless.FileSystem.open(allocator, io, image.file, .{
        .offset = geometry.offset,
        .length = geometry.length,
        .spool_path = spool_path,
        .atomic_path = raw_path,
        .inodes = .{ .bytes_per_inode = distro_bytes_per_inode },
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

fn requireSucceeded(
    result: package_family.Result,
    request: package_family.Request,
    package: []const u8,
) !void {
    if (!result.succeeded or result.diagnostic != null) {
        std.debug.print(
            "debz transaction package={s} operation={s} cache_mode={s} cache={s} config={s} keyring={s} lock={s}\n",
            .{
                package,
                @tagName(request.operation),
                @tagName(request.inputs.cache_mode),
                request.inputs.cache_path,
                request.inputs.config_paths[0],
                request.inputs.keyring_paths[0],
                request.inputs.lock_input_path orelse request.inputs.lock_output_path orelse "none",
            },
        );
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

/// Resolves the guest directory holding `release_name`'s kernel modules.
///
/// An Ubuntu 26.04 root is merged-usr: the modules really live under
/// `/usr/lib/modules`, and `/lib` is only a compatibility symlink to `usr/lib`.
/// `offline_root` refuses to walk a symlink in an intermediate component on
/// purpose -- that refusal is what stops a package escaping the root through
/// one -- so asking it for `/lib/modules/...` fails with `NotDirectory` instead
/// of landing on the real directory. Ask for the canonical location first and
/// keep the split-usr spelling as a fallback, so a root that never merged still
/// validates.
fn kernelModulesPath(
    allocator: Allocator,
    root: *offline_root.Root,
    release_name: []const u8,
) ![]u8 {
    const merged = try std.fmt.allocPrint(allocator, "/usr/lib/modules/{s}", .{release_name});
    if (root.inspect(merged)) |inspection| {
        allocator.free(inspection.path);
        if (inspection.kind == .directory) return merged;
    } else |err| switch (err) {
        error.PathNotFound, error.FileNotFound, error.NotDirectory => {},
        else => {
            allocator.free(merged);
            return err;
        },
    }
    allocator.free(merged);
    return std.fmt.allocPrint(allocator, "/lib/modules/{s}", .{release_name});
}

/// The `kernelModulesPath` rule for the built image rather than the staging
/// root. The mountless ext4 reader resolves a path by exact node lookup and
/// never expands a symlink either, so `/lib/modules/...` misses the same way --
/// here as `PathNotFound`.
fn nativeKernelModulesPath(
    allocator: Allocator,
    filesystem: *const miz.ext4_mountless.FileSystem,
    release_name: []const u8,
) ![]u8 {
    const merged = try std.fmt.allocPrint(allocator, "/usr/lib/modules/{s}", .{release_name});
    if (filesystem.stat(merged)) |entry| {
        if (entry.kind == .directory) return merged;
    } else |err| switch (err) {
        error.PathNotFound, error.NotDirectory => {},
        else => {
            allocator.free(merged);
            return err;
        },
    }
    allocator.free(merged);
    return std.fmt.allocPrint(allocator, "/lib/modules/{s}", .{release_name});
}

/// The kernel artifacts `update-initramfs` reads: the module tree and the
/// dependency index built from it. Checked before the initramfs is generated,
/// so a root missing its modules says exactly that instead of surfacing later
/// as an initramfs that could not be built.
fn validateKernelModuleArtifacts(
    allocator: Allocator,
    root: *offline_root.Root,
    release_name: []const u8,
) !void {
    const modules_path = try kernelModulesPath(allocator, root, release_name);
    defer allocator.free(modules_path);
    const modules = try root.discover(modules_path, "*");
    defer root.freeFound(modules);
    if (modules.len == 0) return error.ExpectedKernelModulesMissing;
    const modules_dep_path = try std.fmt.allocPrint(allocator, "{s}/modules.dep", .{modules_path});
    defer allocator.free(modules_dep_path);
    const modules_dep = root.inspect(modules_dep_path) catch |err| switch (err) {
        error.PathNotFound => return error.KernelModulesDependencyMissing,
        else => return err,
    };
    defer allocator.free(modules_dep.path);
    if (modules_dep.kind != .file) return error.KernelModulesDependencyMissing;
}

/// The initramfs `update-initramfs` writes.
///
/// Only meaningful once it has actually run. A root the kernel package was
/// unpacked into carries `/boot/initrd.img` as a symlink to an image that does
/// not exist yet -- the package ships the link, the generator supplies the
/// target -- so checking this before generating is guaranteed to fail.
fn validateInitramfs(
    allocator: Allocator,
    root: *offline_root.Root,
    release_name: []const u8,
) !void {
    const initrd_path = try std.fmt.allocPrint(allocator, "/boot/initrd.img-{s}", .{release_name});
    defer allocator.free(initrd_path);
    const initrd = root.inspect(initrd_path) catch |err| switch (err) {
        error.PathNotFound => return error.InitramfsMissing,
        else => return err,
    };
    defer allocator.free(initrd.path);
    if (initrd.kind != .file or initrd.size == 0) return error.InitramfsMissing;
}

fn validateNativeBootArtifacts(
    allocator: Allocator,
    root: *offline_root.Root,
    release_name: []const u8,
) !void {
    try validateKernelModuleArtifacts(allocator, root, release_name);
    try validateInitramfs(allocator, root, release_name);
}

fn validateCoreKernelModules(
    allocator: Allocator,
    root: *offline_root.Root,
    release_name: []const u8,
    flavor: Flavor,
) !void {
    const modules_path = try kernelModulesPath(allocator, root, release_name);
    defer allocator.free(modules_path);
    const modules_dep_path = try std.fmt.allocPrint(
        allocator,
        "{s}/modules.dep",
        .{modules_path},
    );
    defer allocator.free(modules_dep_path);
    const modules_dep = try root.readFile(modules_dep_path);
    defer allocator.free(modules_dep);
    for (&[_][]const u8{ "hv_netvsc.ko", "overlay.ko", "isofs.ko", "udf.ko", "xfs.ko" }) |module|
        if (std.mem.indexOf(u8, modules_dep, module) == null)
            return error.CoreKernelModuleMissing;
    // Binder is an Azure-kernel-only capability: bare metal boots the NVIDIA
    // BaseOS kernel and never claims Binder support, so this stays scoped to
    // `.core` rather than joining the shared list above.
    if (flavor == .core and std.mem.indexOf(u8, modules_dep, android_binder_module_name ++ ".ko") == null)
        return error.CoreKernelModuleMissing;
}

/// The kernel's own trailer, appended after `struct module_signature` at the
/// very end of a signed `.ko` (see <linux/module_signature.h>). Checking for
/// it is a structural "is this module signed" check, not a cryptographic
/// one: verifying a specific signer would mean pinning a certificate
/// identity nothing in this build independently establishes, and the actual
/// verification is the kernel's own signature-enforcing module loader.
const module_signature_marker = "~Module signature appended~\n";

fn hasModuleSignatureMarker(bytes: []const u8) bool {
    return std.mem.endsWith(u8, bytes, module_signature_marker);
}

/// What was found and recorded about the packaged `binder_linux` module:
/// used both to fail the build if it is missing, out-of-tree-shadowed, or
/// unsigned, and to extend the boot-input evidence document with something
/// checkable about it.
const AndroidBinderModuleEvidence = struct {
    path: []u8,
    sha256: [64]u8,
    signed: bool,
};

/// Locates the packaged `binder_linux` module under the kernel's own module
/// tree, rejects a DKMS-built shadow copy that would otherwise take priority
/// over it (`depmod`'s `updates/dkms` overlay directory), and confirms the
/// packaged bytes carry the kernel's module-signing trailer. Deliberately
/// does not decompress `.ko.zst` bytes for anything other than this
/// structural check: the packaged bytes are exactly what get evidenced here
/// and what mizinit's `finit_module()` hands the kernel unmodified at boot.
fn validateAndroidBinderModule(
    allocator: Allocator,
    root: *offline_root.Root,
    release_name: []const u8,
) !AndroidBinderModuleEvidence {
    const modules_path = try kernelModulesPath(allocator, root, release_name);
    defer allocator.free(modules_path);

    const shadow_dir = try std.fmt.allocPrint(allocator, "{s}/updates/dkms", .{modules_path});
    defer allocator.free(shadow_dir);
    const shadow = root.discover(shadow_dir, "*") catch |err| switch (err) {
        error.FileNotFound, error.NotDirectory => &.{},
        else => return err,
    };
    defer root.freeFound(shadow);
    if (shadow.len != 0) return error.ShadowBinderModulePresent;

    const android_dir = try std.fmt.allocPrint(allocator, "{s}/kernel/drivers/android", .{modules_path});
    defer allocator.free(android_dir);
    const found = root.discover(android_dir, android_binder_module_name ++ ".ko*") catch |err| switch (err) {
        error.FileNotFound, error.NotDirectory => return error.AndroidBinderModuleMissing,
        else => return err,
    };
    defer root.freeFound(found);
    if (found.len != 1) return error.AndroidBinderModuleMissing;

    const module_path = try allocator.dupe(u8, found[0].path);
    errdefer allocator.free(module_path);
    const packaged = try root.readFile(module_path);
    defer allocator.free(packaged);
    const sha256 = artifact_pipeline.formatSha256(artifact_pipeline.sha256Bytes(packaged));

    const signed = if (std.mem.endsWith(u8, module_path, ".zst")) signed: {
        const decoded = miz.zstd.decodeAlloc(allocator, packaged) catch return error.AndroidBinderModuleUnreadable;
        defer allocator.free(decoded.bytes);
        break :signed hasModuleSignatureMarker(decoded.bytes);
    } else hasModuleSignatureMarker(packaged);
    if (!signed) return error.AndroidBinderModuleUnsigned;

    return .{ .path = module_path, .sha256 = sha256, .signed = signed };
}

/// The `/boot/config-<release>` lines core's signed Binder support depends
/// on must be present verbatim, the same way `validateCoreKernelModules`
/// checks `modules.dep`: a plain substring search, since Ubuntu's kernel
/// config is one setting per line and each of these is specific enough that
/// a false-positive substring match is not a realistic concern.
fn validateCoreKernelConfig(
    allocator: Allocator,
    root: *offline_root.Root,
    release_name: []const u8,
) !void {
    const config_path = try std.fmt.allocPrint(allocator, "/boot/config-{s}", .{release_name});
    defer allocator.free(config_path);
    const config = try root.readFile(config_path);
    defer allocator.free(config);
    for (&core_required_kernel_config) |line|
        if (std.mem.indexOf(u8, config, line) == null) return error.CoreKernelConfigMissing;
}

/// `signed_bytes` is what the signer returned, so this is the binding that matters: the UKI carried
/// by the finalized image is byte-for-byte the artifact that was signed, not merely something that
/// parses as a UKI. Comparing the ESP copy against a second ESP copy could never establish that,
/// because the builder writes both in the same pass.
fn validateUkiBytes(
    fallback_bytes: []const u8,
    signed_bytes: []const u8,
    profile: *const Profile,
) !void {
    if (!std.mem.eql(u8, fallback_bytes, signed_bytes)) return error.FinalUkiMissing;
    if (try peMachine(fallback_bytes) != profile.pe_machine) return error.WrongUkiArchitecture;
}

fn validateUkiContract(
    allocator: Allocator,
    bytes: []const u8,
    expected_cmdline: []const u8,
) !void {
    var inspection = try miz.uki.inspect(allocator, bytes);
    defer inspection.deinit(allocator);
    if (inspection.security_directory == null) return error.UnsignedUki;
    for (&[_][]const u8{ ".linux", ".initrd", ".osrel", ".uname" }) |name| {
        const section = inspection.findSection(name) orelse return error.MissingUkiSection;
        if (section.contents.len == 0) return error.EmptyUkiSection;
    }
    const cmdline = inspection.findSection(".cmdline") orelse return error.MissingUkiSection;
    if (!std.mem.eql(u8, cmdline.contents, expected_cmdline))
        return error.UnexpectedUkiCmdline;
}

fn customizeOfflineRoot(
    allocator: Allocator,
    io: Io,
    profile: *const Profile,
    flavor: Flavor,
    root_path: []const u8,
    provenance_dir: []const u8,
) ![]u8 {
    var root = try offline_root.Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    const release_name = try root.activeKernelRelease(flavor.kernelSuffix());
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
    switch (flavor) {
        .full => {
            try root.apply(&.{
                .{ .create_directory = .{ .path = "/etc/ssh/sshd_config.d", .mode = 0o755 } },
                .{ .create_directory = .{ .path = "/etc/cloud/cloud.cfg.d", .mode = 0o755 } },
                .{ .create_directory = .{ .path = "/etc/netplan", .mode = 0o755 } },
                .{ .create_directory = .{ .path = "/var/lib/miz", .mode = 0o755 } },
                .{ .write_file = .{ .path = "/etc/ssh/sshd_config.d/10-miz-generalized.conf", .source = .{ .inline_bytes = ssh_config } } },
                .{ .write_file = .{ .path = "/etc/cloud/cloud.cfg.d/90-azure.cfg", .source = .{ .inline_bytes = cloud_config } } },
                .{ .write_file = .{ .path = "/etc/netplan/50-cloud-init.yaml", .source = .{ .inline_bytes = netplan } } },
                .{ .write_file = .{ .path = "/etc/waagent.conf", .source = .{ .inline_bytes = waagent } } },
                .{ .replace_symlink = .{ .path = "/etc/resolv.conf", .target = "/run/systemd/resolve/stub-resolv.conf" } },
            });
        },
        .core => {
            try root.apply(&.{
                .{ .create_directory = .{ .path = "/etc/ssh/sshd_config.d", .mode = 0o755 } },
                .{ .create_directory = .{ .path = "/etc/initramfs-tools", .mode = 0o755 } },
                .{ .create_directory = .{ .path = "/var/lib/miz", .mode = 0o755 } },
                .{ .write_file = .{ .path = "/etc/ssh/sshd_config.d/10-mizinit.conf", .source = .{ .inline_bytes = core_ssh_config }, .mode = 0o600 } },
                .{ .write_file = .{ .path = "/etc/waagent.conf", .source = .{ .inline_bytes = core_azagent_config } } },
                .{ .write_file = .{ .path = "/etc/resolv.conf", .source = .{ .inline_bytes = "" } } },
                .{ .write_file = .{ .path = "/etc/initramfs-tools/modules", .source = .{ .inline_bytes = core_initramfs_modules } } },
            });
        },
        .baremetal => {
            try root.apply(&.{
                .{ .create_directory = .{ .path = "/etc/ssh/sshd_config.d", .mode = 0o755 } },
                .{ .create_directory = .{ .path = "/etc/initramfs-tools", .mode = 0o755 } },
                .{ .create_directory = .{ .path = "/usr/local/sbin", .mode = 0o755 } },
                .{ .create_directory = .{ .path = "/var/lib/miz", .mode = 0o755 } },
                .{ .write_file = .{ .path = "/etc/ssh/sshd_config.d/10-mizinit.conf", .source = .{ .inline_bytes = core_ssh_config }, .mode = 0o600 } },
                .{ .write_file = .{ .path = "/etc/waagent.conf", .source = .{ .inline_bytes = core_azagent_config } } },
                .{ .write_file = .{ .path = "/etc/resolv.conf", .source = .{ .inline_bytes = "" } } },
                .{ .write_file = .{ .path = "/etc/initramfs-tools/initramfs.conf", .source = .{ .inline_bytes = baremetal_initramfs_conf } } },
                .{ .write_file = .{ .path = "/etc/initramfs-tools/modules", .source = .{ .inline_bytes = baremetal_initramfs_modules } } },
                .{ .write_file = .{ .path = baremetal_access_provider_path, .source = .{ .inline_bytes = baremetal_access_provider }, .mode = 0o755 } },
            });
        },
    }

    // The module tree is `update-initramfs`'s input, so it is checked here;
    // the initramfs it produces is checked below, once it exists.
    try validateKernelModuleArtifacts(allocator, &root, release_name);
    if (flavor.freshRoot()) try validateCoreKernelModules(allocator, &root, release_name, flavor);

    var binder_evidence: ?AndroidBinderModuleEvidence = null;
    defer if (binder_evidence) |*evidence| allocator.free(evidence.path);
    if (flavor == .core) {
        try validateCoreKernelConfig(allocator, &root, release_name);
        binder_evidence = try validateAndroidBinderModule(allocator, &root, release_name);
    }

    var initramfs = try runOfflineCommand(&executor, .{ .update_initramfs = release_name });
    defer initramfs.deinit(allocator);

    try validateInitramfs(allocator, &root, release_name);

    var package_query = try runOfflineCommand(&executor, .dpkg_query);
    defer package_query.deinit(allocator);
    const lock = try sortedPackageLock(allocator, package_query.stdout);
    defer allocator.free(lock);
    try root.apply(&.{
        .{ .write_file = .{
            .path = "/var/lib/miz/ubuntu2604-package-lock.tsv",
            .source = .{ .inline_bytes = lock },
        } },
        .{ .write_file = .{
            .path = "/var/lib/miz/source-release",
            .source = .{ .inline_bytes = release ++ "\n" },
        } },
        .{ .write_file = .{
            .path = "/etc/machine-id",
            .source = .{ .inline_bytes = "" },
            .mode = 0o444,
        } },
    });

    var cloud_init: ?offline_root.CommandResult = if (flavor == .full)
        try runOfflineCommand(&executor, .{ .cloud_init_clean = .{ .logs = true } })
    else
        null;
    defer if (cloud_init) |*result| result.deinit(allocator);
    try root.apply(&.{
        .{ .remove = "/var/lib/dbus/machine-id" },
        .{ .remove = "/var/lib/systemd/random-seed" },
        .{ .cleanup = .{ .directory = "/etc/ssh", .pattern = "ssh_host_*" } },
        .{ .cleanup = .{ .directory = "/var/log/azure", .pattern = "*" } },
        .{ .cleanup = .{ .directory = "/var/log/journal", .pattern = "*" } },
        .{ .cleanup = .{ .directory = "/tmp", .pattern = "*" } },
        .{ .cleanup = .{ .directory = "/var/tmp", .pattern = "*" } },
    });
    if (flavor == .full) {
        try root.apply(&.{
            .{ .cleanup = .{ .directory = "/var/lib/cloud", .pattern = "*" } },
            .{ .cleanup = .{ .directory = "/var/lib/waagent", .pattern = "*" } },
        });
    } else {
        try root.apply(&.{
            .{ .remove = "/var/lib/cloud" },
            .{ .remove = "/var/lib/waagent" },
            .{ .remove = "/var/lib/azagent" },
            .{ .remove = "/var/lib/dhcp" },
            .{ .remove = "/var/lib/NetworkManager" },
        });
    }

    const modules_path = try kernelModulesPath(allocator, &root, release_name);
    defer allocator.free(modules_path);
    const initrd_path = try std.fmt.allocPrint(allocator, "/boot/initrd.img-{s}", .{release_name});
    defer allocator.free(initrd_path);
    const full_cleanup_patterns = [_][]const u8{
        "/etc/ssh/ssh_host_*", "/var/lib/cloud/*",   "/var/lib/waagent/*",
        "/var/log/azure/*",    "/var/log/journal/*", "/tmp/*",
        "/var/tmp/*",
    };
    const core_cleanup_patterns = [_][]const u8{
        "/etc/ssh/ssh_host_*",       "/var/lib/azagent/*", "/var/lib/dhcp/*",
        "/var/lib/NetworkManager/*", "/var/log/azure/*",   "/var/log/journal/*",
        "/tmp/*",                    "/var/tmp/*",
    };
    const cleanup_patterns: []const []const u8 = if (flavor == .full)
        &full_cleanup_patterns
    else
        &core_cleanup_patterns;
    for (cleanup_patterns) |pattern| {
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
    // Structural evidence only: this records that the required kernel config
    // lines were present and that the packaged module carries a signature
    // trailer, not a specific signer identity -- nothing here independently
    // establishes what that signer should be, so asserting one would be
    // invented, not verified.
    const binder_kernel_config_verified: ?bool = if (flavor == .core) true else null;
    const binder_module_path: ?[]const u8 = if (binder_evidence) |e| e.path else null;
    const binder_module_sha256: ?[]const u8 = if (binder_evidence) |*e| @as([]const u8, &e.sha256) else null;
    const binder_module_signed: ?bool = if (binder_evidence) |e| e.signed else null;
    const evidence = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = 1,
        .type = "miz-ubuntu2604-boot-input-evidence",
        .architecture = @tagName(profile.architecture),
        .kernel_release = release_name,
        .kernel = kernel_path,
        .initramfs = initrd_path,
        .modules = modules_path,
        .package_lock = "/var/lib/miz/ubuntu2604-package-lock.tsv",
        .package_lock_sha256 = @as([]const u8, &lock_sha256),
        .binder_kernel_config_verified = binder_kernel_config_verified,
        .binder_module_path = binder_module_path,
        .binder_module_sha256 = binder_module_sha256,
        .binder_module_signed = binder_module_signed,
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(evidence);
    try Dir.cwd().writeFile(io, .{ .sub_path = evidence_path, .data = evidence });
    return release_name;
}

fn generalizationPolicy(flavor: Flavor) miz.os_customization.GeneralizationPolicy {
    return switch (flavor) {
        .full => .{ .azure = .{
            .reset_hostname = false,
            .clear_machine_id = false,
            .remove_ssh_host_keys = false,
            .remove_agent_state = false,
            .remove_dhcp_leases = false,
            .remove_resolver_configuration = false,
            .clear_random_seed = false,
            .remove_users = &.{"ubuntu"},
        } },
        .core, .baremetal => .{ .azure = .{ .remove_users = &.{"ubuntu"} } },
    };
}

fn expectedElfMachine(profile: *const Profile) u16 {
    return switch (profile.architecture) {
        .x86_64 => 62,
        .aarch64 => 183,
    };
}

fn validateGuestElf(bytes: []const u8, profile: *const Profile) !void {
    if (bytes.len < 20 or !std.mem.eql(u8, bytes[0..4], "\x7fELF") or bytes[5] != 1)
        return error.InvalidGuestExecutable;
    if (std.mem.readInt(u16, bytes[18..20], .little) != expectedElfMachine(profile))
        return error.WrongGuestExecutableArchitecture;
}

fn removeIfPresent(filesystem: *miz.ext4_mountless.FileSystem, path: []const u8) !void {
    filesystem.remove(path, true) catch |err| switch (err) {
        error.PathNotFound => {},
        else => return err,
    };
}

const Arm64FstabLine = enum {
    unrelated,
    retired_xbootldr,
    retired_esp,
    unexpected_boot_mount,
};

fn classifyArm64FstabLine(line: []const u8) Arm64FstabLine {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0 or trimmed[0] == '#') return .unrelated;

    var fields: [7][]const u8 = undefined;
    var field_count: usize = 0;
    var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
    while (tokens.next()) |field| {
        if (field_count < fields.len) fields[field_count] = field;
        field_count += 1;
    }
    if (field_count < 2 or
        (!std.mem.eql(u8, fields[1], "/boot") and
            !std.mem.eql(u8, fields[1], "/boot/efi")))
    {
        return .unrelated;
    }
    if (field_count == 6 and
        std.mem.eql(u8, fields[0], "LABEL=BOOT") and
        std.mem.eql(u8, fields[1], "/boot") and
        std.mem.eql(u8, fields[2], "ext4") and
        std.mem.eql(u8, fields[3], "defaults") and
        std.mem.eql(u8, fields[4], "0") and
        std.mem.eql(u8, fields[5], "2"))
    {
        return .retired_xbootldr;
    }
    if (field_count == 6 and
        std.mem.eql(u8, fields[0], "LABEL=UEFI") and
        std.mem.eql(u8, fields[1], "/boot/efi") and
        std.mem.eql(u8, fields[2], "vfat") and
        std.mem.eql(u8, fields[3], "umask=0077") and
        std.mem.eql(u8, fields[4], "0") and
        std.mem.eql(u8, fields[5], "1"))
    {
        return .retired_esp;
    }
    return .unexpected_boot_mount;
}

fn retireArm64BootFstabAlloc(
    allocator: Allocator,
    fstab: []const u8,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var xbootldr_removed: usize = 0;
    var esp_removed: usize = 0;
    var offset: usize = 0;
    while (offset < fstab.len) {
        const relative_newline = std.mem.indexOfScalar(u8, fstab[offset..], '\n');
        const line_end = offset + (relative_newline orelse fstab.len - offset);
        const segment_end = if (relative_newline == null) line_end else line_end + 1;
        switch (classifyArm64FstabLine(fstab[offset..line_end])) {
            .unrelated => try output.writer.writeAll(fstab[offset..segment_end]),
            .retired_xbootldr => xbootldr_removed += 1,
            .retired_esp => esp_removed += 1,
            .unexpected_boot_mount => return error.UnexpectedArm64BootMount,
        }
        offset = segment_end;
    }
    if (xbootldr_removed == 0) return error.MissingArm64XbootldrFstabEntry;
    if (xbootldr_removed != 1) return error.AmbiguousArm64XbootldrFstabEntry;
    if (esp_removed == 0) return error.MissingArm64EspFstabEntry;
    if (esp_removed != 1) return error.AmbiguousArm64EspFstabEntry;
    return output.toOwnedSlice();
}

fn validateArm64BootFstabRetired(fstab: []const u8) !void {
    var lines = std.mem.splitScalar(u8, fstab, '\n');
    while (lines.next()) |line| {
        if (classifyArm64FstabLine(line) != .unrelated) {
            return error.Arm64BootFstabEntryRetained;
        }
    }
}

fn retireArm64BootMounts(
    allocator: Allocator,
    filesystem: *miz.ext4_mountless.FileSystem,
) !void {
    const fstab = try filesystem.read(allocator, "/etc/fstab", 1024 * 1024);
    defer allocator.free(fstab);
    const rewritten = try retireArm64BootFstabAlloc(allocator, fstab);
    defer allocator.free(rewritten);
    try validateArm64BootFstabRetired(rewritten);
    try filesystem.write("/etc/fstab", rewritten, null);
}

fn injectCoreGuest(
    allocator: Allocator,
    io: Io,
    filesystem: *miz.ext4_mountless.FileSystem,
    profile: *const Profile,
    mizinit_path: []const u8,
    azagent_path: []const u8,
    evidence: []const DebzEvidence,
) !void {
    const mizinit_bytes = try Dir.cwd().readFileAlloc(io, mizinit_path, allocator, .limited(32 * 1024 * 1024));
    defer allocator.free(mizinit_bytes);
    const azagent_bytes = try Dir.cwd().readFileAlloc(io, azagent_path, allocator, .limited(32 * 1024 * 1024));
    defer allocator.free(azagent_bytes);
    try validateGuestElf(mizinit_bytes, profile);
    try validateGuestElf(azagent_bytes, profile);

    try filesystem.mkdir("/var/lib/miz/provenance", .{ .mode = 0o755 });
    try filesystem.mkdir("/etc/ssh/sshd_config.d", .{ .mode = 0o755 });
    try filesystem.write("/usr/sbin/mizinit", mizinit_bytes, .{ .mode = 0o755 });
    try filesystem.write("/usr/sbin/azagent", azagent_bytes, .{ .mode = 0o755 });
    for (&[_][]const u8{ "init", "poweroff", "reboot", "shutdown" }) |name| {
        const path = try std.fmt.allocPrint(allocator, "/usr/sbin/{s}", .{name});
        defer allocator.free(path);
        try filesystem.symlink(path, "mizinit", .{ .mode = 0o777 });
    }
    try filesystem.write(
        "/etc/ssh/sshd_config.d/10-mizinit.conf",
        core_ssh_config,
        .{ .mode = 0o600 },
    );
    try filesystem.write("/etc/waagent.conf", core_azagent_config, .{ .mode = 0o644 });
    try filesystem.write("/etc/resolv.conf", "", .{ .mode = 0o644 });

    for (evidence) |item| {
        for ([_][]const u8{ item.lock_path, item.provenance_path }) |source| {
            const destination = try std.fmt.allocPrint(
                allocator,
                "/var/lib/miz/provenance/{s}",
                .{std.fs.path.basename(source)},
            );
            defer allocator.free(destination);
            try filesystem.copyIn(source, destination, .{ .mode = 0o600 });
        }
    }
    const contract = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = 1,
        .type = "miz-ubuntu2604-core-provenance",
        .flavor = "core",
        .release = "26.04",
        .snapshot = snapshot_base,
        .debz_api_commit = package_family.debz_api_commit,
        .package_roots = core_debz_packages,
        .transaction_count = evidence.len,
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(contract);
    try filesystem.write(
        "/var/lib/miz/ubuntu2604-core-provenance.json",
        contract,
        .{ .mode = 0o600 },
    );
}

fn requireRootPath(filesystem: *const miz.ext4_mountless.FileSystem, path: []const u8) !void {
    const entry = filesystem.stat(path) catch |err| switch (err) {
        error.PathNotFound => return error.CoreRequiredPathMissing,
        else => return err,
    };
    if (entry.kind != .file) return error.CoreRequiredPathMissing;
}

fn requireRootPathAbsent(filesystem: *const miz.ext4_mountless.FileSystem, path: []const u8) !void {
    _ = filesystem.stat(path) catch |err| switch (err) {
        error.PathNotFound => return,
        else => return err,
    };
    return error.ForbiddenCorePath;
}

/// Walks the finished root for identity that must not be built into an image.
///
/// Host keys are rejected for every flavor: they must differ per machine, and
/// an image that ships one hands every machine built from it the same
/// identity. Authorized keys are rejected only where identity arrives at boot
/// -- on Azure, from OVF media, which makes a baked key both unnecessary and a
/// way for one to outlive the provisioning that was supposed to replace it.
/// Bare metal has no such media and no agent to read it, so the administrator
/// key has to be in the image; that is the whole difference.
fn validateNoBakedIdentity(
    allocator: Allocator,
    filesystem: *const miz.ext4_mountless.FileSystem,
    directory: []const u8,
    flavor: Flavor,
) !void {
    const entries = filesystem.list(allocator, directory, 100_000) catch |err| switch (err) {
        error.PathNotFound => return,
        else => return err,
    };
    defer allocator.free(entries);
    for (entries) |entry| {
        const name = std.fs.path.basename(entry.path);
        if (std.mem.startsWith(u8, name, "ssh_host_")) return error.BakedIdentityState;
        if (flavor.azure() and std.mem.eql(u8, name, "authorized_keys"))
            return error.BakedIdentityState;
        if (entry.kind == .directory) try validateNoBakedIdentity(allocator, filesystem, entry.path, flavor);
    }
}

fn validateCoreRoot(
    allocator: Allocator,
    io: Io,
    filesystem: *const miz.ext4_mountless.FileSystem,
    profile: *const Profile,
    flavor: Flavor,
    evidence: []const DebzEvidence,
) !void {
    if (evidence.len != flavor.debzPackages().len) return error.InvalidDebzEvidence;
    for (&core_required_paths) |path| try requireRootPath(filesystem, path);
    if (flavor == .baremetal) {
        // Without this the machine boots and never becomes reachable: mizinit
        // would fall back to sshd, which waits for a provisioning sentinel that
        // nothing on bare metal ever writes.
        try requireRootPath(filesystem, baremetal_access_provider_path);
        try requireRootPath(filesystem, "/etc/initramfs-tools/initramfs.conf");
    }
    for (&core_forbidden_paths) |path| try requireRootPathAbsent(filesystem, path);
    const sbin = try filesystem.readLink(allocator, "/sbin", 1024);
    defer allocator.free(sbin);
    if (!std.mem.eql(u8, sbin, "usr/sbin")) return error.InvalidUsrMerge;
    for (&[_][]const u8{ "init", "poweroff", "reboot", "shutdown" }) |name| {
        const path = try std.fmt.allocPrint(allocator, "/usr/sbin/{s}", .{name});
        defer allocator.free(path);
        const target = try filesystem.readLink(allocator, path, 1024);
        defer allocator.free(target);
        if (!std.mem.eql(u8, target, "mizinit")) return error.InvalidCoreInitLink;
    }
    const machine_id = try filesystem.read(allocator, "/etc/machine-id", 1024);
    defer allocator.free(machine_id);
    if (machine_id.len != 0) return error.BakedIdentityState;
    const random_seed: ?[]u8 = filesystem.read(
        allocator,
        "/var/lib/systemd/random-seed",
        1024 * 1024,
    ) catch |err| switch (err) {
        error.PathNotFound => null,
        else => return err,
    };
    if (random_seed) |seed| {
        defer allocator.free(seed);
        if (seed.len != 0) return error.BakedIdentityState;
    }
    try validateNoBakedIdentity(allocator, filesystem, "/", flavor);

    const ssh_config = try filesystem.read(allocator, "/etc/ssh/sshd_config.d/10-mizinit.conf", 64 * 1024);
    defer allocator.free(ssh_config);
    for (&[_][]const u8{
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitRootLogin prohibit-password",
        "PubkeyAuthentication yes",
    }) |setting| if (std.mem.indexOf(u8, ssh_config, setting) == null)
        return error.InvalidCoreSshConfiguration;
    const azagent_config = try filesystem.read(allocator, "/etc/waagent.conf", 64 * 1024);
    defer allocator.free(azagent_config);
    for (&[_][]const u8{
        "ResourceDisk.Format=y",
        "ResourceDisk.Filesystem=xfs",
        "ResourceDisk.EnableSwap=n",
        "DataDisk.Mount=y",
    }) |setting| if (std.mem.indexOf(u8, azagent_config, setting) == null)
        return error.InvalidCoreAzagentConfiguration;

    const inventory = try filesystem.read(
        allocator,
        "/var/lib/miz/ubuntu2604-package-lock.tsv",
        4 * 1024 * 1024,
    );
    defer allocator.free(inventory);
    try validateExactLockRuntime(allocator, inventory, profile, flavor);
    const final_exact_lock = try Dir.cwd().readFileAlloc(
        io,
        evidence[evidence.len - 1].lock_path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
    defer allocator.free(final_exact_lock);
    try validateInventoryAgainstExactLock(allocator, inventory, final_exact_lock, profile);

    for (evidence) |item| {
        const embedded_lock_path = try std.fmt.allocPrint(
            allocator,
            "/var/lib/miz/provenance/{s}",
            .{std.fs.path.basename(item.lock_path)},
        );
        defer allocator.free(embedded_lock_path);
        const embedded_lock = try filesystem.read(allocator, embedded_lock_path, 16 * 1024 * 1024);
        defer allocator.free(embedded_lock);
        const embedded_lock_sha256 = artifact_pipeline.formatSha256(
            artifact_pipeline.sha256Bytes(embedded_lock),
        );
        if (!std.mem.eql(
            u8,
            &embedded_lock_sha256,
            &item.lock_sha256,
        )) return error.EmbeddedProvenanceMismatch;

        const embedded_provenance_path = try std.fmt.allocPrint(
            allocator,
            "/var/lib/miz/provenance/{s}",
            .{std.fs.path.basename(item.provenance_path)},
        );
        defer allocator.free(embedded_provenance_path);
        const embedded_provenance = try filesystem.read(allocator, embedded_provenance_path, 16 * 1024 * 1024);
        defer allocator.free(embedded_provenance);
        const embedded_provenance_sha256 = artifact_pipeline.formatSha256(
            artifact_pipeline.sha256Bytes(embedded_provenance),
        );
        if (!std.mem.eql(
            u8,
            &embedded_provenance_sha256,
            &item.provenance_sha256,
        )) return error.EmbeddedProvenanceMismatch;
    }

    const mizinit = try filesystem.read(allocator, "/usr/sbin/mizinit", 32 * 1024 * 1024);
    defer allocator.free(mizinit);
    try validateGuestElf(mizinit, profile);
    const azagent = try filesystem.read(allocator, "/usr/sbin/azagent", 32 * 1024 * 1024);
    defer allocator.free(azagent);
    try validateGuestElf(azagent, profile);
}

fn customizeRootWithDebz(
    allocator: Allocator,
    io: Io,
    timing: *image_phase_timing.Recorder,
    profile: *const Profile,
    flavor: Flavor,
    mutable_image: []const u8,
    work_dir: []const u8,
    provenance_dir: []const u8,
    mizinit_path: ?[]const u8,
    azagent_path: ?[]const u8,
    proxy: ?[]const u8,
    debz_cache: ?[]const u8,
    debz_input_dir: ?[]const u8,
    debz_lock_dir: ?[]const u8,
    offline: bool,
    authorized_key: ?[]const u8,
) !DebzCustomization {
    var debz_aggregate = timing.begin(.debz_aggregate, null);
    defer debz_aggregate.end();
    errdefer |err| debz_aggregate.fail(@errorName(err));

    const extraction = try std.fs.path.join(allocator, &.{ work_dir, "official-root" });
    defer allocator.free(extraction);
    try Dir.cwd().deleteTree(io, extraction);
    try Dir.cwd().createDirPath(io, extraction);
    var native_root = try openNativeRoot(allocator, io, mutable_image, work_dir);
    defer native_root.deinit();
    var host_manifest = miz.ext4_mountless.HostTreeManifest.init(allocator);
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

    const repository_input_dir = debz_input_dir orelse work_dir;
    try Dir.cwd().createDirPath(io, repository_input_dir);
    const repository_input_stat = try Dir.cwd().statFile(io, repository_input_dir, .{ .follow_symlinks = false });
    if (repository_input_stat.kind != .directory) return error.DebzInputDirNotDirectory;
    const absolute_repository_input_dir = try Dir.cwd().realPathFileAlloc(io, repository_input_dir, allocator);
    defer allocator.free(absolute_repository_input_dir);

    const trusted_keyring = try std.fs.path.join(allocator, &.{ current, "usr/share/keyrings/ubuntu-archive-keyring.gpg" });
    defer allocator.free(trusted_keyring);
    const external_keyring = try std.fs.path.join(allocator, &.{ absolute_repository_input_dir, "ubuntu-archive-keyring.gpg" });
    defer allocator.free(external_keyring);
    var trusted = try materializeTrustedKeyring(allocator, io, trusted_keyring, external_keyring);
    defer trusted.deinit(allocator);
    const absolute_keyring = trusted.path;
    if (flavor.freshRoot()) {
        try Dir.cwd().deleteTree(io, current);
        try Dir.cwd().createDirPath(io, current);
    }
    for (&[_][]const u8{ "dev", "proc", "run", "sys" }) |name| {
        const mountpoint = try std.fs.path.join(allocator, &.{ current, name });
        defer allocator.free(mountpoint);
        try Dir.cwd().createDirPath(io, mountpoint);
    }
    const source_path = try std.fs.path.join(allocator, &.{ absolute_repository_input_dir, "ubuntu-snapshot.sources" });
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
    const source_config_path = try std.fs.path.join(allocator, &.{ absolute_repository_input_dir, "ubuntu-snapshot.json" });
    defer allocator.free(source_config_path);
    const source_config = try std.json.Stringify.valueAlloc(allocator, .{
        .source_path = absolute_source,
        .immutable = true,
    }, .{});
    defer allocator.free(source_config);
    try Dir.cwd().writeFile(io, .{ .sub_path = source_config_path, .data = source_config });
    const absolute_source_config = try Dir.cwd().realPathFileAlloc(io, source_config_path, allocator);
    defer allocator.free(absolute_source_config);

    // Caller-owned single-element input slices. Their storage outlives every
    // resolve and customize request so the package-family boundary never reads
    // dangling pointers, and both requests reuse the same trusted keyring copy.
    const config_inputs = [_][]const u8{absolute_source_config};
    const keyring_inputs = [_][]const u8{absolute_keyring};

    // One content-addressed cache for every stage, kept across runs. Objects are
    // named by their own SHA-256 and the sources document pins an immutable
    // snapshot, so a hit cannot change what a stage resolves to or installs --
    // the same argument `acquireVerified` already reuses the cloud image on.
    // Per-stage `state` stays per-stage and is still discarded: it is dpkg
    // admin state, not content, and reusing it across transactions would carry
    // one stage's installed baseline into the next.
    const shared_cache = if (debz_cache) |path|
        try allocator.dupe(u8, path)
    else
        try std.fs.path.join(allocator, &.{ work_dir, "debz-cache" });
    defer allocator.free(shared_cache);
    if (offline) {
        const cache_stat = Dir.cwd().statFile(io, shared_cache, .{ .follow_symlinks = false }) catch |err| return switch (err) {
            error.FileNotFound => error.DebzOfflineCacheMissing,
            else => err,
        };
        if (cache_stat.kind != .directory) return error.DebzOfflineCacheNotDirectory;
    } else {
        try Dir.cwd().createDirPath(io, shared_cache);
    }
    try cleanupSharedDebzCacheStaging(io, shared_cache);
    const absolute_cache = try Dir.cwd().realPathFileAlloc(io, shared_cache, allocator);
    defer allocator.free(absolute_cache);

    const debz_packages: []const []const u8 = flavor.debzPackages();
    var evidence: [max_debz_packages]DebzEvidence = undefined;
    var evidence_count: usize = 0;
    errdefer {
        for (evidence[0..evidence_count]) |*item| item.deinit(allocator);
    }

    for (debz_packages, 0..) |package, index| {
        var debz_transaction = timing.begin(.debz_transaction, package);
        defer debz_transaction.end();
        errdefer |err| debz_transaction.fail(@errorName(err));

        const installed_baseline: package_family.InstalledBaselinePolicy =
            if (flavor.freshRoot() and index == 0) .none else .require_locked;
        const apply_operation: package_family.Operation =
            if (flavor.freshRoot() and index == 0) .create else .customize;
        const packages = [_][]const u8{package};
        const transaction_dir = try std.fmt.allocPrint(allocator, "{s}/debz-{s}", .{ work_dir, package });
        defer allocator.free(transaction_dir);
        try Dir.cwd().deleteTree(io, transaction_dir);
        try Dir.cwd().createDirPath(io, transaction_dir);
        const state = try std.fs.path.join(allocator, &.{ transaction_dir, "state" });
        defer allocator.free(state);
        try Dir.cwd().createDirPath(io, state);

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
        const lock_filename = try std.fmt.allocPrint(
            allocator,
            "debz-exact-lock-{s}-{s}.json",
            .{ package, profile.ubuntu_architecture },
        );
        defer allocator.free(lock_filename);
        if (debz_lock_dir) |lock_dir| {
            const lock_input = try std.fs.path.join(allocator, &.{ lock_dir, lock_filename });
            defer allocator.free(lock_input);
            try copyExactLockInput(allocator, io, lock_input, absolute_lock);
        } else {
            const resolve_request = packageFamilyRequest(
                .resolve_lock,
                profile,
                &packages,
                absolute_resolve_root,
                absolute_dummy,
                &config_inputs,
                &keyring_inputs,
                absolute_cache,
                absolute_state,
                absolute_lock,
                installed_baseline,
                proxy,
                offline,
            );
            try assertRequestSeparation(resolve_request);
            const resolved = try package_family.execute(allocator, io, .{}, resolve_request);
            try requireSucceeded(resolved, resolve_request, package);
            if (resolved.lock_path == null or !std.mem.eql(u8, resolved.lock_path.?, absolute_lock))
                return error.DebzLockMismatch;
        }

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

        const customize_request = packageFamilyRequest(
            apply_operation,
            profile,
            &packages,
            absolute_stage,
            absolute_published,
            &config_inputs,
            &keyring_inputs,
            absolute_cache,
            absolute_state,
            absolute_lock,
            installed_baseline,
            proxy,
            offline,
        );
        try assertRequestSeparation(customize_request);
        const customized = try package_family.execute(allocator, io, .{}, customize_request);
        try requireSucceeded(customized, customize_request, package);
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
        debz_transaction.succeed();
    }

    try assertTrustedKeyringUnchanged(io, trusted);
    debz_aggregate.succeed();

    var initramfs_import = timing.begin(.initramfs_ext4_import, null);
    defer initramfs_import.end();
    errdefer |err| initramfs_import.fail(@errorName(err));
    const release_name = try customizeOfflineRoot(
        allocator,
        io,
        profile,
        flavor,
        current,
        provenance_dir,
    );
    allocator.free(release_name);
    try native_root.filesystem.importHostTreeWithManifest(current, .{}, &host_manifest);
    if (flavor == .full) {
        try native_root.filesystem.applyCustomization(.{
            .services = &full_service_policy,
        }, 0);
    } else {
        try native_root.filesystem.applyCustomization(.{
            .services = &.{
                .{ .name = "ssh.service", .state = .disabled },
            },
        }, 0);
        for (&[_][]const u8{
            "/etc/systemd/system/ssh.service",
            "/etc/systemd/system/multi-user.target.wants/ssh.service",
            "/etc/systemd/system/sockets.target.wants/ssh.socket",
        }) |path| try removeIfPresent(&native_root.filesystem, path);
    }
    try native_root.filesystem.generalize(generalizationPolicy(flavor));
    // After generalization, which is what removes accounts: an administrator
    // created before it would be taken straight back out again.
    if (authorized_key) |key| {
        try native_root.filesystem.applyCustomization(.{
            .users = &.{.{
                .name = baremetal_admin_user,
                .shell = "/bin/bash",
                .password = .locked,
                .ssh_authorized_keys = &.{key},
                .passwordless_sudo = true,
            }},
        }, 0);
    }
    if (flavor.freshRoot()) {
        const mizinit = mizinit_path orelse return error.CoreGuestArtifactsRequired;
        const azagent = azagent_path orelse return error.CoreGuestArtifactsRequired;
        try injectCoreGuest(
            allocator,
            io,
            &native_root.filesystem,
            profile,
            mizinit,
            azagent,
            evidence[0..evidence_count],
        );
        try validateCoreRoot(
            allocator,
            io,
            &native_root.filesystem,
            profile,
            flavor,
            evidence[0..evidence_count],
        );
    }
    if (native_root.filesystem.stat("/home/ubuntu")) |_| {
        return error.UserCleanupIncomplete;
    } else |err| switch (err) {
        error.PathNotFound => {},
        else => return error.UserCleanupIncomplete,
    }
    if (profile.architecture == .aarch64 and flavor == .full) {
        try retireArm64BootMounts(allocator, &native_root.filesystem);
    }
    const filesystem_info = try native_root.finish();
    const root_free_bytes = @as(u64, filesystem_info.free_block_count) * 4096;
    try validateRootHeadroom(flavor, root_free_bytes, filesystem_info.free_inode_count);
    initramfs_import.succeed();
    return .{
        .root_path = current,
        .evidence = evidence,
        .evidence_count = evidence_count,
        .root_free_bytes = root_free_bytes,
    };
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

fn diskLayoutProvenance(profile: *const Profile) []const u8 {
    return switch (profile.architecture) {
        .x86_64 =>
        \\{"source":"canonical-gen2-gpt","transform":"preserved"}
        ,
        .aarch64 =>
        \\{"source":"canonical-gen2-gpt","transform":"arm64-esp-rebuild-v1","esp":{"table_index":14,"first_lba":2048,"last_lba":1050623,"size_bytes":536870912,"fat32":"reformatted-preserve-volume-id","content":"signed-fallback-only"},"retired_xbootldr":{"table_index":12,"cleared":true}}
        ,
    };
}

fn writeProvenance(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    profile: *const Profile,
    source_digest: [64]u8,
    evidence: []const DebzEvidence,
) !void {
    if (evidence.len != full_debz_packages.len) return error.InvalidDebzEvidence;
    const document = try std.fmt.allocPrint(allocator,
        \\{{"schema":1,"type":"miz-ubuntu2604-build-provenance","architecture":"{s}","release":"26.04","snapshot":{{"id":"release-{s}","base_url":"{s}/"}},"canonical_key_fingerprint":"{s}","sha256sums_signature_verified":true,"artifacts":{{"sha256sums":{{"filename":"SHA256SUMS","sha256":"{s}"}},"sha256sums_signature":{{"filename":"SHA256SUMS.gpg","sha256":"{s}"}},"source_image":{{"filename":"{s}","sha256":"{s}"}},"image_manifest":{{"filename":"{s}","sha256":"{s}"}}}},"disk_layout":{s},"debz":{{"api_commit":"{s}","baseline":{{"source":"canonical-image-dpkg-status","enforcement":"exact-final-closure"}},"transactions":[{{"package":"{s}","exact_lock":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}"}},"transaction_provenance":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}","lock_sha256":"{s}"}}}},{{"package":"{s}","exact_lock":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}"}},"transaction_provenance":{{"filename":"{s}","sha256":"{s}","digest_sha256":"{s}","lock_sha256":"{s}"}}}}]}}}}
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
        diskLayoutProvenance(profile),
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

/// Provenance for the flavors that build their root from scratch with debz.
/// The package roots and the transaction evidence both come from the flavor
/// rather than from one flavor's hardcoded list, because `core` and
/// `baremetal` install different closures and a document that named core's
/// roots under a bare-metal build would describe an image that was never
/// built.
fn writeFreshRootProvenance(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    profile: *const Profile,
    flavor: Flavor,
    source_digest: [64]u8,
    evidence: []const DebzEvidence,
    virtual_size: u64,
    root_free_bytes: u64,
) !void {
    const package_roots = flavor.debzPackages();
    // Count alone would let a transaction for the wrong package pass, so the
    // evidence has to name this flavor's roots in the order they were applied.
    if (evidence.len != package_roots.len) return error.InvalidDebzEvidence;
    for (evidence, package_roots) |item, root| {
        if (!std.mem.eql(u8, item.package, root)) return error.InvalidDebzEvidence;
    }
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try output.writer.print(
        "{{\"schema\":1,\"type\":\"miz-ubuntu2604-build-provenance\",\"architecture\":\"{s}\",\"flavor\":\"{s}\",\"release\":\"26.04\",\"virtual_size\":{d},\"minimum_root_free_bytes\":{d},\"validated_root_free_bytes\":{d},\"snapshot\":{{\"id\":\"release-{s}\",\"base_url\":\"{s}/\"}},\"canonical_key_fingerprint\":\"{s}\",\"sha256sums_signature_verified\":true,\"artifacts\":{{\"sha256sums\":{{\"filename\":\"SHA256SUMS\",\"sha256\":\"{s}\"}},\"sha256sums_signature\":{{\"filename\":\"SHA256SUMS.gpg\",\"sha256\":\"{s}\"}},\"source_image\":{{\"filename\":\"{s}\",\"sha256\":\"{s}\",\"role\":\"signed-gpt-esp-substrate\"}},\"image_manifest\":{{\"filename\":\"{s}\",\"sha256\":\"{s}\"}}}},\"disk_layout\":{s},\"debz\":{{\"api_commit\":\"{s}\",\"baseline\":{{\"source\":\"empty-debz-root\",\"enforcement\":\"exact-final-closure\"}},\"package_roots\":[",
        .{
            @tagName(profile.architecture),
            @tagName(flavor),
            virtual_size,
            core_minimum_root_free_bytes,
            root_free_bytes,
            release,
            release_base,
            canonical_fingerprint_lower,
            sums_sha256,
            sums_signature_sha256,
            profile.source_name,
            source_digest,
            profile.manifest_name,
            profile.manifest_sha256,
            diskLayoutProvenance(profile),
            package_family.debz_api_commit,
        },
    );
    for (package_roots, 0..) |root, index| {
        if (index != 0) try output.writer.writeByte(',');
        try output.writer.print("\"{s}\"", .{root});
    }
    try output.writer.writeAll("],\"transactions\":[");
    for (evidence, 0..) |item, index| {
        if (index != 0) try output.writer.writeByte(',');
        try output.writer.print(
            "{{\"package\":\"{s}\",\"exact_lock\":{{\"filename\":\"{s}\",\"sha256\":\"{s}\",\"digest_sha256\":\"{s}\"}},\"transaction_provenance\":{{\"filename\":\"{s}\",\"sha256\":\"{s}\",\"digest_sha256\":\"{s}\",\"lock_sha256\":\"{s}\"}}}}",
            .{
                item.package,
                std.fs.path.basename(item.lock_path),
                item.lock_sha256,
                item.lock_digest_sha256,
                std.fs.path.basename(item.provenance_path),
                item.provenance_sha256,
                item.provenance_digest_sha256,
                item.provenance_lock_sha256,
            },
        );
    }
    try output.writer.writeAll("]}}\n");
    const document = try output.toOwnedSlice();
    defer allocator.free(document);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = document });
}

fn writeSigningProvenance(
    allocator: Allocator,
    io: Io,
    provenance_dir: []const u8,
    profile: *const Profile,
    flavor: Flavor,
    config: uki_signing.Config,
    certificate: *const uki_signing.Certificate,
    signed: *const uki_signing.SignedUki,
    stub_source_path: []const u8,
    stub_sha256: []const u8,
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
        .type = "miz-uki-signing",
        .architecture = @tagName(profile.architecture),
        .flavor = @tagName(flavor),
        .uki_stub = .{
            .source_path = stub_source_path,
            .sha256 = stub_sha256,
        },
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
        "uki-signing-{s}-{s}.json",
        .{ @tagName(flavor), @tagName(profile.architecture) },
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
    flavor: Flavor,
) ![]u8 {
    var native_root = try openNativeRoot(allocator, io, image_path, work_dir);
    defer native_root.deinit();
    const lock_bytes = try native_root.filesystem.read(
        allocator,
        "/var/lib/miz/ubuntu2604-package-lock.tsv",
        4 * 1024 * 1024,
    );
    defer allocator.free(lock_bytes);
    try validateExactLockRuntime(allocator, lock_bytes, profile, flavor);

    const boot_entries = try native_root.filesystem.list(allocator, "/boot", 4096);
    defer allocator.free(boot_entries);
    var release_name: ?[]u8 = null;
    for (boot_entries) |entry| {
        const name = std.fs.path.basename(entry.path);
        if (std.mem.startsWith(u8, name, "vmlinuz-") and
            std.mem.endsWith(u8, name, flavor.kernelSuffix()))
        {
            if (release_name != null) return error.MultipleExpectedKernels;
            release_name = try allocator.dupe(u8, name["vmlinuz-".len..]);
        }
    }
    const kernel_release = release_name orelse return error.ExpectedKernelMissing;
    errdefer allocator.free(kernel_release);
    const modules_guest = try nativeKernelModulesPath(
        allocator,
        &native_root.filesystem,
        kernel_release,
    );
    defer allocator.free(modules_guest);
    const modules = try native_root.filesystem.list(allocator, modules_guest, 4096);
    defer allocator.free(modules);
    if (modules.len == 0) return error.ExpectedKernelModulesMissing;

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
    if (flavor == .baremetal)
        try requireInitramfsModules(allocator, initrd, &baremetal_required_initramfs_modules);
    if (flavor == .core)
        try requireInitramfsModules(allocator, initrd, &core_required_initramfs_modules);
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

/// The drivers without which the machine cannot find its root or be reached.
///
/// Named separately from `/etc/initramfs-tools/modules` because that file is a
/// request and this is the verification: `MODULES=most` is a heuristic, and an
/// initramfs missing either of these boots into a machine that either cannot
/// mount root or never appears on the network -- two failures that look
/// identical from outside and are diagnosable only at the BMC console.
const baremetal_required_initramfs_modules = [_][]const u8{ "nvme", "r8152" };

/// The Android-container Binder driver core's boot depends on. Bare metal
/// has no such requirement -- it boots no Binder workload at all -- so this
/// stays a `.core`-only list rather than joining the one above.
const core_required_initramfs_modules = [_][]const u8{android_binder_module_name};

/// The gzip header mkinitramfs falls back to, as it appears on disk.
const initramfs_gzip_magic: u16 = 0x8b1f;

/// Decompresses the compressed archive that follows an initramfs's leading
/// uncompressed cpio archives.
///
/// `COMPRESS` in `initramfs.conf` is a request, not a record. `mkinitramfs`
/// checks for the configured compressor on `PATH` and, not finding it, warns
/// and uses gzip instead -- so a root that asks for zstd without installing the
/// `zstd` binary silently produces a gzip initramfs. Sniffing the bytes is
/// therefore the only way to read the archive the machine will actually boot,
/// which is the same reason this check reads the image rather than the
/// configuration that asked for it.
fn decompressInitramfsTail(allocator: Allocator, tail: []const u8) ![]u8 {
    if (tail.len >= 4 and
        std.mem.readInt(u32, tail[0..4], .little) == miz.zstd.zstd_magic)
    {
        const decoded = miz.zstd.decodeAlloc(allocator, tail) catch
            return error.UnreadableInitramfs;
        return decoded.bytes;
    }
    if (tail.len >= 2 and
        std.mem.readInt(u16, tail[0..2], .little) == initramfs_gzip_magic)
    {
        var input: std.Io.Reader = .fixed(tail);
        var output = std.Io.Writer.Allocating.init(allocator);
        errdefer output.deinit();
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var decompress = std.compress.flate.Decompress.init(&input, .gzip, &window);
        _ = decompress.reader.streamRemaining(&output.writer) catch
            return error.UnreadableInitramfs;
        return output.toOwnedSlice();
    }
    return error.UnreadableInitramfs;
}

/// Fails unless every named module is inside the built initramfs.
///
/// The image is the concatenation an initramfs may be: any number of
/// uncompressed early cpio archives, then the compressed main archive. The
/// leading archives are walked directly; whatever follows them is decompressed
/// and walked the same way. Reading the image the builder is about to seal into
/// the UKI, rather than the configuration that asked for it, is the point --
/// the question is what the machine will boot, not what it was told to build.
fn requireInitramfsModules(
    allocator: Allocator,
    image: []const u8,
    required: []const []const u8,
) !void {
    const found = try allocator.alloc(bool, required.len);
    defer allocator.free(found);
    @memset(found, false);

    var early = miz.cpio.Reader.init(image);
    try scanCpioForModules(&early, required, found);
    if (early.offset < image.len) {
        const decoded = try decompressInitramfsTail(allocator, image[early.offset..]);
        defer allocator.free(decoded);
        var payload = miz.cpio.Reader.init(decoded);
        try scanCpioForModules(&payload, required, found);
    }

    for (found, required) |present, name| {
        if (!present) {
            std.debug.print("[ubuntu2604] initramfs is missing {s}\n", .{name});
            return error.InitramfsModuleMissing;
        }
    }
}

fn scanCpioForModules(
    reader: *miz.cpio.Reader,
    required: []const []const u8,
    found: []bool,
) !void {
    while (reader.next() catch return) |entry| {
        const name = std.fs.path.basename(entry.path);
        // `.ko`, or `.ko` plus whatever the distribution compresses modules
        // with -- `.ko.zst` on Ubuntu today, which is not a promise.
        const stem = if (std.mem.indexOf(u8, name, ".ko")) |at| name[0..at] else continue;
        for (required, 0..) |candidate, index| {
            if (std.mem.eql(u8, stem, candidate)) found[index] = true;
        }
    }
}

/// Writes the validated image's guest bytes out again, uncompressed.
///
/// A QCOW2 is the artifact everything else here validates, and it stays that:
/// this is a second copy, produced only after the first has passed every gate,
/// for the one consumer that cannot read the format -- `dd` onto a disk. Going
/// through `miz.Image` rather than a converter keeps the two copies provably
/// the same bytes, and keeps the promise that this builder shells out to
/// nothing. It is staged and renamed for the same reason the QCOW2 is: a copy
/// interrupted partway through must not be left at the name something else is
/// about to write to a disk.
fn writeRawCopy(
    allocator: Allocator,
    io: Io,
    qcow2_path: []const u8,
    raw_path: []const u8,
) !void {
    const staged = try std.fmt.allocPrint(allocator, "{s}.miz-raw-stage", .{raw_path});
    defer allocator.free(staged);
    Dir.cwd().deleteFile(io, staged) catch {};
    errdefer Dir.cwd().deleteFile(io, staged) catch {};

    try copyNativeImage(allocator, io, qcow2_path, staged, .raw);

    var written = try miz.Image.openPathReadOnlyStandalone(io, staged);
    const written_format = written.format;
    const written_size = written.virtual_size;
    written.close(io);
    if (written_format != .raw) return error.InvalidRawCopy;

    var source = try miz.Image.openPathReadOnlyStandalone(io, qcow2_path);
    const source_size = source.virtual_size;
    source.close(io);
    if (written_size != source_size) return error.InvalidRawCopy;

    try Dir.cwd().rename(staged, Dir.cwd(), raw_path, io);
}

fn espPartition(partitions: []const miz.gpt.PartitionEntry) !miz.gpt.PartitionEntry {
    var found: ?miz.gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (!std.mem.eql(u8, &partition.partition_type_guid, &guid.esp)) continue;
        if (found != null) return error.AmbiguousEspPartition;
        found = partition;
    }
    return found orelse error.MissingEspPartition;
}

const Arm64SourceLayout = struct {
    root: miz.gpt.PartitionEntry,
    xbootldr: miz.gpt.PartitionEntry,
    esp: miz.gpt.PartitionEntry,
};

fn partitionGeometryMatches(
    partition: miz.gpt.PartitionEntry,
    expected: PartitionGeometry,
) bool {
    return partition.table_index == expected.table_index and
        partition.first_lba == expected.first_lba and
        partition.last_lba == expected.last_lba;
}

fn findXbootldrPartition(
    partitions: []const miz.gpt.PartitionEntry,
) !miz.gpt.PartitionEntry {
    var found: ?miz.gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (!std.mem.eql(
            u8,
            &partition.partition_type_guid,
            &guid.linux_xbootldr,
        )) continue;
        if (found != null) return error.AmbiguousXbootldrPartition;
        found = partition;
    }
    return found orelse error.MissingXbootldrPartition;
}

fn validateArm64SourceLayout(
    verified: miz.gpt.VerifiedGpt,
    virtual_size: u64,
) !Arm64SourceLayout {
    if (virtual_size == 0 or virtual_size % miz.gpt.sector_size != 0 or
        verified.primary_header.backup_lba + 1 != virtual_size / miz.gpt.sector_size)
    {
        return error.UnexpectedArm64DiskSize;
    }
    if (verified.primary_header.num_partition_entries !=
        miz.gpt.default_num_partition_entries or
        verified.primary_header.partition_entry_size !=
            miz.gpt.partition_entry_size)
    {
        return error.UnexpectedArm64PartitionTableShape;
    }
    if (verified.partitions.len != 3) return error.UnexpectedArm64PartitionCount;

    const root = try findNamedRootPartition(verified.partitions);
    if (root.table_index != 0 or
        !std.mem.eql(u8, &root.partition_type_guid, &guid.linux_root_aarch64) or
        root.first_lba != arm64_root_first_lba or
        root.last_lba != verified.primary_header.last_usable_lba)
    {
        return error.UnexpectedArm64RootGeometry;
    }
    const xbootldr = try findXbootldrPartition(verified.partitions);
    if (!partitionGeometryMatches(xbootldr, arm64_source_xbootldr) or
        !std.mem.eql(
            u8,
            &xbootldr.unique_partition_guid,
            &arm64_source_xbootldr_unique_guid,
        ))
    {
        return error.UnexpectedArm64XbootldrGeometry;
    }
    const esp = try espPartition(verified.partitions);
    if (!partitionGeometryMatches(esp, arm64_source_esp)) {
        return error.UnexpectedArm64EspGeometry;
    }
    if (!partitionNameEquals(xbootldr, "") or !partitionNameEquals(esp, "")) {
        return error.UnexpectedArm64AuxiliaryPartitionName;
    }
    if (std.mem.eql(u8, &verified.primary_header.disk_guid, &guid.nil) or
        std.mem.eql(u8, &root.unique_partition_guid, &guid.nil) or
        std.mem.eql(u8, &esp.unique_partition_guid, &guid.nil) or
        std.mem.eql(u8, &root.unique_partition_guid, &esp.unique_partition_guid))
    {
        return error.InvalidArm64PartitionIdentity;
    }
    if (arm64_final_esp.last_lba >= root.first_lba) {
        return error.Arm64EspWouldOverlapRoot;
    }
    return .{ .root = root, .xbootldr = xbootldr, .esp = esp };
}

fn partitionEntryBytes(
    verified: miz.gpt.VerifiedGpt,
    table_index: u32,
) ![]const u8 {
    const entry_size: usize = @intCast(verified.primary_header.partition_entry_size);
    const start = std.math.mul(
        usize,
        @as(usize, @intCast(table_index)),
        entry_size,
    ) catch return error.InvalidPartitionArrayBounds;
    const end = std.math.add(usize, start, entry_size) catch
        return error.InvalidPartitionArrayBounds;
    if (end > verified.partition_array.len) return error.InvalidPartitionArrayBounds;
    return verified.partition_array[start..end];
}

fn validateArm64FinalLayout(
    verified: miz.gpt.VerifiedGpt,
    virtual_size: u64,
) !miz.gpt.PartitionEntry {
    if (virtual_size == 0 or virtual_size % miz.gpt.sector_size != 0 or
        verified.primary_header.backup_lba + 1 != virtual_size / miz.gpt.sector_size)
    {
        return error.UnexpectedArm64DiskSize;
    }
    if (verified.primary_header.num_partition_entries !=
        miz.gpt.default_num_partition_entries or
        verified.primary_header.partition_entry_size !=
            miz.gpt.partition_entry_size or
        verified.partitions.len != 2)
    {
        return error.UnexpectedFinalArm64PartitionTable;
    }
    const root = try findNamedRootPartition(verified.partitions);
    if (root.table_index != 0 or
        !std.mem.eql(u8, &root.partition_type_guid, &guid.linux_root_aarch64) or
        root.first_lba != arm64_root_first_lba or
        root.last_lba != verified.primary_header.last_usable_lba)
    {
        return error.UnexpectedArm64RootGeometry;
    }
    const esp = try espPartition(verified.partitions);
    if (!partitionGeometryMatches(esp, arm64_final_esp) or
        !partitionNameEquals(esp, ""))
    {
        return error.UnexpectedArm64EspGeometry;
    }
    if (std.mem.eql(u8, &root.unique_partition_guid, &guid.nil) or
        std.mem.eql(u8, &esp.unique_partition_guid, &guid.nil) or
        std.mem.eql(u8, &root.unique_partition_guid, &esp.unique_partition_guid))
    {
        return error.InvalidArm64PartitionIdentity;
    }
    if (!std.mem.allEqual(
        u8,
        try partitionEntryBytes(verified, arm64_source_xbootldr.table_index),
        0,
    )) {
        return error.Arm64XbootldrEntryNotCleared;
    }
    return esp;
}

fn validateArm64PartitionRewrite(
    before: miz.gpt.VerifiedGpt,
    after: miz.gpt.VerifiedGpt,
) !void {
    if (before.primary_header.current_lba != after.primary_header.current_lba or
        before.primary_header.backup_lba != after.primary_header.backup_lba or
        before.primary_header.first_usable_lba != after.primary_header.first_usable_lba or
        before.primary_header.last_usable_lba != after.primary_header.last_usable_lba or
        before.primary_header.partition_entry_lba != after.primary_header.partition_entry_lba or
        before.primary_header.num_partition_entries != after.primary_header.num_partition_entries or
        before.primary_header.partition_entry_size != after.primary_header.partition_entry_size or
        !std.mem.eql(u8, &before.primary_header.disk_guid, &after.primary_header.disk_guid) or
        before.backup_header.current_lba != after.backup_header.current_lba or
        before.backup_header.partition_entry_lba != after.backup_header.partition_entry_lba or
        before.partition_array.len != after.partition_array.len)
    {
        return error.Arm64GptGeometryChanged;
    }

    var index: u32 = 0;
    while (index < before.primary_header.num_partition_entries) : (index += 1) {
        const source = try partitionEntryBytes(before, index);
        const final = try partitionEntryBytes(after, index);
        if (index == arm64_source_xbootldr.table_index) {
            if (!std.mem.allEqual(u8, final, 0))
                return error.Arm64XbootldrEntryNotCleared;
        } else if (index == arm64_source_esp.table_index) {
            if (!std.mem.eql(u8, source[0..40], final[0..40]) or
                !std.mem.eql(u8, source[48..], final[48..]) or
                std.mem.readInt(u64, final[40..48], .little) !=
                    arm64_final_esp.last_lba)
            {
                return error.Arm64EspOpaqueFieldsChanged;
            }
        } else if (!std.mem.eql(u8, source, final)) {
            return error.Arm64UnrelatedPartitionEntryChanged;
        }
    }
}

fn reformatArm64EspFat(
    allocator: Allocator,
    io: Io,
    image: *miz.Image,
    source_esp: miz.gpt.PartitionEntry,
    final_esp: miz.gpt.PartitionEntry,
) !void {
    var source_filesystem = try miz.fat32.open(image, io, .{
        .offset = source_esp.first_lba * miz.gpt.sector_size,
        .length = (source_esp.last_lba - source_esp.first_lba + 1) *
            miz.gpt.sector_size,
    });
    const fat_metadata = source_filesystem.volumeMetadata();
    const final_length = (final_esp.last_lba - final_esp.first_lba + 1) *
        miz.gpt.sector_size;
    try miz.fat32.format(image, io, .{
        .partition_offset = final_esp.first_lba * miz.gpt.sector_size,
        .partition_len = final_length,
        .hidden_sectors = @intCast(final_esp.first_lba),
        .volume_id = fat_metadata.volume_id,
        .volume_label = fat_metadata.volume_label,
    });
    var rebuilt = try miz.fat32.open(image, io, .{
        .offset = final_esp.first_lba * miz.gpt.sector_size,
        .length = final_length,
    });
    const rebuilt_metadata = rebuilt.volumeMetadata();
    if (rebuilt_metadata.volume_id != fat_metadata.volume_id) {
        return error.Arm64EspVolumeIdChanged;
    }
    const entries = try rebuilt.listDirAlloc(io, allocator, "");
    defer miz.fat32.freeDirEntries(allocator, entries);
    if (entries.len != 0) return error.Arm64EspReformatNotEmpty;
}

const Arm64ImageReadContext = struct {
    image: *const miz.Image,
    io: Io,
};

fn readArm64ImageAt(
    context: *const anyopaque,
    io: Io,
    buffer: []u8,
    offset: u64,
) anyerror!usize {
    const read_context: *const Arm64ImageReadContext =
        @ptrCast(@alignCast(context));
    _ = io;
    return read_context.image.pread(read_context.io, buffer, offset);
}

fn validateArm64XbootldrFilesystem(
    allocator: Allocator,
    io: Io,
    image: *const miz.Image,
    xbootldr: miz.gpt.PartitionEntry,
) !void {
    var context = Arm64ImageReadContext{ .image = image, .io = io };
    var reader = try miz.ext4.Reader.openReadOnlySource(
        io,
        image.file,
        .{
            .ctx = &context,
            .read_at_fn = readArm64ImageAt,
        },
        allocator,
        .{ .offset = xbootldr.first_lba * miz.gpt.sector_size },
    );
    defer reader.deinit();
    if (!std.mem.eql(
        u8,
        &reader.uuid,
        &arm64_source_xbootldr_filesystem_uuid,
    ) or !labelEquals(reader.label, "BOOT")) {
        return error.UnexpectedArm64XbootldrFilesystem;
    }
}

fn validateArm64SourceSubstrate(
    allocator: Allocator,
    io: Io,
    image: *miz.Image,
) !void {
    var verified = try miz.gpt.readVerifiedGpt(
        image.*,
        io,
        allocator,
        miz.gpt.default_max_partition_array_bytes,
    );
    defer verified.deinit(allocator);
    const source = try validateArm64SourceLayout(verified, image.virtual_size);
    try validateArm64XbootldrFilesystem(
        allocator,
        io,
        image,
        source.xbootldr,
    );
    _ = try miz.fat32.open(image, io, .{
        .offset = source.esp.first_lba * miz.gpt.sector_size,
        .length = (source.esp.last_lba - source.esp.first_lba + 1) *
            miz.gpt.sector_size,
    });
}

fn rebuildArm64Esp(
    allocator: Allocator,
    io: Io,
    image: *miz.Image,
    expected_virtual_size: u64,
) !miz.gpt.PartitionEntry {
    if (image.virtual_size != expected_virtual_size) {
        return error.UnexpectedArm64DiskSize;
    }
    var before = try miz.gpt.readVerifiedGpt(
        image.*,
        io,
        allocator,
        miz.gpt.default_max_partition_array_bytes,
    );
    defer before.deinit(allocator);
    const source = try validateArm64SourceLayout(before, image.virtual_size);
    try validateArm64XbootldrFilesystem(
        allocator,
        io,
        image,
        source.xbootldr,
    );

    try miz.gpt.rewritePartitionEntries(
        image,
        io,
        allocator,
        before,
        &.{
            .{ .set_last_lba = .{
                .table_index = source.esp.table_index,
                .expected_last_lba = source.esp.last_lba,
                .new_last_lba = arm64_final_esp.last_lba,
            } },
            .{ .clear = .{ .table_index = source.xbootldr.table_index } },
        },
    );

    var after = try miz.gpt.readVerifiedGpt(
        image.*,
        io,
        allocator,
        miz.gpt.default_max_partition_array_bytes,
    );
    defer after.deinit(allocator);
    const esp = try validateArm64FinalLayout(after, image.virtual_size);
    try validateArm64PartitionRewrite(before, after);
    const final_root = try findNamedRootPartition(after.partitions);
    if (!std.mem.eql(
        u8,
        &source.esp.unique_partition_guid,
        &esp.unique_partition_guid,
    ) or !std.mem.eql(
        u8,
        &source.root.unique_partition_guid,
        &final_root.unique_partition_guid,
    )) {
        return error.Arm64PartitionIdentityChanged;
    }

    try reformatArm64EspFat(allocator, io, image, source.esp, esp);
    return esp;
}

fn translateGuestEspCapacity(err: anyerror) anyerror {
    return if (err == error.FilesystemFull) error.GuestEspNoSpace else err;
}

fn expectOnlyEspEntry(
    allocator: Allocator,
    io: Io,
    filesystem: *miz.fat32.FileSystem,
    directory: []const u8,
    expected_name: []const u8,
    expected_kind: miz.fat32.DirEntryKind,
    expected_size: u32,
) !void {
    const entries = try filesystem.listDirAlloc(io, allocator, directory);
    defer miz.fat32.freeDirEntries(allocator, entries);
    if (entries.len != 1 or
        !std.mem.eql(u8, entries[0].name, expected_name) or
        entries[0].kind != expected_kind or
        entries[0].size != expected_size)
    {
        return error.UnexpectedArm64EspContents;
    }
}

fn validateOnlySignedFallback(
    allocator: Allocator,
    io: Io,
    filesystem: *miz.fat32.FileSystem,
    profile: *const Profile,
    signed_size: usize,
) !void {
    const file_size = std.math.cast(u32, signed_size) orelse
        return error.FinalUkiTooLarge;
    try expectOnlyEspEntry(
        allocator,
        io,
        filesystem,
        "",
        "EFI",
        .directory,
        0,
    );
    try expectOnlyEspEntry(
        allocator,
        io,
        filesystem,
        "EFI",
        "BOOT",
        .directory,
        0,
    );
    try expectOnlyEspEntry(
        allocator,
        io,
        filesystem,
        "EFI/BOOT",
        profile.efi_fallback,
        .file,
        file_size,
    );
}

fn insertSignedUki(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    signed_path: []const u8,
    profile: *const Profile,
    expected_virtual_size: u64,
) !void {
    var image = try miz.Image.openPath(io, image_path);
    defer image.close(io);
    const esp = if (profile.architecture == .aarch64)
        try rebuildArm64Esp(allocator, io, &image, expected_virtual_size)
    else blk: {
        const parsed = try miz.gpt.readGpt(image, io, allocator);
        defer allocator.free(parsed.partitions);
        break :blk try espPartition(parsed.partitions);
    };
    var filesystem = try miz.fat32.open(&image, io, .{
        .offset = esp.first_lba * miz.gpt.sector_size,
        .length = (esp.last_lba - esp.first_lba + 1) * miz.gpt.sector_size,
    });
    filesystem.createDir(io, "EFI/BOOT") catch |err| {
        if (err == error.FilesystemFull) {
            std.debug.print(
                "guest ESP capacity exhausted while creating EFI/BOOT\n",
                .{},
            );
            return translateGuestEspCapacity(err);
        }
        return err;
    };
    const signed = try Dir.cwd().readFileAlloc(io, signed_path, allocator, .limited(256 * 1024 * 1024));
    defer allocator.free(signed);
    const fallback = try std.fmt.allocPrint(allocator, "EFI/BOOT/{s}", .{profile.efi_fallback});
    defer allocator.free(fallback);
    // Older images carried a duplicate under EFI/Linux. Nothing loads it -- that is the Boot Loader
    // Specification type 2 directory, which needs a boot loader to scan it, and this image ships
    // none -- and at 62 MiB the copy no longer fits beside the one that boots.
    const stale_named = try std.fmt.allocPrint(allocator, "EFI/Linux/{s}", .{profile.efi_fallback});
    defer allocator.free(stale_named);
    for ([_][]const u8{ fallback, stale_named }) |path| {
        filesystem.deletePath(io, path) catch |err| switch (err) {
            error.PathNotFound => {},
            else => return err,
        };
    }
    filesystem.writeFile(io, fallback, signed) catch |err| {
        if (err == error.FilesystemFull) {
            std.debug.print(
                "guest ESP capacity exhausted while writing {s} ({d} bytes)\n",
                .{ fallback, signed.len },
            );
            return translateGuestEspCapacity(err);
        }
        return err;
    };
    if (profile.architecture == .aarch64) {
        try validateOnlySignedFallback(
            allocator,
            io,
            &filesystem,
            profile,
            signed.len,
        );
    }
}

fn validateFinalNativeImage(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    signed_bytes: []const u8,
    profile: *const Profile,
    expected_cmdline: []const u8,
) !void {
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var parsed = try miz.gpt.readVerifiedGpt(
        image,
        io,
        allocator,
        miz.gpt.default_max_partition_array_bytes,
    );
    defer parsed.deinit(allocator);
    const esp = if (profile.architecture == .aarch64)
        try validateArm64FinalLayout(parsed, image.virtual_size)
    else
        try espPartition(parsed.partitions);
    var filesystem = try miz.fat32.open(&image, io, .{
        .offset = esp.first_lba * miz.gpt.sector_size,
        .length = (esp.last_lba - esp.first_lba + 1) * miz.gpt.sector_size,
    });
    const fallback = try std.fmt.allocPrint(allocator, "EFI/BOOT/{s}", .{profile.efi_fallback});
    defer allocator.free(fallback);
    const fallback_bytes = try filesystem.readFileAlloc(io, allocator, fallback);
    defer allocator.free(fallback_bytes);
    try validateUkiBytes(fallback_bytes, signed_bytes, profile);
    try validateUkiContract(allocator, fallback_bytes, expected_cmdline);
    try validateNoStaleNamedUki(allocator, io, &filesystem, profile);
    if (profile.architecture == .aarch64) {
        try validateOnlySignedFallback(
            allocator,
            io,
            &filesystem,
            profile,
            signed_bytes.len,
        );
    }
}

/// The duplicate under EFI/Linux is gone, and it has to stay gone. A leftover from an earlier build
/// would be a second bootable-looking UKI that nothing keeps in step with the one that actually
/// boots, and on this ESP the two do not fit together anyway.
fn validateNoStaleNamedUki(
    allocator: Allocator,
    io: Io,
    filesystem: *miz.fat32.FileSystem,
    profile: *const Profile,
) !void {
    const entries = filesystem.listDirAlloc(io, allocator, "EFI/Linux") catch |err| switch (err) {
        error.PathNotFound => return,
        else => return err,
    };
    defer miz.fat32.freeDirEntries(allocator, entries);
    for (entries) |entry| {
        if (entry.kind != .file) continue;
        // FAT is case-insensitive, so a stale copy can resurface under any spelling.
        if (std.ascii.eqlIgnoreCase(entry.name, profile.efi_fallback))
            return error.StaleNamedUkiPresent;
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = parseArgs(argv[1..]) catch |err| {
        std.debug.print("error: {s}\n{s}", .{ @errorName(err), help });
        std.process.exit(1);
    };
    const architecture = args.architecture orelse {
        std.debug.print("error: --architecture is required\n", .{});
        std.process.exit(1);
    };
    // The NVIDIA BaseOS kernel is published for arm64 alone, because the
    // machines it exists for are arm64. Saying so here turns a confusing
    // package-resolution failure hours into the build into an immediate one.
    if (args.flavor == .baremetal and architecture != .aarch64) {
        std.debug.print("error: the baremetal flavor is aarch64 only\n", .{});
        std.process.exit(1);
    }
    var timing = image_phase_timing.Recorder.init(
        allocator,
        init.io,
        args.timing_output,
    );
    var total_runtime = timing.begin(.total_runtime, null);
    buildImage(init, args, architecture, &timing) catch |err| {
        total_runtime.fail(@errorName(err));
        timing.write(.failure) catch |timing_err| {
            const failed_phase = timing.failedPhase() orelse .total_runtime;
            std.debug.print(
                "error: image phase {s} failed with {s}; timing output failed with {s}\n",
                .{ @tagName(failed_phase), @errorName(err), @errorName(timing_err) },
            );
            return timing_err;
        };
        return err;
    };
    total_runtime.succeed();
    try timing.write(.success);
}

fn buildImage(
    init: std.process.Init,
    args: Args,
    architecture: Architecture,
    timing: *image_phase_timing.Recorder,
) !void {
    const allocator = init.gpa;
    const io = init.io;
    const profile = profileFor(architecture);
    var input_acquisition = timing.begin(.input_acquisition, null);
    defer input_acquisition.end();
    errdefer |err| input_acquisition.fail(@errorName(err));
    const work_dir = args.work_dir orelse profile.workDirFor(args.flavor);
    const output = args.output orelse profile.outputFor(args.flavor);
    try Dir.cwd().createDirPath(io, work_dir);
    const allocated_provenance_dir = if (args.provenance_dir == null)
        try std.fs.path.join(allocator, &.{ work_dir, "internal-provenance" })
    else
        null;
    defer if (allocated_provenance_dir) |path| allocator.free(path);
    const provenance_dir = args.provenance_dir orelse allocated_provenance_dir.?;
    try Dir.cwd().deleteTree(io, provenance_dir);
    try Dir.cwd().createDirPath(io, provenance_dir);

    var https = if (args.proxy) |proxy|
        try artifact_pipeline.NativeHttpsDownloader.initProxied(allocator, io, proxy)
    else
        artifact_pipeline.NativeHttpsDownloader.init(allocator, io);
    defer https.deinit();
    const downloader = https.downloader();

    const sums_path = try std.fs.path.join(allocator, &.{ work_dir, "SHA256SUMS" });
    defer allocator.free(sums_path);
    const signature_path = try std.fs.path.join(allocator, &.{ work_dir, "SHA256SUMS.gpg" });
    defer allocator.free(signature_path);
    try acquire(allocator, io, release_base ++ "/SHA256SUMS", sums_path, sums_sha256, sums_max_size, downloader, args.offline);
    try acquire(allocator, io, release_base ++ "/SHA256SUMS.gpg", signature_path, sums_signature_sha256, signature_max_size, downloader, args.offline);
    try verifyCanonicalPublication(allocator, io, sums_path, signature_path);
    const sums = try Dir.cwd().readFileAlloc(io, sums_path, allocator, .limited(sums_max_size));
    defer allocator.free(sums);
    try requireSha256SumsEntry(sums, profile.source_name, profile.source_sha256);
    try requireSha256SumsEntry(sums, profile.manifest_name, profile.manifest_sha256);

    const manifest_path = try std.fs.path.join(allocator, &.{ work_dir, profile.manifest_name });
    defer allocator.free(manifest_path);
    const manifest_url = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ release_base, profile.manifest_name });
    defer allocator.free(manifest_url);
    try acquire(allocator, io, manifest_url, manifest_path, profile.manifest_sha256, manifest_max_size, downloader, args.offline);
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
        try acquire(allocator, io, url, path, profile.source_sha256, source_max_size, downloader, args.offline);
        break :blk path;
    };
    defer if (args.source == null) allocator.free(source_path);
    const source_metadata = try artifact_pipeline.hashFile(io, source_path);
    if (!std.mem.eql(u8, &source_metadata.sha256, &(try artifact_pipeline.parseSha256(profile.source_sha256))))
        return error.ChecksumMismatch;
    if (args.preflight_only) {
        input_acquisition.succeed();
        return;
    }

    const config = try signingConfig(args);
    const authorized_key: ?[]u8 = if (args.authorized_key) |path|
        try readAuthorizedKey(allocator, io, path)
    else
        null;
    defer if (authorized_key) |key| allocator.free(key);
    input_acquisition.succeed();

    const mutable = try std.fs.path.join(allocator, &.{ work_dir, "customized.qcow2" });
    defer allocator.free(mutable);
    var source_setup = timing.begin(.source_qcow2_setup, null);
    defer source_setup.end();
    errdefer |err| source_setup.fail(@errorName(err));
    Dir.cwd().deleteFile(io, mutable) catch {};
    var source_image = try miz.Image.openPathReadOnlyStandalone(io, source_path);
    defer source_image.close(io);
    if (profile.architecture == .aarch64) {
        try validateArm64SourceSubstrate(allocator, io, &source_image);
    }
    if (args.flavor.freshRoot() and source_image.virtual_size != core_virtual_size)
        return error.UnexpectedCoreSubstrateSize;
    if (args.size < source_image.virtual_size) return error.ImageTooSmall;
    var mutable_image = try miz.Image.createExclusive(
        io,
        mutable,
        .qcow2,
        source_image.virtual_size,
        .{},
    );
    _ = try miz.copyAll(io, source_image, &mutable_image, allocator);
    mutable_image.close(io);
    if (args.size > source_image.virtual_size) {
        _ = try miz.root_resize.growExistingQcow2(
            allocator,
            io,
            mutable,
            .{
                .target_size = args.size,
                .filesystem_label = miz.root_resize.default_filesystem_label,
            },
        );
    }
    source_setup.succeed();
    var debz_customization = try customizeRootWithDebz(
        allocator,
        io,
        timing,
        profile,
        args.flavor,
        mutable,
        work_dir,
        provenance_dir,
        args.mizinit,
        args.azagent,
        args.proxy,
        args.debz_cache,
        args.debz_input_dir,
        args.debz_lock_dir,
        args.offline,
        authorized_key,
    );
    defer debz_customization.deinit(allocator);

    var uki_assembly = timing.begin(.uki_assembly, null);
    defer uki_assembly.end();
    errdefer |err| uki_assembly.fail(@errorName(err));
    const extract_dir = try std.fs.path.join(allocator, &.{ work_dir, "uki-input" });
    defer allocator.free(extract_dir);
    const release_name = try extractNativeBootInputs(
        allocator,
        io,
        mutable,
        work_dir,
        extract_dir,
        profile,
        args.flavor,
    );
    defer allocator.free(release_name);

    const kernel_host = try std.fmt.allocPrint(allocator, "{s}/vmlinuz-{s}", .{ extract_dir, release_name });
    defer allocator.free(kernel_host);
    const initrd_host = try std.fmt.allocPrint(allocator, "{s}/initrd.img-{s}", .{ extract_dir, release_name });
    defer allocator.free(initrd_host);
    const os_release_host = try std.fs.path.join(allocator, &.{ extract_dir, "os-release" });
    defer allocator.free(os_release_host);
    const root_partition_guid = try rootPartitionGuid(allocator, io, mutable, profile);
    const cmdline = try ukiCmdline(allocator, root_partition_guid, profile, args.flavor);
    defer allocator.free(cmdline);

    const stub_path = args.uki_stub orelse profile.uki_stub_host_path;
    const stub_bytes = try readUkiStub(allocator, io, stub_path);
    defer allocator.free(stub_bytes);
    if (try peMachine(stub_bytes) != profile.pe_machine) return error.WrongStubArchitecture;
    const stub_sha256 = artifact_pipeline.formatSha256(artifact_pipeline.sha256Bytes(stub_bytes));

    const kernel_bytes = try Dir.cwd().readFileAlloc(io, kernel_host, allocator, .limited(miz.uki.limits.max_linux_size));
    defer allocator.free(kernel_bytes);
    var kernel_payload = try uki_kernel_payload.normalize(
        allocator,
        profile.architecture,
        kernel_bytes,
        miz.uki.limits.max_linux_size,
    );
    defer kernel_payload.deinit(allocator);
    const initrd_bytes = try Dir.cwd().readFileAlloc(io, initrd_host, allocator, .limited(miz.uki.limits.max_initrd_size));
    defer allocator.free(initrd_bytes);
    const os_release_bytes = try Dir.cwd().readFileAlloc(io, os_release_host, allocator, .limited(miz.uki.limits.max_os_release_size));
    defer allocator.free(os_release_bytes);

    const unsigned_bytes = try miz.uki.generate(allocator, .{
        .stub = stub_bytes,
        .linux = kernel_payload.bytes,
        .initrd = initrd_bytes,
        .cmdline = cmdline,
        .os_release = os_release_bytes,
        .uname = release_name,
    });
    defer allocator.free(unsigned_bytes);
    if (try peMachine(unsigned_bytes) != profile.pe_machine) return error.WrongUkiArchitecture;
    const unsigned_uki = try std.fs.path.join(allocator, &.{ work_dir, "ubuntu2604.unsigned.efi" });
    defer allocator.free(unsigned_uki);
    try Dir.cwd().writeFile(io, .{ .sub_path = unsigned_uki, .data = unsigned_bytes });
    uki_assembly.succeed();

    var uki_signing_phase = timing.begin(.uki_signing, null);
    defer uki_signing_phase.end();
    errdefer |err| uki_signing_phase.fail(@errorName(err));
    const signing_scratch = try std.fs.path.join(allocator, &.{ work_dir, "signing" });
    defer allocator.free(signing_scratch);
    try uki_signing.prepareScratchDirectory(io, signing_scratch);
    var certificate = try uki_signing.prepareCertificate(allocator, io, config);
    defer certificate.deinit(allocator);
    var signed = try uki_signing.signUkiAlloc(
        allocator,
        io,
        config,
        signing_scratch,
        init.environ_map,
        0,
        @tagName(profile.architecture),
        @tagName(args.flavor),
        unsigned_bytes,
    );
    defer signed.deinit(allocator);
    const signed_path = try std.fs.path.join(allocator, &.{ work_dir, profile.efi_fallback });
    defer allocator.free(signed_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = signed_path, .data = signed.bytes });
    try uki_signing.verifyBytes(allocator, io, config, signed.bytes);
    uki_signing_phase.succeed();

    var qcow2_finalization = timing.begin(.qcow2_finalization, null);
    defer qcow2_finalization.end();
    errdefer |err| qcow2_finalization.fail(@errorName(err));
    try insertSignedUki(
        allocator,
        io,
        mutable,
        signed_path,
        profile,
        args.size,
    );
    try finalizeCompressedQcow2(allocator, io, mutable, output);
    try validateFinalQcow2(io, output, args.size);
    try validateFinalNativeImage(allocator, io, output, signed.bytes, profile, cmdline);
    qcow2_finalization.succeed();
    var final_image_validation = timing.begin(.final_image_validation, null);
    defer final_image_validation.end();
    errdefer |err| final_image_validation.fail(@errorName(err));
    var final_root = try openNativeRoot(allocator, io, output, work_dir);
    defer final_root.deinit();
    const os_release = try final_root.filesystem.read(allocator, "/etc/os-release", 64 * 1024);
    defer allocator.free(os_release);
    if (std.mem.indexOf(u8, os_release, "VERSION_ID=\"26.04\"") == null) return error.WrongGuestRelease;
    const final_lock = try final_root.filesystem.read(allocator, "/var/lib/miz/ubuntu2604-package-lock.tsv", 4 * 1024 * 1024);
    defer allocator.free(final_lock);
    try validateExactLockRuntime(allocator, final_lock, profile, args.flavor);
    if (profile.architecture == .aarch64 and args.flavor == .full) {
        const fstab = try final_root.filesystem.read(allocator, "/etc/fstab", 1024 * 1024);
        defer allocator.free(fstab);
        try validateArm64BootFstabRetired(fstab);
    }
    if (args.flavor.freshRoot()) try validateCoreRoot(
        allocator,
        io,
        &final_root.filesystem,
        profile,
        args.flavor,
        debz_customization.evidence[0..debz_customization.evidence_count],
    );
    if (try peMachine(signed.bytes) != profile.pe_machine) return error.WrongUkiArchitecture;
    final_image_validation.succeed();
    if (args.raw_output) |raw_path| {
        var raw_materialization = timing.begin(.raw_image_materialization, null);
        defer raw_materialization.end();
        errdefer |err| raw_materialization.fail(@errorName(err));
        try writeRawCopy(allocator, io, output, raw_path);
        raw_materialization.succeed();
    } else {
        timing.skip(.raw_image_materialization, null);
    }
    var provenance_output = timing.begin(.provenance_output, null);
    defer provenance_output.end();
    errdefer |err| provenance_output.fail(@errorName(err));
    try writeSigningProvenance(
        allocator,
        io,
        provenance_dir,
        profile,
        args.flavor,
        config,
        &certificate,
        &signed,
        stub_path,
        &stub_sha256,
    );

    const provenance_path = try std.fs.path.join(allocator, &.{ provenance_dir, "ubuntu2604-build-provenance.json" });
    defer allocator.free(provenance_path);
    if (args.flavor.freshRoot()) {
        try writeFreshRootProvenance(
            allocator,
            io,
            provenance_path,
            profile,
            args.flavor,
            artifact_pipeline.formatSha256(source_metadata.sha256),
            debz_customization.evidence[0..debz_customization.evidence_count],
            args.size,
            debz_customization.root_free_bytes,
        );
    } else {
        try writeProvenance(
            allocator,
            io,
            provenance_path,
            profile,
            artifact_pipeline.formatSha256(source_metadata.sha256),
            debz_customization.evidence[0..debz_customization.evidence_count],
        );
    }
    provenance_output.succeed();
}

/// The `/boot` scan that `extractNativeBootInputs` performs, separated so it
/// can be tested without a built image.
fn findKernelRelease(listing: []const u8, suffix: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, listing, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "vmlinuz-") and std.mem.endsWith(u8, line, suffix))
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

fn arm64PartitionFixture(
    table_index: u32,
    partition_type_guid: guid.Guid,
    unique_partition_guid: guid.Guid,
    first_lba: u64,
    last_lba: u64,
    name: []const u8,
) miz.gpt.PartitionEntry {
    var partition: miz.gpt.PartitionEntry = .{
        .table_index = table_index,
        .partition_type_guid = partition_type_guid,
        .unique_partition_guid = unique_partition_guid,
        .first_lba = first_lba,
        .last_lba = last_lba,
    };
    for (name, 0..) |byte, index| partition.name_utf16le[index] = byte;
    return partition;
}

fn arm64VerifiedFixture(
    partitions: []miz.gpt.PartitionEntry,
    partition_array: []u8,
    virtual_size: u64,
) miz.gpt.VerifiedGpt {
    const total_sectors = virtual_size / miz.gpt.sector_size;
    const last_usable_lba = total_sectors - 2 - miz.gpt.partition_array_sectors;
    const array_crc = std.hash.crc.Crc32.hash(partition_array);
    const primary = miz.gpt.Header{
        .current_lba = 1,
        .backup_lba = total_sectors - 1,
        .first_usable_lba = 2 + miz.gpt.partition_array_sectors,
        .last_usable_lba = last_usable_lba,
        .disk_guid = guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        .partition_entry_lba = 2,
        .partition_array_crc32 = array_crc,
    };
    const backup = miz.gpt.Header{
        .current_lba = total_sectors - 1,
        .backup_lba = 1,
        .first_usable_lba = primary.first_usable_lba,
        .last_usable_lba = last_usable_lba,
        .disk_guid = primary.disk_guid,
        .partition_entry_lba = total_sectors - 1 -
            miz.gpt.partition_array_sectors,
        .partition_array_crc32 = array_crc,
    };
    return .{
        .primary_header = primary,
        .backup_header = backup,
        .primary_header_sector = primary.encode(),
        .backup_header_sector = backup.encode(),
        .partition_array = partition_array,
        .partitions = partitions,
        .protective_mbr_sector = @splat(0),
        .protective_entry_index = 0,
    };
}

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

test "Arm64 ESP source and final geometry are exact and reject layout drift" {
    const virtual_size = default_virtual_size;
    const total_sectors = virtual_size / miz.gpt.sector_size;
    const last_usable_lba = total_sectors - 2 - miz.gpt.partition_array_sectors;
    var source_partitions = [_]miz.gpt.PartitionEntry{
        arm64PartitionFixture(
            0,
            guid.linux_root_aarch64,
            guid.parse("11111111-1111-1111-1111-111111111111"),
            arm64_root_first_lba,
            last_usable_lba,
            "cloudimg-rootfs",
        ),
        arm64PartitionFixture(
            arm64_source_xbootldr.table_index,
            guid.linux_xbootldr,
            arm64_source_xbootldr_unique_guid,
            arm64_source_xbootldr.first_lba,
            arm64_source_xbootldr.last_lba,
            "",
        ),
        arm64PartitionFixture(
            arm64_source_esp.table_index,
            guid.esp,
            guid.parse("33333333-3333-3333-3333-333333333333"),
            arm64_source_esp.first_lba,
            arm64_source_esp.last_lba,
            "",
        ),
    };
    var source_array: [
        miz.gpt.default_num_partition_entries *
            miz.gpt.partition_entry_size
    ]u8 = @splat(0);
    var source = arm64VerifiedFixture(
        &source_partitions,
        &source_array,
        virtual_size,
    );
    const validated = try validateArm64SourceLayout(source, virtual_size);
    try std.testing.expectEqual(
        arm64_source_xbootldr.table_index,
        validated.xbootldr.table_index,
    );
    try std.testing.expectEqual(arm64_source_esp.last_lba, validated.esp.last_lba);

    source_partitions[1].last_lba -= 1;
    try std.testing.expectError(
        error.UnexpectedArm64XbootldrGeometry,
        validateArm64SourceLayout(source, virtual_size),
    );
    source_partitions[1].last_lba = arm64_source_xbootldr.last_lba;
    source_partitions[2].first_lba += 1;
    try std.testing.expectError(
        error.UnexpectedArm64EspGeometry,
        validateArm64SourceLayout(source, virtual_size),
    );
    source_partitions[2].first_lba = arm64_source_esp.first_lba;
    source.partitions = source_partitions[0..2];
    try std.testing.expectError(
        error.UnexpectedArm64PartitionCount,
        validateArm64SourceLayout(source, virtual_size),
    );

    var final_partitions = [_]miz.gpt.PartitionEntry{
        source_partitions[0],
        arm64PartitionFixture(
            arm64_final_esp.table_index,
            guid.esp,
            source_partitions[2].unique_partition_guid,
            arm64_final_esp.first_lba,
            arm64_final_esp.last_lba,
            "",
        ),
    };
    var final_array: [
        miz.gpt.default_num_partition_entries *
            miz.gpt.partition_entry_size
    ]u8 = @splat(0);
    const final = arm64VerifiedFixture(
        &final_partitions,
        &final_array,
        virtual_size,
    );
    const final_esp = try validateArm64FinalLayout(final, virtual_size);
    try std.testing.expectEqual(
        @as(u64, 512 * 1024 * 1024),
        (final_esp.last_lba - final_esp.first_lba + 1) *
            miz.gpt.sector_size,
    );
    final_array[
        arm64_source_xbootldr.table_index *
            miz.gpt.partition_entry_size
    ] = 1;
    try std.testing.expectError(
        error.Arm64XbootldrEntryNotCleared,
        validateArm64FinalLayout(final, virtual_size),
    );
}

test "Arm64 FAT rebuild preserves volume ID and leaves only signed fallback" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-ubuntu2604-arm64-esp.raw";
    defer Dir.cwd().deleteFile(io, path) catch {};

    const source_length = (arm64_source_esp.last_lba -
        arm64_source_esp.first_lba + 1) * miz.gpt.sector_size;
    const final_length = (arm64_final_esp.last_lba -
        arm64_final_esp.first_lba + 1) * miz.gpt.sector_size;
    const signed_size: u64 = 143_438_240;
    const file_sizes = [_]u64{signed_size};
    const directory_slots = [_]u32{
        miz.fat32.root_directory_overhead_slots +
            try miz.fat32.nameSlotCount("EFI"),
        miz.fat32.subdirectory_overhead_slots +
            try miz.fat32.nameSlotCount("BOOT"),
        miz.fat32.subdirectory_overhead_slots +
            try miz.fat32.nameSlotCount("BOOTAA64.EFI"),
    };
    const minimum = try miz.fat32.minimumVolumeLength(
        .{
            .file_sizes = &file_sizes,
            .directory_slots = &directory_slots,
        },
        .{},
    );
    try std.testing.expect(minimum > source_length);
    try std.testing.expect(minimum <= final_length);
    try std.testing.expectEqual(@as(u64, 512 * 1024 * 1024), final_length);

    const image_length = (arm64_final_esp.last_lba + 1) *
        miz.gpt.sector_size;
    var image = try miz.Image.create(io, path, .raw, image_length, .{});
    defer image.close(io);
    try miz.fat32.format(&image, io, .{
        .partition_offset = arm64_source_esp.first_lba * miz.gpt.sector_size,
        .partition_len = source_length,
        .hidden_sectors = @intCast(arm64_source_esp.first_lba),
        .volume_id = 0x1234_5678,
        .volume_label = "CANONICAL  ".*,
    });
    var source_filesystem = try miz.fat32.open(&image, io, .{
        .offset = arm64_source_esp.first_lba * miz.gpt.sector_size,
        .length = source_length,
    });
    try source_filesystem.createDir(io, "EFI/ubuntu");
    try source_filesystem.writeFile(io, "EFI/ubuntu/grub.cfg", "stale grub");

    const source_esp = arm64PartitionFixture(
        arm64_source_esp.table_index,
        guid.esp,
        guid.parse("33333333-3333-3333-3333-333333333333"),
        arm64_source_esp.first_lba,
        arm64_source_esp.last_lba,
        "",
    );
    const final_esp = arm64PartitionFixture(
        arm64_final_esp.table_index,
        guid.esp,
        source_esp.unique_partition_guid,
        arm64_final_esp.first_lba,
        arm64_final_esp.last_lba,
        "",
    );
    try reformatArm64EspFat(
        allocator,
        io,
        &image,
        source_esp,
        final_esp,
    );

    var rebuilt = try miz.fat32.open(&image, io, .{
        .offset = arm64_final_esp.first_lba * miz.gpt.sector_size,
        .length = final_length,
    });
    try std.testing.expectEqual(
        @as(u32, 0x1234_5678),
        rebuilt.volumeMetadata().volume_id,
    );
    const empty = try rebuilt.listDirAlloc(io, allocator, "");
    defer miz.fat32.freeDirEntries(allocator, empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    const signed = "signed Arm64 UKI";
    try rebuilt.createDir(io, "EFI/BOOT");
    try rebuilt.writeFile(io, "EFI/BOOT/BOOTAA64.EFI", signed);
    try validateOnlySignedFallback(
        allocator,
        io,
        &rebuilt,
        profileFor(.aarch64),
        signed.len,
    );
    try rebuilt.createDir(io, "EFI/ubuntu");
    try std.testing.expectError(
        error.UnexpectedArm64EspContents,
        validateOnlySignedFallback(
            allocator,
            io,
            &rebuilt,
            profileFor(.aarch64),
            signed.len,
        ),
    );
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
            false,
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
        &.{"linux-azure"},
        "/root-stage",
        "/published",
        &.{"/inputs/ubuntu.sources"},
        &.{"/inputs/ubuntu.gpg"},
        "/cache",
        "/state",
        "/state/linux-azure.lock",
        .require_locked,
        null,
        false,
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
    try std.testing.expect(amd64.inputs.deadline_ms == null);
    const arm64 = packageFamilyRequest(
        .customize,
        profileFor(.aarch64),
        &.{"walinuxagent"},
        "/root-stage",
        "/published",
        &.{"/inputs/ubuntu.sources"},
        &.{"/inputs/ubuntu.gpg"},
        "/cache",
        "/state",
        "/state/walinuxagent.lock",
        .require_locked,
        // A proxy is an input like any other: it is either stated or absent,
        // never inherited from the environment.
        "http://127.0.0.1:18080",
        false,
    );
    try std.testing.expectEqualStrings("http://127.0.0.1:18080", arm64.inputs.proxy.?);
    try std.testing.expect(amd64.inputs.proxy == null);
    try std.testing.expectEqual(package_family.Architecture.arm64, arm64.inputs.architecture);
    try std.testing.expectEqual(
        package_family.InstalledBaselinePolicy.require_locked,
        arm64.inputs.installed_baseline,
    );
    try std.testing.expectEqual(@as(usize, 0), arm64.inputs.source_paths.len);
    try std.testing.expectEqualStrings("/inputs/ubuntu.sources", arm64.inputs.config_paths[0]);
    try std.testing.expectEqualStrings("/state/walinuxagent.lock", arm64.inputs.lock_input_path.?);
    try std.testing.expect(arm64.inputs.lock_output_path == null);
    try std.testing.expect(arm64.inputs.deadline_ms == null);

    const core_create = packageFamilyRequest(
        .create,
        profileFor(.x86_64),
        &.{"ubuntu-minimal"},
        "/root-stage",
        "/published",
        &.{"/inputs/ubuntu.sources"},
        &.{"/inputs/ubuntu.gpg"},
        "/cache",
        "/state",
        "/state/ubuntu-minimal.lock",
        .none,
        null,
        false,
    );
    try std.testing.expectEqual(package_family.Operation.create, core_create.operation);
    try std.testing.expectEqual(
        package_family.InstalledBaselinePolicy.none,
        core_create.inputs.installed_baseline,
    );
    const offline = packageFamilyRequest(
        .customize,
        profileFor(.aarch64),
        &.{"sudo"},
        "/root-stage",
        "/published",
        &.{"/inputs/ubuntu.sources"},
        &.{"/inputs/ubuntu.gpg"},
        "/cache",
        "/state",
        "/state/sudo.lock",
        .require_locked,
        null,
        true,
    );
    try std.testing.expectEqual(package_family.CacheMode.offline, offline.inputs.cache_mode);
}

test "package-family requests reject keyrings overlapping staging and accept the external copy" {
    const profile = profileFor(.aarch64);
    const resolve_root = "/work/official-root";
    const resolve_published = "/work/debz-linux-azure/resolve-published-unused";
    const external_keyring = "/work/ubuntu-archive-keyring.gpg";
    const source_config = "/work/ubuntu-snapshot.json";
    const cache = "/work/debz-linux-azure/cache";
    const state = "/work/debz-linux-azure/state";
    const lock = "/work/debz-linux-azure/exact-lock.json";

    // The corrected requests resolve the keyring from an external host copy and
    // pass the shared separation policy for both resolve and customize.
    const good_resolve = packageFamilyRequest(.resolve_lock, profile, &.{"linux-azure"}, resolve_root, resolve_published, &.{source_config}, &.{external_keyring}, cache, state, lock, .require_locked, null, false);
    try assertRequestSeparation(good_resolve);
    try std.testing.expectEqualStrings(external_keyring, good_resolve.inputs.keyring_paths[0]);
    const good_customize = packageFamilyRequest(.customize, profile, &.{"linux-azure"}, "/work/root-stage-0", "/work/root-debz-0", &.{source_config}, &.{external_keyring}, cache, state, lock, .require_locked, null, false);
    try assertRequestSeparation(good_customize);
    try std.testing.expectEqualStrings(external_keyring, good_customize.inputs.keyring_paths[0]);

    // The original blocker: a keyring read from inside the resolve root_stage is
    // rejected with the exact boundary message the protected aarch64 builder hit.
    const guest_keyring = resolve_root ++ "/usr/share/keyrings/ubuntu-archive-keyring.gpg";
    const bad_resolve = packageFamilyRequest(.resolve_lock, profile, &.{"linux-azure"}, resolve_root, resolve_published, &.{source_config}, &.{guest_keyring}, cache, state, lock, .require_locked, null, false);
    try std.testing.expectError(error.PackageFamilySeparationViolation, assertRequestSeparation(bad_resolve));
    try std.testing.expectEqualStrings(
        "debian keyring paths must be absolute and outside staging",
        package_family.requestViolation(bad_resolve).?,
    );

    const staged_keyring = "/work/root-stage-0/usr/share/keyrings/ubuntu-archive-keyring.gpg";
    const bad_customize = packageFamilyRequest(.customize, profile, &.{"linux-azure"}, "/work/root-stage-0", "/work/root-debz-0", &.{source_config}, &.{staged_keyring}, cache, state, lock, .require_locked, null, false);
    try std.testing.expectError(error.PackageFamilySeparationViolation, assertRequestSeparation(bad_customize));

    // A keyring under the publication root is rejected too, so a published guest
    // can never mutate the trusted input after debz consumes it.
    const published_keyring = "/work/root-debz-0/usr/share/keyrings/ubuntu-archive-keyring.gpg";
    const published_overlap = packageFamilyRequest(.customize, profile, &.{"linux-azure"}, "/work/root-stage-0", "/work/root-debz-0", &.{source_config}, &.{published_keyring}, cache, state, lock, .require_locked, null, false);
    try std.testing.expectError(error.PackageFamilySeparationViolation, assertRequestSeparation(published_overlap));
    try std.testing.expectEqualStrings(
        "debian keyring paths must be outside publication",
        package_family.requestViolation(published_overlap).?,
    );
}

test "the shared debz cache outlives per-stage deletion and stays outside every publication" {
    const profile = profileFor(.aarch64);
    const work_dir = "/work";
    const shared_cache = work_dir ++ "/debz-cache";

    // The per-stage transaction directory is deleted at the top of every stage.
    // The cache has to sit beside it, not inside it, or each stage would throw
    // away the objects the previous one just fetched. Both flavors share the
    // `debz-` prefix, so a package literally named `cache` would collide with
    // the shared directory and be deleted along with its own stage.
    for (&[_][]const []const u8{ &core_debz_packages, &baremetal_debz_packages }) |packages| {
        for (packages) |package| {
            var buffer: [128]u8 = undefined;
            const transaction_dir = try std.fmt.bufPrint(&buffer, "{s}/debz-{s}", .{ work_dir, package });
            try std.testing.expect(!package_family.pathsOverlap(transaction_dir, shared_cache));
        }
    }

    // Sharing one cache across stages must not weaken the boundary: every
    // request still has to keep the cache out of what it publishes.
    const config = work_dir ++ "/ubuntu-snapshot.json";
    const keyring = work_dir ++ "/ubuntu-archive-keyring.gpg";
    for (&baremetal_debz_packages, 0..) |package, index| {
        var stage_buffer: [128]u8 = undefined;
        const stage = try std.fmt.bufPrint(&stage_buffer, "{s}/root-stage-{d}", .{ work_dir, index });
        var published_buffer: [128]u8 = undefined;
        const published = try std.fmt.bufPrint(&published_buffer, "{s}/root-debz-{d}", .{ work_dir, index });
        var state_buffer: [128]u8 = undefined;
        const state = try std.fmt.bufPrint(&state_buffer, "{s}/debz-{s}/state", .{ work_dir, package });
        var lock_buffer: [128]u8 = undefined;
        const lock = try std.fmt.bufPrint(&lock_buffer, "{s}/debz-{s}/exact-lock.json", .{ work_dir, package });
        const packages = [_][]const u8{package};

        const resolve = packageFamilyRequest(.resolve_lock, profile, &packages, stage, published, &.{config}, &.{keyring}, shared_cache, state, lock, .require_locked, null, false);
        try assertRequestSeparation(resolve);
        try std.testing.expectEqualStrings(shared_cache, resolve.inputs.cache_path);
        const customize = packageFamilyRequest(.customize, profile, &packages, stage, published, &.{config}, &.{keyring}, shared_cache, state, lock, .require_locked, null, false);
        try assertRequestSeparation(customize);
        try std.testing.expectEqualStrings(shared_cache, customize.inputs.cache_path);

        // Each stage keeps its own dpkg admin state, which is what makes
        // sharing the content cache safe rather than a baseline leak.
        try std.testing.expect(!package_family.pathsOverlap(state, shared_cache));
    }

    // A cache placed under a publication root is still refused.
    const bad = packageFamilyRequest(.customize, profile, &.{"sudo"}, work_dir ++ "/root-stage-0", work_dir ++ "/root-debz-0", &.{config}, &.{keyring}, work_dir ++ "/root-debz-0/cache", work_dir ++ "/debz-sudo/state", work_dir ++ "/debz-sudo/exact-lock.json", .require_locked, null, false);
    try std.testing.expectError(error.PackageFamilySeparationViolation, assertRequestSeparation(bad));
}

test "shared debz cache startup removes only abandoned staging files" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const io = std.testing.io;

    for (&[_][]const u8{ "metadata-v1", "packages-v1" }) |namespace| {
        var path_buffer: [128]u8 = undefined;
        const staging = try std.fmt.bufPrint(&path_buffer, "cache/{s}/staging", .{namespace});
        try temporary.dir.createDirPath(io, staging);
        var locks_buffer: [128]u8 = undefined;
        const locks = try std.fmt.bufPrint(&locks_buffer, "cache/{s}/locks", .{namespace});
        try temporary.dir.createDirPath(io, locks);
        var objects_buffer: [128]u8 = undefined;
        const objects = try std.fmt.bufPrint(&objects_buffer, "cache/{s}/objects", .{namespace});
        try temporary.dir.createDirPath(io, objects);
        var abandoned_buffer: [160]u8 = undefined;
        const abandoned = try std.fmt.bufPrint(&abandoned_buffer, "{s}/abandoned.tmp", .{staging});
        try temporary.dir.writeFile(io, .{ .sub_path = abandoned, .data = "partial" });
        var object_buffer: [160]u8 = undefined;
        const object = try std.fmt.bufPrint(&object_buffer, "{s}/verified-object", .{objects});
        try temporary.dir.writeFile(io, .{ .sub_path = object, .data = "verified" });
    }

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try temporary.dir.realPath(io, &root_buffer)];
    const cache_path = try std.fs.path.join(std.testing.allocator, &.{ root, "cache" });
    defer std.testing.allocator.free(cache_path);

    {
        var locks = try temporary.dir.openDir(io, "cache/metadata-v1/locks", .{});
        defer locks.close(io);
        const writer_lock = try locks.createFile(io, "writer.lock", .{
            .read = true,
            .truncate = false,
            .lock = .exclusive,
            .lock_nonblocking = true,
        });
        defer writer_lock.close(io);
        try std.testing.expectError(error.WouldBlock, cleanupSharedDebzCacheStaging(io, cache_path));
        _ = try temporary.dir.statFile(io, "cache/metadata-v1/staging/abandoned.tmp", .{});
    }

    try cleanupSharedDebzCacheStaging(io, cache_path);

    for (&[_][]const u8{ "metadata-v1", "packages-v1" }) |namespace| {
        var abandoned_buffer: [160]u8 = undefined;
        const abandoned = try std.fmt.bufPrint(&abandoned_buffer, "cache/{s}/staging/abandoned.tmp", .{namespace});
        try std.testing.expectError(error.FileNotFound, temporary.dir.statFile(io, abandoned, .{}));
        var object_buffer: [160]u8 = undefined;
        const object = try std.fmt.bufPrint(&object_buffer, "cache/{s}/objects/verified-object", .{namespace});
        _ = try temporary.dir.statFile(io, object, .{});
    }
}

test "trusted keyring copy is bounded, read-only, and immune to guest mutation" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    const guest_relative = "guest/usr/share/keyrings/ubuntu-archive-keyring.gpg";
    try temporary.dir.createDirPath(io, "guest/usr/share/keyrings");
    const guest_bytes = "trusted-ubuntu-archive-keyring-bytes";
    try temporary.dir.writeFile(io, .{ .sub_path = guest_relative, .data = guest_bytes });

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try temporary.dir.realPath(io, &root_buffer)];
    const guest_keyring = try std.fs.path.join(allocator, &.{ root, guest_relative });
    defer allocator.free(guest_keyring);
    const destination = try std.fs.path.join(allocator, &.{ root, "ubuntu-archive-keyring.gpg" });
    defer allocator.free(destination);

    var trusted = try materializeTrustedKeyring(allocator, io, guest_keyring, destination);
    defer trusted.deinit(allocator);

    // The copy lives at the external host destination, is a read-only regular
    // file, and carries the digest of exactly the guest bytes.
    try std.testing.expectEqualStrings(destination, trusted.path);
    const copy_stat = try temporary.dir.statFile(io, "ubuntu-archive-keyring.gpg", .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.file, copy_stat.kind);
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o400), copy_stat.permissions.toMode() & 0o777);
    try std.testing.expectEqual(@as(u64, guest_bytes.len), copy_stat.size);
    try std.testing.expectEqual(artifact_pipeline.sha256Bytes(guest_bytes), trusted.sha256);
    try assertTrustedKeyringUnchanged(io, trusted);

    // Mutating the guest source after materialization cannot change the trusted
    // host copy: its digest is stable and the immutability assertion still holds.
    try temporary.dir.writeFile(io, .{ .sub_path = guest_relative, .data = "tampered-guest-keyring-bytes-differ" });
    try assertTrustedKeyringUnchanged(io, trusted);
    const after = try artifact_pipeline.hashFile(io, destination);
    try std.testing.expectEqual(trusted.sha256, after.sha256);
}

test "trusted keyring materialization rejects empty and non-regular sources" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try temporary.dir.realPath(io, &root_buffer)];
    const destination = try std.fs.path.join(allocator, &.{ root, "keyring.gpg" });
    defer allocator.free(destination);

    try temporary.dir.writeFile(io, .{ .sub_path = "empty.gpg", .data = "" });
    const empty = try std.fs.path.join(allocator, &.{ root, "empty.gpg" });
    defer allocator.free(empty);
    try std.testing.expectError(
        error.TrustedKeyringEmpty,
        materializeTrustedKeyring(allocator, io, empty, destination),
    );

    try temporary.dir.createDirPath(io, "keyring-dir");
    const directory = try std.fs.path.join(allocator, &.{ root, "keyring-dir" });
    defer allocator.free(directory);
    try std.testing.expectError(
        error.TrustedKeyringNotRegularFile,
        materializeTrustedKeyring(allocator, io, directory, destination),
    );

    // No destination file is produced when validation rejects the source.
    try std.testing.expectError(
        error.FileNotFound,
        temporary.dir.statFile(io, "keyring.gpg", .{}),
    );
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

const RecoveryDisposalProbe = struct {
    recovery_path: []const u8,
    called: bool = false,
};

fn expectRecoveryDisposedPublisher(
    allocator: Allocator,
    io: Io,
    raw_path: []const u8,
    destination_path: []const u8,
    opaque_context: ?*anyopaque,
) !void {
    _ = allocator;
    _ = raw_path;
    _ = destination_path;
    const context: *RecoveryDisposalProbe = @ptrCast(@alignCast(opaque_context.?));
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(io, context.recovery_path, .{}),
    );
    context.called = true;
}

fn failNativePublicationNoSpace(
    allocator: Allocator,
    io: Io,
    raw_path: []const u8,
    destination_path: []const u8,
    context: ?*anyopaque,
) !void {
    _ = allocator;
    _ = io;
    _ = raw_path;
    _ = destination_path;
    _ = context;
    return error.NoSpaceLeft;
}

test "guest ESP capacity translation preserves host NoSpaceLeft" {
    try std.testing.expectEqual(
        error.GuestEspNoSpace,
        translateGuestEspCapacity(error.FilesystemFull),
    );
    try std.testing.expectEqual(
        error.NoSpaceLeft,
        translateGuestEspCapacity(error.NoSpaceLeft),
    );
}

test "Arm64 boot fstab retirement removes the exact legacy mounts" {
    const allocator = std.testing.allocator;
    const source =
        "# /etc/fstab: static file system information.\n" ++
        "LABEL=cloudimg-rootfs / ext4 defaults 0 1\n" ++
        "LABEL=BOOT\t/boot\text4\tdefaults\t0\t2\n" ++
        "LABEL=UEFI\t/boot/efi\tvfat\tumask=0077\t0\t1\n" ++
        "UUID=swap none swap sw 0 0\n";
    const rewritten = try retireArm64BootFstabAlloc(allocator, source);
    defer allocator.free(rewritten);
    try std.testing.expectEqualStrings(
        \\# /etc/fstab: static file system information.
        \\LABEL=cloudimg-rootfs / ext4 defaults 0 1
        \\UUID=swap none swap sw 0 0
        \\
    , rewritten);
    try validateArm64BootFstabRetired(rewritten);
}

test "Arm64 boot fstab retirement rejects missing or unexpected mounts" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.UnexpectedArm64BootMount,
        retireArm64BootFstabAlloc(
            allocator,
            "UUID=unexpected /boot ext4 defaults 0 2\n",
        ),
    );
    try std.testing.expectError(
        error.MissingArm64XbootldrFstabEntry,
        retireArm64BootFstabAlloc(
            allocator,
            "LABEL=cloudimg-rootfs / ext4 defaults 0 1\n",
        ),
    );
    try std.testing.expectError(
        error.MissingArm64EspFstabEntry,
        retireArm64BootFstabAlloc(
            allocator,
            "LABEL=BOOT /boot ext4 defaults 0 2\n",
        ),
    );
    try std.testing.expectError(
        error.Arm64BootFstabEntryRetained,
        validateArm64BootFstabRetired(
            "LABEL=BOOT /boot ext4 defaults 0 2\n" ++
                "LABEL=UEFI /boot/efi vfat umask=0077 0 1\n",
        ),
    );
}

test "full service policy disables the obsolete GRUB fallback helper" {
    var found = false;
    for (&full_service_policy) |service| {
        if (!std.mem.eql(u8, service.name, "grub-initrd-fallback.service")) continue;
        try std.testing.expectEqual(miz.os_customization.ServiceState.disabled, service.state);
        found = true;
    }
    try std.testing.expect(found);
}

test "durable native recovery is disposed before QCOW2 publication" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    const root = root_buffer[0..root_length];
    const recovery_path = try std.fs.path.join(allocator, &.{ root, "recovery" });
    defer allocator.free(recovery_path);
    const recovery_image = try std.fs.path.join(allocator, &.{ recovery_path, "stage" });
    defer allocator.free(recovery_image);
    const destination_path = try std.fs.path.join(allocator, &.{ root, "published.qcow2" });
    defer allocator.free(destination_path);
    try Dir.cwd().createDirPath(io, recovery_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = recovery_image,
        .data = "displaced image",
    });

    var probe = RecoveryDisposalProbe{ .recovery_path = recovery_path };
    try disposeRecoveryAndPublishNativeQcow2(
        allocator,
        io,
        "missing.raw",
        destination_path,
        recovery_path,
        .{
            .context = &probe,
            .publish = expectRecoveryDisposedPublisher,
        },
    );
    try std.testing.expect(probe.called);
}

test "native QCOW2 host exhaustion has distinct context after recovery disposal" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    const root = root_buffer[0..root_length];
    const recovery_path = try std.fs.path.join(allocator, &.{ root, "recovery" });
    defer allocator.free(recovery_path);
    const destination_path = try std.fs.path.join(allocator, &.{ root, "published.qcow2" });
    defer allocator.free(destination_path);
    try Dir.cwd().createDirPath(io, recovery_path);

    try std.testing.expectError(
        error.HostNativeQcow2NoSpace,
        disposeRecoveryAndPublishNativeQcow2(
            allocator,
            io,
            "missing.raw",
            destination_path,
            recovery_path,
            .{ .publish = failNativePublicationNoSpace },
        ),
    );
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(io, recovery_path, .{}),
    );
}

test "native image conversion round trips and failed publication cleans its stage" {
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

    var raw = try miz.Image.create(io, raw_path, .raw, 1024 * 1024, .{});
    try raw.pwrite(io, "native-ubuntu-builder", 4096);
    raw.close(io);
    try copyNativeImage(allocator, io, raw_path, qcow_path, .qcow2);
    try copyNativeImage(allocator, io, qcow_path, roundtrip_path, .raw);
    var roundtrip = try miz.Image.openPathReadOnly(io, roundtrip_path);
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
        "{s}.miz-native-stage",
        .{blocked_destination},
    );
    defer allocator.free(staged);
    try std.testing.expectError(error.FileNotFound, Dir.cwd().statFile(io, staged, .{}));
    try std.testing.expectEqual(
        Io.File.Kind.directory,
        (try Dir.cwd().statFile(io, blocked_destination, .{})).kind,
    );
    try std.testing.expectEqual(
        @as(u64, 1024 * 1024),
        (try Dir.cwd().statFile(io, raw_path, .{})).size,
    );
}

test "the raw copy is the same guest bytes, published only once complete" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    const root = root_buffer[0..root_length];
    const seed_path = try std.fs.path.join(allocator, &.{ root, "seed.raw" });
    defer allocator.free(seed_path);
    const qcow_path = try std.fs.path.join(allocator, &.{ root, "image.qcow2" });
    defer allocator.free(qcow_path);
    const raw_path = try std.fs.path.join(allocator, &.{ root, "image.raw" });
    defer allocator.free(raw_path);

    var seed = try miz.Image.create(io, seed_path, .raw, 1024 * 1024, .{});
    try seed.pwrite(io, "written-to-a-disk", 8192);
    seed.close(io);
    try copyNativeImage(allocator, io, seed_path, qcow_path, .qcow2);

    try writeRawCopy(allocator, io, qcow_path, raw_path);
    var raw = try miz.Image.openPathReadOnly(io, raw_path);
    defer raw.close(io);
    try std.testing.expectEqual(ImageFormat.raw, raw.format);
    try std.testing.expectEqual(@as(u64, 1024 * 1024), raw.virtual_size);
    var bytes: [17]u8 = undefined;
    try std.testing.expectEqual(bytes.len, try raw.pread(io, &bytes, 8192));
    try std.testing.expectEqualStrings("written-to-a-disk", &bytes);

    // A failed copy leaves nothing at the published name: the next step writes
    // whatever is there straight onto a disk.
    const blocked = try std.fs.path.join(allocator, &.{ root, "blocked" });
    defer allocator.free(blocked);
    try Dir.cwd().createDirPath(io, blocked);
    try std.testing.expectError(error.IsDir, writeRawCopy(allocator, io, qcow_path, blocked));
    const staged_raw = try std.fmt.allocPrint(allocator, "{s}.miz-raw-stage", .{blocked});
    defer allocator.free(staged_raw);
    try std.testing.expectError(error.FileNotFound, Dir.cwd().statFile(io, staged_raw, .{}));
}

test "arguments accept Ubuntu and project architecture spellings" {
    try std.testing.expectEqual(Architecture.x86_64, (try parseArgs(&.{ "--architecture", "amd64" })).architecture.?);
    try std.testing.expectEqual(Architecture.aarch64, (try parseArgs(&.{ "--architecture", "aarch64" })).architecture.?);
    try std.testing.expectEqualStrings(
        "candidate/internal-provenance",
        (try parseArgs(&.{ "--provenance-dir", "candidate/internal-provenance" })).provenance_dir.?,
    );
    try std.testing.expectEqualStrings(
        "candidate/image-timing.json",
        (try parseArgs(&.{ "--timing-output", "candidate/image-timing.json" })).timing_output.?,
    );
    const offline = try parseArgs(&.{
        "--source",
        "ubuntu.img",
        "--debz-cache",
        "/cache",
        "--debz-input-dir",
        "/repository-inputs",
        "--debz-lock-dir",
        "/locks",
        "--offline",
    });
    try std.testing.expect(offline.offline);
    try std.testing.expectEqualStrings("/cache", offline.debz_cache.?);
    try std.testing.expectEqualStrings("/repository-inputs", offline.debz_input_dir.?);
    try std.testing.expectEqualStrings("/locks", offline.debz_lock_dir.?);
    try std.testing.expectError(error.OfflineSourceRequired, parseArgs(&.{"--offline"}));
    try std.testing.expectError(
        error.OfflineProxyNotSupported,
        parseArgs(&.{ "--source", "ubuntu.img", "--offline", "--proxy", "http://127.0.0.1:8080" }),
    );
    try std.testing.expectError(error.MissingArgument, parseArgs(&.{"--timing-output"}));
    try std.testing.expectError(error.ImageTooSmall, parseArgs(&.{ "--size", "4G" }));
}

test "flavor defaults preserve full names and isolate core outputs" {
    const full = try parseArgs(&.{});
    try std.testing.expectEqual(Flavor.full, full.flavor);
    try std.testing.expectEqual(default_virtual_size, full.size);
    const core_args = try parseArgs(&.{ "--flavor", "core" });
    try std.testing.expectEqual(Flavor.core, core_args.flavor);
    try std.testing.expectEqual(core_virtual_size, core_args.size);
    try std.testing.expectError(
        error.ImageTooSmall,
        parseArgs(&.{ "--flavor", "core", "--size", "3G" }),
    );
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-x86_64.qcow2",
        profileFor(.x86_64).outputFor(.full),
    );
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-x86_64.core.qcow2",
        profileFor(.x86_64).outputFor(.core),
    );
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-aarch64.core.qcow2",
        profileFor(.aarch64).outputFor(.core),
    );
    try std.testing.expectEqualStrings(
        ".scratch/ubuntu2604-aarch64-core",
        profileFor(.aarch64).workDirFor(.core),
    );
}

test "root headroom rejects inode exhaustion for every flavor" {
    try std.testing.expectError(
        error.RootFreeInodesTooSmall,
        validateRootHeadroom(.full, 0, minimum_root_free_inodes - 1),
    );
    try validateRootHeadroom(.full, 0, minimum_root_free_inodes);
    try std.testing.expectError(
        error.CoreRootFreeSpaceTooSmall,
        validateRootHeadroom(.core, core_minimum_root_free_bytes - 1, minimum_root_free_inodes),
    );
    try validateRootHeadroom(.core, core_minimum_root_free_bytes, minimum_root_free_inodes);
}

test "bare metal is named apart from core and requires exactly one administrator key" {
    // A key is the only way into a bare-metal image. Building one without a key
    // produces a machine nobody can reach; offering a key to a flavor that
    // refuses to bake it would let the caller believe otherwise.
    const baremetal_args = try parseArgs(&.{ "--flavor", "baremetal", "--authorized-key", "id_ed25519.pub" });
    try std.testing.expectEqual(Flavor.baremetal, baremetal_args.flavor);
    try std.testing.expectEqual(baremetal_virtual_size, baremetal_args.size);
    try std.testing.expectError(
        error.AuthorizedKeyRequired,
        parseArgs(&.{ "--flavor", "baremetal" }),
    );
    try std.testing.expectError(
        error.AuthorizedKeyNotSupported,
        parseArgs(&.{ "--flavor", "core", "--authorized-key", "id_ed25519.pub" }),
    );
    try std.testing.expectError(
        error.AuthorizedKeyNotSupported,
        parseArgs(&.{ "--authorized-key", "id_ed25519.pub" }),
    );

    // The bare-metal artifact never shares a name or a scratch directory with
    // core: they differ by kernel, and a stale one of either would be
    // indistinguishable from a fresh build of the other.
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-aarch64.baremetal.qcow2",
        profileFor(.aarch64).outputFor(.baremetal),
    );
    try std.testing.expectEqualStrings(
        ".scratch/ubuntu2604-aarch64-baremetal",
        profileFor(.aarch64).workDirFor(.baremetal),
    );

    // The flavor's structural claims, stated once so a later edit cannot
    // quietly reverse them.
    try std.testing.expect(Flavor.baremetal.freshRoot());
    try std.testing.expect(!Flavor.baremetal.azure());
    try std.testing.expect(Flavor.core.azure());
    try std.testing.expectEqualStrings(nvidia_bos_kernel_suffix, Flavor.baremetal.kernelSuffix());
    try std.testing.expectEqualStrings(azure_kernel_suffix, Flavor.core.kernelSuffix());
}

test "fresh-root package roots explicitly install runtime requirements" {
    for ([_][]const []const u8{ &core_debz_packages, &baremetal_debz_packages }) |packages| {
        for ([_][]const u8{ "initramfs-tools", "ca-certificates" }) |expected| {
            var found = false;
            for (packages) |package| {
                if (std.mem.eql(u8, package, expected)) {
                    found = true;
                    break;
                }
            }
            try std.testing.expect(found);
        }
    }

    for ([_][]const u8{ "initramfs-tools", "ca-certificates" }) |expected| {
        var required = false;
        for (&core_required_packages) |package| {
            if (std.mem.eql(u8, package, expected)) {
                required = true;
                break;
            }
        }
        try std.testing.expect(required);
    }
}

test "bare-metal access resizes root best-effort before starting sshd" {
    try std.testing.expectEqualStrings(
        "#!/bin/sh\n" ++
            "set -e\n" ++
            "if ! /usr/sbin/azagent --resize-root-only; then\n" ++
            "    echo \"mizinit-access: warning: root resize failed; continuing boot\" >&2\n" ++
            "fi\n" ++
            "[ -f /etc/ssh/ssh_host_ed25519_key ] || /usr/bin/ssh-keygen -A\n" ++
            "mkdir -p /run/sshd\n" ++
            "exec /usr/sbin/sshd -D -e\n",
        baremetal_access_provider,
    );
}

test "an administrator key is read only when it is one public key" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const dir_path = try std.fs.path.join(allocator, &.{ cwd, ".scratch/ubuntu-authorized-key" });
    defer allocator.free(dir_path);
    Io.Dir.cwd().deleteTree(io, dir_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, dir_path) catch {};
    try Io.Dir.cwd().createDirPath(io, dir_path);

    const write = struct {
        fn file(a: Allocator, i: Io, directory: []const u8, name: []const u8, contents: []const u8) ![]u8 {
            const path = try std.fs.path.join(a, &.{ directory, name });
            try Io.Dir.cwd().writeFile(i, .{ .sub_path = path, .data = contents });
            return path;
        }
    };

    const good = try write.file(allocator, io, dir_path, "id.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA g@example\n");
    defer allocator.free(good);
    const key = try readAuthorizedKey(allocator, io, good);
    defer allocator.free(key);
    // Read back without the trailing newline, so the caller can place it in a
    // file whose format it controls rather than inheriting whatever the source
    // file happened to end with.
    try std.testing.expectEqualStrings("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA g@example", key);

    // A private key is the mistake worth catching: the paths differ by four
    // characters and the consequence of baking the wrong one is severe.
    const private = try write.file(allocator, io, dir_path, "id", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----\n");
    defer allocator.free(private);
    try std.testing.expectError(error.InvalidAuthorizedKey, readAuthorizedKey(allocator, io, private));

    // Two keys in one file would silently authorize a second party.
    const two = try write.file(allocator, io, dir_path, "two.pub", "ssh-ed25519 AAAA a@b\nssh-ed25519 BBBB c@d\n");
    defer allocator.free(two);
    try std.testing.expectError(error.InvalidAuthorizedKey, readAuthorizedKey(allocator, io, two));

    const empty = try write.file(allocator, io, dir_path, "empty.pub", "\n");
    defer allocator.free(empty);
    try std.testing.expectError(error.InvalidAuthorizedKey, readAuthorizedKey(allocator, io, empty));

    const missing = try std.fs.path.join(allocator, &.{ dir_path, "absent.pub" });
    defer allocator.free(missing);
    try std.testing.expectError(error.AuthorizedKeyMissing, readAuthorizedKey(allocator, io, missing));
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

fn makeMinimalSignablePe(allocator: Allocator) ![]u8 {
    // Smallest PE32+ shape the native Authenticode signer accepts: an MZ/PE
    // header with a PE32+ optional header whose data-directory count reaches the
    // security (certificate) directory the signature is embedded into.
    const image = try allocator.alloc(u8, 512);
    @memset(image, 0);
    image[0] = 'M';
    image[1] = 'Z';
    std.mem.writeInt(u32, image[0x3c..][0..4], 0x80, .little);
    @memcpy(image[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, image[0x84..][0..2], 0x8664, .little);
    std.mem.writeInt(u16, image[0x94..][0..2], 0xf0, .little);
    std.mem.writeInt(u16, image[0x98..][0..2], 0x20b, .little);
    std.mem.writeInt(u32, image[0x104..][0..4], 5, .little);
    return image;
}

test "committed local UKI signing fixtures load and sign against the enrolled certificate" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // The safe, public, test-only signing identity the local end-to-end driver
    // (scripts/ubuntu2604_local_e2e.sh) and its documentation pin. Guarding the
    // committed PEM fixtures here keeps the local release gate reproducible: a
    // silent fixture swap, a corrupted key, or a key/certificate mismatch all
    // fail in `zig build test-generalized-ubuntu2604`, before any 5 GiB build.
    var certificate = try miz.uki_signing.loadCertificateAlloc(allocator, io, .{
        .host_path = "tests/fixtures/ubuntu2604-local-signing/signing-cert.pem",
    });
    defer certificate.deinit(allocator);
    const expected = try uki_signing.parseFingerprint(
        "8ca3b80b1a2272a4f3a6d13246a65cfdd89764eb83beb8a0709e3cf591490279",
    );
    try std.testing.expectEqual(expected, certificate.sha256);

    const key_pem = try Dir.cwd().readFileAlloc(
        io,
        "tests/fixtures/ubuntu2604-local-signing/signing-key.pem",
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(key_pem);
    const key_der = try miz.authenticode.decodePrivateKeyPemAlloc(allocator, key_pem);
    defer allocator.free(key_der);

    // Exercise the exact native local-key path the builder uses: sign a minimal
    // PE with the fixture key and re-derive the signer from the bytes. A key
    // that does not belong to the enrolled certificate cannot verify here.
    const image = try makeMinimalSignablePe(allocator);
    defer allocator.free(image);
    const signed = try miz.authenticode.signPeRsaSha256Alloc(
        allocator,
        image,
        key_der,
        certificate.der,
    );
    defer allocator.free(signed);
    const signer = try miz.authenticode.verifyRsaSha256(signed);
    try std.testing.expectEqualSlices(u8, certificate.der, signer.certificate_der);
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

test "kernel discovery is architecture-neutral, exact, and flavor-driven" {
    try std.testing.expectEqualStrings(
        "7.0.0-1001-azure",
        findKernelRelease("config\nvmlinuz-7.0.0-1001-azure\n", azure_kernel_suffix).?,
    );
    try std.testing.expect(findKernelRelease("vmlinuz-7.0.0-28-generic\n", azure_kernel_suffix) == null);

    // The point of the suffix being a parameter: the Azure kernel is not an
    // acceptable substitute for the bare-metal one, or the other way around.
    const nvidia_listing = "config\nvmlinuz-7.0.0-2015-nvidia-bos-64k\n";
    try std.testing.expectEqualStrings(
        baremetal_kernel_release,
        findKernelRelease(nvidia_listing, nvidia_bos_kernel_suffix).?,
    );
    try std.testing.expect(findKernelRelease(nvidia_listing, azure_kernel_suffix) == null);
    try std.testing.expect(
        findKernelRelease("vmlinuz-7.0.0-1001-azure\n", nvidia_bos_kernel_suffix) == null,
    );
}

test "the bare-metal initramfs is required to carry the drivers that reach the machine" {
    const allocator = std.testing.allocator;

    // An initramfs as initramfs-tools builds one: an uncompressed early cpio,
    // then the compressed main archive. Both halves are searched, because
    // which half a module lands in is not this builder's decision.
    const pack = struct {
        fn archive(a: Allocator, paths: []const []const u8) ![]u8 {
            var buffer = std.array_list.Managed(u8).init(a);
            errdefer buffer.deinit();
            var writer = miz.cpio.Writer.init(&buffer, .newc);
            // Every archive initramfs-tools writes opens with the root entry.
            try writer.append(.{
                .path = ".",
                .content = "",
                .metadata = .{ .mode = 0o040755, .nlink = 1 },
            });
            for (paths) |path| try writer.append(.{
                .path = path,
                .content = "module",
                .metadata = .{ .mode = 0o100644, .nlink = 1 },
            });
            try writer.finish();
            return buffer.toOwnedSlice();
        }

        fn image(a: Allocator, early: []const []const u8, payload: []const []const u8) ![]u8 {
            const early_bytes = try archive(a, early);
            defer a.free(early_bytes);
            const main_bytes = try archive(a, payload);
            defer a.free(main_bytes);
            var out: std.Io.Writer.Allocating = .init(a);
            errdefer out.deinit();
            try out.writer.writeAll(early_bytes);
            try miz.zstd.writeRawFrameForSlice(&out.writer, main_bytes, null);
            return out.toOwnedSlice();
        }

        /// The same image as `image`, compressed the way `mkinitramfs` does
        /// when the configured compressor is not installed in the root.
        fn gzipImage(a: Allocator, early: []const []const u8, payload: []const []const u8) ![]u8 {
            const early_bytes = try archive(a, early);
            defer a.free(early_bytes);
            const main_bytes = try archive(a, payload);
            defer a.free(main_bytes);
            var out: std.Io.Writer.Allocating = .init(a);
            errdefer out.deinit();
            try out.writer.writeAll(early_bytes);
            var history: [std.compress.flate.max_window_len]u8 = undefined;
            var compressor = try std.compress.flate.Compress.init(&out.writer, &history, .gzip, .default);
            try compressor.writer.writeAll(main_bytes);
            try compressor.finish();
            return out.toOwnedSlice();
        }

        /// An early archive followed by a tail carrying an arbitrary magic, so
        /// an unrecognized compressor can be distinguished from a readable one.
        fn taggedImage(a: Allocator, early: []const []const u8, magic: []const u8) ![]u8 {
            const early_bytes = try archive(a, early);
            defer a.free(early_bytes);
            var out: std.Io.Writer.Allocating = .init(a);
            errdefer out.deinit();
            try out.writer.writeAll(early_bytes);
            try out.writer.writeAll(magic);
            return out.toOwnedSlice();
        }
    };

    const complete = try pack.image(
        allocator,
        &.{"kernel/drivers/net/usb/r8152.ko.zst"},
        &.{ "kernel/drivers/nvme/host/nvme.ko.zst", "kernel/fs/ext4/ext4.ko.zst" },
    );
    defer allocator.free(complete);
    try requireInitramfsModules(allocator, complete, &baremetal_required_initramfs_modules);

    // The failure this exists to catch: an initramfs built the way an Azure
    // image's would be, carrying neither the disk nor the NIC this machine has.
    const azure_shaped = try pack.image(
        allocator,
        &.{},
        &.{ "kernel/drivers/net/hyperv/hv_netvsc.ko.zst", "kernel/drivers/scsi/sd_mod.ko.zst" },
    );
    defer allocator.free(azure_shaped);
    try std.testing.expectError(
        error.InitramfsModuleMissing,
        requireInitramfsModules(allocator, azure_shaped, &baremetal_required_initramfs_modules),
    );

    // Half of it is still a machine that does not come back: root without a
    // network is as unreachable as a network without root.
    const no_nic = try pack.image(allocator, &.{}, &.{"kernel/drivers/nvme/host/nvme.ko.zst"});
    defer allocator.free(no_nic);
    try std.testing.expectError(
        error.InitramfsModuleMissing,
        requireInitramfsModules(allocator, no_nic, &baremetal_required_initramfs_modules),
    );

    // A name that merely contains a required one is not that module.
    const near_miss = try pack.image(
        allocator,
        &.{},
        &.{ "kernel/drivers/nvme/host/nvme-core.ko.zst", "kernel/drivers/net/usb/r8152.ko.zst" },
    );
    defer allocator.free(near_miss);
    try std.testing.expectError(
        error.InitramfsModuleMissing,
        requireInitramfsModules(allocator, near_miss, &baremetal_required_initramfs_modules),
    );

    // An image whose compressed half cannot be read fails closed rather than
    // reporting the modules it could not look for as absent-but-fine.
    var truncated = try allocator.dupe(u8, complete);
    defer allocator.free(truncated);
    @memset(truncated[truncated.len - 16 ..], 0);
    try std.testing.expectError(
        error.UnreadableInitramfs,
        requireInitramfsModules(allocator, truncated[0 .. truncated.len - 8], &baremetal_required_initramfs_modules),
    );

    // `COMPRESS=zstd` is what the root asks for; gzip is what it gets when the
    // `zstd` binary is not installed, because `mkinitramfs` warns and falls
    // back rather than failing. A real aarch64 bare-metal root produced exactly
    // this, and reading only zstd rejected a perfectly bootable initramfs.
    const gzipped = try pack.gzipImage(
        allocator,
        &.{"kernel/drivers/net/usb/r8152.ko.zst"},
        &.{ "kernel/drivers/nvme/host/nvme.ko.zst", "kernel/fs/ext4/ext4.ko.zst" },
    );
    defer allocator.free(gzipped);
    try requireInitramfsModules(allocator, gzipped, &baremetal_required_initramfs_modules);

    // The fallback is read, not merely tolerated: a gzip image missing a
    // required driver is still rejected for the right reason.
    const gzipped_no_nic = try pack.gzipImage(
        allocator,
        &.{},
        &.{"kernel/drivers/nvme/host/nvme.ko.zst"},
    );
    defer allocator.free(gzipped_no_nic);
    try std.testing.expectError(
        error.InitramfsModuleMissing,
        requireInitramfsModules(allocator, gzipped_no_nic, &baremetal_required_initramfs_modules),
    );

    // A compressor neither branch recognizes is refused rather than silently
    // treated as an archive with nothing in it.
    const unknown = try pack.taggedImage(
        allocator,
        &.{"kernel/drivers/net/usb/r8152.ko.zst"},
        &.{ 0xfd, 0x37, 0x7a, 0x58 },
    );
    defer allocator.free(unknown);
    try std.testing.expectError(
        error.UnreadableInitramfs,
        requireInitramfsModules(allocator, unknown, &baremetal_required_initramfs_modules),
    );
}

test "UKI cmdline binds final root PARTUUID and native serial console" {
    const root_guid = guid.parse("11111111-2222-3333-4444-555555555555");
    const x86_cmdline = try ukiCmdline(std.testing.allocator, root_guid, profileFor(.x86_64), .full);
    defer std.testing.allocator.free(x86_cmdline);
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 console=ttyS0,115200n8",
        x86_cmdline,
    );
    const arm_cmdline = try ukiCmdline(std.testing.allocator, root_guid, profileFor(.aarch64), .full);
    defer std.testing.allocator.free(arm_cmdline);
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 console=ttyAMA0,115200n8",
        arm_cmdline,
    );
    try std.testing.expect(std.mem.indexOf(u8, x86_cmdline, "LABEL=") == null);
    try std.testing.expect(std.mem.indexOf(u8, arm_cmdline, "ttyS0") == null);

    const core_cmdline = try ukiCmdline(
        std.testing.allocator,
        root_guid,
        profileFor(.aarch64),
        .core,
    );
    defer std.testing.allocator.free(core_cmdline);
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 init=/sbin/mizinit mizinit.mode=persistent mizinit.azure=auto console=tty0 console=ttyAMA0,115200n8",
        core_cmdline,
    );
    try std.testing.expect(std.mem.indexOf(u8, core_cmdline, "mizinit.shell=on") == null);

    const baremetal_cmdline = try ukiCmdline(
        std.testing.allocator,
        root_guid,
        profileFor(.aarch64),
        .baremetal,
    );
    defer std.testing.allocator.free(baremetal_cmdline);
    try std.testing.expectEqualStrings(
        "root=PARTUUID=11111111-2222-3333-4444-555555555555 init=/sbin/mizinit mizinit.mode=persistent mizinit.azure=off console=tty0 console=ttyAMA0,115200n8",
        baremetal_cmdline,
    );
    // `auto` would send the machine looking for an Azure it is never going to
    // find; `off` is the whole point of the flavor.
    try std.testing.expect(std.mem.indexOf(u8, baremetal_cmdline, "mizinit.azure=auto") == null);
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

test "native boot validation follows a merged-usr root" {
    // The production shape: the modules really live under `/usr/lib/modules`
    // and `/lib` is only a compatibility symlink. `offline_root` refuses to walk
    // that symlink, so validating through `/lib/modules` reported the modules of
    // a correctly built root as missing -- `error.NotDirectory` raised after
    // dpkg had already succeeded.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, ".scratch/ubuntu-merged-usr-boot-validation" });
    defer allocator.free(root_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDirPath(io, root_path);
    var root = try offline_root.Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    const kernel_release = "7.0.0-2015-nvidia-bos-64k";
    try root.createDirectory("/usr/lib/modules/" ++ kernel_release, 0o755);
    try root.createDirectory("/boot", 0o755);
    try root.writeFile(.{
        .path = "/usr/lib/modules/" ++ kernel_release ++ "/kernel",
        .source = .{ .inline_bytes = "module" },
    });
    try root.writeFile(.{
        .path = "/usr/lib/modules/" ++ kernel_release ++ "/modules.dep",
        .source = .{ .inline_bytes = "kernel/drivers/net/hv_netvsc.ko:\n" },
    });
    try root.writeFile(.{
        .path = "/boot/initrd.img-" ++ kernel_release,
        .source = .{ .inline_bytes = "initrd" },
    });
    try root.replaceSymlink("/lib", "usr/lib");

    // The symlink is genuinely unwalkable, so the old spelling cannot work and
    // the resolver stays as strict as it was.
    try std.testing.expectError(
        error.NotDirectory,
        root.discover("/lib/modules/" ++ kernel_release, "*"),
    );

    const resolved = try kernelModulesPath(allocator, &root, kernel_release);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings("/usr/lib/modules/" ++ kernel_release, resolved);
    try validateNativeBootArtifacts(allocator, &root, kernel_release);

    // A root that never merged keeps the `/lib` spelling.
    const split_path = try std.fs.path.join(allocator, &.{ cwd, ".scratch/ubuntu-split-usr-boot-validation" });
    defer allocator.free(split_path);
    Io.Dir.cwd().deleteTree(io, split_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, split_path) catch {};
    try Io.Dir.cwd().createDirPath(io, split_path);
    var split = try offline_root.Root.init(allocator, io, split_path, .{});
    defer split.deinit();
    try split.createDirectory("/lib/modules/" ++ kernel_release, 0o755);
    const split_resolved = try kernelModulesPath(allocator, &split, kernel_release);
    defer allocator.free(split_resolved);
    try std.testing.expectEqualStrings("/lib/modules/" ++ kernel_release, split_resolved);
}

test "the initramfs is validated as a generated artifact, not an unpacked one" {
    // The ordering this exists to hold: a root the kernel package was unpacked
    // into has `/boot/initrd.img` pointing at an image that does not exist
    // yet, because the package ships the link and `update-initramfs` supplies
    // the target. Validating the initramfs before running the generator is
    // therefore guaranteed to fail on exactly the roots the builder produces.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, ".scratch/ubuntu-initramfs-ordering" });
    defer allocator.free(root_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDirPath(io, root_path);
    var root = try offline_root.Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    const kernel_release = "7.0.0-2015-nvidia-bos-64k";

    // A root as the kernel package leaves it: modules present, and a dangling
    // `/boot/initrd.img` whose target has not been generated.
    try root.createDirectory("/usr/lib/modules/" ++ kernel_release, 0o755);
    try root.createDirectory("/boot", 0o755);
    try root.writeFile(.{
        .path = "/usr/lib/modules/" ++ kernel_release ++ "/kernel",
        .source = .{ .inline_bytes = "module" },
    });
    try root.writeFile(.{
        .path = "/usr/lib/modules/" ++ kernel_release ++ "/modules.dep",
        .source = .{ .inline_bytes = "kernel/drivers/net/hv_netvsc.ko:\n" },
    });
    try root.replaceSymlink("/boot/initrd.img", "initrd.img-" ++ kernel_release);

    // The generator's inputs are ready, so this passes and the build proceeds
    // to build the initramfs.
    try validateKernelModuleArtifacts(allocator, &root, kernel_release);

    // Its output is not ready, which is the whole reason it has to be checked
    // afterwards. The dangling link must not be mistaken for the image.
    try std.testing.expectError(
        error.InitramfsMissing,
        validateInitramfs(allocator, &root, kernel_release),
    );

    // An empty image is a failed generation, not a successful one.
    try root.writeFile(.{
        .path = "/boot/initrd.img-" ++ kernel_release,
        .source = .{ .inline_bytes = "" },
    });
    try std.testing.expectError(
        error.InitramfsMissing,
        validateInitramfs(allocator, &root, kernel_release),
    );

    // What `update-initramfs` leaves behind.
    try root.writeFile(.{
        .path = "/boot/initrd.img-" ++ kernel_release,
        .source = .{ .inline_bytes = "initramfs" },
    });
    try validateInitramfs(allocator, &root, kernel_release);
    try validateNativeBootArtifacts(allocator, &root, kernel_release);
}

test "core kernel config validation requires every Binder-enabling line" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, ".scratch/ubuntu-core-kernel-config" });
    defer allocator.free(root_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDirPath(io, root_path);
    var root = try offline_root.Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    const kernel_release = "7.0.0-1001-azure";
    try root.createDirectory("/boot", 0o755);

    // Every required line present: the config core's Binder support needs.
    try root.writeFile(.{
        .path = "/boot/config-" ++ kernel_release,
        .source = .{ .inline_bytes =
        \\CONFIG_ANDROID=y
        \\CONFIG_ANDROID_BINDER_IPC=m
        \\CONFIG_ANDROID_BINDERFS=m
        \\CONFIG_ANDROID_BINDER_DEVICES=""
        \\CONFIG_MODULE_DECOMPRESS=y
        \\
        },
    });
    try validateCoreKernelConfig(allocator, &root, kernel_release);

    // Binder built directly in, rather than as the loadable module mizinit
    // expects to load, must be rejected just as absence would be.
    try root.writeFile(.{
        .path = "/boot/config-" ++ kernel_release,
        .source = .{ .inline_bytes =
        \\CONFIG_ANDROID_BINDER_IPC=y
        \\CONFIG_ANDROID_BINDERFS=m
        \\CONFIG_ANDROID_BINDER_DEVICES=""
        \\CONFIG_MODULE_DECOMPRESS=y
        \\
        },
    });
    try std.testing.expectError(
        error.CoreKernelConfigMissing,
        validateCoreKernelConfig(allocator, &root, kernel_release),
    );

    // A default device name is exactly the drift `mizinit.binder=required`
    // must not race with: the kernel would already own `/dev/binder`.
    try root.writeFile(.{
        .path = "/boot/config-" ++ kernel_release,
        .source = .{ .inline_bytes =
        \\CONFIG_ANDROID_BINDER_IPC=m
        \\CONFIG_ANDROID_BINDERFS=m
        \\CONFIG_ANDROID_BINDER_DEVICES="binder,hwbinder,vndbinder"
        \\CONFIG_MODULE_DECOMPRESS=y
        \\
        },
    });
    try std.testing.expectError(
        error.CoreKernelConfigMissing,
        validateCoreKernelConfig(allocator, &root, kernel_release),
    );
}

test "the packaged Android Binder module must be present signed and never DKMS-shadowed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, ".scratch/ubuntu-android-binder-module" });
    defer allocator.free(root_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDirPath(io, root_path);
    var root = try offline_root.Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    const kernel_release = "7.0.0-1001-azure";
    const android_dir = "/usr/lib/modules/" ++ kernel_release ++ "/kernel/drivers/android";
    try root.createDirectory(android_dir, 0o755);
    const signed_bytes = "binder-module-bytes" ++ module_signature_marker;
    const unsigned_bytes = "binder-module-bytes-without-a-trailer";

    // Nothing packaged yet: the offline root has no such module.
    try std.testing.expectError(
        error.AndroidBinderModuleMissing,
        validateAndroidBinderModule(allocator, &root, kernel_release),
    );

    // The plain, uncompressed shape: signed and accepted.
    try root.writeFile(.{
        .path = android_dir ++ "/binder_linux.ko",
        .source = .{ .inline_bytes = signed_bytes },
    });
    {
        const evidence = try validateAndroidBinderModule(allocator, &root, kernel_release);
        defer allocator.free(evidence.path);
        try std.testing.expectEqualStrings(android_dir ++ "/binder_linux.ko", evidence.path);
        try std.testing.expect(evidence.signed);
    }
    try root.remove(android_dir ++ "/binder_linux.ko", false);

    // Signed, but Ubuntu-shaped: zstd-compressed, with the marker recovered
    // only once the kernel-decompressed bytes are inspected.
    {
        var compressed: std.Io.Writer.Allocating = .init(allocator);
        defer compressed.deinit();
        try miz.zstd.writeRawFrameForSlice(&compressed.writer, signed_bytes, null);
        try root.writeFile(.{
            .path = android_dir ++ "/binder_linux.ko.zst",
            .source = .{ .inline_bytes = compressed.written() },
        });
    }
    {
        const evidence = try validateAndroidBinderModule(allocator, &root, kernel_release);
        defer allocator.free(evidence.path);
        try std.testing.expectEqualStrings(android_dir ++ "/binder_linux.ko.zst", evidence.path);
        try std.testing.expect(evidence.signed);
    }

    // Two candidates at once is exactly as unresolvable as none: which one
    // mizinit would load is not this builder's call to make silently.
    try root.writeFile(.{
        .path = android_dir ++ "/binder_linux.ko",
        .source = .{ .inline_bytes = signed_bytes },
    });
    try std.testing.expectError(
        error.AndroidBinderModuleMissing,
        validateAndroidBinderModule(allocator, &root, kernel_release),
    );
    try root.remove(android_dir ++ "/binder_linux.ko", false);
    try root.remove(android_dir ++ "/binder_linux.ko.zst", false);

    // A packaged module missing the kernel's own signing trailer: structurally
    // unsigned, regardless of what the build otherwise believes about it.
    try root.writeFile(.{
        .path = android_dir ++ "/binder_linux.ko",
        .source = .{ .inline_bytes = unsigned_bytes },
    });
    try std.testing.expectError(
        error.AndroidBinderModuleUnsigned,
        validateAndroidBinderModule(allocator, &root, kernel_release),
    );
    try root.remove(android_dir ++ "/binder_linux.ko", false);

    // A DKMS-built shadow tree overriding the in-tree module: rejected even
    // when a legitimate, signed module is also present alongside it.
    try root.writeFile(.{
        .path = android_dir ++ "/binder_linux.ko",
        .source = .{ .inline_bytes = signed_bytes },
    });
    try root.createDirectory("/usr/lib/modules/" ++ kernel_release ++ "/updates/dkms", 0o755);
    try root.writeFile(.{
        .path = "/usr/lib/modules/" ++ kernel_release ++ "/updates/dkms/anbox_binder.ko",
        .source = .{ .inline_bytes = signed_bytes },
    });
    try std.testing.expectError(
        error.ShadowBinderModulePresent,
        validateAndroidBinderModule(allocator, &root, kernel_release),
    );
}

test "core kernel module validation additionally requires the Binder module, bare metal does not" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, ".scratch/ubuntu-core-binder-modules-dep" });
    defer allocator.free(root_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDirPath(io, root_path);
    var root = try offline_root.Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    const kernel_release = "7.0.0-1001-azure";
    try root.createDirectory("/usr/lib/modules/" ++ kernel_release, 0o755);
    try root.writeFile(.{
        .path = "/usr/lib/modules/" ++ kernel_release ++ "/modules.dep",
        .source = .{ .inline_bytes = "kernel/drivers/net/hv_netvsc.ko:\nkernel/fs/overlayfs/overlay.ko:\nkernel/fs/isofs/isofs.ko:\nkernel/fs/udf/udf.ko:\nkernel/fs/xfs/xfs.ko:\n" },
    });

    // Every other required core module is present, but Binder's is not.
    try std.testing.expectError(
        error.CoreKernelModuleMissing,
        validateCoreKernelModules(allocator, &root, kernel_release, .core),
    );

    // Bare metal never claims Binder support, so the same tree passes for it.
    try validateCoreKernelModules(allocator, &root, kernel_release, .baremetal);

    try root.writeFile(.{
        .path = "/usr/lib/modules/" ++ kernel_release ++ "/modules.dep",
        .source = .{ .inline_bytes = "kernel/drivers/net/hv_netvsc.ko:\nkernel/fs/overlayfs/overlay.ko:\nkernel/fs/isofs/isofs.ko:\nkernel/fs/udf/udf.ko:\nkernel/fs/xfs/xfs.ko:\nkernel/drivers/android/binder_linux.ko:\n" },
    });
    try validateCoreKernelModules(allocator, &root, kernel_release, .core);
}

test "core initramfs validation requires the packaged Binder module" {
    const allocator = std.testing.allocator;
    const pack = struct {
        fn archive(a: Allocator, paths: []const []const u8) ![]u8 {
            var buffer = std.array_list.Managed(u8).init(a);
            errdefer buffer.deinit();
            var writer = miz.cpio.Writer.init(&buffer, .newc);
            for (paths) |path| try writer.append(.{
                .path = path,
                .content = "module",
                .metadata = .{ .mode = 0o100644, .nlink = 1 },
            });
            try writer.finish();
            return buffer.toOwnedSlice();
        }

        fn image(a: Allocator, payload: []const []const u8) ![]u8 {
            const main_bytes = try archive(a, payload);
            defer a.free(main_bytes);
            var out: std.Io.Writer.Allocating = .init(a);
            errdefer out.deinit();
            try miz.zstd.writeRawFrameForSlice(&out.writer, main_bytes, null);
            return out.toOwnedSlice();
        }
    };

    const missing_binder = try pack.image(allocator, &.{"kernel/fs/ext4/ext4.ko.zst"});
    defer allocator.free(missing_binder);
    try std.testing.expectError(
        error.InitramfsModuleMissing,
        requireInitramfsModules(allocator, missing_binder, &core_required_initramfs_modules),
    );

    const with_binder = try pack.image(allocator, &.{ "kernel/fs/ext4/ext4.ko.zst", "kernel/drivers/android/binder_linux.ko.zst" });
    defer allocator.free(with_binder);
    try requireInitramfsModules(allocator, with_binder, &core_required_initramfs_modules);
}

test "core package policy rejects Anbox DKMS shadow packages" {
    const inventory =
        "ca-certificates\t1\tall\n" ++
        "initramfs-tools\t0.151\tall\n" ++
        "linux-azure\t7.0\tamd64\n" ++
        "openssh-client\t10.2\tamd64\n" ++
        "openssh-server\t10.2\tamd64\n" ++
        "sudo\t1.9\tamd64\n" ++
        "ubuntu-minimal\t1\tamd64\n";
    try validateExactLock(inventory, profileFor(.x86_64), .core);
    try std.testing.expectError(
        error.ForbiddenCorePackage,
        validateExactLock(inventory ++ "anbox-modules-dkms\t1\tamd64\n", profileFor(.x86_64), .core),
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
    try validateExactLock(amd64_lock, profileFor(.x86_64), .full);
    try std.testing.expectError(error.ForeignArchitecturePackage, validateExactLock(
        amd64_lock ++ "libc6\t2.43\tarm64\n",
        profileFor(.x86_64),
        .full,
    ));
    try std.testing.expectError(
        error.ExactLockIncomplete,
        validateExactLock("linux-azure\t7.0\tamd64\n", profileFor(.x86_64), .full),
    );
}

test "core package policy rejects server agents foreign packages and closure drift" {
    const inventory =
        "ca-certificates\t1\tall\n" ++
        "initramfs-tools\t0.151\tall\n" ++
        "linux-azure\t7.0\tamd64\n" ++
        "openssh-client\t10.2\tamd64\n" ++
        "openssh-server\t10.2\tamd64\n" ++
        "sudo\t1.9\tamd64\n" ++
        "ubuntu-minimal\t1\tamd64\n";
    try validateExactLock(inventory, profileFor(.x86_64), .core);
    try std.testing.expectError(
        error.ForbiddenCorePackage,
        validateExactLock(inventory ++ "cloud-init\t26.1\tall\n", profileFor(.x86_64), .core),
    );

    const exact_lock =
        \\{"target_architecture":"amd64","packages":[
        \\{"name":"ca-certificates","version":"1","architecture":"all"},
        \\{"name":"initramfs-tools","version":"0.151","architecture":"all"},
        \\{"name":"linux-azure","version":"7.0","architecture":"amd64"},
        \\{"name":"openssh-client","version":"10.2","architecture":"amd64"},
        \\{"name":"openssh-server","version":"10.2","architecture":"amd64"},
        \\{"name":"sudo","version":"1.9","architecture":"amd64"},
        \\{"name":"ubuntu-minimal","version":"1","architecture":"amd64"}]}
    ;
    try validateInventoryAgainstExactLock(
        std.testing.allocator,
        inventory,
        exact_lock,
        profileFor(.x86_64),
    );
    try std.testing.expectError(
        error.UnexpectedCorePackage,
        validateInventoryAgainstExactLock(
            std.testing.allocator,
            inventory ++ "unexpected\t1\tall\n",
            exact_lock,
            profileFor(.x86_64),
        ),
    );
}

test "core guest contract uses architecture-correct static artifacts and full generalization" {
    var elf: [20]u8 = @splat(0);
    @memcpy(elf[0..4], "\x7fELF");
    elf[5] = 1;
    std.mem.writeInt(u16, elf[18..20], 62, .little);
    try validateGuestElf(&elf, profileFor(.x86_64));
    try std.testing.expectError(
        error.WrongGuestExecutableArchitecture,
        validateGuestElf(&elf, profileFor(.aarch64)),
    );
    switch (generalizationPolicy(.core)) {
        .azure => |policy| {
            try std.testing.expect(policy.clear_machine_id);
            try std.testing.expect(policy.remove_ssh_host_keys);
            try std.testing.expect(policy.remove_agent_state);
            try std.testing.expect(policy.remove_dhcp_leases);
            try std.testing.expect(policy.clear_random_seed);
        },
        .none => return error.CoreGeneralizationMissing,
    }
    switch (generalizationPolicy(.full)) {
        .azure => |policy| {
            try std.testing.expect(!policy.clear_machine_id);
            try std.testing.expect(!policy.remove_agent_state);
        },
        .none => return error.FullGeneralizationMissing,
    }
}

test "core injection writes static agents links configuration and embedded evidence" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const image_path = "test-ubuntu2604-core-injection.raw";
    const spool_path = "test-ubuntu2604-core-injection.spool";
    const mizinit_path = "test-ubuntu2604-mizinit";
    const azagent_path = "test-ubuntu2604-azagent";
    defer Dir.cwd().deleteFile(io, image_path) catch {};
    defer Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Dir.cwd().deleteFile(io, mizinit_path) catch {};
    defer Dir.cwd().deleteFile(io, azagent_path) catch {};

    var elf: [20]u8 = @splat(0);
    @memcpy(elf[0..4], "\x7fELF");
    elf[5] = 1;
    std.mem.writeInt(u16, elf[18..20], 62, .little);
    try Dir.cwd().writeFile(io, .{ .sub_path = mizinit_path, .data = &elf });
    try Dir.cwd().writeFile(io, .{ .sub_path = azagent_path, .data = &elf });

    const length: u64 = 32 * 1024 * 1024;
    var image = try miz.Image.createExclusive(io, image_path, .raw, length, .{});
    defer image.close(io);
    var tree = miz.root_tree.RootTree.initMemory(allocator, io, .{});
    defer tree.deinit();
    for (&[_][]const u8{
        "usr", "usr/sbin", "etc",         "etc/ssh", "etc/ssh/sshd_config.d",
        "var", "var/lib",  "var/lib/miz",
    }) |directory| try tree.putDirectory(directory, .{ .mode = 0o755 });
    try tree.putSymlink("sbin", "usr/sbin", .{ .mode = 0o777 });
    _ = try miz.ext4.populate(io, image.file, allocator, try tree.cursor(), .{
        .length = length,
        .label = "cloudimg-rootfs",
    });

    var filesystem = try miz.ext4_mountless.FileSystem.open(allocator, io, image.file, .{
        .length = length,
        .spool_path = spool_path,
        .atomic_path = image_path,
    });
    defer filesystem.deinit();
    var evidence: [core_debz_packages.len]DebzEvidence = undefined;
    var initialized: usize = 0;
    defer for (evidence[0..initialized]) |*item| item.deinit(allocator);
    for (&core_debz_packages, 0..) |package, index| {
        const lock_path = try std.fmt.allocPrint(allocator, "test-core-{d}.lock.json", .{index});
        errdefer allocator.free(lock_path);
        const provenance_path = try std.fmt.allocPrint(allocator, "test-core-{d}.transaction.json", .{index});
        errdefer allocator.free(provenance_path);
        try Dir.cwd().writeFile(io, .{ .sub_path = lock_path, .data = "{}" });
        try Dir.cwd().writeFile(io, .{ .sub_path = provenance_path, .data = "{}" });
        evidence[index] = .{
            .package = package,
            .lock_path = lock_path,
            .lock_sha256 = @splat('1'),
            .lock_digest_sha256 = @splat('a'),
            .provenance_path = provenance_path,
            .provenance_sha256 = @splat('2'),
            .provenance_digest_sha256 = @splat('b'),
            .provenance_lock_sha256 = @splat('a'),
        };
        initialized += 1;
    }
    defer for (evidence[0..initialized]) |item| {
        Dir.cwd().deleteFile(io, item.lock_path) catch {};
        Dir.cwd().deleteFile(io, item.provenance_path) catch {};
    };

    try injectCoreGuest(
        allocator,
        io,
        &filesystem,
        profileFor(.x86_64),
        mizinit_path,
        azagent_path,
        &evidence,
    );
    const injected = try filesystem.read(allocator, "/usr/sbin/mizinit", 1024);
    defer allocator.free(injected);
    try std.testing.expectEqualSlices(u8, &elf, injected);
    const init_target = try filesystem.readLink(allocator, "/usr/sbin/init", 1024);
    defer allocator.free(init_target);
    try std.testing.expectEqualStrings("mizinit", init_target);
    const ssh_config = try filesystem.read(
        allocator,
        "/etc/ssh/sshd_config.d/10-mizinit.conf",
        4096,
    );
    defer allocator.free(ssh_config);
    try std.testing.expectEqualStrings(core_ssh_config, ssh_config);
    _ = try filesystem.stat("/var/lib/miz/provenance/test-core-0.lock.json");
    _ = try filesystem.stat("/var/lib/miz/ubuntu2604-core-provenance.json");
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
    var image = try miz.Image.create(
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
        // compressed qcow2 clusters are emitted natively by miz.qcow2.
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
    try std.testing.expectEqual(@as(usize, 10), parsed.value.object.count());
    try std.testing.expectEqual(@as(i64, 1), parsed.value.object.get("schema").?.integer);
    try std.testing.expectEqualStrings("miz-ubuntu2604-build-provenance", parsed.value.object.get("type").?.string);
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
    try std.testing.expectEqualStrings(
        "preserved",
        parsed.value.object.get("disk_layout").?.object.get("transform").?.string,
    );
    try std.testing.expectEqual(@as(usize, 4), parsed.value.object.get("artifacts").?.object.count());
}

test "fresh-root provenance binds flavor closure size and free-space evidence" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    // Both fresh-root flavors, because `baremetal` installs seven package
    // roots against core's four and a writer that only fits one of them
    // fails the other at the very end of a finished build.
    for ([_]Flavor{ .core, .baremetal }) |flavor| {
        const package_roots = flavor.debzPackages();
        const path = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}/{s}-provenance.json",
            .{ root_buffer[0..root_length], @tagName(flavor) },
        );
        defer std.testing.allocator.free(path);
        var evidence: [max_debz_packages]DebzEvidence = undefined;
        var initialized: usize = 0;
        defer for (evidence[0..initialized]) |*item| item.deinit(std.testing.allocator);
        for (package_roots, 0..) |package, index| {
            evidence[index] = .{
                .package = package,
                .lock_path = try std.fmt.allocPrint(std.testing.allocator, "/state/{s}.lock", .{package}),
                .lock_sha256 = @splat('1'),
                .lock_digest_sha256 = @splat('a'),
                .provenance_path = try std.fmt.allocPrint(std.testing.allocator, "/state/{s}.transaction.json", .{package}),
                .provenance_sha256 = @splat('2'),
                .provenance_digest_sha256 = @splat('b'),
                .provenance_lock_sha256 = @splat('a'),
            };
            initialized += 1;
        }
        try writeFreshRootProvenance(
            std.testing.allocator,
            std.testing.io,
            path,
            profileFor(.aarch64),
            flavor,
            @splat('5'),
            evidence[0..package_roots.len],
            flavor.defaultSize(),
            core_minimum_root_free_bytes + 4096,
        );
        const document = try Dir.cwd().readFileAlloc(
            std.testing.io,
            path,
            std.testing.allocator,
            .limited(64 * 1024),
        );
        defer std.testing.allocator.free(document);
        const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, document, .{});
        defer parsed.deinit();
        try std.testing.expectEqualStrings(@tagName(flavor), parsed.value.object.get("flavor").?.string);
        try std.testing.expectEqual(
            @as(i64, @intCast(flavor.defaultSize())),
            parsed.value.object.get("virtual_size").?.integer,
        );
        const debz_object = parsed.value.object.get("debz").?.object;
        try std.testing.expectEqual(
            package_roots.len,
            debz_object.get("transactions").?.array.items.len,
        );
        // The declared roots are this flavor's, not another flavor's.
        const declared = debz_object.get("package_roots").?.array.items;
        try std.testing.expectEqual(package_roots.len, declared.len);
        for (declared, package_roots) |item, expected|
            try std.testing.expectEqualStrings(expected, item.string);
        try std.testing.expectEqualStrings(
            "empty-debz-root",
            debz_object.get("baseline").?.object.get("source").?.string,
        );
        const disk_layout = parsed.value.object.get("disk_layout").?.object;
        try std.testing.expectEqualStrings(
            "arm64-esp-rebuild-v1",
            disk_layout.get("transform").?.string,
        );
        try std.testing.expectEqual(
            @as(i64, 1_050_623),
            disk_layout.get("esp").?.object.get("last_lba").?.integer,
        );
        try std.testing.expect(
            disk_layout.get("retired_xbootldr").?.object.get("cleared").?.bool,
        );
    }
}

test "fresh-root provenance rejects evidence that is not this flavor's roots" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(std.testing.io, &root_buffer);
    const path = try std.fs.path.join(
        std.testing.allocator,
        &.{ root_buffer[0..root_length], "mismatched-provenance.json" },
    );
    defer std.testing.allocator.free(path);
    var evidence: [core_debz_packages.len]DebzEvidence = undefined;
    var initialized: usize = 0;
    defer for (evidence[0..initialized]) |*item| item.deinit(std.testing.allocator);
    for (&core_debz_packages, 0..) |package, index| {
        evidence[index] = .{
            .package = package,
            .lock_path = try std.fmt.allocPrint(std.testing.allocator, "/state/{s}.lock", .{package}),
            .lock_sha256 = @splat('1'),
            .lock_digest_sha256 = @splat('a'),
            .provenance_path = try std.fmt.allocPrint(std.testing.allocator, "/state/{s}.transaction.json", .{package}),
            .provenance_sha256 = @splat('2'),
            .provenance_digest_sha256 = @splat('b'),
            .provenance_lock_sha256 = @splat('a'),
        };
        initialized += 1;
    }
    // Core's evidence offered for a bare-metal build: the wrong count.
    try std.testing.expectError(error.InvalidDebzEvidence, writeFreshRootProvenance(
        std.testing.allocator,
        std.testing.io,
        path,
        profileFor(.aarch64),
        .baremetal,
        @splat('5'),
        &evidence,
        baremetal_virtual_size,
        core_minimum_root_free_bytes + 4096,
    ));
    // Right count, wrong package: the last transaction names something core
    // never installs, which a count-only check would have accepted.
    evidence[core_debz_packages.len - 1].package = "cloud-init";
    try std.testing.expectError(error.InvalidDebzEvidence, writeFreshRootProvenance(
        std.testing.allocator,
        std.testing.io,
        path,
        profileFor(.aarch64),
        .core,
        @splat('5'),
        &evidence,
        core_virtual_size,
        core_minimum_root_free_bytes + 4096,
    ));
}
