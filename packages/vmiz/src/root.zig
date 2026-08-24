//! vmiz: a Zig library for reading and writing VM disk image formats
//! (raw, VHD/VPC, VHDX, and qcow2), analogous to qemu-img's
//! block-driver layer. See the project plan for the full format roadmap and
//! the Azure Linux + container build-image workflow this library exists to
//! support.
//!
//! Milestone 7 status: raw + fixed/dynamic vhd read/write, MBR + GPT
//! partition table read/write, FAT32 filesystem read/write, native ESP
//! bootloader population (copy EFI binaries + generate grub.cfg/BLS),
//! Secure Boot MOK asset plumbing, UKI generation, dm-verity hash-tree
//! generation + kernel cmdline/COSI metadata wiring,
//! qcow2 read/write, VHDX read/write, ISO9660 read/write (reader handles
//! Rock Ridge/Joliet, combines multi-extent files, and models volume metadata
//! plus El Torito boot catalogs for a rewrite-preservation preflight; writer
//! emits deterministic Rock Ridge images with optional El Torito boot support
//! from a pull-based tree) and SquashFS
//! read/write (reader handles XZ/zstd-compressed blocks; writer emits zstd
//! or uncompressed images from a pull-based tree), local OCI image ingestion, a minimal native ext4
//! writer/readback helper, COSI output packaging, the `build-image`
//! orchestration pipeline for ISO + OCI -> raw/fixed-VHD/VHDX/qcow2, the
//! `build-iso` pipeline that regenerates a customized LiveOS ISO (ext4
//! rootfs.img wrapped in SquashFS at the LiveOS payload path, with recreated
//! El Torito boot entries), and the strict `recustomize-iso` pipeline that
//! rewrites a source ISO into a customized one while preserving its directory
//! tree, node metadata/timestamps, volume metadata, and El Torito catalog --
//! or refusing via the strict rewrite gate (PXE is out of scope).

const std = @import("std");

pub const vhd = @import("vhd.zig");
pub const vhdx = @import("vhdx.zig");
pub const qcow2 = @import("qcow2.zig");
pub const fat32 = @import("fat32.zig");
pub const iso9660 = @import("iso9660.zig");
pub const squashfs = @import("squashfs.zig");
pub const ext4 = @import("ext4.zig");
pub const ext4_mountless = @import("ext4_mountless.zig");
pub const ext4_native = ext4_mountless;
pub const xfs = @import("xfs.zig");
pub const xfs_writer = @import("xfs_writer.zig");
pub const tree_cursor = @import("tree_cursor.zig");
pub const bootconfig = @import("bootconfig.zig");
pub const boot_options = @import("boot_options.zig");
pub const grub_defaults = @import("grub_defaults.zig");
pub const uki = @import("uki.zig");
pub const uki_signing = @import("uki_signing.zig");
pub const guid = @import("guid.zig");
pub const mbr = @import("mbr.zig");
pub const gpt = @import("gpt.zig");
pub const lvm = @import("lvm.zig");
pub const azure = @import("azure.zig");
pub const deprovision = @import("deprovision.zig");
pub const root_resize = @import("root_resize.zig");
pub const layout = @import("layout.zig");
pub const filesystem_writer = @import("filesystem_writer.zig");
pub const oci = @import("oci.zig");
pub const cosi = @import("cosi.zig");
pub const build_image = @import("build_image.zig");
pub const build_iso = @import("build_iso.zig");
pub const recustomize_iso = @import("recustomize_iso.zig");
pub const customize = @import("customize.zig");
pub const cpio = @import("cpio.zig");
/// Deterministic Zstandard framing backed by linked libzstd.
pub const zstd = @import("zstd.zig");
pub const kernel_modules = @import("kernel_modules.zig");
pub const limits = @import("limits.zig");
pub const free_space = @import("free_space.zig");
pub const root_tree = @import("root_tree.zig");
pub const identity_rewrite = @import("identity_rewrite.zig");
pub const preserved_image = @import("preserved_image.zig");
pub const os_customization = @import("os_customization.zig");
pub const offline_root = @import("offline_root.zig");
pub const customization_wire = @import("customization_wire.zig");
pub const preserved_image_wire = @import("preserved_image_wire.zig");
pub const unsafe_chroot = @import("unsafe_chroot.zig");
pub const vm_backend = @import("vm_backend.zig");
pub const vm_control = @import("vm_control.zig");
pub const vm_payload = @import("vm_payload.zig");
pub const artifact_pipeline = @import("artifact_pipeline.zig");
pub const package_family = @import("package_family.zig");
pub const verity = @import("verity.zig");
pub const authenticode = @import("authenticode.zig");
pub const der = @import("der.zig");
pub const uki_certificate = @import("uki_certificate.zig");
pub const block_device = @import("block_device.zig");
pub const output = @import("output.zig");
pub const disk_assembly = @import("disk_assembly.zig");
pub const disk_fit = @import("disk_fit.zig");
const image_mod = @import("image.zig");
const size_mod = @import("size.zig");

pub const Format = image_mod.Format;
pub const Image = image_mod.Image;
pub const Info = image_mod.Info;
pub const CreateOptions = image_mod.CreateOptions;
pub const OpenOptions = image_mod.OpenOptions;
pub const DeviceWriteOptions = image_mod.DeviceWriteOptions;
pub const DeviceInfo = image_mod.DeviceInfo;
pub const DevicePreflightReport = block_device.PreflightReport;
pub const DeviceWriteOutcome = image_mod.DeviceWriteOutcome;
pub const CopyFinalization = image_mod.CopyFinalization;
pub const CopyResult = image_mod.CopyResult;
pub const VhdSubformat = image_mod.VhdSubformat;
pub const copyAll = image_mod.copyAll;
pub const copyAllBytes = image_mod.copyAllBytes;
pub const copyAllWithFinalization = image_mod.copyAllWithFinalization;

pub const OutputSpec = output.Spec;
pub const Compression = output.Compression;
pub const OutputDestination = output.Destination;

pub const parseSize = size_mod.parseSize;

test {
    std.testing.refAllDecls(@This());
}
