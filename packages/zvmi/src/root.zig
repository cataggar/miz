//! zvmi: a Zig library for reading and writing VM disk image formats
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
//! qcow2 read/write, VHDX read/write, ISO9660/squashfs
//! **read-only** (including squashfs XZ/zstd-compressed blocks), local OCI image ingestion, a minimal native ext4
//! writer/readback helper, COSI output packaging, and the initial
//! `build-image` orchestration pipeline for ISO + OCI -> raw/fixed-VHD/VHDX/qcow2.

const std = @import("std");

pub const vhd = @import("vhd.zig");
pub const vhdx = @import("vhdx.zig");
pub const qcow2 = @import("qcow2.zig");
pub const fat32 = @import("fat32.zig");
pub const iso9660 = @import("iso9660.zig");
pub const squashfs = @import("squashfs.zig");
pub const ext4 = @import("ext4.zig");
pub const bootconfig = @import("bootconfig.zig");
pub const uki = @import("uki.zig");
pub const guid = @import("guid.zig");
pub const mbr = @import("mbr.zig");
pub const gpt = @import("gpt.zig");
pub const azure = @import("azure.zig");
pub const deprovision = @import("deprovision.zig");
pub const layout = @import("layout.zig");
pub const oci = @import("oci.zig");
pub const cosi = @import("cosi.zig");
pub const build_image = @import("build_image.zig");
pub const customize = @import("customize.zig");
pub const cpio = @import("cpio.zig");
pub const kernel_modules = @import("kernel_modules.zig");
pub const root_tree = @import("root_tree.zig");
pub const preserved_image = @import("preserved_image.zig");
pub const os_customization = @import("os_customization.zig");
pub const customization_wire = @import("customization_wire.zig");
pub const preserved_image_wire = @import("preserved_image_wire.zig");
pub const unsafe_chroot = @import("unsafe_chroot.zig");
pub const vm_backend = @import("vm_backend.zig");
pub const vm_control = @import("vm_control.zig");
pub const vm_payload = @import("vm_payload.zig");
pub const artifact_pipeline = @import("artifact_pipeline.zig");
pub const verity = @import("verity.zig");
pub const authenticode = @import("authenticode.zig");
pub const uki_certificate = @import("uki_certificate.zig");
const image_mod = @import("image.zig");
const size_mod = @import("size.zig");

pub const Format = image_mod.Format;
pub const Image = image_mod.Image;
pub const Info = image_mod.Info;
pub const CreateOptions = image_mod.CreateOptions;
pub const VhdSubformat = image_mod.VhdSubformat;
pub const copyAll = image_mod.copyAll;

pub const parseSize = size_mod.parseSize;

test {
    std.testing.refAllDecls(@This());
}
