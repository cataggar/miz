#!/usr/bin/env bash
# Builds a verity-capable initramfs (i.e. one with dm-verity userspace
# tooling added via `dracut --add systemd-veritysetup`) from a real Azure
# Linux ISO fixture, for use as the VMIZ_BOOT_TEST_VERITY_OCI fixture in CI.
#
# See "Producing a verity-capable initramfs" in doc/image-building.md for
# the manual version of this recipe. This script automates it against the
# same ISO fixture the boot-smoke job already downloads
# (VMIZ_BOOT_TEST_ISO), rather than a separately-provisioned installed
# system, so the exact kernel/module version always matches what the
# boot-smoke tests actually boot.
#
# Azure Linux's installer/live media ships an ext4 rootfs image nested
# inside an outer squashfs wrapper (LiveOS/squashfs.img -> LiveOS/rootfs.img
# -- see build_image.zig's "LiveOS-style media" handling for why vmiz itself
# reads it the same way), and that rootfs already has `dracut`/`tdnf` plus
# working package-repo config, but lacks `veritysetup` (dm-verity userspace
# tooling) since it's live/installer media, not the installed system.
#
# Usage: build-verity-initramfs-fixture.sh <iso-path> <output-initramfs-path>
#
# On success, writes the initramfs to <output-initramfs-path> and the exact
# kernel version string (needed to name the OCI overlay entry
# boot/initramfs-<kver>.img so it precisely replaces the ISO's own copy) to
# <output-initramfs-path>.kver.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <iso-path> <output-initramfs-path>" >&2
    exit 2
fi

iso_path=$1
out_initramfs=$2

work=$(mktemp -d)
cleanup() {
    sudo umount "$work/rootfs/dev" 2>/dev/null || true
    sudo umount "$work/rootfs/proc" 2>/dev/null || true
    sudo umount "$work/rootfs/sys" 2>/dev/null || true
    sudo umount "$work/rootfs" 2>/dev/null || true
    sudo umount "$work/squash" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/squash" "$work/rootfs"

echo "extracting LiveOS/squashfs.img from $iso_path"
bsdtar -C "$work" -xf "$iso_path" LiveOS/squashfs.img

# squashfs.img itself is just a read-only wrapper around one nested ext4
# image (LiveOS/rootfs.img); mount it to pull that image out, since we need
# a writable copy for tdnf/dracut to operate on.
sudo mount -o loop,ro "$work/LiveOS/squashfs.img" "$work/squash"
# The nested image is root-only readable (mode 0600) inside the squashfs,
# so plain `cp` as the invoking (non-root) user fails with EACCES.
sudo cp --sparse=always "$work/squash/LiveOS/rootfs.img" "$work/rootfs.img"
sudo chown "$(id -u):$(id -g)" "$work/rootfs.img"
sudo umount "$work/squash"

sudo mount -o loop "$work/rootfs.img" "$work/rootfs"

initramfs_name=$(sudo find "$work/rootfs/boot" -maxdepth 1 -name 'initramfs-*.img' -printf '%f\n' | head -1)
if [ -z "$initramfs_name" ]; then
    echo "error: couldn't find boot/initramfs-*.img in the extracted rootfs" >&2
    exit 1
fi
kver=${initramfs_name#initramfs-}
kver=${kver%.img}
echo "found kernel version: $kver"

sudo mount --bind /dev "$work/rootfs/dev"
sudo mount --bind /proc "$work/rootfs/proc"
sudo mount --bind /sys "$work/rootfs/sys"
sudo cp /etc/resolv.conf "$work/rootfs/etc/resolv.conf"

echo "installing dracut/veritysetup/systemd in the chroot"
sudo chroot "$work/rootfs" /usr/bin/tdnf install -y dracut veritysetup systemd

# The dracut module is named `systemd-veritysetup`, not `veritysetup` --
# confirmed by testing against real Azure Linux dracut packages (both 3.0's
# 102-13.azl3 and this ISO's 4.0 107-9.azl4): `dracut --list-modules` only
# ever lists `systemd-veritysetup` (see modules.d/01systemd-veritysetup).
echo "running dracut --add systemd-veritysetup for kernel $kver"
# --force-drivers is essential here: dracut (seeing the *invoking host's*
# real hardware via the bind-mounted /proc/sys, not the eventual QEMU
# boot-smoke guest's virtio-blk/virtio-pci virtual hardware) would otherwise
# hostonly-detect only drivers relevant to the CI runner itself, silently
# dropping the storage driver the QEMU guest actually needs and hanging
# very early at boot before the root device is even found. Explicitly
# forcing in the small set of virtio drivers QEMU emulates (rather than
# --no-hostonly, which pulls in every available driver and produces a
# ~70+ MiB initramfs that trips oci.zig's 64 MiB max_blob_size guard) keeps
# the initramfs close to its original, hostonly-trimmed size.
#
# dm-verity also needs forcing in for the same hostonly-detection reason:
# the systemd-veritysetup dracut module only pulls in the actual dm-verity
# *target* kernel module (dm-verity, registering the "verity" device-mapper
# target type) when hostonly mode also detects real dm-verity usage on the
# *build host* -- which it never will here, since the CI runner obviously
# isn't itself booted with --verity. Without it, device-mapper's core still
# loads fine (dm_mod), but `systemd-veritysetup@root.service` fails with
# "verity: unknown target type" / "error adding target to table" the moment
# it tries to actually create the verity-protected root device.
sudo chroot "$work/rootfs" /usr/bin/dracut --force-drivers "virtio_pci virtio_blk virtio_scsi dm-verity" --add systemd-veritysetup --force --kver "$kver" "/tmp/initramfs-verity.img"

mkdir -p "$(dirname "$out_initramfs")"
sudo cp "$work/rootfs/tmp/initramfs-verity.img" "$out_initramfs"
sudo chown "$(id -u):$(id -g)" "$out_initramfs"
echo -n "$kver" >"${out_initramfs}.kver"

echo "wrote verity-capable initramfs for kernel $kver to $out_initramfs"
