#!/usr/bin/env bash
# Fetches the kernel and built-in module list that `zig build test-vm-real-boot`
# boots a guest with.
#
# The VM backend boots the image's own kernel directly with `rdinit=`, and the
# only drivers the guest gets are the ones that kernel built in plus whatever
# the image's own module tree can supply. That rules out the runner's own
# kernel, which brings no such tree with it. Azure Linux builds ext4,
# virtio_scsi and virtio_net in, which is also what this project's images
# actually run, so the test boots the same kernel its users do.
#
# This is the built-in half of the boot coverage; fetch-vm-boot-modular-kernel.sh
# fetches a kernel that modularizes the same drivers, for the other half.
#
# The version is pinned rather than resolved from repodata. A kernel that
# disappears should fail this step loudly, not silently change what CI proves.
#
# Usage: fetch-vm-boot-kernel.sh <destination-directory> [architecture] [prefix]
#
# The architecture defaults to the host's; naming the other one is how the
# cross-architecture boot gets a kernel it can only run under emulation.
#
# Prints two lines on success:
#   <prefix>KERNEL=<path>
#   <prefix>MODULES_BUILTIN=<path>
# which can be appended straight to "$GITHUB_ENV". The prefix defaults to
# `MIZ_VM_BOOT_`.

set -euo pipefail

kernel_version="6.6.139.1-1.azl3"
base_url="https://packages.microsoft.com/azurelinux/3.0/prod/base"

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <destination-directory> [architecture] [prefix]" >&2
    exit 2
fi
destination="$1"
requested_architecture="${2:-$(uname -m)}"
prefix="${3:-MIZ_VM_BOOT_}"

case "$requested_architecture" in
    x86_64 | amd64) rpm_architecture="x86_64" ;;
    aarch64 | arm64) rpm_architecture="aarch64" ;;
    *)
        echo "fetch-vm-boot-kernel: unsupported architecture ${requested_architecture}" >&2
        exit 1
        ;;
esac

kernel_path="${destination}/boot/vmlinuz-${kernel_version}"
modules_builtin_path="${destination}/lib/modules/${kernel_version}/modules.builtin"

# The caller is expected to wrap this in actions/cache keyed on the version
# above, so a cache hit skips the download entirely.
if [ ! -f "$kernel_path" ] || [ ! -f "$modules_builtin_path" ]; then
    for tool in curl rpm2cpio zig; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "fetch-vm-boot-kernel: ${tool} is required to extract the kernel" >&2
            echo "on Debian and Ubuntu: sudo apt-get install -y rpm2cpio" >&2
            exit 1
        fi
    done
    mkdir -p "$destination"
    rpm_name="kernel-${kernel_version}.${rpm_architecture}.rpm"
    rpm_path="${destination}/${rpm_name}"
    curl -fL -sS --retry 3 -o "$rpm_path" \
        "${base_url}/${rpm_architecture}/Packages/k/${rpm_name}"

    # Only these two members are extracted: the rest of an Azure Linux kernel
    # package is the module tree, which an rdinit guest can never load.  The
    # native cpio reader rejects malformed metadata and unsafe paths.
    cpio_path="${destination}/${rpm_name}.cpio"
    rpm2cpio "$rpm_path" > "$cpio_path"
    zig run packages/miz/src/cpio_extract.zig -- "$cpio_path" "$destination" \
        "./boot/vmlinuz-${kernel_version}" \
        "./lib/modules/${kernel_version}/modules.builtin"
    rm -f "$rpm_path" "$cpio_path"
fi

for required in "$kernel_path" "$modules_builtin_path"; do
    if [ ! -f "$required" ]; then
        echo "fetch-vm-boot-kernel: ${required} was not produced" >&2
        exit 1
    fi
done

echo "${prefix}KERNEL=$(readlink -f "$kernel_path")"
echo "${prefix}MODULES_BUILTIN=$(readlink -f "$modules_builtin_path")"
