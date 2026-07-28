#!/usr/bin/env bash
# Fetches the kernel and built-in module list that `zig build test-vm-real-boot`
# boots a guest with.
#
# The VM backend boots the image's own kernel directly with `rdinit=`, so no
# module is ever inserted and every driver the guest needs must be built in.
# That rules out the runner's own kernel: Ubuntu modularizes ext4, so a guest
# booted on it can see the disk and cannot mount it. Azure Linux builds ext4,
# virtio_scsi and virtio_net in, which is also what this project's images
# actually run, so the test boots the same kernel its users do.
#
# The version is pinned rather than resolved from repodata. A kernel that
# disappears should fail this step loudly, not silently change what CI proves.
#
# Usage: fetch-vm-boot-kernel.sh <destination-directory>
#
# Prints two lines on success:
#   ZVMI_VM_BOOT_KERNEL=<path>
#   ZVMI_VM_BOOT_MODULES_BUILTIN=<path>
# which can be appended straight to "$GITHUB_ENV".

set -euo pipefail

kernel_version="6.6.139.1-1.azl3"
base_url="https://packages.microsoft.com/azurelinux/3.0/prod/base"

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <destination-directory>" >&2
    exit 2
fi
destination="$1"

case "$(uname -m)" in
    x86_64) rpm_architecture="x86_64" ;;
    aarch64 | arm64) rpm_architecture="aarch64" ;;
    *)
        echo "fetch-vm-boot-kernel: unsupported host architecture $(uname -m)" >&2
        exit 1
        ;;
esac

kernel_path="${destination}/boot/vmlinuz-${kernel_version}"
modules_builtin_path="${destination}/lib/modules/${kernel_version}/modules.builtin"

# The caller is expected to wrap this in actions/cache keyed on the version
# above, so a cache hit skips the download entirely.
if [ ! -f "$kernel_path" ] || [ ! -f "$modules_builtin_path" ]; then
    for tool in curl rpm2cpio cpio; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "fetch-vm-boot-kernel: ${tool} is required to extract the kernel" >&2
            echo "on Debian and Ubuntu: sudo apt-get install -y rpm2cpio cpio" >&2
            exit 1
        fi
    done
    mkdir -p "$destination"
    rpm_name="kernel-${kernel_version}.${rpm_architecture}.rpm"
    rpm_path="${destination}/${rpm_name}"
    curl -fL -sS --retry 3 -o "$rpm_path" \
        "${base_url}/${rpm_architecture}/Packages/k/${rpm_name}"

    # Only these two members are extracted: the rest of an Azure Linux kernel
    # package is the module tree, which an rdinit guest can never load.
    (
        cd "$destination"
        rpm2cpio "$rpm_name" | cpio -idm --quiet \
            "./boot/vmlinuz-${kernel_version}" \
            "./lib/modules/${kernel_version}/modules.builtin"
    )
    rm -f "$rpm_path"
fi

for required in "$kernel_path" "$modules_builtin_path"; do
    if [ ! -f "$required" ]; then
        echo "fetch-vm-boot-kernel: ${required} was not produced" >&2
        exit 1
    fi
done

echo "ZVMI_VM_BOOT_KERNEL=$(readlink -f "$kernel_path")"
echo "ZVMI_VM_BOOT_MODULES_BUILTIN=$(readlink -f "$modules_builtin_path")"
