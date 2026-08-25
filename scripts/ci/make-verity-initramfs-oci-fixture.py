#!/usr/bin/env python3
"""Builds a from-scratch OCI image layout overlaying a verity-capable
initramfs at `boot/initramfs-<kver>.img`, for use as the
`MIZ_BOOT_TEST_VERITY_OCI` fixture in CI.

`miz build-image --verity` needs the source initramfs to already include
dm-verity userspace tooling (`systemd-veritysetup-generator`/
`systemd-veritysetup`/`veritysetup`) -- see "Producing a verity-capable
initramfs" in `doc/image-building.md`. Container layers always take
precedence over ISO/squashfs entries at the same path, so overlaying the
regenerated initramfs at the exact same `boot/initramfs-<kver>.img` path the ISO uses
(matching kernel version is essential -- see
`build-verity-initramfs-fixture.sh`, which produces both the initramfs and
its kernel version) cleanly replaces the stock copy with no extra `miz`
flag needed.

Usage: make-verity-initramfs-oci-fixture.py <output-dir> <path-to-initramfs> <kernel-version>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_layout import build_single_layer_oci_layout


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <output-dir> <path-to-initramfs> <kernel-version>", file=sys.stderr)
        return 2

    out_dir = sys.argv[1]
    initramfs_path = sys.argv[2]
    kver = sys.argv[3]

    with open(initramfs_path, "rb") as f:
        initramfs_bytes = f.read()

    archive_path = f"boot/initramfs-{kver}.img"
    build_single_layer_oci_layout(out_dir, {archive_path: initramfs_bytes})

    print(f"built verity-initramfs OCI layout at {out_dir} ({archive_path}: {len(initramfs_bytes)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
