#!/usr/bin/env python3
"""Builds a from-scratch OCI image layout overlaying a systemd EFI stub
(`linuxx64.efi.stub`) for use as the `MIZ_BOOT_TEST_UKI_OCI` fixture in CI.

`miz build-image --boot-mode uki` needs a systemd EFI stub (e.g.
`linuxx64.efi.stub`, typically from the `systemd-boot-unsigned`/
`systemd-boot-efi` package) to exist somewhere in the merged ISO/squashfs/
container source tree -- see the UKI guidance in `doc/image-building.md`.
`miz.bootconfig` discovers it by *basename* match anywhere in the merged
tree (not a fixed path), so this only needs to overlay the single stub file;
the archive path used below
(`usr/lib/systemd/boot/efi/linuxx64.efi.stub`) simply mirrors the
conventional on-disk location.

The stub itself is sourced from the host's own `systemd-boot-efi` package
(Ubuntu/Debian; installed separately, e.g. via `apt-get install -y
systemd-boot-efi` in CI) rather than built from scratch -- it's a real
PE/COFF EFI binary, not something worth reimplementing for a test fixture.

Usage: make-uki-stub-oci-fixture.py <output-dir> <path-to-linuxx64.efi.stub>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_layout import build_single_layer_oci_layout


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <output-dir> <path-to-linuxx64.efi.stub>", file=sys.stderr)
        return 2

    out_dir = sys.argv[1]
    stub_path = sys.argv[2]

    with open(stub_path, "rb") as f:
        stub_bytes = f.read()
    if len(stub_bytes) < 2 or stub_bytes[0:2] != b"MZ":
        print(f"warning: {stub_path} doesn't look like a PE/COFF EFI binary (missing 'MZ' header)", file=sys.stderr)

    build_single_layer_oci_layout(out_dir, {"usr/lib/systemd/boot/efi/linuxx64.efi.stub": stub_bytes})

    print(f"built UKI-stub OCI layout at {out_dir} (stub: {len(stub_bytes)} bytes from {stub_path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
