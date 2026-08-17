#!/usr/bin/env python3
"""Builds a minimal, from-scratch OCI image layout for use as the
`--container`/`VMIZ_BOOT_TEST_OCI` fixture in CI, without depending on
network access to a container registry.

The resulting layout contains a single tiny layer (just a `/hello` text
file) -- enough for `vmiz build-image` to have a valid OCI container to
merge on top of the real ISO/squashfs rootfs, matching the "container
becomes the effective root filesystem" documentation in
`doc/image-building.md` without needing anything from it beyond
`architecture`/`os` and one harmless file.

Usage: make-minimal-oci-fixture.py <output-dir>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oci_layout import build_single_layer_oci_layout


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <output-dir>", file=sys.stderr)
        return 2

    out_dir = sys.argv[1]
    build_single_layer_oci_layout(out_dir, {"hello.txt": b"hello from vmiz CI\n"})

    print(f"built minimal OCI layout at {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
