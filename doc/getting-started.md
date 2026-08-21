# Getting started

## Requirements

- Zig **0.16.0** or later.
- `zig build test` requires the `zstd` CLI for encoder interoperability tests.
  On Debian-family systems, install `zstd` and `libzstd-dev` together from the
  same distribution repository so the CLI and system library use the same
  zstd source version:

  ```console
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends liblzma-dev libzstd-dev zstd
  ```

- `vmiz qemu` additionally requires [ghr](https://github.com/cataggar/ghr) for automatic known-image download. Install the packaged QEMU build with `ghr install cataggar/qemu`, or provide a system QEMU/UEFI installation.
- The released `vmiz` binary includes bzip2 support for packaged compressed firmware and does not require a system decompression tool.

## Build and run

```console
zig build
zig build test
zig build test-boot-smoke
zig build test-freebsd15-boot
zig build run -- info foo.vhd
zig build run -- qemu
```

See [Image building](image-building.md) for advanced image commands,
[Azure Linux images](azure-linux.md) and
[Ubuntu 26.04 images](ubuntu.md) for hosted release recipes, and
[FreeBSD images](freebsd.md) for the FreeBSD workflow.
