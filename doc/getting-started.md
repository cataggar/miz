# Getting started

## Requirements

- Zig **0.16.0** or later.
- `zig build` compiles the pinned static libzstd dependency from
  `build.zig.zon`; no system libzstd development package is needed for miz's
  zstd wrapper.
- `zig build test` additionally requires the `zstd` CLI for interoperability
  coverage. On Debian-family systems:

  ```console
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends zstd
  ```

- `miz qemu` additionally requires [ghr](https://github.com/cataggar/ghr) for automatic known-image download. Install the packaged QEMU build with `ghr install cataggar/qemu`, or provide a system QEMU/UEFI installation.
- The released `miz` binary includes bzip2 support for packaged compressed firmware and does not require a system decompression tool.

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
