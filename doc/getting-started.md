# Getting started

## Requirements

- Zig **0.17.0**, matching the signed compiler pin used by CI and releases.
- Target OS floors, including guest targets: **Linux 5.10+**, **macOS 15+**,
  **Windows 10+**, and **FreeBSD 14+**. Linux-only image builders, package
  operations, privileged integrations, and VM boot tests still require Linux;
  portable CLI/library smoke tests run natively on Linux, macOS, and Windows.
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

The default optimization mode is `.safe`. Override it with
`-Doptimize=debug|safe|fast|small`; the former `Debug`, `ReleaseSafe`,
`ReleaseFast`, and `ReleaseSmall` spellings are not Zig 0.17 modes.

```console
zig build
zig build test
zig build test-boot-smoke
zig build test-freebsd15-boot
zig build run -- info foo.vhd
zig build run -- qemu
```

See [Image building](image-building.md) for advanced image commands,
[Azure Trusted Launch images](azure-trusted-launch.md),
[Azure Confidential VM images](azure-confidential-vm.md),
[Azure Linux images](azure-linux.md), and
[Ubuntu 26.04 images](ubuntu.md) for hosted release recipes, and
[FreeBSD images](freebsd.md) for the FreeBSD workflow.
