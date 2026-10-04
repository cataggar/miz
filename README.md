# miz

A Zig 0.17 library and CLI for reading, writing, converting, and building disk
images for bare-metal systems and virtual machines, including raw, VHD/VPC,
VHDX, and qcow2 formats. It also provides filesystem, boot configuration,
image customization, QEMU, and cloud-ready image workflows.

**Zig 0.17 source compatibility.**

This branch preserves the exact `b243969` consumer generation, including
released ESP/UKI preservation, root customization, artifact acquisition,
deadlines/offline package-lock inputs and ARM Binder behavior. It does not
adopt subsequent default-branch image changes or refresh released assets.
The preserved helper checks the resolved output target; native tailnet-style
rebuilds retain the released ESP. See [Image building](doc/image-building.md).

The debz, TLS, bzip2 and zstd source prerequisites are exact tested
compatibility revisions. C translation uses GitHub `cataggar/translate-c`
at `62d06a5`; libc-free module graphs retain their existing policy.
The exact-generation RPM port at `c9b23a2`, lazy tool-path environment
wrapper and retained phase-failure diagnostics address those source
prerequisites. The full safe source graph passes (239 steps), along with
native tooling and static x86_64/AArch64 payload builds. Tool-path tests
also pass with spaces and apostrophes in a real install prefix. Native
macOS/AArch64 execution and broader image/privileged acceptance remain open.
The source target
is Zig 0.17.0, Linux 5.10+ and macOS 15+; image/hardware acceptance and
publication are not claimed.
The compatibility branch's native source CI is manual-only and selects
the signed Zig 0.17 compiler; it has not been dispatched.

## Install

Install the pre-built `miz` CLI from GitHub Releases with [ghr](https://github.com/cataggar/ghr):

```console
ghr install cataggar/miz@v0.2.0
```

The only executable in release archives is the `miz` CLI. Build from source
to use the library or the repository's other tools.

The current naming is a hard cutover with no compatibility aliases or
fallbacks. See [Migration and breaking changes](doc/migration.md).

## Documentation

- [Documentation index](doc/readme.md)
- [Migration and breaking changes](doc/migration.md)
- [Getting started](doc/getting-started.md)
- [Library API](doc/library-api.md)
- [Image building](doc/image-building.md)
- [OCI copy, inspect, and tag listing](doc/oci.md)
- [UKI signing certificate extraction](doc/uki-certificate.md)
- [Azure Linux images](doc/azure-linux.md)
- [Ubuntu 26.04 virtual-machine and bare-metal images](doc/ubuntu.md)
- [QEMU](doc/qemu.md)

Licensed under the [MIT License](LICENSE).
