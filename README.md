# miz

A Zig 0.16 library and CLI for reading, writing, converting, and building disk
images for bare-metal systems and virtual machines, including raw, VHD/VPC,
VHDX, and qcow2 formats. It also provides filesystem, boot configuration,
image customization, QEMU, and cloud-ready image workflows.

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
