# vmiz

A Zig 0.16 library and CLI for reading, writing, converting, and building VM
disk images, including raw, VHD/VPC, VHDX, and qcow2 formats. It also provides
filesystem, boot configuration, image customization, QEMU, and Azure-ready
image workflows.

## Install

Install the pre-built `vmiz` CLI from GitHub Releases with [ghr](https://github.com/cataggar/ghr):

```console
ghr install cataggar/vmiz@v0.2.0
```

The only executable in release archives is the `vmiz` CLI. Build from source
to use the library or the repository's other tools.

## Documentation

- [Documentation index](doc/readme.md)
- [Getting started](doc/getting-started.md)
- [Library API](doc/library-api.md)
- [Image building](doc/image-building.md)
- [OCI copy, inspect, and tag listing](doc/oci.md)
- [UKI signing certificate extraction](doc/uki-certificate.md)
- [Azure Linux images](doc/azure-linux.md)
- [QEMU](doc/qemu.md)

Licensed under the [MIT License](LICENSE).
