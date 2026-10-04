# zvmi

A Zig 0.17 library and CLI for reading, writing, converting, and building VM
disk images, including raw, VHD/VPC, VHDX, and qcow2 formats. It also provides
filesystem, boot configuration, image customization, QEMU, and Azure-ready
image workflows.

This consumer compatibility branch ports `0e9f25f` without adopting the later
vmiz/miz naming cutovers or unrelated image behavior. The `zvmi` build-helper
and module names, preserved released ESP/signed UKI, artifact acquisition,
customization requests, offline package inputs and execution deadlines remain
unchanged. Source builds require Linux 5.10+ or macOS 15+. Released image
versions and package inputs are not refreshed or published by this port.
The preserved-image helper verifies the committed path against the unchanged
resolved plan, not the raw argument spelling. Relative maker paths beginning
with `./` remain supported without accepting a different output target.
A native tailnet-style rebuild and status check retain the complete released
ESP byte-for-byte. This is not guest boot or native macOS/AArch64 acceptance.

## Install

Install the pre-built `zvmi` CLI from GitHub Releases with [ghr](https://github.com/cataggar/ghr):

```console
ghr install cataggar/zvmi@v0.1.0
```

The only executable in release archives is the `zvmi` CLI. Build from source
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
