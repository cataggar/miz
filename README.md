# vmiz

A Zig 0.16 library and CLI for reading, writing, converting, and building VM
disk images, including raw, VHD/VPC, VHDX, and qcow2 formats. It also provides
filesystem, boot configuration, image customization, QEMU, and Azure-ready
image workflows.

## Zig 0.17 compatibility work (not consumer-ready)

This branch keeps the exact `e3f9051` vmiz generation rather than importing
later naming/API and image changes. Typed repetitions preserve fixture bytes
and sentinels; guest network and wait-status layouts remain unchanged. The
preserved released ESP/UKI, artifact acquisition, root customization,
deadlines and offline package-lock inputs are not refreshed.

Validation is blocked by the pinned RPM backend's removed configurer APIs
and C-import mechanism, and the separate legacy debz 0.2 source generation
at `9cabfc0`. Do not use this branch as a compatible consumer pin yet.
The source target is Zig 0.17.0, Linux 5.10+ and macOS 15+; no image
publication/deployment or hosted workflow dispatch is part of this work.
The compatibility branch's native source CI is manual-only and selects
the signed Zig 0.17 compiler; it has not been dispatched.

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
