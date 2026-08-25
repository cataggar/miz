# Documentation

`miz` is a Zig library and CLI for disk formats, filesystem construction, boot
configuration, and image customization for bare-metal systems and virtual
machines, including QEMU and cloud-ready workflows.

## Getting started

- [Migration and breaking changes](migration.md)
- [Getting started](getting-started.md)
- [QEMU](qemu.md)

## APIs and image building

- [Library API](library-api.md)
- [Image building](image-building.md)
- [Ubuntu and Debian package families](debian-package-family.md)
- [Host RPM package family](rpm-package-family.md)
- [OCI copy, inspect, and tag listing](oci.md)
- [UKI signing certificate extraction](uki-certificate.md)
- [mizinit](https://github.com/cataggar/miz/blob/main/mizinit/README.md)

## Platform images

- [Azure Linux images](azure-linux.md)
- [Ubuntu 26.04 full, core, and bare-metal images](ubuntu.md)
- [FreeBSD images](freebsd.md)

## Development

- [Development and repository layout](development.md)
- [QMP client](https://github.com/cataggar/miz/blob/main/qmp/README.md)
- [NBD client and reference server](https://github.com/cataggar/miz/blob/main/nbd/README.md)
- [Standalone qcow2 implementation](https://github.com/cataggar/miz/blob/main/qcow2/README.md)
