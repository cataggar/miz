# Development

## Goal

Build a fixed, 1 MiB-aligned Azure-compatible VHD from the
[Azure Linux 4.0 ISO](https://aka.ms/azurelinux-4.0-x86_64.iso) plus a
container image, ready to upload as an Azure managed disk and run as a VM.
See [Image building](image-building.md) for the implemented format,
filesystem, container, boot, and `zvmi build-image` workflows.

## Layout

```
zvmi/
  build.zig               # top-level build graph
  build.zig.zon            # package manifest
  packages/
    zvmi/                   # the core disk-image library
      src/
        root.zig             # public API surface
        image.zig            # format-agnostic Image (open/create/read/write,
                              #   resize/check/map; raw + fixed/dynamic vhd +
                              #   vhdx + qcow2, file- or block-device-backed)
        block_device.zig      # block-device geometry probing
                              #   (BLKGETSIZE64/BLKSSZGET), since stat(2)
                              #   reports st_size == 0 for a device node
        fat32.zig             # FAT32 formatter + directory/file read/write
                              #   for partition-sized regions inside an Image
        vhd.zig               # VHD/VPC footer + dynamic header codec
                              #   (spec + QEMU-verified)
        vhdx.zig              # VHDX codec (header, region table, metadata,
                              #   BAT, create/pwrite/resize -- QEMU-verified)
        qcow2.zig              # qcow2 codec (header, L1/L2 cluster mapping,
                              #   create/pwrite/resize)
        iso9660.zig            # ISO9660 **read-only** codec (PVD, Rock
                              #   Ridge, Joliet)
        squashfs.zig           # squashfs **read-only** codec (superblock,
                              #   inode/directory/fragment tables, XZ/zstd
                              #   compressed blocks)
        oci.zig                # local OCI/docker-save image ingestion
                              #   plus shared OCI transport exports
        oci/                   # references/models, verified content, local
                              #   layouts, registry/auth, and copy engine
        ext4.zig              # native ext4 writer + readback helper (htree
                              #   dirs, metadata checksums, extent trees,
                              #   offline resize; opt-in JBD2 journal)
        bootconfig.zig         # ESP bootloader population (copy EFI binaries
                              #   + Secure Boot MOK/UKI orchestration)
        uki.zig                # low-level UKI/systemd-stub PE section
                              #   assembly helpers
        authenticode.zig       # native PE Authenticode signing and signer
                              #   certificate inspection
        uki_certificate.zig    # GPT/FAT32 fallback + named UKI signer
                              #   extraction and consistency checks
        verity.zig             # dm-verity SHA-256 hash-tree generation +
                              #   kernel cmdline metadata helpers
        cpio.zig               # minimal read-only newc-format cpio archive
                              #   reader (concatenated archives, e.g. dracut
                              #   early-cpio + main)
        initramfs.zig           # initramfs dm-verity userspace tooling
                              #   detection for `--verity` (issue #77)
        layout.zig             # partition-layout planner (sizing math,
                              #   alignment, DPS type GUIDs)
        guid.zig               # mixed-endian GUID encoding + well-known
                              #   partition type GUIDs (ESP, Linux data)
        mbr.zig                # MBR partition table codec (protective +
                              #   plain single-partition)
        gpt.zig                # GPT header + partition entry array codec
                              #   (CRC-32, spec-verified layout)
        lvm.zig                # read-only LVM2 reader for offline images:
                              #   label, PV header, metadata area, volume
                              #   group text, extent-to-offset mapping
        azure.zig              # 1 MiB alignment + Gen1/Gen2 partition-style
                              #   checks (backs `zvmi azure fixup`)
        deprovision.zig        # offline image generalization: resets
                              #   hostname/SSH host keys/machine-id/DHCP
                              #   state (+ optional user removal) directly
                              #   via ext4.Editor (backs
                              #   `zvmi azure deprovision`; issue #110)
        tar.zig                # minimal private USTAR reader/writer shared by
                              #   OCI layer ingestion and COSI packaging
        zstd.zig               # minimal private raw-block zstd codec for COSI
        cosi.zig               # COSI writer (tar + metadata.json + raw.zst parts)
        build_image.zig        # ISO + OCI -> raw/fixed-VHD orchestration
        formats.zig           # Format enum (raw, vhd, vhdx, qcow2)
        size.zig              # qemu-img-style size suffix parsing (K/M/G/T)
  cli/
    src/
      main.zig               # `zvmi` executable entry point
      commands/
        create.zig            # `zvmi create`
        info.zig              # `zvmi info`
        convert.zig           # `zvmi convert`
        resize.zig            # `zvmi resize`
        check.zig             # `zvmi check`
        map.zig               # `zvmi map`
        azure.zig             # Azure fixed-VHD derivation/readiness helpers
        cosi.zig              # `zvmi cosi`
        oci.zig               # `zvmi oci` transport and bundle commands
        build_image.zig       # `zvmi build-image`
        qemu.zig              # `zvmi qemu`
        opts.zig              # shared `-o subformat=...` parsing
  zvminit/                  # minimal PID 1 for real-boot testing of
                              #   --skip-iso-rootfs images (see zvminit/README.md)
  qmp/                      # native Zig QEMU Machine Protocol (QMP) client,
                              #   MIT licensed (see qmp/README.md)
  qemu/
    bzip2.zig               # embedded bzip2 streaming decoder binding
    host.zig                # shared host QEMU executable + OVMF discovery
  nbd/                      # native Zig NBD client + reference server, MIT
                              #   licensed (see nbd/README.md)
  qcow2/                    # native Zig qcow2 reader/writer, MIT licensed
                              #   (see qcow2/README.md -- a separate,
                              #   standalone implementation from
                              #   packages/zvmi/src/qcow2.zig, kept for its
                              #   CLI + qemu-img cross-validation
                              #   methodology; see issue #96)
  wireserver/
    wireserver.zig            # native Zig client for the Azure WireServer
                              #   goal-state protocol (minimal provisioning
                              #   subset): version negotiation, goal-state
                              #   fetch, health reporting -- a building
                              #   block for the future `azagent` guest
                              #   provisioning executable (issue #112)
    xml.zig                   # minimal hand-rolled XML parser sufficient for
                              #   the concrete goal-state/health-report shapes
  azagent/                  # minimal guest provisioning agent for first-boot
                              #   Azure VM setup (issue #112); statically
                              #   linked, imports wireserver
    main.zig                  # entry point + provision() orchestration
    ovf.zig                   # ovf-env.xml parser (hostname/username/ssh keys)
    cdrom.zig                  # locates/mounts/reads ovf-env.xml off the
                              #   provisioning CD-ROM/DVD
    hostname.zig                # sethostname(2) + /etc/hostname
    passwd.zig                  # direct /etc/passwd,shadow,group editing
                              #   (useradd/usermod -L equivalent) + root
                              #   password lock
    sudoers.zig                 # /etc/sudoers.d/azagent NOPASSWD drop-in
    ssh_keys.zig                 # ~/.ssh/authorized_keys deployment + SSH
                              #   host key regeneration (ssh-keygen -A)
    sentinel.zig                # /var/lib/azagent/provisioned first-boot
                              #   sentinel
    waagent_conf.zig             # minimal /etc/waagent.conf reader (issue
                              #   #125): parses the real format, but only
                              #   honors a small explicit key whitelist --
                              #   not full waagent.conf compatibility
    root_resize.zig              # grows the root partition + ext4 filesystem
                              #   to fill a larger deployed disk (issue #130,
                              #   "growpart" equivalent); runs every boot,
                              #   not sentinel-gated
  tests/
    oci_registry.zig        # deterministic loopback registry/auth/TLS/copy
                              #   transport coverage
    boot_smoke.zig          # opportunistic real-QEMU boot verification for
                              #   build-image output (Gen1/Gen2, --verity,
                              #   --boot-mode uki); driven by qmp, skips
                              #   gracefully when qemu-system-x86_64, OVMF, or
                              #   the ZVMI_BOOT_TEST_* fixture env vars aren't
                              #   available
    freebsd15_boot.zig
                              #   opt-in generalized FreeBSD acceptance under
                              #   architecture-matched UEFI QEMU, including
                              #   SSH and reboot
  scripts/
    build_generalized_azurelinux4.zig  # generalized Azure Linux 4 Gen2 QCOW2
                              #   builder (run via `zig build generalized-azurelinux4`)
    build_generalized_freebsd15.zig
                              #   generalized FreeBSD 15.1 QCOW2 builder
                              #   (run via `zig build generalized-freebsd15`)
    zstd_max_preload.zig       # LD_PRELOAD shared library that forces maximum
                              #   zstd compression level in qemu-img
    ci/
      make-minimal-oci-fixture.py   # builds a tiny from-scratch OCI layout
                              #   used as the boot-smoke tests' --container
                              #   fixture in CI
      fetch-vm-boot-kernel.sh # fetches the kernel the vm backend's real-boot
                              #   tests boot a guest with, for either
                              #   architecture
  .github/
    workflows/
      ci.yml                 # required build + test for pushes and PRs
      boot-smoke.yml         # required for release tags; also manual
```


## CI

`.github/workflows/ci.yml` runs the required `zig fmt --check`, `zig build`, and `zig build test` checks on every pull request and push to `main`. It also boots a real guest through the `vm` customization backend, both same- and cross-architecture (see below).

### The vm backend's tests

Four steps, cheapest first:

- `zig build test-vm-backend` runs `tests/vm_backend_integration.zig`, which
  stands in for the emulator by re-entering the test binary under
  `qemu-system-<arch>`. It needs nothing installed and is part of
  `zig build test`.
- `zig build test-vm-real-boot` runs `tests/vm_real_boot.zig` against a real
  emulator and a real distribution kernel. It is the only place the guest
  agent's mount, chroot and teardown paths execute at all, since they have to
  be PID 1 to run. It is opt-in because it needs a kernel and an emulator that
  no unit test can assume:

  ```
  ghr install cataggar/qemu@v11.0.91-z.15
  scripts/ci/fetch-vm-boot-kernel.sh fixtures/vm-boot-kernel

  ZVMI_RUN_VM_BOOT_TEST=1 \
  ZVMI_VM_BOOT_KERNEL=... ZVMI_VM_BOOT_MODULES_BUILTIN=... \
  ZVMI_VM_QEMU=$(readlink -f "$(command -v qemu-system-$(uname -m))") \
    zig build test-vm-real-boot
  ```

  `ZVMI_VM_ACCEL` defaults to `software`, because no hosted runner class
  guarantees `/dev/kvm` and a test that demands one is a test that quietly
  stops running. `ZVMI_VM_BOOT_WORKDIR` (default `/tmp`) moves the workspace,
  which needs room for two copies of the image.
- The same test with `ZVMI_VM_BOOT_ARCH` naming the *other* architecture is the
  cross-architecture acceptance test: the kernel, the guest agent and the
  binary the guest executes are all the guest's, and only the emulator is the
  host's. Pass the matching `ZVMI_VM_QEMU` and a kernel for that architecture.
  One `cataggar/qemu` ghr install supplies every `qemu-system-*`.

- `zig build test-vm-firmware-boot` runs `tests/vm_firmware_boot.zig`, which
  attests a *bootable* image through real EDK2 firmware. Firmware boot is the
  one part of the backend a synthesized fixture cannot cover: `vm_real_boot`'s
  image has no bootloader and no ESP, so no firmware could ever boot it. It is
  opt-in for that reason:

  ```
  ghr install cataggar/qemu@v11.0.91-z.15

  ZVMI_RUN_VM_FIRMWARE_TEST=1 \
  ZVMI_VM_FIRMWARE_IMAGE=/path/to/bootable.raw \
  ZVMI_VM_FIRMWARE_MARKER='Welcome to Azure Linux' \
  ZVMI_VM_QEMU=$(readlink -f "$(command -v qemu-system-$(uname -m))") \
    zig build test-vm-firmware-boot
  ```

  With `ZVMI_VM_FIRMWARE_CODE`/`ZVMI_VM_FIRMWARE_VARS` unset, the firmware is
  resolved through the same `qemu_host` search `zvmi qemu` uses, so the
  resolution path a real build takes is exercised too. Set
  `ZVMI_VM_FIRMWARE_ARCH` to the other architecture for the cross-architecture
  case, `ZVMI_VM_FIRMWARE_SECURE_BOOT=1` for the Secure Boot wiring, and
  `ZVMI_VM_FIRMWARE_TIMEOUT` to change the 1800-second budget. The image is
  attested in place and the test fails if a single byte of it changed, which is
  the read-only claim checked against a real emulator rather than a stand-in.

Both real boots take roughly 15 seconds under pure TCG, fixture construction
included, which is why they run in `ci.yml` rather than `boot-smoke.yml`.

CI cannot use the runner's own kernel: the guest agent runs as `rdinit`, so
whatever the guest needs is either built into the kernel or inserted from the
image's own `lib/modules/<release>` tree, and the runner's kernel has no such
tree to hand. Two pinned kernels are fetched instead, and between them they
cover both halves of that sentence:

- `fetch-vm-boot-kernel.sh` fetches an Azure Linux kernel, which builds `ext4`,
  `virtio_scsi` and `virtio_net` in. It proves the built-in path, and it is the
  kernel this project's own images run.
- `fetch-vm-boot-modular-kernel.sh` fetches a Debian *generic* kernel, which
  modularizes `ext4`, `virtio_blk`, `virtio_scsi`, `sd_mod` and `virtio_pci`.
  Pointing `ZVMI_VM_BOOT_MODULE_TREE` at the tree it prints stages that tree
  into the synthetic image, so the guest reaches its root only if the backend
  resolved the dependency closure, appended the modules to the initramfs and
  inserted them in order. With the variable unset the test behaves exactly as
  it did before, which is what keeps the built-in run an unchanged control.

  Debian ships no `modules.dep` in the `.deb` — `depmod` runs from the
  postinst — so the script runs `depmod` itself, and it prunes the 288 MiB
  tree to the subtrees the closure can reach. It needs `binutils` (for `ar`)
  and `kmod` (for `depmod`).

`.github/workflows/boot-smoke.yml` runs `zig build test-boot-smoke` for every release tag and when manually dispatched. It installs `qemu-system-x86`/`ovmf`, downloads and caches the [Azure Linux 4.0 ISO](https://aka.ms/azurelinux-4.0-x86_64.iso), and builds the OCI fixtures used by the real-QEMU tests. The job is required (not `continue-on-error`) for release tags but is not part of universal pull-request CI.


## Notes on Zig 0.16

This codebase targets Zig 0.16's new `std.Io` interface: every filesystem,
clock, and randomness operation takes an explicit `io: std.Io` parameter
(via `std.process.Init.io` in the CLI, or `std.testing.io` in tests) rather
than relying on implicit global state.
