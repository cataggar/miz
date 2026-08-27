# Development

## Goal

Build reproducible disk images for bare-metal systems and virtual machines.
The reference workflows include Azure-compatible VHDs built from the
[Azure Linux 4.0 ISO](https://aka.ms/azurelinux-4.0-x86_64.iso), Ubuntu
bare-metal images, and locally bootable QEMU images. See
[Image building](image-building.md) for the implemented format, filesystem,
container, boot, `miz build-image`, `miz build-iso`, and
`miz recustomize-iso` workflows.

## Layout

```
miz/
  build.zig               # top-level build graph
  build.zig.zon            # package manifest
  packages/
    miz/                   # the core disk-image library
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
        iso9660.zig            # ISO9660 read/write codec (PVD, Rock Ridge,
                              #   Joliet reader; writer emits deterministic
                              #   Rock Ridge images with both-endian path
                              #   tables and optional El Torito boot support;
                              #   readVolumeIdAlloc/readBootCatalog helpers)
        squashfs.zig           # squashfs read/write codec (superblock,
                              #   inode/directory/fragment tables, XZ/zstd
                              #   compressed blocks; writer emits zstd or
                              #   uncompressed images from a pull-based tree)
        oci.zig                # local OCI/docker-save image ingestion
                              #   plus shared OCI transport exports
        oci/                   # references/models, verified content, local
                              #   layouts, registry/auth, copy engine, and
                              #   cosign signature verification (cosign.zig
                              #   decides, cosign_discovery.zig fetches)
        ext4.zig              # native ext4 writer + readback helper (htree
                              #   dirs, metadata checksums, extent trees,
                              #   offline resize; opt-in JBD2 journal and
                              #   inode ratio)
        bootconfig.zig         # ESP bootloader population (copy EFI binaries
                              #   + Secure Boot MOK/UKI orchestration)
        uki.zig                # low-level UKI/systemd-stub PE section
                              #   assembly helpers
        authenticode.zig       # native PE Authenticode signing and signer
                              #   certificate inspection
        uki_certificate.zig    # GPT/FAT32 fallback + named UKI signer
                              #   extraction and consistency checks
        uki_signing.zig        # external signing-provider protocol, and
                              #   verification of what it returns
        verity.zig             # dm-verity SHA-256 hash-tree generation +
                              #   kernel cmdline metadata helpers
        cpio.zig               # strict deterministic newc/CRC cpio reader
                              #   and writer (safe paths, metadata and checks)
        verity_tooling.zig     # initramfs dm-verity userspace tooling
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
                              #   checks (backs `miz azure fixup`)
        deprovision.zig        # offline image generalization: resets
                              #   hostname/SSH host keys/machine-id/DHCP
                              #   state (+ optional user removal) directly
                              #   via ext4.Editor (backs
                              #   `miz azure deprovision`; issue #110)
        tar.zig                # minimal private USTAR reader/writer shared by
                              #   OCI layer ingestion and COSI packaging
        zstd.zig               # zstd support shared by COSI, SquashFS,
                              #   and streaming raw.zst output
        cosi.zig               # COSI writer (tar + metadata.json + raw.zst parts)
        build_image.zig        # ISO + OCI -> raw/fixed-VHD orchestration;
                              #   materializeCustomizedRootTree is shared with
                              #   build_iso
        build_iso.zig          # ISO + OCI -> generated LiveOS ISO (ext4
                              #   rootfs.img in SquashFS + El Torito), `build-iso`;
                              #   shares writeRootfsImage/wrapSquashfsPayload/
                              #   OutputIsoTree with recustomize_iso
        recustomize_iso.zig    # strict ISO in -> customized ISO out; preserves
                              #   the source tree/metadata/timestamps/volume/El
                              #   Torito catalog or refuses via the strict gate,
                              #   `recustomize-iso` (PXE out of scope)
        customize.zig          # the image-customization request: versioned
                              #   public types, planning, preflight, backend
                              #   selection, execution and provenance
        preserved_image.zig    # transactional mutation/rebuild of an existing
                              #   image through a full raw staging copy
        preserved_image_wire.zig # the versioned wire types the above
                              #   serializes, split out so the version can be
                              #   read without pulling in the engine
        unsafe_chroot.zig      # the privileged executing backend: mounts the
                              #   target root on the build machine and runs
                              #   the policy in a chroot, as a re-execed
                              #   worker that is PID 1 in its own namespaces
        vm_backend.zig         # host capability probe for the `vm` backend
        vm_control.zig         # the control and result documents exchanged
                              #   with the in-VM guest agent; the only route
                              #   by which shared modules reach the guest
        vm_payload.zig         # direct-kernel boot payload extraction from a
                              #   staged raw image
        packages.zig           # what both executing backends must agree on
        initramfs.zig          #   about package transactions, initramfs
        selinux.zig            #   regeneration and relabelling: tool paths,
                              #   argv shapes, configuration bodies and the
                              #   family probes' decision rules. These read no
                              #   filesystem and import only `std`, because
                              #   they are compiled into the guest agent as
                              #   well as the host -- each backend does its
                              #   own looking, since on `vm` only the guest
                              #   can see the target root
        formats.zig           # Format enum (raw, vhd, vhdx, qcow2)
        size.zig              # qemu-img-style size suffix parsing (K/M/G/T)
  mizguest/
    main.zig                # the guest agent: a static, libc-free PID 1 that
                              #   runs inside the image's own initramfs on the
                              #   `vm` backend, applies the control document
                              #   and reports the result. It imports exactly
                              #   two things -- `std` and `vm_control` -- and
                              #   reaches the shared modules above only as
                              #   re-exports of the latter
  build/
    image.zig               # `addImage`: the exported std.Build helper that
                              #   declares an image build, including the
                              #   registry image an input may name
    iso.zig                 # `addIso`: exported helper for a generated LiveOS
                              #   ISO product (separate from the disk builder);
                              #   `addRecustomize`: strict preserve-or-refuse ISO
                              #   recustomization helper
    oci.zig                 # `addOciPull`: pull a layout beside a build
  cli/
    src/
      main.zig               # `miz` executable entry point
      image_builder.zig      # `miz-image-builder`: turns declared arguments
                              #   into a customize request; pins a registry
                              #   tag before the request is built
      iso_builder.zig        # `miz-iso-builder`: host driver for the exported
                              #   addIso build helper (`miz.build_iso.build`)
      recustomize_iso_builder.zig  # `miz-recustomize-iso-builder`: host driver
                              #   for the exported addRecustomize helper
                              #   (`miz.recustomize_iso.build`)
      commands/
        create.zig            # `miz create`
        info.zig              # `miz info`
        convert.zig           # `miz convert`
        write.zig             # Linux block-device writer (`miz write`)
        resize.zig            # `miz resize`
        check.zig             # `miz check`
        map.zig               # `miz map`
        azure.zig             # Azure fixed-VHD derivation/readiness helpers
        cosi.zig              # `miz cosi`
        oci.zig               # `miz oci` transport and bundle commands
        build_image.zig       # `miz build-image`
        build_iso.zig         # `miz build-iso`
        recustomize_iso.zig   # `miz recustomize-iso`
        qemu.zig              # `miz qemu`
        opts.zig              # shared `-o subformat=...` parsing
  mizinit/                  # minimal PID 1 for real-boot testing of
                              #   --skip-iso-rootfs images (see mizinit/README.md)
  qmp/                      # native Zig QEMU Machine Protocol (QMP) client,
                              #   MIT licensed (see qmp/README.md)
  qemu/
    bzip2.zig               # bounded bzip2z streaming decoder adapter
    host.zig                # shared host QEMU executable + OVMF discovery
  nbd/                      # native Zig NBD client + reference server, MIT
                              #   licensed (see nbd/README.md)
  qcow2/                    # native Zig qcow2 reader/writer, MIT licensed
                              #   (see qcow2/README.md -- a separate,
                              #   standalone implementation from
                              #   packages/miz/src/qcow2.zig, kept for its
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
    stale_brand.zig         # tracked-tree guard: rejects the pre-rename
                              #   brands in path names, file bytes, and the
                              #   DER metadata of PEM certificates (run via
                              #   `zig build test-stale-brand`)
    oci_registry.zig        # deterministic loopback registry/auth/TLS/copy
                              #   transport coverage
    boot_smoke.zig          # opportunistic real-QEMU boot verification for
                              #   build-image output (Gen1/Gen2, --verity,
                              #   --boot-mode uki); driven by qmp, skips
                              #   gracefully when qemu-system-x86_64, OVMF, or
                              #   the MIZ_BOOT_TEST_* fixture env vars aren't
                              #   available
    freebsd15_boot.zig
                              #   opt-in generalized FreeBSD acceptance under
                              #   architecture-matched UEFI QEMU, including
                              #   SSH and reboot
  scripts/
    azure_vhd.zig              # fixed-VHD footer, geometry, and qemu-img
                              #   agreement checks for Azure uploads
                              #   (`zig build test-azure-vhd`)
    release/                   # shared release-tooling foundation: failure
                              #   diagnostics, bounded reads, atomic output
                              #   staging, streaming SHA-256, and
                              #   strict/canonical JSON documents
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

`.github/workflows/ci.yml` runs the required formatting, Python workflow,
build, and Zig checks on every pull request and push to `main`. The main suite
uses `zig build test-ci`; it preserves the `zig build test` graph except for
the VM-backend and privileged device-write and unsafe-chroot integrations,
which run once in dedicated parallel jobs. Windows cross-builds and the
native, cross-architecture, and modular real-VM boots also run as independent
matrix shards (see below).

### Stale brand guard

`zig build test-stale-brand` runs `tests/stale_brand.zig`, which enumerates the
tracked tree with `git ls-files -z` and rejects the pre-rename brands wherever
they survive: in path names, in file bytes (binary included), and in the DER
metadata of every certificate a `.pem` file holds -- where a name can be
spelled in ASCII, UTF-16, or UTF-32 and no text search of the file would find
it. `doc/migration.md` is the one file exempt from the content scan, since the
rename is its subject.

The guard fails closed: a path that is not valid UTF-8, a file that cannot be
read, a certificate that will not decode, and a `git ls-files` that will not
run are all reported as violations, each naming the path (and, for content, the
line) at fault. The quality job runs it as its own step so the signal stays
distinct, and `test-ci` runs it too.

### Migrating off Python

The release, acceptance, and fixture tooling is being moved from Python to
Zig one area at a time. While that is in progress, `tests/python_inventory.zig`
(`zig build test-python-inventory`, and part of `zig build test-ci`) is an
explicit, reviewable inventory of what is left:

- every tracked `*.py` file, which is removed whole by its port; and
- every *invocation site* in any other tracked file, with an exact count. An
  invocation site is a word whose final path component is a lowercase
  `python`, `python3`, or `python3.12` and that is used as a command: spelled
  as an absolute or relative interpreter path, including a shebang, quoted in
  an `argv` array, preceded by `env`, or followed by an argument. A bare token
  followed by a bare word is a package list or a tool-presence check, a word
  whose final component is not the interpreter is a library directory
  (`/usr/lib/pythonN/dist-packages`) or a package (`python3-libs`), and a
  capitalized mention is prose, so none of those count.

Because only commands are counted, a doc comment explaining what a Zig module
replaced never enters the inventory, and the list can only shrink as ports
land. Each non-source entry says what its sites are: `.execution` runs Python
here, `.documentation` shows a command to a reader, and `.reference` is an
explicitly exempted compatibility string, such as an interpreter line in test
data, that has the shape of a command but executes nothing.

The test fails when a Python file or an invocation site is added or removed
without the inventory being updated, and names the file and line of anything
unaccounted for, so each port has to shrink the list in the same change that
lands it. `.tools/` is excluded because it holds provisioned toolchains this
repository does not own, and the inventory excludes itself because its own
fixtures are the command spellings it detects. When the last entry is gone,
the inventory is replaced by a permanent zero-Python guard.

New Zig replacements build on `scripts/release/`, which carries the contracts
every release script shares: a single-line failure diagnostic, digest and
commit shape checks, bounded reads with file identity, atomic output staging,
streaming SHA-256, and strict document reads with canonical
(`sort_keys`, `indent=2`) document writes.

### Direct device-write integration

`zig build test-device-write-integration` runs
`tests/device_write_integration.zig`. It builds a small named GPT image, invokes
the real `miz write` command against same-size and substantially larger sparse
loop devices, and strictly verifies both resulting GPT copies and preserved
partition metadata. The test is Linux-only and opt-in because it needs loop
device privileges:

```
MIZ_RUN_PRIVILEGED_TEST=1 zig build test-device-write-integration
```

When necessary, the test re-executes itself through non-interactive `sudo`.

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

  MIZ_RUN_VM_BOOT_TEST=1 \
  MIZ_VM_BOOT_KERNEL=... MIZ_VM_BOOT_MODULES_BUILTIN=... \
  MIZ_VM_QEMU=$(readlink -f "$(command -v qemu-system-$(uname -m))") \
    zig build test-vm-real-boot
  ```

  `MIZ_VM_ACCEL` defaults to `software`, because no hosted runner class
  guarantees `/dev/kvm` and a test that demands one is a test that quietly
  stops running. `MIZ_VM_BOOT_WORKDIR` (default `/tmp`) moves the workspace,
  which needs room for two copies of the image.
- The same test with `MIZ_VM_BOOT_ARCH` naming the *other* architecture is the
  cross-architecture acceptance test: the kernel, the guest agent and the
  binary the guest executes are all the guest's, and only the emulator is the
  host's. Pass the matching `MIZ_VM_QEMU` and a kernel for that architecture.
  One `cataggar/qemu` ghr install supplies every `qemu-system-*`.

- `zig build test-vm-firmware-boot` runs `tests/vm_firmware_boot.zig`, which
  attests a *bootable* image through real EDK2 firmware. Firmware boot is the
  one part of the backend a synthesized fixture cannot cover: `vm_real_boot`'s
  image has no bootloader and no ESP, so no firmware could ever boot it. It is
  opt-in for that reason:

  ```
  ghr install cataggar/qemu@v11.0.91-z.15

  MIZ_RUN_VM_FIRMWARE_TEST=1 \
  MIZ_VM_FIRMWARE_IMAGE=/path/to/bootable.raw \
  MIZ_VM_FIRMWARE_MARKER='Welcome to Azure Linux' \
  MIZ_VM_QEMU=$(readlink -f "$(command -v qemu-system-$(uname -m))") \
    zig build test-vm-firmware-boot
  ```

  With `MIZ_VM_FIRMWARE_CODE`/`MIZ_VM_FIRMWARE_VARS` unset, the firmware is
  resolved through the same `qemu_host` search `miz qemu` uses, so the
  resolution path a real build takes is exercised too. Set
  `MIZ_VM_FIRMWARE_ARCH` to the other architecture for the cross-architecture
  case, `MIZ_VM_FIRMWARE_SECURE_BOOT=1` for the Secure Boot wiring, and
  `MIZ_VM_FIRMWARE_TIMEOUT` to change the 1800-second budget. The image is
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
  Pointing `MIZ_VM_BOOT_MODULE_TREE` at the tree it prints stages that tree
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
