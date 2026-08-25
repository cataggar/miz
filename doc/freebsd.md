# FreeBSD images

## Generalized FreeBSD 15.1 QCOW2 images

ZFS is the default root filesystem for future FreeBSD 15.1 images.
`miz qemu FreeBSD` selects the host-native image; use
`--arch x86_64|aarch64` to override the host architecture. Historical
published releases remain available under their original immutable tags and
asset names.

The FreeBSD builder is driven by an explicit profile table indexed by
architecture, root filesystem, and flavor. Each profile pins its own upstream
source name, URL, compressed SHA-256, virtual size, and output asset name;
nothing is shared by coincidence, because the upstream UFS and ZFS images do
not even agree on virtual size. Selecting an unsupported combination fails with
`UnsupportedProfile` rather than falling back to a default.

| Architecture | Root | Flavor | Asset |
| --- | --- | --- | --- |
| aarch64 | zfs | full | `FreeBSD-15.1-aarch64.qcow2` |
| x86_64 | zfs | full | `FreeBSD-15.1-x86_64.qcow2` |
| aarch64 | zfs | core | `FreeBSD-15.1-aarch64.core.qcow2` |
| x86_64 | zfs | core | `FreeBSD-15.1-x86_64.core.qcow2` |

These four ZFS profiles form the active release set. Full and core for one
architecture pin the same upstream ZFS source; only the package manifest
realized in the guest differs. UFS profiles remain manually buildable for
legacy use and comparison, but UFS is not a future release set and its images
must not be mixed into the ZFS publication.

All profiles use the official BASIC-CLOUDINIT images so NoCloud provisioning
stays available. The builder downloads the profile's compressed QCOW2, verifies
its pinned SHA-256 (a mismatch is a hard `SourceChecksumMismatch` failure), and
decompresses it with explicit memory and output limits. A private mutable QCOW2
is then booted under architecture-matched UEFI QEMU with a nonce-bound NoCloud
seed.

Guest customization installs the pinned `azure-agent-2.15.0.1` package, enables
SSH and generic `vtnet*` plus Azure `hn0` DHCP, applies FreeBSD's official Azure
multi-console/115200-baud serial settings, removes OS-disk swap, locks root,
removes the default `freebsd` user, deprovisions waagent, and clears guest
identity during a normal shutdown. That generalized guest contract is identical
for every profile and is asserted per profile by the builder's unit tests.

## Package flavors

The core flavor is realized by `pkg` from an explicit, versioned manifest in
`scripts/freebsd15_package_manifest.zig`, never by deleting files from a full
image. FreeBSD 15 release VM images install the base system as pkgbase
packages, so the thing a smaller image has to describe is a package set. The
manifest names roots; `pkg` computes their closure; every base package outside
that closure is removed as a package, so the shipped image and its manifest
cannot disagree.

Both flavors carry the same retained contract and both verify it, which is what
keeps a core-only change from silently regressing the full images. Only the
core flavor prunes.

### Retained contract

Every clause of the contract is claimed by at least one named package, and the
mapping is enforced by tests rather than by careful reading:

| Clause | Packages |
| --- | --- |
| UEFI boot | `FreeBSD-bootloader`, `FreeBSD-efi-tools` |
| Release kernel and virtual hardware | `FreeBSD-kernel-generic`, `FreeBSD-hyperv-tools`, `FreeBSD-devd` |
| rc, `sysrc`, and account management | `FreeBSD-rc`, `FreeBSD-bsdconfig`, `FreeBSD-runtime`, `FreeBSD-pam` |
| DNS and DHCP | `FreeBSD-dhclient`, `FreeBSD-resolvconf` |
| Certificates | `FreeBSD-caroot`, `FreeBSD-certctl`, `FreeBSD-openssl` |
| Entropy and time | `FreeBSD-rc` (`rc.d/random`), `FreeBSD-ntp` |
| Key-only SSH and recovery | `FreeBSD-ssh`, `FreeBSD-rescue`, `FreeBSD-utilities`, `FreeBSD-vi`, `FreeBSD-geom` |
| Provisioning | `FreeBSD-nuageinit`, `FreeBSD-flua` |
| Packages and base updates | `pkg`, `FreeBSD-pkg-bootstrap`, `FreeBSD-libarchive` |
| Azure Agent | `azure-agent` |
| Root growth and storage administration | `FreeBSD-zfs` or `FreeBSD-ufs`, `FreeBSD-geom`, `FreeBSD-rc` |

pkgbase leaf packages declare no dependencies at all: the real edges live in
shared-library metadata that `pkg`'s solver does not consult, so the manifest
also names thirteen library roots (`FreeBSD-openssl-lib`, `FreeBSD-libcasper`,
`FreeBSD-tcpd`, and so on) that OpenSSH, `pkg`, and the base utilities link
against. After pruning, the guest recomputes shared-library metadata from the
installed ELF files and requires that no library became unresolvable that was
resolvable before the prune. That audit is what makes the manifest
dependency-closed rather than merely reviewed.

FreeBSD marks several pkgbase set metapackages as vital. `pkg autoremove`
therefore cannot remove them merely because the pipeline changed their
automatic state, and a surviving `FreeBSD-set-devel` can keep
`FreeBSD-clang` installed. The core prune first computes the ordinary retained
closure, then collects only packages selected by the reviewed exclusion names
and classes, marks those survivors automatic and non-vital, and asks
`pkg autoremove` to solve the closure again. It never uses forced deletion. If
a retained package or shared-library consumer actually requires an exclusion,
the solver leaves it installed and the build reports its automatic, vital, and
locked state, reverse package dependencies, and shared-library consumers before
failing.

The shared retained manifest names the exact pkgbase provider
`FreeBSD-bsdconfig` for `sysrc(8)`. The core flavor does not retain
`FreeBSD-set-base`, `FreeBSD-set-devel`, or `FreeBSD-set-optional` to obtain
it; those broad sets remain reviewed exclusions.

For ZFS core, the filesystem-aware contract also retains the ZFS kernel and
userland packages plus the boot, pool import, growth, health, scrub, and
recovery tools required by a ZFS root. Validation proves the root pool remains
healthy and administrable after pruning and that ordinary signed package
install/remove operations do not change the reviewed retained package state.
The core image removes only packages outside that closure; it does not reduce
storage capability by deleting ZFS administration or recovery support.

### Exclusions

Each exclusion is listed by name in the manifest and must be absent from the
finished image; a closure that pulled one back in fails the build:

- Compilers, linkers, debuggers, and build tooling: `FreeBSD-clang`,
  `FreeBSD-lld`, `FreeBSD-lldb`, `FreeBSD-toolchain`, `FreeBSD-bmake`,
  `FreeBSD-ctf`, `FreeBSD-dtrace`, `FreeBSD-dwatch`.
- Tests, sources, examples, and games: `FreeBSD-tests`, `FreeBSD-atf`,
  `FreeBSD-kyua`, `FreeBSD-src`, `FreeBSD-src-sys`, `FreeBSD-examples`,
  `FreeBSD-games`.
- Hardware and services the supported virtual machines never use:
  `FreeBSD-bhyve`, `FreeBSD-bluetooth`, `FreeBSD-hostapd`, `FreeBSD-sound`,
  `FreeBSD-cxgbe-tools`, `FreeBSD-mlx-tools`, `FreeBSD-kerberos`,
  `FreeBSD-kerberos-kdc`, `FreeBSD-sendmail`.
- Superset metapackages whose survival would mean the prune did nothing:
  `FreeBSD-set-base`, `-devel`, `-optional`, `-src`, `-tests`, `-lib32`.
- Whole name classes: `-dbg` debug symbols, `-dev` headers and static
  libraries, and `-lib32` compatibility libraries. FreeBSD names every member
  of these families with the class as the final hyphen-separated component, so
  the match is exact and never catches `FreeBSD-devd` or `FreeBSD-devmatch`.

Manpages are *not* excluded. Only `FreeBSD-kernel-man` is a separate manpage
package in 15.1 pkgbase; the rest ship inside their owning packages, so
removing them would require the ad hoc file deletion this design rejects.

### Verification

The guest writes `/usr/local/etc/pkg/repos/miz-FreeBSD-base.conf` to enable the
base repository explicitly. `/etc/pkg/FreeBSD.conf` ships it disabled, and
upstream's VM images re-enable it as an unpackaged side effect; stating it in
the pipeline keeps the supported update path from depending on a file the
source image happened to arrive with.

The guest proves, for both flavors, that every required package is present,
that `pkg update` works against both the ports and `FreeBSD-base` repositories,
and that `pkg rquery -r FreeBSD-base` resolves a base package. It then runs
`pkg upgrade -n -U -r FreeBSD-base`: this invokes the real upgrade solver
against the freshly downloaded base catalogue and fails on repository or
dependency errors, but cannot modify the source image and succeeds whether or
not upstream happens to have published an update. A package-state digest before
and after the dry run proves the installed set did not change.

The same validation installs and removes the dependency-free ports package
`tree`, requires it to be absent both before and after the check, and requires
the package-state digest to return to its original value. The core flavor
additionally proves every exclusion is gone and that the shared-library audit
is clean. Nonce-bound serial records identify successful ports metadata, base
metadata, base solver, and third-party lifecycle checks. The package manifest
is recorded only after `tree` is removed; host-side validation also rejects a
recorded manifest containing it. Package archives, caches, and repository
catalogues are then removed before free-space reclamation.

QEMU acceptance repeats the static guest, package-presence, filesystem, and
identity contract on both instances before and after reboot. It repeats the
metadata refresh, dry-run base solver, and `tree` install/remove/cleanup cycle
once on the first clean, finalized clone; the builder has already exercised
the same lifecycle while producing every image, while this pass proves it
still works after catalogues and caches were removed. The network phases have
separate bounded timeouts from fast SSH readiness and identity probes. All
commands run through the provisioned key-only, non-root account and use
`sudo -n` for every catalogue or package-database write, so acceptance also
proves the published administrative path rather than relying on root console
access.

The guest then writes the manifest it actually shipped to the serial console.
The builder parses those records, re-verifies them against the reviewed
manifest on the host, and writes `<asset>.packages.txt` next to the asset, so a
guest whose own checks silently did nothing still cannot produce a publishable
artifact. `scripts/freebsd15_release.py` mirrors the manifest and validates the
recorded one a third time when a candidate is recorded and again when a release
is staged, without trusting the builder that produced it.
`tests/freebsd15_release_test.py` keeps the Zig and Python manifests in
agreement, exactly as it already does for the profile table.

## Free space, swap, and disk size

After the package caches are removed (`pkg clean -ay`, `/var/cache/pkg`, and
the repository catalogues), the guest returns unused space to the image before
the final compression. The mutable QCOW2 is attached with
`discard=unmap,detect-zeroes=unmap`, so:

- **UFS** writes zeroes into the remaining free space, leaving a 256 MiB
  margin so the fill cannot starve running services, then deletes the file.
  Zeroing is the only discard UFS has.
- **ZFS** runs `zpool trim` and waits for it. Zero-filling a compressing pool
  reclaims nothing, because the fill compresses away and the freed blocks are
  never handed back.

Both flavors additionally zero every `freebsd-swap` GPT partition. Swap is
already disabled and unreferenced by `/etc/fstab` at that point, but the
partition still holds whatever the build paged through it, and every non-zero
cluster in it is download size.

**The swap partition is not deleted and the GPT is not shrunk.** This was
investigated and rejected:

- Upstream's layout places swap *between* the EFI partition and the last
  partition, which is the root. Deleting swap therefore leaves an interior
  hole; shrinking the disk would require relocating the root partition, not
  just truncating the image.
- UFS cannot shrink in place, so reducing a manually built UFS image's
  virtual size would mean
  rebuilding the root filesystem and forfeiting the in-place, verified-upstream
  provenance the whole pipeline is built around.
- The virtual size is pinned per profile and is what Azure fixed-VHD derivation
  and the publisher's validation gate depend on. Changing it is a
  release-compatibility change, not a size optimization.
- A zeroed swap partition already contributes essentially nothing to the
  download, which is the metric a core image is judged on.

## Size reporting

Every schema-3 candidate records three distinct measures: the pinned virtual
size, qemu-img's `actual-size` (the allocated QCOW2 size), and the
compressed/download file size. Allocated size comes from the trusted
`qemu-img info --output=json` validation result, not filesystem block counts.
The workflow persists that exact JSON beside the candidate; schema 3 records
its digest and normalized values, and staging re-reads and re-hashes it before
preserving all three measures. Schema-2 candidates and staging manifests are
intentionally rejected rather than guessed or migrated; build artifacts are
short-lived and must be regenerated with complete size metadata.

The combined ZFS staging manifest carries both flavors, so the comparison
table is produced from that one digest- and provenance-bound manifest:

```text
python3 scripts/freebsd15_release.py compare \
  --candidate .release/freebsd15/staging/assets/publish-manifest.json \
  --output comparison.md
```

The report shows full and core virtual, allocated, and compressed/download
sizes and reductions for both architectures. Pairing is derived from exact
`<architecture>-zfs-full` and `<architecture>-zfs-core` variant identities, so
the comparison direction cannot be reversed.

ZFS staging is also the core publication size gate. Both architectures must
reduce allocated and compressed/download size relative to their matching full
ZFS asset, while virtual size may not increase. `describe` exposes the
reviewed 10% threshold used by staging so the workflow and review use one
value. Pre-publication validation measured reductions above 72% for both
architectures in both metrics, leaving substantial margin above that
conservative floor. Missing, incomplete, cross-filesystem, wrong-flavor, or
wrong-architecture pairings fail closed, and external baseline manifests are
not accepted. All four ZFS candidates come from the same source commit and
workflow run and enter the publication allowlist together.

Root storage handling is the one part that is deliberately *not* shared. The
UFS and ZFS seeds embed disjoint shell fragments:

- **UFS** asserts an `ufs` root, keeps `/etc/fstab`'s root entry, and relies on
  `rc.d/growfs` running `gpart resize` plus `growfs -y` on first boot.
- **ZFS** asserts a `zfs` root, pins and re-derives the `zroot` pool name,
  requires `zpool status -x` to report the pool healthy, sets
  `zpool autoexpand=on` so `rc.d/growfs`'s `zpool online -e` keeps working for
  later enlargements, sets `zfs_enable=YES` and `zpool_reguid="zroot"` so each
  fresh instance gets a distinct pool GUID, and destroys any swap zvol.

Both fragments disable swap and strip swap entries from `/etc/fstab`, but they
share no text; a unit test asserts the UFS fragment mentions no ZFS commands
and the ZFS fragment mentions no UFS commands, so a UFS assumption cannot leak
into the ZFS path unnoticed.

Only an authenticated success marker
followed by a clean QEMU exit permits transactional publication as a standalone
zstd-compressed QCOW2.

```text
zig build generalized-freebsd15 -- \
  --architecture aarch64 \
  --filesystem ufs \
  --work-dir /path/to/aarch64-ufs-cache \
  --output /path/to/FreeBSD-15.1-aarch64.ufs.qcow2

zig build generalized-freebsd15 -- \
  --architecture x86_64 \
  --filesystem zfs \
  --work-dir /path/to/x86_64-zfs-cache \
  --output /path/to/FreeBSD-15.1-x86_64.qcow2

zig build generalized-freebsd15 -- \
  --architecture x86_64 \
  --filesystem zfs \
  --flavor core \
  --work-dir /path/to/x86_64-zfs-core-cache \
  --output /path/to/FreeBSD-15.1-x86_64.core.qcow2
```

`--filesystem` defaults to `zfs` and `--flavor` defaults to `full`; both, with
`--architecture`, select exactly one profile, whose defaults for `--output` and
`--work-dir` are used when those options are omitted.

The builder is Linux-only and requires Zig 0.16, `curl`, XZ Utils, `qemu-img`,
the architecture-matched `qemu-system` executable, matching
EDK2/AAVMF or OVMF firmware, and outbound guest networking for signed FreeBSD
package installation. Use `--source` for a local official compressed image;
the pinned profile checksum remains required unless explicitly overridden with
`--source-sha256`. `--accel auto` uses KVM when the host architecture matches
the guest and `/dev/kvm` is accessible, and TCG otherwise. `--base-only`
retains the verified-base behavior without guest customization.

Run the opt-in dual-instance acceptance against either completed image:

```text
MIZ_FREEBSD15_ARCHITECTURE=aarch64 \
MIZ_FREEBSD15_FILESYSTEM=ufs \
MIZ_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-aarch64.qcow2 \
MIZ_FREEBSD15_QEMU=/usr/bin/qemu-system-aarch64 \
zig build test-freebsd15-boot

MIZ_FREEBSD15_ARCHITECTURE=x86_64 \
MIZ_FREEBSD15_FILESYSTEM=zfs \
MIZ_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-x86_64.qcow2 \
MIZ_FREEBSD15_QEMU=/usr/bin/qemu-system-x86_64 \
zig build test-freebsd15-boot

MIZ_FREEBSD15_ARCHITECTURE=x86_64 \
MIZ_FREEBSD15_FILESYSTEM=zfs \
MIZ_FREEBSD15_FLAVOR=core \
MIZ_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-x86_64.core.qcow2 \
MIZ_FREEBSD15_QEMU=/usr/bin/qemu-system-x86_64 \
zig build test-freebsd15-boot
```

`MIZ_FREEBSD15_FILESYSTEM` defaults to `zfs` and must match the image under
test, because the guest-side assertions are filesystem-specific.
`MIZ_FREEBSD15_FLAVOR` defaults to `full`; the flavor-specific assertions are
generated from the same manifest the builder used, so acceptance and the image
can never disagree about what the contract is.

The test boots two independent disposable overlays with fresh NoCloud seeds,
proves each injected SSH key works, verifies generalized
agent/network/swap/account/identity state, reboots and reconnects, and powers
off cleanly. Each guest's SSH host fingerprint and host UUID must remain stable
across its reboot, while both values must differ between guests; ZFS guests
additionally compare pool GUIDs, which `rc.d/zpoolreguid` regenerates once per
fresh instance.

Both overlays are created larger than the release asset's virtual size, so
first-boot growth is exercised on every run: the test requires the root
filesystem to have grown past the shipped size, `gpart show` to report no
`CORRUPT` GPT metadata, and every `gpart status` entry to read `OK`.

The manually dispatched **Build, validate, and publish FreeBSD 15.1 images**
workflow has one active release set:

| Release set | Tag | Assets |
| --- | --- | --- |
| `zfs` | `FreeBSD-15.1-<reviewed YYYYMMDD>` | `FreeBSD-15.1-aarch64.qcow2`, `FreeBSD-15.1-x86_64.qcow2`, `FreeBSD-15.1-aarch64.core.qcow2`, `FreeBSD-15.1-x86_64.core.qcow2` |

The tag and assets are intentionally unqualified: neither `.zfs` nor `-zfs`
appears in a default ZFS publication. UFS remains manually buildable, but
there is no active UFS release-set option and no future UFS publication path.
Previously published UFS, ZFS-qualified, full-only, and core-only releases are
immutable historical releases; this workflow never replaces or edits them.

`scripts/freebsd15_release.py matrix` expands the selected set into the build
matrix and `describe` resolves its tag, title, asset count, and reviewed size
threshold, so the tag, allowlist, and built variants cannot disagree. ZFS
requires an explicit reviewed `release_date` in valid calendar `YYYYMMDD`
form. Historical tags are reserved and cannot be selected for a replacement
release. Each candidate builds on a native GitHub-hosted runner, caches its
digest-pinned upstream source, persists its exact qemu-img validation JSON,
validates the standalone QCOW2, and runs dual-instance acceptance. ZFS staging
requires both architectures to pass the reviewed full-versus-core allocated
and compressed/download reduction threshold and records virtual, allocated,
compressed, and package-count evidence for both sides. A separate publication
job requires every needed candidate, refuses candidates from another set or
source commit, stages a draft, uploads exactly the release set's assets,
verifies GitHub's asset digests and a fresh exact-allowlist download, and then
publishes the non-Latest release. SHA-256 values, package manifests, retained
and excluded core package contracts, all size evidence, and complete
source/build/QEMU/Azure provenance are recorded in the release notes; checksum
files and package-manifest sidecars are not published.

The required procedure is:

1. Dispatch `release_set=zfs` with the reviewed date and
   `validation_only=true`.
2. Review all four QEMU and exact-candidate Azure results, the candidate
   manifests, and the same-manifest full/core ZFS size comparison against the
   reviewed threshold reported by `describe`.
3. After review, dispatch the identical merged `main` release configuration
   with `validation_only=false`. Publication is gated on all four builds, all
   four protected-environment Azure runs, staging reproduction, and the exact
   four-asset allowlist.

Validation-only uploads short-lived evidence and cannot create a tag, draft,
asset, or release. Publication is possible only from merged `main`; the
protected `azurelinux4-release` environment remains the credential boundary
for Azure acceptance.

The released QCOW2 files are not directly uploadable to Azure. Derive aligned
fixed VHDs without changing their partitions:

```text
miz azure derive \
  --input-sha256 <release-note-sha256> \
  --expected-virtual-size <release-note-virtual-size> \
  FreeBSD-15.1-aarch64.qcow2 \
  FreeBSD-15.1-aarch64.vhd
```

The ZFS release set enforces exact-candidate Azure acceptance as a required
gate before publication. It validates all four full and core assets with
protected Azure boot-and-contract runs (using
`scripts/freebsd15_azure_acceptance.sh`) against the same build artifacts
accepted by the QEMU step, and the publication script refuses to proceed unless
the exact result matrix is present.
The Azure acceptance job reuses the existing protected
`azurelinux4-release` GitHub environment so FreeBSD validation runs in the
same Azure subscription as Azure Linux validation. It authenticates only with
OIDC through the `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and
`AZURE_SUBSCRIPTION_ID` secrets and selects the architecture-specific
`AZURE_LOCATION_X64`/`AZURE_VM_SIZE_X64` or
`AZURE_LOCATION_ARM64`/`AZURE_VM_SIZE_ARM64` configuration variables.
The harness also accepts manually built UFS full and core candidates, using
the same protected subscription configuration and temporary-resource-group
ownership model. Its
shared Gen2, provisioning, network, serial, reboot, identity, GPT, growth, and
shutdown checks are combined with disjoint storage contracts: UFS proves root
partition and filesystem growth without invoking ZFS, while ZFS preserves pool
health, autoexpand, and GUID stability checks. Every supported harness path
emits the canonical schema-3 result through
`freebsd15_release.py azure-result`, binding the candidate's virtual,
allocated, compressed, digest, source commit, deterministic storage contract,
and workflow identity metadata.

See [Image building](image-building.md) for the shared image-format and Azure
VHD tooling.
