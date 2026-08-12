# FreeBSD images

## Generalized FreeBSD 15.1 QCOW2 images

`zvmi qemu FreeBSD` selects the host-native FreeBSD 15.1 image from release
`FreeBSD-15.1-20260724`; use `--arch x86_64|aarch64` to override the host
architecture.

The FreeBSD builder is driven by an explicit profile table indexed by
architecture, root filesystem, and flavor. Each profile pins its own upstream
source name, URL, compressed SHA-256, virtual size, and output asset name;
nothing is shared by coincidence, because the upstream UFS and ZFS images do
not even agree on virtual size. Selecting an unsupported combination fails with
`UnsupportedProfile` rather than falling back to a default.

| Architecture | Root | Flavor | Asset |
| --- | --- | --- | --- |
| aarch64 | ufs | full | `FreeBSD-15.1-aarch64.qcow2` |
| x86_64 | ufs | full | `FreeBSD-15.1-x86_64.qcow2` |
| aarch64 | zfs | full | `FreeBSD-15.1-aarch64.zfs.qcow2` |
| x86_64 | zfs | full | `FreeBSD-15.1-x86_64.zfs.qcow2` |
| aarch64 | ufs | core | `FreeBSD-15.1-aarch64.core.qcow2` |
| x86_64 | ufs | core | `FreeBSD-15.1-x86_64.core.qcow2` |

The table is deliberately not a full cross product. A core ZFS image is not a
supported combination - ZFS already compresses most of what the core manifest
removes, and a second unpublished variant would double the acceptance matrix
for no download-size win - so `--filesystem zfs --flavor core` fails with
`UnsupportedProfile`. The two core profiles pin the *same* upstream source as
the corresponding full UFS profiles: nothing about the acquired image differs,
only the package manifest the guest realizes.

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
| rc and account management | `FreeBSD-rc`, `FreeBSD-runtime`, `FreeBSD-pam` |
| DNS and DHCP | `FreeBSD-dhclient`, `FreeBSD-resolvconf` |
| Certificates | `FreeBSD-caroot`, `FreeBSD-certctl`, `FreeBSD-openssl` |
| Entropy and time | `FreeBSD-rc` (`rc.d/random`), `FreeBSD-ntp` |
| Key-only SSH and recovery | `FreeBSD-ssh`, `FreeBSD-rescue`, `FreeBSD-utilities`, `FreeBSD-vi`, `FreeBSD-geom` |
| Provisioning | `FreeBSD-nuageinit`, `FreeBSD-flua` |
| Packages and base updates | `pkg`, `FreeBSD-pkg-bootstrap`, `FreeBSD-libarchive` |
| Azure Agent | `azure-agent` |
| Root growth | `FreeBSD-ufs`, `FreeBSD-geom`, `FreeBSD-rc` |

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

The guest writes `/usr/local/etc/pkg/repos/zvmi-FreeBSD-base.conf` to enable the
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

QEMU acceptance repeats the metadata refresh, dry-run base solver, and
`tree` install/remove cycle on both instances before and after reboot. These
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
- UFS cannot shrink in place, so reducing the virtual size would mean
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

Given two staged release sets, the comparison table of full against core is
produced by:

```text
python3 scripts/freebsd15_release.py compare \
  --baseline .release/freebsd15/staging-ufs/publish-manifest.json \
  --candidate .release/freebsd15/staging-core/publish-manifest.json \
  --output comparison.md
```

The report shows full and core virtual, allocated, and compressed/download
sizes and reductions for both architectures. Argument roles are strict:
`--baseline` must be the two-architecture full UFS release and `--candidate`
must be the corresponding core UFS release, so reversing the comparison cannot
turn a regression into an apparent improvement.

Core staging is also the publication size gate. Both architectures must reduce
both allocated and compressed/download size by at least 10% relative to their
matching full UFS baselines, while virtual size may not increase. The reviewed
default is `CORE_MINIMUM_REDUCTION_PERCENT = 10`; maintainers may set
`stage --minimum-core-reduction-percent` explicitly for a release review.
The exact boundary is inclusive. A full UFS staging manifest is mandatory via
`stage --baseline`; missing, incomplete, cross-filesystem, wrong-flavor, or
wrong-architecture baselines fail closed.

For a core dispatch, the same source commit builds four candidates: the two
core assets plus full UFS candidates for both architectures. Publication
stages and validates the full candidates locally to create the baseline
manifest, then passes that manifest into core staging. The baseline JSON is
therefore derived from digest-, package-, provenance-, and qemu-info-bound
artifacts from the same run; an external baseline JSON is never trusted. Only
the two core assets enter the publication allowlist.

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
  --output /path/to/FreeBSD-15.1-aarch64.qcow2

zig build generalized-freebsd15 -- \
  --architecture x86_64 \
  --filesystem zfs \
  --work-dir /path/to/x86_64-zfs-cache \
  --output /path/to/FreeBSD-15.1-x86_64.zfs.qcow2

zig build generalized-freebsd15 -- \
  --architecture x86_64 \
  --flavor core \
  --work-dir /path/to/x86_64-core-cache \
  --output /path/to/FreeBSD-15.1-x86_64.core.qcow2
```

`--filesystem` defaults to `ufs` and `--flavor` defaults to `full`; both, with
`--architecture`, select exactly one profile, whose defaults for `--output` and
`--work-dir` are used when those options are omitted.

The builder is Linux-only and requires Zig 0.16, `curl`, XZ Utils, `qemu-img`,
the architecture-matched `qemu-system` executable, `xorriso`, matching
EDK2/AAVMF or OVMF firmware, and outbound guest networking for signed FreeBSD
package installation. Use `--source` for a local official compressed image;
the pinned profile checksum remains required unless explicitly overridden with
`--source-sha256`. `--accel auto` uses KVM when the host architecture matches
the guest and `/dev/kvm` is accessible, and TCG otherwise. `--base-only`
retains the verified-base behavior without guest customization.

Run the opt-in dual-instance acceptance against either completed image:

```text
ZVMI_FREEBSD15_ARCHITECTURE=aarch64 \
ZVMI_FREEBSD15_FILESYSTEM=ufs \
ZVMI_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-aarch64.qcow2 \
ZVMI_FREEBSD15_QEMU=/usr/bin/qemu-system-aarch64 \
zig build test-freebsd15-boot

ZVMI_FREEBSD15_ARCHITECTURE=x86_64 \
ZVMI_FREEBSD15_FILESYSTEM=zfs \
ZVMI_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-x86_64.zfs.qcow2 \
ZVMI_FREEBSD15_QEMU=/usr/bin/qemu-system-x86_64 \
zig build test-freebsd15-boot

ZVMI_FREEBSD15_ARCHITECTURE=x86_64 \
ZVMI_FREEBSD15_FLAVOR=core \
ZVMI_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-x86_64.core.qcow2 \
ZVMI_FREEBSD15_QEMU=/usr/bin/qemu-system-x86_64 \
zig build test-freebsd15-boot
```

`ZVMI_FREEBSD15_FILESYSTEM` defaults to `ufs` and must match the image under
test, because the guest-side assertions are filesystem-specific.
`ZVMI_FREEBSD15_FLAVOR` defaults to `full`; the flavor-specific assertions are
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
workflow takes a `release_set` input that names exactly which assets a run may
publish:

| Release set | Tag | Assets |
| --- | --- | --- |
| `ufs` | `FreeBSD-15.1-20260724` | `FreeBSD-15.1-aarch64.qcow2`, `FreeBSD-15.1-x86_64.qcow2` |
| `zfs` | `FreeBSD-15.1-zfs-20260729` | `FreeBSD-15.1-aarch64.zfs.qcow2`, `FreeBSD-15.1-x86_64.zfs.qcow2` |
| `core` | `FreeBSD-15.1-core-<reviewed YYYYMMDD>` | `FreeBSD-15.1-aarch64.core.qcow2`, `FreeBSD-15.1-x86_64.core.qcow2` |

`scripts/freebsd15_release.py matrix` expands the selected set into the build
matrix and `describe` resolves its tag, title, asset count, and reviewed size
threshold, so the tag, allowlist, and built variants cannot disagree. Core
requires the dispatcher to enter `core_release_date` explicitly as a valid
calendar `YYYYMMDD`; there is no preselected proposed publication date. Core
adds the two full UFS baseline builds described above from the same source
commit and architecture-specific pinned UFS sources; its published asset count
remains two. Each candidate builds on a native GitHub-hosted runner, caches its
digest-pinned upstream source, persists its exact qemu-img validation JSON,
validates the standalone QCOW2, and runs dual-instance acceptance. Core staging
requires both architectures to pass the reviewed full-versus-core allocated
and compressed/download reduction threshold and records virtual, allocated,
compressed, and package-count evidence for both sides. A separate publication
job requires every needed candidate, refuses candidates from another set or
source commit, stages a draft, uploads exactly the release set's assets,
verifies GitHub's asset digests and a fresh exact-allowlist download, and then
publishes the non-Latest release. SHA-256 values, package manifests, retained
and excluded core package contracts, all size evidence, and complete
source/build/QEMU/Azure provenance are recorded in the release notes; baseline
images, checksum files, and package-manifest sidecars are not published.

The released QCOW2 files are not directly uploadable to Azure. Derive aligned
fixed VHDs without changing their partitions:

```text
zvmi azure derive \
  --input-sha256 <release-note-sha256> \
  --expected-virtual-size <release-note-virtual-size> \
  FreeBSD-15.1-aarch64.qcow2 \
  FreeBSD-15.1-aarch64.vhd
```

The ZFS and core release workflows enforce exact-candidate Azure acceptance as
a required gate before publication: both architectures must pass a protected
Azure boot-and-contract validation run (using
`scripts/freebsd15_azure_acceptance.sh`) against the same build artifacts
accepted by the QEMU step, and the publication script refuses to proceed unless
both `azure-result.json` files are present. Full UFS publication retains its
existing QEMU-only behavior and rejects accidental Azure-result input.
The Azure acceptance job uses a protected GitHub environment with OIDC
credentials and architecture-specific `AZURE_LOCATION_X64`/`AZURE_VM_SIZE_X64`
and `AZURE_LOCATION_ARM64`/`AZURE_VM_SIZE_ARM64` configuration variables.
The harness also accepts UFS full and core candidates, using the same protected
subscription configuration and temporary-resource-group ownership model. Its
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
