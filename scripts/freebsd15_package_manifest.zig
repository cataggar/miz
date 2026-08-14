//! Explicit, versioned package manifests for the published FreeBSD 15.1
//! image flavors, and the guest script that realizes and audits them.
//!
//! FreeBSD 15 release VM images install the base system as pkgbase packages:
//! `release/tools/vmimage.subr` runs `pkg install -r FreeBSD-base` with
//! `FreeBSD-set-base`, `FreeBSD-set-base-dbg`, `FreeBSD-set-kernels`,
//! `FreeBSD-set-kernels-dbg`, `FreeBSD-set-lib32`, `FreeBSD-set-lib32-dbg`,
//! `FreeBSD-set-tests`, and `pkg`. The thing a smaller image has to describe
//! is therefore a package set, not a file tree, and a core image is realized
//! by pkg from this manifest rather than by deleting files from a full image:
//! the manifest names the roots, pkg computes their closure, and every base
//! package outside that closure is removed as a package.
//!
//! Both filesystems and flavors carry the same shared retained contract.
//! Filesystem packages are selected separately so the recorded contract
//! proves the root can be administered and recovered. The full flavor only
//! verifies it, which is what keeps a core-only change from silently
//! regressing the full images; the core flavor additionally prunes and then
//! proves that every reviewed exclusion is really gone and that nothing
//! retained lost a shared library it links against.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// Content flavor of the published artifact. The axis is deliberately
/// separate from architecture and root filesystem: the manifests below are
/// architecture-independent because `FreeBSD-set-minimal` already absorbs the
/// per-architecture differences (it pulls `FreeBSD-dtb` on aarch64 only).
pub const Flavor = enum {
    full,
    core,

    pub fn parse(text: []const u8) ?Flavor {
        if (std.mem.eql(u8, text, "full")) return .full;
        if (std.mem.eql(u8, text, "core")) return .core;
        return null;
    }
};

pub const RootFilesystem = enum {
    ufs,
    zfs,
};

/// One clause of the retained contract. Every clause must be claimed by at
/// least one manifest entry, so losing a capability requires deleting the
/// clause in a reviewed diff rather than quietly dropping a package name.
pub const Clause = enum {
    uefi_boot,
    release_kernel,
    virtual_hardware,
    rc_services,
    account_management,
    dns_and_dhcp,
    certificates,
    entropy,
    time_synchronization,
    remote_access,
    recovery_tools,
    provisioning,
    package_management,
    base_updates,
    azure_agent,
    root_growth,
    serial_console,
    system_configuration,
};

/// Which repository a required package comes from. Only pkgbase packages are
/// prune candidates; third-party packages are roots whose shared-library
/// needs the prune has to respect.
pub const PackageSource = enum {
    pkgbase,
    third_party,
};

pub const RequiredPackage = struct {
    name: []const u8,
    source: PackageSource,
    clauses: []const Clause,
    why: []const u8,
};

/// Packages every published flavor must carry, each tied to the contract
/// clauses it satisfies. `FreeBSD-set-minimal` already implies most of these,
/// but naming them individually is what makes the contract testable: a test
/// can assert that DHCP or the base update path is still claimed, which a
/// single metapackage name could never express.
pub const shared_required_packages = [_]RequiredPackage{
    .{
        .name = "FreeBSD-set-minimal",
        .source = .pkgbase,
        .clauses = &.{.rc_services},
        .why = "Upstream's own minimal multi-user set; the manifest's base.",
    },
    .{
        .name = "FreeBSD-runtime",
        .source = .pkgbase,
        .clauses = &.{.account_management},
        .why = "init, sh, and the account tools pw(8) and passwd(1).",
    },
    .{
        .name = "FreeBSD-rc",
        .source = .pkgbase,
        .clauses = &.{ .rc_services, .entropy, .root_growth },
        .why = "rc.d, including rc.d/random and rc.d/growfs.",
    },
    .{
        .name = "FreeBSD-bsdconfig",
        .source = .pkgbase,
        .clauses = &.{.system_configuration},
        .why = "sysrc(8), used to inspect and safely edit rc.conf settings.",
    },
    .{
        .name = "FreeBSD-pam",
        .source = .pkgbase,
        .clauses = &.{.account_management},
        .why = "PAM stack sshd and su authenticate through.",
    },
    .{
        .name = "FreeBSD-bootloader",
        .source = .pkgbase,
        .clauses = &.{ .uefi_boot, .serial_console },
        .why = "loader.efi and the loader.conf console settings.",
    },
    .{
        .name = "FreeBSD-efi-tools",
        .source = .pkgbase,
        .clauses = &.{.uefi_boot},
        .why = "efibootmgr and efivar for EFI boot recovery.",
    },
    .{
        .name = "FreeBSD-kernel-generic",
        .source = .pkgbase,
        .clauses = &.{ .release_kernel, .virtual_hardware },
        .why = "Release GENERIC kernel with the virtio and Hyper-V drivers.",
    },
    .{
        .name = "FreeBSD-hyperv-tools",
        .source = .pkgbase,
        .clauses = &.{.virtual_hardware},
        .why = "Hyper-V KVP/VSS daemons Azure's host integration expects.",
    },
    .{
        .name = "FreeBSD-devd",
        .source = .pkgbase,
        .clauses = &.{.virtual_hardware},
        .why = "Device attach events that name the virtio and hn interfaces.",
    },
    .{
        .name = "FreeBSD-dhclient",
        .source = .pkgbase,
        .clauses = &.{.dns_and_dhcp},
        .why = "SYNCDHCP on vtnet and hn interfaces.",
    },
    .{
        .name = "FreeBSD-resolvconf",
        .source = .pkgbase,
        .clauses = &.{.dns_and_dhcp},
        .why = "Installs the DHCP-supplied resolvers into /etc/resolv.conf.",
    },
    .{
        .name = "FreeBSD-caroot",
        .source = .pkgbase,
        .clauses = &.{.certificates},
        .why = "Root certificate bundle pkg and the agent validate TLS with.",
    },
    .{
        .name = "FreeBSD-certctl",
        .source = .pkgbase,
        .clauses = &.{.certificates},
        .why = "Rebuilds the trust store when certificates change.",
    },
    .{
        .name = "FreeBSD-openssl",
        .source = .pkgbase,
        .clauses = &.{.certificates},
        .why = "openssl(1), used by certctl and the Azure Agent.",
    },
    .{
        .name = "FreeBSD-ntp",
        .source = .pkgbase,
        .clauses = &.{.time_synchronization},
        .why = "ntpd and ntpdate; Azure requires a correct clock for TLS.",
    },
    .{
        .name = "FreeBSD-ssh",
        .source = .pkgbase,
        .clauses = &.{.remote_access},
        .why = "OpenSSH, the only way into a key-only generalized guest.",
    },
    .{
        .name = "FreeBSD-rescue",
        .source = .pkgbase,
        .clauses = &.{.recovery_tools},
        .why = "Statically linked /rescue for repairing a broken root.",
    },
    .{
        .name = "FreeBSD-utilities",
        .source = .pkgbase,
        .clauses = &.{.recovery_tools},
        .why = "awk and the general administration utilities.",
    },
    .{
        .name = "FreeBSD-vi",
        .source = .pkgbase,
        .clauses = &.{.recovery_tools},
        .why = "An editor for repairing configuration over the console.",
    },
    .{
        .name = "FreeBSD-geom",
        .source = .pkgbase,
        .clauses = &.{ .recovery_tools, .root_growth },
        .why = "gpart(8), which rc.d/growfs resizes the last partition with.",
    },
    .{
        .name = "FreeBSD-nuageinit",
        .source = .pkgbase,
        .clauses = &.{.provisioning},
        .why = "NoCloud provisioning that injects keys and the hostname.",
    },
    .{
        .name = "FreeBSD-flua",
        .source = .pkgbase,
        .clauses = &.{.provisioning},
        .why = "The Lua interpreter nuageinit is written against.",
    },
    .{
        .name = "FreeBSD-pkg-bootstrap",
        .source = .pkgbase,
        .clauses = &.{ .package_management, .base_updates },
        .why = "/etc/pkg/FreeBSD.conf and the pkgbase signing keys.",
    },
    .{
        .name = "FreeBSD-libarchive",
        .source = .pkgbase,
        .clauses = &.{.package_management},
        .why = "libarchive.so.7, which pkg links against.",
    },
    .{
        .name = "pkg",
        .source = .third_party,
        .clauses = &.{ .package_management, .base_updates },
        .why = "Installs packages and applies FreeBSD-base updates.",
    },
    .{
        .name = "azure-agent",
        .source = .third_party,
        .clauses = &.{.azure_agent},
        .why = "Azure provisioning, extension, and heartbeat agent.",
    },
};

/// The FreeBSD 15.1 pkgbase repository describes these as the UFS management
/// utilities and their runtime library. Keeping both explicit makes growfs,
/// fsck, dump/restore, and console recovery part of the recorded contract.
pub const ufs_required_packages =
    shared_required_packages ++ [_]RequiredPackage{
        .{
            .name = "FreeBSD-ufs",
            .source = .pkgbase,
            .clauses = &.{ .root_growth, .recovery_tools },
            .why = "growfs(8), newfs(8), fsck, dump, and restore for UFS.",
        },
        .{
            .name = "FreeBSD-ufs-lib",
            .source = .pkgbase,
            .clauses = &.{.recovery_tools},
            .why = "Runtime libufs used by the UFS administration tools.",
        },
    };

/// Official 15.1 pkgbase metadata assigns zfs(8), zpool(8), zfsd(8), and the
/// administration/recovery utilities to FreeBSD-zfs, with their runtime
/// libraries in FreeBSD-zfs-lib.
pub const zfs_required_packages =
    shared_required_packages ++ [_]RequiredPackage{
        .{
            .name = "FreeBSD-zfs",
            .source = .pkgbase,
            .clauses = &.{ .root_growth, .recovery_tools },
            .why = "Boot/import, zfs/zpool administration, online growth, scrub, health, and recovery tools.",
        },
        .{
            .name = "FreeBSD-zfs-lib",
            .source = .pkgbase,
            .clauses = &.{.recovery_tools},
            .why = "Runtime OpenZFS libraries required by the ZFS tools.",
        },
    };

/// Packages the retained set links against but that no declared pkgbase
/// dependency names. pkgbase records these edges as shlib metadata only, so
/// `pkg autoremove` alone would delete, for instance, FreeBSD-openssl-lib out
/// from under OpenSSH and pkg. The prune recomputes the shlib edges first and
/// then still keeps these explicitly, because a manifest that depends on one
/// pkg subcommand behaving is not a manifest.
pub const library_roots = [_][]const u8{
    "FreeBSD-audit-lib",
    "FreeBSD-blocklist",
    "FreeBSD-ctf-lib",
    "FreeBSD-kerberos-lib",
    "FreeBSD-libbsdstat",
    "FreeBSD-libcasper",
    "FreeBSD-libldns",
    "FreeBSD-libmagic",
    "FreeBSD-libucl",
    "FreeBSD-libyaml",
    "FreeBSD-natd",
    "FreeBSD-openssl-lib",
    "FreeBSD-tcpd",
};

/// Reviewed exclusions. Each entry must be absent from a finished core image;
/// if the closure pulled one back in, the build fails instead of shipping an
/// image whose contents disagree with its manifest.
pub const core_excluded_packages = [_][]const u8{
    // Compilers, linkers, debuggers, and build tooling.
    "FreeBSD-clang",
    "FreeBSD-lld",
    "FreeBSD-lldb",
    "FreeBSD-toolchain",
    "FreeBSD-bmake",
    "FreeBSD-ctf",
    "FreeBSD-dtrace",
    "FreeBSD-dwatch",
    // Test suites, sources, examples, and games.
    "FreeBSD-tests",
    "FreeBSD-atf",
    "FreeBSD-kyua",
    "FreeBSD-src",
    "FreeBSD-src-sys",
    "FreeBSD-examples",
    "FreeBSD-games",
    // Services and tools the supported virtual hardware never uses.
    "FreeBSD-bhyve",
    "FreeBSD-bluetooth",
    "FreeBSD-hostapd",
    "FreeBSD-sound",
    "FreeBSD-cxgbe-tools",
    "FreeBSD-mlx-tools",
    "FreeBSD-kerberos",
    "FreeBSD-kerberos-kdc",
    "FreeBSD-sendmail",
    // Superset metapackages whose survival would mean the prune did nothing.
    "FreeBSD-set-base",
    "FreeBSD-set-devel",
    "FreeBSD-set-optional",
    "FreeBSD-set-src",
    "FreeBSD-set-tests",
    "FreeBSD-set-lib32",
};

/// Whole families of pkgbase packages excluded by name class rather than one
/// name at a time: debug symbols, development headers and static libraries,
/// and 32-bit compatibility libraries. FreeBSD names every member of these
/// families with a trailing component, so the class is exact rather than a
/// heuristic.
pub const core_excluded_classes = [_][]const u8{
    "dbg",
    "dev",
    "lib32",
};

/// A dependency-free third-party package. Installing and removing it proves
/// the ports repository, the solver, and the install path still work without
/// leaving an automatic dependency behind that the recorded manifest would
/// then have to explain.
pub const representative_package = "tree";

pub const Manifest = struct {
    filesystem: RootFilesystem,
    flavor: Flavor,
    /// Manifest revision. Bump it whenever the retained or excluded sets
    /// change so a recorded image manifest can be tied to a reviewed one.
    revision: u32,
    /// FreeBSD release the package names and sets were reviewed against.
    release: []const u8,
    /// Repository the base packages come from and are updated from.
    base_repository: []const u8,
    required: []const RequiredPackage,
    library_roots: []const []const u8,
    excluded: []const []const u8,
    excluded_classes: []const []const u8,
    /// Whether the guest removes everything outside the manifest closure.
    prunes: bool,
};

pub const ufs_full_manifest = Manifest{
    .filesystem = .ufs,
    .flavor = .full,
    .revision = 3,
    .release = "15.1",
    .base_repository = "FreeBSD-base",
    .required = &ufs_required_packages,
    // The full flavor keeps upstream's complete base install, so it has no
    // library roots to name and nothing to exclude; it only has to prove the
    // retained contract still holds.
    .library_roots = &.{},
    .excluded = &.{},
    .excluded_classes = &.{},
    .prunes = false,
};

pub const ufs_core_manifest = Manifest{
    .filesystem = .ufs,
    .flavor = .core,
    .revision = 3,
    .release = "15.1",
    .base_repository = "FreeBSD-base",
    .required = &ufs_required_packages,
    .library_roots = &library_roots,
    .excluded = &core_excluded_packages,
    .excluded_classes = &core_excluded_classes,
    .prunes = true,
};

pub const zfs_full_manifest = Manifest{
    .filesystem = .zfs,
    .flavor = .full,
    .revision = 3,
    .release = "15.1",
    .base_repository = "FreeBSD-base",
    .required = &zfs_required_packages,
    .library_roots = &.{},
    .excluded = &.{},
    .excluded_classes = &.{},
    .prunes = false,
};

pub const zfs_core_manifest = Manifest{
    .filesystem = .zfs,
    .flavor = .core,
    .revision = 3,
    .release = "15.1",
    .base_repository = "FreeBSD-base",
    .required = &zfs_required_packages,
    .library_roots = &library_roots,
    .excluded = &core_excluded_packages,
    .excluded_classes = &core_excluded_classes,
    .prunes = true,
};

pub fn forProfile(
    filesystem: RootFilesystem,
    flavor: Flavor,
) *const Manifest {
    return switch (filesystem) {
        .ufs => switch (flavor) {
            .full => &ufs_full_manifest,
            .core => &ufs_core_manifest,
        },
        .zfs => switch (flavor) {
            .full => &zfs_full_manifest,
            .core => &zfs_core_manifest,
        },
    };
}

/// Marker every recorded package line carries. The guest writes the manifest
/// of what it actually ships to the console so the host can verify it against
/// this file instead of trusting the guest's own checks.
pub const record_prefix = "ZVMI_FREEBSD_PACKAGE";
pub const update_validation_prefix = "ZVMI_FREEBSD_UPDATE_VALIDATION";

/// Shared package handling: identify which installed packages came from
/// pkgbase, and prove both repositories and the install path still work.
/// Every flavor runs this, so a full build regresses loudly if the update
/// path breaks.
const shared_package_script =
    \\      pkg -N
    \\      pkg query -a '%n %o' > /root/zvmi-installed
    \\      awk '$2 ~ /^base\// { print $1 }' /root/zvmi-installed \
    \\          > /root/zvmi-base-packages
    \\      awk '$2 !~ /^base\// { print $1 }' /root/zvmi-installed \
    \\          > /root/zvmi-third-party-packages
    \\      test -s /root/zvmi-base-packages
    \\      # The prune addresses base packages through the FreeBSD- name
    \\      # glob, so that glob and the base/ origin prefix must describe
    \\      # exactly the same set or the prune would miss or overreach.
    \\      ! grep -qv '^FreeBSD-' /root/zvmi-base-packages
    \\      ! grep -q '^FreeBSD-' /root/zvmi-third-party-packages
    \\      # The base repository is disabled by default in the packaged
    \\      # /etc/pkg/FreeBSD.conf; upstream's VM images re-enable it as an
    \\      # unpackaged side effect. State it explicitly instead, so the
    \\      # supported update path does not depend on a file the image
    \\      # happened to arrive with.
    \\      mkdir -p /usr/local/etc/pkg/repos
    \\      printf '%s: { enabled: yes }\n' @BASE_REPOSITORY@ \
    \\          > /usr/local/etc/pkg/repos/zvmi-@BASE_REPOSITORY@.conf
    \\@PACKAGE_PRUNE@
    \\      for required in @REQUIRED_PACKAGES@; do
    \\          pkg info -e "${required}"
    \\      done
    \\      zvmi_package_state()
    \\      {
    \\          pkg query -a '%n %v %a' | sort | sha256 -q
    \\      }
    \\      # A system that cannot refresh both catalogues, solve a base
    \\      # upgrade, or install a ports package is not supportable. The
    \\      # upgrade is deliberately a dry run: it exercises repository and
    \\      # dependency solving without making release output depend on
    \\      # whether an update happens to exist today.
    \\      pkg update -f
    \\      pkg update -f -r @BASE_REPOSITORY@
    \\      pkg rquery -r @BASE_REPOSITORY@ '%n-%v' FreeBSD-runtime
    \\      package_state_before=$(zvmi_package_state)
    \\      pkg upgrade -n -U -r @BASE_REPOSITORY@
    \\      test "$(zvmi_package_state)" = "${package_state_before}"
    \\      ! pkg info -e @REPRESENTATIVE_PACKAGE@
    \\      pkg rquery '%n-%v' @REPRESENTATIVE_PACKAGE@
    \\      package_state_before=$(zvmi_package_state)
    \\      pkg install -y @REPRESENTATIVE_PACKAGE@
    \\      pkg info -e @REPRESENTATIVE_PACKAGE@
    \\      pkg delete -y @REPRESENTATIVE_PACKAGE@
    \\      ! pkg info -e @REPRESENTATIVE_PACKAGE@
    \\      test "$(zvmi_package_state)" = "${package_state_before}"
;

/// Core prune. pkg computes the closure; the manifest only names the roots.
const package_prune_script =
    \\      zvmi_unresolved_shlibs()
    \\      {
    \\          pkg query -a '%b' | sort -u > "$1.provided"
    \\          pkg query -a '%B' | sort -u > "$1.required"
    \\          comm -13 "$1.provided" "$1.required" > "$1"
    \\      }
    \\      zvmi_collect_core_exclusions()
    \\      {
    \\          output=$1
    \\          : > "${output}"
    \\          for excluded in @EXCLUDED_PACKAGES@; do
    \\              if pkg info -e "${excluded}"; then
    \\                  printf '%s\n' "${excluded}" >> "${output}"
    \\              fi
    \\          done
    \\          pkg query -a '%n' |
    \\              grep -E '^FreeBSD-.*-(@EXCLUDED_CLASSES@)$' \
    \\                  >> "${output}" || true
    \\          sort -u -o "${output}" "${output}"
    \\      }
    \\      zvmi_exclusion_diagnostic()
    \\      {
    \\          package=$1
    \\          echo "core manifest cannot remove ${package}" >&2
    \\          pkg query \
    \\              '  state: %n-%v automatic=%a vital=%V locked=%k' \
    \\              "${package}" >&2 || true
    \\          pkg query '  required by package: %rn-%rv' \
    \\              "${package}" >&2 || true
    \\          for capability in $(pkg query '%y' "${package}"); do
    \\              consumers=$(pkg query -a '%n %Y' |
    \\                  awk -v wanted="${capability}" \
    \\                      '$2 == wanted { print $1 }')
    \\              if [ -n "${consumers}" ]; then
    \\                  echo "  capability ${capability} required by:" >&2
    \\                  printf '%s\n' "${consumers}" |
    \\                      sed 's/^/    /' >&2
    \\              fi
    \\          done
    \\          for library in $(pkg query '%b' "${package}"); do
    \\              consumers=$(pkg shlib -qR "${library}" || true)
    \\              if [ -n "${consumers}" ]; then
    \\                  echo "  shared library ${library} required by:" >&2
    \\                  printf '%s\n' "${consumers}" |
    \\                      sed 's/^/    /' >&2
    \\              fi
    \\          done
    \\      }
    \\      zvmi_unresolved_shlibs /root/zvmi-shlibs-before
    \\      # pkgbase leaf packages declare no dependencies at all: the real
    \\      # edges live in shlib metadata, which pkg's solver does not
    \\      # consult. That is why the manifest names library roots and why
    \\      # the audit below is not optional. Recompute the metadata from
    \\      # the installed ELF files first so the audit compares against
    \\      # what is on disk rather than what a package claimed.
    \\      pkg check -B -a
    \\      # Every base package becomes a removal candidate and the manifest
    \\      # roots plus every third-party package become the explicit roots
    \\      # whose closure pkg keeps. The closure is pkg's to compute; the
    \\      # manifest never enumerates it.
    \\      pkg set -y -g -A 1 'FreeBSD-*'
    \\      for root in @RETAINED_ROOTS@; do
    \\          pkg info -e "${root}"
    \\          pkg set -y -A 0 "${root}"
    \\      done
    \\      while read -r third_party; do
    \\          pkg set -y -A 0 "${third_party}"
    \\      done < /root/zvmi-third-party-packages
    \\      pkg autoremove -y
    \\      # FreeBSD's package sets are vital. Marking every base package
    \\      # automatic therefore computes most of the closure, but a vital
    \\      # excluded set can survive and keep manual or automatic excluded
    \\      # dependencies such as FreeBSD-clang alive. Only packages selected
    \\      # by the reviewed exclusion names and classes may lose that
    \\      # protection. A retained dependency still keeps them installed.
    \\      zvmi_collect_core_exclusions /root/zvmi-core-exclusions
    \\      if [ -s /root/zvmi-core-exclusions ]; then
    \\          while read -r excluded; do
    \\              if ! pkg set -y -A 1 "${excluded}"; then
    \\                  zvmi_exclusion_diagnostic "${excluded}"
    \\                  exit 1
    \\              fi
    \\              if ! pkg set -y -v 0 "${excluded}"; then
    \\                  zvmi_exclusion_diagnostic "${excluded}"
    \\                  exit 1
    \\              fi
    \\          done < /root/zvmi-core-exclusions
    \\          pkg autoremove -y
    \\      fi
    \\      zvmi_collect_core_exclusions /root/zvmi-core-exclusions
    \\      if [ -s /root/zvmi-core-exclusions ]; then
    \\          while read -r excluded; do
    \\              zvmi_exclusion_diagnostic "${excluded}"
    \\          done < /root/zvmi-core-exclusions
    \\          echo "core manifest violated: exclusions are required" >&2
    \\          exit 1
    \\      fi
    \\      for root in @RETAINED_ROOTS@; do
    \\          if ! pkg info -e "${root}"; then
    \\              echo "core manifest lost retained root: ${root}" >&2
    \\              exit 1
    \\          fi
    \\      done
    \\      # Dry run: report a broken declared dependency rather than
    \\      # quietly reinstalling the package the prune just removed.
    \\      pkg check -d -n -a
    \\      zvmi_unresolved_shlibs /root/zvmi-shlibs-after
    \\      # A shared library that nothing provides any more is exactly what
    \\      # a manifest that is not dependency-closed produces. Compare
    \\      # against the pre-prune audit so a pre-existing upstream quirk
    \\      # cannot be mistaken for damage this prune caused.
    \\      comm -13 /root/zvmi-shlibs-before /root/zvmi-shlibs-after \
    \\          > /root/zvmi-shlibs-lost
    \\      test ! -s /root/zvmi-shlibs-lost
;

/// Record what the image actually ships. The host verifies this against the
/// manifest, so the shipped contents are checked by something other than the
/// guest that produced them.
const package_record_script =
    \\      for output in /dev/console /dev/ttyu0; do
    \\          if [ -w "${output}" ]; then
    \\              printf '@UPDATE_PREFIX@ @NONCE@ ports-metadata-ok\n' \
    \\                  >"${output}" || true
    \\              printf '@UPDATE_PREFIX@ @NONCE@ base-metadata-ok\n' \
    \\                  >"${output}" || true
    \\              printf '@UPDATE_PREFIX@ @NONCE@ base-solver-dry-run-ok\n' \
    \\                  >"${output}" || true
    \\              printf '@UPDATE_PREFIX@ @NONCE@ ports-lifecycle-ok\n' \
    \\                  >"${output}" || true
    \\              pkg query -a \
    \\                  '@RECORD_PREFIX@ @NONCE@ %n %v %sb' \
    \\                  >"${output}" || true
    \\          fi
    \\      done
    \\      rm -f /root/zvmi-installed /root/zvmi-base-packages
    \\      rm -f /root/zvmi-third-party-packages
    \\      rm -f /root/zvmi-shlibs-before* /root/zvmi-shlibs-after*
    \\      rm -f /root/zvmi-shlibs-lost
    \\      rm -f /root/zvmi-core-exclusions
;

const Substitution = struct {
    token: []const u8,
    value: []const u8,
};

fn renderAlloc(
    allocator: Allocator,
    template: []const u8,
    substitutions: []const Substitution,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var offset: usize = 0;
    scan: while (offset < template.len) {
        if (template[offset] == '@') {
            for (substitutions) |substitution| {
                if (std.mem.startsWith(
                    u8,
                    template[offset..],
                    substitution.token,
                )) {
                    try output.writer.writeAll(substitution.value);
                    offset += substitution.token.len;
                    continue :scan;
                }
            }
        }
        try output.writer.writeByte(template[offset]);
        offset += 1;
    }
    return output.toOwnedSlice();
}

fn joinAlloc(
    allocator: Allocator,
    parts: []const []const u8,
    separator: []const u8,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    for (parts, 0..) |part, index| {
        if (index != 0) try output.writer.writeAll(separator);
        try output.writer.writeAll(part);
    }
    return output.toOwnedSlice();
}

fn requiredNamesAlloc(
    allocator: Allocator,
    manifest: *const Manifest,
    source: ?PackageSource,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var written: usize = 0;
    for (manifest.required) |package| {
        if (source) |wanted| {
            if (package.source != wanted) continue;
        }
        if (written != 0) try output.writer.writeByte(' ');
        try output.writer.writeAll(package.name);
        written += 1;
    }
    return output.toOwnedSlice();
}

/// The roots the prune marks explicit: every required pkgbase package plus
/// the shlib providers no declared dependency names. Third-party packages are
/// roots too, but the guest reads those from the live database rather than
/// from the manifest, because the manifest cannot know what a build installed.
fn retainedRootsAlloc(
    allocator: Allocator,
    manifest: *const Manifest,
) ![]u8 {
    const required = try requiredNamesAlloc(allocator, manifest, .pkgbase);
    defer allocator.free(required);
    const libraries = try joinAlloc(allocator, manifest.library_roots, " ");
    defer allocator.free(libraries);
    if (libraries.len == 0) return allocator.dupe(u8, required);
    return std.fmt.allocPrint(
        allocator,
        "{s} {s}",
        .{ required, libraries },
    );
}

/// Render the manifest's half of the generalization script. The nonce is
/// substituted here rather than by the caller, because the caller renders the
/// outer template in a single pass and never rescans what it substitutes in.
pub fn guestScriptAlloc(
    allocator: Allocator,
    manifest: *const Manifest,
    nonce: []const u8,
) ![]u8 {
    const prune = if (manifest.prunes) blk: {
        const roots = try retainedRootsAlloc(allocator, manifest);
        defer allocator.free(roots);
        const excluded = try joinAlloc(allocator, manifest.excluded, " ");
        defer allocator.free(excluded);
        const classes = try joinAlloc(allocator, manifest.excluded_classes, "|");
        defer allocator.free(classes);
        break :blk try renderAlloc(allocator, package_prune_script, &.{
            .{ .token = "@RETAINED_ROOTS@", .value = roots },
            .{ .token = "@EXCLUDED_PACKAGES@", .value = excluded },
            .{ .token = "@EXCLUDED_CLASSES@", .value = classes },
        });
    } else try allocator.dupe(
        u8,
        "      # The full flavor keeps upstream's complete base install.",
    );
    defer allocator.free(prune);

    const required = try requiredNamesAlloc(allocator, manifest, null);
    defer allocator.free(required);
    const shared = try renderAlloc(allocator, shared_package_script, &.{
        .{ .token = "@PACKAGE_PRUNE@", .value = prune },
        .{ .token = "@REQUIRED_PACKAGES@", .value = required },
        .{ .token = "@BASE_REPOSITORY@", .value = manifest.base_repository },
        .{ .token = "@REPRESENTATIVE_PACKAGE@", .value = representative_package },
    });
    defer allocator.free(shared);
    const record = try renderAlloc(allocator, package_record_script, &.{
        .{ .token = "@RECORD_PREFIX@", .value = record_prefix },
        .{ .token = "@UPDATE_PREFIX@", .value = update_validation_prefix },
        .{ .token = "@NONCE@", .value = nonce },
    });
    defer allocator.free(record);
    return std.fmt.allocPrint(allocator, "{s}\n{s}", .{ shared, record });
}

/// One line of a manifest an image actually shipped.
pub const InstalledPackage = struct {
    name: []const u8,
    version: []const u8,
    installed_bytes: u64,
};

fn hasNameClass(name: []const u8, class: []const u8) bool {
    // FreeBSD names every member of these families with the class as the
    // final hyphen-separated component, so an exact component match avoids
    // mistaking FreeBSD-devd or FreeBSD-devmatch for a development package.
    if (name.len <= class.len + 1) return false;
    const suffix_start = name.len - class.len;
    if (name[suffix_start - 1] != '-') return false;
    return std.mem.eql(u8, name[suffix_start..], class);
}

/// Which package made a verification fail. Returned through a diagnostic
/// rather than printed, so the caller decides how to report it and a test can
/// assert on the offender instead of scraping stderr.
pub const Diagnostic = struct {
    package: []const u8 = "",
};

/// Verify a manifest an image actually recorded against the reviewed one.
/// The guest performs the same checks, but it is the guest that was pruned;
/// repeating them on the host means a guest whose checks silently did nothing
/// still cannot produce a publishable artifact.
pub fn verifyRecordedManifest(
    manifest: *const Manifest,
    installed: []const InstalledPackage,
    diagnostic: ?*Diagnostic,
) !void {
    if (installed.len == 0) return error.RecordedManifestEmpty;
    for (manifest.required) |package| {
        for (installed) |entry| {
            if (std.mem.eql(u8, entry.name, package.name)) break;
        } else {
            if (diagnostic) |out| out.package = package.name;
            return error.RequiredPackageMissing;
        }
    }
    for (installed) |entry| {
        if (std.mem.eql(u8, entry.name, representative_package)) {
            if (diagnostic) |out| out.package = entry.name;
            return error.RepresentativePackagePresent;
        }
        for (manifest.excluded) |excluded| {
            if (std.mem.eql(u8, entry.name, excluded)) {
                if (diagnostic) |out| out.package = entry.name;
                return error.ExcludedPackagePresent;
            }
        }
        if (!std.mem.startsWith(u8, entry.name, "FreeBSD-")) continue;
        for (manifest.excluded_classes) |class| {
            if (hasNameClass(entry.name, class)) {
                if (diagnostic) |out| out.package = entry.name;
                return error.ExcludedPackageClassPresent;
            }
        }
    }
}

test "each filesystem retained contract claims every clause" {
    for (std.enums.values(RootFilesystem)) |filesystem| {
        const required = forProfile(filesystem, .core).required;
        var claimed = std.EnumSet(Clause).initEmpty();
        for (required, 0..) |package, index| {
            try std.testing.expect(package.name.len != 0);
            try std.testing.expect(package.why.len != 0);
            try std.testing.expect(package.clauses.len != 0);
            for (package.clauses) |clause| claimed.insert(clause);
            for (package.clauses, 0..) |clause, first| {
                for (package.clauses[first + 1 ..]) |other| {
                    try std.testing.expect(clause != other);
                }
            }
            for (required[index + 1 ..]) |other| {
                try std.testing.expect(!std.mem.eql(
                    u8,
                    package.name,
                    other.name,
                ));
            }
        }
        for (std.enums.values(Clause)) |clause| {
            std.testing.expect(claimed.contains(clause)) catch |err| {
                std.debug.print(
                    "{s} contract does not claim {s}\n",
                    .{ @tagName(filesystem), @tagName(clause) },
                );
                return err;
            };
        }
    }
}

test "filesystem and flavor manifests are versioned and consistent" {
    for (std.enums.values(RootFilesystem)) |filesystem| {
        const full = forProfile(filesystem, .full);
        const core = forProfile(filesystem, .core);
        try std.testing.expectEqual(filesystem, full.filesystem);
        try std.testing.expectEqual(filesystem, core.filesystem);
        try std.testing.expectEqual(Flavor.full, full.flavor);
        try std.testing.expectEqual(Flavor.core, core.flavor);
        try std.testing.expect(!full.prunes);
        try std.testing.expect(core.prunes);
        try std.testing.expectEqual(@as(u32, 3), full.revision);
        try std.testing.expectEqual(full.revision, core.revision);
        try std.testing.expectEqualStrings("15.1", core.release);
        try std.testing.expectEqualStrings("FreeBSD-base", core.base_repository);
        try std.testing.expectEqual(full.required.len, core.required.len);
        try std.testing.expectEqual(@as(usize, 0), full.excluded.len);
        try std.testing.expect(core.excluded.len > 0);
        try std.testing.expect(core.library_roots.len > 0);
    }

    const ufs = forProfile(.ufs, .core);
    const zfs = forProfile(.zfs, .core);
    try std.testing.expectEqual(
        shared_required_packages.len + 2,
        ufs.required.len,
    );
    try std.testing.expectEqual(
        shared_required_packages.len + 2,
        zfs.required.len,
    );
    try std.testing.expectEqualStrings("FreeBSD-ufs", ufs.required[ufs.required.len - 2].name);
    try std.testing.expectEqualStrings("FreeBSD-ufs-lib", ufs.required[ufs.required.len - 1].name);
    try std.testing.expectEqualStrings("FreeBSD-zfs", zfs.required[zfs.required.len - 2].name);
    try std.testing.expectEqualStrings("FreeBSD-zfs-lib", zfs.required[zfs.required.len - 1].name);
    for (shared_required_packages, 0..) |package, index| {
        try std.testing.expectEqualStrings(package.name, ufs.required[index].name);
        try std.testing.expectEqualStrings(package.name, zfs.required[index].name);
    }
    for (ufs.required) |package| {
        try std.testing.expect(!std.mem.eql(u8, package.name, "FreeBSD-zfs"));
        try std.testing.expect(!std.mem.eql(u8, package.name, "FreeBSD-zfs-lib"));
    }
    for (zfs.required) |package| {
        try std.testing.expect(!std.mem.eql(u8, package.name, "FreeBSD-ufs"));
        try std.testing.expect(!std.mem.eql(u8, package.name, "FreeBSD-ufs-lib"));
    }

    const core = ufs;

    // An exclusion class that matched a retained package would delete it at
    // build time, on a runner, after an hour of QEMU.
    for (core.excluded_classes) |class| {
        for (core.required) |package| {
            try std.testing.expect(!hasNameClass(package.name, class));
        }
        for (core.library_roots) |library| {
            try std.testing.expect(!hasNameClass(library, class));
        }
    }

    for (core.excluded, 0..) |excluded, index| {
        // An exclusion that names a retained package would fail only at build
        // time, on a runner, after an hour of QEMU.
        for (core.required) |package| {
            try std.testing.expect(!std.mem.eql(u8, excluded, package.name));
        }
        for (core.library_roots) |library| {
            try std.testing.expect(!std.mem.eql(u8, excluded, library));
        }
        for (core.excluded[index + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, excluded, other));
        }
        try std.testing.expect(std.mem.startsWith(u8, excluded, "FreeBSD-"));
    }

    var retains_sysrc_provider = false;
    for (core.required) |package| {
        if (std.mem.eql(u8, package.name, "FreeBSD-bsdconfig")) {
            retains_sysrc_provider = true;
        }
    }
    try std.testing.expect(retains_sysrc_provider);
    for ([_][]const u8{
        "FreeBSD-set-base",
        "FreeBSD-set-devel",
        "FreeBSD-set-optional",
    }) |broad_set| {
        var excludes_broad_set = false;
        for (core.excluded) |excluded| {
            if (std.mem.eql(u8, excluded, broad_set)) {
                excludes_broad_set = true;
            }
        }
        try std.testing.expect(excludes_broad_set);
    }

    for (core.excluded_classes) |class| {
        for (core.required) |package| {
            try std.testing.expect(!hasNameClass(package.name, class));
        }
        for (core.library_roots) |library| {
            try std.testing.expect(!hasNameClass(library, class));
        }
    }
}

test "excluded name classes match components, not substrings" {
    try std.testing.expect(hasNameClass("FreeBSD-clang-dev", "dev"));
    try std.testing.expect(hasNameClass("FreeBSD-clibs-dbg", "dbg"));
    try std.testing.expect(hasNameClass("FreeBSD-efi-tools-lib32", "lib32"));
    // The families whose names merely start with the class text must not be
    // mistaken for members of it.
    try std.testing.expect(!hasNameClass("FreeBSD-devd", "dev"));
    try std.testing.expect(!hasNameClass("FreeBSD-devmatch", "dev"));
    try std.testing.expect(!hasNameClass("FreeBSD-ufs-lib", "lib32"));
    try std.testing.expect(!hasNameClass("dev", "dev"));
}

test "the core guest script prunes from the manifest and audits the result" {
    const allocator = std.testing.allocator;
    const nonce = "0123456789abcdef";
    const script = try guestScriptAlloc(allocator, forProfile(.ufs, .core), nonce);
    defer allocator.free(script);

    try std.testing.expect(std.mem.indexOf(u8, script, "@") == null);
    // The prune must be pkg-driven; a file deletion pass is exactly what the
    // core contract forbids.
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg autoremove -y") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg check -B -a") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg check -d -n -a") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg delete -f") == null);
    try std.testing.expect(std.mem.indexOf(u8, script, "rm -rf /usr") == null);
    try std.testing.expect(std.mem.indexOf(u8, script, "find /usr") == null);
    // Every retained package and every reviewed exclusion has to appear.
    for (&ufs_required_packages) |package| {
        try std.testing.expect(std.mem.indexOf(u8, script, package.name) != null);
    }
    for (&library_roots) |library| {
        try std.testing.expect(std.mem.indexOf(u8, script, library) != null);
    }
    for (&core_excluded_packages) |excluded| {
        try std.testing.expect(std.mem.indexOf(u8, script, excluded) != null);
    }
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "grep -E '^FreeBSD-.*-(dbg|dev|lib32)$'",
    ) != null);
    // The update path, a non-destructive base solver run, and a real ports
    // package lifecycle are proven in the guest.
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg update -f\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg update -f -r FreeBSD-base") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "pkg upgrade -n -U -r FreeBSD-base",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "test \"$(zvmi_package_state)\" = \"${package_state_before}\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "! pkg info -e tree") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg rquery '%n-%v' tree") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg install -y tree") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg delete -y tree") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "ZVMI_FREEBSD_UPDATE_VALIDATION 0123456789abcdef base-solver-dry-run-ok",
    ) != null);
    // The shipped manifest is recorded under the run's nonce.
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "ZVMI_FREEBSD_PACKAGE 0123456789abcdef %n %v %sb",
    ) != null);
    // Every line stays inside the cloud-config script literal's indentation.
    var lines = std.mem.splitScalar(u8, script, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try std.testing.expect(std.mem.startsWith(u8, line, "      "));
    }
}

test "the ZFS core guest script retains ZFS administration packages" {
    const allocator = std.testing.allocator;
    const script = try guestScriptAlloc(
        allocator,
        forProfile(.zfs, .core),
        "abc",
    );
    defer allocator.free(script);

    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "FreeBSD-zfs FreeBSD-zfs-lib",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "FreeBSD-ufs FreeBSD-ufs-lib",
    ) == null);
}

test "a manual excluded package surviving autoremove is reclassified" {
    const allocator = std.testing.allocator;
    const script = try guestScriptAlloc(allocator, forProfile(.ufs, .core), "abc");
    defer allocator.free(script);

    // Model an upstream-manual FreeBSD-clang surviving the first autoremove:
    // the exact reviewed name is collected regardless of its automatic flag,
    // and the second pass changes both flags that can keep it out of
    // autoremove.
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "for excluded in FreeBSD-clang ",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "if pkg info -e \"${excluded}\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "if ! pkg set -y -A 1 \"${excluded}\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "if ! pkg set -y -v 0 \"${excluded}\"",
    ) != null);
}

test "generated exclusion commands preserve dependency-safe order" {
    const allocator = std.testing.allocator;
    const script = try guestScriptAlloc(allocator, forProfile(.ufs, .core), "abc");
    defer allocator.free(script);

    // The first autoremove may leave an upstream-manual package behind, and
    // vital pkgbase sets are never orphaned. Every surviving reviewed
    // exclusion is therefore made automatic and non-vital before a second
    // dependency-aware autoremove. The final collection and diagnostic happen
    // only after that second pass.
    const first_autoremove = std.mem.indexOf(
        u8,
        script,
        "pkg autoremove -y",
    ).?;
    const first_collection = std.mem.indexOfPos(
        u8,
        script,
        first_autoremove,
        "zvmi_collect_core_exclusions /root/zvmi-core-exclusions",
    ).?;
    const automatic = std.mem.indexOfPos(
        u8,
        script,
        first_collection,
        "if ! pkg set -y -A 1 \"${excluded}\"",
    ).?;
    const non_vital = std.mem.indexOfPos(
        u8,
        script,
        automatic,
        "if ! pkg set -y -v 0 \"${excluded}\"",
    ).?;
    const second_autoremove = std.mem.indexOfPos(
        u8,
        script,
        non_vital,
        "pkg autoremove -y",
    ).?;
    const final_collection = std.mem.indexOfPos(
        u8,
        script,
        second_autoremove,
        "zvmi_collect_core_exclusions /root/zvmi-core-exclusions",
    ).?;
    const diagnostic = std.mem.indexOfPos(
        u8,
        script,
        final_collection,
        "zvmi_exclusion_diagnostic \"${excluded}\"",
    ).?;

    try std.testing.expect(first_autoremove < first_collection);
    try std.testing.expect(first_collection < automatic);
    try std.testing.expect(automatic < non_vital);
    try std.testing.expect(non_vital < second_autoremove);
    try std.testing.expect(second_autoremove < final_collection);
    try std.testing.expect(final_collection < diagnostic);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "automatic=%a vital=%V locked=%k",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "required by package: %rn-%rv",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "capability ${capability} required by:",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "pkg shlib -qR \"${library}\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script[final_collection..],
        "if ! pkg info -e \"${root}\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script[final_collection..],
        "core manifest lost retained root: ${root}",
    ) != null);
}

test "the full guest script verifies the contract without pruning" {
    const allocator = std.testing.allocator;
    const script = try guestScriptAlloc(allocator, forProfile(.ufs, .full), "abc");
    defer allocator.free(script);

    try std.testing.expect(std.mem.indexOf(u8, script, "@") == null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg autoremove") == null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg set -y -g -A 1") == null);
    // The retained contract and the update path are still proven, so a core
    // change that breaks them cannot pass the full builds either.
    for (&ufs_required_packages) |package| {
        try std.testing.expect(std.mem.indexOf(u8, script, package.name) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg update -f -r FreeBSD-base") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        script,
        "pkg upgrade -n -U -r FreeBSD-base",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg install -y tree") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "pkg delete -y tree") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "! pkg info -e tree") != null);
}

test "a recorded manifest is verified against the reviewed one" {
    const core = forProfile(.ufs, .core);
    var installed: std.ArrayList(InstalledPackage) = .empty;
    defer installed.deinit(std.testing.allocator);
    for (core.required) |package| {
        try installed.append(std.testing.allocator, .{
            .name = package.name,
            .version = "15.1",
            .installed_bytes = 1,
        });
    }
    var diagnostic: Diagnostic = .{};
    try verifyRecordedManifest(core, installed.items, &diagnostic);

    // A missing contract package must fail even though nothing forbidden is
    // present, and it must name the package it missed.
    try std.testing.expectError(
        error.RequiredPackageMissing,
        verifyRecordedManifest(core, installed.items[1..], &diagnostic),
    );
    try std.testing.expectEqualStrings(
        core.required[0].name,
        diagnostic.package,
    );

    try installed.append(std.testing.allocator, .{
        .name = representative_package,
        .version = "2.2.1",
        .installed_bytes = 1,
    });
    try std.testing.expectError(
        error.RepresentativePackagePresent,
        verifyRecordedManifest(core, installed.items, &diagnostic),
    );
    try std.testing.expectEqualStrings(representative_package, diagnostic.package);
    _ = installed.pop();

    try installed.append(std.testing.allocator, .{
        .name = "FreeBSD-clang",
        .version = "15.1",
        .installed_bytes = 1,
    });
    try std.testing.expectError(
        error.ExcludedPackagePresent,
        verifyRecordedManifest(core, installed.items, &diagnostic),
    );
    try std.testing.expectEqualStrings("FreeBSD-clang", diagnostic.package);
    installed.items[installed.items.len - 1].name = "FreeBSD-runtime-dbg";
    try std.testing.expectError(
        error.ExcludedPackageClassPresent,
        verifyRecordedManifest(core, installed.items, &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "FreeBSD-runtime-dbg",
        diagnostic.package,
    );
    // A third-party name that merely ends in an excluded class is not a
    // pkgbase family member.
    installed.items[installed.items.len - 1].name = "py312-dev";
    try verifyRecordedManifest(core, installed.items, &diagnostic);

    // The full flavor excludes nothing, so the same list passes.
    try verifyRecordedManifest(forProfile(.ufs, .full), installed.items, null);
    try std.testing.expectError(
        error.RecordedManifestEmpty,
        verifyRecordedManifest(core, &.{}, null),
    );
}

test "flavors parse only their exact names" {
    try std.testing.expectEqual(Flavor.full, Flavor.parse("full").?);
    try std.testing.expectEqual(Flavor.core, Flavor.parse("core").?);
    try std.testing.expectEqual(@as(?Flavor, null), Flavor.parse("Core"));
    try std.testing.expectEqual(@as(?Flavor, null), Flavor.parse("minimal"));
    try std.testing.expectEqual(@as(?Flavor, null), Flavor.parse(""));
}
