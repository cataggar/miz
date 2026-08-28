//! The FreeBSD 15.1 release contract tables.
//!
//! Native port of the constant tables that opened `scripts/freebsd15_release.py`.
//! Every value here duplicates something a builder also knows -- the profile
//! table in `scripts/build_generalized_freebsd15.zig`, the package manifest in
//! `scripts/freebsd15_package_manifest.zig` -- and the duplication is the
//! point: the release tooling must be able to reject a candidate without
//! trusting the builder that produced it. `tests/freebsd15_release.zig` keeps
//! the tables in agreement.

const std = @import("std");

pub const source_url_prefix =
    "https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/";

/// Every pinned source URL fits comfortably; the bound keeps `sourceUrl`
/// allocation-free so it can be called from validation paths.
pub const max_source_url_len = 256;

pub const Variant = struct {
    key: []const u8,
    architecture: []const u8,
    filesystem: []const u8,
    flavor: []const u8,
    source_directory: []const u8,
    asset_name: []const u8,
    source_name: []const u8,
    source_sha256: []const u8,
    virtual_size: u64,
    runner: []const u8,
    qemu: []const u8,

    /// `source_url` from the Python helper.
    pub fn sourceUrl(
        self: *const Variant,
        buffer: *[max_source_url_len]u8,
    ) []const u8 {
        return std.fmt.bufPrint(buffer, "{s}{s}/Latest/{s}", .{
            source_url_prefix,
            self.source_directory,
            self.source_name,
        }) catch unreachable;
    }
};

/// One entry per architecture x root filesystem x flavor the FreeBSD builder
/// can produce, in the order the workflow matrix expects to see them.
///
/// Core variants start from the matching full profile's pinned source; only
/// the package manifest the guest realizes differs.
pub const variants = [_]Variant{
    .{
        .key = "aarch64-ufs-full",
        .architecture = "aarch64",
        .filesystem = "ufs",
        .flavor = "full",
        .source_directory = "aarch64",
        .asset_name = "FreeBSD-15.1-aarch64.ufs.qcow2",
        .source_name = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        .source_sha256 = "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963",
        .virtual_size = 6_477_643_776,
        .runner = "ubuntu-24.04-arm",
        .qemu = "/usr/bin/qemu-system-aarch64",
    },
    .{
        .key = "x86_64-ufs-full",
        .architecture = "x86_64",
        .filesystem = "ufs",
        .flavor = "full",
        .source_directory = "amd64",
        .asset_name = "FreeBSD-15.1-x86_64.ufs.qcow2",
        .source_name = "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        .source_sha256 = "e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f",
        .virtual_size = 6_477_709_312,
        .runner = "ubuntu-24.04",
        .qemu = "/usr/bin/qemu-system-x86_64",
    },
    .{
        .key = "aarch64-zfs-full",
        .architecture = "aarch64",
        .filesystem = "zfs",
        .flavor = "full",
        .source_directory = "aarch64",
        .asset_name = "FreeBSD-15.1-aarch64.qcow2",
        .source_name = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        .source_sha256 = "0911a033b0a5d060486f92e534f3482c6a2ab96af6abb8a60683eeb24f6746af",
        .virtual_size = 6_477_643_776,
        .runner = "ubuntu-24.04-arm",
        .qemu = "/usr/bin/qemu-system-aarch64",
    },
    .{
        .key = "x86_64-zfs-full",
        .architecture = "x86_64",
        .filesystem = "zfs",
        .flavor = "full",
        .source_directory = "amd64",
        .asset_name = "FreeBSD-15.1-x86_64.qcow2",
        .source_name = "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        .source_sha256 = "4159e137d4a78f46b62d3523edd9a4dc79fd0cdcf17e34e531342f52333f4131",
        .virtual_size = 6_477_840_384,
        .runner = "ubuntu-24.04",
        .qemu = "/usr/bin/qemu-system-x86_64",
    },
    .{
        .key = "aarch64-ufs-core",
        .architecture = "aarch64",
        .filesystem = "ufs",
        .flavor = "core",
        .source_directory = "aarch64",
        .asset_name = "FreeBSD-15.1-aarch64.ufs.core.qcow2",
        .source_name = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        .source_sha256 = "9722aea499610802de9a14bb645707fc4f6df49ff765cd9ce372b783c4693963",
        .virtual_size = 6_477_643_776,
        .runner = "ubuntu-24.04-arm",
        .qemu = "/usr/bin/qemu-system-aarch64",
    },
    .{
        .key = "x86_64-ufs-core",
        .architecture = "x86_64",
        .filesystem = "ufs",
        .flavor = "core",
        .source_directory = "amd64",
        .asset_name = "FreeBSD-15.1-x86_64.ufs.core.qcow2",
        .source_name = "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz",
        .source_sha256 = "e4ca4db889f8559c9b9dfcacc70405c038476f4b6d41649b152d3809a2ed9e1f",
        .virtual_size = 6_477_709_312,
        .runner = "ubuntu-24.04",
        .qemu = "/usr/bin/qemu-system-x86_64",
    },
    .{
        .key = "aarch64-zfs-core",
        .architecture = "aarch64",
        .filesystem = "zfs",
        .flavor = "core",
        .source_directory = "aarch64",
        .asset_name = "FreeBSD-15.1-aarch64.core.qcow2",
        .source_name = "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        .source_sha256 = "0911a033b0a5d060486f92e534f3482c6a2ab96af6abb8a60683eeb24f6746af",
        .virtual_size = 6_477_643_776,
        .runner = "ubuntu-24.04-arm",
        .qemu = "/usr/bin/qemu-system-aarch64",
    },
    .{
        .key = "x86_64-zfs-core",
        .architecture = "x86_64",
        .filesystem = "zfs",
        .flavor = "core",
        .source_directory = "amd64",
        .asset_name = "FreeBSD-15.1-x86_64.core.qcow2",
        .source_name = "FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        .source_sha256 = "4159e137d4a78f46b62d3523edd9a4dc79fd0cdcf17e34e531342f52333f4131",
        .virtual_size = 6_477_840_384,
        .runner = "ubuntu-24.04",
        .qemu = "/usr/bin/qemu-system-x86_64",
    },
};

pub fn findVariant(key: []const u8) ?*const Variant {
    for (&variants) |*variant| {
        if (std.mem.eql(u8, variant.key, key)) return variant;
    }
    return null;
}

/// The variant a `<architecture> <filesystem> <flavor>` triple names, or null
/// when the triple names no supported variant.
pub fn variantFor(
    architecture: []const u8,
    filesystem: []const u8,
    flavor: []const u8,
) ?*const Variant {
    for (&variants) |*variant| {
        if (std.mem.eql(u8, variant.architecture, architecture) and
            std.mem.eql(u8, variant.filesystem, filesystem) and
            std.mem.eql(u8, variant.flavor, flavor)) return variant;
    }
    return null;
}

// ---- Package manifests ----------------------------------------------------
//
// The retained contract and the reviewed exclusions, mirrored from
// scripts/freebsd15_package_manifest.zig. The duplication is the point: the
// release helper validates the manifest an image actually recorded without
// trusting the builder that produced it, exactly as it does for the profile
// table.

pub const shared_required_packages = [_][]const u8{
    "FreeBSD-set-minimal",
    "FreeBSD-runtime",
    "FreeBSD-rc",
    "FreeBSD-bsdconfig",
    "FreeBSD-pam",
    "FreeBSD-bootloader",
    "FreeBSD-efi-tools",
    "FreeBSD-kernel-generic",
    "FreeBSD-hyperv-tools",
    "FreeBSD-devd",
    "FreeBSD-dhclient",
    "FreeBSD-resolvconf",
    "FreeBSD-caroot",
    "FreeBSD-certctl",
    "FreeBSD-openssl",
    "FreeBSD-ntp",
    "FreeBSD-ssh",
    "FreeBSD-rescue",
    "FreeBSD-utilities",
    "FreeBSD-vi",
    "FreeBSD-geom",
    "FreeBSD-nuageinit",
    "FreeBSD-flua",
    "FreeBSD-pkg-bootstrap",
    "FreeBSD-libarchive",
    "pkg",
    "azure-agent",
};

pub const ufs_required_packages = [_][]const u8{ "FreeBSD-ufs", "FreeBSD-ufs-lib" };
pub const zfs_required_packages = [_][]const u8{ "FreeBSD-zfs", "FreeBSD-zfs-lib" };

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

pub const core_excluded_packages = [_][]const u8{
    "FreeBSD-clang",
    "FreeBSD-lld",
    "FreeBSD-lldb",
    "FreeBSD-toolchain",
    "FreeBSD-bmake",
    "FreeBSD-ctf",
    "FreeBSD-dtrace",
    "FreeBSD-dwatch",
    "FreeBSD-tests",
    "FreeBSD-atf",
    "FreeBSD-kyua",
    "FreeBSD-src",
    "FreeBSD-src-sys",
    "FreeBSD-examples",
    "FreeBSD-games",
    "FreeBSD-bhyve",
    "FreeBSD-bluetooth",
    "FreeBSD-hostapd",
    "FreeBSD-sound",
    "FreeBSD-cxgbe-tools",
    "FreeBSD-mlx-tools",
    "FreeBSD-kerberos",
    "FreeBSD-kerberos-kdc",
    "FreeBSD-sendmail",
    "FreeBSD-set-base",
    "FreeBSD-set-devel",
    "FreeBSD-set-optional",
    "FreeBSD-set-src",
    "FreeBSD-set-tests",
    "FreeBSD-set-lib32",
};

pub const core_excluded_classes = [_][]const u8{ "dbg", "dev", "lib32" };

pub const package_manifest_revision: i64 = 3;

pub const PackageManifest = struct {
    filesystem: []const u8,
    flavor: []const u8,
    revision: i64,
    required: []const []const u8,
    library_roots: []const []const u8,
    excluded: []const []const u8,
    excluded_classes: []const []const u8,
    prunes: bool,
};

const ufs_required = shared_required_packages ++ ufs_required_packages;
const zfs_required = shared_required_packages ++ zfs_required_packages;

pub const package_manifests = [_]PackageManifest{
    .{
        .filesystem = "ufs",
        .flavor = "full",
        .revision = package_manifest_revision,
        .required = &ufs_required,
        .library_roots = &.{},
        .excluded = &.{},
        .excluded_classes = &.{},
        .prunes = false,
    },
    .{
        .filesystem = "ufs",
        .flavor = "core",
        .revision = package_manifest_revision,
        .required = &ufs_required,
        .library_roots = &library_roots,
        .excluded = &core_excluded_packages,
        .excluded_classes = &core_excluded_classes,
        .prunes = true,
    },
    .{
        .filesystem = "zfs",
        .flavor = "full",
        .revision = package_manifest_revision,
        .required = &zfs_required,
        .library_roots = &.{},
        .excluded = &.{},
        .excluded_classes = &.{},
        .prunes = false,
    },
    .{
        .filesystem = "zfs",
        .flavor = "core",
        .revision = package_manifest_revision,
        .required = &zfs_required,
        .library_roots = &library_roots,
        .excluded = &core_excluded_packages,
        .excluded_classes = &core_excluded_classes,
        .prunes = true,
    },
};

pub fn packageManifest(
    filesystem: []const u8,
    flavor: []const u8,
) ?*const PackageManifest {
    for (&package_manifests) |*manifest| {
        if (std.mem.eql(u8, manifest.filesystem, filesystem) and
            std.mem.eql(u8, manifest.flavor, flavor)) return manifest;
    }
    return null;
}

pub fn hasFilesystem(filesystem: []const u8) bool {
    for (&package_manifests) |*manifest| {
        if (std.mem.eql(u8, manifest.filesystem, filesystem)) return true;
    }
    return false;
}

/// `has_name_class`: FreeBSD names every member of these families with the
/// class as the final hyphen-separated component, so an exact component match
/// avoids mistaking FreeBSD-devd or FreeBSD-devmatch for a development
/// package.
pub fn hasNameClass(name: []const u8, name_class: []const u8) bool {
    if (!std.mem.startsWith(u8, name, "FreeBSD-")) return false;
    if (name.len < name_class.len + 1) return false;
    const boundary = name.len - name_class.len - 1;
    if (name[boundary] != '-') return false;
    return std.mem.eql(u8, name[boundary + 1 ..], name_class);
}

// ---- Release sets ---------------------------------------------------------

/// A release set is exactly the assets one dispatch of the release workflow is
/// allowed to publish. Keeping the tag, title, and asset allowlist together is
/// what lets the publisher refuse an incomplete or unexpected upload without
/// consulting a second source of truth.
pub const ReleaseSet = struct {
    name: []const u8,
    release_tag_prefix: []const u8,
    release_title_prefix: []const u8,
    requires_release_date: bool,
    variants: []const []const u8,
    summary: []const u8,
    highlights: []const []const u8,
};

pub const release_sets = [_]ReleaseSet{
    .{
        .name = "zfs",
        .release_tag_prefix = "FreeBSD-15.1-",
        .release_title_prefix = "FreeBSD 15.1 - ",
        .requires_release_date = true,
        .variants = &.{
            "aarch64-zfs-full",
            "x86_64-zfs-full",
            "aarch64-zfs-core",
            "x86_64-zfs-core",
        },
        .summary = "Generalized FreeBSD 15.1-RELEASE full and core ZFS images built " ++
            "with miz.",
        .highlights = &.{
            "Added matching AArch64 and x86_64 full and core release images.",
            "Each asset is a standalone zstd-compressed QCOW2 with no backing " ++
                "file.",
            "The core flavor is realized by pkg from an explicit, reviewed " ++
                "pkgbase manifest, not by deleting files from a full image.",
            "First boot grows the last GPT partition and onlines the enlarged " ++
                "`zroot` vdev; `autoexpand` keeps later enlargements working.",
            "`zpool_reguid` gives every instance a distinct pool GUID.",
        },
    },
};

pub fn findReleaseSet(name: []const u8) ?*const ReleaseSet {
    for (&release_sets) |*selected| {
        if (std.mem.eql(u8, selected.name, name)) return selected;
    }
    return null;
}

pub const ReservedTag = struct {
    tag: []const u8,
    reason: []const u8,
};

/// Historical tags remain published but are not dispatchable release sets.
/// Keeping their ownership explicit prevents the broad combined UFS prefix
/// from targeting an existing release.
pub const reserved_release_tags = [_]ReservedTag{
    .{ .tag = "FreeBSD-15.1-20260724", .reason = "historical full UFS release" },
    .{ .tag = "FreeBSD-15.1-zfs-20260729", .reason = "historical ZFS release" },
};

pub fn reservedTag(tag: []const u8) ?*const ReservedTag {
    for (&reserved_release_tags) |*reserved| {
        if (std.mem.eql(u8, reserved.tag, tag)) return reserved;
    }
    return null;
}

// ---- Azure acceptance contracts -------------------------------------------

pub const azure_shared_contracts_before_storage = [_][]const u8{
    "matching-architecture-gen2",
    "key-only-ssh",
    "agent-ready",
    "hn0-dhcp",
    "serial-console",
};

pub const azure_ufs_contracts = [_][]const u8{
    "ufs-root",
    "ufs-root-partition-growth",
    "ufs-root-filesystem-growth",
    "no-os-disk-swap",
};

pub const azure_zfs_contracts = [_][]const u8{
    "zfs-root",
    "zpool-healthy",
};

pub const azure_shared_contracts_after_storage = [_][]const u8{
    "root-growth",
    "gpt-healthy",
    "reboot-reconnect",
    "instance-identity",
};

const azure_ufs_all = azure_shared_contracts_before_storage ++
    azure_ufs_contracts ++ azure_shared_contracts_after_storage;
const azure_zfs_all = azure_shared_contracts_before_storage ++
    azure_zfs_contracts ++ azure_shared_contracts_after_storage;

/// `AZURE_CONTRACTS`: the ZFS contract list, which is the established default
/// the published result documents were first written with.
pub const azure_contracts_default: []const []const u8 = &azure_zfs_all;

pub fn azureContracts(filesystem: []const u8) ?[]const []const u8 {
    if (std.mem.eql(u8, filesystem, "ufs")) return &azure_ufs_all;
    if (std.mem.eql(u8, filesystem, "zfs")) return &azure_zfs_all;
    return null;
}

// ---- Schema and gate constants --------------------------------------------

pub const candidate_schema: i64 = 3;

/// Core publication requires at least this reduction in both qemu-img's
/// allocated size and the downloadable compressed file size. Validation of
/// both architectures measured reductions above 72%, so ten percent is a
/// conservative fail-closed floor while the reviewed package manifest -- not
/// an aggressive size target -- remains the primary definition of "core".
pub const core_minimum_reduction_percent: i64 = 10;

/// The profile fields a candidate, a staged release asset, and an Azure result
/// all restate and must agree on.
pub const profile_keys = [_][]const u8{
    "architecture",
    "filesystem",
    "flavor",
    "asset_name",
};

/// The profile field a `Variant` carries under `profile_keys[index]`.
pub fn profileField(variant: *const Variant, key: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, key, "architecture")) return variant.architecture;
    if (std.mem.eql(u8, key, "filesystem")) return variant.filesystem;
    if (std.mem.eql(u8, key, "flavor")) return variant.flavor;
    if (std.mem.eql(u8, key, "asset_name")) return variant.asset_name;
    return null;
}

test "every variant key is the architecture, filesystem, and flavor triple" {
    var buffer: [64]u8 = undefined;
    for (&variants) |*variant| {
        const key = try std.fmt.bufPrint(&buffer, "{s}-{s}-{s}", .{
            variant.architecture,
            variant.filesystem,
            variant.flavor,
        });
        try std.testing.expectEqualStrings(variant.key, key);
        try std.testing.expectEqual(variant, findVariant(key).?);
        try std.testing.expectEqual(variant, variantFor(
            variant.architecture,
            variant.filesystem,
            variant.flavor,
        ).?);
    }
    try std.testing.expectEqual(
        @as(?*const Variant, null),
        findVariant("riscv64-ufs-core"),
    );
    try std.testing.expectEqual(
        @as(?*const Variant, null),
        variantFor("x86_64", "ufs", "minimal"),
    );
}

test "core and full profiles share their pinned source" {
    var full_buffer: [max_source_url_len]u8 = undefined;
    var core_buffer: [max_source_url_len]u8 = undefined;
    for ([_][]const u8{ "ufs", "zfs" }) |filesystem| {
        for ([_][]const u8{ "aarch64", "x86_64" }) |architecture| {
            const full = variantFor(architecture, filesystem, "full").?;
            const core = variantFor(architecture, filesystem, "core").?;
            try std.testing.expectEqualStrings(full.source_name, core.source_name);
            try std.testing.expectEqualStrings(full.source_sha256, core.source_sha256);
            try std.testing.expectEqual(full.virtual_size, core.virtual_size);
            try std.testing.expectEqualStrings(
                full.sourceUrl(&full_buffer),
                core.sourceUrl(&core_buffer),
            );
        }
    }
}

test "source URLs are the pinned prefix, directory, and file name" {
    var buffer: [max_source_url_len]u8 = undefined;
    const aarch64 = variantFor("aarch64", "zfs", "full").?;
    try std.testing.expectEqualStrings(
        source_url_prefix ++ "aarch64/Latest/" ++
            "FreeBSD-15.1-RELEASE-arm64-aarch64-BASIC-CLOUDINIT-zfs.qcow2.xz",
        aarch64.sourceUrl(&buffer),
    );
}

test "package manifests carry the shared contract plus the filesystem roots" {
    const ufs_core = packageManifest("ufs", "core").?;
    try std.testing.expect(ufs_core.prunes);
    try std.testing.expectEqual(package_manifest_revision, ufs_core.revision);
    try std.testing.expectEqualStrings(
        "FreeBSD-ufs",
        ufs_core.required[shared_required_packages.len],
    );
    try std.testing.expectEqualStrings(
        "FreeBSD-ufs-lib",
        ufs_core.required[shared_required_packages.len + 1],
    );
    const zfs_full = packageManifest("zfs", "full").?;
    try std.testing.expect(!zfs_full.prunes);
    try std.testing.expectEqual(@as(usize, 0), zfs_full.excluded.len);
    try std.testing.expectEqualStrings(
        "FreeBSD-zfs",
        zfs_full.required[shared_required_packages.len],
    );
    try std.testing.expectEqual(
        @as(?*const PackageManifest, null),
        packageManifest("ufs", "minimal"),
    );
    try std.testing.expectEqual(
        @as(?*const PackageManifest, null),
        packageManifest("ext4", "full"),
    );
    try std.testing.expect(hasFilesystem("ufs"));
    try std.testing.expect(!hasFilesystem("ext4"));
}

test "name classes match only the final hyphenated component" {
    try std.testing.expect(hasNameClass("FreeBSD-runtime-dbg", "dbg"));
    try std.testing.expect(hasNameClass("FreeBSD-clibs-dev", "dev"));
    try std.testing.expect(!hasNameClass("FreeBSD-devd", "dev"));
    try std.testing.expect(!hasNameClass("FreeBSD-devmatch", "dev"));
    try std.testing.expect(!hasNameClass("py312-dev", "dev"));
    try std.testing.expect(!hasNameClass("dev", "dev"));
}

test "the ZFS release set claims every published variant exactly once" {
    const selected = findReleaseSet("zfs").?;
    try std.testing.expectEqual(@as(usize, 4), selected.variants.len);
    for (selected.variants) |key| {
        const variant = findVariant(key).?;
        try std.testing.expectEqualStrings("zfs", variant.filesystem);
    }
    try std.testing.expectEqual(@as(?*const ReleaseSet, null), findReleaseSet("ufs"));
    try std.testing.expectEqualStrings(
        "historical full UFS release",
        reservedTag("FreeBSD-15.1-20260724").?.reason,
    );
    try std.testing.expectEqual(
        @as(?*const ReservedTag, null),
        reservedTag("FreeBSD-15.1-20260812"),
    );
}

test "azure contracts are filesystem specific and default to ZFS" {
    const ufs = azureContracts("ufs").?;
    const zfs = azureContracts("zfs").?;
    try std.testing.expectEqual(@as(usize, 13), ufs.len);
    try std.testing.expectEqual(@as(usize, 11), zfs.len);
    try std.testing.expectEqualStrings("ufs-root", ufs[5]);
    try std.testing.expectEqualStrings("zfs-root", zfs[5]);
    try std.testing.expectEqual(zfs.len, azure_contracts_default.len);
    try std.testing.expectEqual(@as(?[]const []const u8, null), azureContracts("ext4"));
}

test "profile fields resolve for every profile key" {
    const variant = findVariant("x86_64-zfs-core").?;
    for (&profile_keys) |key| {
        try std.testing.expect(profileField(variant, key) != null);
    }
    try std.testing.expectEqualStrings(
        "FreeBSD-15.1-x86_64.core.qcow2",
        profileField(variant, "asset_name").?,
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        profileField(variant, "virtual_size"),
    );
}
