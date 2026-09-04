//! Identity tables and acceptance-contract sets for the Ubuntu 26.04 release.
//!
//! Everything in this file is published behavior. Candidate keys decide which
//! architecture, flavor, and asset name a document is allowed to claim; the
//! contract sets are written verbatim into candidate and acceptance documents
//! and are compared for exact equality by every later job. A set that gains or
//! loses a member changes what "accepted" means, so the sets live in one place
//! and are stored pre-sorted: the Python they replace emitted
//! `tuple(sorted(...))`, and the sorted spelling is the one already recorded in
//! shipped documents.

const std = @import("std");

const runtime_contract = @import("ubuntu2604_runtime_contract");

pub const Flavor = enum { full, core };

pub const Architecture = enum { x86_64, aarch64 };

pub const Candidate = struct {
    key: []const u8,
    architecture: []const u8,
    flavor: []const u8,
    asset_name: []const u8,
};

/// `CANDIDATE_EXPECTED`: every key any Ubuntu document may claim.
pub const candidate_expected = [_]Candidate{
    .{
        .key = "x86_64-full",
        .architecture = "x86_64",
        .flavor = "full",
        .asset_name = "Ubuntu-26.04-x86_64.qcow2",
    },
    .{
        .key = "aarch64-full",
        .architecture = "aarch64",
        .flavor = "full",
        .asset_name = "Ubuntu-26.04-aarch64.qcow2",
    },
    .{
        .key = "x86_64-core",
        .architecture = "x86_64",
        .flavor = "core",
        .asset_name = "Ubuntu-26.04-x86_64.core.qcow2",
    },
    .{
        .key = "aarch64-core",
        .architecture = "aarch64",
        .flavor = "core",
        .asset_name = "Ubuntu-26.04-aarch64.core.qcow2",
    },
};

/// `RELEASE_ORDER` / `EXPECTED`: the exact four-asset publication order. It is
/// fixed so staged metadata and release notes are reproducible.
pub const release_order = [_][]const u8{
    "x86_64-full",
    "aarch64-full",
    "x86_64-core",
    "aarch64-core",
};

pub fn lookup(key: []const u8) ?Candidate {
    for (candidate_expected) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry;
    }
    return null;
}

/// Whether `key` is one of the four published candidate keys.
pub fn isReleaseKey(key: []const u8) bool {
    for (release_order) |entry| {
        if (std.mem.eql(u8, entry, key)) return true;
    }
    return false;
}

pub fn parseFlavor(text: []const u8) ?Flavor {
    if (std.mem.eql(u8, text, "full")) return .full;
    if (std.mem.eql(u8, text, "core")) return .core;
    return null;
}

pub fn parseArchitecture(text: []const u8) ?Architecture {
    if (std.mem.eql(u8, text, "x86_64")) return .x86_64;
    if (std.mem.eql(u8, text, "aarch64")) return .aarch64;
    return null;
}

/// Debian architecture name Canonical publishes its cloud images under.
pub fn sourceArchitecture(architecture: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, architecture, "x86_64")) return "amd64";
    if (std.mem.eql(u8, architecture, "aarch64")) return "arm64";
    return null;
}

pub const full_azure_contracts = [_][]const u8{
    "agent-ready",
    "cloud-init-provisioning",
    "kernel-lockdown",
    "key-only-ssh",
    "managed-data-disk",
    "matching-architecture-gen2",
    "module-signatures",
    "reboot-reconnect",
    "root-growth",
    "runtime-release-identity",
    "secure-boot",
    "signed-uki",
    "trusted-launch",
    "uefi-db-signer",
    "vtpm",
};

pub const core_azure_contracts = [_][]const u8{
    "agent-ready",
    "azagent-provisioning",
    "binder-devices-usable",
    "binder-module-signed",
    "binderfs-mounted",
    "dma-heap-device",
    "identity-persistence",
    "kernel-lockdown",
    "key-only-ssh",
    "managed-data-disk-mount-only",
    "matching-architecture-gen2",
    "mizinit-pid1",
    "module-signatures",
    "no-anbox-evidence",
    "no-cloud-init",
    "no-dkms-binder-module",
    "no-systemd-service-manager",
    "no-walinuxagent",
    "pid1-supervised-sshd",
    "reboot-reconnect",
    "resource-disk",
    "root-growth",
    "runtime-contract",
    "runtime-release-identity",
    "secure-boot",
    "signed-uki",
    "sshd-restart-reconnect",
    "trusted-launch",
    "uefi-db-signer",
    "vtpm",
};

pub const full_native_contracts = [_][]const u8{
    "clean-service-health",
    "cloud-init-provisioning",
    "generalized-identity",
    "gpt-layout",
    "kernel-lockdown",
    "key-only-ssh",
    "module-signatures",
    "netplan-networkd",
    "reboot-reconnect",
    "root-growth",
    "same-architecture-qemu",
    "secure-boot",
    "signed-uki",
    "standalone-zstd-qcow2",
    "tampered-uki-rejected",
    "uefi-db-signer",
    "vtpm",
    "walinuxagent",
};

pub const core_native_contracts = [_][]const u8{
    "azagent-provisioning",
    "binder-boot-required",
    "binder-device-usability",
    "binderfs-dynamic-devices",
    "clean-service-health",
    "dma-heap-device",
    "generalized-identity",
    "gpt-layout",
    "kernel-lockdown",
    "key-only-ssh",
    "local-ovf-azagent-skip-ready",
    "mizinit-pid1",
    "mizinit-sshd-supervision",
    "module-signatures",
    "no-cloud-init",
    "no-walinuxagent",
    "persistent-provisioned-state",
    "reboot-reconnect",
    "root-growth",
    "runtime-contract",
    "same-architecture-qemu",
    "secure-boot",
    "signed-binder-module",
    "signed-uki",
    "sshd-restart",
    "standalone-zstd-qcow2",
    "tampered-uki-rejected",
    "uefi-db-signer",
    "vtpm",
};

pub fn azureContracts(flavor: Flavor) []const []const u8 {
    return switch (flavor) {
        .full => &full_azure_contracts,
        .core => &core_azure_contracts,
    };
}

pub fn nativeContracts(flavor: Flavor) []const []const u8 {
    return switch (flavor) {
        .full => &full_native_contracts,
        .core => &core_native_contracts,
    };
}

/// `CANDIDATE_FIELDS`: the exact top-level key set of a candidate document.
pub const candidate_fields = [_][]const u8{
    "architecture",
    "asset_name",
    "azure_contracts",
    "build_validation",
    "bytes",
    "flavor",
    "key",
    "provenance",
    "schema",
    "sha256",
    "source_commit",
    "type",
    "ubuntu_provenance",
    "uki_signing",
    "virtual_size",
    "workflow",
};

/// Native results bind the complete candidate identity, its originating
/// workflow attempt, the acceptance attempt, and the exact signed bytes and
/// flavor-specific contract set.
pub const native_result_fields = [_][]const u8{
    "architecture",
    "asset_name",
    "candidate_sha256",
    "candidate_workflow",
    "certificate_sha256",
    "contracts",
    "execution",
    "fallback_uki_sha256",
    "flavor",
    "key",
    "schema",
    "source_commit",
    "status",
    "type",
    "virtual_size",
    "workflow",
};

pub fn nativeResultFields(_: Flavor) []const []const u8 {
    return &native_result_fields;
}

/// `AZURE_RESULT_FIELDS`: the exact top-level key set of every Azure
/// acceptance result.
pub const azure_result_fields = [_][]const u8{
    "architecture",
    "asset_name",
    "azure_accepted_sha256",
    "candidate_workflow",
    "certificate_sha256",
    "contracts",
    "conversion",
    "fallback_uki_sha256",
    "flavor",
    "image_version_id",
    "key",
    "location",
    "qcow_sha256",
    "resource_group",
    "schema",
    "signing_certificate_sha256",
    "source_commit",
    "status",
    "type",
    "uefi_settings",
    "vm_size",
    "workflow",
};

pub fn azureResultFields(_: Flavor) []const []const u8 {
    return &azure_result_fields;
}

/// `PRIVATE_KEY_PEM_MARKERS`.
pub const private_key_pem_markers = [_][]const u8{
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
};

pub const openssh_private_key_magic = "openssh-key-v1\x00";

pub const ubuntu_provenance_filename = "ubuntu2604-build-provenance.json";

/// The runtime-contract document a core candidate binds into its provenance
/// (issue #677 step 2). Only the core appliance has this contract, so the name
/// is flavor-qualified and no full-flavor document exists to be confused with it.
pub fn runtimeContractFilename(
    buffer: []u8,
    flavor: Flavor,
    architecture: []const u8,
) ?[]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "ubuntu2604-runtime-contract-{s}-{s}.json",
        .{ @tagName(flavor), architecture },
    ) catch null;
}
pub const debz_api_commit = "beac3f20dd93fd98863af71e8fe621d47db663f6";
pub const full_debz_packages = [_][]const u8{ "linux-azure", "walinuxagent" };

/// The literal package roots the core appliance installs into the final guest,
/// after the selected kernel roots and in resolution order.
///
/// Issue #677 step 3 removed the `ubuntu-minimal` metapackage; step 4 removed
/// the initramfs generator, which is now resolved into a staging root the guest
/// never inherits. The *members* are derived from the runtime contract -- the
/// comptime check below refuses any drift between the two -- while the *order*
/// is a build decision this file owns.
pub const core_guest_package_roots = [_][]const u8{
    "openssh-server",
    "sudo",
    "ca-certificates",
};

/// The package roots resolved only into the initramfs build stage.
pub const core_build_package_roots = [_][]const u8{"initramfs-tools"};

/// How many roots a core guest publishes: the selected kernel image, its
/// module tree, then the literal roots above.
pub const core_kernel_root_count = 2;
pub const core_package_root_count = core_kernel_root_count + core_guest_package_roots.len;

comptime {
    if (!runtime_contract.isGuestPackageRootSet(&core_guest_package_roots))
        @compileError(
            "Ubuntu core guest package roots and the runtime contract's " ++
                "guest_runtime package requirements have separated; #677 " ++
                "requires a root to exist if and only if a contract entry " ++
                "names it for the guest",
        );
    if (!runtime_contract.isBuildPackageRootSet(&core_build_package_roots))
        @compileError(
            "Ubuntu core build-stage package roots and the runtime contract's " ++
                "build_tooling package requirements have separated; #677 step 4 " ++
                "requires the build stage to resolve exactly the contract's " ++
                "build tooling",
        );
}

pub const CorePackageRootError = error{
    /// The published roots are not `[image, modules, ...literal roots]`.
    InvalidCorePackageRoots,
};

/// Validates a published core `package_roots` list and returns the kernel it
/// selected.
///
/// Exact and ordered, like the literal check it replaces, except that the first
/// two entries are matched against the contract's kernel templates rather than
/// against a version this repository would otherwise have to keep re-pinning.
pub fn validateCorePackageRoots(
    roots: []const std.json.Value,
) CorePackageRootError!runtime_contract.KernelSelection {
    if (roots.len != core_package_root_count) return error.InvalidCorePackageRoots;
    var names: [core_package_root_count][]const u8 = undefined;
    for (roots, 0..) |value, index| {
        names[index] = switch (value) {
            .string => |text| text,
            else => return error.InvalidCorePackageRoots,
        };
    }
    const selection = runtime_contract.selectKernel(
        names[0..core_kernel_root_count],
    ) catch return error.InvalidCorePackageRoots;
    if (!std.mem.eql(u8, names[0], selection.image_package) or
        !std.mem.eql(u8, names[1], selection.modules_package))
        return error.InvalidCorePackageRoots;
    for (names[core_kernel_root_count..], core_guest_package_roots) |actual, expected| {
        if (!std.mem.eql(u8, actual, expected)) return error.InvalidCorePackageRoots;
    }
    return selection;
}

/// Packages the core closure must never contain, published from the one place
/// that defines them so the release tooling and the builder cannot drift.
pub const core_forbidden_packages = runtime_contract.forbidden_packages;

pub fn debzPackages(flavor: Flavor) []const []const u8 {
    return switch (flavor) {
        .full => &full_debz_packages,
        .core => &core_guest_package_roots,
    };
}

test "candidate identity tables agree with the release order" {
    try std.testing.expectEqual(candidate_expected.len, release_order.len);
    for (candidate_expected, release_order) |candidate, key| {
        try std.testing.expectEqualStrings(candidate.key, key);
        try std.testing.expect(isReleaseKey(key));
    }
    try std.testing.expect(lookup("riscv64-core") == null);
    try std.testing.expect(!isReleaseKey("riscv64-core"));
    try std.testing.expectEqualStrings("amd64", sourceArchitecture("x86_64").?);
    try std.testing.expectEqualStrings("arm64", sourceArchitecture("aarch64").?);
    try std.testing.expect(sourceArchitecture("riscv64") == null);
}

test "core package roots are the contract's guest set without ubuntu-minimal" {
    // #677 acceptance criterion: `ubuntu-minimal` is absent from the closure,
    // starting with the roots that produce it. Step 4 adds a second criterion:
    // build-only tooling is absent from the final guest, so the generator is
    // not a guest root either.
    try std.testing.expect(runtime_contract.isGuestPackageRootSet(&core_guest_package_roots));
    try std.testing.expect(runtime_contract.isBuildPackageRootSet(&core_build_package_roots));
    var saw_ca_certificates = false;
    for (core_guest_package_roots) |package| {
        try std.testing.expect(!std.mem.eql(u8, package, "ubuntu-minimal"));
        try std.testing.expect(!std.mem.eql(u8, package, "initramfs-tools"));
        if (std.mem.eql(u8, package, "ca-certificates")) saw_ca_certificates = true;
    }
    try std.testing.expect(saw_ca_certificates);
}

test "published core package roots must select a kernel rather than name one" {
    const allocator = std.testing.allocator;
    const good = try std.json.parseFromSlice(std.json.Value, allocator,
        \\["linux-image-7.0.0-1010-azure","linux-modules-7.0.0-1010-azure",
        \\ "openssh-server","sudo","ca-certificates"]
    , .{});
    defer good.deinit();
    const selection = try validateCorePackageRoots(good.value.array.items);
    try std.testing.expectEqualStrings("7.0.0-1010-azure", selection.release);

    for ([_][]const u8{
        // The convenience metapackage is not a selection.
        \\["linux-azure","linux-modules-7.0.0-1010-azure","openssh-server","sudo","ca-certificates"]
        ,
        // Image and modules from different kernels.
        \\["linux-image-7.0.0-1010-azure","linux-modules-7.0.0-1004-azure","openssh-server","sudo","ca-certificates"]
        ,
        // The generator is a build root and must not be published as a guest one.
        \\["linux-image-7.0.0-1010-azure","linux-modules-7.0.0-1010-azure","initramfs-tools","openssh-server","sudo","ca-certificates"]
        ,
        // A dropped literal root.
        \\["linux-image-7.0.0-1010-azure","linux-modules-7.0.0-1010-azure","openssh-server","sudo"]
        ,
    }) |document| {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, document, .{});
        defer parsed.deinit();
        try std.testing.expectError(
            error.InvalidCorePackageRoots,
            validateCorePackageRoots(parsed.value.array.items),
        );
    }
}

test "the forbidden set names ubuntu-minimal and no guest package root" {
    var saw_ubuntu_minimal = false;
    for (core_forbidden_packages) |forbidden| {
        if (std.mem.eql(u8, forbidden, "ubuntu-minimal")) saw_ubuntu_minimal = true;
        try std.testing.expect(!runtime_contract.isGuestPackageRoot(forbidden));
    }
    try std.testing.expect(saw_ubuntu_minimal);
    // Step 4: what the build resolves elsewhere is exactly what the guest must
    // not contain.
    for (core_build_package_roots) |build_root| {
        try std.testing.expect(runtime_contract.isForbiddenPackage(build_root));
    }
}

test "contract and field sets are stored sorted and duplicate-free" {
    const sets = [_][]const []const u8{
        &full_azure_contracts,
        &core_azure_contracts,
        &full_native_contracts,
        &core_native_contracts,
        &candidate_fields,
        &native_result_fields,
        &azure_result_fields,
        &core_forbidden_packages,
    };
    for (sets) |set| {
        var index: usize = 1;
        while (index < set.len) : (index += 1) {
            try std.testing.expect(std.mem.lessThan(u8, set[index - 1], set[index]));
        }
    }
}
