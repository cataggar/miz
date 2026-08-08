//! The control and result documents exchanged with the in-VM guest agent.
//!
//! This module deliberately imports nothing but `std`. The guest agent is a
//! static, libc-free PID 1 that has to be small and auditable, so it must not
//! drag in the host-side orchestration graph just to read its instructions.
//!
//! The control document travels in the initramfs, appended alongside the agent
//! by `vm_payload`, so the guest needs no filesystem driver and no second disk
//! to learn what to do. The result travels back out on a dedicated block
//! device, framed and digested, because a block device carries structured
//! output of unbounded shape where a serial console carries a byte stream that
//! the guest's own kernel messages interleave with.
//!
//! Every string that becomes a guest argv element or path is validated here,
//! on both sides. The host validates because it must not emit a document it
//! would refuse to read; the guest validates because a guest that trusts its
//! control document is a guest that can be driven anywhere by whoever wrote it.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const control_version: u32 = 6;
pub const result_version: u32 = 4;

/// Path the host writes the control document to inside the initramfs, and the
/// path the guest reads it back from once the kernel has unpacked rootfs.
pub const control_path = "zvmi-control.json";
/// Path the agent is appended at. `rdinit=/zvmi-guest-agent` matches.
pub const agent_path = "zvmi-guest-agent";

pub const sector_size: usize = 512;
pub const max_control_bytes: usize = 16 * 1024 * 1024;
pub const max_result_bytes: usize = 4 * 1024 * 1024;
/// Size of the result block device. Sized well above `max_result_bytes` so a
/// result is never truncated by the transport.
pub const result_device_bytes: u64 = 16 * 1024 * 1024;
/// Ceiling on how many modules a control document may ask the guest to insert.
/// Well above any real driver closure, so it bounds a malformed document
/// rather than a real run.
pub const max_modules: usize = 64;

/// Bounds on the hooks a control document may carry. Kept equal to the
/// `customize.max_hook_*` constants of the same names by a test in
/// `vm_backend`, which is the one place that imports both.
pub const max_hook_script_bytes: usize = 256 * 1024;
pub const max_hook_arguments: usize = 64;
pub const max_hook_argument_bytes: usize = 4096;

/// How many hooks one control document may carry, and what they may weigh in
/// total once decoded.
///
/// The count on its own would not bound the document. One hook may carry
/// `max_hook_script_bytes`, so `max_hooks` of them is 16 MiB decoded and over
/// 21 MiB base64-encoded -- past `max_control_bytes` before anything else in
/// the document has been counted, which would turn a request the library
/// accepted into an unexplained write failure. The total is the bound that
/// actually holds; the count is what keeps a document of empty hooks from
/// costing the guest an unbounded number of forks. Neither is a limit the
/// library imposes, so both are refused by name where the document is built.
pub const max_hooks: usize = 64;
pub const max_hook_total_script_bytes: usize = 4 * 1024 * 1024;

pub const Error = error{
    UnsupportedVersion,
    InvalidDevicePath,
    InvalidRepositoryId,
    InvalidPackageName,
    InvalidKernelRelease,
    InvalidRepositoryUrl,
    RepositoryUrlCarriesCredential,
    InvalidTrustMaterial,
    EmptyAction,
    OfflineNetworkWithPackageActions,
    NoDeclaredRepositories,
    InvalidNetworkConfiguration,
    UnusableNameserver,
    RepositoryWithoutTrust,
    DuplicateRepositoryId,
    BadFrameMagic,
    FrameTooLarge,
    TruncatedFrame,
    FrameDigestMismatch,
    ResultTooLarge,
    InvalidToolRecord,
    InvalidSelinuxRecord,
    InvalidInitramfsRecord,
    InvalidTrustKeyRecord,
    InvalidFailureRecord,
    InvalidModuleMember,
    TooManyModules,
    UnknownTargetFile,
    DuplicateTargetFile,
    InvalidPackagePin,
    DuplicatePackagePin,
    UnpinnedPackageAction,
    InvalidHookName,
    DuplicateHookName,
    HookPhaseOutOfOrder,
    InvalidHookScript,
    InvalidHookArgument,
    TooManyHookArguments,
    TooManyHooks,
    HookScriptsTooLarge,
    UnexecutedHook,
    UnexpectedHookOutcome,
    TooManyCredentials,
    CredentialMaterialTooLarge,
    CredentialIndexOutOfRange,
    InvalidCredentialUsername,
    MissingCredentialDevice,
    UnexpectedCredentialDevice,
};

pub const Network = union(enum) {
    /// The guest gets no network device at all.
    offline,
    /// The guest may reach exactly the repositories named below, over a
    /// statically configured interface.
    ///
    /// The address is static rather than leased because the host configures
    /// QEMU's network itself: running a DHCP client in the guest would add a
    /// timeout, a retry policy, and a failure mode to a link whose entire
    /// topology is already known before the guest starts.
    declared_repositories: NetworkConfig,
};

pub const NetworkConfig = struct {
    interface: []const u8 = "eth0",
    address: []const u8,
    netmask: []const u8 = "255.255.255.0",
    gateway: []const u8,
    nameservers: []const []const u8,

    pub fn validate(self: NetworkConfig) Error!void {
        if (self.interface.len == 0 or self.interface.len > 15) {
            return error.InvalidNetworkConfiguration;
        }
        for (self.interface) |byte| {
            if (!std.ascii.isAlphanumeric(byte)) return error.InvalidNetworkConfiguration;
        }
        if (parseIpv4(self.address) == null or
            parseIpv4(self.netmask) == null or
            parseIpv4(self.gateway) == null)
        {
            return error.InvalidNetworkConfiguration;
        }
        try validateNameservers(self.nameservers);
    }
};

/// `MAXNS` -- the number of `nameserver` lines a resolver library tracks
/// before ignoring the rest (glibc `resolv/bits/types/res_state.h`, and musl's
/// `__res_state` matches). A longer list would be a declaration the run does
/// not honour, so it is refused rather than silently truncated.
pub const max_nameservers: usize = 3;

/// What a declared nameserver list has to be, wherever it was declared. Shared
/// so the two executors cannot come to differ about which lists are legal.
pub fn validateNameservers(nameservers: []const []const u8) Error!void {
    if (nameservers.len == 0 or nameservers.len > max_nameservers) {
        return error.InvalidNetworkConfiguration;
    }
    for (nameservers) |nameserver| {
        const octets = parseIpv4(nameserver) orelse
            return error.InvalidNetworkConfiguration;
        // A declared resolver has to mean the same thing wherever the plan
        // runs, and these do not. Loopback reaches the build host's own stub
        // resolver from a chroot, which shares the host's network namespace,
        // and reaches nothing at all from inside a guest -- and `127.0.0.53`
        // is the likeliest value for someone to copy off their own machine
        // while trying to pin down what `host_resolver` already gave them,
        // quietly reintroducing the dependence they were removing. The
        // unspecified, multicast and reserved ranges are not resolvers
        // anywhere.
        if (octets[0] == 0 or octets[0] == 127 or octets[0] >= 224) {
            return error.UnusableNameserver;
        }
    }
}

/// Renders the `/etc/resolv.conf` body for a declared nameserver list.
///
/// Both executors call this, so the same declaration produces the same bytes
/// whichever backend runs it. That is the whole point of declaring it: a
/// resolver that differed between backends would make the plan a description
/// of one of them rather than of the run.
pub fn renderResolverBody(
    allocator: Allocator,
    nameservers: []const []const u8,
) Allocator.Error![]u8 {
    var body: std.array_list.Managed(u8) = .init(allocator);
    errdefer body.deinit();
    for (nameservers) |nameserver| {
        try body.appendSlice("nameserver ");
        try body.appendSlice(nameserver);
        try body.append('\n');
    }
    return body.toOwnedSlice();
}

/// Renders the tdnf repository file body for one repository.
///
/// Shared for the same reason `renderResolverBody` is: the chroot backend and
/// the guest agent must write byte-identical configuration for the same
/// declaration, and the only reliable way two renderers agree is for there to
/// be one. It takes the fields rather than a repository type because the host
/// and the guest hold trust material in different shapes and neither shape
/// reaches the body.
/// The material a credential names, already resolved by whoever could reach it.
/// This module reaches nothing, which is why it is the one place the host and
/// the guest can share a renderer.
pub const BasicMaterial = struct {
    username: []const u8,
    password: []const u8,
};

pub fn renderRepositoryBody(
    allocator: Allocator,
    id: []const u8,
    urls: []const []const u8,
    credential: ?BasicMaterial,
) Allocator.Error![]u8 {
    var body: std.array_list.Managed(u8) = .init(allocator);
    errdefer body.deinit();
    try body.appendSlice("[");
    try body.appendSlice(id);
    try body.appendSlice("]\nname=zvmi-");
    try body.appendSlice(id);
    try body.appendSlice("\nenabled=1\ngpgcheck=1\nbaseurl=");
    for (urls, 0..) |url, index| {
        if (index != 0) try body.append(' ');
        try body.appendSlice(url);
    }
    try body.append('\n');
    if (credential) |material| {
        try body.appendSlice("username=");
        try body.appendSlice(material.username);
        try body.appendSlice("\npassword=");
        try body.appendSlice(material.password);
        try body.append('\n');
    }
    return body.toOwnedSlice();
}

/// Strict dotted-quad parsing. Deliberately narrower than `std.net`, which
/// also accepts forms no configuration here should be written in.
pub fn parseIpv4(text: []const u8) ?[4]u8 {
    var octets: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, text, '.');
    for (&octets) |*octet| {
        const part = parts.next() orelse return null;
        if (part.len == 0 or part.len > 3) return null;
        for (part) |byte| {
            if (!std.ascii.isDigit(byte)) return null;
        }
        if (part.len > 1 and part[0] == '0') return null;
        octet.* = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (parts.next() != null) return null;
    return octets;
}

/// QEMU's user-mode network is a fixed, documented topology, so the guest can
/// be configured statically from it rather than discovering it.
pub const qemu_user_network: NetworkConfig = .{
    .interface = "eth0",
    .address = "10.0.2.15",
    .netmask = "255.255.255.0",
    .gateway = "10.0.2.2",
    .nameservers = &.{"10.0.2.3"},
};

/// Whether an address is inside the user-mode network's own subnet.
///
/// Every address in it is an alias for something on the build machine rather
/// than a resolver the request chose: slirp answers `10.0.2.3` itself by
/// forwarding to the emulator's `/etc/resolv.conf`, and rewrites traffic to
/// any other in-subnet address to the build host's loopback. So a declared
/// list naming one of them would state a resolver while still meaning
/// "whatever this machine has" -- and would mean something else again on the
/// chroot backend, where the same address is just an address on the host's
/// LAN. `host_resolver` is how a request asks for the build machine's
/// resolver; naming slirp's alias for it is not.
/// A credential user name as the guest will write it into a repository file.
///
/// The same single-line printable rule the request-level validator applies,
/// re-stated here because the guest must not trust a control document to have
/// been written by a host that checked: a name carrying a newline would end the
/// INI line and let whatever followed be read back as configuration.
pub fn validCredentialUsername(text: []const u8) bool {
    if (text.len == 0 or text.len > max_credential_field_bytes) return false;
    for (text) |byte| {
        if (byte < 0x21 or byte > 0x7e) return false;
    }
    return true;
}

pub fn isUserNetAddress(text: []const u8) bool {
    const octets = parseIpv4(text) orelse return false;
    const resolver = parseIpv4(qemu_user_network.nameservers[0]).?;
    return octets[0] == resolver[0] and
        octets[1] == resolver[1] and
        octets[2] == resolver[2];
}

/// A repository's credential, as much of it as a control document may hold.
///
/// The user name is here because it is not a secret -- the model states it
/// outright so a reader can tell which identity a build ran as -- and the
/// password is not, because this document is written into an initramfs file on
/// the build host and read back by the guest from the unpacked rootfs. What
/// travels instead is an index into the credential device, which is memory on
/// the host and a block device in the guest and a file nowhere.
pub const ControlCredential = union(enum) {
    basic: struct {
        username: []const u8,
        password_index: u32,
    },
};

pub const Repository = struct {
    id: []const u8,
    urls: []const []const u8,
    /// Keyring material, base64-encoded. Trust material may legitimately be a
    /// binary keyring rather than an ASCII armour, and JSON strings must be
    /// valid UTF-8, so it cannot travel raw.
    trust_base64: []const []const u8 = &.{},
    credential: ?ControlCredential = null,
};

pub const Action = union(enum) {
    install: []const []const u8,
    remove: []const []const u8,
    update_all,
    update_selected: []const []const u8,
};

pub const NoInstalledKernelsPolicy = enum {
    fail,
    nothing_to_regenerate,
};

pub const Initramfs = union(enum) {
    /// The image's initramfs is left exactly as it was found.
    unchanged,
    /// Empty `kernels` regenerates every kernel release installed in the
    /// target root, discovered by the receiver at run time. Naming releases
    /// explicitly overrides that. The distinction between this and
    /// `unchanged` is carried by the tag rather than by an empty list, so a
    /// document cannot express "regenerate nothing in particular".
    regenerate: struct {
        kernels: []const []const u8 = &.{},
        /// Whether discovering no installed kernel is a failure or simply
        /// nothing to do. The host decides this, because only the host knows
        /// whether the regeneration was asked for or derived; the guest can
        /// only see that the tree is empty.
        no_installed_kernels: NoInstalledKernelsPolicy = .fail,
    },
};

/// A file the host rendered for the guest to place in the target root.
///
/// The guest accepts these only at the destinations in
/// `kernel_module_config_paths`. A control document therefore cannot turn the
/// agent into a general-purpose file writer, which is the whole reason the
/// destination is carried rather than assumed: the host is the single source
/// of what a request renders to, and a host that names a path this guest does
/// not recognise is refused loudly instead of writing somewhere unintended.
pub const TargetFile = struct {
    path: []const u8,
    contents: []const u8,
};

/// Kept byte-identical to the `os_customization` constants of the same names
/// by a test in `vm_backend`, which is the one place that imports both.
/// What relabelling a root involves, shared with the host and the privileged
/// worker so all three carry out the same operation.
pub const selinux = @import("selinux.zig");

/// What pinning a package transaction involves, shared with the host and the
/// privileged worker so all three enforce the same lock.
pub const packages = @import("packages.zig");

/// What regenerating an initramfs involves, shared with the host and the
/// privileged worker so all three act on the same kernel releases.
///
/// Suffixed because `Result.initramfs` is captured under its own name a few
/// hundred lines down, and a capture may not shadow a declaration.
pub const initramfs_mod = @import("initramfs.zig");

pub const kernel_module_config_paths = [_][]const u8{
    "etc/modules-load.d/zvmi.conf",
    "etc/modprobe.d/zvmi-blacklist.conf",
    "etc/modprobe.d/zvmi-options.conf",
};

/// Mirrors `customize.HookPhase`, in declaration order, because the order is
/// the meaning: a hook may not move earlier than the one declared before it,
/// and both sides decide that by comparing tag values.
pub const HookPhase = enum {
    after_packages,
    before_initramfs,
    before_seal,
    finalize,
};

/// Caller-supplied code the guest runs inside the target root.
///
/// The destination is deliberately absent. `TargetFile` carries a path because
/// the host is the single source of what a request renders to; a hook is the
/// opposite case -- the caller supplies the code and nothing else, so the
/// guest names the file itself from the hook's position in this list. A
/// control document therefore has no way to express where a script lands, and
/// the hook channel cannot be turned into a file writer even by a host that
/// wanted to.
pub const Hook = struct {
    /// Carried for diagnostics only: the guest reports failures by name so a
    /// build log names the hook the caller declared rather than an index.
    name: []const u8,
    phase: HookPhase,
    /// The script, base64-encoded. A script is whatever bytes the caller
    /// wrote and JSON strings must be valid UTF-8, so it travels encoded for
    /// the same reason `Repository.trust_base64` does.
    script_base64: []const u8,
    arguments: []const []const u8 = &.{},
};

/// What one hook did. Paired with the control document's hooks by position,
/// which is what lets the host check that the guest ran every hook it was
/// given and ran nothing else -- the failure #302 shipped, where a complete
/// implementation was silently unreachable, is exactly the one an outcome
/// list makes impossible to repeat.
pub const HookOutcome = struct {
    index: u32,
    exit_code: u8,
};

pub const Control = struct {
    version: u32 = control_version,
    /// Block device holding the target root filesystem, e.g. `/dev/vda2`.
    /// The guest kernel scans the partition table, so the host passes the
    /// partition device rather than an offset the guest would have to honour.
    root_device: []const u8,
    /// Block device the sealed result is written to, e.g. `/dev/vdb`.
    result_device: []const u8,
    /// Block device holding the framed credential material, e.g. `/dev/vdc`,
    /// or nothing when no declared repository has a credential.
    ///
    /// Optional rather than always present because the device is only attached
    /// when there is material for it: a run with no credentials must not have a
    /// device the guest would read, and a guest handed a name must find one.
    credential_device: ?[]const u8 = null,
    network: Network,
    repositories: []const Repository = &.{},
    actions: []const Action = &.{},
    /// The exact identities every package this transaction installs must end
    /// up at, or empty for an unlocked run.
    ///
    /// A flat list rather than the library's `PackageLockPolicy` union because
    /// the only variant the guest can act on is the exact one: a repository
    /// snapshot names a state of the repositories, which nothing inside the
    /// target root can be compared against. The host refuses the others before
    /// a control document is written, so there is no variant left to carry.
    package_pins: []const PackagePin = &.{},
    /// Whether, and for which kernel releases, the initramfs is regenerated.
    initramfs: Initramfs = .unchanged,
    /// Kernel-module configuration the host rendered, placed in the target
    /// root before the initramfs is regenerated so a generator that reads it
    /// sees the declared state rather than the one it replaced.
    kernel_module_files: []const TargetFile = &.{},
    /// Initramfs members holding kernel modules the guest inserts, in
    /// insertion order, before it waits for any device.
    ///
    /// Named here rather than discovered by the agent so the host's dependency
    /// order is what the guest obeys, and so the set folds into the control
    /// document's digest like every other instruction.
    modules: []const []const u8 = &.{},
    /// Caller-supplied code, in the order it runs. Nondecreasing by phase, so
    /// the guest can walk this list once per phase and still obey the order
    /// the plan publishes.
    hooks: []const Hook = &.{},
    /// What the guest does to the target's SELinux configuration before it
    /// seals the result.
    ///
    /// A document rather than a flag, because both operations now reach the
    /// guest: relabelling with the policy the target already carries, and
    /// writing a declared mode and policy into the target's own
    /// `/etc/selinux/config`. Absent means the run leaves SELinux alone.
    selinux: ?Selinux = null,

    pub fn validate(self: Control) Error!void {
        if (self.version != control_version) return error.UnsupportedVersion;
        try validateDevicePath(self.root_device);
        try validateDevicePath(self.result_device);

        if (self.modules.len > max_modules) return error.TooManyModules;
        for (self.modules) |member| {
            if (!validModuleMember(member)) return error.InvalidModuleMember;
        }

        for (self.repositories, 0..) |repository, index| {
            if (!validRepositoryId(repository.id)) return error.InvalidRepositoryId;
            for (self.repositories[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.id, repository.id)) {
                    return error.DuplicateRepositoryId;
                }
            }
            if (repository.urls.len == 0) return error.InvalidRepositoryUrl;
            for (repository.urls) |url| {
                if (hasUserinfo(url)) return error.RepositoryUrlCarriesCredential;
                if (!validRepositoryUrl(url)) return error.InvalidRepositoryUrl;
            }
            // gpgcheck is on unconditionally in the generated tdnf config, so a
            // repository with no trust material could only ever fail mid-run.
            if (repository.trust_base64.len == 0) return error.RepositoryWithoutTrust;
            for (repository.trust_base64) |trust| {
                if (trust.len == 0) return error.InvalidTrustMaterial;
                _ = std.base64.standard.Decoder.calcSizeForSlice(trust) catch
                    return error.InvalidTrustMaterial;
            }
            const credential = repository.credential orelse continue;
            switch (credential) {
                .basic => |basic| {
                    if (!validCredentialUsername(basic.username)) {
                        return error.InvalidCredentialUsername;
                    }
                    if (basic.password_index >= max_credentials) {
                        return error.CredentialIndexOutOfRange;
                    }
                    // A repository naming material with no device to read it
                    // from would fail the run after the image had been opened,
                    // and a device with nothing to read would mean the host
                    // attached one for no declared reason. Both are refused on
                    // both sides of the channel.
                    if (self.credential_device == null) {
                        return error.MissingCredentialDevice;
                    }
                },
            }
        }

        if (self.credential_device) |device| {
            try validateDevicePath(device);
            var any = false;
            for (self.repositories) |repository| {
                if (repository.credential != null) any = true;
            }
            if (!any) return error.UnexpectedCredentialDevice;
        }

        for (self.actions) |action| {
            const names: []const []const u8 = switch (action) {
                .install, .remove, .update_selected => |values| values,
                // `update_all` names nothing by definition, so the empty-name
                // rejection below must not reach it.
                .update_all => continue,
            };
            if (names.len == 0) return error.EmptyAction;
            for (names) |name| {
                if (!validPackageName(name)) return error.InvalidPackageName;
            }
        }

        for (self.package_pins, 0..) |pin, index| {
            if (!validPackageName(pin.name)) return error.InvalidPackagePin;
            if (!validPackageEvr(pin.evr)) return error.InvalidPackagePin;
            if (!validKernelRelease(pin.architecture)) return error.InvalidPackagePin;
            for (self.package_pins[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.name, pin.name) and
                    std.mem.eql(u8, earlier.architecture, pin.architecture))
                {
                    return error.DuplicatePackagePin;
                }
            }
        }
        if (self.package_pins.len != 0) {
            // Pins describe a transaction; with no actions there is none, and
            // the guest's coverage check would compare the whole installed set
            // against an empty baseline.
            if (self.actions.len == 0) return error.UnpinnedPackageAction;
            for (self.actions) |action| {
                const names: []const []const u8 = switch (action) {
                    .install, .update_selected => |values| values,
                    // A removal names what must not be installed; a pin names
                    // a version for what is.
                    .remove => continue,
                    // Its subject is whatever the repositories hold, which is
                    // the question a pin exists to close.
                    .update_all => return error.UnpinnedPackageAction,
                };
                for (names) |name| {
                    if (findPackagePin(self.package_pins, name) == null) {
                        return error.UnpinnedPackageAction;
                    }
                }
            }
        }

        switch (self.initramfs) {
            .unchanged => {},
            .regenerate => |regenerate| for (regenerate.kernels) |kernel| {
                if (!validKernelRelease(kernel)) return error.InvalidKernelRelease;
            },
        }

        for (self.kernel_module_files, 0..) |file, index| {
            if (!knownKernelModuleConfigPath(file.path)) {
                return error.UnknownTargetFile;
            }
            for (self.kernel_module_files[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.path, file.path)) {
                    return error.DuplicateTargetFile;
                }
            }
        }

        try validateHooks(self.hooks);

        switch (self.network) {
            .offline => if (self.actions.len != 0) {
                return error.OfflineNetworkWithPackageActions;
            },
            .declared_repositories => |config| {
                if (self.repositories.len == 0) return error.NoDeclaredRepositories;
                try config.validate();
            },
        }
    }
};

/// One package pinned to an exact rpm identity.
///
/// The same type as `customize.PackageVersionLock`, not a copy of it: both are
/// aliases of `packages.VersionLock`. See there for why there is no repository
/// field, why the EVR is required in full, and why one type carries two names.
pub const PackagePin = packages.VersionLock;

/// Splits an `rpm -qa` record of the form `NAME-EPOCH:VERSION-RELEASE.ARCH`
/// back into its parts, or nothing if it is not one. See
/// `packages.parseInstalledRecord` for why the split is decidable.
pub const parseInstalledPackageRecord = packages.parseInstalledRecord;

/// Finds the pin for a package name, or nothing.
pub const findPackagePin = packages.find;

/// Whether an `rpm -qa` record is one of rpm's own trust pseudo-packages
/// rather than a package a transaction installed.
pub const isTrustPseudoPackage = packages.isTrustPseudoPackage;

/// The key rpm derived from imported trust, without the constant `(none)`
/// architecture rpm gives every one of them.
pub const trustKeyIdentity = packages.trustKeyIdentity;

/// Whether a `NAME-EPOCH:VERSION-RELEASE.ARCH` record is one of these pins.
pub const pinsCoverRecord = packages.coverRecord;

/// An EVR carries the one `:` a package name may not, so it gets its own rule.
pub fn validPackageEvr(evr: []const u8) bool {
    if (evr.len == 0 or !std.ascii.isAlphanumeric(evr[0])) return false;
    if (std.mem.indexOfScalar(u8, evr, ':') == null) return false;
    if (std.mem.indexOfScalar(u8, evr, '-') == null) return false;
    for (evr[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '+' and
            byte != '-' and
            byte != '~' and
            byte != '^' and
            byte != ':')
        {
            return false;
        }
    }
    return true;
}

pub const Tool = struct {
    name: []const u8,
    /// Nothing when the guest could not learn a version. A tool that was never
    /// successfully asked and a tool that answered with an empty string are
    /// different facts, and provenance may not present the first as the
    /// second.
    version: ?[]const u8 = null,
    command: []const []const u8,
};

/// A `/lib/modules` entry the guest's kernel discovery passed over, and why.
pub const SkippedKernel = struct {
    name: []const u8,
    reason: SkippedKernelReason,
};

pub const SkippedKernelReason = enum {
    invalid_release_name,
    not_a_module_directory,
    no_module_dependency_index,
};

/// An initramfs the guest regenerated and left in the target root.
pub const InitramfsImage = struct {
    kernel_release: []const u8,
    image_path: []const u8,
    size: u64,
    /// Raw bytes rather than hex: the frame is already binary-safe, and a
    /// fixed-length array is one fewer thing for the host to validate.
    sha256: [32]u8,
};

/// What a regeneration passed over and what it produced. Named for the outcome
/// rather than the request, because `Initramfs` above is the instruction.
pub const InitramfsOutcome = struct {
    skipped_kernel_releases: []const SkippedKernel = &.{},
    images: []const InitramfsImage = &.{},
};

/// What a relabel found, as distinct from what it did. The `setfiles` argv the
/// guest also reports says what ran; this says what the target's own
/// configuration named, which no request and no plan can.
/// What the guest does about SELinux.
///
/// `relabel_only` and `configure` are the two operations rather than one with
/// optional fields, because they are what the plan publishes as two actions
/// and because they fail differently: a relabel needs the policy the target
/// names, and a configuration change needs the settings the target declares.
pub const Selinux = union(enum) {
    /// Relabel with whatever policy the target's own configuration names,
    /// changing nothing else. Which policy is deliberately not named here: the
    /// guest reads it out of the target while the run executes, because a
    /// package action in the same run can have replaced it.
    relabel_only,
    configure: SelinuxConfigure,
};

pub const SelinuxConfigure = struct {
    /// The mode to write, absent to leave the target's own alone.
    mode: ?selinux.Mode = null,
    /// The policy to write, absent to leave the target's own alone.
    policy: ?[]const u8 = null,
    relabel: selinux.RelabelPolicy = .when_needed,
};

pub const SelinuxRelabel = struct {
    policy: []const u8,
    /// The `SELINUX=` setting, absent when the configuration names none the
    /// guest recognises. A relabelled root configured `disabled` never
    /// consults the labels this run wrote.
    mode: ?selinux.Mode = null,
};

/// What a configuration change found, as distinct from what it was told. The
/// control document already carries the mode and policy that were requested,
/// so what is left is the state the guest replaced and why it did or did not
/// walk the tree -- which depends on that state and so is not knowable to the
/// host that wrote the document.
pub const SelinuxConfigureOutcome = struct {
    previous_mode: ?selinux.Mode = null,
    /// Absent when the configuration the guest replaced named no policy this
    /// recognises.
    previous_policy: ?[]const u8 = null,
    relabelled: bool = false,
    relabel_reason: selinux.RelabelReason,
};

pub const Failure = struct {
    /// Which stage gave up, e.g. `mount-root` or `packages`.
    stage: []const u8,
    detail: []const u8 = "",
    /// Set when the stage failed because a guest command exited non-zero.
    exit_code: ?u8 = null,
};

pub const Result = struct {
    version: u32 = result_version,
    /// `null` means the guest completed the whole plan and unmounted cleanly.
    failure: ?Failure = null,
    tools: []const Tool = &.{},
    installed_packages: []const []const u8 = &.{},
    /// Every package the transaction added or changed, at the exact identity
    /// it settled on. The lock a later run would state to get this closure,
    /// emitted whether or not one was declared.
    package_lock: []const PackagePin = &.{},
    /// What each hook the control document declared did, in the order they
    /// ran. The host pairs these with the hooks it sent and refuses a result
    /// that does not account for every one of them.
    hooks: []const HookOutcome = &.{},
    /// What the guest read out of the target's own SELinux configuration when
    /// it relabelled. Absent when the document asked for no relabel.
    selinux_relabel: ?SelinuxRelabel = null,
    /// What the guest found in the target's own SELinux configuration before
    /// it rewrote it, and whether the change made it relabel. Absent when the
    /// document asked for no configuration change.
    selinux_configure: ?SelinuxConfigureOutcome = null,
    /// What an initramfs regeneration passed over and what it produced. Absent
    /// when the document asked for none.
    initramfs: ?InitramfsOutcome = null,
    /// Trust rpm holds because of this run, as `gpg-pubkey-<keyid>-<ts>`.
    imported_trust_keys: []const []const u8 = &.{},

    /// The result is recorded in the host's provenance, so its shape is
    /// bounded here for the same reason the control document's is: a document
    /// that arrives from the other side of a trust boundary is checked before
    /// it is believed, even when this build wrote the agent that sent it.
    pub fn validate(self: Result) Error!void {
        if (self.version != result_version) return error.UnsupportedVersion;
        if (self.tools.len > max_result_tools) return error.ResultTooLarge;
        for (self.tools) |tool| {
            if (tool.name.len == 0 or tool.name.len > 128) return error.InvalidToolRecord;
            if (tool.version) |version| {
                if (version.len == 0 or version.len > 1024) return error.InvalidToolRecord;
            }
            if (tool.command.len == 0 or tool.command.len > 64) {
                return error.InvalidToolRecord;
            }
        }
        if (self.selinux_relabel) |relabel| {
            // Held to the same rule the guest used to build a path out of it,
            // rather than to a length: a name that arrives from the other side
            // of the boundary is checked before it is published.
            if (!selinux.validPolicyName(relabel.policy)) return error.InvalidSelinuxRecord;
        }
        if (self.selinux_configure) |configure| {
            // The same rule, for the same reason: this name is published in
            // the host's provenance and arrives from the other side of the
            // boundary.
            if (configure.previous_policy) |name| {
                if (!selinux.validPolicyName(name)) return error.InvalidSelinuxRecord;
            }
            // A run that says it relabelled for no reason, or that says it
            // did not relabel while naming one, is describing something that
            // did not happen.
            if (configure.relabelled != selinux.relabels(configure.relabel_reason)) {
                return error.InvalidSelinuxRecord;
            }
        }
        if (self.initramfs) |initramfs| {
            // Bounded by the same limit the inventory is: both are lists the
            // guest sizes from a directory the target controls.
            if (initramfs.images.len > max_result_packages) return error.ResultTooLarge;
            if (initramfs.skipped_kernel_releases.len > max_result_packages) {
                return error.ResultTooLarge;
            }
            for (initramfs.images) |image| {
                if (!validKernelRelease(image.kernel_release)) {
                    return error.InvalidInitramfsRecord;
                }
                if (image.image_path.len == 0 or image.image_path.len > 512) {
                    return error.InvalidInitramfsRecord;
                }
            }
            for (initramfs.skipped_kernel_releases) |skipped| {
                // Deliberately not held to `validKernelRelease`: the whole
                // point of the record is that the name failed that rule. It is
                // bounded and checked for embedded nulls instead, because it
                // reaches a published document.
                if (skipped.name.len == 0 or skipped.name.len > 512) {
                    return error.InvalidInitramfsRecord;
                }
                if (std.mem.indexOfScalar(u8, skipped.name, 0) != null) {
                    return error.InvalidInitramfsRecord;
                }
            }
        }
        // Bounded by the same limit the inventory it is drawn from is.
        if (self.imported_trust_keys.len > max_result_packages) return error.ResultTooLarge;
        for (self.imported_trust_keys) |key| {
            if (!isTrustPseudoPackage(key) and
                !std.mem.startsWith(u8, key, "gpg-pubkey-"))
            {
                return error.InvalidTrustKeyRecord;
            }
            if (key.len > 128) return error.InvalidTrustKeyRecord;
        }
        if (self.installed_packages.len > max_result_packages) return error.ResultTooLarge;
        for (self.installed_packages) |name| {
            if (name.len == 0 or name.len > 512) return error.InvalidPackageName;
        }
        // The same bound as the inventory it is a subset of, and the same
        // rules the control document's pins are held to: a result crosses the
        // trust boundary in the other direction, so it is checked in its own
        // right rather than trusted because the host wrote the agent.
        if (self.package_lock.len > max_result_packages) return error.ResultTooLarge;
        for (self.package_lock) |pin| {
            if (!validPackageName(pin.name)) return error.InvalidPackagePin;
            if (!validPackageEvr(pin.evr)) return error.InvalidPackagePin;
            if (!validKernelRelease(pin.architecture)) return error.InvalidPackagePin;
        }
        if (self.failure) |failure| {
            if (failure.stage.len == 0 or failure.stage.len > 64) {
                return error.InvalidFailureRecord;
            }
            if (failure.detail.len > 4096) return error.InvalidFailureRecord;
        }
        if (self.hooks.len > max_hooks) return error.ResultTooLarge;
        for (self.hooks, 0..) |outcome, position| {
            // Strictly increasing, so a result cannot report one hook twice to
            // make up the count for one it skipped. Which indices those are is
            // checked against the control document by the host, which is the
            // only side that still has it.
            if (position != 0 and outcome.index <= self.hooks[position - 1].index) {
                return error.UnexpectedHookOutcome;
            }
        }
    }
};

pub const max_result_tools: usize = 64;
pub const max_result_packages: usize = 100_000;

fn validateDevicePath(path: []const u8) Error!void {
    if (!std.mem.startsWith(u8, path, "/dev/")) return error.InvalidDevicePath;
    const name = path["/dev/".len..];
    if (name.len == 0 or name.len > 32) return error.InvalidDevicePath;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return error.InvalidDevicePath;
    }
}

/// Mirrors `customize.validUnsafeRepositoryId`: the id becomes both a tdnf
/// section name and a file name under the guest's repository directory.
pub fn validRepositoryId(id: []const u8) bool {
    if (id.len == 0 or id.len > 128 or !std.ascii.isAlphanumeric(id[0])) return false;
    for (id[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and byte != '-') {
            return false;
        }
    }
    return true;
}

/// Mirrors `customize.validUnsafePackageName`. A name that could be read as a
/// local file or an option is rejected: it becomes a tdnf argv element.
pub fn validPackageName(name: []const u8) bool {
    if (name.len == 0 or name.len > 256 or !std.ascii.isAlphanumeric(name[0])) return false;
    if (name.len >= 4 and std.ascii.eqlIgnoreCase(name[name.len - 4 ..], ".rpm")) return false;
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and byte != '_' and byte != '+' and
            byte != '-' and byte != '~' and byte != '^')
        {
            return false;
        }
    }
    return true;
}

/// The guest writes rendered configuration only where it recognises the
/// destination, so a host that renders somewhere new fails loudly here rather
/// than the two backends quietly producing different images.
pub fn knownKernelModuleConfigPath(path: []const u8) bool {
    for (kernel_module_config_paths) |known| {
        if (std.mem.eql(u8, known, path)) return true;
    }
    return false;
}

/// Whether a string is a kernel release the backends will act on. The release
/// becomes both a dracut argument and a `/boot/initramfs-<release>.img` path,
/// so it is bounded as well as restricted. One rule, in `initramfs.zig`,
/// shared with `customize` and `unsafe_chroot` rather than mirrored by them.
pub const validKernelRelease = initramfs_mod.validKernelRelease;

/// A module member is a path the guest opens in its own rootfs and a name the
/// host chose, so it is confined to a top-level `.ko` file: no directory to
/// traverse out of, nothing the cpio unpacker would have had to create, and
/// nothing that could name a file the agent did not put there.
pub fn validModuleMember(member: []const u8) bool {
    if (member.len <= ".ko".len or member.len > 128) return false;
    if (!std.mem.endsWith(u8, member, ".ko")) return false;
    if (!std.ascii.isAlphanumeric(member[0])) return false;
    for (member[1 .. member.len - ".ko".len]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-') return false;
    }
    return true;
}

/// Mirrors `customize.validConfigName` as applied to a hook name, and
/// `unsafe_chroot.validHookName`: the same value is re-checked at each
/// privilege boundary it crosses rather than trusted because an earlier one
/// looked at it.
pub fn validHookName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255 or name[0] == '.') return false;
    return std.mem.indexOfAny(u8, name, "/\r\n\x00") == null;
}

/// Whether the encoded script names its own interpreter, decided without
/// decoding it.
///
/// The first four base64 characters carry the first three bytes, which is one
/// more than this needs. Deciding it here means `validate` enforces the rule
/// where every other rule is enforced -- before the guest has allocated for
/// the script, let alone written it anywhere.
fn hookScriptNamesInterpreter(script_base64: []const u8) bool {
    if (script_base64.len < 4) return false;
    const head_source = script_base64[0..4];
    const size = std.base64.standard.Decoder.calcSizeForSlice(head_source) catch return false;
    if (size < 2) return false;
    var head: [3]u8 = undefined;
    std.base64.standard.Decoder.decode(head[0..size], head_source) catch return false;
    return head[0] == '#' and head[1] == '!';
}

/// Holds a control document's hooks to the same model the library validated
/// the request against.
///
/// Re-checked rather than trusted, because this runs in the guest against a
/// document that arrived across the transport, and because the guest is about
/// to write these bytes to an executable file and run them as root.
fn validateHooks(hooks: []const Hook) Error!void {
    if (hooks.len > max_hooks) return error.TooManyHooks;
    var previous_phase: ?HookPhase = null;
    var total_script_bytes: usize = 0;
    for (hooks, 0..) |hook, index| {
        if (!validHookName(hook.name)) return error.InvalidHookName;
        for (hooks[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.name, hook.name)) return error.DuplicateHookName;
        }
        if (previous_phase) |phase| {
            if (@intFromEnum(hook.phase) < @intFromEnum(phase)) {
                return error.HookPhaseOutOfOrder;
            }
        }
        previous_phase = hook.phase;

        const size = std.base64.standard.Decoder.calcSizeForSlice(hook.script_base64) catch
            return error.InvalidHookScript;
        if (size == 0 or size > max_hook_script_bytes) return error.InvalidHookScript;
        if (!hookScriptNamesInterpreter(hook.script_base64)) return error.InvalidHookScript;
        total_script_bytes += size;
        if (total_script_bytes > max_hook_total_script_bytes) {
            return error.HookScriptsTooLarge;
        }

        if (hook.arguments.len > max_hook_arguments) return error.TooManyHookArguments;
        for (hook.arguments) |argument| {
            if (argument.len > max_hook_argument_bytes) return error.InvalidHookArgument;
            if (std.mem.indexOfScalar(u8, argument, 0) != null) {
                return error.InvalidHookArgument;
            }
        }
    }
}

/// The decoded length of a validated hook script. Separate from `validate` so
/// the guest sizes its buffer from the same arithmetic the bound was checked
/// against rather than from a second reading of the same string.
pub fn hookScriptSize(hook: Hook) Error!usize {
    return std.base64.standard.Decoder.calcSizeForSlice(hook.script_base64) catch
        error.InvalidHookScript;
}

pub fn decodeHookScript(hook: Hook, into: []u8) Error!void {
    std.base64.standard.Decoder.decode(into, hook.script_base64) catch
        return error.InvalidHookScript;
}

pub fn validRepositoryUrl(url: []const u8) bool {
    if (url.len == 0 or url.len > 2048) return false;
    // The url is written into a repository file whose grammar is line-based
    // and whose baseurl values are space-separated.
    for (url) |byte| {
        if (byte <= 0x20 or byte == 0x7F) return false;
    }
    if (hasUserinfo(url)) return false;
    return std.mem.startsWith(u8, url, "https://") or
        std.mem.startsWith(u8, url, "http://") or
        std.mem.startsWith(u8, url, "file://");
}

/// Whether a URL carries a userinfo component -- `https://user:secret@host/`.
///
/// Refused rather than accepted, because everything about a repository is
/// recorded: the URL is hashed into the plan identifier, written out verbatim
/// by the request and plan JSON, and kept in provenance. A password smuggled in
/// here would be published by all three. It is also the one place a secret can
/// reach a run without being declared, which is the whole point of declaring
/// credentials separately -- so it has to be refused rather than merely
/// discouraged.
///
/// Only the authority is examined. `@` is an ordinary path character, and a
/// repository whose path contains one is not carrying a credential.
pub fn hasUserinfo(url: []const u8) bool {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return false;
    const authority = url[scheme_end + 3 ..];
    const authority_end = std.mem.indexOfAny(u8, authority, "/?#") orelse authority.len;
    return std.mem.indexOfScalar(u8, authority[0..authority_end], '@') != null;
}

// ---- Framing ----------------------------------------------------------
//
// The result device is raw storage with no filesystem, so a reader cannot tell
// "the guest wrote nothing" from "the guest wrote something" without a frame.
// The host zeroes the device before the run; a missing magic therefore means
// the guest never got far enough to answer, which is a distinct outcome from
// any answer it could have given.

pub const frame_magic = "ZVMIVMR1";
pub const frame_header_size: usize = 8 + 8 + 32;

/// Serializes and frames `result`, padded to a whole number of sectors so it
/// can be written straight to a block device.
pub fn seal(allocator: Allocator, result: Result) ![]u8 {
    const payload = try std.json.Stringify.valueAlloc(allocator, result, .{});
    defer allocator.free(payload);
    return frame(allocator, payload);
}

pub fn frame(allocator: Allocator, payload: []const u8) ![]u8 {
    return frameWith(allocator, frame_magic, max_result_bytes, payload);
}

/// Returns the payload bytes of a framed result, borrowed from `bytes`.
pub fn unframe(bytes: []const u8) Error![]const u8 {
    return unframeWith(frame_magic, max_result_bytes, bytes);
}

/// The framing both block-device channels use, parameterized by the magic that
/// says which one it is.
///
/// The magic is a parameter rather than a constant because the two channels
/// must not be interchangeable. A credential blob that framed like a result
/// would be accepted by `parseResult` if the devices were ever attached in the
/// wrong order, and the failure would be a successful parse of the wrong
/// document rather than a refusal.
fn frameWith(
    allocator: Allocator,
    magic: []const u8,
    limit: usize,
    payload: []const u8,
) ![]u8 {
    if (payload.len > limit) return error.FrameTooLarge;
    const total = std.mem.alignForward(usize, frame_header_size + payload.len, sector_size);
    const buffer = try allocator.alloc(u8, total);
    errdefer allocator.free(buffer);
    @memset(buffer, 0);

    @memcpy(buffer[0..magic.len], magic);
    std.mem.writeInt(u64, buffer[8..16], payload.len, .little);
    std.crypto.hash.sha2.Sha256.hash(payload, buffer[16..48], .{});
    @memcpy(buffer[frame_header_size..][0..payload.len], payload);
    return buffer;
}

fn unframeWith(magic: []const u8, limit: usize, bytes: []const u8) Error![]const u8 {
    if (bytes.len < frame_header_size) return error.TruncatedFrame;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return error.BadFrameMagic;
    const length = std.mem.readInt(u64, bytes[8..16], .little);
    if (length > limit) return error.FrameTooLarge;
    if (frame_header_size + length > bytes.len) return error.TruncatedFrame;
    const payload = bytes[frame_header_size..][0..@intCast(length)];

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, bytes[16..48].*)) {
        return error.FrameDigestMismatch;
    }
    return payload;
}

// The credential device.
//
// Credential material is the one thing the host has to hand the guest that
// must not survive the run anywhere. It therefore travels on its own device
// rather than in the control document, which the host writes into an initramfs
// file on its own disk, and it is framed rather than serialized: JSON would
// mean the guest parsing a password into an allocation it would then have to
// find and scrub, where a length-prefixed record can be read in place and the
// single device buffer zeroed once.

pub const credential_magic = "ZVMIVMK1";
/// Kept equal to `customize.max_credential_material_bytes` by a test in
/// `vm_backend`, which is the one module that imports both.
pub const max_credential_material_bytes: usize = 4096;
pub const max_credentials: usize = 64;
pub const max_credential_field_bytes: usize = 256;
pub const max_credential_bytes: usize =
    4 + max_credentials * (4 + max_credential_material_bytes);
/// Size of the credential block device. A whole number of sectors, and large
/// enough for the bound above, so the guest never has to grow a read.
pub const credential_device_bytes: u64 = 512 * 1024;

/// Frames the resolved passwords, in the order the control document indexes
/// them, for writing to the credential device.
///
/// Only passwords: a user name is not a secret, is stated outright in the
/// control document so a reader can tell which identity a build ran as, and
/// carrying it here as well would put it in two places that could disagree.
pub fn sealCredentials(allocator: Allocator, passwords: []const []const u8) ![]u8 {
    if (passwords.len > max_credentials) return error.TooManyCredentials;
    var payload: std.array_list.Managed(u8) = .init(allocator);
    defer {
        @memset(payload.items, 0);
        payload.deinit();
    }
    var count: [4]u8 = undefined;
    std.mem.writeInt(u32, &count, @intCast(passwords.len), .little);
    try payload.appendSlice(&count);
    for (passwords) |password| {
        if (password.len > max_credential_material_bytes) {
            return error.CredentialMaterialTooLarge;
        }
        var length: [4]u8 = undefined;
        std.mem.writeInt(u32, &length, @intCast(password.len), .little);
        try payload.appendSlice(&length);
        try payload.appendSlice(password);
    }
    return frameWith(allocator, credential_magic, max_credential_bytes, payload.items);
}

/// The passwords a credential device holds, borrowed from the buffer it was
/// read into. Nothing here allocates, so scrubbing the material is scrubbing
/// that one buffer.
pub const Credentials = struct {
    payload: []const u8,
    count: u32,

    pub fn password(self: Credentials, index: u32) Error![]const u8 {
        if (index >= self.count) return error.CredentialIndexOutOfRange;
        var offset: usize = 4;
        var current: u32 = 0;
        while (current < self.count) : (current += 1) {
            if (offset + 4 > self.payload.len) return error.TruncatedFrame;
            const length = std.mem.readInt(u32, self.payload[offset..][0..4], .little);
            offset += 4;
            if (length > max_credential_material_bytes) return error.FrameTooLarge;
            if (offset + length > self.payload.len) return error.TruncatedFrame;
            if (current == index) return self.payload[offset..][0..length];
            offset += length;
        }
        return error.CredentialIndexOutOfRange;
    }
};

pub fn parseCredentials(bytes: []const u8) Error!Credentials {
    const payload = try unframeWith(credential_magic, max_credential_bytes, bytes);
    if (payload.len < 4) return error.TruncatedFrame;
    const count = std.mem.readInt(u32, payload[0..4], .little);
    if (count > max_credentials) return error.TooManyCredentials;
    return .{ .payload = payload, .count = count };
}

pub fn parseResult(allocator: Allocator, bytes: []const u8) !std.json.Parsed(Result) {
    const payload = try unframe(bytes);
    return std.json.parseFromSlice(Result, allocator, payload, .{
        .allocate = .alloc_always,
    });
}

pub fn parseControl(allocator: Allocator, bytes: []const u8) !std.json.Parsed(Control) {
    if (bytes.len > max_control_bytes) return error.FrameTooLarge;
    // The version must be read before the document is parsed into `Control`,
    // not after it. A document written by a different build may carry fields or
    // union tags this build has no type for, and those fail during parsing --
    // so a version check placed after the parse never runs for the very change
    // it exists to catch, and a version mismatch surfaces as an opaque
    // `UnknownField` instead of a refusal naming the cause.
    const probe = try std.json.parseFromSlice(
        struct { version: u32 = control_version },
        allocator,
        bytes,
        .{ .ignore_unknown_fields = true },
    );
    defer probe.deinit();
    if (probe.value.version != control_version) return error.UnsupportedVersion;

    const parsed = try std.json.parseFromSlice(Control, allocator, bytes, .{
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    try parsed.value.validate();
    return parsed;
}

test "a version mismatch is refused by name even when the document is otherwise unparseable" {
    const allocator = std.testing.allocator;

    // A future build's document: a newer version, and an action tag this build
    // has no type for. The version is what the receiver can act on, so that is
    // what it must report -- not the parse failure that happens to come first.
    try std.testing.expectError(error.UnsupportedVersion, parseControl(
        allocator,
        \\{"version":7,"root_device":"/dev/vda2","result_device":"/dev/vdb",
        \\"network":{"offline":{}},"actions":[{"reinstall_everything":["x"]}]}
        ,
    ));

    // A document of this version carrying an unknown tag is still a parse
    // failure: the version claimed it would be understood, and it was not.
    try std.testing.expectError(error.UnknownField, parseControl(
        allocator,
        \\{"version":6,"root_device":"/dev/vda2","result_device":"/dev/vdb",
        \\"network":{"offline":{}},"actions":[{"reinstall_everything":["x"]}]}
        ,
    ));
}

test "a control document round-trips and is validated on the way back in" {
    const allocator = std.testing.allocator;
    const control = Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .{ .declared_repositories = qemu_user_network },
        .repositories = &.{.{
            .id = "azurelinux-base",
            .urls = &.{"https://packages.microsoft.com/azurelinux/3.0/prod/base/x86_64"},
            .trust_base64 = &.{"a2V5"},
        }},
        .actions = &.{.{ .install = &.{"strace"} }},
        .package_pins = &.{.{
            .name = "strace",
            .evr = "0:6.8-1.azl3",
            .architecture = "x86_64",
        }},
        .initramfs = .{ .regenerate = .{ .kernels = &.{"6.12.0-1.azl"} } },
        .modules = &.{ "zvmi-module-00-virtio_pci.ko", "zvmi-module-01-ext4.ko" },
    };
    try control.validate();

    const json = try std.json.Stringify.valueAlloc(allocator, control, .{});
    defer allocator.free(json);

    // `PackagePin` is an alias of `packages.VersionLock` rather than a struct
    // of its own, and an alias must not be visible on the wire. Asserted
    // rather than assumed, because the document a released host writes has to
    // stay readable by a guest agent built from a different revision.
    try std.testing.expect(std.mem.indexOf(
        u8,
        json,
        "\"package_pins\":[{\"name\":\"strace\",\"evr\":\"0:6.8-1.azl3\",\"architecture\":\"x86_64\"}]",
    ) != null);

    const parsed = try parseControl(allocator, json);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("/dev/vda2", parsed.value.root_device);
    try std.testing.expectEqualStrings("strace", parsed.value.package_pins[0].name);
    try std.testing.expectEqualStrings("0:6.8-1.azl3", parsed.value.package_pins[0].evr);
    try std.testing.expectEqualStrings("x86_64", parsed.value.package_pins[0].architecture);
    try std.testing.expectEqualStrings(
        "10.0.2.15",
        parsed.value.network.declared_repositories.address,
    );
    try std.testing.expectEqualStrings("strace", parsed.value.actions[0].install[0]);
    try std.testing.expectEqualStrings(
        "6.12.0-1.azl",
        parsed.value.initramfs.regenerate.kernels[0],
    );
    // Insertion order is an instruction, not a set, so it survives the trip.
    try std.testing.expectEqual(@as(usize, 2), parsed.value.modules.len);
    try std.testing.expectEqualStrings("zvmi-module-00-virtio_pci.ko", parsed.value.modules[0]);
    try std.testing.expectEqualStrings("zvmi-module-01-ext4.ko", parsed.value.modules[1]);
}

test "regenerating every initramfs is distinct from leaving it alone" {
    const allocator = std.testing.allocator;
    const base = Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .offline,
    };

    // Naming no kernel release used to be indistinguishable from asking for
    // nothing at all, because both were an empty list. The tag carries the
    // difference now, so a document cannot express a contradiction and the
    // guest never has to guess which of the two was meant.
    var regenerate_all = base;
    regenerate_all.initramfs = .{ .regenerate = .{} };
    try regenerate_all.validate();

    const json = try std.json.Stringify.valueAlloc(allocator, regenerate_all, .{});
    defer allocator.free(json);
    const parsed = try parseControl(allocator, json);
    defer parsed.deinit();
    try std.testing.expect(parsed.value.initramfs == .regenerate);
    try std.testing.expectEqual(
        @as(usize, 0),
        parsed.value.initramfs.regenerate.kernels.len,
    );

    const unchanged_json = try std.json.Stringify.valueAlloc(allocator, base, .{});
    defer allocator.free(unchanged_json);
    const unchanged = try parseControl(allocator, unchanged_json);
    defer unchanged.deinit();
    try std.testing.expect(unchanged.value.initramfs == .unchanged);
    try std.testing.expect(!std.mem.eql(u8, json, unchanged_json));
}

test "a document with no modules is the document this backend has always sent" {
    const allocator = std.testing.allocator;
    const control = Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .offline,
    };
    const json = try std.json.Stringify.valueAlloc(allocator, control, .{});
    defer allocator.free(json);

    const parsed = try parseControl(allocator, json);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 0), parsed.value.modules.len);
}

test "a control document the guest could be driven by is rejected" {
    const base = Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .{ .declared_repositories = qemu_user_network },
        .repositories = &.{.{
            .id = "base",
            .urls = &.{"https://example.invalid/base"},
            .trust_base64 = &.{"a2V5"},
        }},
    };
    try base.validate();

    const cases = [_]struct {
        expected: Error,
        control: Control,
    }{
        .{ .expected = error.UnsupportedVersion, .control = blk: {
            var control = base;
            control.version = control_version + 1;
            break :blk control;
        } },
        .{ .expected = error.InvalidDevicePath, .control = blk: {
            var control = base;
            control.root_device = "/dev/../etc/shadow";
            break :blk control;
        } },
        .{ .expected = error.InvalidDevicePath, .control = blk: {
            var control = base;
            control.result_device = "vdb";
            break :blk control;
        } },
        .{ .expected = error.InvalidRepositoryId, .control = blk: {
            var control = base;
            control.repositories = &.{.{
                .id = "../../etc/yum.repos.d/evil",
                .urls = &.{"https://example.invalid/base"},
                .trust_base64 = &.{"a2V5"},
            }};
            break :blk control;
        } },
        // A module member is a path the guest opens as PID 1, so a name that
        // could reach outside the initramfs is refused on both sides.
        .{ .expected = error.InvalidModuleMember, .control = blk: {
            var control = base;
            control.modules = &.{"../lib/modules/evil.ko"};
            break :blk control;
        } },
        .{ .expected = error.InvalidModuleMember, .control = blk: {
            var control = base;
            control.modules = &.{"subdir/ext4.ko"};
            break :blk control;
        } },
        .{ .expected = error.InvalidModuleMember, .control = blk: {
            var control = base;
            control.modules = &.{"zvmi-module-00-ext4.ko.xz"};
            break :blk control;
        } },
        .{ .expected = error.InvalidModuleMember, .control = blk: {
            var control = base;
            control.modules = &.{".ko"};
            break :blk control;
        } },
        .{ .expected = error.TooManyModules, .control = blk: {
            var control = base;
            control.modules = &([_][]const u8{"zvmi-module-00-ext4.ko"} ** (max_modules + 1));
            break :blk control;
        } },
        .{ .expected = error.DuplicateRepositoryId, .control = blk: {
            var control = base;
            control.repositories = &.{
                .{
                    .id = "base",
                    .urls = &.{"https://example.invalid/a"},
                    .trust_base64 = &.{"a2V5"},
                },
                .{
                    .id = "base",
                    .urls = &.{"https://example.invalid/b"},
                    .trust_base64 = &.{"a2V5"},
                },
            };
            break :blk control;
        } },
        .{ .expected = error.RepositoryWithoutTrust, .control = blk: {
            var control = base;
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"https://example.invalid/base"},
            }};
            break :blk control;
        } },
        .{ .expected = error.InvalidRepositoryUrl, .control = blk: {
            var control = base;
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"ftp://example.invalid/base"},
                .trust_base64 = &.{"a2V5"},
            }};
            break :blk control;
        } },
        .{ .expected = error.InvalidRepositoryUrl, .control = blk: {
            var control = base;
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"https://example.invalid/a b"},
                .trust_base64 = &.{"a2V5"},
            }};
            break :blk control;
        } },
        // A credential the guest could not resolve is worse than no
        // credential: the run would reach the package manager, fail to
        // authenticate, and report an error about the repository rather than
        // about the document that was wrong.
        .{ .expected = error.MissingCredentialDevice, .control = blk: {
            var control = base;
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"https://example.invalid/base"},
                .trust_base64 = &.{"a2V5"},
                .credential = .{ .basic = .{ .username = "builder", .password_index = 0 } },
            }};
            break :blk control;
        } },
        // The other direction, and refused for a different reason: a device
        // attached for nobody is material sealed and handed to the emulator
        // with no reader, which is a host that thinks it is carrying a secret
        // somewhere it is not.
        .{ .expected = error.UnexpectedCredentialDevice, .control = blk: {
            var control = base;
            control.credential_device = "/dev/vdc";
            break :blk control;
        } },
        .{ .expected = error.CredentialIndexOutOfRange, .control = blk: {
            var control = base;
            control.credential_device = "/dev/vdc";
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"https://example.invalid/base"},
                .trust_base64 = &.{"a2V5"},
                .credential = .{ .basic = .{
                    .username = "builder",
                    .password_index = max_credentials,
                } },
            }};
            break :blk control;
        } },
        // A user name reaches the repository file as an INI value, so a
        // newline in it would end the line and let the rest be read as
        // configuration the policy never asked for.
        .{ .expected = error.InvalidCredentialUsername, .control = blk: {
            var control = base;
            control.credential_device = "/dev/vdc";
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"https://example.invalid/base"},
                .trust_base64 = &.{"a2V5"},
                .credential = .{ .basic = .{
                    .username = "builder\nproxy=http://attacker.invalid",
                    .password_index = 0,
                } },
            }};
            break :blk control;
        } },
        .{ .expected = error.InvalidDevicePath, .control = blk: {
            var control = base;
            control.credential_device = "/dev/../etc/shadow";
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"https://example.invalid/base"},
                .trust_base64 = &.{"a2V5"},
                .credential = .{ .basic = .{ .username = "builder", .password_index = 0 } },
            }};
            break :blk control;
        } },
        // Named apart from a malformed URL: this one is well-formed, and the
        // thing wrong with it is that it is carrying a password into the field
        // the plan hashes and provenance records verbatim.
        .{ .expected = error.RepositoryUrlCarriesCredential, .control = blk: {
            var control = base;
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"https://builder:hunter2@example.invalid/base"},
                .trust_base64 = &.{"a2V5"},
            }};
            break :blk control;
        } },
        .{ .expected = error.InvalidPackageName, .control = blk: {
            var control = base;
            control.actions = &.{.{ .install = &.{"--setopt=tsflags=noscripts"} }};
            break :blk control;
        } },
        .{ .expected = error.InvalidPackageName, .control = blk: {
            var control = base;
            control.actions = &.{.{ .install = &.{"/tmp/evil.rpm"} }};
            break :blk control;
        } },
        .{ .expected = error.EmptyAction, .control = blk: {
            var control = base;
            control.actions = &.{.{ .remove = &.{} }};
            break :blk control;
        } },
        .{ .expected = error.InvalidKernelRelease, .control = blk: {
            var control = base;
            control.initramfs = .{ .regenerate = .{ .kernels = &.{"../../../boot/vmlinuz"} } };
            break :blk control;
        } },
        .{ .expected = error.OfflineNetworkWithPackageActions, .control = blk: {
            var control = base;
            control.network = .offline;
            control.actions = &.{.{ .install = &.{"strace"} }};
            break :blk control;
        } },
        .{ .expected = error.NoDeclaredRepositories, .control = blk: {
            var control = base;
            control.repositories = &.{};
            break :blk control;
        } },
        .{ .expected = error.InvalidTrustMaterial, .control = blk: {
            var control = base;
            control.repositories = &.{.{
                .id = "base",
                .urls = &.{"https://example.invalid/base"},
                .trust_base64 = &.{"not valid base64!"},
            }};
            break :blk control;
        } },
        // A hook is the one field a caller fills with code rather than
        // configuration, and the guest is about to make these bytes executable
        // and run them as root. Every rule the library applied to the request
        // is applied again here, to the document that actually arrived.
        .{ .expected = error.InvalidHookName, .control = blk: {
            var control = base;
            control.hooks = &.{.{
                .name = "../../etc/cron.d/evil",
                .phase = .finalize,
                .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=",
            }};
            break :blk control;
        } },
        .{ .expected = error.DuplicateHookName, .control = blk: {
            var control = base;
            control.hooks = &.{
                .{ .name = "same", .phase = .finalize, .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=" },
                .{ .name = "same", .phase = .finalize, .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=" },
            };
            break :blk control;
        } },
        .{ .expected = error.HookPhaseOutOfOrder, .control = blk: {
            var control = base;
            control.hooks = &.{
                .{ .name = "late", .phase = .finalize, .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=" },
                .{ .name = "early", .phase = .after_packages, .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=" },
            };
            break :blk control;
        } },
        // No shebang: a script that does not name its own interpreter is one
        // whose meaning depends on who runs it.
        .{ .expected = error.InvalidHookScript, .control = blk: {
            var control = base;
            control.hooks = &.{.{
                .name = "no-interpreter",
                .phase = .finalize,
                .script_base64 = "ZXhpdCAwCg==",
            }};
            break :blk control;
        } },
        .{ .expected = error.InvalidHookScript, .control = blk: {
            var control = base;
            control.hooks = &.{.{
                .name = "not-base64",
                .phase = .finalize,
                .script_base64 = "not valid base64!",
            }};
            break :blk control;
        } },
        .{ .expected = error.InvalidHookScript, .control = blk: {
            var control = base;
            control.hooks = &.{.{
                .name = "empty",
                .phase = .finalize,
                .script_base64 = "",
            }};
            break :blk control;
        } },
        .{ .expected = error.InvalidHookArgument, .control = blk: {
            var control = base;
            control.hooks = &.{.{
                .name = "nul-argument",
                .phase = .finalize,
                .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=",
                .arguments = &.{"first\x00second"},
            }};
            break :blk control;
        } },
        .{ .expected = error.TooManyHookArguments, .control = blk: {
            var control = base;
            control.hooks = &.{.{
                .name = "wordy",
                .phase = .finalize,
                .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=",
                .arguments = &([_][]const u8{"x"} ** (max_hook_arguments + 1)),
            }};
            break :blk control;
        } },
    };

    for (cases, 0..) |case, index| {
        std.testing.expectError(case.expected, case.control.validate()) catch |err| {
            std.debug.print("control rejection case {d} did not fail as expected\n", .{index});
            return err;
        };
    }
}

test "the hook channel is bounded by weight, not only by count" {
    const allocator = std.testing.allocator;
    const base = Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .offline,
    };

    // `max_hooks` scripts of `max_hook_script_bytes` would be 16 MiB decoded
    // and over 21 MiB encoded -- past `max_control_bytes` before the rest of
    // the document is counted. The count bound alone would let that through,
    // which is the whole reason the total exists.
    const oversized = try allocator.alloc(u8, max_hook_script_bytes);
    defer allocator.free(oversized);
    @memset(oversized, 'x');
    oversized[0] = '#';
    oversized[1] = '!';
    const encoded = try allocator.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(oversized.len),
    );
    defer allocator.free(encoded);
    const script_base64 = std.base64.standard.Encoder.encode(encoded, oversized);

    const heavy = try allocator.alloc(Hook, max_hook_total_script_bytes / max_hook_script_bytes + 1);
    defer allocator.free(heavy);
    const names = try allocator.alloc([16]u8, heavy.len);
    defer allocator.free(names);
    for (heavy, names, 0..) |*hook, *name, index| {
        hook.* = .{
            .name = std.fmt.bufPrint(name, "hook-{d}", .{index}) catch unreachable,
            .phase = .finalize,
            .script_base64 = script_base64,
        };
    }
    var weighty = base;
    weighty.hooks = heavy;
    try std.testing.expect(heavy.len <= max_hooks);
    try std.testing.expectError(error.HookScriptsTooLarge, weighty.validate());

    // And the count still bounds a document of hooks light enough that the
    // total never fires: an empty-script hook is a fork the guest performs.
    const many = try allocator.alloc(Hook, max_hooks + 1);
    defer allocator.free(many);
    const light_names = try allocator.alloc([16]u8, many.len);
    defer allocator.free(light_names);
    for (many, light_names, 0..) |*hook, *name, index| {
        hook.* = .{
            .name = std.fmt.bufPrint(name, "hook-{d}", .{index}) catch unreachable,
            .phase = .finalize,
            .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=",
        };
    }
    var numerous = base;
    numerous.hooks = many;
    try std.testing.expectError(error.TooManyHooks, numerous.validate());
}

test "a hook survives the control document unchanged" {
    const allocator = std.testing.allocator;
    const script = "#!/bin/sh\nexit 0\n";

    var control = Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .offline,
    };
    control.hooks = &.{.{
        .name = "seal-check",
        .phase = .before_seal,
        .script_base64 = "IyEvYmluL3NoCmV4aXQgMAo=",
        .arguments = &.{ "--strict", "/etc" },
    }};
    try control.validate();

    const bytes = try std.json.Stringify.valueAlloc(allocator, control, .{});
    defer allocator.free(bytes);
    const parsed = try parseControl(allocator, bytes);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.value.hooks.len);
    const hook = parsed.value.hooks[0];
    try std.testing.expectEqualStrings("seal-check", hook.name);
    try std.testing.expectEqual(HookPhase.before_seal, hook.phase);
    try std.testing.expectEqual(@as(usize, 2), hook.arguments.len);

    // The bytes the guest will make executable are the bytes the host had.
    const size = try hookScriptSize(hook);
    const decoded = try allocator.alloc(u8, size);
    defer allocator.free(decoded);
    try decodeHookScript(hook, decoded);
    try std.testing.expectEqualStrings(script, decoded);
}

test "a result cannot account for a hook twice to cover one it skipped" {
    const complete = Result{ .hooks = &.{
        .{ .index = 0, .exit_code = 0 },
        .{ .index = 1, .exit_code = 0 },
    } };
    try complete.validate();

    const repeated = Result{ .hooks = &.{
        .{ .index = 0, .exit_code = 0 },
        .{ .index = 0, .exit_code = 0 },
    } };
    try std.testing.expectError(error.UnexpectedHookOutcome, repeated.validate());

    const reordered = Result{ .hooks = &.{
        .{ .index = 1, .exit_code = 0 },
        .{ .index = 0, .exit_code = 0 },
    } };
    try std.testing.expectError(error.UnexpectedHookOutcome, reordered.validate());
}

test "a sealed result round-trips through the block-device frame" {
    const allocator = std.testing.allocator;
    const sealed = try seal(allocator, .{
        .tools = &.{.{
            .name = "tdnf",
            .version = "3.5.8",
            .command = &.{ "/usr/bin/tdnf", "install", "-y", "strace" },
        }},
        .installed_packages = &.{ "filesystem-1.1-1.azl.x86_64", "strace-6.6-1.azl.x86_64" },
    });
    defer allocator.free(sealed);
    try std.testing.expectEqual(@as(usize, 0), sealed.len % sector_size);

    const parsed = try parseResult(allocator, sealed);
    defer parsed.deinit();
    try std.testing.expect(parsed.value.failure == null);
    try std.testing.expectEqualStrings("tdnf", parsed.value.tools[0].name);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.installed_packages.len);
}

test "a guest failure survives the round trip with its stage and exit code" {
    const allocator = std.testing.allocator;
    const sealed = try seal(allocator, .{
        .failure = .{ .stage = "packages", .detail = "tdnf install failed", .exit_code = 1 },
    });
    defer allocator.free(sealed);

    const parsed = try parseResult(allocator, sealed);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("packages", parsed.value.failure.?.stage);
    try std.testing.expectEqual(@as(?u8, 1), parsed.value.failure.?.exit_code);
}

test "an unwritten result device is distinguishable from any answer" {
    const allocator = std.testing.allocator;
    const blank = try allocator.alloc(u8, sector_size);
    defer allocator.free(blank);
    @memset(blank, 0);
    try std.testing.expectError(error.BadFrameMagic, unframe(blank));

    const sealed = try seal(allocator, .{});
    defer allocator.free(sealed);
    try std.testing.expectError(error.TruncatedFrame, unframe(sealed[0 .. frame_header_size - 1]));

    // A frame whose payload was clipped by a short write must not parse as a
    // shorter but valid result.
    const payload_len = std.mem.readInt(u64, sealed[8..16], .little);
    try std.testing.expectError(
        error.TruncatedFrame,
        unframe(sealed[0 .. frame_header_size + payload_len - 1]),
    );

    const corrupted = try allocator.dupe(u8, sealed);
    defer allocator.free(corrupted);
    corrupted[frame_header_size] ^= 0xFF;
    try std.testing.expectError(error.FrameDigestMismatch, unframe(corrupted));
}

test "a malformed static network configuration is rejected" {
    try qemu_user_network.validate();

    const cases = [_]NetworkConfig{
        .{ .address = "10.0.2.256", .gateway = "10.0.2.2", .nameservers = &.{"10.0.2.3"} },
        .{ .address = "10.0.2", .gateway = "10.0.2.2", .nameservers = &.{"10.0.2.3"} },
        .{ .address = "10.0.2.15", .gateway = "gateway", .nameservers = &.{"10.0.2.3"} },
        .{ .address = "10.0.2.15", .gateway = "10.0.2.2", .nameservers = &.{} },
        .{ .address = "10.0.2.15", .gateway = "10.0.2.2", .nameservers = &.{"not-an-ip"} },
        .{
            .interface = "eth0; rm -rf /",
            .address = "10.0.2.15",
            .gateway = "10.0.2.2",
            .nameservers = &.{"10.0.2.3"},
        },
        .{
            .address = "10.0.2.15",
            .netmask = "255.255.255",
            .gateway = "10.0.2.2",
            .nameservers = &.{"10.0.2.3"},
        },
    };
    for (cases, 0..) |case, index| {
        std.testing.expectError(
            error.InvalidNetworkConfiguration,
            case.validate(),
        ) catch |err| {
            std.debug.print("network case {d} did not fail as expected\n", .{index});
            return err;
        };
    }
}

test "dotted quads parse strictly" {
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 2, 15 }, &parseIpv4("10.0.2.15").?);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &parseIpv4("0.0.0.0").?);
    try std.testing.expectEqualSlices(u8, &.{ 255, 255, 255, 255 }, &parseIpv4("255.255.255.255").?);

    // Leading zeroes read as octal in some resolvers and as decimal in others,
    // so a configuration that contains them is ambiguous rather than valid.
    try std.testing.expect(parseIpv4("010.0.2.15") == null);
    try std.testing.expect(parseIpv4("10.0.2.15.1") == null);
    try std.testing.expect(parseIpv4("10.0.2.") == null);
    try std.testing.expect(parseIpv4("10.0.2.-1") == null);
    try std.testing.expect(parseIpv4(" 10.0.2.15") == null);
    try std.testing.expect(parseIpv4("") == null);
}

test "a result the host would record verbatim is bounded before it is believed" {
    const valid = Result{
        .tools = &.{.{ .name = "tdnf", .version = "3.5.8", .command = &.{ "tdnf", "--version" } }},
        .installed_packages = &.{"strace-6.6-1.azl3.x86_64"},
        .imported_trust_keys = &.{"gpg-pubkey-3135ce90-5e6d0f1e"},
        .initramfs = .{
            // A release that failed the rule is reported under the name that
            // failed it, which is the one thing here that is deliberately not
            // held to `validKernelRelease`.
            .skipped_kernel_releases = &.{
                .{ .name = "6.12.0 spaced", .reason = .invalid_release_name },
            },
            .images = &.{.{
                .kernel_release = "6.12.0-1.azl",
                .image_path = "/boot/initramfs-6.12.0-1.azl.img",
                .size = 4096,
                .sha256 = @splat(0xab),
            }},
        },
    };
    try valid.validate();

    const failed = Result{ .failure = .{ .stage = "packages", .exit_code = 1 } };
    try failed.validate();

    const cases = [_]struct { name: []const u8, result: Result, expected: Error }{
        .{
            .name = "an unknown version means the guest and host disagree on the contract",
            .result = .{ .version = result_version + 1 },
            .expected = error.UnsupportedVersion,
        },
        .{
            .name = "a nameless tool records nothing",
            .result = .{ .tools = &.{.{ .name = "", .version = "1", .command = &.{"x"} }} },
            .expected = error.InvalidToolRecord,
        },
        .{
            .name = "a tool with no command cannot be reproduced",
            .result = .{ .tools = &.{.{ .name = "tdnf", .version = "1", .command = &.{} }} },
            .expected = error.InvalidToolRecord,
        },
        .{
            .name = "an empty package name is not a package",
            .result = .{ .installed_packages = &.{""} },
            .expected = error.InvalidPackageName,
        },
        .{
            .name = "a failure that names no stage explains nothing",
            .result = .{ .failure = .{ .stage = "" } },
            .expected = error.InvalidFailureRecord,
        },
        .{
            // The host publishes these verbatim, so a guest that put a package
            // -- or anything else -- in the trust list would have the host
            // state as trust something rpm never derived a key from.
            .name = "trust is only trust if rpm named it as such",
            .result = .{ .imported_trust_keys = &.{"strace-6.6-1.azl3.x86_64"} },
            .expected = error.InvalidTrustKeyRecord,
        },
        .{
            .name = "a regenerated image must name the release it was built for",
            .result = .{ .initramfs = .{ .images = &.{.{
                .kernel_release = "6.12.0 spaced",
                .image_path = "/boot/initramfs.img",
                .size = 1,
                .sha256 = @splat(0),
            }} } },
            .expected = error.InvalidInitramfsRecord,
        },
        .{
            .name = "a skipped release is bounded even though it failed the release rule",
            .result = .{ .initramfs = .{ .skipped_kernel_releases = &.{.{
                .name = "",
                .reason = .invalid_release_name,
            }} } },
            .expected = error.InvalidInitramfsRecord,
        },
    };
    for (cases) |case| {
        std.testing.expectError(case.expected, case.result.validate()) catch |err| {
            std.debug.print("case: {s}\n", .{case.name});
            return err;
        };
    }
}

test "the guest places rendered files only where it recognises the destination" {
    const base = Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .offline,
    };

    var accepted = base;
    accepted.kernel_module_files = &.{
        .{ .path = "etc/modules-load.d/zvmi.conf", .contents = "overlay\n" },
        .{ .path = "etc/modprobe.d/zvmi-blacklist.conf", .contents = "blacklist floppy\n" },
    };
    try accepted.validate();

    // A control document must not be usable as a general-purpose file writer,
    // and a host that starts rendering somewhere new has to fail here rather
    // than produce an image that differs from the rebuild backend's.
    var unknown = base;
    unknown.kernel_module_files = &.{
        .{ .path = "etc/sudoers.d/zvmi.conf", .contents = "ALL ALL=(ALL) NOPASSWD: ALL\n" },
    };
    try std.testing.expectError(error.UnknownTargetFile, unknown.validate());

    var traversal = base;
    traversal.kernel_module_files = &.{
        .{ .path = "../etc/modules-load.d/zvmi.conf", .contents = "overlay\n" },
    };
    try std.testing.expectError(error.UnknownTargetFile, traversal.validate());

    // Two writes to one destination make the result depend on which came
    // last, which is not something a document should be able to express.
    var duplicated = base;
    duplicated.kernel_module_files = &.{
        .{ .path = "etc/modules-load.d/zvmi.conf", .contents = "overlay\n" },
        .{ .path = "etc/modules-load.d/zvmi.conf", .contents = "loop\n" },
    };
    try std.testing.expectError(error.DuplicateTargetFile, duplicated.validate());
}

test "rendered files survive the control round trip" {
    const allocator = std.testing.allocator;
    var control = Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .offline,
    };
    control.kernel_module_files = &.{
        .{ .path = "etc/modprobe.d/zvmi-options.conf", .contents = "options i915 enable_guc=2\n" },
    };

    const bytes = try std.json.Stringify.valueAlloc(allocator, control, .{});
    defer allocator.free(bytes);
    const parsed = try parseControl(allocator, bytes);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.value.kernel_module_files.len);
    try std.testing.expectEqualStrings(
        "etc/modprobe.d/zvmi-options.conf",
        parsed.value.kernel_module_files[0].path,
    );
    try std.testing.expectEqualStrings(
        "options i915 enable_guc=2\n",
        parsed.value.kernel_module_files[0].contents,
    );
}

test "a credential is rendered where the package manager reads it, not where it is logged" {
    const allocator = std.testing.allocator;
    const bare = try renderRepositoryBody(
        allocator,
        "base",
        &.{"https://packages.example.invalid"},
        null,
    );
    defer allocator.free(bare);
    try std.testing.expectEqualStrings(
        "[base]\nname=zvmi-base\nenabled=1\ngpgcheck=1\n" ++
            "baseurl=https://packages.example.invalid\n",
        bare,
    );

    // The credential lines come last, so a repository file is the same
    // document with or without one and diffing the two shows only the addition.
    const authenticated = try renderRepositoryBody(
        allocator,
        "base",
        &.{ "https://a.example.invalid", "https://b.example.invalid" },
        .{ .username = "builder", .password = "s3cr3t" },
    );
    defer allocator.free(authenticated);
    try std.testing.expectEqualStrings(
        "[base]\nname=zvmi-base\nenabled=1\ngpgcheck=1\n" ++
            "baseurl=https://a.example.invalid https://b.example.invalid\n" ++
            "username=builder\npassword=s3cr3t\n",
        authenticated,
    );

    // Adding a credential adds lines and changes none, so a repository that
    // starts needing authentication keeps resolving to the same packages.
    const same_urls = try renderRepositoryBody(
        allocator,
        "base",
        &.{"https://packages.example.invalid"},
        .{ .username = "builder", .password = "s3cr3t" },
    );
    defer allocator.free(same_urls);
    try std.testing.expect(std.mem.startsWith(u8, same_urls, bare));
    try std.testing.expectEqualStrings(
        "username=builder\npassword=s3cr3t\n",
        same_urls[bare.len..],
    );
}

test "only a URL's authority can carry a credential" {
    // The refusal has to read the authority and stop there. `@` is an ordinary
    // path character -- a repository laid out per-account, or a mirror using a
    // package's own name, has one and is carrying nothing.
    try std.testing.expect(hasUserinfo("https://builder:hunter2@packages.invalid/base"));
    try std.testing.expect(hasUserinfo("https://token@packages.invalid/base"));
    try std.testing.expect(hasUserinfo("https://builder:hunter2@packages.invalid"));
    try std.testing.expect(hasUserinfo("https://builder:p@ss@packages.invalid/base"));
    try std.testing.expect(!hasUserinfo("https://packages.invalid/base/user@example/rpms"));
    try std.testing.expect(!hasUserinfo("https://packages.invalid/base?q=user@example"));
    try std.testing.expect(!hasUserinfo("https://packages.invalid/base#user@example"));
    try std.testing.expect(!hasUserinfo("https://packages.invalid/base"));
    try std.testing.expect(!hasUserinfo("not-a-url"));

    // And it has to be part of the shared predicate rather than a separate
    // check some callers remember, since every caller writes the URL somewhere
    // that keeps it.
    try std.testing.expect(!validRepositoryUrl("https://builder:hunter2@packages.invalid/base"));
    try std.testing.expect(validRepositoryUrl("https://packages.invalid/base/user@example/rpms"));
}

test "credential material survives the device and comes back byte for byte" {
    const allocator = std.testing.allocator;

    const passwords = [_][]const u8{ "first-secret", "", "a-much-longer-second-secret" };
    const sealed = try sealCredentials(allocator, &passwords);
    defer allocator.free(sealed);

    const credentials = try parseCredentials(sealed);
    try std.testing.expectEqual(@as(u32, passwords.len), credentials.count);
    for (passwords, 0..) |expected, index| {
        try std.testing.expectEqualStrings(
            expected,
            try credentials.password(@intCast(index)),
        );
    }
    // An index the document never named is a document that disagrees with the
    // device, which the guest must refuse rather than answer with whatever
    // bytes happen to follow.
    try std.testing.expectError(
        error.CredentialIndexOutOfRange,
        credentials.password(passwords.len),
    );

    // A device that was never written is not an empty credential set: the
    // guest has to be able to tell "no material arrived" from "no material was
    // asked for", because only the first is a failure.
    const blank = [_]u8{0} ** 128;
    try std.testing.expectError(error.BadFrameMagic, parseCredentials(&blank));
}

test "the credential device and the result device cannot be read as each other" {
    const allocator = std.testing.allocator;

    // Both channels are length-prefixed and digested the same way, and both
    // are raw block devices the guest opens by path. The only thing keeping a
    // misattached drive from being parsed as the other channel's payload is
    // the magic, so that separation is asserted rather than assumed.
    try std.testing.expect(!std.mem.eql(u8, credential_magic, frame_magic));

    const sealed = try sealCredentials(allocator, &.{"s3cr3t"});
    defer allocator.free(sealed);
    try std.testing.expectError(error.BadFrameMagic, unframe(sealed));

    const result = try frame(allocator, "{}");
    defer allocator.free(result);
    try std.testing.expectError(error.BadFrameMagic, parseCredentials(result));

    // Corruption anywhere in the payload is caught, because the digest covers
    // it. Checked on the credential channel specifically: material the guest
    // wrote into a repository file after silently accepting a flipped bit
    // would authenticate against nothing and look like a wrong password.
    const damaged = try allocator.dupe(u8, sealed);
    defer allocator.free(damaged);
    damaged[frame_header_size] ^= 0x01;
    try std.testing.expectError(error.FrameDigestMismatch, parseCredentials(damaged));
}

test "the sealed blob refuses more than the guest agreed to read" {
    const allocator = std.testing.allocator;

    const too_many = [_][]const u8{"x"} ** (max_credentials + 1);
    try std.testing.expectError(
        error.TooManyCredentials,
        sealCredentials(allocator, &too_many),
    );

    const oversized = [_][]const u8{&([_]u8{'x'} ** (max_credential_material_bytes + 1))};
    try std.testing.expectError(
        error.CredentialMaterialTooLarge,
        sealCredentials(allocator, &oversized),
    );
}
