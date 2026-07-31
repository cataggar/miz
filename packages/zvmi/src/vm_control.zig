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

pub const control_version: u32 = 1;
pub const result_version: u32 = 1;

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

pub const Error = error{
    UnsupportedVersion,
    InvalidDevicePath,
    InvalidRepositoryId,
    InvalidPackageName,
    InvalidKernelRelease,
    InvalidRepositoryUrl,
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
    InvalidFailureRecord,
    InvalidModuleMember,
    TooManyModules,
    UnknownTargetFile,
    DuplicateTargetFile,
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
pub fn isUserNetAddress(text: []const u8) bool {
    const octets = parseIpv4(text) orelse return false;
    const resolver = parseIpv4(qemu_user_network.nameservers[0]).?;
    return octets[0] == resolver[0] and
        octets[1] == resolver[1] and
        octets[2] == resolver[2];
}

pub const Repository = struct {
    id: []const u8,
    urls: []const []const u8,
    /// Keyring material, base64-encoded. Trust material may legitimately be a
    /// binary keyring rather than an ASCII armour, and JSON strings must be
    /// valid UTF-8, so it cannot travel raw.
    trust_base64: []const []const u8 = &.{},
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
pub const kernel_module_config_paths = [_][]const u8{
    "etc/modules-load.d/zvmi.conf",
    "etc/modprobe.d/zvmi-blacklist.conf",
    "etc/modprobe.d/zvmi-options.conf",
};

pub const Control = struct {
    version: u32 = control_version,
    /// Block device holding the target root filesystem, e.g. `/dev/vda2`.
    /// The guest kernel scans the partition table, so the host passes the
    /// partition device rather than an offset the guest would have to honour.
    root_device: []const u8,
    /// Block device the sealed result is written to, e.g. `/dev/vdb`.
    result_device: []const u8,
    network: Network,
    repositories: []const Repository = &.{},
    actions: []const Action = &.{},
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

pub const Tool = struct {
    name: []const u8,
    version: []const u8,
    command: []const []const u8,
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

    /// The result is recorded in the host's provenance, so its shape is
    /// bounded here for the same reason the control document's is: a document
    /// that arrives from the other side of a trust boundary is checked before
    /// it is believed, even when this build wrote the agent that sent it.
    pub fn validate(self: Result) Error!void {
        if (self.version != result_version) return error.UnsupportedVersion;
        if (self.tools.len > max_result_tools) return error.ResultTooLarge;
        for (self.tools) |tool| {
            if (tool.name.len == 0 or tool.name.len > 128) return error.InvalidToolRecord;
            if (tool.version.len > 1024) return error.InvalidToolRecord;
            if (tool.command.len == 0 or tool.command.len > 64) {
                return error.InvalidToolRecord;
            }
        }
        if (self.installed_packages.len > max_result_packages) return error.ResultTooLarge;
        for (self.installed_packages) |name| {
            if (name.len == 0 or name.len > 512) return error.InvalidPackageName;
        }
        if (self.failure) |failure| {
            if (failure.stage.len == 0 or failure.stage.len > 64) {
                return error.InvalidFailureRecord;
            }
            if (failure.detail.len > 4096) return error.InvalidFailureRecord;
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

/// Mirrors `customize.validUnsafeKernelRelease`. The release becomes both a
/// dracut argument and a `/boot/initramfs-<release>.img` path.
pub fn validKernelRelease(kernel: []const u8) bool {
    if (kernel.len == 0 or kernel.len > 128 or !std.ascii.isAlphanumeric(kernel[0])) return false;
    for (kernel[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and byte != '_' and byte != '+' and byte != '-' and byte != '~')
        {
            return false;
        }
    }
    return true;
}

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

fn validRepositoryUrl(url: []const u8) bool {
    if (url.len == 0 or url.len > 2048) return false;
    // The url is written into a repository file whose grammar is line-based
    // and whose baseurl values are space-separated.
    for (url) |byte| {
        if (byte <= 0x20 or byte == 0x7F) return false;
    }
    return std.mem.startsWith(u8, url, "https://") or
        std.mem.startsWith(u8, url, "http://") or
        std.mem.startsWith(u8, url, "file://");
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
    if (payload.len > max_result_bytes) return error.FrameTooLarge;
    const total = std.mem.alignForward(usize, frame_header_size + payload.len, sector_size);
    const buffer = try allocator.alloc(u8, total);
    errdefer allocator.free(buffer);
    @memset(buffer, 0);

    @memcpy(buffer[0..frame_magic.len], frame_magic);
    std.mem.writeInt(u64, buffer[8..16], payload.len, .little);
    std.crypto.hash.sha2.Sha256.hash(payload, buffer[16..48], .{});
    @memcpy(buffer[frame_header_size..][0..payload.len], payload);
    return buffer;
}

/// Returns the payload bytes of a framed result, borrowed from `bytes`.
pub fn unframe(bytes: []const u8) Error![]const u8 {
    if (bytes.len < frame_header_size) return error.TruncatedFrame;
    if (!std.mem.eql(u8, bytes[0..frame_magic.len], frame_magic)) return error.BadFrameMagic;
    const length = std.mem.readInt(u64, bytes[8..16], .little);
    if (length > max_result_bytes) return error.FrameTooLarge;
    if (frame_header_size + length > bytes.len) return error.TruncatedFrame;
    const payload = bytes[frame_header_size..][0..@intCast(length)];

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, bytes[16..48].*)) {
        return error.FrameDigestMismatch;
    }
    return payload;
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
        \\{"version":2,"root_device":"/dev/vda2","result_device":"/dev/vdb",
        \\"network":{"offline":{}},"actions":[{"reinstall_everything":["x"]}]}
        ,
    ));

    // A document of this version carrying an unknown tag is still a parse
    // failure: the version claimed it would be understood, and it was not.
    try std.testing.expectError(error.UnknownField, parseControl(
        allocator,
        \\{"version":1,"root_device":"/dev/vda2","result_device":"/dev/vdb",
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
        .initramfs = .{ .regenerate = .{ .kernels = &.{"6.12.0-1.azl"} } },
        .modules = &.{ "zvmi-module-00-virtio_pci.ko", "zvmi-module-01-ext4.ko" },
    };
    try control.validate();

    const json = try std.json.Stringify.valueAlloc(allocator, control, .{});
    defer allocator.free(json);

    const parsed = try parseControl(allocator, json);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("/dev/vda2", parsed.value.root_device);
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
            control.version = 2;
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
    };

    for (cases, 0..) |case, index| {
        std.testing.expectError(case.expected, case.control.validate()) catch |err| {
            std.debug.print("control rejection case {d} did not fail as expected\n", .{index});
            return err;
        };
    }
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
