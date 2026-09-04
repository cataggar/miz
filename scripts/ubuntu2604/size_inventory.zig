//! Reproducible size attribution for the Ubuntu 26.04 images.
//!
//! Issue #677 asks for one question to be answerable before the package
//! closure is touched: where does every byte of a published image come from?
//! This module is the answer, and it is deliberately a *measurement* rather
//! than a gate. It records installed and allocated bytes per package, the
//! exact closure and its digest, the unowned payload split into an explicit
//! allowlist and everything else, top-level root usage, the boot inputs, the
//! filesystem's own block and inode accounting, and the published artifact's
//! size. Budgets and refusals come later in the plan; a number nobody has
//! measured is not a budget.
//!
//! The document is *phase aware* because the facts arrive at different times.
//! The root tree is measurable while it is still a host directory; the ext4
//! and ESP accounting only exists once the image is finalized; the compressed
//! artifact only exists after that; and first-boot growth only exists after
//! something has booted. Each phase is appended by the stage that can actually
//! observe it, `phases_present` names exactly the phases a document carries,
//! and a phase that has not happened is absent rather than zero -- a zero would
//! be indistinguishable from a measurement, and every consumer would have to
//! guess which one it was holding.
//!
//! Validation is strict in both directions: a document that declares a phase
//! must carry it, a document that carries a phase must declare it, and the
//! aggregates must equal the parts they are aggregates of. A report that does
//! not add up is a broken measurement, and reporting it as a size is worse
//! than reporting nothing.
//!
//! The module depends on `std` alone so that the builder, the release tool,
//! and the benchmark can all speak the same schema without any of them
//! acquiring the image library as a dependency.

const std = @import("std");
const builtin = @import("builtin");

const contract = @import("../release/contract.zig");
const json_document = @import("../release/json_document.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

pub const Diagnostic = contract.Diagnostic;

/// The release tooling spells every rejection as one operator-facing line, so
/// this module uses the same error set and diagnostic as `support.zig` and can
/// be called straight from the provenance validator.
pub const Error = error{ Failed, OutOfMemory };

pub fn fail(
    diagnostic: *Diagnostic,
    comptime fmt: []const u8,
    args: anytype,
) Error {
    diagnostic.set(fmt, args);
    return error.Failed;
}

pub const schema_version: i64 = 1;
pub const document_type = "miz-ubuntu2604-size-inventory";
pub const comparison_type = "miz-ubuntu2604-size-inventory-comparison";
pub const release_id = "26.04";
pub const document_max_bytes: u64 = 16 * 1024 * 1024;

/// Where the shipped exact closure lives inside the root being measured.
pub const package_lock_path = "/var/lib/miz/ubuntu2604-package-lock.tsv";
/// dpkg's per-package file lists, the only ownership record a finished root
/// carries.
pub const dpkg_info_path = "/var/lib/dpkg/info";

/// Chronological order of the stages that can observe a measurement. The order
/// is part of the contract: a phase may only be appended after every earlier
/// phase it follows is already present, so a document can never claim to know
/// something before the stage that measures it has run.
pub const Phase = enum {
    /// The finished root tree, still a host directory: packages, unowned
    /// files, top-level usage, and boot inputs.
    root_build,
    /// The finalized image: ext4 block and inode accounting before first boot,
    /// the signed UKI, and ESP occupancy.
    image_build,
    /// The published artifact: compressed QCOW2 length and host allocation.
    publication,
    /// The same ext4 accounting after the image has booted once, which is what
    /// makes measured first-boot growth possible.
    first_boot,

    pub fn key(self: Phase) []const u8 {
        return @tagName(self);
    }

    pub fn parse(text: []const u8) ?Phase {
        inline for (@typeInfo(Phase).@"enum".fields) |field| {
            if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }
};

pub const phase_order = [_]Phase{ .root_build, .image_build, .publication, .first_boot };

pub const Architecture = enum { x86_64, aarch64 };
pub const Flavor = enum { full, core, baremetal };

pub const Identity = struct {
    architecture: Architecture,
    flavor: Flavor,
};

// ---------------------------------------------------------------------------
// Small JSON construction helpers.
//
// `std.json.ObjectMap` is unmanaged and `std.json.Array` is managed, exactly as
// in `support.zig`; these mirror that module's `Builder` so documents built
// here look like every other document the release tooling writes.
// ---------------------------------------------------------------------------

const Builder = struct {
    arena: Allocator,

    fn object(_: Builder) std.json.ObjectMap {
        return .empty;
    }

    fn array(self: Builder) std.json.Array {
        return .init(self.arena);
    }

    fn string(self: Builder, text: []const u8) Error!std.json.Value {
        return .{ .string = try self.arena.dupe(u8, text) };
    }

    fn put(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        value: std.json.Value,
    ) Error!void {
        try map.put(self.arena, try self.arena.dupe(u8, key), value);
    }

    fn putString(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        text: []const u8,
    ) Error!void {
        try self.put(map, key, try self.string(text));
    }

    fn putCount(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        number: u64,
    ) Error!void {
        try self.put(map, key, .{ .integer = castCount(number) });
    }
};

/// Sizes are counted in bytes and never approach `i64`'s range, but a cast
/// that silently wrapped would turn an impossible measurement into a plausible
/// one, so it saturates at the representable maximum instead.
fn castCount(number: u64) i64 {
    return std.math.cast(i64, number) orelse std.math.maxInt(i64);
}

fn integerOf(value: ?std.json.Value) ?i64 {
    const entry = value orelse return null;
    return switch (entry) {
        .integer => |number| number,
        else => null,
    };
}

fn countOf(value: ?std.json.Value) ?u64 {
    const number = integerOf(value) orelse return null;
    if (number < 0) return null;
    return @intCast(number);
}

fn stringOf(value: ?std.json.Value) ?[]const u8 {
    const entry = value orelse return null;
    return switch (entry) {
        .string => |text| text,
        else => null,
    };
}

fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const entry = value orelse return null;
    return switch (entry) {
        .object => |map| map,
        else => null,
    };
}

fn arrayOf(value: ?std.json.Value) ?[]const std.json.Value {
    const entry = value orelse return null;
    return switch (entry) {
        .array => |items| items.items,
        else => null,
    };
}

fn hasExactFields(map: std.json.ObjectMap, expected: []const []const u8) bool {
    if (map.count() != expected.len) return false;
    for (expected) |key| {
        if (!map.contains(key)) return false;
    }
    return true;
}

fn isSha256(text: []const u8) bool {
    if (text.len != 64) return false;
    for (text) |byte| {
        switch (byte) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

fn hexDigest(bytes: []const u8) [64]u8 {
    var raw: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &raw, .{});
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&raw}) catch unreachable;
    return hex;
}

/// Component-wise path ordering, matching `support.lessThanPath`: emitted path
/// lists are part of the document, so their order is part of the contract.
pub fn lessThanPath(_: void, left: []const u8, right: []const u8) bool {
    var left_parts = std.mem.splitScalar(u8, left, '/');
    var right_parts = std.mem.splitScalar(u8, right, '/');
    while (true) {
        const left_part = left_parts.next() orelse return right_parts.next() != null;
        const right_part = right_parts.next() orelse return false;
        if (!std.mem.eql(u8, left_part, right_part)) {
            return std.mem.lessThan(u8, left_part, right_part);
        }
    }
}

// ---------------------------------------------------------------------------
// Report: the document under construction.
// ---------------------------------------------------------------------------

/// A size-inventory document being assembled across build stages.
///
/// The arena owns every string and section the document refers to, so a
/// section measured early in a build survives until the document is written at
/// the end of it. Nothing here retains an `Allocator` derived from the arena:
/// the value is returned by value, and a captured allocator would point at the
/// address `init` had rather than the one the caller keeps.
pub const Report = struct {
    arena: std.heap.ArenaAllocator,
    identity: Identity,
    fields: std.json.ObjectMap,
    present: [phase_order.len]bool = @splat(false),

    pub fn init(gpa: Allocator, identity: Identity) Error!Report {
        var report: Report = .{
            .arena = .init(gpa),
            .identity = identity,
            .fields = .empty,
        };
        const builder: Builder = .{ .arena = report.arena.allocator() };
        try builder.put(&report.fields, "schema", .{ .integer = schema_version });
        try builder.putString(&report.fields, "type", document_type);
        try builder.putString(&report.fields, "release", release_id);
        try builder.putString(
            &report.fields,
            "architecture",
            @tagName(identity.architecture),
        );
        try builder.putString(&report.fields, "flavor", @tagName(identity.flavor));
        return report;
    }

    pub fn deinit(self: *Report) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// Allocator every section handed to `addPhase` must be built from.
    pub fn allocator(self: *Report) Allocator {
        return self.arena.allocator();
    }

    pub fn has(self: *const Report, phase: Phase) bool {
        return self.present[@intFromEnum(phase)];
    }

    /// Records `section` as `phase`. Refuses a repeat and refuses a phase that
    /// arrives before a phase it must follow, which is what keeps a document's
    /// stage ordering honest.
    pub fn addPhase(
        self: *Report,
        phase: Phase,
        section: std.json.Value,
        diagnostic: *Diagnostic,
    ) Error!void {
        if (self.has(phase)) return fail(
            diagnostic,
            "size inventory phase {s} is already recorded",
            .{phase.key()},
        );
        for (phase_order) |candidate| {
            if (candidate == phase) break;
            if (!self.has(candidate)) return fail(
                diagnostic,
                "size inventory phase {s} cannot precede {s}",
                .{ phase.key(), candidate.key() },
            );
        }
        const builder: Builder = .{ .arena = self.arena.allocator() };
        try builder.put(&self.fields, phase.key(), section);
        self.present[@intFromEnum(phase)] = true;
    }

    /// The document as a JSON value. `phases_present` is rebuilt here so it
    /// always names exactly the sections the document carries, in stage order.
    pub fn value(self: *Report) Error!std.json.Value {
        const builder: Builder = .{ .arena = self.arena.allocator() };
        var phases = builder.array();
        for (phase_order) |phase| {
            if (self.has(phase)) try phases.append(try builder.string(phase.key()));
        }
        try builder.put(&self.fields, "phases_present", .{ .array = phases });
        return .{ .object = self.fields };
    }

    pub fn toJsonAlloc(self: *Report, gpa: Allocator) Error![]u8 {
        return json_document.canonicalAlloc(gpa, try self.value(), .document) catch
            error.OutOfMemory;
    }

    pub fn write(
        self: *Report,
        gpa: Allocator,
        io: Io,
        path: []const u8,
        diagnostic: *Diagnostic,
    ) Error!void {
        json_document.writeDocument(gpa, io, path, try self.value()) catch |err|
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return fail(
                    diagnostic,
                    "cannot write size inventory {s}: {s}",
                    .{ path, @errorName(err) },
                ),
            };
    }
};

// ---------------------------------------------------------------------------
// Root-tree measurement.
// ---------------------------------------------------------------------------

/// Logical and physically allocated bytes for one path.
///
/// Allocation is what a filesystem actually spends, and it is the number that
/// decides whether an image fits; logical size is what a package believes it
/// installed. Both are recorded because the difference between them is where
/// sparse files, tail packing, and per-file rounding hide. Linux reports
/// allocation in 512-byte units; hosts that cannot answer report nothing, and
/// the walk records the path as unreadable rather than inventing a size.
pub const Usage = struct {
    logical_bytes: u64 = 0,
    allocated_bytes: u64 = 0,

    fn add(self: *Usage, other: Usage) void {
        self.logical_bytes +|= other.logical_bytes;
        self.allocated_bytes +|= other.allocated_bytes;
    }
};

/// `statx(AT_SYMLINK_NOFOLLOW)`, mirroring `miz.free_space.fileUsage`. It is
/// repeated here rather than imported so this module keeps depending on `std`
/// alone; the release tool validates these documents and must not need the
/// image library to do it.
fn pathUsage(path: [:0]const u8) ?Usage {
    if (builtin.os.tag != .linux) return null;
    var info: std.os.linux.Statx = undefined;
    const result = std.os.linux.statx(
        std.os.linux.AT.FDCWD,
        path.ptr,
        std.os.linux.AT.SYMLINK_NOFOLLOW | std.os.linux.AT.STATX_DONT_SYNC,
        std.os.linux.STATX.BASIC_STATS,
        &info,
    );
    if (@as(isize, @bitCast(result)) < 0 or !info.mask.SIZE or !info.mask.BLOCKS) {
        return null;
    }
    return .{
        .logical_bytes = info.size,
        .allocated_bytes = std.math.mul(u64, info.blocks, 512) catch return null,
    };
}

/// One rule in the explicit unowned-file allowlist.
///
/// Every file in a finished root that no package claims is either something
/// this image put there on purpose -- the injected `mizinit` and `azagent`, the
/// provenance it carries, the generated initramfs and module index -- or state
/// a maintainer script wrote. Naming each one with the reason it is allowed is
/// what makes the remainder reviewable, and the remainder is what later steps
/// of #677 drive to zero.
pub const UnownedRule = struct {
    /// `path` matches exactly, `path/**` matches that directory and everything
    /// beneath it, and `prefix*` matches any path with that prefix.
    pattern: []const u8,
    reason: []const u8,

    fn matches(self: UnownedRule, path: []const u8) bool {
        if (std.mem.endsWith(u8, self.pattern, "/**")) {
            const subtree = self.pattern[0 .. self.pattern.len - 2];
            const directory = self.pattern[0 .. self.pattern.len - 3];
            // The directory a subtree rule names is part of the subtree it
            // names. A root's own `/var/lib/miz` is exactly as attributable as
            // the provenance inside it, and a rule that covered the contents
            // but not the container would leave a directory nobody can explain.
            return std.mem.eql(u8, directory, path) or
                std.mem.startsWith(u8, path, subtree);
        }
        if (std.mem.endsWith(u8, self.pattern, "*")) {
            return std.mem.startsWith(u8, path, self.pattern[0 .. self.pattern.len - 1]);
        }
        return std.mem.eql(u8, self.pattern, path);
    }
};

/// Unowned payload every flavor is allowed to carry.
pub const shared_unowned_rules = [_]UnownedRule{
    .{ .pattern = "/etc/.pwd.lock", .reason = "dpkg account-database lock" },
    .{ .pattern = "/etc/alternatives/**", .reason = "update-alternatives symlink farm" },
    .{ .pattern = "/etc/group*", .reason = "account database written by maintainer scripts" },
    .{ .pattern = "/etc/gshadow*", .reason = "account database written by maintainer scripts" },
    .{ .pattern = "/etc/hostname", .reason = "generalized host identity" },
    .{ .pattern = "/etc/hosts", .reason = "generalized host identity" },
    .{ .pattern = "/etc/ld.so.cache", .reason = "ldconfig-generated linker cache" },
    .{ .pattern = "/etc/machine-id", .reason = "cleared machine identity" },
    .{ .pattern = "/etc/pam.d/common-*", .reason = "pam-auth-update generated PAM stacks" },
    .{ .pattern = "/etc/passwd*", .reason = "account database written by maintainer scripts" },
    .{ .pattern = "/etc/resolv.conf", .reason = "runtime resolver state" },
    .{ .pattern = "/etc/shadow*", .reason = "account database written by maintainer scripts" },
    .{ .pattern = "/etc/ssh/**", .reason = "sshd policy and per-machine host keys" },
    .{ .pattern = "/etc/ssl/certs/**", .reason = "ca-certificates trust store" },
    .{ .pattern = "/etc/subgid*", .reason = "account database written by maintainer scripts" },
    .{ .pattern = "/etc/subuid*", .reason = "account database written by maintainer scripts" },
    .{ .pattern = "/etc/waagent.conf", .reason = "Azure agent configuration" },
    .{ .pattern = "/boot/initrd.img*", .reason = "initramfs generated for the installed kernel; for the fresh roots, by the discarded build stage of #677 step 4" },
    .{ .pattern = "/dev/**", .reason = "runtime device tree mount point" },
    .{ .pattern = "/home/**", .reason = "provisioned administrator home" },
    .{ .pattern = "/media/**", .reason = "mount point" },
    .{ .pattern = "/mnt/**", .reason = "mount point" },
    .{ .pattern = "/opt/**", .reason = "mount point" },
    .{ .pattern = "/proc/**", .reason = "runtime kernel filesystem mount point" },
    .{ .pattern = "/root/**", .reason = "root account state" },
    .{ .pattern = "/run/**", .reason = "runtime state mount point" },
    .{ .pattern = "/srv/**", .reason = "mount point" },
    .{ .pattern = "/sys/**", .reason = "runtime kernel filesystem mount point" },
    .{ .pattern = "/tmp/**", .reason = "temporary state" },
    .{ .pattern = "/usr/lib/modules/**", .reason = "depmod-generated module index" },
    .{ .pattern = "/usr/share/info/dir*", .reason = "install-info generated index" },
    .{ .pattern = "/var/cache/**", .reason = "package and tooling caches" },
    .{ .pattern = "/var/lib/dbus/**", .reason = "cleared D-Bus machine identity" },
    .{ .pattern = "/var/lib/dpkg/**", .reason = "package database and provenance" },
    .{ .pattern = "/var/lib/misc/**", .reason = "maintainer-script bookkeeping" },
    .{ .pattern = "/var/lib/miz/**", .reason = "miz provenance and exact package lock" },
    .{ .pattern = "/var/lib/pam/**", .reason = "pam-auth-update profile bookkeeping" },
    .{ .pattern = "/var/lib/systemd/**", .reason = "cleared systemd state" },
    .{ .pattern = "/var/lib/ucf/**", .reason = "configuration-file bookkeeping" },
    .{ .pattern = "/var/log/**", .reason = "cleared log state" },
    .{ .pattern = "/var/tmp/**", .reason = "temporary state" },
};

/// Unowned payload only the fresh-root flavors carry: the injected guest.
///
/// Since #677 step 4 that no longer includes anything belonging to initramfs
/// generation. The generated image itself is covered by the shared
/// `/boot/initrd.img*` rule; its inputs and the generator's bookkeeping live in
/// the staging root the guest never inherits.
pub const fresh_root_unowned_rules = [_]UnownedRule{
    .{ .pattern = "/usr/sbin/mizinit", .reason = "injected miz PID 1" },
    .{ .pattern = "/usr/sbin/azagent", .reason = "injected Azure provisioning agent" },
    .{ .pattern = "/usr/sbin/init", .reason = "mizinit init symlink" },
    .{ .pattern = "/usr/sbin/poweroff", .reason = "mizinit poweroff symlink" },
    .{ .pattern = "/usr/sbin/reboot", .reason = "mizinit reboot symlink" },
    .{ .pattern = "/usr/sbin/shutdown", .reason = "mizinit shutdown symlink" },
    .{ .pattern = "/usr/local/**", .reason = "injected local access provider" },
};

/// Unowned payload only the full flavor carries: cloud-init, netplan, and the
/// systemd unit overrides the Azure contract needs.
pub const full_unowned_rules = [_]UnownedRule{
    .{ .pattern = "/etc/cloud/**", .reason = "cloud-init datasource configuration" },
    // Only `full` still installs the initramfs generator: it inherits
    // Canonical's server root. Issue #677 step 4 moved the fresh roots'
    // generation into a staging root, so neither the generator's bookkeeping
    // nor its configuration is allowlisted for them any more -- if either
    // reappears in a core or bare-metal image, the build fails.
    .{ .pattern = "/var/lib/initramfs-tools/**", .reason = "initramfs generation bookkeeping" },
    .{ .pattern = "/etc/netplan/**", .reason = "network configuration" },
    .{ .pattern = "/etc/systemd/system/**", .reason = "systemd unit overrides" },
    .{ .pattern = "/var/lib/cloud/**", .reason = "cleared cloud-init state" },
    .{ .pattern = "/var/lib/waagent/**", .reason = "cleared Azure agent state" },
    .{ .pattern = "/var/lib/dhcp/**", .reason = "cleared DHCP lease state" },
    .{ .pattern = "/var/lib/NetworkManager/**", .reason = "cleared network state" },
};

/// The allowlist a flavor is measured against, as an owned slice.
pub fn unownedRulesAlloc(allocator: Allocator, flavor: Flavor) Error![]UnownedRule {
    const extra: []const UnownedRule = switch (flavor) {
        .full => &full_unowned_rules,
        .core, .baremetal => &fresh_root_unowned_rules,
    };
    const rules = try allocator.alloc(UnownedRule, shared_unowned_rules.len + extra.len);
    @memcpy(rules[0..shared_unowned_rules.len], &shared_unowned_rules);
    @memcpy(rules[shared_unowned_rules.len..], extra);
    std.mem.sort(UnownedRule, rules, {}, struct {
        fn lessThan(_: void, left: UnownedRule, right: UnownedRule) bool {
            return lessThanPath({}, left.pattern, right.pattern);
        }
    }.lessThan);
    return rules;
}

pub const RootMeasurementOptions = struct {
    /// Host path of the finished root tree.
    root_path: []const u8,
    flavor: Flavor,
    /// Kernel release whose image, module tree, and initramfs are attributed.
    kernel_release: []const u8,
    /// Paths that exist in the finished image but not in the host tree it was
    /// imported from, measured by the caller that placed them there.
    ///
    /// The fresh-root flavors write their guest into the ext4 filesystem
    /// directly, so a walk of the host tree alone would report an image whose
    /// PID 1 weighs nothing. These entries are attributed by exactly the same
    /// ownership and allowlist rules as everything the walk finds.
    injected: []const InjectedEntry = &.{},
    /// Upper bound on individually named unexpected unowned paths. The counts
    /// and byte totals are always complete; only the path list is bounded, and
    /// the document says when it was truncated.
    unexpected_path_limit: usize = 512,
    /// Whether unowned payload outside the allowlist is a build failure rather
    /// than a reported remainder.
    ///
    /// Issue #677 step 3 requires the fresh roots to fail closed: every file
    /// the finished image carries is either claimed by a package in the exact
    /// closure or named by an explicit injected-file rule with a reason. The
    /// `full` flavor inherits Canonical's server root and is measured, not
    /// gated, so this stays opt-in rather than becoming the default.
    require_allowlisted_unowned: bool = false,
};

/// One measured path that exists only in the finished image.
pub const InjectedEntry = struct {
    path: []const u8,
    logical_bytes: u64,
    allocated_bytes: u64,
};

const shared_owner = std.math.maxInt(u32);
const unmatched_owner = shared_owner - 1;

const Bucket = struct {
    file_count: u64 = 0,
    usage: Usage = .{},

    fn record(self: *Bucket, usage: Usage) void {
        self.file_count += 1;
        self.usage.add(usage);
    }
};

const PackageEntry = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    bucket: Bucket = .{},
};

/// Measures the finished root tree and returns the `root_build` section.
///
/// `arena` must be a report arena: every string the returned value refers to is
/// allocated from it. `scratch` must also be an arena -- the ownership index
/// borrows the dpkg file lists it is built from rather than copying every path
/// out of them -- and the caller releases it once the section is built.
pub fn measureRootBuild(
    arena: Allocator,
    scratch: Allocator,
    io: Io,
    options: RootMeasurementOptions,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    const builder: Builder = .{ .arena = arena };

    const lock_bytes = readRootFile(
        scratch,
        io,
        options.root_path,
        package_lock_path,
        4 * 1024 * 1024,
    ) catch return fail(
        diagnostic,
        "size inventory cannot read the exact package lock {s}",
        .{package_lock_path},
    );
    defer scratch.free(lock_bytes);

    var packages: std.ArrayList(PackageEntry) = .empty;
    defer packages.deinit(scratch);
    try parsePackageLock(scratch, lock_bytes, &packages, diagnostic);

    var index: std.StringHashMapUnmanaged(u32) = .empty;
    defer index.deinit(scratch);
    for (packages.items, 0..) |entry, position| {
        const qualified = try std.fmt.allocPrint(
            scratch,
            "{s}:{s}",
            .{ entry.name, entry.architecture },
        );
        try index.put(scratch, entry.name, @intCast(position));
        try index.put(scratch, qualified, @intCast(position));
    }

    var owners: std.StringHashMapUnmanaged(u32) = .empty;
    defer owners.deinit(scratch);
    var unmatched: std.ArrayList([]const u8) = .empty;
    defer unmatched.deinit(scratch);
    try readOwnership(scratch, io, options.root_path, &index, &owners, &unmatched);

    const rules = try unownedRulesAlloc(scratch, options.flavor);
    defer scratch.free(rules);

    var walk: Walk = .{
        .scratch = scratch,
        .io = io,
        .root_path = options.root_path,
        .owners = &owners,
        .packages = packages.items,
        .rules = rules,
        .rule_buckets = try scratch.alloc(Bucket, rules.len),
        .unexpected_limit = options.unexpected_path_limit,
        .kernel_path = try std.fmt.allocPrint(
            scratch,
            "/boot/vmlinuz-{s}",
            .{options.kernel_release},
        ),
        .initramfs_path = try std.fmt.allocPrint(
            scratch,
            "/boot/initrd.img-{s}",
            .{options.kernel_release},
        ),
        .modules_prefix = try std.fmt.allocPrint(
            scratch,
            "/usr/lib/modules/{s}/",
            .{options.kernel_release},
        ),
    };
    @memset(walk.rule_buckets, .{});
    defer {
        scratch.free(walk.rule_buckets);
        walk.unexpected.deinit(scratch);
    }
    try walk.run(diagnostic);
    for (options.injected) |entry| try walk.recordInjected(entry);

    if (options.require_allowlisted_unowned and walk.unexpected_bucket.file_count != 0) {
        std.mem.sort([]const u8, walk.unexpected.items, {}, lessThanPath);
        const named = walk.unexpected.items[0..@min(walk.unexpected.items.len, 8)];
        var buffer: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        for (named, 0..) |path, position| {
            writer.print("{s}{s}", .{ if (position == 0) "" else " ", path }) catch break;
        }
        return fail(
            diagnostic,
            "{d} unowned path(s) totalling {d} bytes are outside the explicit " ++
                "injected-file allowlist: {s}{s}",
            .{
                walk.unexpected_bucket.file_count,
                walk.unexpected_bucket.usage.logical_bytes,
                writer.buffered(),
                if (named.len < walk.unexpected.items.len or walk.unexpected_truncated)
                    " ..."
                else
                    "",
            },
        );
    }

    var section = builder.object();
    try builder.putCount(&section, "package_count", packages.items.len);
    const closure = try closureDigest(scratch, packages.items);
    try builder.putString(&section, "closure_sha256", &closure);
    try builder.putString(&section, "package_lock_sha256", &hexDigest(lock_bytes));
    try builder.putCount(&section, "file_count", walk.total.file_count);
    try builder.putCount(&section, "installed_bytes", walk.total.usage.logical_bytes);
    try builder.putCount(&section, "allocated_bytes", walk.total.usage.allocated_bytes);
    try builder.putCount(&section, "unreadable_path_count", walk.unreadable);

    var package_values = builder.array();
    try package_values.ensureTotalCapacity(packages.items.len);
    for (packages.items) |entry| {
        var item = builder.object();
        try builder.putString(&item, "name", entry.name);
        try builder.putString(&item, "version", entry.version);
        try builder.putString(&item, "architecture", entry.architecture);
        try builder.putCount(&item, "file_count", entry.bucket.file_count);
        try builder.putCount(&item, "installed_bytes", entry.bucket.usage.logical_bytes);
        try builder.putCount(&item, "allocated_bytes", entry.bucket.usage.allocated_bytes);
        package_values.appendAssumeCapacity(.{ .object = item });
    }
    try builder.put(&section, "packages", .{ .array = package_values });
    try builder.put(&section, "owned", try bucketValue(builder, walk.owned));
    try builder.put(&section, "shared", try bucketValue(builder, walk.shared));

    var unmatched_section = try bucketObject(builder, walk.unmatched);
    std.mem.sort([]const u8, unmatched.items, {}, lessThanPath);
    var unmatched_names = builder.array();
    try unmatched_names.ensureTotalCapacity(unmatched.items.len);
    for (unmatched.items) |name| {
        unmatched_names.appendAssumeCapacity(try builder.string(name));
    }
    try builder.put(&unmatched_section, "packages", .{ .array = unmatched_names });
    try builder.put(&section, "unmatched", .{ .object = unmatched_section });

    var unowned = try bucketObject(builder, walk.unowned);
    var allowed = builder.array();
    try allowed.ensureTotalCapacity(rules.len);
    for (rules, walk.rule_buckets) |rule, bucket| {
        var item = builder.object();
        try builder.putString(&item, "rule", rule.pattern);
        try builder.putString(&item, "reason", rule.reason);
        try builder.putCount(&item, "file_count", bucket.file_count);
        try builder.putCount(&item, "installed_bytes", bucket.usage.logical_bytes);
        try builder.putCount(&item, "allocated_bytes", bucket.usage.allocated_bytes);
        allowed.appendAssumeCapacity(.{ .object = item });
    }
    try builder.put(&unowned, "allowed", .{ .array = allowed });

    var unexpected = try bucketObject(builder, walk.unexpected_bucket);
    std.mem.sort([]const u8, walk.unexpected.items, {}, lessThanPath);
    var unexpected_paths = builder.array();
    try unexpected_paths.ensureTotalCapacity(walk.unexpected.items.len);
    for (walk.unexpected.items) |path| {
        unexpected_paths.appendAssumeCapacity(try builder.string(path));
    }
    try builder.put(&unexpected, "paths", .{ .array = unexpected_paths });
    try builder.put(&unexpected, "truncated", .{ .bool = walk.unexpected_truncated });
    try builder.put(&unowned, "unexpected", .{ .object = unexpected });
    try builder.put(&section, "unowned", .{ .object = unowned });

    var directories = builder.array();
    try directories.ensureTotalCapacity(walk.directories.items.len);
    std.mem.sort(NamedBucket, walk.directories.items, {}, NamedBucket.lessThan);
    for (walk.directories.items) |entry| {
        var item = builder.object();
        try builder.putString(&item, "path", entry.name);
        try builder.putCount(&item, "file_count", entry.bucket.file_count);
        try builder.putCount(&item, "installed_bytes", entry.bucket.usage.logical_bytes);
        try builder.putCount(&item, "allocated_bytes", entry.bucket.usage.allocated_bytes);
        directories.appendAssumeCapacity(.{ .object = item });
    }
    try builder.put(&section, "root_directories", .{ .array = directories });

    var boot = builder.object();
    try builder.putString(&boot, "kernel_release", options.kernel_release);
    try builder.putCount(&boot, "kernel_bytes", walk.kernel.allocated_bytes);
    try builder.putCount(&boot, "initramfs_bytes", walk.initramfs.allocated_bytes);
    try builder.putCount(&boot, "modules_bytes", walk.modules.allocated_bytes);
    try builder.putCount(&boot, "firmware_bytes", walk.firmware.allocated_bytes);
    try builder.put(&section, "boot", .{ .object = boot });

    return .{ .object = section };
}

const NamedBucket = struct {
    name: []const u8,
    bucket: Bucket,

    fn lessThan(_: void, left: NamedBucket, right: NamedBucket) bool {
        return lessThanPath({}, left.name, right.name);
    }
};

fn bucketObject(builder: Builder, bucket: Bucket) Error!std.json.ObjectMap {
    var map = builder.object();
    try builder.putCount(&map, "file_count", bucket.file_count);
    try builder.putCount(&map, "installed_bytes", bucket.usage.logical_bytes);
    try builder.putCount(&map, "allocated_bytes", bucket.usage.allocated_bytes);
    return map;
}

fn bucketValue(builder: Builder, bucket: Bucket) Error!std.json.Value {
    return .{ .object = try bucketObject(builder, bucket) };
}

fn readRootFile(
    allocator: Allocator,
    io: Io,
    root_path: []const u8,
    guest_path: []const u8,
    limit: usize,
) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ root_path, guest_path[1..] });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(io, path, allocator, .limited(limit));
}

fn parsePackageLock(
    allocator: Allocator,
    bytes: []const u8,
    packages: *std.ArrayList(PackageEntry),
    diagnostic: *Diagnostic,
) Error!void {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const name = fields.next() orelse return fail(
            diagnostic,
            "size inventory found a malformed package lock line",
            .{},
        );
        const version = fields.next() orelse return fail(
            diagnostic,
            "size inventory found a malformed package lock line",
            .{},
        );
        const architecture = fields.next() orelse return fail(
            diagnostic,
            "size inventory found a malformed package lock line",
            .{},
        );
        if (fields.next() != null or
            name.len == 0 or
            version.len == 0 or
            architecture.len == 0)
        {
            return fail(
                diagnostic,
                "size inventory found a malformed package lock line",
                .{},
            );
        }
        try packages.append(allocator, .{
            .name = name,
            .version = version,
            .architecture = architecture,
        });
    }
    if (packages.items.len == 0) return fail(
        diagnostic,
        "size inventory found an empty package lock",
        .{},
    );
}

/// `sha256` over the closure spelled one `name<TAB>version<TAB>architecture`
/// line per package, sorted. Deriving it from the parsed set rather than the
/// shipped file's bytes makes it stable against formatting drift, which is what
/// lets two builds be compared on closure identity alone.
fn closureDigest(allocator: Allocator, packages: []const PackageEntry) Error![64]u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    defer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }
    try lines.ensureTotalCapacity(allocator, packages.len);
    for (packages) |entry| {
        lines.appendAssumeCapacity(try std.fmt.allocPrint(
            allocator,
            "{s}\t{s}\t{s}\n",
            .{ entry.name, entry.version, entry.architecture },
        ));
    }
    std.mem.sort([]const u8, lines.items, {}, struct {
        fn lessThan(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.lessThan);
    var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (lines.items) |line| hash.update(line);
    var raw: [32]u8 = undefined;
    hash.final(&raw);
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&raw}) catch unreachable;
    return hex;
}

/// Every path dpkg's own file lists claim in a root, keyed by path.
///
/// Issue #677 forbids installing broad packages and then deleting what they
/// brought: "nothing is installed only to be deleted later". The builder asks
/// this index before it generalizes a fresh root, so a cleanup that would carve
/// a file out of an installed package fails the build instead of producing an
/// image whose dpkg database describes files that are not there.
pub const OwnedPaths = struct {
    arena: std.heap.ArenaAllocator,
    owners: std.StringHashMapUnmanaged([]const u8) = .empty,

    pub fn deinit(self: *OwnedPaths) void {
        self.owners.deinit(self.arena.allocator());
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn count(self: *const OwnedPaths) usize {
        return self.owners.count();
    }

    /// The package that claims `path`, if any.
    pub fn owner(self: *const OwnedPaths, path: []const u8) ?[]const u8 {
        return self.owners.get(path);
    }

    /// The package that claims `path` or anything beneath it. A recursive
    /// removal deletes a subtree, so asking about the root of that subtree
    /// alone would miss the files it takes with it.
    pub fn subtreeOwner(self: *const OwnedPaths, path: []const u8) ?struct {
        path: []const u8,
        package: []const u8,
    } {
        if (self.owners.getEntry(path)) |entry| return .{
            .path = entry.key_ptr.*,
            .package = entry.value_ptr.*,
        };
        var iterator = self.owners.iterator();
        while (iterator.next()) |entry| {
            const candidate = entry.key_ptr.*;
            if (candidate.len <= path.len) continue;
            if (!std.mem.startsWith(u8, candidate, path)) continue;
            if (candidate[path.len] != '/') continue;
            return .{ .path = candidate, .package = entry.value_ptr.* };
        }
        return null;
    }
};

/// Reads `root_path`'s dpkg file lists into an ownership index.
///
/// A root without a dpkg database yields an empty index rather than an error:
/// the callers that use it are the fresh-root flavors, and a missing database
/// is caught by the closure checks that read the package lock.
pub fn readOwnedPaths(allocator: Allocator, io: Io, root_path: []const u8) Error!OwnedPaths {
    var result: OwnedPaths = .{ .arena = .init(allocator) };
    errdefer result.arena.deinit();
    const arena = result.arena.allocator();
    const info_path = std.fs.path.join(
        arena,
        &.{ root_path, dpkg_info_path[1..] },
    ) catch return error.OutOfMemory;
    var directory = Dir.cwd().openDir(io, info_path, .{ .iterate = true }) catch return result;
    defer directory.close(io);
    var iterator = directory.iterate();
    while (iterator.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".list")) continue;
        const package = try arena.dupe(u8, entry.name[0 .. entry.name.len - ".list".len]);
        const list_path = try std.fs.path.join(arena, &.{ info_path, entry.name });
        const contents = Dir.cwd().readFileAlloc(
            io,
            list_path,
            arena,
            .limited(64 * 1024 * 1024),
        ) catch continue;
        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            const path = std.mem.trimEnd(u8, line, "\r");
            if (path.len == 0 or path[0] != '/') continue;
            try result.owners.put(arena, path, package);
        }
    }
    return result;
}

/// Builds the path-to-package index from dpkg's per-package file lists. A list
/// naming a package the exact closure does not contain is recorded rather than
/// refused: the closure is enforced elsewhere, and a measurement that refuses
/// to report a discrepancy is how the discrepancy stays invisible.
fn readOwnership(
    allocator: Allocator,
    io: Io,
    root_path: []const u8,
    index: *const std.StringHashMapUnmanaged(u32),
    owners: *std.StringHashMapUnmanaged(u32),
    unmatched: *std.ArrayList([]const u8),
) Error!void {
    const info_path = std.fs.path.join(
        allocator,
        &.{ root_path, dpkg_info_path[1..] },
    ) catch return error.OutOfMemory;
    defer allocator.free(info_path);
    var directory = Dir.cwd().openDir(io, info_path, .{ .iterate = true }) catch return;
    defer directory.close(io);
    var iterator = directory.iterate();
    while (iterator.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".list")) continue;
        const stem = entry.name[0 .. entry.name.len - ".list".len];
        const owner = index.get(stem) orelse blk: {
            const name = try allocator.dupe(u8, stem);
            try unmatched.append(allocator, name);
            break :blk unmatched_owner;
        };
        const list_path = try std.fs.path.join(allocator, &.{ info_path, entry.name });
        defer allocator.free(list_path);
        const contents = Dir.cwd().readFileAlloc(
            io,
            list_path,
            allocator,
            .limited(64 * 1024 * 1024),
        ) catch continue;
        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            const path = std.mem.trimEnd(u8, line, "\r");
            if (path.len == 0 or path[0] != '/') continue;
            const existing = try owners.getOrPut(allocator, path);
            if (existing.found_existing) {
                if (existing.value_ptr.* != owner) existing.value_ptr.* = shared_owner;
            } else {
                existing.value_ptr.* = owner;
            }
        }
    }
}

/// Accumulating walk over the finished root tree.
const Walk = struct {
    scratch: Allocator,
    io: Io,
    root_path: []const u8,
    owners: *const std.StringHashMapUnmanaged(u32),
    packages: []PackageEntry,
    rules: []const UnownedRule,
    rule_buckets: []Bucket,
    unexpected_limit: usize,
    kernel_path: []const u8,
    initramfs_path: []const u8,
    modules_prefix: []const u8,

    total: Bucket = .{},
    owned: Bucket = .{},
    shared: Bucket = .{},
    unmatched: Bucket = .{},
    unowned: Bucket = .{},
    unexpected_bucket: Bucket = .{},
    unexpected: std.ArrayList([]const u8) = .empty,
    unexpected_truncated: bool = false,
    unreadable: u64 = 0,
    directories: std.ArrayList(NamedBucket) = .empty,
    kernel: Usage = .{},
    initramfs: Usage = .{},
    modules: Usage = .{},
    firmware: Usage = .{},

    fn run(self: *Walk, diagnostic: *Diagnostic) Error!void {
        var directory = Dir.cwd().openDir(
            self.io,
            self.root_path,
            .{ .iterate = true },
        ) catch return fail(
            diagnostic,
            "size inventory cannot read the root tree {s}",
            .{self.root_path},
        );
        defer directory.close(self.io);
        var iterator = directory.iterate();
        while (iterator.next(self.io) catch |err| return fail(
            diagnostic,
            "size inventory cannot walk the root tree: {s}",
            .{@errorName(err)},
        )) |entry| {
            const guest = try std.fmt.allocPrint(self.scratch, "/{s}", .{entry.name});
            defer self.scratch.free(guest);
            const host = try std.fs.path.join(
                self.scratch,
                &.{ self.root_path, entry.name },
            );
            defer self.scratch.free(host);
            var bucket: Bucket = .{};
            try self.visit(guest, host, entry.kind, &bucket);
            try self.directories.append(self.scratch, .{
                .name = try self.scratch.dupe(u8, guest),
                .bucket = bucket,
            });
        }
    }

    /// Records one entry and, for a directory, everything beneath it.
    /// `top_level` accumulates the subtree so the per-root-directory table adds
    /// up to the same totals the rest of the section reports.
    fn visit(
        self: *Walk,
        guest: []const u8,
        host: []const u8,
        kind: std.Io.File.Kind,
        top_level: *Bucket,
    ) Error!void {
        const host_z = try self.scratch.dupeZ(u8, host);
        defer self.scratch.free(host_z);
        const usage = pathUsage(host_z) orelse {
            self.unreadable += 1;
            return;
        };
        self.total.record(usage);
        top_level.record(usage);
        self.attribute(guest, usage);
        try self.attributeBoot(guest, usage);
        if (kind != .directory) return;

        var directory = Dir.cwd().openDir(self.io, host, .{ .iterate = true }) catch {
            self.unreadable += 1;
            return;
        };
        defer directory.close(self.io);
        var iterator = directory.iterate();
        while (true) {
            const next = iterator.next(self.io) catch {
                self.unreadable += 1;
                return;
            };
            const entry = next orelse break;
            const child_guest = try std.fmt.allocPrint(
                self.scratch,
                "{s}/{s}",
                .{ guest, entry.name },
            );
            defer self.scratch.free(child_guest);
            const child_host = try std.fs.path.join(
                self.scratch,
                &.{ host, entry.name },
            );
            defer self.scratch.free(child_host);
            try self.visit(child_guest, child_host, entry.kind, top_level);
        }
    }

    /// Records a path that exists only in the finished image, using the same
    /// attribution the walk applies to everything it finds.
    fn recordInjected(self: *Walk, entry: InjectedEntry) Error!void {
        if (entry.path.len < 2 or entry.path[0] != '/') return;
        const usage: Usage = .{
            .logical_bytes = entry.logical_bytes,
            .allocated_bytes = entry.allocated_bytes,
        };
        self.total.record(usage);
        self.attribute(entry.path, usage);
        try self.attributeBoot(entry.path, usage);
        const end = std.mem.indexOfScalarPos(u8, entry.path, 1, '/') orelse
            entry.path.len;
        const top = entry.path[0..end];
        for (self.directories.items) |*item| {
            if (std.mem.eql(u8, item.name, top)) {
                item.bucket.record(usage);
                return;
            }
        }
        try self.directories.append(self.scratch, .{
            .name = try self.scratch.dupe(u8, top),
            .bucket = .{ .file_count = 1, .usage = usage },
        });
    }

    fn attribute(self: *Walk, guest: []const u8, usage: Usage) void {
        if (self.owners.get(guest)) |owner| {
            switch (owner) {
                shared_owner => self.shared.record(usage),
                unmatched_owner => self.unmatched.record(usage),
                else => {
                    self.owned.record(usage);
                    self.packages[owner].bucket.record(usage);
                },
            }
            return;
        }
        self.unowned.record(usage);
        for (self.rules, self.rule_buckets) |rule, *bucket| {
            if (rule.matches(guest)) {
                bucket.record(usage);
                return;
            }
        }
        self.unexpected_bucket.record(usage);
        if (self.unexpected.items.len >= self.unexpected_limit) {
            self.unexpected_truncated = true;
            return;
        }
        const copy = self.scratch.dupe(u8, guest) catch {
            self.unexpected_truncated = true;
            return;
        };
        self.unexpected.append(self.scratch, copy) catch {
            self.unexpected_truncated = true;
        };
    }

    fn attributeBoot(self: *Walk, guest: []const u8, usage: Usage) Error!void {
        if (std.mem.eql(u8, guest, self.kernel_path)) self.kernel.add(usage);
        if (std.mem.eql(u8, guest, self.initramfs_path)) self.initramfs.add(usage);
        if (std.mem.startsWith(u8, guest, self.modules_prefix)) self.modules.add(usage);
        if (std.mem.startsWith(u8, guest, "/usr/lib/firmware/")) self.firmware.add(usage);
    }
};

// ---------------------------------------------------------------------------
// Later-phase sections.
// ---------------------------------------------------------------------------

/// ext4 accounting for one observation of the root filesystem.
pub const FilesystemUsage = struct {
    block_size: u64,
    total_blocks: u64,
    free_blocks: u64,
    total_inodes: u64,
    free_inodes: u64,
};

pub const ImageBuild = struct {
    virtual_size: u64,
    root: FilesystemUsage,
    uki_bytes: u64,
    esp_partition_bytes: u64,
    esp_total_bytes: u64,
    esp_free_bytes: u64,
};

pub const Publication = struct {
    artifact_name: []const u8,
    compressed_artifact_bytes: u64,
    qcow2_allocated_bytes: u64,
};

fn filesystemFields(
    builder: Builder,
    map: *std.json.ObjectMap,
    usage: FilesystemUsage,
    diagnostic: *Diagnostic,
) Error!void {
    if (usage.free_blocks > usage.total_blocks or
        usage.free_inodes > usage.total_inodes or
        usage.block_size == 0)
    {
        return fail(diagnostic, "size inventory filesystem usage is inconsistent", .{});
    }
    try builder.putCount(map, "root_block_size", usage.block_size);
    try builder.putCount(map, "root_total_blocks", usage.total_blocks);
    try builder.putCount(map, "root_used_blocks", usage.total_blocks - usage.free_blocks);
    try builder.putCount(map, "root_free_blocks", usage.free_blocks);
    try builder.putCount(map, "root_total_inodes", usage.total_inodes);
    try builder.putCount(map, "root_used_inodes", usage.total_inodes - usage.free_inodes);
    try builder.putCount(map, "root_free_inodes", usage.free_inodes);
}

pub fn imageBuildValue(
    arena: Allocator,
    image: ImageBuild,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    const builder: Builder = .{ .arena = arena };
    if (image.esp_free_bytes > image.esp_total_bytes or
        image.esp_total_bytes > image.esp_partition_bytes or
        image.uki_bytes > image.esp_total_bytes - image.esp_free_bytes)
    {
        return fail(diagnostic, "size inventory ESP usage is inconsistent", .{});
    }
    var map = builder.object();
    try builder.putCount(&map, "virtual_size", image.virtual_size);
    try filesystemFields(builder, &map, image.root, diagnostic);
    try builder.putCount(&map, "uki_bytes", image.uki_bytes);
    try builder.putCount(&map, "esp_partition_bytes", image.esp_partition_bytes);
    try builder.putCount(&map, "esp_total_bytes", image.esp_total_bytes);
    try builder.putCount(
        &map,
        "esp_used_bytes",
        image.esp_total_bytes - image.esp_free_bytes,
    );
    try builder.putCount(&map, "esp_free_bytes", image.esp_free_bytes);
    return .{ .object = map };
}

pub fn publicationValue(
    arena: Allocator,
    publication: Publication,
) Error!std.json.Value {
    const builder: Builder = .{ .arena = arena };
    var map = builder.object();
    try builder.putString(&map, "artifact_name", publication.artifact_name);
    try builder.putCount(
        &map,
        "compressed_artifact_bytes",
        publication.compressed_artifact_bytes,
    );
    try builder.putCount(
        &map,
        "qcow2_allocated_bytes",
        publication.qcow2_allocated_bytes,
    );
    return .{ .object = map };
}

pub fn firstBootValue(
    arena: Allocator,
    usage: FilesystemUsage,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    const builder: Builder = .{ .arena = arena };
    var map = builder.object();
    try filesystemFields(builder, &map, usage, diagnostic);
    return .{ .object = map };
}

// ---------------------------------------------------------------------------
// Validation.
// ---------------------------------------------------------------------------

pub const ValidateOptions = struct {
    architecture: ?[]const u8 = null,
    flavor: ?[]const u8 = null,
    /// Phases the caller's stage is entitled to expect. A document missing one
    /// of these is incomplete for that caller and is refused by name.
    required_phases: []const Phase = &.{.root_build},
};

pub const Summary = struct {
    architecture: []const u8,
    flavor: []const u8,
    phases: [phase_order.len]bool = @splat(false),
    package_count: u64 = 0,
    closure_sha256: []const u8 = "",
    installed_bytes: u64 = 0,
    allocated_bytes: u64 = 0,
    unexpected_unowned_count: u64 = 0,

    pub fn has(self: Summary, phase: Phase) bool {
        return self.phases[@intFromEnum(phase)];
    }
};

const base_document_fields = [_][]const u8{
    "architecture",
    "flavor",
    "phases_present",
    "release",
    "schema",
    "type",
};

const root_build_fields = [_][]const u8{
    "allocated_bytes",
    "boot",
    "closure_sha256",
    "file_count",
    "installed_bytes",
    "owned",
    "package_count",
    "package_lock_sha256",
    "packages",
    "root_directories",
    "shared",
    "unmatched",
    "unowned",
    "unreadable_path_count",
};

const bucket_fields = [_][]const u8{
    "allocated_bytes",
    "file_count",
    "installed_bytes",
};

const image_build_fields = [_][]const u8{
    "esp_free_bytes",
    "esp_partition_bytes",
    "esp_total_bytes",
    "esp_used_bytes",
    "root_block_size",
    "root_free_blocks",
    "root_free_inodes",
    "root_total_blocks",
    "root_total_inodes",
    "root_used_blocks",
    "root_used_inodes",
    "uki_bytes",
    "virtual_size",
};

const publication_fields = [_][]const u8{
    "artifact_name",
    "compressed_artifact_bytes",
    "qcow2_allocated_bytes",
};

const first_boot_fields = [_][]const u8{
    "root_block_size",
    "root_free_blocks",
    "root_free_inodes",
    "root_total_blocks",
    "root_total_inodes",
    "root_used_blocks",
    "root_used_inodes",
};

/// Full structural and arithmetic check over a parsed size-inventory document.
pub fn validateDocument(
    allocator: Allocator,
    value: std.json.Value,
    options: ValidateOptions,
    diagnostic: *Diagnostic,
) Error!Summary {
    const object = objectOf(value) orelse return fail(
        diagnostic,
        "size inventory is not a JSON object",
        .{},
    );
    if (integerOf(object.get("schema")) != schema_version or
        !stringIs(object.get("type"), document_type) or
        !stringIs(object.get("release"), release_id))
    {
        return fail(diagnostic, "size inventory identity is invalid", .{});
    }
    const architecture = stringOf(object.get("architecture")) orelse return fail(
        diagnostic,
        "size inventory architecture is invalid",
        .{},
    );
    if (std.meta.stringToEnum(Architecture, architecture) == null or
        (options.architecture != null and
            !std.mem.eql(u8, architecture, options.architecture.?)))
    {
        return fail(diagnostic, "size inventory architecture is invalid", .{});
    }
    const flavor_text = stringOf(object.get("flavor")) orelse return fail(
        diagnostic,
        "size inventory flavor is invalid",
        .{},
    );
    if (std.meta.stringToEnum(Flavor, flavor_text) == null or
        (options.flavor != null and !std.mem.eql(u8, flavor_text, options.flavor.?)))
    {
        return fail(diagnostic, "size inventory flavor is invalid", .{});
    }

    var summary: Summary = .{ .architecture = architecture, .flavor = flavor_text };
    const declared = arrayOf(object.get("phases_present")) orelse return fail(
        diagnostic,
        "size inventory phases_present is invalid",
        .{},
    );
    if (declared.len == 0) return fail(
        diagnostic,
        "size inventory declares no phases",
        .{},
    );
    var previous: usize = 0;
    var expected_fields: std.ArrayList([]const u8) = .empty;
    defer expected_fields.deinit(allocator);
    try expected_fields.appendSlice(allocator, &base_document_fields);
    for (declared, 0..) |entry, position| {
        const text = stringOf(entry) orelse return fail(
            diagnostic,
            "size inventory phases_present is invalid",
            .{},
        );
        const phase = Phase.parse(text) orelse return fail(
            diagnostic,
            "size inventory declares unknown phase {s}",
            .{text},
        );
        const rank = @intFromEnum(phase);
        if (position != 0 and rank <= previous) return fail(
            diagnostic,
            "size inventory phases_present is out of order at {s}",
            .{text},
        );
        previous = rank;
        summary.phases[rank] = true;
        try expected_fields.append(allocator, phase.key());
    }
    if (!summary.has(.root_build)) return fail(
        diagnostic,
        "size inventory is missing required phase root_build",
        .{},
    );
    if (!hasExactFields(object, expected_fields.items)) return fail(
        diagnostic,
        "size inventory sections do not match phases_present",
        .{},
    );
    for (options.required_phases) |phase| {
        if (!summary.has(phase)) return fail(
            diagnostic,
            "size inventory is missing required phase {s}",
            .{phase.key()},
        );
    }

    try validateRootBuild(object.get("root_build"), &summary, diagnostic);
    if (summary.has(.image_build)) {
        try validateImageBuild(object.get("image_build"), diagnostic);
    }
    if (summary.has(.publication)) {
        try validatePublication(object.get("publication"), diagnostic);
    }
    if (summary.has(.first_boot)) {
        try validateFilesystemSection(
            objectOf(object.get("first_boot")) orelse return fail(
                diagnostic,
                "size inventory first_boot is invalid",
                .{},
            ),
            &first_boot_fields,
            "first_boot",
            diagnostic,
        );
    }
    return summary;
}

fn stringIs(value: ?std.json.Value, expected: []const u8) bool {
    const text = stringOf(value) orelse return false;
    return std.mem.eql(u8, text, expected);
}

fn requireBucket(
    value: ?std.json.Value,
    label: []const u8,
    extra: []const []const u8,
    diagnostic: *Diagnostic,
) Error!Bucket {
    const object = objectOf(value) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    if (object.count() != bucket_fields.len + extra.len) return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    for (bucket_fields) |field| {
        if (!object.contains(field)) return fail(
            diagnostic,
            "size inventory {s} is invalid",
            .{label},
        );
    }
    for (extra) |field| {
        if (!object.contains(field)) return fail(
            diagnostic,
            "size inventory {s} is invalid",
            .{label},
        );
    }
    const file_count = countOf(object.get("file_count")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    const installed = countOf(object.get("installed_bytes")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    const allocated = countOf(object.get("allocated_bytes")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    return .{
        .file_count = file_count,
        .usage = .{ .logical_bytes = installed, .allocated_bytes = allocated },
    };
}

fn accumulate(total: *Bucket, part: Bucket) void {
    total.file_count += part.file_count;
    total.usage.add(part.usage);
}

fn bucketsEqual(left: Bucket, right: Bucket) bool {
    return left.file_count == right.file_count and
        left.usage.logical_bytes == right.usage.logical_bytes and
        left.usage.allocated_bytes == right.usage.allocated_bytes;
}

fn validateRootBuild(
    value: ?std.json.Value,
    summary: *Summary,
    diagnostic: *Diagnostic,
) Error!void {
    const object = objectOf(value) orelse return fail(
        diagnostic,
        "size inventory root_build is invalid",
        .{},
    );
    if (!hasExactFields(object, &root_build_fields)) return fail(
        diagnostic,
        "size inventory root_build has unexpected fields",
        .{},
    );
    const closure = stringOf(object.get("closure_sha256")) orelse return fail(
        diagnostic,
        "size inventory closure digest is invalid",
        .{},
    );
    const lock_digest = stringOf(object.get("package_lock_sha256")) orelse return fail(
        diagnostic,
        "size inventory package lock digest is invalid",
        .{},
    );
    if (!isSha256(closure) or !isSha256(lock_digest)) return fail(
        diagnostic,
        "size inventory closure digest is invalid",
        .{},
    );
    const package_count = countOf(object.get("package_count")) orelse return fail(
        diagnostic,
        "size inventory package count is invalid",
        .{},
    );
    _ = countOf(object.get("unreadable_path_count")) orelse return fail(
        diagnostic,
        "size inventory unreadable path count is invalid",
        .{},
    );
    const total: Bucket = .{
        .file_count = countOf(object.get("file_count")) orelse return fail(
            diagnostic,
            "size inventory root_build totals are invalid",
            .{},
        ),
        .usage = .{
            .logical_bytes = countOf(object.get("installed_bytes")) orelse return fail(
                diagnostic,
                "size inventory root_build totals are invalid",
                .{},
            ),
            .allocated_bytes = countOf(object.get("allocated_bytes")) orelse return fail(
                diagnostic,
                "size inventory root_build totals are invalid",
                .{},
            ),
        },
    };

    const packages = arrayOf(object.get("packages")) orelse return fail(
        diagnostic,
        "size inventory packages are invalid",
        .{},
    );
    if (packages.len != package_count) return fail(
        diagnostic,
        "size inventory package count does not match the package table",
        .{},
    );
    var owned_sum: Bucket = .{};
    var previous_name: []const u8 = "";
    for (packages) |entry| {
        const item = objectOf(entry) orelse return fail(
            diagnostic,
            "size inventory package entry is invalid",
            .{},
        );
        const bucket = try requireBucket(
            entry,
            "package entry",
            &.{ "architecture", "name", "version" },
            diagnostic,
        );
        const name = stringOf(item.get("name")) orelse return fail(
            diagnostic,
            "size inventory package entry is invalid",
            .{},
        );
        if (stringOf(item.get("version")) == null or
            stringOf(item.get("architecture")) == null)
        {
            return fail(diagnostic, "size inventory package entry is invalid", .{});
        }
        if (previous_name.len != 0 and std.mem.lessThan(u8, name, previous_name)) {
            return fail(diagnostic, "size inventory packages are unsorted", .{});
        }
        previous_name = name;
        accumulate(&owned_sum, bucket);
    }
    const owned = try requireBucket(object.get("owned"), "owned totals", &.{}, diagnostic);
    if (!bucketsEqual(owned, owned_sum)) return fail(
        diagnostic,
        "size inventory owned totals do not match the package table",
        .{},
    );

    const shared = try requireBucket(object.get("shared"), "shared totals", &.{}, diagnostic);
    const unmatched = try requireBucket(
        object.get("unmatched"),
        "unmatched totals",
        &.{"packages"},
        diagnostic,
    );
    if (arrayOf(objectOf(object.get("unmatched")).?.get("packages")) == null) return fail(
        diagnostic,
        "size inventory unmatched packages are invalid",
        .{},
    );

    const unowned_object = objectOf(object.get("unowned")) orelse return fail(
        diagnostic,
        "size inventory unowned totals are invalid",
        .{},
    );
    const unowned = try requireBucket(
        object.get("unowned"),
        "unowned totals",
        &.{ "allowed", "unexpected" },
        diagnostic,
    );
    const allowed = arrayOf(unowned_object.get("allowed")) orelse return fail(
        diagnostic,
        "size inventory unowned allowlist is invalid",
        .{},
    );
    var unowned_sum: Bucket = .{};
    for (allowed) |entry| {
        const item = objectOf(entry) orelse return fail(
            diagnostic,
            "size inventory unowned allowlist entry is invalid",
            .{},
        );
        const bucket = try requireBucket(
            entry,
            "unowned allowlist entry",
            &.{ "reason", "rule" },
            diagnostic,
        );
        if (stringOf(item.get("rule")) == null or stringOf(item.get("reason")) == null) {
            return fail(
                diagnostic,
                "size inventory unowned allowlist entry is invalid",
                .{},
            );
        }
        accumulate(&unowned_sum, bucket);
    }
    const unexpected_object = objectOf(unowned_object.get("unexpected")) orelse
        return fail(diagnostic, "size inventory unexpected payload is invalid", .{});
    const unexpected = try requireBucket(
        unowned_object.get("unexpected"),
        "unexpected payload",
        &.{ "paths", "truncated" },
        diagnostic,
    );
    const paths = arrayOf(unexpected_object.get("paths")) orelse return fail(
        diagnostic,
        "size inventory unexpected payload is invalid",
        .{},
    );
    const truncated = switch (unexpected_object.get("truncated") orelse std.json.Value.null) {
        .bool => |flag| flag,
        else => return fail(
            diagnostic,
            "size inventory unexpected payload is invalid",
            .{},
        ),
    };
    for (paths) |entry| {
        if (stringOf(entry) == null) return fail(
            diagnostic,
            "size inventory unexpected payload is invalid",
            .{},
        );
    }
    if (!truncated and paths.len != unexpected.file_count) return fail(
        diagnostic,
        "size inventory unexpected payload is incomplete",
        .{},
    );
    if (truncated and paths.len >= unexpected.file_count) return fail(
        diagnostic,
        "size inventory unexpected payload is not truncated",
        .{},
    );
    accumulate(&unowned_sum, unexpected);
    if (!bucketsEqual(unowned, unowned_sum)) return fail(
        diagnostic,
        "size inventory unowned totals do not match their parts",
        .{},
    );

    var parts: Bucket = .{};
    accumulate(&parts, owned);
    accumulate(&parts, shared);
    accumulate(&parts, unmatched);
    accumulate(&parts, unowned);
    if (!bucketsEqual(total, parts)) return fail(
        diagnostic,
        "size inventory totals do not match owned, shared, unmatched, and unowned bytes",
        .{},
    );

    const directories = arrayOf(object.get("root_directories")) orelse return fail(
        diagnostic,
        "size inventory root directories are invalid",
        .{},
    );
    var directory_sum: Bucket = .{};
    for (directories) |entry| {
        const item = objectOf(entry) orelse return fail(
            diagnostic,
            "size inventory root directory entry is invalid",
            .{},
        );
        const bucket = try requireBucket(
            entry,
            "root directory entry",
            &.{"path"},
            diagnostic,
        );
        const path = stringOf(item.get("path")) orelse return fail(
            diagnostic,
            "size inventory root directory entry is invalid",
            .{},
        );
        if (path.len < 2 or path[0] != '/') return fail(
            diagnostic,
            "size inventory root directory entry is invalid",
            .{},
        );
        accumulate(&directory_sum, bucket);
    }
    if (!bucketsEqual(total, directory_sum)) return fail(
        diagnostic,
        "size inventory root directory usage does not match the totals",
        .{},
    );

    const boot = objectOf(object.get("boot")) orelse return fail(
        diagnostic,
        "size inventory boot usage is invalid",
        .{},
    );
    const boot_fields = [_][]const u8{
        "firmware_bytes",
        "initramfs_bytes",
        "kernel_bytes",
        "kernel_release",
        "modules_bytes",
    };
    if (!hasExactFields(boot, &boot_fields)) return fail(
        diagnostic,
        "size inventory boot usage is invalid",
        .{},
    );
    if (stringOf(boot.get("kernel_release")) == null) return fail(
        diagnostic,
        "size inventory boot usage is invalid",
        .{},
    );
    for ([_][]const u8{
        "kernel_bytes",
        "initramfs_bytes",
        "modules_bytes",
        "firmware_bytes",
    }) |field| {
        _ = countOf(boot.get(field)) orelse return fail(
            diagnostic,
            "size inventory boot usage is invalid",
            .{},
        );
    }

    summary.package_count = package_count;
    summary.closure_sha256 = closure;
    summary.installed_bytes = total.usage.logical_bytes;
    summary.allocated_bytes = total.usage.allocated_bytes;
    summary.unexpected_unowned_count = unexpected.file_count;
}

fn validateFilesystemSection(
    object: std.json.ObjectMap,
    fields: []const []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    for (fields) |field| {
        if (!object.contains(field)) return fail(
            diagnostic,
            "size inventory {s} is invalid",
            .{label},
        );
    }
    if (object.count() != fields.len) return fail(
        diagnostic,
        "size inventory {s} has unexpected fields",
        .{label},
    );
    const block_size = countOf(object.get("root_block_size")) orelse 0;
    const total_blocks = countOf(object.get("root_total_blocks")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    const used_blocks = countOf(object.get("root_used_blocks")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    const free_blocks = countOf(object.get("root_free_blocks")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    const total_inodes = countOf(object.get("root_total_inodes")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    const used_inodes = countOf(object.get("root_used_inodes")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    const free_inodes = countOf(object.get("root_free_inodes")) orelse return fail(
        diagnostic,
        "size inventory {s} is invalid",
        .{label},
    );
    if (block_size == 0 or total_blocks == 0 or total_inodes == 0 or
        used_blocks + free_blocks != total_blocks or
        used_inodes + free_inodes != total_inodes)
    {
        return fail(
            diagnostic,
            "size inventory {s} block and inode accounting does not add up",
            .{label},
        );
    }
}

fn validateImageBuild(value: ?std.json.Value, diagnostic: *Diagnostic) Error!void {
    const object = objectOf(value) orelse return fail(
        diagnostic,
        "size inventory image_build is invalid",
        .{},
    );
    try validateFilesystemSection(object, &image_build_fields, "image_build", diagnostic);
    const virtual_size = countOf(object.get("virtual_size")) orelse return fail(
        diagnostic,
        "size inventory image_build is invalid",
        .{},
    );
    const uki = countOf(object.get("uki_bytes")) orelse return fail(
        diagnostic,
        "size inventory image_build is invalid",
        .{},
    );
    const partition = countOf(object.get("esp_partition_bytes")) orelse return fail(
        diagnostic,
        "size inventory image_build is invalid",
        .{},
    );
    const total = countOf(object.get("esp_total_bytes")) orelse return fail(
        diagnostic,
        "size inventory image_build is invalid",
        .{},
    );
    const used = countOf(object.get("esp_used_bytes")) orelse return fail(
        diagnostic,
        "size inventory image_build is invalid",
        .{},
    );
    const free = countOf(object.get("esp_free_bytes")) orelse return fail(
        diagnostic,
        "size inventory image_build is invalid",
        .{},
    );
    const blocks = countOf(object.get("root_total_blocks")).? *
        countOf(object.get("root_block_size")).?;
    if (virtual_size == 0 or uki == 0 or
        used + free != total or
        total > partition or
        uki > used or
        blocks > virtual_size)
    {
        return fail(
            diagnostic,
            "size inventory image_build geometry does not add up",
            .{},
        );
    }
}

fn validatePublication(value: ?std.json.Value, diagnostic: *Diagnostic) Error!void {
    const object = objectOf(value) orelse return fail(
        diagnostic,
        "size inventory publication is invalid",
        .{},
    );
    if (!hasExactFields(object, &publication_fields)) return fail(
        diagnostic,
        "size inventory publication has unexpected fields",
        .{},
    );
    const name = stringOf(object.get("artifact_name")) orelse return fail(
        diagnostic,
        "size inventory publication is invalid",
        .{},
    );
    const bytes = countOf(object.get("compressed_artifact_bytes")) orelse return fail(
        diagnostic,
        "size inventory publication is invalid",
        .{},
    );
    const allocated = countOf(object.get("qcow2_allocated_bytes")) orelse return fail(
        diagnostic,
        "size inventory publication is invalid",
        .{},
    );
    if (name.len == 0 or bytes == 0 or allocated == 0) return fail(
        diagnostic,
        "size inventory publication is invalid",
        .{},
    );
}

/// Reads, parses, and validates a size-inventory document.
pub fn readValidated(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    options: ValidateOptions,
    diagnostic: *Diagnostic,
) Error!std.json.Parsed(std.json.Value) {
    const bytes = Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(document_max_bytes),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read size inventory {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    defer allocator.free(bytes);
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read size inventory {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    errdefer parsed.deinit();
    _ = try validateDocument(allocator, parsed.value, options, diagnostic);
    return parsed;
}

// ---------------------------------------------------------------------------
// Appending a later phase to an existing document.
// ---------------------------------------------------------------------------

/// Adds `section` to an already validated document as `phase`.
///
/// This is what lets a stage that can finally see a number write it into the
/// document the earlier stage produced, instead of the earlier stage guessing.
pub fn appendPhaseAlloc(
    arena: Allocator,
    document: std.json.Value,
    phase: Phase,
    section: std.json.Value,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    const object = objectOf(document) orelse return fail(
        diagnostic,
        "size inventory is not a JSON object",
        .{},
    );
    if (object.contains(phase.key())) return fail(
        diagnostic,
        "size inventory phase {s} is already recorded",
        .{phase.key()},
    );
    const declared = arrayOf(object.get("phases_present")) orelse return fail(
        diagnostic,
        "size inventory phases_present is invalid",
        .{},
    );
    for (phase_order) |candidate| {
        if (candidate == phase) break;
        var found = false;
        for (declared) |entry| {
            if (stringIs(entry, candidate.key())) found = true;
        }
        if (!found) return fail(
            diagnostic,
            "size inventory phase {s} cannot precede {s}",
            .{ phase.key(), candidate.key() },
        );
    }

    const builder: Builder = .{ .arena = arena };
    var updated = builder.object();
    var iterator = object.iterator();
    while (iterator.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "phases_present")) continue;
        try builder.put(&updated, entry.key_ptr.*, entry.value_ptr.*);
    }
    var phases = builder.array();
    try phases.ensureTotalCapacity(declared.len + 1);
    for (declared) |entry| phases.appendAssumeCapacity(entry);
    phases.appendAssumeCapacity(try builder.string(phase.key()));
    try builder.put(&updated, "phases_present", .{ .array = phases });
    try builder.put(&updated, phase.key(), section);
    return .{ .object = updated };
}

// ---------------------------------------------------------------------------
// Comparison.
// ---------------------------------------------------------------------------

/// Difference between two validated documents, restricted to the phases both
/// carry. Comparing a phase only one side measured would be comparing a
/// measurement with an absence.
pub fn compareAlloc(
    arena: Allocator,
    scratch: Allocator,
    baseline: std.json.Value,
    candidate: std.json.Value,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    const base_summary = try validateDocument(scratch, baseline, .{}, diagnostic);
    const candidate_summary = try validateDocument(
        scratch,
        candidate,
        .{
            .architecture = base_summary.architecture,
            .flavor = base_summary.flavor,
        },
        diagnostic,
    );
    const base_object = objectOf(baseline).?;
    const candidate_object = objectOf(candidate).?;

    const builder: Builder = .{ .arena = arena };
    var document = builder.object();
    try builder.put(&document, "schema", .{ .integer = schema_version });
    try builder.putString(&document, "type", comparison_type);
    try builder.putString(&document, "release", release_id);
    try builder.putString(&document, "architecture", base_summary.architecture);
    try builder.putString(&document, "flavor", base_summary.flavor);

    var compared = builder.array();
    for (phase_order) |phase| {
        if (base_summary.has(phase) and candidate_summary.has(phase)) {
            try compared.append(try builder.string(phase.key()));
        }
    }
    try builder.put(&document, "phases_compared", .{ .array = compared });

    var root = builder.object();
    try builder.put(&root, "closure_changed", .{
        .bool = !std.mem.eql(u8, base_summary.closure_sha256, candidate_summary.closure_sha256),
    });
    try builder.put(&root, "package_count_delta", .{
        .integer = delta(base_summary.package_count, candidate_summary.package_count),
    });
    try builder.put(&root, "installed_bytes_delta", .{
        .integer = delta(base_summary.installed_bytes, candidate_summary.installed_bytes),
    });
    try builder.put(&root, "allocated_bytes_delta", .{
        .integer = delta(base_summary.allocated_bytes, candidate_summary.allocated_bytes),
    });
    try builder.put(&root, "packages", try comparePackages(
        builder,
        scratch,
        objectOf(base_object.get("root_build")).?,
        objectOf(candidate_object.get("root_build")).?,
    ));
    try builder.put(&document, "root_build", .{ .object = root });

    for ([_]struct { phase: Phase, fields: []const []const u8 }{
        .{ .phase = .image_build, .fields = &image_build_fields },
        .{ .phase = .publication, .fields = &publication_fields },
        .{ .phase = .first_boot, .fields = &first_boot_fields },
    }) |entry| {
        if (!base_summary.has(entry.phase) or !candidate_summary.has(entry.phase)) continue;
        const left = objectOf(base_object.get(entry.phase.key())).?;
        const right = objectOf(candidate_object.get(entry.phase.key())).?;
        var section = builder.object();
        for (entry.fields) |field| {
            const before = countOf(left.get(field)) orelse continue;
            const after = countOf(right.get(field)) orelse continue;
            const key = try std.fmt.allocPrint(arena, "{s}_delta", .{field});
            try builder.put(&section, key, .{ .integer = delta(before, after) });
        }
        try builder.put(&document, entry.phase.key(), .{ .object = section });
    }
    return .{ .object = document };
}

fn delta(before: u64, after: u64) i64 {
    return castCount(after) - castCount(before);
}

fn comparePackages(
    builder: Builder,
    scratch: Allocator,
    baseline: std.json.ObjectMap,
    candidate: std.json.ObjectMap,
) Error!std.json.Value {
    var index: std.StringHashMapUnmanaged(usize) = .empty;
    defer index.deinit(scratch);
    const base_items = arrayOf(baseline.get("packages")).?;
    const candidate_items = arrayOf(candidate.get("packages")).?;
    for (base_items, 0..) |entry, position| {
        try index.put(scratch, stringOf(objectOf(entry).?.get("name")).?, position);
    }

    var added = builder.array();
    var changed = builder.array();
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(scratch);
    for (candidate_items) |entry| {
        const item = objectOf(entry).?;
        const name = stringOf(item.get("name")).?;
        try seen.put(scratch, name, {});
        const installed = countOf(item.get("installed_bytes")).?;
        const allocated = countOf(item.get("allocated_bytes")).?;
        const position = index.get(name) orelse {
            var record = builder.object();
            try builder.putString(&record, "name", name);
            try builder.putCount(&record, "installed_bytes", installed);
            try builder.putCount(&record, "allocated_bytes", allocated);
            try added.append(.{ .object = record });
            continue;
        };
        const before = objectOf(base_items[position]).?;
        const before_installed = countOf(before.get("installed_bytes")).?;
        const before_allocated = countOf(before.get("allocated_bytes")).?;
        const before_version = stringOf(before.get("version")).?;
        const after_version = stringOf(item.get("version")).?;
        if (before_installed == installed and
            before_allocated == allocated and
            std.mem.eql(u8, before_version, after_version))
        {
            continue;
        }
        var record = builder.object();
        try builder.putString(&record, "name", name);
        try builder.put(&record, "installed_bytes_delta", .{
            .integer = delta(before_installed, installed),
        });
        try builder.put(&record, "allocated_bytes_delta", .{
            .integer = delta(before_allocated, allocated),
        });
        try builder.put(&record, "version_changed", .{
            .bool = !std.mem.eql(u8, before_version, after_version),
        });
        try changed.append(.{ .object = record });
    }

    var removed = builder.array();
    for (base_items) |entry| {
        const item = objectOf(entry).?;
        const name = stringOf(item.get("name")).?;
        if (seen.contains(name)) continue;
        var record = builder.object();
        try builder.putString(&record, "name", name);
        try builder.putCount(&record, "installed_bytes", countOf(item.get("installed_bytes")).?);
        try builder.putCount(&record, "allocated_bytes", countOf(item.get("allocated_bytes")).?);
        try removed.append(.{ .object = record });
    }

    var packages = builder.object();
    try builder.put(&packages, "added", .{ .array = added });
    try builder.put(&packages, "removed", .{ .array = removed });
    try builder.put(&packages, "changed", .{ .array = changed });
    return .{ .object = packages };
}
