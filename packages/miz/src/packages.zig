//! What both executors need to know about pinning a package transaction, in
//! one place so the host, the privileged worker and the guest agent cannot
//! drift.
//!
//! Nothing here reads a filesystem. It is the shape of the knowledge -- what a
//! pin is, how an `rpm -qa` record splits back into one, which records are
//! rpm's own bookkeeping rather than a package -- so that the host can refuse
//! a request the target cannot satisfy, and the two backends can enforce the
//! same lock rather than two similar ones.
//!
//! The same charter as `selinux.zig`, and for the same reason: this module
//! reaches the guest agent through `vm_control`, and the guest agent is a
//! static, libc-free PID 1 that imports `std` and nothing else.

const std = @import("std");

/// Where the package manager is looked for inside the target root. An absolute
/// path rather than a name on `PATH`, because the command runs in a chroot the
/// caller does not control the environment of.
pub const tool_path = "/usr/bin/tdnf";

/// Where the database tool is looked for. `rpm` rather than `tdnf` for the two
/// operations that are about the database rather than about a transaction:
/// reading the installed set, and importing trust.
pub const database_tool_path = "/usr/bin/rpm";

/// Package managers recognised **in order to be refused**, not in order to be
/// used.
///
/// This is not a dispatch table and must not become one. Nothing reads it to
/// decide what to run; it exists so that a run against a root this project
/// does not support can say what the image is rather than only what it is not
/// -- the same distinction `unsafe_chroot.findGuestGenerator` already draws
/// between a systemd-managed target and a target with no bootloader generator
/// at all.
///
/// The difference matters to whoever pointed a build at the wrong image. "No
/// `/usr/bin/tdnf` here" leaves them wondering whether the image is broken;
/// "this looks like a dpkg root, and both executing backends target the RPM
/// family" tells them what happened in one line.
pub const foreign_tool_paths = [_][]const u8{
    "/usr/bin/apt-get",
    "/usr/bin/dpkg",
    "/usr/bin/zypper",
    "/usr/bin/pacman",
    "/sbin/apk",
};

/// Which of the two tools a run actually needs, given what it was asked to do.
///
/// A root with no package manager is a legitimate thing to customize as long
/// as nothing asks it to install, so a run that needs neither must behave
/// exactly as it did before this check existed -- the same rule
/// `os_customization.applyServices` follows when it returns on an empty
/// service list before refusing anything.
///
/// The database tool is needed more often than the manager. Trust import is
/// `rpm --import` and runs for a request that declares repository trust and no
/// actions at all, while the installed-set inventory a transaction reads is
/// `rpm -qa`. So a transaction needs both and a bare trust import needs only
/// the second.
pub const ToolNeed = struct {
    manager: bool,
    database: bool,

    pub fn none(self: ToolNeed) bool {
        return !self.manager and !self.database;
    }
};

pub fn toolNeed(runs_transaction: bool, imports_trust: bool) ToolNeed {
    return .{
        .manager = runs_transaction,
        .database = runs_transaction or imports_trust,
    };
}

/// What a target root can and cannot satisfy. Deliberately not an error: the
/// two executors raise their own, and this module answers the question rather
/// than deciding how a backend reports it.
pub const ToolVerdict = enum {
    satisfied,
    missing_manager,
    missing_database,
};

/// Decided here rather than twice, so the host worker and the guest agent
/// cannot disagree about which root is customizable.
///
/// Presence is passed in rather than probed: this module reads no filesystem,
/// and on the `vm` backend the host cannot stat the target root at all.
pub fn toolVerdict(need: ToolNeed, manager_present: bool, database_present: bool) ToolVerdict {
    if (need.manager and !manager_present) return .missing_manager;
    if (need.database and !database_present) return .missing_database;
    return .satisfied;
}

/// The configuration the transaction is run under, inside the target root.
///
/// The target's own `/etc/tdnf` is deliberately not used: a run must depend on
/// the repositories the request declared and on nothing the input image
/// happened to carry.
pub const config_path = "/run/miz-tdnf.conf";

/// Where the declared repositories are written, inside the target root.
///
/// Under `/run` because it is a tmpfs the target already has and neither
/// backend publishes: the files carry credentials, and the run removes them
/// before anything is sealed.
pub const repository_directory = "/run/miz-repos";

/// The `.repo` file for a declared repository id, inside the target root.
///
/// The guest-visible path and only that. The privileged worker prefixes it
/// with the mounted root itself, because a shared module that knew about
/// `<root>` would be a shared module with opinions about the host's
/// filesystem.
pub fn repositoryPath(allocator: std.mem.Allocator, id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, repository_directory ++ "/{s}.repo", .{id});
}

/// Where a repository's trust key is staged for `rpm --import`, inside the
/// target root.
///
/// Numbered by the order the keys are walked in rather than by anything in the
/// key, so that two repositories declaring the same key still get two files and
/// neither backend has to parse a key to name the file it writes.
pub fn trustPath(allocator: std.mem.Allocator, index: usize) ![]u8 {
    return std.fmt.allocPrint(allocator, "/run/miz-trust-{d}.asc", .{index});
}

/// The `--qf` both backends ask rpm for.
///
/// `%{EPOCHNUM}` rather than `%{EPOCH}` because the second prints `(none)` for
/// a package without one, and the epoch is what makes
/// `parseInstalledRecord` decidable. It has to agree exactly with that
/// function, so the two live beside each other.
pub const installed_query_format = "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n";

/// The command that reads the installed set out of the target's rpm database.
pub fn installedQueryArgv() [4][]const u8 {
    return .{ database_tool_path, "-qa", "--qf", installed_query_format };
}

/// The command that adds a staged key to the target's rpm trust.
pub fn importTrustArgv(staged_path: []const u8) [3][]const u8 {
    return .{ database_tool_path, "--import", staged_path };
}

/// The exact identity, in the spelling tdnf accepts as a package spec.
///
/// The same string `coverRecord` reassembles and the same shape
/// `parseInstalledRecord` splits, which is what lets a run ask for the pinned
/// release outright instead of asking for the name and complaining afterwards.
pub fn pinnedSpec(allocator: std.mem.Allocator, pin: VersionLock) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}-{s}.{s}",
        .{ pin.name, pin.evr, pin.architecture },
    );
}

/// The `[main]` section both backends write to `config_path`.
///
/// `cache_directory` is the guest-visible path of a declared package cache, or
/// nothing. It is one-sided by design rather than by accident: a package cache
/// is a *host* directory bind-mounted into the target, and the vm backend
/// refuses `.cache` by name because the control channel carries a rendered
/// document rather than host files. So the asymmetry is a parameter the guest
/// passes `null` to, instead of a second body it maintains separately.
///
/// `cachedir` and `keepcache` are ordinary configuration keys rather than
/// command-line flags, which is what lets this work against the tdnf 3.x the
/// target images ship: the 4.0 flag that would name a cache directory on the
/// command line does not exist there. `keepcache` is what makes a populating
/// run leave the downloaded packages behind for the offline run to install
/// from; without it tdnf discards them once the transaction commits.
pub fn configBody(
    allocator: std.mem.Allocator,
    cache_directory: ?[]const u8,
) ![]u8 {
    const head = "[main]\ngpgcheck=1\nreposdir=" ++ repository_directory ++ "\n";
    if (cache_directory) |directory| {
        return std.fmt.allocPrint(
            allocator,
            head ++ "cachedir={s}\nkeepcache=1\n",
            .{directory},
        );
    }
    return allocator.dupe(u8, head);
}

/// What a declared package action is, independently of what either side's
/// action type carries.
///
/// Both `customize.PackageAction` and `vm_control.PackageAction` are tagged
/// with this, so `std.meta.activeTag` on either yields the same value and
/// `invocationFor` can answer for both.
pub const ActionKind = enum {
    install,
    remove,
    update_all,
    update_selected,
};

/// How an action reaches the package manager.
pub const Invocation = struct {
    /// The tdnf verb. Two of the four actions share one.
    verb: []const u8,
    /// Whether the names are rewritten to the exact identities the lock pins.
    ///
    /// False for `remove`, and that is the interesting one: a removal names
    /// what must not be installed, so asking to remove one exact version would
    /// silently leave any other in place.
    pinned: bool,
    /// Whether the declared repositories are enabled for this verb. A removal
    /// resolves entirely against the local database and has no reason to reach
    /// a network the run may not even have.
    repositories: bool,
};

pub fn invocationFor(kind: ActionKind) Invocation {
    return switch (kind) {
        .install => .{ .verb = "install", .pinned = true, .repositories = true },
        .remove => .{ .verb = "remove", .pinned = false, .repositories = false },
        .update_all => .{ .verb = "update", .pinned = false, .repositories = true },
        .update_selected => .{ .verb = "update", .pinned = true, .repositories = true },
    };
}

/// Everything a tdnf command line varies by.
pub const Transaction = struct {
    verb: []const u8,
    /// The repository ids to enable, or none. Every repository is disabled
    /// first and the declared ones enabled by id, so a repository the input
    /// image carried cannot take part in the transaction.
    repository_ids: []const []const u8 = &.{},
    /// tdnf's own refusal to fetch. A package the declared cache does not hold
    /// fails as `ERROR_TDNF_CACHE_DISABLED` rather than being downloaded, which
    /// is what makes an offline claim checkable instead of merely intended.
    ///
    /// Host-only in practice, for the reason `configBody` gives.
    cache_only: bool = false,
    names: []const []const u8 = &.{},
};

/// Appends the tdnf command line for a transaction.
///
/// Appends rather than returns, so that ownership of the `--enablerepo=`
/// elements it allocates stays exactly where each caller already put it: the
/// privileged worker frees its argv, the guest agent runs once and does not.
pub fn appendTransactionArgv(
    argv: *std.array_list.Managed([]const u8),
    transaction: Transaction,
) !void {
    try argv.appendSlice(&.{ tool_path, "--config", config_path, "--disablerepo=*" });
    if (transaction.cache_only) try argv.append("--cacheonly");
    for (transaction.repository_ids) |id| {
        try argv.append(try std.fmt.allocPrint(
            argv.allocator,
            "--enablerepo={s}",
            .{id},
        ));
    }
    try argv.appendSlice(&.{ transaction.verb, "-y" });
    try argv.appendSlice(transaction.names);
}

/// One package pinned to an exact rpm identity.
///
/// There is no repository field, and there could not honestly be one: rpm's
/// database does not record which repository a package came from, and the
/// `repoquery --installed` route to it is documented as unreliable under the
/// DNF5 backend Azure Linux ships as tdnf -- `reponame` is answered for
/// available packages and not for installed ones. So an emitted lock could
/// only have copied the sole declared repository's id, or invented one, and a
/// verifier reading it back would be checking a claim the run never made. The
/// repositories a transaction was allowed to use are already declared in the
/// request, hashed into the plan, and recorded in provenance; the lock's job
/// is the part that is not, which is the exact version.
///
/// One type with two public spellings. A caller declares a
/// `customize.PackageVersionLock`; the control document carries a
/// `vm_control.PackagePin`. Both names read correctly where they are used and
/// both are public API, so both stay -- but as aliases of this, because when
/// they were separate structs with identical fields the host could not call
/// `vm_control`'s pin helpers with its own locks and re-implemented four of
/// them instead. That is the whole mechanism by which the two executors
/// drifted apart, and an alias closes it.
pub const VersionLock = struct {
    name: []const u8,
    /// rpm's `EPOCH:VERSION-RELEASE`, with the epoch always written even when
    /// it is zero. Required in full rather than accepted as a bare version,
    /// because `1.2.3` and `0:1.2.3-4.azl3` are different amounts of pinning
    /// and only one of them is a lock -- a caller who wrote the short form and
    /// got a silent partial match would have a build that reports itself
    /// reproducible and is not.
    evr: []const u8,
    /// rpm's `%{ARCH}`. Part of identity rather than decoration: `noarch` and
    /// `x86_64` builds of one name at one EVR are different packages, and a
    /// multilib root can hold two of them at once.
    architecture: []const u8,
};

/// Splits an `rpm -qa` record of the form `NAME-EPOCH:VERSION-RELEASE.ARCH`
/// back into its parts, or nothing if it is not one.
///
/// Unambiguous despite having no reserved delimiter, and worth stating why
/// because the obvious readings are both wrong. Splitting on the first `-`
/// fails for a name like `python3-libs`; splitting on the first `.` fails for
/// a release like `1.azl3`. What makes it decidable is the epoch: it is the
/// only field that may contain `:`, and it may not contain `-`, so the `-`
/// immediately before the `:` is always the boundary between the name and the
/// version. The architecture is whatever follows the last `.`, because no rpm
/// architecture contains one while a release routinely does.
///
/// This is how a completed run turns its own installed set into a lock the
/// next run can state, so it has to agree exactly with the `--qf` format both
/// backends ask rpm for.
pub fn parseInstalledRecord(record: []const u8) ?VersionLock {
    const architecture_dot = std.mem.lastIndexOfScalar(u8, record, '.') orelse return null;
    const architecture = record[architecture_dot + 1 ..];
    if (architecture.len == 0) return null;
    const head = record[0..architecture_dot];
    const colon = std.mem.indexOfScalar(u8, head, ':') orelse return null;
    const name_end = std.mem.lastIndexOfScalar(u8, head[0..colon], '-') orelse return null;
    if (name_end == 0) return null;
    const evr = head[name_end + 1 ..];
    // A release as well as a version: the `-` that separates them has to come
    // after the epoch, or this is a record rpm did not write.
    if (std.mem.indexOfScalarPos(u8, evr, colon - name_end, '-') == null) return null;
    return .{
        .name = head[0..name_end],
        .evr = evr,
        .architecture = architecture,
    };
}

/// Finds the pin for a package name, or nothing.
///
/// Linear because a lock is the closure of one transaction rather than of a
/// distribution: tens of entries, walked a handful of times.
pub fn find(pins: []const VersionLock, name: []const u8) ?VersionLock {
    for (pins) |pin| {
        if (std.mem.eql(u8, pin.name, name)) return pin;
    }
    return null;
}

/// Whether a `NAME-EPOCH:VERSION-RELEASE.ARCH` record is one of these pins.
///
/// Reassembles each pin and compares whole strings rather than splitting the
/// record, because the record has no delimiter a package name may not also
/// contain: `foo-1:2-3.noarch` could be `foo` at `1:2-3` or `foo-1` at
/// something else, and only equality against a candidate decides it.
pub fn coverRecord(pins: []const VersionLock, record: []const u8) bool {
    for (pins) |pin| {
        if (record.len != pin.name.len + pin.evr.len + pin.architecture.len + 2) continue;
        if (!std.mem.startsWith(u8, record, pin.name)) continue;
        if (record[pin.name.len] != '-') continue;
        const rest = record[pin.name.len + 1 ..];
        if (!std.mem.startsWith(u8, rest, pin.evr)) continue;
        if (rest[pin.evr.len] != '.') continue;
        if (!std.mem.eql(u8, rest[pin.evr.len + 1 ..], pin.architecture)) continue;
        return true;
    }
    return false;
}

/// Whether an `rpm -qa` record is one of rpm's own trust pseudo-packages
/// rather than a package a transaction installed.
///
/// `rpm --import` records each trusted key as `gpg-pubkey-<keyid>-<timestamp>`
/// with `%{ARCH}` of `(none)`, and both backends import the declared
/// repository trust before they run anything. Ordering the baseline read after
/// the import already keeps the declared keys out of the delta; this is for
/// the ones a package transaction imports on its own, which no caller declared
/// and no lock could pin -- `(none)` is not an architecture the pin rules
/// accept, so a lock naming one could never be restated.
pub fn isTrustPseudoPackage(record: []const u8) bool {
    return std.mem.startsWith(u8, record, "gpg-pubkey-") and
        std.mem.endsWith(u8, record, ".(none)");
}

/// The key rpm derived from imported trust, without the constant `(none)`
/// architecture rpm gives every one of them.
pub fn trustKeyIdentity(record: []const u8) []const u8 {
    return record[0 .. record.len - ".(none)".len];
}

test "parseInstalledRecord splits the records rpm writes and refuses the rest" {
    const cases = [_]struct {
        record: []const u8,
        expected: ?VersionLock,
        why: []const u8,
    }{
        .{
            .record = "bash-0:5.2.15-1.azl3.x86_64",
            .expected = .{ .name = "bash", .evr = "0:5.2.15-1.azl3", .architecture = "x86_64" },
            .why = "the ordinary shape, with a release that itself contains a dot",
        },
        .{
            .record = "python3-libs-0:3.12.3-2.azl3.aarch64",
            .expected = .{ .name = "python3-libs", .evr = "0:3.12.3-2.azl3", .architecture = "aarch64" },
            .why = "a name containing '-', which splitting on the first '-' would break",
        },
        .{
            .record = "tzdata-0:2024a-1.azl3.noarch",
            .expected = .{ .name = "tzdata", .evr = "0:2024a-1.azl3", .architecture = "noarch" },
            .why = "noarch is an architecture like any other",
        },
        .{
            .record = "bash-5.2.15-1.azl3.x86_64",
            .expected = null,
            .why = "no epoch, so the name/version boundary is not decidable",
        },
        .{
            .record = "bash-0:5.2.15.x86_64",
            .expected = null,
            .why = "an epoch and a version but no release",
        },
        .{
            .record = "bash-0:5.2.15-1.azl3",
            .expected = .{ .name = "bash", .evr = "0:5.2.15-1", .architecture = "azl3" },
            .why = "a record with no architecture is not detectable as one: the rule takes whatever follows the last dot, and a release ending in `.azl3` looks exactly like one. This is why both backends ask rpm for `%{ARCH}` as its own `--qf` field rather than letting a caller hand over a bare NEVR",
        },
        .{
            .record = "-0:5.2.15-1.azl3.x86_64",
            .expected = null,
            .why = "an empty name is not a package",
        },
        .{
            .record = "",
            .expected = null,
            .why = "an empty record",
        },
    };
    for (cases) |case| {
        const actual = parseInstalledRecord(case.record);
        if (case.expected) |expected| {
            try std.testing.expect(actual != null);
            try std.testing.expectEqualStrings(expected.name, actual.?.name);
            try std.testing.expectEqualStrings(expected.evr, actual.?.evr);
            try std.testing.expectEqualStrings(expected.architecture, actual.?.architecture);
        } else {
            try std.testing.expect(actual == null);
        }
    }
}

test "coverRecord compares whole specs rather than guessing the name boundary" {
    const pins = [_]VersionLock{
        .{ .name = "foo", .evr = "1:2-3", .architecture = "noarch" },
        .{ .name = "bash", .evr = "0:5.2.15-1.azl3", .architecture = "x86_64" },
    };
    const cases = [_]struct {
        record: []const u8,
        covered: bool,
        why: []const u8,
    }{
        .{
            .record = "foo-1:2-3.noarch",
            .covered = true,
            .why = "the pin reassembled exactly",
        },
        .{
            .record = "bash-0:5.2.15-1.azl3.x86_64",
            .covered = true,
            .why = "a second pin in the same list",
        },
        .{
            .record = "foo-1:2-3.x86_64",
            .covered = false,
            .why = "same name and EVR, different architecture: a different package",
        },
        .{
            .record = "foo-1:2-4.noarch",
            .covered = false,
            .why = "a release the lock did not pin",
        },
        .{
            .record = "foo-1-2:3.noarch",
            .covered = false,
            .why = "the ambiguity the whole-string comparison exists for: this is package 'foo-1', which no pin names, and a name-then-version match would have accepted it against pin 'foo'",
        },
        .{
            .record = "foo-1:2-3.noarch.x86_64",
            .covered = false,
            .why = "longer than the pin, so the length check rejects it before any prefix match",
        },
    };
    for (cases) |case| {
        try std.testing.expectEqual(case.covered, coverRecord(&pins, case.record));
    }
}

test "find returns the pin for a name and nothing for an unpinned one" {
    const pins = [_]VersionLock{
        .{ .name = "foo", .evr = "1:2-3", .architecture = "noarch" },
        .{ .name = "bash", .evr = "0:5.2.15-1.azl3", .architecture = "x86_64" },
    };
    try std.testing.expectEqualStrings("0:5.2.15-1.azl3", find(&pins, "bash").?.evr);
    try std.testing.expect(find(&pins, "openssh") == null);
    try std.testing.expect(find(&.{}, "bash") == null);
}

test "trust pseudo-packages are recognised by both of rpm's markers" {
    const cases = [_]struct {
        record: []const u8,
        pseudo: bool,
        why: []const u8,
    }{
        .{
            .record = "gpg-pubkey-3135ce90-5e6f6e2f.(none)",
            .pseudo = true,
            .why = "the shape rpm --import writes",
        },
        .{
            .record = "gpg-pubkey-3135ce90-5e6f6e2f.x86_64",
            .pseudo = false,
            .why = "the name prefix alone is not enough: a real package could carry it",
        },
        .{
            .record = "bash-0:5.2.15-1.azl3.(none)",
            .pseudo = false,
            .why = "the (none) architecture alone is not enough either",
        },
    };
    for (cases) |case| {
        try std.testing.expectEqual(case.pseudo, isTrustPseudoPackage(case.record));
    }
    try std.testing.expectEqualStrings(
        "gpg-pubkey-3135ce90-5e6f6e2f",
        trustKeyIdentity("gpg-pubkey-3135ce90-5e6f6e2f.(none)"),
    );
}

test "the transaction argv is the one both backends used to spell for themselves" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        transaction: Transaction,
        expected: []const []const u8,
        why: []const u8,
    }{
        .{
            .transaction = .{
                .verb = "install",
                .repository_ids = &.{ "base", "updates" },
                .names = &.{"strace-0:6.8-1.azl3.x86_64"},
            },
            .expected = &.{
                "/usr/bin/tdnf",
                "--config",
                "/run/miz-tdnf.conf",
                "--disablerepo=*",
                "--enablerepo=base",
                "--enablerepo=updates",
                "install",
                "-y",
                "strace-0:6.8-1.azl3.x86_64",
            },
            .why = "every repository disabled first and the declared ones enabled by id, in order",
        },
        .{
            .transaction = .{ .verb = "remove", .names = &.{"strace"} },
            .expected = &.{
                "/usr/bin/tdnf",
                "--config",
                "/run/miz-tdnf.conf",
                "--disablerepo=*",
                "remove",
                "-y",
                "strace",
            },
            .why = "a removal resolves against the local database, so no repository is enabled",
        },
        .{
            .transaction = .{ .verb = "update", .repository_ids = &.{"base"} },
            .expected = &.{
                "/usr/bin/tdnf",
                "--config",
                "/run/miz-tdnf.conf",
                "--disablerepo=*",
                "--enablerepo=base",
                "update",
                "-y",
            },
            .why = "update_all names nothing, so the argv simply ends after -y",
        },
        .{
            .transaction = .{
                .verb = "install",
                .repository_ids = &.{"base"},
                .cache_only = true,
                .names = &.{"strace"},
            },
            .expected = &.{
                "/usr/bin/tdnf",
                "--config",
                "/run/miz-tdnf.conf",
                "--disablerepo=*",
                "--cacheonly",
                "--enablerepo=base",
                "install",
                "-y",
                "strace",
            },
            .why = "the offline claim, before the repositories rather than after them",
        },
    };
    for (cases) |case| {
        var argv: std.array_list.Managed([]const u8) = .init(allocator);
        defer {
            for (argv.items) |item| {
                if (std.mem.startsWith(u8, item, "--enablerepo=")) allocator.free(item);
            }
            argv.deinit();
        }
        try appendTransactionArgv(&argv, case.transaction);
        try std.testing.expectEqual(case.expected.len, argv.items.len);
        for (case.expected, argv.items) |want, got| try std.testing.expectEqualStrings(want, got);
    }
}

test "every action maps to one verb, and only two of them are rewritten by a lock" {
    const cases = [_]struct {
        kind: ActionKind,
        verb: []const u8,
        pinned: bool,
        repositories: bool,
        why: []const u8,
    }{
        .{
            .kind = .install,
            .verb = "install",
            .pinned = true,
            .repositories = true,
            .why = "the ordinary case",
        },
        .{
            .kind = .remove,
            .verb = "remove",
            .pinned = false,
            .repositories = false,
            .why = "a removal names what must not be installed; removing one exact version would leave any other in place",
        },
        .{
            .kind = .update_all,
            .verb = "update",
            .pinned = false,
            .repositories = true,
            .why = "names nothing, so there is nothing for a pin to rewrite",
        },
        .{
            .kind = .update_selected,
            .verb = "update",
            .pinned = true,
            .repositories = true,
            .why = "the same verb as update_all and a different answer to both other questions",
        },
    };
    for (cases) |case| {
        const invocation = invocationFor(case.kind);
        try std.testing.expectEqualStrings(case.verb, invocation.verb);
        try std.testing.expectEqual(case.pinned, invocation.pinned);
        try std.testing.expectEqual(case.repositories, invocation.repositories);
    }
}

test "the config body differs from itself only by a cache the guest cannot have" {
    const allocator = std.testing.allocator;

    const without = try configBody(allocator, null);
    defer allocator.free(without);
    try std.testing.expectEqualStrings(
        "[main]\ngpgcheck=1\nreposdir=/run/miz-repos\n",
        without,
    );

    const with = try configBody(allocator, "/run/miz-cache");
    defer allocator.free(with);
    try std.testing.expectEqualStrings(
        "[main]\ngpgcheck=1\nreposdir=/run/miz-repos\ncachedir=/run/miz-cache\nkeepcache=1\n",
        with,
    );

    // The asymmetry is a parameter rather than a fork: the body the guest
    // agent writes is a prefix of the one the privileged worker writes.
    try std.testing.expect(std.mem.startsWith(u8, with, without));
}

test "the paths and the query format are the ones the other side reads back" {
    const allocator = std.testing.allocator;

    const repository = try repositoryPath(allocator, "azurelinux-base");
    defer allocator.free(repository);
    try std.testing.expectEqualStrings(
        "/run/miz-repos/azurelinux-base.repo",
        repository,
    );
    // The `.repo` files have to be where the config says to look for them, or
    // a transaction runs against no repository at all and says so only by
    // failing to resolve.
    try std.testing.expect(std.mem.startsWith(u8, repository, repository_directory));

    const trust = try trustPath(allocator, 2);
    defer allocator.free(trust);
    try std.testing.expectEqualStrings("/run/miz-trust-2.asc", trust);

    const query = installedQueryArgv();
    try std.testing.expectEqualStrings("/usr/bin/rpm", query[0]);
    try std.testing.expectEqualStrings("-qa", query[1]);
    try std.testing.expectEqualStrings("--qf", query[2]);
    try std.testing.expectEqualStrings(
        "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n",
        query[3],
    );

    const import = importTrustArgv("/run/miz-trust-0.asc");
    try std.testing.expectEqualStrings("/usr/bin/rpm", import[0]);
    try std.testing.expectEqualStrings("--import", import[1]);
    try std.testing.expectEqualStrings("/run/miz-trust-0.asc", import[2]);
}

test "a pinned spec is the string the record parser splits back" {
    const allocator = std.testing.allocator;
    const pin: VersionLock = .{
        .name = "python3-libs",
        .evr = "0:3.12.3-2.azl3",
        .architecture = "aarch64",
    };
    const spec = try pinnedSpec(allocator, pin);
    defer allocator.free(spec);
    try std.testing.expectEqualStrings("python3-libs-0:3.12.3-2.azl3.aarch64", spec);

    // The round trip is the point: what a run asks tdnf for is what it later
    // matches the rpm database against, so the two spellings cannot drift.
    const parsed = parseInstalledRecord(spec).?;
    try std.testing.expectEqualStrings(pin.name, parsed.name);
    try std.testing.expectEqualStrings(pin.evr, parsed.evr);
    try std.testing.expectEqualStrings(pin.architecture, parsed.architecture);
    try std.testing.expect(coverRecord(&.{pin}, spec));
}

test "a run that installs nothing and imports no trust needs no tool at all" {
    // The regression fence for the whole check: a minimal root with no package
    // manager stays customizable, and behaves exactly as it did before the
    // probe existed.
    const need = toolNeed(false, false);
    try std.testing.expect(need.none());
    try std.testing.expectEqual(ToolVerdict.satisfied, toolVerdict(need, false, false));
}

test "importing trust needs the database tool and not the manager" {
    // `rpm --import` runs for a request that declares repository trust and no
    // actions, so a root with rpm and no tdnf can still satisfy it.
    const need = toolNeed(false, true);
    try std.testing.expect(!need.manager);
    try std.testing.expect(need.database);
    try std.testing.expectEqual(ToolVerdict.satisfied, toolVerdict(need, false, true));
    try std.testing.expectEqual(ToolVerdict.missing_database, toolVerdict(need, true, false));
}

test "a transaction needs both tools, and the manager is reported first" {
    const need = toolNeed(true, false);
    try std.testing.expect(need.manager);
    // Reported first because it is the one the request named: a root with
    // neither is a root with no package manager, which is the more useful
    // half of the answer.
    try std.testing.expectEqual(ToolVerdict.missing_manager, toolVerdict(need, false, false));
    try std.testing.expectEqual(ToolVerdict.missing_database, toolVerdict(need, true, false));
    try std.testing.expectEqual(ToolVerdict.satisfied, toolVerdict(need, true, true));
}

test "the foreign table names other families and never this one" {
    // It exists to refuse, not to dispatch. A path this project actually runs
    // appearing here would turn a supported root into a refused one.
    for (foreign_tool_paths) |candidate| {
        try std.testing.expect(!std.mem.eql(u8, candidate, tool_path));
        try std.testing.expect(!std.mem.eql(u8, candidate, database_tool_path));
        try std.testing.expect(candidate[0] == '/');
    }
}
