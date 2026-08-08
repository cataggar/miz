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
