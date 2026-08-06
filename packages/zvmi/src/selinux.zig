//! What both executors need to know about relabelling a target root, in one
//! place so the host, the privileged worker and the guest agent cannot drift.
//!
//! Nothing here reads a filesystem. It is the shape of the operation -- where
//! the tool lives, where the policy lives, what the command line is -- so that
//! the host can refuse a request the target cannot satisfy, and the two
//! backends can carry out the same operation rather than two similar ones.

const std = @import("std");

/// Where the labelling tool is looked for inside the target root, in order.
/// `setfiles` rather than `restorecon` because it takes the file-contexts file
/// as an argument instead of resolving the active policy through libselinux,
/// which needs a loaded policy and a mounted selinuxfs -- neither of which
/// exists in an executor that is not running the target's kernel.
pub const setfiles_candidates = [_][]const u8{
    "/usr/sbin/setfiles",
    "/sbin/setfiles",
    "/usr/bin/setfiles",
};

/// The target's own SELinux configuration, which names the policy in use.
pub const config_path = "/etc/selinux/config";

/// Directories excluded from the walk, when they exist in the target root.
///
/// A relabel is about the files the image carries. These four are either
/// kernel interfaces the executor mounted for the run or state that exists
/// only while it runs, so labelling them would spend time on bytes that are
/// not in the image and, for the pseudo-filesystems, on inodes whose labels
/// are decided by the kernel that mounts them rather than by any policy file.
pub const excluded_directories = [_][]const u8{
    "/proc",
    "/sys",
    "/dev",
    "/run",
};

/// The longest policy name accepted. Long enough for any real policy name and
/// short enough that the paths built from it stay well inside `PATH_MAX`.
pub const max_policy_name_bytes: usize = 64;

/// Whether `name` is a policy name that can be used to build a path. A policy
/// name reaches a path and an argument vector, so it is checked as input
/// rather than trusted: letters, digits, `.`, `-` and `_`, never empty, never
/// starting with a dot, so it cannot be `.`, `..`, or anything that leaves the
/// directory it names.
pub fn validPolicyName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_policy_name_bytes) return false;
    if (name[0] == '.') return false;
    for (name) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-', '_' => {},
        else => return false,
    };
    return true;
}

/// The file-contexts file of `policy`, written into `buffer`.
///
/// A caller-supplied buffer rather than an allocation because the guest agent
/// is libc-free and allocates as little as it can, and because the length is
/// bounded by `max_policy_name_bytes` either way.
pub fn fileContextsPath(buffer: []u8, policy: []const u8) error{ InvalidPolicy, NoSpaceLeft }![]const u8 {
    if (!validPolicyName(policy)) return error.InvalidPolicy;
    return std.fmt.bufPrint(buffer, "/etc/selinux/{s}/contexts/files/file_contexts", .{policy}) catch
        return error.NoSpaceLeft;
}

/// The policy `/etc/selinux/config` names, or nothing when it names none.
///
/// Parsed rather than assumed, and parsed from the target rather than from the
/// request, because the policy a relabel must use is whichever one the image
/// carries when the relabel runs -- which a package action in the same run can
/// have changed. Comments and blank lines are skipped; a `SELINUXTYPE` naming
/// something that is not a usable policy name is reported as absent, because a
/// name that cannot build a path is not a policy this can act on.
pub fn parseConfiguredPolicy(contents: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const equals = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..equals], " \t");
        if (!std.mem.eql(u8, key, "SELINUXTYPE")) continue;
        const value = std.mem.trim(u8, line[equals + 1 ..], " \t\"");
        if (!validPolicyName(value)) return null;
        return value;
    }
    return null;
}

test "parses the configured policy" {
    try std.testing.expectEqualStrings("targeted", parseConfiguredPolicy(
        "# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n",
    ).?);
    try std.testing.expectEqualStrings("mls", parseConfiguredPolicy(
        "  SELINUXTYPE = \"mls\"  \r\n",
    ).?);
    try std.testing.expect(parseConfiguredPolicy("SELINUX=enforcing\n") == null);
    try std.testing.expect(parseConfiguredPolicy("SELINUXTYPE=../escape\n") == null);
    try std.testing.expect(parseConfiguredPolicy("#SELINUXTYPE=targeted\n") == null);
}

test "rejects policy names that cannot build a path" {
    try std.testing.expect(validPolicyName("targeted"));
    try std.testing.expect(!validPolicyName(""));
    try std.testing.expect(!validPolicyName("."));
    try std.testing.expect(!validPolicyName(".."));
    try std.testing.expect(!validPolicyName("a/b"));
    try std.testing.expect(!validPolicyName("a b"));
    try std.testing.expect(!validPolicyName("a" ** (max_policy_name_bytes + 1)));
}

test "builds the file contexts path" {
    var buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/etc/selinux/targeted/contexts/files/file_contexts",
        try fileContextsPath(&buffer, "targeted"),
    );
    try std.testing.expectError(error.InvalidPolicy, fileContextsPath(&buffer, "../x"));
}
