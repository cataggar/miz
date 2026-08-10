//! Direct `/etc/passwd`, `/etc/shadow`, `/etc/group` editing -- this
//! project's `useradd`/`usermod -L` equivalent, deliberately not shelling
//! out to those binaries (see issue #112). Password-based authentication
//! (`UserPassword` in `ovf-env.xml`) is explicitly out of scope: accounts
//! are always created locked (SSH-key-only), since correctly hashing a
//! password to match glibc's `crypt(3)` is real, security-sensitive work
//! that deserves its own follow-up rather than a rushed reimplementation.
//!
//! All the parsing/line-building logic here is pure (transforms file
//! *content* strings, never touches a real file), so it's fully unit
//! testable; only `createUserIfMissing`/`lockRootPasswordInPlace` (in the
//! impure half at the bottom) perform real file I/O, and even those take
//! an already-open `etc_dir`/`home_parent_dir` so tests can point them at a
//! throwaway temp directory instead of the real `/etc` and `/home`.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const min_uid: u32 = 1000;
pub const max_uid: u32 = 60_000;
pub const default_shell = "/bin/bash";

/// A day-granularity "days since the Unix epoch", matching `/etc/shadow`'s
/// `lastchg` field convention (what real `passwd`/`chage` write there).
pub fn daysSinceEpoch(unix_seconds: i64) i64 {
    return @divTrunc(unix_seconds, 86_400);
}

/// Returns true if `username` already has a line in `passwd_content`
/// (matching upstream's idempotent `useradd` skip).
pub fn userExists(passwd_content: []const u8, username: []const u8) bool {
    return fieldZeroEquals(passwd_content, username);
}

fn fieldZeroEquals(content: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.mem.eql(u8, line[0..colon], name)) return true;
    }
    return false;
}

fn idInUse(content: []const u8, id: u32) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        _ = fields.next() orelse continue; // name
        _ = fields.next() orelse continue; // password placeholder
        const id_field = fields.next() orelse continue;
        const existing = std.fmt.parseInt(u32, id_field, 10) catch continue;
        if (existing == id) return true;
    }
    return false;
}

/// Returns the first free id in the normal login-user range. Choosing the
/// first gap avoids treating reserved high IDs such as `nobody` (65534) as
/// the end of the allocatable range.
pub fn nextFreeId(content: []const u8, min_id: u32) !u32 {
    var candidate = min_id;
    while (candidate <= max_uid) : (candidate += 1) {
        if (!idInUse(content, candidate)) return candidate;
    }
    return error.NoAvailableUserId;
}

fn nextFreeUserId(passwd_content: []const u8, group_content: []const u8) !u32 {
    var candidate = min_uid;
    while (candidate <= max_uid) : (candidate += 1) {
        if (!idInUse(passwd_content, candidate) and !idInUse(group_content, candidate)) return candidate;
    }
    return error.NoAvailableUserId;
}

/// Appends a new `useradd -m`-equivalent entry to `passwd_content`
/// (`username:x:uid:gid:comment:home:shell`). Ensures the result ends with
/// exactly one trailing newline regardless of whether `passwd_content` did.
pub fn appendPasswdLine(allocator: Allocator, passwd_content: []const u8, username: []const u8, uid: u32, gid: u32, home: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, passwd_content.len + 128);
    errdefer out.deinit();
    try appendTrimmedWithNewline(&out.writer, passwd_content);
    try out.writer.print("{s}:x:{d}:{d}::{s}:{s}\n", .{ username, uid, gid, home, default_shell });
    return out.toOwnedSlice();
}

/// Appends a locked (`!`, i.e. no valid password -- SSH-key-only)
/// `/etc/shadow` entry for a freshly created user.
pub fn appendShadowLine(allocator: Allocator, shadow_content: []const u8, username: []const u8, last_change_days: i64) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, shadow_content.len + 96);
    errdefer out.deinit();
    try appendTrimmedWithNewline(&out.writer, shadow_content);
    try out.writer.print("{s}:!:{d}:0:99999:7:::\n", .{ username, last_change_days });
    return out.toOwnedSlice();
}

/// Appends a new private group for `username` (`useradd`'s default
/// user-private-group scheme: a group named after the user, with `gid`
/// matching the user's `uid`).
pub fn appendGroupLine(allocator: Allocator, group_content: []const u8, username: []const u8, gid: u32) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, group_content.len + 64);
    errdefer out.deinit();
    try appendTrimmedWithNewline(&out.writer, group_content);
    try out.writer.print("{s}:x:{d}:\n", .{ username, gid });
    return out.toOwnedSlice();
}

fn appendTrimmedWithNewline(w: *std.Io.Writer, content: []const u8) !void {
    const trimmed = std.mem.trimEnd(u8, content, "\n");
    if (trimmed.len == 0) return;
    try w.writeAll(trimmed);
    try w.writeAll("\n");
}

/// Locks the `root` account's password in `shadow_content` -- prepends `!`
/// to its existing hash field (standard `passwd -l`/`usermod -L`
/// semantics), or sets the field to `!` if it was already empty. Unlike
/// upstream's `del_root_password` (which replaces `root`'s *entire*
/// `/etc/passwd` line with a hardcoded minimal one, discarding its real
/// UID/home/shell), this only ever touches `/etc/shadow`'s password field,
/// which is both the standard way to lock an account and doesn't risk
/// corrupting root's other fields. Idempotent: a line already starting
/// with `!` is left untouched. Returns `error.RootEntryNotFound` if there's
/// no `root:` line to lock.
pub fn lockRootPassword(allocator: Allocator, shadow_content: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, shadow_content.len + 8);
    errdefer out.deinit();

    var found = false;
    var lines = std.mem.splitScalar(u8, shadow_content, '\n');
    var first = true;
    while (lines.next()) |line| {
        if (!first) try out.writer.writeAll("\n");
        first = false;
        if (line.len == 0) continue;

        const name_colon = std.mem.indexOfScalar(u8, line, ':') orelse {
            try out.writer.writeAll(line);
            continue;
        };
        const name = line[0..name_colon];
        if (!std.mem.eql(u8, name, "root")) {
            try out.writer.writeAll(line);
            continue;
        }
        found = true;
        const hash_end = std.mem.indexOfScalarPos(u8, line, name_colon + 1, ':') orelse line.len;
        const hash = line[name_colon + 1 .. hash_end];
        const rest_of_line = line[hash_end..]; // remaining fields, including their leading ':', or "" if none

        if (hash.len == 0) {
            try out.writer.print("{s}:!{s}", .{ name, rest_of_line });
        } else if (std.mem.startsWith(u8, hash, "!")) {
            try out.writer.writeAll(line); // already locked, unchanged
        } else {
            try out.writer.print("{s}:!{s}{s}", .{ name, hash, rest_of_line });
        }
    }
    if (!found) return error.RootEntryNotFound;

    return out.toOwnedSlice();
}

test "userExists finds an existing user by the first field only" {
    const passwd = "root:x:0:0::/root:/bin/bash\nazureuser:x:1000:1000::/home/azureuser:/bin/bash\n";
    try std.testing.expect(userExists(passwd, "azureuser"));
    try std.testing.expect(userExists(passwd, "root"));
    try std.testing.expect(!userExists(passwd, "nobody-here"));
}

test "lookupIds resolves an existing account and reports a missing one as null" {
    const passwd = "root:x:0:0::/root:/bin/bash\ng:x:1000:1000::/home/g:/bin/bash\n";
    const found = (try lookupIds(passwd, "g")).?;
    try std.testing.expectEqual(@as(u32, 1000), found.uid);
    try std.testing.expectEqual(@as(u32, 1000), found.gid);

    const root_ids = (try lookupIds(passwd, "root")).?;
    try std.testing.expectEqual(@as(u32, 0), root_ids.uid);

    // A ResourceDisk.Owner naming an account that was never created is a
    // warning, not an error, so this has to be distinguishable from uid 0.
    try std.testing.expect(try lookupIds(passwd, "nobody-here") == null);
}

test "nextFreeId picks min_id when nothing at or above it is in use" {
    const passwd = "root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n";
    try std.testing.expectEqual(@as(u32, 1000), try nextFreeId(passwd, 1000));
}

test "nextFreeId returns the first free id" {
    const passwd = "root:x:0:0::/root:/bin/bash\nfirst:x:1000:1000::/home/first:/bin/bash\nsecond:x:1001:1001::/home/second:/bin/bash\n";
    try std.testing.expectEqual(@as(u32, 1002), try nextFreeId(passwd, 1000));
}

test "nextFreeId ignores the reserved nobody id" {
    const passwd = "root:x:0:0::/root:/bin/bash\nnobody:x:65534:65534:Nobody:/:/usr/sbin/nologin\n";
    try std.testing.expectEqual(@as(u32, 1000), try nextFreeId(passwd, 1000));
}

test "nextFreeUserId avoids existing user and group ids" {
    const passwd = "root:x:0:0::/root:/bin/bash\nfirst:x:1000:1000::/home/first:/bin/bash\nnobody:x:65534:65534:Nobody:/:/usr/sbin/nologin\n";
    const group = "root:x:0:\nreserved:x:1001:\nnobody:x:65534:\n";
    try std.testing.expectEqual(@as(u32, 1002), try nextFreeUserId(passwd, group));
}

test "appendPasswdLine appends a well-formed entry with a single trailing newline" {
    const allocator = std.testing.allocator;
    const result = try appendPasswdLine(allocator, "root:x:0:0::/root:/bin/bash\n", "azureuser", 1000, 1000, "/home/azureuser");
    defer allocator.free(result);
    try std.testing.expectEqualStrings(
        "root:x:0:0::/root:/bin/bash\nazureuser:x:1000:1000::/home/azureuser:/bin/bash\n",
        result,
    );
}

test "appendPasswdLine tolerates a missing trailing newline in the input" {
    const allocator = std.testing.allocator;
    const result = try appendPasswdLine(allocator, "root:x:0:0::/root:/bin/bash", "u", 1000, 1000, "/home/u");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\n", result);
}

test "appendShadowLine appends a locked entry" {
    const allocator = std.testing.allocator;
    const result = try appendShadowLine(allocator, "root:!:19000:0:99999:7:::\n", "azureuser", 19700);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(
        "root:!:19000:0:99999:7:::\nazureuser:!:19700:0:99999:7:::\n",
        result,
    );
}

test "appendGroupLine appends a user-private group" {
    const allocator = std.testing.allocator;
    const result = try appendGroupLine(allocator, "root:x:0:\n", "azureuser", 1000);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("root:x:0:\nazureuser:x:1000:\n", result);
}

test "lockRootPassword prepends ! to an existing hash" {
    const allocator = std.testing.allocator;
    const result = try lockRootPassword(allocator, "root:$6$abc$def:19000:0:99999:7:::\nazureuser:!:19700:0:99999:7:::\n");
    defer allocator.free(result);
    try std.testing.expectEqualStrings(
        "root:!$6$abc$def:19000:0:99999:7:::\nazureuser:!:19700:0:99999:7:::\n",
        result,
    );
}

test "lockRootPassword sets an empty hash directly to !" {
    const allocator = std.testing.allocator;
    const result = try lockRootPassword(allocator, "root::19000:0:99999:7:::\n");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("root:!:19000:0:99999:7:::\n", result);
}

test "lockRootPassword is idempotent when already locked" {
    const allocator = std.testing.allocator;
    const result = try lockRootPassword(allocator, "root:!$6$abc$def:19000:0:99999:7:::\n");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("root:!$6$abc$def:19000:0:99999:7:::\n", result);
}

test "lockRootPassword fails when there is no root entry" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.RootEntryNotFound, lockRootPassword(allocator, "azureuser:!:19700:0:99999:7:::\n"));
}

// ---------------------------------------------------------------------
// Impure half: real file I/O, scoped to a caller-provided directory so
// tests can safely point it at a temp directory instead of the real
// `/etc`/`/home`.
// ---------------------------------------------------------------------

pub const read_limit: std.Io.Limit = .limited(4 * 1024 * 1024);

pub const CreateUserResult = struct {
    uid: u32,
    gid: u32,
    home: []const u8,
    already_existed: bool,
};

/// Idempotently creates `username` (skipping straight to computing its
/// existing uid/gid if it's already present): appends passwd/shadow/group
/// entries and creates its home directory (mode `0700`, owned by the new
/// uid/gid). `etc_dir` and `home_parent_dir` are already-open directory
/// handles (production passes `/etc` and `/home`; tests pass a temp dir)
/// so this performs no hardcoded-absolute-path I/O.
pub fn createUserIfMissing(
    allocator: Allocator,
    etc_dir: std.Io.Dir,
    home_parent_dir: std.Io.Dir,
    io: std.Io,
    username: []const u8,
    now_unix_seconds: i64,
) !CreateUserResult {
    const passwd_content = try etc_dir.readFileAlloc(io, "passwd", allocator, read_limit);
    defer allocator.free(passwd_content);

    if (userExists(passwd_content, username)) {
        const uid, const gid = try findExistingIds(passwd_content, username);
        const home = try std.fmt.allocPrint(allocator, "/home/{s}", .{username});
        return .{ .uid = uid, .gid = gid, .home = home, .already_existed = true };
    }

    const group_content = try etc_dir.readFileAlloc(io, "group", allocator, read_limit);
    defer allocator.free(group_content);
    const shadow_content = try etc_dir.readFileAlloc(io, "shadow", allocator, read_limit);
    defer allocator.free(shadow_content);

    const uid = try nextFreeUserId(passwd_content, group_content);
    const gid = uid; // user-private-group scheme: gid mirrors uid

    const home = try std.fmt.allocPrint(allocator, "/home/{s}", .{username});
    errdefer allocator.free(home);

    const new_passwd = try appendPasswdLine(allocator, passwd_content, username, uid, gid, home);
    defer allocator.free(new_passwd);
    const new_group = try appendGroupLine(allocator, group_content, username, gid);
    defer allocator.free(new_group);
    const new_shadow = try appendShadowLine(allocator, shadow_content, username, daysSinceEpoch(now_unix_seconds));
    defer allocator.free(new_shadow);

    try etc_dir.writeFile(io, .{ .sub_path = "passwd", .data = new_passwd });
    try etc_dir.writeFile(io, .{ .sub_path = "group", .data = new_group });
    try etc_dir.writeFile(io, .{ .sub_path = "shadow", .data = new_shadow, .flags = .{ .truncate = true, .permissions = .fromMode(0o600) } });

    try home_parent_dir.createDirPath(io, username);
    var new_home_dir = try home_parent_dir.openDir(io, username, .{ .iterate = true });
    defer new_home_dir.close(io);
    try new_home_dir.setPermissions(io, .fromMode(0o700));
    try new_home_dir.setOwner(io, uid, gid);

    return .{ .uid = uid, .gid = gid, .home = home, .already_existed = false };
}

/// A resolved account's numeric ids, as `chown(2)` wants them.
pub const Ids = struct { uid: u32, gid: u32 };

/// Resolves an existing account's uid/gid out of `/etc/passwd` content,
/// returning `null` when there is no such account. Callers that treat a
/// missing account as recoverable (`main.zig`'s `ResourceDisk.Owner`
/// handling warns and leaves the mount root-owned) want this rather than
/// `findExistingIds`, whose `error.UserNotFound` is a genuine inconsistency
/// in the one place it is used -- `createUserIfMissing` only calls it after
/// `userExists` has already said yes.
pub fn lookupIds(passwd_content: []const u8, username: []const u8) !?Ids {
    if (!userExists(passwd_content, username)) return null;
    const uid, const gid = try findExistingIds(passwd_content, username);
    return .{ .uid = uid, .gid = gid };
}

fn findExistingIds(passwd_content: []const u8, username: []const u8) !struct { u32, u32 } {
    var lines = std.mem.splitScalar(u8, passwd_content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        if (!std.mem.eql(u8, name, username)) continue;
        _ = fields.next() orelse continue; // password placeholder
        const uid_field = fields.next() orelse return error.MalformedPasswdEntry;
        const gid_field = fields.next() orelse return error.MalformedPasswdEntry;
        const uid = std.fmt.parseInt(u32, uid_field, 10) catch return error.MalformedPasswdEntry;
        const gid = std.fmt.parseInt(u32, gid_field, 10) catch return error.MalformedPasswdEntry;
        return .{ uid, gid };
    }
    return error.UserNotFound;
}

/// Reads, locks (see `lockRootPassword`), and writes back `shadow_content`
/// under `etc_dir`.
pub fn lockRootPasswordInPlace(allocator: Allocator, etc_dir: std.Io.Dir, io: std.Io) !void {
    const shadow_content = try etc_dir.readFileAlloc(io, "shadow", allocator, read_limit);
    defer allocator.free(shadow_content);
    const new_shadow = try lockRootPassword(allocator, shadow_content);
    defer allocator.free(new_shadow);
    try etc_dir.writeFile(io, .{ .sub_path = "shadow", .data = new_shadow, .flags = .{ .truncate = true, .permissions = .fromMode(0o600) } });
}

test "createUserIfMissing creates passwd/shadow/group entries and a home dir" {
    // Chowning the home directory to the newly assigned uid/gid requires
    // real root privileges (production `azagent` always runs as root while
    // provisioning; this sandbox/CI likely does not) -- skip gracefully
    // rather than asserting behavior the OS itself won't allow us to
    // perform, matching this repo's existing convention for
    // environment-dependent tests (see tests/boot_smoke.zig).
    if (std.os.linux.geteuid() != 0) {
        std.debug.print("skipping createUserIfMissing test: not running as root, chown would fail\n", .{});
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "passwd", .data = "root:x:0:0::/root:/bin/bash\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "group", .data = "root:x:0:\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "shadow", .data = "root:!:19000:0:99999:7:::\n" });
    try tmp.dir.createDir(io, "home", .default_dir);

    var etc_dir = try tmp.dir.openDir(io, ".", .{});
    defer etc_dir.close(io);
    var home_dir = try tmp.dir.openDir(io, "home", .{});
    defer home_dir.close(io);

    const result = try createUserIfMissing(allocator, etc_dir, home_dir, io, "azureuser", 19700 * 86_400);
    defer allocator.free(result.home);

    try std.testing.expectEqual(@as(u32, 1000), result.uid);
    try std.testing.expectEqual(@as(u32, 1000), result.gid);
    try std.testing.expectEqualStrings("/home/azureuser", result.home);
    try std.testing.expect(!result.already_existed);

    const passwd_after = try tmp.dir.readFileAlloc(io, "passwd", allocator, read_limit);
    defer allocator.free(passwd_after);
    try std.testing.expect(std.mem.indexOf(u8, passwd_after, "azureuser:x:1000:1000::/home/azureuser:/bin/bash\n") != null);

    const shadow_after = try tmp.dir.readFileAlloc(io, "shadow", allocator, read_limit);
    defer allocator.free(shadow_after);
    try std.testing.expect(std.mem.indexOf(u8, shadow_after, "azureuser:!:19700:0:99999:7:::\n") != null);

    const group_after = try tmp.dir.readFileAlloc(io, "group", allocator, read_limit);
    defer allocator.free(group_after);
    try std.testing.expect(std.mem.indexOf(u8, group_after, "azureuser:x:1000:\n") != null);

    const home_stat = try home_dir.statFile(io, "azureuser", .{});
    try std.testing.expectEqual(std.Io.File.Kind.directory, home_stat.kind);
}

test "createUserIfMissing is idempotent when the user already exists" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "passwd", .data = "root:x:0:0::/root:/bin/bash\nazureuser:x:1000:1000::/home/azureuser:/bin/bash\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "group", .data = "root:x:0:\nazureuser:x:1000:\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "shadow", .data = "root:!:19000:0:99999:7:::\nazureuser:!:19700:0:99999:7:::\n" });
    try tmp.dir.createDir(io, "home", .default_dir);

    var etc_dir = try tmp.dir.openDir(io, ".", .{});
    defer etc_dir.close(io);
    var home_dir = try tmp.dir.openDir(io, "home", .{});
    defer home_dir.close(io);

    const result = try createUserIfMissing(allocator, etc_dir, home_dir, io, "azureuser", 20000 * 86_400);
    defer allocator.free(result.home);

    try std.testing.expect(result.already_existed);
    try std.testing.expectEqual(@as(u32, 1000), result.uid);
    try std.testing.expectEqual(@as(u32, 1000), result.gid);
}

test "lockRootPasswordInPlace locks root's shadow entry on disk" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "shadow", .data = "root:$6$abc$def:19000:0:99999:7:::\n" });

    var etc_dir = try tmp.dir.openDir(io, ".", .{});
    defer etc_dir.close(io);

    try lockRootPasswordInPlace(allocator, etc_dir, io);

    const shadow_after = try tmp.dir.readFileAlloc(io, "shadow", allocator, read_limit);
    defer allocator.free(shadow_after);
    try std.testing.expectEqualStrings("root:!$6$abc$def:19000:0:99999:7:::\n", shadow_after);
}
