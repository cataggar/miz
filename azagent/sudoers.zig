//! Grants the provisioned user passwordless sudo, via a drop-in
//! `/etc/sudoers.d/azagent` file (this project's own name, not upstream's
//! `waagent` drop-in). Matches upstream's `conf_sudoer`, scoped down to the
//! `nopasswd` case only, since `azagent` never provisions a password for
//! the account (see `passwd.zig`'s module doc comment).
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const sudoers_dir = "sudoers.d";
pub const drop_in_name = "azagent";
const includedir_line = "#includedir /etc/sudoers.d\n";

/// The sudoers rule line granting `username` passwordless sudo.
pub fn sudoerLine(allocator: Allocator, username: []const u8) ![]u8 {
    return allocator.print("{s} ALL=(ALL) NOPASSWD: ALL\n", .{username});
}

/// True if `content` already grants `username` a sudoers rule (matching
/// upstream's simple substring check via `findstr_in_file`).
pub fn hasSudoerRule(content: []const u8, username: []const u8) bool {
    return std.mem.indexOf(u8, content, username) != null;
}

/// Appends `username`'s sudoers rule to `drop_in_content` if not already
/// present. Idempotent.
pub fn appendSudoerRuleIfMissing(allocator: Allocator, drop_in_content: []const u8, username: []const u8) ![]u8 {
    if (hasSudoerRule(drop_in_content, username)) {
        return allocator.dupe(u8, drop_in_content);
    }
    const line = try sudoerLine(allocator, username);
    defer allocator.free(line);

    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, drop_in_content.len + line.len);
    errdefer out.deinit();
    try out.writer.writeAll(drop_in_content);
    try out.writer.writeAll(line);
    return out.toOwnedSlice();
}

/// Appends the `#includedir /etc/sudoers.d` directive to `sudoers_content`
/// if not already present (older distros' `/etc/sudoers` may not already
/// source `/etc/sudoers.d` by default).
pub fn ensureIncludeDir(allocator: Allocator, sudoers_content: []const u8) ![]u8 {
    if (std.mem.indexOf(u8, sudoers_content, "sudoers.d") != null) {
        return allocator.dupe(u8, sudoers_content);
    }
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, sudoers_content.len + includedir_line.len + 1);
    errdefer out.deinit();
    try out.writer.writeAll(sudoers_content);
    if (sudoers_content.len > 0 and sudoers_content[sudoers_content.len - 1] != '\n') try out.writer.writeAll("\n");
    try out.writer.writeAll(includedir_line);
    return out.toOwnedSlice();
}

test "sudoerLine formats a passwordless rule" {
    const allocator = std.testing.allocator;
    const line = try sudoerLine(allocator, "azureuser");
    defer allocator.free(line);
    try std.testing.expectEqualStrings("azureuser ALL=(ALL) NOPASSWD: ALL\n", line);
}

test "hasSudoerRule finds an existing rule by substring" {
    try std.testing.expect(hasSudoerRule("azureuser ALL=(ALL) NOPASSWD: ALL\n", "azureuser"));
    try std.testing.expect(!hasSudoerRule("someoneelse ALL=(ALL) NOPASSWD: ALL\n", "azureuser"));
}

test "appendSudoerRuleIfMissing adds a new rule" {
    const allocator = std.testing.allocator;
    const result = try appendSudoerRuleIfMissing(allocator, "", "azureuser");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("azureuser ALL=(ALL) NOPASSWD: ALL\n", result);
}

test "appendSudoerRuleIfMissing is idempotent" {
    const allocator = std.testing.allocator;
    const existing = "azureuser ALL=(ALL) NOPASSWD: ALL\n";
    const result = try appendSudoerRuleIfMissing(allocator, existing, "azureuser");
    defer allocator.free(result);
    try std.testing.expectEqualStrings(existing, result);
}

test "ensureIncludeDir appends the directive when absent" {
    const allocator = std.testing.allocator;
    const result = try ensureIncludeDir(allocator, "root ALL=(ALL) ALL\n");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("root ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n", result);
}

test "ensureIncludeDir is idempotent when already present" {
    const allocator = std.testing.allocator;
    const existing = "root ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n";
    const result = try ensureIncludeDir(allocator, existing);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(existing, result);
}

// ---------------------------------------------------------------------
// Impure half: real file I/O, scoped to a caller-provided `/etc` handle.
// ---------------------------------------------------------------------

const read_limit: std.Io.Limit = .limited(1024 * 1024);

/// Idempotently grants `username` passwordless sudo: ensures
/// `/etc/sudoers` sources `/etc/sudoers.d`, creates `/etc/sudoers.d/azagent`
/// (mode `0440`) with `username`'s rule appended if not already present.
pub fn configureSudoer(allocator: Allocator, etc_dir: std.Io.Dir, io: std.Io, username: []const u8) !void {
    try etc_dir.createDirPath(io, sudoers_dir);

    const sudoers_content = etc_dir.readFileAlloc(io, "sudoers", allocator, read_limit) catch |err| switch (err) {
        error.FileNotFound => try allocator.dupe(u8, ""),
        else => return err,
    };
    defer allocator.free(sudoers_content);
    const new_sudoers = try ensureIncludeDir(allocator, sudoers_content);
    defer allocator.free(new_sudoers);
    if (!std.mem.eql(u8, sudoers_content, new_sudoers)) {
        try etc_dir.writeFile(io, .{ .sub_path = "sudoers", .data = new_sudoers });
    }

    var drop_in_dir = try etc_dir.openDir(io, sudoers_dir, .{});
    defer drop_in_dir.close(io);

    // The drop-in may already exist, locked to 0440 from a previous run --
    // make sure it's writable before we try to update it (chmod only
    // requires ownership, not existing write access, so this works even
    // when re-run unprivileged against a file this same user created).
    drop_in_dir.setFilePermissions(io, drop_in_name, .fromMode(0o640), .{}) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    const drop_in_content = drop_in_dir.readFileAlloc(io, drop_in_name, allocator, read_limit) catch |err| switch (err) {
        error.FileNotFound => try allocator.dupe(u8, ""),
        else => return err,
    };
    defer allocator.free(drop_in_content);
    const new_drop_in = try appendSudoerRuleIfMissing(allocator, drop_in_content, username);
    defer allocator.free(new_drop_in);

    try drop_in_dir.writeFile(io, .{ .sub_path = drop_in_name, .data = new_drop_in });
    try drop_in_dir.setFilePermissions(io, drop_in_name, .fromMode(0o440), .{});
}

test "configureSudoer writes a working sudoers.d drop-in under a scoped directory" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var etc_dir = try tmp.dir.openDir(io, ".", .{});
    defer etc_dir.close(io);

    try configureSudoer(allocator, etc_dir, io, "azureuser");

    const sudoers_after = try tmp.dir.readFileAlloc(io, "sudoers", allocator, read_limit);
    defer allocator.free(sudoers_after);
    try std.testing.expect(std.mem.indexOf(u8, sudoers_after, "#includedir /etc/sudoers.d") != null);

    const drop_in_after = try tmp.dir.readFileAlloc(io, "sudoers.d/azagent", allocator, read_limit);
    defer allocator.free(drop_in_after);
    try std.testing.expectEqualStrings("azureuser ALL=(ALL) NOPASSWD: ALL\n", drop_in_after);

    // Calling again should be idempotent (no duplicate rule).
    try configureSudoer(allocator, etc_dir, io, "azureuser");
    const drop_in_after2 = try tmp.dir.readFileAlloc(io, "sudoers.d/azagent", allocator, read_limit);
    defer allocator.free(drop_in_after2);
    try std.testing.expectEqualStrings("azureuser ALL=(ALL) NOPASSWD: ALL\n", drop_in_after2);
}
