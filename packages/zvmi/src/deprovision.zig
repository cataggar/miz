//! Offline `zvmi azure deprovision` support: resets an already-built
//! image's machine-specific state, mirroring the Microsoft Azure Linux
//! Agent's (`waagent`) `-deprovision`/`-deprovision+user` -- but entirely
//! offline, directly on the image file via `ext4.Editor`: no running
//! system, no network, no Python. See issue #110.
//!
//! Every reset here is tolerant of the target path not existing (a
//! from-scratch `build-image` output won't have DHCP lease files, for
//! instance, since it's never actually been network-booted) -- this is a
//! best-effort "reset whatever machine-specific state happens to be
//! present", not an assertion that every listed path must exist.
const std = @import("std");
const Io = std.Io;
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const ext4 = @import("ext4.zig");
const gpt = @import("gpt.zig");
const mbr = @import("mbr.zig");

pub const default_hostname = "localhost.localdomain";

const dhcp_lease_dirs = [_][]const u8{
    "/var/lib/dhclient",
    "/var/lib/dhcpcd",
    "/var/lib/dhcp",
};

pub const FindRootError = mbr.Mbr.DecodeError || gpt.ReadError || Image.PreadError || std.mem.Allocator.Error || error{NoExt4PartitionFound};

/// Finds the byte offset of the ext4 root filesystem partition within
/// `img` by trying each partition table entry -- GPT if a protective MBR
/// is present, else plain MBR -- and returning the first one whose
/// content `ext4.Editor` can actually open. Doesn't assume a fixed
/// partition index or type GUID, since a `build-image` output's exact
/// partition layout varies (Gen1 vs Gen2, `--boot-mode uki`, `--verity`).
pub fn findRootExt4Offset(allocator: std.mem.Allocator, img: Image, io: Io) FindRootError!u64 {
    var mbr_buf: [mbr.sector_size]u8 = undefined;
    _ = try img.pread(io, &mbr_buf, 0);
    const boot_record = try mbr.Mbr.decode(&mbr_buf);

    const has_protective_entry = for (boot_record.entries) |entry| {
        if (entry.partition_type == .gpt_protective) break true;
    } else false;

    if (has_protective_entry) {
        const parsed = try gpt.readGpt(img, io, allocator);
        defer allocator.free(parsed.partitions);
        for (parsed.partitions) |p| {
            const offset = p.first_lba * mbr.sector_size;
            if (tryOpenExt4(allocator, img, io, offset)) return offset;
        }
    } else {
        for (boot_record.entries) |entry| {
            if (entry.partition_type == .empty or entry.partition_type == .gpt_protective) continue;
            const offset = @as(u64, entry.first_lba) * mbr.sector_size;
            if (tryOpenExt4(allocator, img, io, offset)) return offset;
        }
    }
    return error.NoExt4PartitionFound;
}

fn tryOpenExt4(allocator: std.mem.Allocator, img: Image, io: Io, offset: u64) bool {
    var editor = ext4.Editor.open(io, img.file, allocator, .{ .offset = offset }) catch return false;
    editor.deinit();
    return true;
}

pub const Options = struct {
    /// If set, also removes this user's `/etc/passwd`/`shadow`/`group`
    /// entries and `/home/<username>` -- this project's equivalent of
    /// upstream's `-deprovision+user`. Explicit rather than
    /// auto-detected (e.g. by scanning for the highest UID >= 1000):
    /// simpler, unambiguous, and doesn't need to duplicate `azagent`'s
    /// user-numbering convention here in the offline library.
    username: ?[]const u8 = null,
};

pub const DeprovisionError = ext4.EditError || std.mem.Allocator.Error || std.Io.Writer.Error;

/// Resets the machine-specific state of the ext4 filesystem at `offset`
/// within `img`. See the module doc comment for the full list and the
/// tolerant-of-absence policy.
pub fn deprovision(allocator: std.mem.Allocator, img: Image, io: Io, offset: u64, options: Options) DeprovisionError!void {
    var editor = try ext4.Editor.open(io, img.file, allocator, .{ .offset = offset });
    defer editor.deinit();

    try resetHostname(&editor, io);
    try deleteSshHostKeys(allocator, &editor, io);
    try deleteIfExists(&editor, io, "/etc/resolv.conf");
    try deleteIfExists(&editor, io, "/root/.bash_history");
    try deleteTreeIfExists(&editor, io, "/var/lib/azagent");
    for (dhcp_lease_dirs) |dir| try deleteTreeIfExists(&editor, io, dir);
    try resetMachineId(&editor, io);

    if (options.username) |username| try removeUser(allocator, &editor, io, username);

    try editor.flush(io);
}

fn resetHostname(editor: *ext4.Editor, io: Io) !void {
    editor.writeFile(io, "/etc/hostname", default_hostname ++ "\n") catch |err| switch (err) {
        error.NotFound => {},
        else => return err,
    };
}

fn resetMachineId(editor: *ext4.Editor, io: Io) !void {
    // Emptied, not deleted: systemd regenerates a fresh id on next boot
    // only if the file exists and is empty (matches upstream's CoreOS
    // variant, and is safer than removing the file, which some systemd
    // versions don't handle as gracefully as an empty one).
    editor.writeFile(io, "/etc/machine-id", "") catch |err| switch (err) {
        error.NotFound => {},
        else => return err,
    };
}

fn deleteIfExists(editor: *ext4.Editor, io: Io, path: []const u8) !void {
    editor.deleteFile(io, path) catch |err| switch (err) {
        error.NotFound => {},
        else => return err,
    };
}

fn deleteTreeIfExists(editor: *ext4.Editor, io: Io, path: []const u8) !void {
    editor.deleteTree(io, path) catch |err| switch (err) {
        error.NotFound => {},
        else => return err,
    };
}

/// True if `name` looks like an SSH host key file (`ssh_host_<type>_key`
/// or its `.pub` counterpart).
fn isSshHostKeyFile(name: []const u8) bool {
    const prefix = "ssh_host_";
    const infix = "_key";
    if (!std.mem.startsWith(u8, name, prefix)) return false;
    return std.mem.indexOf(u8, name[prefix.len..], infix) != null;
}

fn deleteSshHostKeys(allocator: std.mem.Allocator, editor: *ext4.Editor, io: Io) !void {
    const entries = editor.reader.listDir(io, allocator, "/etc/ssh") catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    defer ext4.freeDirEntries(allocator, entries);

    for (entries) |entry| {
        if (entry.kind != .file) continue;
        if (!isSshHostKeyFile(entry.name)) continue;
        const path = try std.fmt.allocPrint(allocator, "/etc/ssh/{s}", .{entry.name});
        defer allocator.free(path);
        try editor.deleteFile(io, path);
    }
}

/// Removes every line from `content` whose first `:`-delimited field
/// equals `username` (matches `passwd`/`shadow`/`group`'s shared
/// `name:...` shape). Pure and allocation-only; no I/O.
fn removeUserLine(allocator: std.mem.Allocator, content: []const u8, username: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, content.len);
    errdefer out.deinit();

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':');
        const name = if (colon) |c| line[0..c] else line;
        if (std.mem.eql(u8, name, username)) continue;
        try out.writer.writeAll(line);
        try out.writer.writeAll("\n");
    }
    return out.toOwnedSlice();
}

fn removeUserFromFile(allocator: std.mem.Allocator, editor: *ext4.Editor, io: Io, path: []const u8, username: []const u8) !void {
    const content = editor.reader.readFileAlloc(io, allocator, path) catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    defer allocator.free(content);

    const new_content = try removeUserLine(allocator, content, username);
    defer allocator.free(new_content);

    try editor.writeFile(io, path, new_content);
}

fn removeUser(allocator: std.mem.Allocator, editor: *ext4.Editor, io: Io, username: []const u8) !void {
    try removeUserFromFile(allocator, editor, io, "/etc/passwd", username);
    try removeUserFromFile(allocator, editor, io, "/etc/shadow", username);
    try removeUserFromFile(allocator, editor, io, "/etc/group", username);

    const home_path = try std.fmt.allocPrint(allocator, "/home/{s}", .{username});
    defer allocator.free(home_path);
    try deleteTreeIfExists(editor, io, home_path);
}

test "removeUserLine drops only the matching user's line" {
    const allocator = std.testing.allocator;
    const content = "root:x:0:0::/root:/bin/bash\nazureuser:x:1000:1000::/home/azureuser:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n";
    const result = try removeUserLine(allocator, content, "azureuser");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n", result);
}

test "removeUserLine is a no-op when the user isn't present" {
    const allocator = std.testing.allocator;
    const content = "root:x:0:0::/root:/bin/bash\n";
    const result = try removeUserLine(allocator, content, "nobody-here");
    defer allocator.free(result);
    try std.testing.expectEqualStrings(content, result);
}

test "isSshHostKeyFile matches private and public host key files" {
    try std.testing.expect(isSshHostKeyFile("ssh_host_rsa_key"));
    try std.testing.expect(isSshHostKeyFile("ssh_host_rsa_key.pub"));
    try std.testing.expect(!isSshHostKeyFile("sshd_config"));
}

const TestEntry = struct {
    path: []const u8,
    kind: ext4.Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64 = 0,
    bytes: []const u8 = "",
};

const TestTree = struct {
    entries: []const TestEntry,
    index: usize = 0,
    view: ext4.FileTreeView,

    fn init(entries: []const TestEntry) TestTree {
        return .{ .entries = entries, .view = .{ .ctx = undefined, .next_fn = next, .reset_fn = reset } };
    }

    fn bind(self: *TestTree) void {
        self.view = .{ .ctx = self, .next_fn = next, .reset_fn = reset };
    }

    fn reset(ctx: *anyopaque) void {
        const self: *TestTree = @ptrCast(@alignCast(ctx));
        self.index = 0;
    }

    fn next(ctx: *anyopaque) ext4.FileTreeView.IteratorError!?ext4.FileTreeView.Entry {
        const self: *TestTree = @ptrCast(@alignCast(ctx));
        if (self.index >= self.entries.len) return null;
        const entry = self.entries[self.index];
        self.index += 1;
        return .{
            .path = entry.path,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = switch (entry.kind) {
                .file, .symlink => .{ .ctx = &self.entries[self.index - 1], .read_at_fn = readContent },
                else => null,
            },
        };
    }

    fn readContent(ctx: *const anyopaque, buffer: []u8, offset: u64) ext4.FileTreeView.ContentError!usize {
        const entry: *const TestEntry = @ptrCast(@alignCast(ctx));
        const off = std.math.cast(usize, offset) orelse return error.UnexpectedEndOfStream;
        if (off > entry.bytes.len) return error.UnexpectedEndOfStream;
        const n = @min(buffer.len, entry.bytes.len - off);
        std.mem.copyForwards(u8, buffer[0..n], entry.bytes[off .. off + n]);
        return n;
    }
};

test "findRootExt4Offset and deprovision work end to end on a partitioned disk image" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-deprovision.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const partition_offset: u64 = 1024 * 1024;
    const partition_length: u64 = 15 * 1024 * 1024;
    const disk_size: u64 = partition_offset + partition_length;

    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    var tree = TestTree.init(&[_]TestEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "special-host\n".len, .bytes = "special-host\n" },
        .{ .path = "etc/machine-id", .kind = .file, .mode = 0o444, .uid = 0, .gid = 0, .size = 33, .bytes = "0123456789abcdef0123456789abcdef\n" },
        .{ .path = "etc/resolv.conf", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "nameserver 1.1.1.1\n".len, .bytes = "nameserver 1.1.1.1\n" },
        .{ .path = "etc/ssh", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/ssh/ssh_host_rsa_key", .kind = .file, .mode = 0o600, .uid = 0, .gid = 0, .size = "priv".len, .bytes = "priv" },
        .{ .path = "etc/ssh/ssh_host_rsa_key.pub", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "pub".len, .bytes = "pub" },
        .{ .path = "etc/ssh/sshd_config", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "keep me".len, .bytes = "keep me" },
        .{ .path = "etc/passwd", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "root:x:0:0::/root:/bin/bash\nazureuser:x:1000:1000::/home/azureuser:/bin/bash\n".len, .bytes = "root:x:0:0::/root:/bin/bash\nazureuser:x:1000:1000::/home/azureuser:/bin/bash\n" },
        .{ .path = "etc/shadow", .kind = .file, .mode = 0o600, .uid = 0, .gid = 0, .size = "root:!:19000:0:99999:7:::\nazureuser:!:19700:0:99999:7:::\n".len, .bytes = "root:!:19000:0:99999:7:::\nazureuser:!:19700:0:99999:7:::\n" },
        .{ .path = "etc/group", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "root:x:0:\nazureuser:x:1000:\n".len, .bytes = "root:x:0:\nazureuser:x:1000:\n" },
        .{ .path = "root", .kind = .directory, .mode = 0o700, .uid = 0, .gid = 0 },
        .{ .path = "root/.bash_history", .kind = .file, .mode = 0o600, .uid = 0, .gid = 0, .size = "ls\n".len, .bytes = "ls\n" },
        .{ .path = "var", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "var/lib", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "var/lib/azagent", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "var/lib/azagent/provisioned", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "special-host".len, .bytes = "special-host" },
        .{ .path = "var/lib/azagent/azure-environment", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = "v1 01234567-89ab-cdef-0123-456789abcdef azure\n".len, .bytes = "v1 01234567-89ab-cdef-0123-456789abcdef azure\n" },
        .{ .path = "home", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "home/azureuser", .kind = .directory, .mode = 0o700, .uid = 1000, .gid = 1000 },
        .{ .path = "home/azureuser/.ssh", .kind = .directory, .mode = 0o700, .uid = 1000, .gid = 1000 },
        .{ .path = "home/azureuser/.ssh/authorized_keys", .kind = .file, .mode = 0o600, .uid = 1000, .gid = 1000, .size = "ssh-rsa AAAA test\n".len, .bytes = "ssh-rsa AAAA test\n" },
    });
    tree.bind();

    _ = try ext4.populate(io, img.file, allocator, &tree.view, .{
        .offset = partition_offset,
        .length = partition_length,
        .uuid = [_]u8{0x33} ** 16,
        .timestamp = 1_717_171_717,
    });

    var boot_record = mbr.Mbr{};
    boot_record.entries[0] = .{
        .partition_type = .linux,
        .first_lba = @intCast(partition_offset / mbr.sector_size),
        .sector_count = @intCast(partition_length / mbr.sector_size),
    };
    const mbr_bytes = boot_record.encode();
    try img.pwrite(io, &mbr_bytes, 0);

    const found_offset = try findRootExt4Offset(allocator, img, io);
    try std.testing.expectEqual(partition_offset, found_offset);

    try deprovision(allocator, img, io, found_offset, .{ .username = "azureuser" });

    var reader = try ext4.Reader.open(io, img.file, allocator, .{ .offset = found_offset });
    defer reader.deinit();

    const hostname_after = try reader.readFileAlloc(io, allocator, "/etc/hostname");
    defer allocator.free(hostname_after);
    try std.testing.expectEqualStrings(default_hostname ++ "\n", hostname_after);

    const machine_id_after = try reader.readFileAlloc(io, allocator, "/etc/machine-id");
    defer allocator.free(machine_id_after);
    try std.testing.expectEqualStrings("", machine_id_after);

    try std.testing.expectError(error.NotFound, reader.statPath(io, "/etc/ssh/ssh_host_rsa_key"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "/etc/ssh/ssh_host_rsa_key.pub"));
    _ = try reader.statPath(io, "/etc/ssh/sshd_config");

    try std.testing.expectError(error.NotFound, reader.statPath(io, "/etc/resolv.conf"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "/root/.bash_history"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "/var/lib/azagent"));

    const passwd_after = try reader.readFileAlloc(io, allocator, "/etc/passwd");
    defer allocator.free(passwd_after);
    try std.testing.expect(std.mem.indexOf(u8, passwd_after, "azureuser") == null);
    try std.testing.expect(std.mem.indexOf(u8, passwd_after, "root:x:0:0::/root:/bin/bash") != null);

    const shadow_after = try reader.readFileAlloc(io, allocator, "/etc/shadow");
    defer allocator.free(shadow_after);
    try std.testing.expect(std.mem.indexOf(u8, shadow_after, "azureuser") == null);

    const group_after = try reader.readFileAlloc(io, allocator, "/etc/group");
    defer allocator.free(group_after);
    try std.testing.expect(std.mem.indexOf(u8, group_after, "azureuser") == null);

    try std.testing.expectError(error.NotFound, reader.statPath(io, "/home/azureuser"));
}
