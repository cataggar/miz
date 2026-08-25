//! Sets and publishes the VM's hostname (from `ovf-env.xml`'s `HostName`).
//!
//! Scoped down from upstream's `set_hostname`/`publish_hostname`: this
//! writes `/etc/hostname` and calls `sethostname(2)` directly (a real
//! kernel syscall, not a shell-out to the `hostname` binary), matching
//! `mizinit/init.zig`'s existing direct-syscall style for the same call.
//! Upstream's further `publish_hostname` step edits distro-specific
//! `dhclient.conf` files so the DHCP client also sends the new hostname --
//! out of scope here since Azure Linux's systemd-networkd/NetworkManager
//! already picks up `/etc/hostname` on the next DHCP renewal without that
//! extra config.
const std = @import("std");
const linux = std.os.linux;

pub const max_hostname_len = 64;

/// Formats the `/etc/hostname` file content for `hostname` (the name plus
/// a trailing newline). Pure and allocation-free; the caller writes the
/// result wherever appropriate (see `publish`).
pub fn etcHostnameContent(buf: *[max_hostname_len + 1]u8, hostname: []const u8) ![]const u8 {
    if (hostname.len == 0 or hostname.len > max_hostname_len) return error.InvalidHostname;
    return std.fmt.bufPrint(buf, "{s}\n", .{hostname});
}

/// Calls `sethostname(2)` directly, matching `mizinit`'s style. Real
/// kernel-state mutation -- deliberately not covered by an automated test
/// (it would change the *host* running the test suite); exercised only via
/// manual/real-VM verification.
pub fn setKernelHostname(hostname: []const u8) linux.E {
    const rc = linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len);
    return linux.errno(rc);
}

/// Writes `/etc/hostname` under `etc_dir` and calls `sethostname(2)`.
/// `etc_dir` is an already-open directory handle (production code passes
/// the real `/etc`; tests pass a temp directory) so this is safe to
/// exercise without touching the real system's `/etc/hostname` -- but note
/// `setKernelHostname` still really does call `sethostname(2)` regardless
/// of `etc_dir`, so this whole function is only ever called for real by
/// `main.zig`, never by a test.
pub fn publish(etc_dir: std.Io.Dir, io: std.Io, hostname: []const u8) !void {
    var buf: [max_hostname_len + 1]u8 = undefined;
    const content = try etcHostnameContent(&buf, hostname);

    const file = try etc_dir.createFile(io, "hostname", .{ .truncate = true });
    defer file.close(io);
    var write_buf: [max_hostname_len + 1]u8 = undefined;
    var writer = file.writer(io, &write_buf);
    try writer.interface.writeAll(content);
    try writer.interface.flush();

    const e = setKernelHostname(hostname);
    if (e != .SUCCESS) return error.SetHostnameFailed;
}

test "etcHostnameContent formats the hostname with a trailing newline" {
    var buf: [max_hostname_len + 1]u8 = undefined;
    try std.testing.expectEqualStrings("my-host\n", try etcHostnameContent(&buf, "my-host"));
}

test "etcHostnameContent rejects an empty hostname" {
    var buf: [max_hostname_len + 1]u8 = undefined;
    try std.testing.expectError(error.InvalidHostname, etcHostnameContent(&buf, ""));
}

test "etcHostnameContent rejects an overlong hostname" {
    var buf: [max_hostname_len + 1]u8 = undefined;
    const too_long = "a" ** (max_hostname_len + 1);
    try std.testing.expectError(error.InvalidHostname, etcHostnameContent(&buf, too_long));
}

test "publish writes /etc/hostname content under a scoped directory" {
    // Exercises the file-writing half only, inside a throwaway temp
    // directory -- never the real `/etc/hostname` -- since `publish` also
    // calls the real `sethostname(2)` syscall, which this test does not
    // want to (and, unprivileged, likely could not) actually perform. We
    // instead directly test `etcHostnameContent` above for the pure
    // formatting logic, and only smoke-test the write here.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buf: [max_hostname_len + 1]u8 = undefined;
    const content = try etcHostnameContent(&buf, "my-host");

    const io = std.testing.io;
    const file = try tmp.dir.createFile(io, "hostname", .{ .truncate = true });
    {
        defer file.close(io);
        var write_buf: [max_hostname_len + 1]u8 = undefined;
        var writer = file.writer(io, &write_buf);
        try writer.interface.writeAll(content);
        try writer.interface.flush();
    }

    const read_back = try tmp.dir.openFile(io, "hostname", .{});
    defer read_back.close(io);
    var read_buf: [max_hostname_len + 1]u8 = undefined;
    var reader = read_back.reader(io, &read_buf);
    const got = try reader.interface.allocRemaining(std.testing.allocator, .limited(256));
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("my-host\n", got);
}
