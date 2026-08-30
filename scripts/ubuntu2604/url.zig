//! The slice of URL syntax the Ubuntu release contracts depend on.
//!
//! The Ubuntu snapshot binding and bounded HTTPS downloads both need the same
//! component parsing. This reproduces Python's `urllib.parse.urlsplit`,
//! including that a bad port makes the whole URL invalid rather than silently
//! defaulting.

const std = @import("std");

pub const Parts = struct {
    scheme: []const u8,
    /// Everything between `//` and the path, credentials and port included.
    netloc: []const u8,
    path: []const u8,
    query: []const u8,
    fragment: []const u8,

    /// `urlsplit(...).hostname`: the host with credentials and port removed,
    /// lowercased, and IPv6 brackets stripped.
    pub fn hostname(self: Parts, buffer: []u8) ?[]const u8 {
        const authority = self.hostPort();
        var host = authority;
        if (std.mem.startsWith(u8, host, "[")) {
            const closing = std.mem.indexOfScalar(u8, host, ']') orelse return null;
            host = host[1..closing];
        } else if (std.mem.indexOfScalar(u8, host, ':')) |colon| {
            host = host[0..colon];
        }
        if (host.len == 0 or host.len > buffer.len) return null;
        return std.ascii.lowerString(buffer[0..host.len], host);
    }

    fn hostPort(self: Parts) []const u8 {
        const at = std.mem.lastIndexOfScalar(u8, self.netloc, '@') orelse
            return self.netloc;
        return self.netloc[at + 1 ..];
    }

    /// `urlsplit(...).port`. `error.InvalidPort` is Python's `ValueError`,
    /// which the callers treat as an invalid URL rather than as "no port".
    pub fn port(self: Parts) error{InvalidPort}!?u16 {
        const authority = self.hostPort();
        var rest = authority;
        if (std.mem.startsWith(u8, rest, "[")) {
            const closing = std.mem.indexOfScalar(u8, rest, ']') orelse
                return error.InvalidPort;
            rest = rest[closing + 1 ..];
        }
        const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
        const text = rest[colon + 1 ..];
        if (text.len == 0) return null;
        const value = std.fmt.parseInt(u32, text, 10) catch return error.InvalidPort;
        if (value == 0 or value > 65535) return error.InvalidPort;
        return @intCast(value);
    }
};

fn isSchemeStart(byte: u8) bool {
    return std.ascii.isAlphabetic(byte);
}

fn isSchemeByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '-' or byte == '.';
}

/// `urllib.parse.urlsplit`, restricted to the ASCII forms this repository
/// produces and consumes.
pub fn split(value: []const u8) Parts {
    var rest = value;
    var fragment: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '#')) |index| {
        fragment = rest[index + 1 ..];
        rest = rest[0..index];
    }
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, '?')) |index| {
        query = rest[index + 1 ..];
        rest = rest[0..index];
    }

    var scheme: []const u8 = "";
    if (std.mem.indexOfScalar(u8, rest, ':')) |index| {
        if (index > 0 and isSchemeStart(rest[0])) {
            var valid = true;
            for (rest[0..index]) |byte| {
                if (!isSchemeByte(byte)) {
                    valid = false;
                    break;
                }
            }
            if (valid) {
                scheme = rest[0..index];
                rest = rest[index + 1 ..];
            }
        }
    }

    var netloc: []const u8 = "";
    if (std.mem.startsWith(u8, rest, "//")) {
        const body = rest[2..];
        const end = std.mem.indexOfAny(u8, body, "/?#") orelse body.len;
        netloc = body[0..end];
        rest = body[end..];
    }

    // The scheme is returned as written. Every caller compares it against a
    // lowercase literal, so an uppercase spelling is rejected rather than
    // silently normalized -- which is what these contracts want.
    return .{
        .scheme = scheme,
        .netloc = netloc,
        .path = rest,
        .query = query,
        .fragment = fragment,
    };
}

pub fn isHttps(value: []const u8, host_buffer: []u8) bool {
    const parts = split(value);
    _ = parts.port() catch return false;
    return std.mem.eql(u8, parts.scheme, "https") and
        parts.hostname(host_buffer) != null;
}

test "split reproduces the urlsplit component boundaries" {
    const parts = split("https://cloud-images.ubuntu.com/releases/26.04/release-20260101/");
    try std.testing.expectEqualStrings("https", parts.scheme);
    try std.testing.expectEqualStrings("cloud-images.ubuntu.com", parts.netloc);
    try std.testing.expectEqualStrings(
        "/releases/26.04/release-20260101/",
        parts.path,
    );
    try std.testing.expectEqualStrings("", parts.query);
    try std.testing.expectEqualStrings("", parts.fragment);

    const complex = split("https://user:pass@host.example:8443/a/b?x=1#frag");
    try std.testing.expectEqualStrings("https", complex.scheme);
    try std.testing.expectEqualStrings("user:pass@host.example:8443", complex.netloc);
    try std.testing.expectEqualStrings("/a/b", complex.path);
    try std.testing.expectEqualStrings("x=1", complex.query);
    try std.testing.expectEqualStrings("frag", complex.fragment);
    var buffer: [253]u8 = undefined;
    try std.testing.expectEqualStrings("host.example", complex.hostname(&buffer).?);
    try std.testing.expectEqual(@as(?u16, 8443), try complex.port());
}

test "hostname lowercases and unwraps IPv6 literals" {
    var buffer: [253]u8 = undefined;
    const upper = split("https://HOST.Example/path");
    try std.testing.expectEqualStrings("host.example", upper.hostname(&buffer).?);
    const ipv6 = split("https://[2001:db8::1]:8443/path");
    try std.testing.expectEqualStrings("2001:db8::1", ipv6.hostname(&buffer).?);
    try std.testing.expectEqual(@as(?u16, 8443), try ipv6.port());
}

test "isHttps requires a valid HTTPS host and port" {
    var buffer: [253]u8 = undefined;
    try std.testing.expect(isHttps("https://host.example/a", &buffer));
    try std.testing.expect(isHttps("https://host.example:443/b", &buffer));
    try std.testing.expect(!isHttps("http://host.example/a", &buffer));
    try std.testing.expect(!isHttps("https:///a", &buffer));
    try std.testing.expect(!isHttps("https://host.example:99999/a", &buffer));
}
