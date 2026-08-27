//! A private HTTPS fetch for the external Android container smoke archive.
//!
//! The archive lives behind a bearer token in someone else's storage, so the
//! transport rules are part of the security contract rather than an
//! implementation detail:
//!
//! * only HTTPS, on the first request and after every redirect;
//! * the `Authorization` header is dropped the moment a redirect leaves the
//!   original origin, so the token is never presented to a host the secret did
//!   not name;
//! * the response is staged in a private `.partial` file and renamed only
//!   after the whole body arrived, so a truncated download can never be
//!   mistaken for the artifact.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const File = std.Io.File;
const Io = std.Io;
const url = @import("url.zig");

pub const Error = error{
    NotHttps,
    TooManyRedirects,
    RequestFailed,
    ResponseTooLarge,
    WriteFailed,
    OutOfMemory,
};

/// `HTTPRedirectHandler`'s default limit in the Python standard library.
pub const max_redirects: usize = 10;
const transfer_buffer_size = 64 * 1024;

pub const Options = struct {
    /// Bearer token presented to the original origin only.
    token: ?[]const u8 = null,
    /// Refuse a body larger than this. `null` matches the Python default of
    /// no bound for the archive itself.
    max_bytes: ?u64 = null,
};

/// RFC 3986 reference resolution, which is what `urljoin` implements for the
/// absolute-URL bases a redirect chain uses.
pub fn resolve(
    allocator: Allocator,
    base: []const u8,
    reference: []const u8,
) Allocator.Error![]u8 {
    const target = url.split(reference);
    if (target.scheme.len != 0) return allocator.dupe(u8, reference);

    const source = url.split(base);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, source.scheme);
    try out.appendSlice(allocator, "://");
    if (std.mem.startsWith(u8, reference, "//")) {
        try out.appendSlice(allocator, reference[2..]);
        return out.toOwnedSlice(allocator);
    }
    try out.appendSlice(allocator, source.netloc);

    if (target.path.len == 0) {
        try out.appendSlice(allocator, source.path);
        if (target.query.len != 0) {
            try out.append(allocator, '?');
            try out.appendSlice(allocator, target.query);
        } else if (source.query.len != 0) {
            try out.append(allocator, '?');
            try out.appendSlice(allocator, source.query);
        }
    } else if (target.path[0] == '/') {
        try appendNormalized(allocator, &out, target.path);
        if (target.query.len != 0) {
            try out.append(allocator, '?');
            try out.appendSlice(allocator, target.query);
        }
    } else {
        const directory_end = std.mem.lastIndexOfScalar(u8, source.path, '/');
        var merged: std.ArrayList(u8) = .empty;
        defer merged.deinit(allocator);
        if (directory_end) |index| {
            try merged.appendSlice(allocator, source.path[0 .. index + 1]);
        } else {
            try merged.append(allocator, '/');
        }
        try merged.appendSlice(allocator, target.path);
        try appendNormalized(allocator, &out, merged.items);
        if (target.query.len != 0) {
            try out.append(allocator, '?');
            try out.appendSlice(allocator, target.query);
        }
    }
    if (target.fragment.len != 0) {
        try out.append(allocator, '#');
        try out.appendSlice(allocator, target.fragment);
    }
    return out.toOwnedSlice(allocator);
}

fn appendNormalized(
    allocator: Allocator,
    out: *std.ArrayList(u8),
    path: []const u8,
) Allocator.Error!void {
    var segments: std.ArrayList([]const u8) = .empty;
    defer segments.deinit(allocator);
    var parts = std.mem.splitScalar(u8, path, '/');
    // The leading empty segment is the root; it is re-added by the writer.
    _ = parts.next();
    var trailing_slash = false;
    while (parts.next()) |part| {
        trailing_slash = false;
        if (std.mem.eql(u8, part, ".")) {
            trailing_slash = true;
            continue;
        }
        if (std.mem.eql(u8, part, "..")) {
            if (segments.items.len != 0) _ = segments.pop();
            trailing_slash = true;
            continue;
        }
        if (part.len == 0) {
            trailing_slash = true;
            continue;
        }
        try segments.append(allocator, part);
    }
    for (segments.items) |segment| {
        try out.append(allocator, '/');
        try out.appendSlice(allocator, segment);
    }
    if (trailing_slash or segments.items.len == 0) try out.append(allocator, '/');
}

/// Downloads `initial_url` to `destination`, following only HTTPS redirects
/// and never carrying the bearer token across an origin change.
pub fn fetch(
    allocator: Allocator,
    io: Io,
    initial_url: []const u8,
    destination: []const u8,
    options: Options,
) Error!void {
    var host_buffer: [253]u8 = undefined;
    const first_origin = url.origin(initial_url, &host_buffer) orelse
        return error.NotHttps;
    if (!std.mem.eql(u8, first_origin.scheme, "https")) return error.NotHttps;

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();

    var current = allocator.dupe(u8, initial_url) catch return error.OutOfMemory;
    defer allocator.free(current);
    var carry_token = options.token != null;

    var redirects: usize = 0;
    while (true) {
        if (redirects > max_redirects) return error.TooManyRedirects;
        var current_host_buffer: [253]u8 = undefined;
        const current_origin = url.origin(current, &current_host_buffer) orelse
            return error.NotHttps;
        if (!std.mem.eql(u8, current_origin.scheme, "https")) return error.NotHttps;

        const uri = std.Uri.parse(current) catch return error.NotHttps;
        var authorization_buffer: [4096]u8 = undefined;
        var extra: [2]std.http.Header = undefined;
        var extra_count: usize = 0;
        extra[extra_count] = .{
            .name = "Accept",
            .value = "application/octet-stream",
        };
        extra_count += 1;
        if (carry_token) {
            const token = options.token.?;
            const value = std.fmt.bufPrint(
                &authorization_buffer,
                "Bearer {s}",
                .{token},
            ) catch return error.RequestFailed;
            extra[extra_count] = .{ .name = "Authorization", .value = value };
            extra_count += 1;
        }

        var request = client.request(.GET, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{ .accept_encoding = .{ .override = "identity" } },
            .extra_headers = extra[0..extra_count],
        }) catch return error.RequestFailed;
        defer request.deinit();
        request.sendBodiless() catch return error.RequestFailed;
        var response = request.receiveHead(&.{}) catch return error.RequestFailed;

        if (response.head.status.class() == .redirect) {
            const location = response.head.location orelse return error.RequestFailed;
            const resolved = resolve(allocator, current, location) catch
                return error.OutOfMemory;
            errdefer allocator.free(resolved);
            var next_host_buffer: [253]u8 = undefined;
            const next_origin = url.origin(resolved, &next_host_buffer) orelse
                return error.NotHttps;
            if (!std.mem.eql(u8, next_origin.scheme, "https")) return error.NotHttps;
            if (!next_origin.eql(current_origin)) carry_token = false;
            allocator.free(current);
            current = resolved;
            redirects += 1;
            continue;
        }
        if (response.head.status != .ok) return error.RequestFailed;

        try writeBody(io, &response, destination, options.max_bytes);
        return;
    }
}

fn writeBody(
    io: Io,
    response: *std.http.Client.Response,
    destination: []const u8,
    max_bytes: ?u64,
) Error!void {
    const output = Dir.cwd().createFile(io, destination, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    }) catch return error.WriteFailed;
    defer output.close(io);

    var response_buffer: [transfer_buffer_size]u8 = undefined;
    var transfer_buffer: [transfer_buffer_size]u8 = undefined;
    const reader = response.reader(&response_buffer);
    var total: u64 = 0;
    while (true) {
        const count = reader.readSliceShort(&transfer_buffer) catch
            return error.RequestFailed;
        if (count == 0) break;
        total += count;
        if (max_bytes) |limit| {
            if (total > limit) return error.ResponseTooLarge;
        }
        output.writePositionalAll(
            io,
            transfer_buffer[0..count],
            total - count,
        ) catch return error.WriteFailed;
    }
    if (response.head.content_length) |length| {
        if (total != length) return error.RequestFailed;
    }
}

test "resolve implements the reference-resolution urljoin performs" {
    const cases = [_]struct {
        base: []const u8,
        reference: []const u8,
        expected: []const u8,
    }{
        .{
            .base = "https://a.example/dir/file",
            .reference = "https://b.example/other",
            .expected = "https://b.example/other",
        },
        .{
            .base = "https://a.example/dir/file",
            .reference = "/root",
            .expected = "https://a.example/root",
        },
        .{
            .base = "https://a.example/dir/file",
            .reference = "sibling",
            .expected = "https://a.example/dir/sibling",
        },
        .{
            .base = "https://a.example/dir/file",
            .reference = "../up",
            .expected = "https://a.example/up",
        },
        .{
            .base = "https://a.example/dir/file",
            .reference = "//b.example/x",
            .expected = "https://b.example/x",
        },
        .{
            .base = "https://a.example/dir/file?q=1",
            .reference = "?q=2",
            .expected = "https://a.example/dir/file?q=2",
        },
        .{
            .base = "https://a.example/dir/file",
            .reference = "next?sig=abc",
            .expected = "https://a.example/dir/next?sig=abc",
        },
    };
    for (cases) |case| {
        const resolved = try resolve(
            std.testing.allocator,
            case.base,
            case.reference,
        );
        defer std.testing.allocator.free(resolved);
        try std.testing.expectEqualStrings(case.expected, resolved);
    }
}

test "a non-HTTPS destination is refused before any connection" {
    try std.testing.expectError(error.NotHttps, fetch(
        std.testing.allocator,
        std.testing.io,
        "http://artifacts.example.invalid/artifact.zip",
        ".zig-cache/never-written",
        .{},
    ));
    try std.testing.expectError(error.NotHttps, fetch(
        std.testing.allocator,
        std.testing.io,
        "file:///etc/passwd",
        ".zig-cache/never-written",
        .{},
    ));
}
