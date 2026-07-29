//! Offline loopback coverage for the OCI Distribution read transport.
const std = @import("std");
const tls = @import("tls");
const zvmi = @import("zvmi");

const Io = std.Io;
const oci = zvmi.oci;

const Scenario = enum {
    anonymous,
    basic,
    basic_rejected,
    basic_blob_rejected,
    bearer_refresh,
    bearer_blob_rejected,
    same_origin_redirect,
    retryable_manifest,
    mid_body_manifest_failure,
    bad_blob_digest,
    bad_blob_size,
    bad_content_length,
    cross_origin_blob_redirect,
    cross_origin_config_redirect,
    tags,
    malformed_challenge,
    malformed_location,
    bounded_error,
    plain_token_nonloopback,
    config_platform_mismatch,
    head_digest_mismatch,
    ping_no_content,
    zero_length_blob_no_content,
    manifest_media_type_mismatch,
    nested_manifest_media_type_mismatch,
    invalid_head_content_type,
    inspect_index_all,
    inspect_annotated_contradiction,
    inspect_annotated_variant,
    tags_rfc_links,
    tags_duplicate_next,
    tags_cross_origin,
};

const RedirectResponse = enum {
    blob,
    bearer_challenge,
};

const RedirectTarget = struct {
    allocator: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    authority: []u8,
    layer: []const u8,
    digest: []const u8,
    response: RedirectResponse,
    thread: ?std.Thread = null,
    err: ?anyerror = null,
    authorization_seen: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        io: Io,
        layer: []const u8,
        digest: []const u8,
        response: RedirectResponse,
    ) !RedirectTarget {
        var address = Io.net.IpAddress{ .ip4 = .loopback(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const authority = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{try listenerPort(&listener)});
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .authority = authority,
            .layer = layer,
            .digest = digest,
            .response = response,
        };
    }

    fn start(self: *RedirectTarget) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn finish(self: *RedirectTarget) !void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.err) |err| return err;
        try std.testing.expect(!self.authorization_seen);
    }

    fn deinit(self: *RedirectTarget) void {
        if (self.thread) |thread| {
            self.listener.deinit(self.io);
            thread.join();
        } else self.listener.deinit(self.io);
        self.allocator.free(self.authority);
        self.* = undefined;
    }

    fn run(self: *RedirectTarget) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *RedirectTarget) !void {
        var stream = try self.listener.accept(self.io);
        defer stream.close(self.io);
        var input_buffer: [response_head_buffer_size]u8 = undefined;
        var output_buffer: [response_head_buffer_size]u8 = undefined;
        var reader = stream.reader(self.io, &input_buffer);
        var writer = stream.writer(self.io, &output_buffer);
        var server = std.http.Server.init(&reader.interface, &writer.interface);
        var request = try server.receiveHead();
        if (!std.mem.eql(u8, request.head.target, "/blob")) return error.UnexpectedRedirectTarget;
        self.authorization_seen = header(&request, "Authorization") != null;
        const encoding = header(&request, "Accept-Encoding") orelse return error.MissingIdentityEncoding;
        if (!std.ascii.eqlIgnoreCase(encoding, "identity")) return error.UnexpectedEncoding;
        switch (self.response) {
            .blob => try request.respond(self.layer, .{ .extra_headers = &.{
                .{ .name = "Content-Type", .value = oci.model.media_type_oci_layer },
                .{ .name = "Docker-Content-Digest", .value = self.digest },
            } }),
            .bearer_challenge => try request.respond("", .{ .status = .unauthorized, .extra_headers = &.{
                .{ .name = "WWW-Authenticate", .value = "Bearer realm=\"http://127.0.0.1:1/token\", service=\"cdn\"" },
            } }),
        }
    }
};

/// This is deliberately the only use of the pinned tls.zig dependency. Zig
/// 0.16's std.http.Server is plaintext-only, while std.http.Client itself
/// performs normal certificate and hostname verification.
const TlsFixture = struct {
    allocator: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    authority: []u8,
    permit_handshake_failure: bool,
    thread: ?std.Thread = null,
    err: ?anyerror = null,
    handled_http: bool = false,

    fn init(allocator: std.mem.Allocator, io: Io, permit_handshake_failure: bool) !TlsFixture {
        var address = Io.net.IpAddress{ .ip4 = .loopback(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        // Zig 0.16's TLS verifier matches dNSName SANs only; OpenSSL verifies
        // this fixture's IP SAN separately with -verify_ip.
        const authority = try std.fmt.allocPrint(allocator, "localhost:{d}", .{try listenerPort(&listener)});
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .authority = authority,
            .permit_handshake_failure = permit_handshake_failure,
        };
    }

    fn start(self: *TlsFixture) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn finish(self: *TlsFixture) !void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.err) |err| return err;
        if (!self.permit_handshake_failure) try std.testing.expect(self.handled_http);
    }

    fn deinit(self: *TlsFixture) void {
        if (self.thread) |thread| {
            self.listener.deinit(self.io);
            thread.join();
        } else self.listener.deinit(self.io);
        self.allocator.free(self.authority);
        self.* = undefined;
    }

    fn run(self: *TlsFixture) void {
        self.serve() catch |err| {
            if (!self.permit_handshake_failure) self.err = err;
        };
    }

    fn serve(self: *TlsFixture) !void {
        var pair = try tls.config.CertKeyPair.fromFilePath(
            self.allocator,
            self.io,
            Io.Dir.cwd(),
            "tests/fixtures/oci-registry/test-server-cert.pem",
            "tests/fixtures/oci-registry/test-server-key.pem",
        );
        defer pair.deinit(self.allocator);
        var stream = try self.listener.accept(self.io);
        defer stream.close(self.io);
        const random_source = std.Random.IoSource{ .io = self.io };
        var connection = try tls.serverFromStream(self.io, stream, .{
            .auth = &pair,
            .now = Io.Clock.real.now(self.io),
            .rng = random_source.interface(),
        });
        var input_buffer: [tls.input_buffer_len]u8 = undefined;
        var output_buffer: [tls.output_buffer_len]u8 = undefined;
        var reader = connection.reader(&input_buffer);
        var writer = connection.writer(&output_buffer);
        var server = std.http.Server.init(&reader.interface, &writer.interface);
        var request = try server.receiveHead();
        if (!std.mem.eql(u8, request.head.target, "/v2/")) return error.UnexpectedTlsRequest;
        const encoding = header(&request, "Accept-Encoding") orelse return error.MissingIdentityEncoding;
        if (!std.ascii.eqlIgnoreCase(encoding, "identity")) return error.UnexpectedEncoding;
        try request.respond("", .{});
        try connection.close();
        self.handled_http = true;
    }
};

fn tlsCertificatePair(allocator: std.mem.Allocator, io: Io) !tls.config.CertKeyPair {
    return tls.config.CertKeyPair.fromFilePath(
        allocator,
        io,
        Io.Dir.cwd(),
        "tests/fixtures/oci-registry/test-server-cert.pem",
        "tests/fixtures/oci-registry/test-server-key.pem",
    );
}

const TlsRedirectTarget = struct {
    allocator: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    authority: []u8,
    layer: []const u8,
    digest: []const u8,
    thread: ?std.Thread = null,
    err: ?anyerror = null,
    authorization_seen: bool = false,

    fn init(allocator: std.mem.Allocator, io: Io, layer: []const u8, digest: []const u8) !TlsRedirectTarget {
        var address = Io.net.IpAddress{ .ip4 = .loopback(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const authority = try std.fmt.allocPrint(allocator, "localhost:{d}", .{try listenerPort(&listener)});
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .authority = authority,
            .layer = layer,
            .digest = digest,
        };
    }

    fn start(self: *TlsRedirectTarget) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn finish(self: *TlsRedirectTarget) !void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.err) |err| return err;
        try std.testing.expect(!self.authorization_seen);
    }

    fn deinit(self: *TlsRedirectTarget) void {
        if (self.thread) |thread| {
            self.listener.deinit(self.io);
            thread.join();
        } else self.listener.deinit(self.io);
        self.allocator.free(self.authority);
        self.* = undefined;
    }

    fn run(self: *TlsRedirectTarget) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *TlsRedirectTarget) !void {
        var pair = try tlsCertificatePair(self.allocator, self.io);
        defer pair.deinit(self.allocator);
        var stream = try self.listener.accept(self.io);
        defer stream.close(self.io);
        const random_source = std.Random.IoSource{ .io = self.io };
        var connection = try tls.serverFromStream(self.io, stream, .{
            .auth = &pair,
            .now = Io.Clock.real.now(self.io),
            .rng = random_source.interface(),
        });
        var input_buffer: [tls.input_buffer_len]u8 = undefined;
        var output_buffer: [tls.output_buffer_len]u8 = undefined;
        var reader = connection.reader(&input_buffer);
        var writer = connection.writer(&output_buffer);
        var server = std.http.Server.init(&reader.interface, &writer.interface);
        var request = try server.receiveHead();
        if (!std.mem.eql(u8, request.head.target, "/blob")) return error.UnexpectedRedirectTarget;
        self.authorization_seen = header(&request, "Authorization") != null;
        const encoding = header(&request, "Accept-Encoding") orelse return error.MissingIdentityEncoding;
        if (!std.ascii.eqlIgnoreCase(encoding, "identity")) return error.UnexpectedEncoding;
        try request.respond(self.layer, .{ .extra_headers = &.{
            .{ .name = "Content-Type", .value = oci.model.media_type_oci_layer },
            .{ .name = "Docker-Content-Digest", .value = self.digest },
        } });
        try connection.close();
    }
};

const TlsRegistryFixture = struct {
    allocator: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    authority: []u8,
    config: []u8,
    layer: []u8,
    manifest: []u8,
    config_digest: []u8,
    layer_digest: []u8,
    manifest_digest: []u8,
    redirect_blob_url: ?[]u8 = null,
    thread: ?std.Thread = null,
    err: ?anyerror = null,
    handled: usize = 0,

    fn init(allocator: std.mem.Allocator, io: Io) !TlsRegistryFixture {
        var address = Io.net.IpAddress{ .ip4 = .loopback(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const authority = try std.fmt.allocPrint(allocator, "localhost:{d}", .{try listenerPort(&listener)});
        errdefer allocator.free(authority);
        const config = try allocator.dupe(u8, "{\"architecture\":\"amd64\",\"os\":\"linux\"}");
        errdefer allocator.free(config);
        const layer = try allocator.dupe(u8, "TLS redirect layer");
        errdefer allocator.free(layer);
        const config_digest = try digestText(allocator, config);
        errdefer allocator.free(config_digest);
        const layer_digest = try digestText(allocator, layer);
        errdefer allocator.free(layer_digest);
        const manifest = try std.fmt.allocPrint(
            allocator,
            "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
            .{
                oci.model.media_type_oci_manifest,
                oci.model.media_type_oci_config,
                config_digest,
                config.len,
                oci.model.media_type_oci_layer,
                layer_digest,
                layer.len,
            },
        );
        errdefer allocator.free(manifest);
        const manifest_digest = try digestText(allocator, manifest);
        errdefer allocator.free(manifest_digest);
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .authority = authority,
            .config = config,
            .layer = layer,
            .manifest = manifest,
            .config_digest = config_digest,
            .layer_digest = layer_digest,
            .manifest_digest = manifest_digest,
        };
    }

    fn setBlobRedirect(self: *TlsRegistryFixture, target_authority: []const u8) !void {
        std.debug.assert(self.redirect_blob_url == null);
        self.redirect_blob_url = try std.fmt.allocPrint(self.allocator, "https://{s}/blob", .{target_authority});
    }

    fn start(self: *TlsRegistryFixture) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn finish(self: *TlsRegistryFixture) !void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.err) |err| return err;
        try std.testing.expectEqual(@as(usize, 7), self.handled);
    }

    fn deinit(self: *TlsRegistryFixture) void {
        if (self.thread) |thread| {
            self.listener.deinit(self.io);
            thread.join();
        } else self.listener.deinit(self.io);
        self.allocator.free(self.authority);
        self.allocator.free(self.config);
        self.allocator.free(self.layer);
        self.allocator.free(self.manifest);
        self.allocator.free(self.config_digest);
        self.allocator.free(self.layer_digest);
        self.allocator.free(self.manifest_digest);
        if (self.redirect_blob_url) |value| self.allocator.free(value);
        self.* = undefined;
    }

    fn run(self: *TlsRegistryFixture) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *TlsRegistryFixture) !void {
        var pair = try tlsCertificatePair(self.allocator, self.io);
        defer pair.deinit(self.allocator);
        while (self.handled < 7) {
            var stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            const random_source = std.Random.IoSource{ .io = self.io };
            var connection = try tls.serverFromStream(self.io, stream, .{
                .auth = &pair,
                .now = Io.Clock.real.now(self.io),
                .rng = random_source.interface(),
            });
            var input_buffer: [tls.input_buffer_len]u8 = undefined;
            var output_buffer: [tls.output_buffer_len]u8 = undefined;
            var reader = connection.reader(&input_buffer);
            var writer = connection.writer(&output_buffer);
            var server = std.http.Server.init(&reader.interface, &writer.interface);
            var request = try server.receiveHead();
            try self.respond(&request);
            try connection.close();
            self.handled += 1;
        }
    }

    fn respond(self: *TlsRegistryFixture, request: *std.http.Server.Request) !void {
        const encoding = header(request, "Accept-Encoding") orelse return error.MissingIdentityEncoding;
        if (!std.ascii.eqlIgnoreCase(encoding, "identity")) return error.UnexpectedEncoding;
        const target = request.head.target;
        if (std.mem.eql(u8, target, "/v2/")) {
            if (header(request, "Authorization") == null) {
                return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{
                    .{ .name = "WWW-Authenticate", .value = "Basic realm=\"registry\"" },
                } });
            }
            try expectTlsBasic(request);
            return request.respond("", .{});
        }
        if (std.mem.eql(u8, target, "/v2/team/image/manifests/latest")) {
            try expectTlsBasic(request);
            return self.respondDocument(request, self.manifest, self.manifest_digest, oci.model.media_type_oci_manifest);
        }
        const manifest_target = try std.fmt.allocPrint(self.allocator, "/v2/team/image/manifests/{s}", .{self.manifest_digest});
        defer self.allocator.free(manifest_target);
        if (std.mem.eql(u8, target, manifest_target)) {
            try expectTlsBasic(request);
            return self.respondDocument(request, self.manifest, self.manifest_digest, oci.model.media_type_oci_manifest);
        }
        const config_target = try std.fmt.allocPrint(self.allocator, "/v2/team/image/blobs/{s}", .{self.config_digest});
        defer self.allocator.free(config_target);
        if (std.mem.eql(u8, target, config_target)) {
            try expectTlsBasic(request);
            return self.respondDocument(request, self.config, self.config_digest, oci.model.media_type_oci_config);
        }
        const layer_target = try std.fmt.allocPrint(self.allocator, "/v2/team/image/blobs/{s}", .{self.layer_digest});
        defer self.allocator.free(layer_target);
        if (std.mem.eql(u8, target, layer_target)) {
            try expectTlsBasic(request);
            const location = self.redirect_blob_url orelse return error.MissingRedirectTarget;
            return request.respond("", .{ .status = .temporary_redirect, .extra_headers = &.{
                .{ .name = "Location", .value = location },
            } });
        }
        return error.UnexpectedTlsRequest;
    }

    fn respondDocument(
        _: *TlsRegistryFixture,
        request: *std.http.Server.Request,
        bytes: []const u8,
        digest: []const u8,
        media_type: []const u8,
    ) !void {
        return request.respond(bytes, .{ .extra_headers = &.{
            .{ .name = "Content-Type", .value = media_type },
            .{ .name = "Docker-Content-Digest", .value = digest },
        } });
    }
};

fn expectTlsBasic(request: *const std.http.Server.Request) !void {
    try std.testing.expectEqualStrings("Basic dXNlcjpzZWNyZXQ=", header(request, "Authorization").?);
}

const AuthKind = enum { none, basic, bearer, other };

const RequestLog = struct {
    target: []u8,
    auth: AuthKind,
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    io: Io,
    scenario: Scenario,
    listener: Io.net.Server,
    authority: []u8,
    expected_requests: usize,
    thread: ?std.Thread = null,
    err: ?anyerror = null,
    handled: usize = 0,
    logs: std.array_list.Managed(RequestLog),
    config: []u8,
    layer: []u8,
    manifest: []u8,
    config_digest: []u8,
    layer_digest: []u8,
    manifest_digest: []u8,
    index: ?[]u8 = null,
    index_digest: ?[]u8 = null,
    token_requests: usize = 0,
    config_manifest_requests: usize = 0,
    config_blob_requests: usize = 0,
    status_body_size: usize = 0,
    redirect_blob_url: ?[]u8 = null,

    fn init(
        allocator: std.mem.Allocator,
        io: Io,
        scenario: Scenario,
        expected_requests: usize,
        redirect_blob_url: ?[]const u8,
    ) !Fixture {
        var address = Io.net.IpAddress{ .ip4 = .loopback(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const port = try listenerPort(&listener);
        const authority = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
        errdefer allocator.free(authority);
        const config = try allocator.dupe(
            u8,
            if (scenario == .config_platform_mismatch or scenario == .inspect_annotated_contradiction)
                "{\"architecture\":\"arm64\",\"os\":\"linux\"}"
            else if (scenario == .inspect_annotated_variant)
                "{\"architecture\":\"amd64\",\"os\":\"linux\",\"variant\":\"v8\"}"
            else
                "{\"architecture\":\"amd64\",\"os\":\"linux\"}",
        );
        errdefer allocator.free(config);
        const layer = try allocator.alloc(u8, if (scenario == .zero_length_blob_no_content) 0 else 3 * 64 * 1024 + 17);
        errdefer allocator.free(layer);
        for (layer, 0..) |*byte, index| byte.* = @truncate(index);
        const config_digest = try digestText(allocator, config);
        errdefer allocator.free(config_digest);
        const layer_digest = try digestText(allocator, layer);
        errdefer allocator.free(layer_digest);
        const manifest = try std.fmt.allocPrint(
            allocator,
            "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
            .{
                if (scenario == .manifest_media_type_mismatch or scenario == .nested_manifest_media_type_mismatch)
                    oci.model.media_type_docker_manifest
                else
                    oci.model.media_type_oci_manifest,
                oci.model.media_type_oci_config,
                config_digest,
                config.len,
                oci.model.media_type_oci_layer,
                layer_digest,
                layer.len,
            },
        );
        errdefer allocator.free(manifest);
        const manifest_digest = try digestText(allocator, manifest);
        errdefer allocator.free(manifest_digest);
        const index = if (scenario == .inspect_index_all or
            scenario == .inspect_annotated_contradiction or
            scenario == .inspect_annotated_variant or
            scenario == .nested_manifest_media_type_mismatch)
        blk: {
            const platform_variant = if (scenario == .inspect_annotated_variant)
                ",\"variant\":\"v8\""
            else
                "";
            break :blk try std.fmt.allocPrint(
                allocator,
                "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"{s}}}}}]}}",
                .{
                    oci.model.media_type_oci_index,
                    oci.model.media_type_oci_manifest,
                    manifest_digest,
                    manifest.len,
                    platform_variant,
                },
            );
        } else null;
        errdefer if (index) |value| allocator.free(value);
        const index_digest = if (index) |value| try digestText(allocator, value) else null;
        errdefer if (index_digest) |value| allocator.free(value);
        return .{
            .allocator = allocator,
            .io = io,
            .scenario = scenario,
            .listener = listener,
            .authority = authority,
            .expected_requests = expected_requests,
            .logs = std.array_list.Managed(RequestLog).init(allocator),
            .config = config,
            .layer = layer,
            .manifest = manifest,
            .config_digest = config_digest,
            .layer_digest = layer_digest,
            .manifest_digest = manifest_digest,
            .index = index,
            .index_digest = index_digest,
            .redirect_blob_url = if (redirect_blob_url) |value| try allocator.dupe(u8, value) else null,
        };
    }

    fn start(self: *Fixture) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn finish(self: *Fixture) !void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.err) |err| return err;
        try std.testing.expectEqual(self.expected_requests, self.handled);
    }

    fn deinit(self: *Fixture) void {
        if (self.thread) |thread| {
            self.listener.deinit(self.io);
            thread.join();
        } else {
            self.listener.deinit(self.io);
        }
        for (self.logs.items) |log| self.allocator.free(log.target);
        self.logs.deinit();
        self.allocator.free(self.authority);
        self.allocator.free(self.config);
        self.allocator.free(self.layer);
        self.allocator.free(self.manifest);
        self.allocator.free(self.config_digest);
        self.allocator.free(self.layer_digest);
        self.allocator.free(self.manifest_digest);
        if (self.index) |value| self.allocator.free(value);
        if (self.index_digest) |value| self.allocator.free(value);
        if (self.redirect_blob_url) |value| self.allocator.free(value);
        self.* = undefined;
    }

    fn rootDocument(self: *const Fixture) []const u8 {
        return self.index orelse self.manifest;
    }

    fn rootDigest(self: *const Fixture) []const u8 {
        return self.index_digest orelse self.manifest_digest;
    }

    fn run(self: *Fixture) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *Fixture) !void {
        while (self.handled < self.expected_requests) {
            {
                var stream = try self.listener.accept(self.io);
                defer stream.close(self.io);
                var input_buffer: [response_head_buffer_size]u8 = undefined;
                var output_buffer: [response_head_buffer_size]u8 = undefined;
                var stream_reader = stream.reader(self.io, &input_buffer);
                var stream_writer = stream.writer(self.io, &output_buffer);
                var server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
                var request = try server.receiveHead();
                try self.recordRequest(&request);
                try self.respond(&request);
                self.handled += 1;
            }
        }
    }

    fn recordRequest(self: *Fixture, request: *const std.http.Server.Request) !void {
        const authorization = header(request, "Authorization");
        const kind: AuthKind = if (authorization) |value|
            if (std.mem.startsWith(u8, value, "Basic ")) .basic else if (std.mem.startsWith(u8, value, "Bearer ")) .bearer else .other
        else
            .none;
        try self.logs.append(.{
            .target = try self.allocator.dupe(u8, request.head.target),
            .auth = kind,
        });
        const encoding = header(request, "Accept-Encoding") orelse return error.MissingIdentityEncoding;
        if (!std.ascii.eqlIgnoreCase(encoding, "identity")) return error.UnexpectedEncoding;
    }

    fn respond(self: *Fixture, request: *std.http.Server.Request) !void {
        const target = request.head.target;
        if (self.scenario == .bounded_error and std.mem.eql(u8, target, "/v2/")) {
            var writer = std.Io.Writer.Allocating.init(self.allocator);
            defer writer.deinit();
            try writer.writer.writeAll("{\"errors\":[{\"code\":\"DENIED\",\"detail\":\"");
            for (0..8192) |_| try writer.writer.writeByte('x');
            try writer.writer.writeAll("\"}]}");
            while (writer.written().len < oci.registry.error_body_limit) try writer.writer.writeByte(' ');
            for (0..8192) |_| try writer.writer.writeByte(' ');
            const body = writer.written();
            self.status_body_size = body.len;
            return request.respond(body, .{ .status = .bad_request });
        }
        if (std.mem.startsWith(u8, target, "/token?")) {
            try self.expectBasic(request);
            const expected = if (self.token_requests == 0)
                "/token?existing=1&service=registry%20service&scope=repository%3Ateam%2Fimage%3Apull&scope=repository%3Aother%3Apull"
            else
                "/token?existing=1&service=registry%20service&scope=repository%3Ateam%2Fimage%3Apull";
            try std.testing.expectEqualStrings(expected, target);
            self.token_requests += 1;
            const token = if (self.token_requests == 1) "first-token" else "refreshed-token";
            const body = try std.fmt.allocPrint(self.allocator, "{{\"token\":\"{s}\",\"expires_in\":3600}}", .{token});
            defer self.allocator.free(body);
            return request.respond(body, .{});
        }
        if (std.mem.eql(u8, target, "/v2/")) return self.respondPing(request);
        if (std.mem.eql(u8, target, "/redirected-manifest")) {
            try self.expectRegistryAuthorization(request);
            return self.respondManifest(request, self.manifest, self.manifest_digest);
        }
        if (std.mem.eql(u8, target, "/v2/team/image/tags/list")) {
            return switch (self.scenario) {
                .tags_rfc_links => request.respond(
                    "{\"name\":\"team/image\",\"tags\":[\"z\",\"a\",\"a\"]}",
                    .{ .extra_headers = &.{
                        .{ .name = "Link", .value = "</v2/team/image/tags/list?ignored=1>; rel=\"prev\"; title=\"comma, \\\"quoted\\\"\"" },
                        .{ .name = "Link", .value = "<../tags/list?n=2>; rel=\"prev next\"; title=\"comma, \\\"quoted\\\"\"" },
                    } },
                ),
                .tags_duplicate_next => request.respond(
                    "{\"name\":\"team/image\",\"tags\":[\"z\"]}",
                    .{ .extra_headers = &.{
                        .{ .name = "Link", .value = "</v2/team/image/tags/list?n=2>; rel=next, </v2/team/image/tags/list?n=3>; rel=\"next\"" },
                    } },
                ),
                .tags_cross_origin => request.respond(
                    "{\"name\":\"team/image\",\"tags\":[\"z\"]}",
                    .{ .extra_headers = &.{.{ .name = "Link", .value = "<http://127.0.0.1:1/v2/team/image/tags/list?n=2>; rel=next" }} },
                ),
                else => request.respond(
                    "{\"name\":\"team/image\",\"tags\":[\"z\",\"a\",\"a\"]}",
                    .{ .extra_headers = &.{.{ .name = "Link", .value = "</v2/team/image/tags/list?n=2>; rel=\"next\"" }} },
                ),
            };
        }
        if (std.mem.eql(u8, target, "/v2/team/image/tags/list?n=2")) {
            return request.respond("{\"name\":\"team/image\",\"tags\":[\"m\",\"z\"]}", .{});
        }
        if (std.mem.eql(u8, target, "/v2/team/image/manifests/latest")) {
            return self.respondTagManifest(request);
        }
        if (self.index_digest) |index_digest| {
            const index_target = try std.fmt.allocPrint(self.allocator, "/v2/team/image/manifests/{s}", .{index_digest});
            defer self.allocator.free(index_target);
            if (std.mem.eql(u8, target, index_target)) {
                try self.expectRegistryAuthorization(request);
                return self.respondManifest(request, self.index.?, index_digest);
            }
        }
        const manifest_target = try std.fmt.allocPrint(self.allocator, "/v2/team/image/manifests/{s}", .{self.manifest_digest});
        defer self.allocator.free(manifest_target);
        if (std.mem.eql(u8, target, manifest_target)) {
            try self.expectRegistryAuthorization(request);
            return self.respondManifest(request, self.manifest, self.manifest_digest);
        }
        const config_manifest_target = try std.fmt.allocPrint(self.allocator, "/v2/team/image/manifests/{s}", .{self.config_digest});
        defer self.allocator.free(config_manifest_target);
        if (std.mem.eql(u8, target, config_manifest_target)) {
            self.config_manifest_requests += 1;
            return request.respond("", .{ .status = .not_found });
        }
        const layer_blob_target = try std.fmt.allocPrint(self.allocator, "/v2/team/image/blobs/{s}", .{self.layer_digest});
        defer self.allocator.free(layer_blob_target);
        if (std.mem.eql(u8, target, layer_blob_target)) {
            return self.respondBlob(request);
        }
        const config_blob_target = try std.fmt.allocPrint(self.allocator, "/v2/team/image/blobs/{s}", .{self.config_digest});
        defer self.allocator.free(config_blob_target);
        if (std.mem.eql(u8, target, config_blob_target)) {
            return self.respondConfigBlob(request);
        }
        return error.UnexpectedRequestTarget;
    }

    fn respondPing(self: *Fixture, request: *std.http.Server.Request) !void {
        if (self.scenario == .ping_no_content) return request.respond("", .{ .status = .no_content });
        switch (self.scenario) {
            .basic, .basic_blob_rejected, .cross_origin_blob_redirect, .cross_origin_config_redirect => {
                if (header(request, "Authorization") == null) {
                    return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{.{ .name = "WWW-Authenticate", .value = "Basic realm=\"registry\"" }} });
                }
                try self.expectBasic(request);
            },
            .basic_rejected => {
                if (header(request, "Authorization") == null) {
                    return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{.{ .name = "WWW-Authenticate", .value = "Basic realm=\"registry\"" }} });
                }
                try self.expectBasic(request);
                return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{.{ .name = "WWW-Authenticate", .value = "Basic realm=\"registry\"" }} });
            },
            .bearer_refresh, .bearer_blob_rejected => {
                if (header(request, "Authorization") == null) {
                    const realm = try std.fmt.allocPrint(self.allocator, "http://{s}/token?existing=1", .{self.authority});
                    defer self.allocator.free(realm);
                    const challenge = try std.fmt.allocPrint(
                        self.allocator,
                        "Basic realm=\"unused\", Bearer realm=\"{s}\", service=\"registry service\", scope=\"repository:team/image:pull\", scope=\"repository:other:pull\"",
                        .{realm},
                    );
                    defer self.allocator.free(challenge);
                    return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{.{ .name = "WWW-Authenticate", .value = challenge }} });
                }
                try std.testing.expectEqualStrings("Bearer first-token", header(request, "Authorization").?);
            },
            .malformed_challenge => {
                return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{.{ .name = "WWW-Authenticate", .value = "Bearer realm=\"unterminated" }} });
            },
            .plain_token_nonloopback => {
                return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{.{ .name = "WWW-Authenticate", .value = "Bearer realm=\"http://registry.example:5000/token\", service=\"registry\", scope=\"repository:team/image:pull\"" }} });
            },
            else => try self.expectRegistryAuthorization(request),
        }
        return request.respond("", .{});
    }

    fn respondTagManifest(self: *Fixture, request: *std.http.Server.Request) !void {
        switch (self.scenario) {
            .same_origin_redirect => {
                try self.expectRegistryAuthorization(request);
                return request.respond("", .{ .status = .temporary_redirect, .extra_headers = &.{.{ .name = "Location", .value = "/redirected-manifest" }} });
            },
            .retryable_manifest => {
                if (self.handled == 1) {
                    return request.respond("", .{ .status = .service_unavailable, .extra_headers = &.{.{ .name = "Retry-After", .value = "0" }} });
                }
            },
            .mid_body_manifest_failure => {
                if (self.handled == 1) return self.respondTruncatedManifest(request);
            },
            .bearer_refresh => {
                const value = header(request, "Authorization") orelse return error.MissingAuthorization;
                if (std.mem.eql(u8, value, "Bearer first-token")) {
                    const realm = try std.fmt.allocPrint(self.allocator, "http://{s}/token?existing=1", .{self.authority});
                    defer self.allocator.free(realm);
                    const challenge = try std.fmt.allocPrint(
                        self.allocator,
                        "Bearer realm=\"{s}\", service=\"registry service\", scope=\"repository:team/image:pull\", error=\"invalid_token\"",
                        .{realm},
                    );
                    defer self.allocator.free(challenge);
                    return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{.{ .name = "WWW-Authenticate", .value = challenge }} });
                }
                try std.testing.expectEqualStrings("Bearer refreshed-token", value);
            },
            .malformed_location => {
                return request.respond("", .{ .status = .temporary_redirect, .extra_headers = &.{.{ .name = "Location", .value = "http://[bad" }} });
            },
            else => try self.expectRegistryAuthorization(request),
        }
        return self.respondManifest(request, self.rootDocument(), self.rootDigest());
    }

    fn respondBlob(self: *Fixture, request: *std.http.Server.Request) !void {
        try self.expectRegistryAuthorization(request);
        switch (self.scenario) {
            .basic_blob_rejected => {
                return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{
                    .{ .name = "WWW-Authenticate", .value = "Basic realm=\"registry\"" },
                } });
            },
            .bearer_blob_rejected => {
                const realm = try std.fmt.allocPrint(self.allocator, "http://{s}/token?existing=1", .{self.authority});
                defer self.allocator.free(realm);
                const challenge = try std.fmt.allocPrint(
                    self.allocator,
                    "Bearer realm=\"{s}\", service=\"registry service\", scope=\"repository:team/image:pull\", error=\"invalid_token\"",
                    .{realm},
                );
                defer self.allocator.free(challenge);
                return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{
                    .{ .name = "WWW-Authenticate", .value = challenge },
                } });
            },
            .cross_origin_blob_redirect => {
                const location = self.redirect_blob_url orelse return error.MissingRedirectTarget;
                return request.respond("", .{ .status = .temporary_redirect, .extra_headers = &.{.{ .name = "Location", .value = location }} });
            },
            .bad_blob_digest => {
                const bad = try self.allocator.dupe(u8, self.layer);
                defer self.allocator.free(bad);
                bad[0] +%= 1;
                return self.respondManifest(request, bad, self.layer_digest);
            },
            .bad_blob_size => return self.respondManifest(request, self.layer[0 .. self.layer.len - 1], self.layer_digest),
            .bad_content_length => {
                const out = request.server.out;
                try out.writeAll("HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 1\r\nDocker-Content-Digest: ");
                try out.writeAll(self.layer_digest);
                try out.writeAll("\r\n\r\n");
                try out.writeAll(self.layer);
                return out.flush();
            },
            .zero_length_blob_no_content => return request.respond("", .{ .status = .no_content }),
            else => return self.respondManifest(request, self.layer, self.layer_digest),
        }
    }

    fn respondManifest(self: *Fixture, request: *std.http.Server.Request, bytes: []const u8, digest: []const u8) !void {
        return request.respond(bytes, .{ .extra_headers = &.{
            .{ .name = "Content-Type", .value = if (self.scenario == .invalid_head_content_type) "application/octet-stream" else self.documentMediaType(bytes) },
            .{ .name = "Docker-Content-Digest", .value = if (self.scenario == .head_digest_mismatch) self.config_digest else digest },
        } });
    }

    fn respondConfigBlob(self: *Fixture, request: *std.http.Server.Request) !void {
        try self.expectRegistryAuthorization(request);
        self.config_blob_requests += 1;
        if (self.scenario == .cross_origin_config_redirect) {
            const location = self.redirect_blob_url orelse return error.MissingRedirectTarget;
            return request.respond("", .{ .status = .temporary_redirect, .extra_headers = &.{
                .{ .name = "Location", .value = location },
            } });
        }
        return request.respond(self.config, .{ .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/octet-stream" },
            .{ .name = "Docker-Content-Digest", .value = self.config_digest },
        } });
    }

    fn documentMediaType(self: *const Fixture, bytes: []const u8) []const u8 {
        if (self.index) |index| {
            if (std.mem.eql(u8, bytes, index)) return oci.model.media_type_oci_index;
        }
        if (std.mem.eql(u8, bytes, self.manifest)) return oci.model.media_type_oci_manifest;
        if (std.mem.eql(u8, bytes, self.config)) return oci.model.media_type_oci_config;
        return oci.model.media_type_oci_layer;
    }

    fn respondTruncatedManifest(self: *Fixture, request: *std.http.Server.Request) !void {
        const out = request.server.out;
        try out.writeAll("HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: ");
        try out.print("{d}", .{self.manifest.len});
        try out.writeAll("\r\nContent-Type: ");
        try out.writeAll(oci.model.media_type_oci_manifest);
        try out.writeAll("\r\nDocker-Content-Digest: ");
        try out.writeAll(self.manifest_digest);
        try out.writeAll("\r\n\r\n");
        try out.writeAll(self.manifest[0 .. self.manifest.len / 2]);
        try out.flush();
    }

    fn expectBasic(_: *Fixture, request: *const std.http.Server.Request) !void {
        try std.testing.expectEqualStrings("Basic dXNlcjpzZWNyZXQ=", header(request, "Authorization").?);
    }

    fn expectRegistryAuthorization(self: *Fixture, request: *const std.http.Server.Request) !void {
        switch (self.scenario) {
            .basic, .basic_rejected, .basic_blob_rejected, .cross_origin_blob_redirect, .cross_origin_config_redirect => try self.expectBasic(request),
            .bearer_refresh => try std.testing.expectEqualStrings("Bearer refreshed-token", header(request, "Authorization").?),
            .bearer_blob_rejected => {
                try std.testing.expect(std.mem.eql(u8, header(request, "Authorization").?, "Bearer first-token") or
                    std.mem.eql(u8, header(request, "Authorization").?, "Bearer refreshed-token"));
            },
            else => try std.testing.expect(header(request, "Authorization") == null),
        }
    }
};

const response_head_buffer_size = 64 * 1024;

fn header(request: *const std.http.Server.Request, name: []const u8) ?[]const u8 {
    var iterator = request.iterateHeaders();
    while (iterator.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry.value;
    }
    return null;
}

fn isLowerHex(value: []const u8) bool {
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    }
    return true;
}

fn digestText(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const value = oci.content.digestBytes(bytes).format();
    return allocator.dupe(u8, &value);
}

fn listenerPort(listener: *Io.net.Server) !u16 {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    var address: std.os.linux.sockaddr.in = undefined;
    var length: std.os.linux.socklen_t = @sizeOf(@TypeOf(address));
    switch (std.os.linux.errno(std.os.linux.getsockname(listener.socket.handle, @ptrCast(&address), &length))) {
        .SUCCESS => return std.mem.bigToNative(u16, address.port),
        else => return error.FixtureAddressUnavailable,
    }
}

fn sourceFor(fixture: *Fixture, authfile: ?[]const u8) !oci.registry.Source {
    return oci.registry.Source.init(
        fixture.io,
        fixture.allocator,
        std.process.Environ.empty,
        .{
            .authority = fixture.authority,
            .repository = "team/image",
            .selection = .{ .tag = "latest" },
        },
        .{
            .plain_http = true,
            .authfile = authfile,
            .sleep = .{ .context = null, .call = noSleep },
        },
    );
}

fn noSleep(_: ?*anyopaque, _: Io, _: u64) !void {}

/// Removes a layout and its bootstrap lock. Every test that writes a layout
/// calls this both before and after the work: a layout left behind by an
/// interrupted run is not an empty destination, so the copy engine skips the
/// transfers whose blobs are already present, the fixture never receives the
/// requests it was told to expect, and the test deadlocks waiting for them.
fn deleteLayout(io: Io, path: []const u8) void {
    Io.Dir.cwd().deleteTree(io, path) catch {};
    const parent = std.fs.path.dirname(path) orelse ".";
    const base = std.fs.path.basename(path);
    var directory = Io.Dir.cwd().openDir(io, parent, .{}) catch return;
    defer directory.close(io);
    var lock_buffer: [512]u8 = undefined;
    const lock = std.fmt.bufPrint(&lock_buffer, ".{s}.zvmi-oci-bootstrap.lock", .{base}) catch return;
    directory.deleteFile(io, lock) catch {};
}

fn writeAuthfile(allocator: std.mem.Allocator, io: Io, path: []const u8, authority: []const u8) !void {
    const content = try std.fmt.allocPrint(allocator, "{{\"auths\":{{\"{s}\":{{\"auth\":\"dXNlcjpzZWNyZXQ=\"}}}}}}", .{authority});
    defer allocator.free(content);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = content });
}

test "anonymous pull copies exact graph into a new layout with streamed blobs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try Fixture.init(allocator, io, .anonymous, 6, null);
    defer fixture.deinit();
    try fixture.start();
    var source = try sourceFor(&fixture, null);
    defer source.deinit();
    const destination = "test-oci-registry-anonymous-layout";
    deleteLayout(io, destination);
    defer deleteLayout(io, destination);
    var result = try source.copyToLayout(
        .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
        .{ .path = destination, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer result.deinit(allocator);
    try fixture.finish();
    try std.testing.expectEqualStrings(fixture.manifest_digest, result.root.digest);
    try std.testing.expect(result.transferred >= 3);
    var resolved = try oci.layout.Source.init(io, allocator, destination).resolve(.{ .path = destination, .selection = .{ .tag = "copied" } });
    defer resolved.deinit();
    try std.testing.expectEqualStrings(fixture.manifest, resolved.bytes);
}

test "Basic and Bearer challenges keep credentials out of request targets" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};
    {
        var fixture = try Fixture.init(allocator, io, .basic, 3, null);
        defer fixture.deinit();
        try writeAuthfile(allocator, io, authfile, fixture.authority);
        try fixture.start();
        var source = try sourceFor(&fixture, authfile);
        defer source.deinit();
        var resolved = try source.resolve(.{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } });
        defer resolved.deinit();
        try fixture.finish();
        for (fixture.logs.items) |log| {
            try std.testing.expect(std.mem.indexOf(u8, log.target, "secret") == null);
        }
        try std.testing.expectEqual(AuthKind.basic, fixture.logs.items[1].auth);
    }

    {
        var fixture = try Fixture.init(allocator, io, .bearer_refresh, 10, null);
        defer fixture.deinit();
        try writeAuthfile(allocator, io, authfile, fixture.authority);
        try fixture.start();
        var source = try sourceFor(&fixture, authfile);
        defer source.deinit();
        const destination = "test-oci-registry-bearer-layout";
        deleteLayout(io, destination);
        defer deleteLayout(io, destination);
        var result = try source.copyToLayout(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .path = destination, .selection = .{ .tag = "copied" } },
            .{},
        );
        defer result.deinit(allocator);
        try fixture.finish();
        try std.testing.expectEqual(@as(usize, 2), fixture.token_requests);
        for (fixture.logs.items) |log| {
            try std.testing.expect(std.mem.indexOf(u8, log.target, "secret") == null);
        }
    }
}

test "Basic and Bearer authentication rejections are bounded for metadata and blobs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-bounded-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};

    {
        var fixture = try Fixture.init(allocator, io, .basic_rejected, 2, null);
        defer fixture.deinit();
        try writeAuthfile(allocator, io, authfile, fixture.authority);
        try fixture.start();
        var source = try sourceFor(&fixture, authfile);
        defer source.deinit();
        try std.testing.expectError(
            error.AuthenticationFailed,
            source.resolve(.{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } }),
        );
        try fixture.finish();
        try std.testing.expectEqual(AuthKind.none, fixture.logs.items[0].auth);
        try std.testing.expectEqual(AuthKind.basic, fixture.logs.items[1].auth);
    }

    {
        var fixture = try Fixture.init(allocator, io, .basic_blob_rejected, 6, null);
        defer fixture.deinit();
        try writeAuthfile(allocator, io, authfile, fixture.authority);
        try fixture.start();
        var source = try sourceFor(&fixture, authfile);
        defer source.deinit();
        const destination = "test-oci-registry-basic-blob-rejection";
        deleteLayout(io, destination);
        defer deleteLayout(io, destination);
        try std.testing.expectError(error.AuthenticationFailed, source.copyToLayout(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .path = destination, .selection = .{ .tag = "copied" } },
            .{},
        ));
        try fixture.finish();
        try std.testing.expectEqual(AuthKind.basic, fixture.logs.items[fixture.logs.items.len - 1].auth);
    }

    {
        var fixture = try Fixture.init(allocator, io, .bearer_blob_rejected, 9, null);
        defer fixture.deinit();
        try writeAuthfile(allocator, io, authfile, fixture.authority);
        try fixture.start();
        var source = try sourceFor(&fixture, authfile);
        defer source.deinit();
        const destination = "test-oci-registry-bearer-blob-rejection";
        deleteLayout(io, destination);
        defer deleteLayout(io, destination);
        try std.testing.expectError(error.AuthenticationFailed, source.copyToLayout(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .path = destination, .selection = .{ .tag = "copied" } },
            .{},
        ));
        try fixture.finish();
        try std.testing.expectEqual(@as(usize, 2), fixture.token_requests);
    }
}

test "same-origin redirects and retryable manifest statuses are retried deterministically" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    {
        var fixture = try Fixture.init(allocator, io, .same_origin_redirect, 3, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        var resolved = try source.resolve(.{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } });
        defer resolved.deinit();
        try fixture.finish();
        try std.testing.expectEqualStrings(fixture.manifest_digest, resolved.descriptor.digest);
    }
    {
        var fixture = try Fixture.init(allocator, io, .retryable_manifest, 3, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        var resolved = try source.resolve(.{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } });
        defer resolved.deinit();
        try fixture.finish();
    }
}

test "retryable metadata body failures are retried as transport failures" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try Fixture.init(allocator, io, .mid_body_manifest_failure, 3, null);
    defer fixture.deinit();
    try fixture.start();
    var source = try sourceFor(&fixture, null);
    defer source.deinit();
    var resolved = try source.resolve(
        .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
    );
    defer resolved.deinit();
    try fixture.finish();
    try std.testing.expectEqualStrings(fixture.manifest_digest, resolved.descriptor.digest);
}

test "manifest HEAD uses OCI and Docker Accept negotiation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try Fixture.init(allocator, io, .anonymous, 2, null);
    defer fixture.deinit();
    try fixture.start();
    var source = try sourceFor(&fixture, null);
    defer source.deinit();
    const descriptor = try source.headManifest(
        .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
    );
    defer {
        if (descriptor.mediaType) |media_type| allocator.free(@constCast(media_type));
        allocator.free(@constCast(descriptor.digest));
    }
    try fixture.finish();
    try std.testing.expectEqualStrings(fixture.manifest_digest, descriptor.digest);
    try std.testing.expectEqual(@as(u64, fixture.manifest.len), descriptor.size);
}

test "digest-selected manifest HEAD rejects a different valid digest header" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try Fixture.init(allocator, io, .head_digest_mismatch, 2, null);
    defer fixture.deinit();
    try fixture.start();
    var source = try sourceFor(&fixture, null);
    defer source.deinit();
    const digest = try oci.content.Digest.parse(fixture.manifest_digest);
    try std.testing.expectError(error.DescriptorMismatch, source.headManifest(
        .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .digest = digest } },
    ));
    try fixture.finish();
}

test "manifest HEAD and GET require exact negotiated media types" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    {
        var fixture = try Fixture.init(allocator, io, .invalid_head_content_type, 2, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(error.InvalidManifest, source.headManifest(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
        ));
        try fixture.finish();
    }
    {
        var fixture = try Fixture.init(allocator, io, .manifest_media_type_mismatch, 2, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(error.InvalidManifest, source.resolve(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
        ));
        try fixture.finish();
    }
    {
        var fixture = try Fixture.init(allocator, io, .nested_manifest_media_type_mismatch, 4, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(error.InvalidManifest, source.inspect(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .mode = .all },
        ));
        try fixture.finish();
    }
}

test "registry operations require exactly 200 OK" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    {
        var fixture = try Fixture.init(allocator, io, .ping_no_content, 1, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(error.RegistryRequestFailed, source.ping());
        try fixture.finish();
    }
    {
        var fixture = try Fixture.init(allocator, io, .zero_length_blob_no_content, 5, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        const destination = "test-oci-registry-zero-blob-status";
        deleteLayout(io, destination);
        defer deleteLayout(io, destination);
        try std.testing.expectError(error.RegistryRequestFailed, source.copyToLayout(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .path = destination, .selection = .{ .tag = "copied" } },
            .{},
        ));
        try fixture.finish();
    }
}

test "cross-origin blob redirects strip registry Authorization" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-cross-origin-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};
    var fixture = try Fixture.init(allocator, io, .cross_origin_blob_redirect, 7, null);
    defer fixture.deinit();
    var target = try RedirectTarget.init(allocator, io, fixture.layer, fixture.layer_digest, .blob);
    defer target.deinit();
    fixture.redirect_blob_url = try std.fmt.allocPrint(allocator, "http://{s}/blob", .{target.authority});
    try writeAuthfile(allocator, io, authfile, fixture.authority);
    try target.start();
    try fixture.start();
    var source = try sourceFor(&fixture, authfile);
    defer source.deinit();
    const destination = "test-oci-registry-cross-origin-layout";
    deleteLayout(io, destination);
    defer deleteLayout(io, destination);
    var result = try source.copyToLayout(
        .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
        .{ .path = destination, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer result.deinit(allocator);
    try fixture.finish();
    try target.finish();
}

test "cross-origin blob authentication challenges cannot nominate token realms" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-cross-origin-challenge-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};
    var fixture = try Fixture.init(allocator, io, .cross_origin_blob_redirect, 6, null);
    defer fixture.deinit();
    var target = try RedirectTarget.init(
        allocator,
        io,
        fixture.layer,
        fixture.layer_digest,
        .bearer_challenge,
    );
    defer target.deinit();
    fixture.redirect_blob_url = try std.fmt.allocPrint(allocator, "http://{s}/blob", .{target.authority});
    try writeAuthfile(allocator, io, authfile, fixture.authority);
    try target.start();
    try fixture.start();
    var source = try sourceFor(&fixture, authfile);
    defer source.deinit();
    const destination = "test-oci-registry-cross-origin-challenge-layout";
    deleteLayout(io, destination);
    defer deleteLayout(io, destination);
    try std.testing.expectError(error.AuthenticationFailed, source.copyToLayout(
        .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
        .{ .path = destination, .selection = .{ .tag = "copied" } },
        .{},
    ));
    try fixture.finish();
    try target.finish();
    try std.testing.expectEqual(@as(usize, 0), fixture.token_requests);
}

test "cross-origin config metadata challenges are rejected in bounded requests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-cross-origin-config-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};
    var fixture = try Fixture.init(allocator, io, .cross_origin_config_redirect, 4, null);
    defer fixture.deinit();
    var target = try RedirectTarget.init(
        allocator,
        io,
        fixture.layer,
        fixture.layer_digest,
        .bearer_challenge,
    );
    defer target.deinit();
    fixture.redirect_blob_url = try std.fmt.allocPrint(allocator, "http://{s}/blob", .{target.authority});
    try writeAuthfile(allocator, io, authfile, fixture.authority);
    try target.start();
    try fixture.start();
    var source = try sourceFor(&fixture, authfile);
    defer source.deinit();
    var resolved = try source.resolve(
        .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
    );
    defer resolved.deinit();
    var manifest = try std.json.parseFromSlice(oci.model.Manifest, allocator, resolved.bytes, .{ .ignore_unknown_fields = true });
    defer manifest.deinit();
    try std.testing.expectError(error.AuthenticationFailed, source.readMetadata(manifest.value.config));
    try fixture.finish();
    try target.finish();
    try std.testing.expectEqual(@as(usize, 0), fixture.token_requests);
}

test "tag pages are validated, deduplicated, and lexically sorted" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try Fixture.init(allocator, io, .tags, 3, null);
    defer fixture.deinit();
    try fixture.start();
    var source = try sourceFor(&fixture, null);
    defer source.deinit();
    var tags = try source.listTags(.{ .authority = fixture.authority, .repository = "team/image", .selection = null });
    defer tags.deinit();
    try fixture.finish();
    try std.testing.expectEqual(@as(usize, 3), tags.tags.len);
    try std.testing.expectEqualStrings("a", tags.tags[0]);
    try std.testing.expectEqualStrings("m", tags.tags[1]);
    try std.testing.expectEqualStrings("z", tags.tags[2]);
}

test "RFC Link pagination supports repeated fields, relation lists, and dot paths" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var fixture = try Fixture.init(allocator, io, .tags_rfc_links, 3, null);
    defer fixture.deinit();
    try fixture.start();
    var source = try sourceFor(&fixture, null);
    defer source.deinit();
    var tags = try source.listTags(.{ .authority = fixture.authority, .repository = "team/image", .selection = null });
    defer tags.deinit();
    try fixture.finish();
    try std.testing.expectEqual(@as(usize, 3), tags.tags.len);
    try std.testing.expectEqualStrings("a", tags.tags[0]);
    try std.testing.expectEqualStrings("m", tags.tags[1]);
    try std.testing.expectEqualStrings("z", tags.tags[2]);
}

test "RFC Link pagination rejects conflicting next links and cross-origin pages" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    inline for ([_]Scenario{ .tags_duplicate_next, .tags_cross_origin }) |scenario| {
        var fixture = try Fixture.init(allocator, io, scenario, 2, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(
            error.InvalidTagLink,
            source.listTags(.{ .authority = fixture.authority, .repository = "team/image", .selection = null }),
        );
        try fixture.finish();
    }
}

test "malformed challenges locations and bounded status errors remain explicit" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    inline for ([_]struct { Scenario, usize, anyerror }{
        .{ .malformed_challenge, 1, error.MalformedChallenge },
        .{ .malformed_location, 2, error.InvalidRedirect },
        .{ .bounded_error, 1, error.RegistryRequestFailed },
    }) |case| {
        var fixture = try Fixture.init(allocator, io, case[0], case[1], null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(case[2], source.resolve(.{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } }));
        try fixture.finish();
        if (case[0] == .bounded_error) {
            const status = source.lastError().?;
            try std.testing.expectEqual(@as(u16, 400), status.status);
            try std.testing.expectEqualStrings("DENIED", status.code.?);
            try std.testing.expect(fixture.status_body_size > oci.registry.error_body_limit);
            try std.testing.expectEqual(@as(usize, 4096), status.detail.?.len);
        }
    }
}

test "plain HTTP token realms are rejected before credential discovery or exchange" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-plain-auth.json";
    const helper_authfile = "test-oci-registry-plain-helper-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};
    defer Io.Dir.cwd().deleteFile(io, helper_authfile) catch {};
    {
        var fixture = try Fixture.init(allocator, io, .plain_token_nonloopback, 1, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(
            error.InsecureAuthorization,
            source.resolve(.{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } }),
        );
        try fixture.finish();
        try std.testing.expectEqual(AuthKind.none, fixture.logs.items[0].auth);
    }
    {
        var fixture = try Fixture.init(allocator, io, .plain_token_nonloopback, 1, null);
        defer fixture.deinit();
        try writeAuthfile(allocator, io, authfile, fixture.authority);
        try fixture.start();
        var source = try sourceFor(&fixture, authfile);
        defer source.deinit();
        try std.testing.expectError(
            error.InsecureAuthorization,
            source.resolve(.{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } }),
        );
        try fixture.finish();
        try std.testing.expectEqual(AuthKind.none, fixture.logs.items[0].auth);
    }
    {
        const Context = struct {
            called: bool = false,

            fn run(
                raw_context: ?*anyopaque,
                _: std.mem.Allocator,
                _: Io,
                _: []const []const u8,
                _: []const u8,
                _: usize,
            ) !oci.auth.ProcessResult {
                const context: *@This() = @ptrCast(@alignCast(raw_context.?));
                context.called = true;
                return error.CredentialHelperShouldNotRun;
            }
        };
        var context = Context{};
        try Io.Dir.cwd().writeFile(io, .{ .sub_path = helper_authfile, .data = "{\"credsStore\":\"test\"}" });
        var fixture = try Fixture.init(allocator, io, .plain_token_nonloopback, 1, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try oci.registry.Source.init(
            io,
            allocator,
            std.process.Environ.empty,
            .{
                .authority = fixture.authority,
                .repository = "team/image",
                .selection = .{ .tag = "latest" },
            },
            .{
                .plain_http = true,
                .authfile = helper_authfile,
                .sleep = .{ .context = null, .call = noSleep },
                .process_runner = .{ .context = &context, .run = Context.run },
            },
        );
        defer source.deinit();
        try std.testing.expectError(
            error.InsecureAuthorization,
            source.resolve(.{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } }),
        );
        try fixture.finish();
        try std.testing.expect(!context.called);
    }
}

test "custom CA extends system roots for the TLS registry fixture" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    {
        var fixture = try TlsFixture.init(allocator, io, true);
        defer fixture.deinit();
        try fixture.start();
        var source = try oci.registry.Source.init(
            io,
            allocator,
            std.process.Environ.empty,
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{},
        );
        defer source.deinit();
        try std.testing.expectError(error.HttpRequestFailed, source.ping());
        try fixture.finish();
    }
    {
        var fixture = try TlsFixture.init(allocator, io, false);
        defer fixture.deinit();
        try fixture.start();
        var source = try oci.registry.Source.init(
            io,
            allocator,
            std.process.Environ.empty,
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .tls_ca = "tests/fixtures/oci-registry/test-ca-cert.pem" },
        );
        defer source.deinit();
        try source.ping();
        try fixture.finish();
    }
}

test "authenticated HTTPS registry blob redirects strip Authorization cross-origin" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-tls-redirect-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};
    var registry = try TlsRegistryFixture.init(allocator, io);
    defer registry.deinit();
    var target = try TlsRedirectTarget.init(allocator, io, registry.layer, registry.layer_digest);
    defer target.deinit();
    try registry.setBlobRedirect(target.authority);
    try writeAuthfile(allocator, io, authfile, registry.authority);
    try target.start();
    try registry.start();
    var source = try oci.registry.Source.init(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .authority = registry.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
        .{
            .authfile = authfile,
            .tls_ca = "tests/fixtures/oci-registry/test-ca-cert.pem",
            .sleep = .{ .context = null, .call = noSleep },
        },
    );
    defer source.deinit();
    const destination = "test-oci-registry-tls-cross-origin-layout";
    deleteLayout(io, destination);
    defer deleteLayout(io, destination);
    var result = try source.copyToLayout(
        .{ .authority = registry.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
        .{ .path = destination, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer result.deinit(allocator);
    try registry.finish();
    try target.finish();
}

test "bad blob responses do not publish a destination reference" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    inline for ([_]Scenario{ .bad_blob_digest, .bad_blob_size, .bad_content_length }) |scenario| {
        var fixture = try Fixture.init(allocator, io, scenario, 5, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        const destination = switch (scenario) {
            .bad_blob_digest => "test-oci-registry-bad-digest",
            .bad_blob_size => "test-oci-registry-bad-size",
            .bad_content_length => "test-oci-registry-bad-length",
            else => unreachable,
        };
        deleteLayout(io, destination);
        defer deleteLayout(io, destination);
        const expected_error: anyerror = switch (scenario) {
            .bad_blob_digest => error.BlobVerificationFailed,
            .bad_blob_size, .bad_content_length => error.InvalidResponseContentLength,
            else => unreachable,
        };
        try std.testing.expectError(expected_error, source.copyToLayout(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .path = destination, .selection = .{ .tag = "copied" } },
            .{},
        ));
        try fixture.finish();
        const directory = Io.Dir.cwd().openDir(io, destination, .{}) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (directory) |opened| {
            opened.close(io);
            return error.TestUnexpectedResult;
        }
    }
}

test "explicit selected registry copies validate config blobs rather than manifests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const platform = oci.model.Platform{ .os = "linux", .architecture = "amd64" };
    {
        var fixture = try Fixture.init(allocator, io, .anonymous, 8, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        const destination = "test-oci-registry-platform-copy-match";
        deleteLayout(io, destination);
        defer deleteLayout(io, destination);
        var result = try source.copyToLayout(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .path = destination, .selection = .{ .tag = "copied" } },
            .{
                .mode = .{ .selected = platform },
                .platform_selection_explicit = true,
            },
        );
        defer result.deinit(allocator);
        try fixture.finish();
        try std.testing.expectEqual(@as(usize, 0), fixture.config_manifest_requests);
    }
    {
        var fixture = try Fixture.init(allocator, io, .config_platform_mismatch, 5, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        const destination = "test-oci-registry-platform-copy-mismatch";
        deleteLayout(io, destination);
        defer deleteLayout(io, destination);
        try std.testing.expectError(error.PlatformConfigMismatch, source.copyToLayout(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .path = destination, .selection = .{ .tag = "copied" } },
            .{
                .mode = .{ .selected = platform },
                .platform_selection_explicit = true,
            },
        ));
        try fixture.finish();
        try std.testing.expectEqual(@as(usize, 0), fixture.config_manifest_requests);
    }
}

test "inspect all and selected graph results are read-only and typed" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    {
        var fixture = try Fixture.init(allocator, io, .anonymous, 4, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        var inspected = try source.inspect(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .mode = .all },
        );
        defer inspected.deinit();
        try fixture.finish();
        try std.testing.expectEqual(oci.registry.InspectKind.manifest, inspected.root.kind);
        try std.testing.expectEqualStrings(fixture.manifest_digest, inspected.root.descriptor.digest);
        try std.testing.expectEqual(@as(usize, 1), inspected.root.layers.len);
        try std.testing.expectEqualStrings("linux", inspected.root.descriptor.platform.?.os);
        try std.testing.expectEqualStrings("amd64", inspected.root.descriptor.platform.?.architecture);
        try std.testing.expectEqual(@as(usize, 1), fixture.config_blob_requests);
        const churn = try allocator.alloc(u8, 64 * 1024);
        defer allocator.free(churn);
        @memset(churn, 'x');
        try std.testing.expectEqualStrings("linux", inspected.root.descriptor.platform.?.os);
        try std.testing.expectEqualStrings("amd64", inspected.root.descriptor.platform.?.architecture);
    }
    {
        var fixture = try Fixture.init(allocator, io, .anonymous, 4, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        var inspected = try source.inspect(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } } },
        );
        defer inspected.deinit();
        try fixture.finish();
        try std.testing.expectEqual(oci.registry.InspectKind.manifest, inspected.root.kind);
        try std.testing.expectEqualStrings("linux", inspected.root.descriptor.platform.?.os);
        try std.testing.expectEqualStrings("amd64", inspected.root.descriptor.platform.?.architecture);
        try std.testing.expectEqual(@as(usize, 0), fixture.config_manifest_requests);
        try std.testing.expectEqual(@as(usize, 1), fixture.config_blob_requests);
    }
    {
        var fixture = try Fixture.init(allocator, io, .config_platform_mismatch, 4, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(error.PlatformConfigMismatch, source.inspect(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } } },
        ));
        try fixture.finish();
        try std.testing.expectEqual(@as(usize, 0), fixture.config_manifest_requests);
        try std.testing.expectEqual(@as(usize, 1), fixture.config_blob_requests);
    }
}

test "inspect resolves recursive manifest platforms and rejects contradictory annotations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    {
        var fixture = try Fixture.init(allocator, io, .inspect_index_all, 5, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        var inspected = try source.inspect(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .mode = .all },
        );
        defer inspected.deinit();
        try fixture.finish();
        try std.testing.expectEqual(oci.registry.InspectKind.index, inspected.root.kind);
        try std.testing.expectEqual(@as(usize, 1), inspected.root.manifests.len);
        try std.testing.expectEqual(oci.registry.InspectKind.manifest, inspected.root.manifests[0].kind);
        try std.testing.expectEqualStrings("linux", inspected.root.manifests[0].descriptor.platform.?.os);
        try std.testing.expectEqualStrings("amd64", inspected.root.manifests[0].descriptor.platform.?.architecture);
        try std.testing.expectEqual(@as(usize, 1), fixture.config_blob_requests);
    }
    {
        var fixture = try Fixture.init(allocator, io, .inspect_annotated_variant, 5, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        var inspected = try source.inspect(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64", .variant = "v8" } } },
        );
        defer inspected.deinit();
        try fixture.finish();
        try std.testing.expectEqualStrings("v8", inspected.root.descriptor.platform.?.variant.?);
        try std.testing.expectEqual(@as(usize, 1), fixture.config_blob_requests);
    }
    {
        var fixture = try Fixture.init(allocator, io, .inspect_annotated_contradiction, 5, null);
        defer fixture.deinit();
        try fixture.start();
        var source = try sourceFor(&fixture, null);
        defer source.deinit();
        try std.testing.expectError(error.PlatformConfigMismatch, source.inspect(
            .{ .authority = fixture.authority, .repository = "team/image", .selection = .{ .tag = "latest" } },
            .{ .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } } },
        ));
        try fixture.finish();
        try std.testing.expectEqual(@as(usize, 1), fixture.config_blob_requests);
    }
}

const PublishEvent = enum {
    blob_head,
    upload_post,
    upload_put,
    manifest_put,
    manifest_head,
};

const PublishedBlob = struct {
    digest: []u8,
    bytes: []u8,
};

const PublishedManifest = struct {
    selector: []u8,
    digest: []u8,
    bytes: []u8,
    media_type: []u8,
};

const MountBehavior = enum {
    disabled,
    complete,
    accepted,
    malformed_location,
    complete_missing_location,
    complete_malformed_location,
    interrupt_after_store,
    denied,
};

const BlobVerificationMode = enum {
    headers,
    omit_head_digest,
    contradictory_head_digest,
    contradictory_get_digest,
};

const badDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

const UploadBehavior = enum {
    normal,
    interrupt_before_store_once,
    interrupt_after_store_once,
    challenge_once,
};

const ManifestBehavior = enum {
    normal,
    reject_root,
    interrupt_after_store_once,
};

const ManifestVerificationMode = enum {
    headers,
    omit_head_digest,
    omit_head_digest_wrong_get,
};

const UploadStartBehavior = enum {
    normal,
    malformed_location,
    denied,
};

const UploadCompletionBehavior = enum {
    normal,
    missing_location,
    malformed_location,
};

const PublishSourceDocuments = struct {
    config: []u8,
    layer: []u8,
    manifest: []u8,
    config_digest: []u8,
    layer_digest: []u8,
    manifest_digest: []u8,

    fn deinit(self: *PublishSourceDocuments, allocator: std.mem.Allocator) void {
        allocator.free(self.config);
        allocator.free(self.layer);
        allocator.free(self.manifest);
        allocator.free(self.config_digest);
        allocator.free(self.layer_digest);
        allocator.free(self.manifest_digest);
        self.* = undefined;
    }
};

const OpaqueSourceDocuments = struct {
    index: []u8,
    opaque_bytes: []u8,
    index_digest: []u8,
    opaque_digest: []u8,

    fn deinit(self: *OpaqueSourceDocuments, allocator: std.mem.Allocator) void {
        allocator.free(self.index);
        allocator.free(self.opaque_bytes);
        allocator.free(self.index_digest);
        allocator.free(self.opaque_digest);
        self.* = undefined;
    }
};

/// Small deterministic writable Distribution fixture. It records only
/// operation classes and body digests, never Authorization values or signed
/// upload query values.
const PublishFixture = struct {
    allocator: std.mem.Allocator,
    io: Io,
    listener: Io.net.Server,
    authority: []u8,
    expected_requests: usize,
    thread: ?std.Thread = null,
    err: ?anyerror = null,
    handled: usize = 0,
    blobs: std.array_list.Managed(PublishedBlob),
    manifests: std.array_list.Managed(PublishedManifest),
    events: std.array_list.Managed(PublishEvent),
    blob_uploads: usize = 0,
    blob_gets: usize = 0,
    source_blob_gets: usize = 0,
    mount_posts: usize = 0,
    mount_behavior: MountBehavior = .disabled,
    blob_verification: BlobVerificationMode = .headers,
    upload_behavior: UploadBehavior = .normal,
    manifest_behavior: ManifestBehavior = .normal,
    manifest_verification: ManifestVerificationMode = .headers,
    upload_start_behavior: UploadStartBehavior = .normal,
    upload_completion_behavior: UploadCompletionBehavior = .normal,
    source_documents: ?PublishSourceDocuments = null,
    opaque_source_documents: ?OpaqueSourceDocuments = null,
    signed_query_preserved: bool = false,
    manifest_gets: usize = 0,
    upload_challenges: usize = 0,
    authorized_upload_posts: usize = 0,
    tls_enabled: bool = false,
    require_basic_auth: bool = false,
    cross_upload_listener: ?Io.net.Server = null,
    cross_upload_authority: ?[]u8 = null,
    cross_upload_authorization_seen: bool = false,
    awaiting_cross_upload: bool = false,

    fn init(allocator: std.mem.Allocator, io: Io, expected_requests: usize) !PublishFixture {
        var address = Io.net.IpAddress{ .ip4 = .loopback(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const authority = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{try listenerPort(&listener)});
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .authority = authority,
            .expected_requests = expected_requests,
            .blobs = std.array_list.Managed(PublishedBlob).init(allocator),
            .manifests = std.array_list.Managed(PublishedManifest).init(allocator),
            .events = std.array_list.Managed(PublishEvent).init(allocator),
        };
    }

    fn initNonLoopback(allocator: std.mem.Allocator, io: Io, expected_requests: usize) !PublishFixture {
        var address = Io.net.IpAddress{ .ip4 = .unspecified(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const authority = try std.fmt.allocPrint(allocator, "0.0.0.0:{d}", .{try listenerPort(&listener)});
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .authority = authority,
            .expected_requests = expected_requests,
            .blobs = std.array_list.Managed(PublishedBlob).init(allocator),
            .manifests = std.array_list.Managed(PublishedManifest).init(allocator),
            .events = std.array_list.Managed(PublishEvent).init(allocator),
        };
    }

    fn initTlsCrossOrigin(allocator: std.mem.Allocator, io: Io, expected_requests: usize) !PublishFixture {
        var address = Io.net.IpAddress{ .ip4 = .loopback(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const port = try listenerPort(&listener);
        const authority = try std.fmt.allocPrint(allocator, "localhost:{d}", .{port});
        errdefer allocator.free(authority);
        var upload_listener = try address.listen(io, .{ .reuse_address = true });
        errdefer upload_listener.deinit(io);
        const upload_port = try listenerPort(&upload_listener);
        const upload_authority = try std.fmt.allocPrint(allocator, "localhost:{d}", .{upload_port});
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .authority = authority,
            .expected_requests = expected_requests,
            .blobs = std.array_list.Managed(PublishedBlob).init(allocator),
            .manifests = std.array_list.Managed(PublishedManifest).init(allocator),
            .events = std.array_list.Managed(PublishEvent).init(allocator),
            .tls_enabled = true,
            .require_basic_auth = true,
            .cross_upload_listener = upload_listener,
            .cross_upload_authority = upload_authority,
        };
    }

    fn start(self: *PublishFixture) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn finish(self: *PublishFixture) !void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
        if (self.err) |err| return err;
        try std.testing.expectEqual(self.expected_requests, self.handled);
        if (self.cross_upload_authority != null) {
            try std.testing.expect(!self.cross_upload_authorization_seen);
        }
    }

    fn deinit(self: *PublishFixture) void {
        if (self.thread) |thread| {
            self.listener.deinit(self.io);
            if (self.cross_upload_listener) |*listener| listener.deinit(self.io);
            thread.join();
        } else {
            self.listener.deinit(self.io);
            if (self.cross_upload_listener) |*listener| listener.deinit(self.io);
        }
        self.allocator.free(self.authority);
        if (self.cross_upload_authority) |value| self.allocator.free(value);
        for (self.blobs.items) |blob| {
            self.allocator.free(blob.digest);
            self.allocator.free(blob.bytes);
        }
        self.blobs.deinit();
        for (self.manifests.items) |manifest| {
            self.allocator.free(manifest.selector);
            self.allocator.free(manifest.digest);
            self.allocator.free(manifest.bytes);
            self.allocator.free(manifest.media_type);
        }
        self.manifests.deinit();
        self.events.deinit();
        if (self.source_documents) |*documents| documents.deinit(self.allocator);
        if (self.opaque_source_documents) |*documents| documents.deinit(self.allocator);
        self.* = undefined;
    }

    fn configureSource(self: *PublishFixture, source: *const Fixture, mount_behavior: MountBehavior) !void {
        std.debug.assert(self.source_documents == null);
        const config = try self.allocator.dupe(u8, source.config);
        errdefer self.allocator.free(config);
        const layer = try self.allocator.dupe(u8, source.layer);
        errdefer self.allocator.free(layer);
        const manifest = try self.allocator.dupe(u8, source.manifest);
        errdefer self.allocator.free(manifest);
        const config_digest = try self.allocator.dupe(u8, source.config_digest);
        errdefer self.allocator.free(config_digest);
        const layer_digest = try self.allocator.dupe(u8, source.layer_digest);
        errdefer self.allocator.free(layer_digest);
        const manifest_digest = try self.allocator.dupe(u8, source.manifest_digest);
        errdefer self.allocator.free(manifest_digest);
        self.source_documents = .{
            .config = config,
            .layer = layer,
            .manifest = manifest,
            .config_digest = config_digest,
            .layer_digest = layer_digest,
            .manifest_digest = manifest_digest,
        };
        self.mount_behavior = mount_behavior;
    }

    fn configureOpaqueSource(self: *PublishFixture) !void {
        return self.configureOpaqueSourceWithMediaType("application/example.opaque");
    }

    fn configureOpaqueSourceWithMediaType(
        self: *PublishFixture,
        media_type: []const u8,
    ) !void {
        std.debug.assert(self.opaque_source_documents == null);
        const opaque_bytes = try self.allocator.dupe(u8, "opaque registry manifest");
        errdefer self.allocator.free(opaque_bytes);
        const opaque_digest = try digestText(self.allocator, opaque_bytes);
        errdefer self.allocator.free(opaque_digest);
        const media_type_json = try std.json.Stringify.valueAlloc(
            self.allocator,
            media_type,
            .{},
        );
        defer self.allocator.free(media_type_json);
        const index = try std.fmt.allocPrint(
            self.allocator,
            "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"manifests\":[{{\"mediaType\":{s},\"digest\":\"{s}\",\"size\":{d}}}]}}",
            .{
                oci.model.media_type_oci_index,
                media_type_json,
                opaque_digest,
                opaque_bytes.len,
            },
        );
        errdefer self.allocator.free(index);
        const index_digest = try digestText(self.allocator, index);
        self.opaque_source_documents = .{
            .index = index,
            .opaque_bytes = opaque_bytes,
            .index_digest = index_digest,
            .opaque_digest = opaque_digest,
        };
    }

    fn run(self: *PublishFixture) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *PublishFixture) !void {
        if (self.cross_upload_listener != null) return self.serveSplitTlsUpload();
        if (self.tls_enabled) return self.serveTls();
        while (self.handled < self.expected_requests) {
            try self.serveRawConnection(&self.listener);
            self.handled += 1;
        }
    }

    fn serveTls(self: *PublishFixture) !void {
        var pair = try tlsCertificatePair(self.allocator, self.io);
        defer pair.deinit(self.allocator);
        while (self.handled < self.expected_requests) {
            try self.serveTlsConnection(&self.listener, &pair);
            self.handled += 1;
        }
    }

    fn serveSplitTlsUpload(self: *PublishFixture) !void {
        var pair = try tlsCertificatePair(self.allocator, self.io);
        defer pair.deinit(self.allocator);
        while (self.handled < self.expected_requests) {
            if (self.awaiting_cross_upload) {
                try self.serveTlsConnection(&self.cross_upload_listener.?, &pair);
            } else {
                try self.serveRawConnection(&self.listener);
            }
            self.handled += 1;
        }
    }

    fn serveRawConnection(self: *PublishFixture, listener: *Io.net.Server) !void {
        var stream = try listener.accept(self.io);
        defer stream.close(self.io);
        var input_buffer: [response_head_buffer_size]u8 = undefined;
        var output_buffer: [response_head_buffer_size]u8 = undefined;
        var reader = stream.reader(self.io, &input_buffer);
        var writer = stream.writer(self.io, &output_buffer);
        var server = std.http.Server.init(&reader.interface, &writer.interface);
        var request = try server.receiveHead();
        self.respond(&request) catch |err| switch (err) {
            error.UploadInterrupted, error.ManifestInterrupted => {},
            else => return err,
        };
    }

    fn serveTlsConnection(
        self: *PublishFixture,
        listener: *Io.net.Server,
        pair: *tls.config.CertKeyPair,
    ) !void {
        var stream = try listener.accept(self.io);
        defer stream.close(self.io);
        const random_source = std.Random.IoSource{ .io = self.io };
        var connection = try tls.serverFromStream(self.io, stream, .{
            .auth = pair,
            .now = Io.Clock.real.now(self.io),
            .rng = random_source.interface(),
        });
        var input_buffer: [tls.input_buffer_len]u8 = undefined;
        var output_buffer: [tls.output_buffer_len]u8 = undefined;
        var reader = connection.reader(&input_buffer);
        var writer = connection.writer(&output_buffer);
        var server = std.http.Server.init(&reader.interface, &writer.interface);
        var request = try server.receiveHead();
        self.respond(&request) catch |err| switch (err) {
            error.UploadInterrupted, error.ManifestInterrupted => {},
            else => return err,
        };
        try connection.close();
    }

    fn respond(self: *PublishFixture, request: *std.http.Server.Request) !void {
        const target = request.head.target;
        const is_cross_upload = self.cross_upload_authority != null and
            std.mem.startsWith(u8, target, "/upload/session?");
        if (is_cross_upload) {
            if (header(request, "Authorization") != null) {
                self.cross_upload_authorization_seen = true;
                return error.UnexpectedPublishRequest;
            }
        } else if (self.require_basic_auth) {
            const authorization = header(request, "Authorization") orelse
                return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{
                    .{ .name = "WWW-Authenticate", .value = "Basic realm=\"registry\"" },
                } });
            if (!std.mem.eql(u8, authorization, "Basic dXNlcjpzZWNyZXQ=")) {
                return error.UnexpectedPublishRequest;
            }
        }
        if (std.mem.eql(u8, target, "/v2/")) {
            if (request.head.method != .GET) return error.UnexpectedPublishRequest;
            return request.respond("", .{});
        }
        if (self.opaque_source_documents) |documents| {
            const source_manifest_prefix = "/v2/team/source/manifests/";
            if (std.mem.startsWith(u8, target, source_manifest_prefix)) {
                if (request.head.method != .GET) return error.UnexpectedPublishRequest;
                const selector = target[source_manifest_prefix.len..];
                if (std.mem.eql(u8, selector, "latest") or
                    std.mem.eql(u8, selector, documents.index_digest))
                {
                    return respondStored(
                        request,
                        documents.index,
                        documents.index_digest,
                        oci.model.media_type_oci_index,
                    );
                }
                if (std.mem.eql(u8, selector, documents.opaque_digest)) {
                    const accept = header(request, "Accept") orelse
                        return error.UnexpectedPublishRequest;
                    if (!std.mem.eql(u8, accept, "application/example.opaque")) {
                        return error.UnexpectedPublishRequest;
                    }
                    return respondStored(
                        request,
                        documents.opaque_bytes,
                        documents.opaque_digest,
                        "application/example.opaque",
                    );
                }
                return error.UnexpectedPublishRequest;
            }
            if (std.mem.startsWith(u8, target, "/v2/team/source/blobs/")) {
                return error.UnexpectedPublishRequest;
            }
        }
        if (self.source_documents) |documents| {
            var manifest_target_buffer: [128]u8 = undefined;
            const manifest_target = try std.fmt.bufPrint(
                &manifest_target_buffer,
                "/v2/team/source/manifests/{s}",
                .{documents.manifest_digest},
            );
            if (std.mem.eql(u8, target, "/v2/team/source/manifests/latest") or
                std.mem.eql(u8, target, manifest_target))
            {
                if (request.head.method != .GET) return error.UnexpectedPublishRequest;
                return respondStored(request, documents.manifest, documents.manifest_digest, oci.model.media_type_oci_manifest);
            }
            const source_blob_prefix = "/v2/team/source/blobs/";
            if (std.mem.startsWith(u8, target, source_blob_prefix)) {
                if (request.head.method != .GET) return error.UnexpectedPublishRequest;
                self.source_blob_gets += 1;
                const digest = target[source_blob_prefix.len..];
                if (std.mem.eql(u8, digest, documents.config_digest)) {
                    return respondStored(request, documents.config, documents.config_digest, oci.model.media_type_oci_config);
                }
                if (std.mem.eql(u8, digest, documents.layer_digest)) {
                    return respondStored(request, documents.layer, documents.layer_digest, oci.model.media_type_oci_layer);
                }
                return error.UnexpectedPublishRequest;
            }
        }
        const blob_prefix = "/v2/dest/blobs/";
        if (std.mem.startsWith(u8, target, blob_prefix)) {
            if (std.mem.startsWith(u8, target, "/v2/dest/blobs/uploads/")) {
                if (request.head.method != .POST) return error.UnexpectedPublishRequest;
                try self.events.append(.upload_post);
                if (header(request, "Authorization") != null) self.authorized_upload_posts += 1;
                if (std.mem.indexOf(u8, target, "mount=") != null) {
                    self.mount_posts += 1;
                    return self.respondMount(request, target);
                }
                switch (self.upload_start_behavior) {
                    .normal => {},
                    .malformed_location => return request.respond("", .{ .status = .accepted, .extra_headers = &.{
                        .{ .name = "Location", .value = "http://[bad" },
                    } }),
                    .denied => return request.respond("{\"errors\":[{\"code\":\"DENIED\"}]}", .{ .status = .forbidden }),
                }
                if (self.cross_upload_authority) |authority| {
                    var location_buffer: [256]u8 = undefined;
                    const location = try std.fmt.bufPrint(
                        &location_buffer,
                        "https://{s}/upload/session?ticket=opaque%2Fvalue",
                        .{authority},
                    );
                    self.awaiting_cross_upload = true;
                    return request.respond("", .{ .status = .accepted, .extra_headers = &.{
                        .{ .name = "Location", .value = location },
                    } });
                }
                return request.respond("", .{ .status = .accepted, .extra_headers = &.{
                    .{ .name = "Location", .value = "/upload/session?ticket=opaque%2Fvalue" },
                } });
            }
            const blob = self.findBlob(target[blob_prefix.len..]) orelse
                return request.respond("", .{ .status = .not_found });
            switch (request.head.method) {
                .HEAD => {
                    try self.events.append(.blob_head);
                    return self.respondBlob(request, blob);
                },
                .GET => {
                    self.blob_gets += 1;
                    return self.respondBlob(request, blob);
                },
                else => return error.UnexpectedPublishRequest,
            }
        }
        if (std.mem.startsWith(u8, target, "/upload/session?")) {
            if (request.head.method != .PUT) return error.UnexpectedPublishRequest;
            const content_type = request.head.content_type orelse return error.UnexpectedPublishRequest;
            const content_length = request.head.content_length orelse return error.UnexpectedPublishRequest;
            const authorization = header(request, "Authorization");
            const has_authorization = authorization != null;
            const has_expected_authorization = if (authorization) |value|
                std.mem.eql(u8, value, "Basic dXNlcjpzZWNyZXQ=")
            else
                false;
            if (!std.mem.eql(u8, content_type, "application/octet-stream")) return error.UnexpectedPublishRequest;
            const signed_prefix = "/upload/session?ticket=opaque%2Fvalue&digest=sha256%3A";
            self.signed_query_preserved = std.mem.startsWith(u8, target, signed_prefix) and
                target.len == signed_prefix.len + 64 and
                isLowerHex(target[signed_prefix.len..]);
            if (self.tls_enabled and is_cross_upload) {
                return self.respondCrossOriginUpload(request, target, content_length);
            }
            if (self.upload_behavior == .interrupt_before_store_once) {
                self.upload_behavior = .normal;
                return error.UploadInterrupted;
            }
            const body = try readPublishBody(self.allocator, request);
            defer self.allocator.free(body);
            if (content_length != body.len) return error.UnexpectedPublishRequest;
            if (self.upload_behavior == .challenge_once) {
                self.upload_behavior = .normal;
                self.upload_challenges += 1;
                if (has_authorization) return error.UnexpectedPublishRequest;
                return request.respond("", .{ .status = .unauthorized, .extra_headers = &.{
                    .{ .name = "WWW-Authenticate", .value = "Basic realm=\"push\"" },
                } });
            }
            if (self.upload_challenges != 0) {
                try std.testing.expect(has_expected_authorization);
            }
            const digest = try digestText(self.allocator, body);
            defer self.allocator.free(digest);
            try self.putBlob(digest, body);
            self.blob_uploads += 1;
            try self.events.append(.upload_put);
            if (self.upload_behavior == .interrupt_after_store_once) {
                self.upload_behavior = .normal;
                return error.UploadInterrupted;
            }
            var location_buffer: [160]u8 = undefined;
            const location = try std.fmt.bufPrint(&location_buffer, "/v2/dest/blobs/{s}", .{digest});
            return switch (self.upload_completion_behavior) {
                .normal => request.respond("", .{ .status = .created, .extra_headers = &.{
                    .{ .name = "Docker-Content-Digest", .value = digest },
                    .{ .name = "Location", .value = location },
                } }),
                .missing_location => request.respond("", .{ .status = .created, .extra_headers = &.{
                    .{ .name = "Docker-Content-Digest", .value = digest },
                } }),
                .malformed_location => request.respond("", .{ .status = .created, .extra_headers = &.{
                    .{ .name = "Docker-Content-Digest", .value = digest },
                    .{ .name = "Location", .value = "http://[bad" },
                } }),
            };
        }
        const manifest_prefix = "/v2/dest/manifests/";
        if (std.mem.startsWith(u8, target, manifest_prefix)) {
            const selector = target[manifest_prefix.len..];
            switch (request.head.method) {
                .PUT => {
                    const content_type = request.head.content_type orelse return error.UnexpectedPublishRequest;
                    const content_length = request.head.content_length orelse return error.UnexpectedPublishRequest;
                    const class = oci.model.classifyMediaType(content_type);
                    const body = try readPublishBody(self.allocator, request);
                    defer self.allocator.free(body);
                    if (content_length != body.len) return error.UnexpectedPublishRequest;
                    const digest = try digestText(self.allocator, body);
                    defer self.allocator.free(digest);
                    try self.events.append(.manifest_put);
                    if (self.manifest_behavior == .reject_root and std.mem.eql(u8, selector, "copied")) {
                        return request.respond("{\"errors\":[{\"code\":\"DENIED\"}]}", .{ .status = .bad_request });
                    }
                    try self.validateManifestDependencies(class, body);
                    try self.putManifest(selector, digest, body, content_type);
                    if (self.manifest_behavior == .interrupt_after_store_once) {
                        self.manifest_behavior = .normal;
                        return error.ManifestInterrupted;
                    }
                    return request.respond("", .{ .status = .created, .extra_headers = &.{
                        .{ .name = "Docker-Content-Digest", .value = digest },
                    } });
                },
                .HEAD => {
                    try self.events.append(.manifest_head);
                    const manifest = self.findManifest(selector) orelse
                        return request.respond("", .{ .status = .not_found });
                    return self.respondManifest(request, manifest);
                },
                .GET => {
                    self.manifest_gets += 1;
                    const manifest = self.findManifest(selector) orelse
                        return request.respond("", .{ .status = .not_found });
                    return self.respondManifest(request, manifest);
                },
                else => return error.UnexpectedPublishRequest,
            }
        }
        return error.UnexpectedPublishRequest;
    }

    fn respondCrossOriginUpload(
        self: *PublishFixture,
        request: *std.http.Server.Request,
        target: []const u8,
        content_length: u64,
    ) !void {
        const documents = self.source_documents orelse return error.UnexpectedPublishRequest;
        self.awaiting_cross_upload = false;
        const digest, const bytes = if (std.mem.indexOf(u8, target, documents.config_digest["sha256:".len..]) != null)
            .{ documents.config_digest, documents.config }
        else if (std.mem.indexOf(u8, target, documents.layer_digest["sha256:".len..]) != null)
            .{ documents.layer_digest, documents.layer }
        else
            return error.UnexpectedPublishRequest;
        if (content_length != bytes.len) return error.UnexpectedPublishRequest;
        const body = try readPublishBody(self.allocator, request);
        defer self.allocator.free(body);
        if (!std.mem.eql(u8, bytes, body)) return error.UnexpectedPublishRequest;
        try self.putBlob(digest, body);
        self.blob_uploads += 1;
        try self.events.append(.upload_put);
        var location_buffer: [160]u8 = undefined;
        const location = try std.fmt.bufPrint(&location_buffer, "/v2/dest/blobs/{s}", .{digest});
        return request.respond("", .{ .status = .created, .extra_headers = &.{
            .{ .name = "Docker-Content-Digest", .value = digest },
            .{ .name = "Location", .value = location },
        } });
    }

    fn respondMount(self: *PublishFixture, request: *std.http.Server.Request, target: []const u8) !void {
        const documents = self.source_documents orelse return error.UnexpectedPublishRequest;
        switch (self.mount_behavior) {
            .disabled => return error.UnexpectedPublishRequest,
            .accepted => return request.respond("", .{ .status = .accepted, .extra_headers = &.{
                .{ .name = "Location", .value = "/upload/session?ticket=opaque%2Fvalue" },
            } }),
            .malformed_location => return request.respond("", .{ .status = .accepted, .extra_headers = &.{
                .{ .name = "Location", .value = "http://[bad" },
            } }),
            .complete_missing_location => {
                try self.putBlob(documents.config_digest, documents.config);
                return request.respond("", .{ .status = .created, .extra_headers = &.{
                    .{ .name = "Docker-Content-Digest", .value = documents.config_digest },
                } });
            },
            .complete_malformed_location => {
                try self.putBlob(documents.config_digest, documents.config);
                return request.respond("", .{ .status = .created, .extra_headers = &.{
                    .{ .name = "Docker-Content-Digest", .value = documents.config_digest },
                    .{ .name = "Location", .value = "http://[bad" },
                } });
            },
            .interrupt_after_store => {},
            .denied => return request.respond("{\"errors\":[{\"code\":\"DENIED\"}]}", .{ .status = .forbidden }),
            .complete => {},
        }
        const encoded_config = "mount=sha256%3A";
        const digest = if (std.mem.indexOf(u8, target, encoded_config)) |offset| blk: {
            const digest_start = offset + encoded_config.len;
            const end = std.mem.indexOfScalarPos(u8, target, digest_start, '&') orelse target.len;
            break :blk target[digest_start..end];
        } else return error.UnexpectedPublishRequest;
        if (std.mem.eql(u8, digest, documents.config_digest["sha256:".len..])) {
            try self.putBlob(documents.config_digest, documents.config);
            if (self.mount_behavior == .interrupt_after_store) return error.UploadInterrupted;
            var location_buffer: [160]u8 = undefined;
            const location = try std.fmt.bufPrint(&location_buffer, "/v2/dest/blobs/{s}", .{documents.config_digest});
            return request.respond("", .{ .status = .created, .extra_headers = &.{
                .{ .name = "Docker-Content-Digest", .value = documents.config_digest },
                .{ .name = "Location", .value = location },
            } });
        }
        if (std.mem.eql(u8, digest, documents.layer_digest["sha256:".len..])) {
            try self.putBlob(documents.layer_digest, documents.layer);
            if (self.mount_behavior == .interrupt_after_store) return error.UploadInterrupted;
            var location_buffer: [160]u8 = undefined;
            const location = try std.fmt.bufPrint(&location_buffer, "/v2/dest/blobs/{s}", .{documents.layer_digest});
            return request.respond("", .{ .status = .created, .extra_headers = &.{
                .{ .name = "Docker-Content-Digest", .value = documents.layer_digest },
                .{ .name = "Location", .value = location },
            } });
        }
        return error.UnexpectedPublishRequest;
    }

    fn respondManifest(
        self: *PublishFixture,
        request: *std.http.Server.Request,
        manifest: PublishedManifest,
    ) !void {
        switch (self.manifest_verification) {
            .headers => return respondStored(request, manifest.bytes, manifest.digest, manifest.media_type),
            .omit_head_digest => return request.respond(manifest.bytes, .{ .extra_headers = &.{
                .{ .name = "Content-Type", .value = manifest.media_type },
            } }),
            .omit_head_digest_wrong_get => {
                if (request.head.method == .HEAD) {
                    return request.respond(manifest.bytes, .{ .extra_headers = &.{
                        .{ .name = "Content-Type", .value = manifest.media_type },
                    } });
                }
                const wrong = try self.allocator.dupe(u8, manifest.bytes);
                defer self.allocator.free(wrong);
                if (wrong.len == 0) return error.UnexpectedPublishRequest;
                wrong[wrong.len - 1] ^= 1;
                return request.respond(wrong, .{ .extra_headers = &.{
                    .{ .name = "Content-Type", .value = manifest.media_type },
                } });
            },
        }
    }

    fn validateManifestDependencies(
        self: *const PublishFixture,
        class: oci.model.MediaTypeClass,
        bytes: []const u8,
    ) !void {
        if (class.isIndex()) {
            var parsed = std.json.parseFromSlice(oci.model.Index, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch
                return error.UnexpectedPublishRequest;
            defer parsed.deinit();
            for (parsed.value.manifests) |descriptor| {
                if (self.findManifest(descriptor.digest) == null) return error.UnexpectedPublishRequest;
            }
            return;
        }
        if (class.isManifest()) {
            var parsed = std.json.parseFromSlice(oci.model.Manifest, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch
                return error.UnexpectedPublishRequest;
            defer parsed.deinit();
            if (self.findBlob(parsed.value.config.digest) == null) return error.UnexpectedPublishRequest;
            for (parsed.value.layers) |descriptor| {
                if (self.findBlob(descriptor.digest) == null) return error.UnexpectedPublishRequest;
            }
        }
    }

    fn respondBlob(self: *PublishFixture, request: *std.http.Server.Request, blob: PublishedBlob) !void {
        const digest = switch (request.head.method) {
            .HEAD => switch (self.blob_verification) {
                .headers => blob.digest,
                .omit_head_digest, .contradictory_get_digest => null,
                .contradictory_head_digest => badDigest,
            },
            .GET => switch (self.blob_verification) {
                .contradictory_get_digest => badDigest,
                else => blob.digest,
            },
            else => return error.UnexpectedPublishRequest,
        };
        if (digest) |value| {
            return request.respond(blob.bytes, .{ .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/octet-stream" },
                .{ .name = "Docker-Content-Digest", .value = value },
            } });
        }
        return request.respond(blob.bytes, .{ .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/octet-stream" },
        } });
    }

    fn findBlob(self: *const PublishFixture, digest: []const u8) ?PublishedBlob {
        for (self.blobs.items) |blob| {
            if (std.mem.eql(u8, blob.digest, digest)) return blob;
        }
        return null;
    }

    fn findManifest(self: *const PublishFixture, selector: []const u8) ?PublishedManifest {
        for (self.manifests.items) |manifest| {
            if (std.mem.eql(u8, manifest.selector, selector)) return manifest;
        }
        return null;
    }

    fn putBlob(self: *PublishFixture, digest: []const u8, bytes: []const u8) !void {
        if (self.findBlob(digest) != null) return;
        const digest_copy = try self.allocator.dupe(u8, digest);
        errdefer self.allocator.free(digest_copy);
        const bytes_copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(bytes_copy);
        try self.blobs.append(.{
            .digest = digest_copy,
            .bytes = bytes_copy,
        });
    }

    fn putManifest(
        self: *PublishFixture,
        selector: []const u8,
        digest: []const u8,
        bytes: []const u8,
        media_type: []const u8,
    ) !void {
        const selector_copy = try self.allocator.dupe(u8, selector);
        errdefer self.allocator.free(selector_copy);
        const digest_copy = try self.allocator.dupe(u8, digest);
        errdefer self.allocator.free(digest_copy);
        const bytes_copy = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(bytes_copy);
        const media_type_copy = try self.allocator.dupe(u8, media_type);
        errdefer self.allocator.free(media_type_copy);
        try self.manifests.append(.{
            .selector = selector_copy,
            .digest = digest_copy,
            .bytes = bytes_copy,
            .media_type = media_type_copy,
        });
    }
};

fn readPublishBody(allocator: std.mem.Allocator, request: *std.http.Server.Request) ![]u8 {
    const content_length = request.head.content_length orelse return error.UnexpectedPublishRequest;
    if (content_length > 16 * 1024 * 1024 or content_length > std.math.maxInt(usize)) {
        return error.UnexpectedPublishRequest;
    }
    const body = try allocator.alloc(u8, @intCast(content_length));
    errdefer allocator.free(body);
    var buffer: [16 * 1024]u8 = undefined;
    try request.readerExpectNone(&buffer).readSliceAll(body);
    return body;
}

fn respondStored(
    request: *std.http.Server.Request,
    bytes: []const u8,
    digest: []const u8,
    media_type: []const u8,
) !void {
    return request.respond(bytes, .{ .extra_headers = &.{
        .{ .name = "Content-Type", .value = media_type },
        .{ .name = "Docker-Content-Digest", .value = digest },
    } });
}

fn sourceBlobRequests(fixture: *const Fixture) usize {
    var count: usize = 0;
    for (fixture.logs.items) |log| {
        if (std.mem.startsWith(u8, log.target, "/v2/team/image/blobs/")) count += 1;
    }
    return count;
}

test "registry destination spools verified blobs and reuses verified HEAD hits" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_fixture = try Fixture.init(allocator, io, .anonymous, 7, null);
    defer source_fixture.deinit();
    var destination_fixture = try PublishFixture.init(allocator, io, 16);
    defer destination_fixture.deinit();
    try source_fixture.start();
    try destination_fixture.start();
    var source = try sourceFor(&source_fixture, null);
    defer source.deinit();
    const source_ref = referenceFor(&source_fixture);
    const destination_ref = oci.reference.RegistryReference{
        .authority = destination_fixture.authority,
        .repository = "dest",
        .selection = .{ .tag = "copied" },
    };
    var first = try source.copyToRegistry(source_ref, destination_ref, .{ .plain_http = true }, .{});
    defer first.deinit(allocator);
    var second = try source.copyToRegistry(source_ref, destination_ref, .{ .plain_http = true }, .{});
    defer second.deinit(allocator);
    try source_fixture.finish();
    try destination_fixture.finish();
    try std.testing.expectEqualStrings(source_fixture.manifest_digest, first.root.digest);
    try std.testing.expectEqual(@as(u64, 2), second.reused);
    try std.testing.expectEqual(@as(usize, 2), destination_fixture.blob_uploads);
    try std.testing.expectEqual(@as(usize, 2), sourceBlobRequests(&source_fixture));
    try std.testing.expect(destination_fixture.signed_query_preserved);
    const first_manifest = destination_fixture.findManifest("copied").?;
    try std.testing.expectEqualSlices(u8, source_fixture.manifest, first_manifest.bytes);
    const first_manifest_event = std.mem.indexOfScalar(PublishEvent, destination_fixture.events.items, .manifest_put).?;
    try std.testing.expect(first_manifest_event > 0);
    for (destination_fixture.events.items[0..first_manifest_event]) |event| {
        try std.testing.expect(event != .manifest_put);
    }
}

test "digestless destination HEAD is streamed before verified reuse" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_fixture = try Fixture.init(allocator, io, .anonymous, 7, null);
    defer source_fixture.deinit();
    var destination_fixture = try PublishFixture.init(allocator, io, 18);
    defer destination_fixture.deinit();
    try source_fixture.start();
    try destination_fixture.start();
    var source = try sourceFor(&source_fixture, null);
    defer source.deinit();
    const source_ref = referenceFor(&source_fixture);
    const destination_ref = oci.reference.RegistryReference{
        .authority = destination_fixture.authority,
        .repository = "dest",
        .selection = .{ .tag = "copied" },
    };
    var first = try source.copyToRegistry(source_ref, destination_ref, .{ .plain_http = true }, .{});
    defer first.deinit(allocator);
    destination_fixture.blob_verification = .omit_head_digest;
    var second = try source.copyToRegistry(source_ref, destination_ref, .{ .plain_http = true }, .{});
    defer second.deinit(allocator);
    try source_fixture.finish();
    try destination_fixture.finish();
    try std.testing.expectEqual(@as(u64, 2), second.reused);
    try std.testing.expectEqual(@as(usize, 2), destination_fixture.blob_gets);
    try std.testing.expectEqual(@as(usize, 2), destination_fixture.blob_uploads);
    try std.testing.expectEqual(@as(usize, 2), sourceBlobRequests(&source_fixture));
}

test "contradictory destination blob verification is corruption, not a transfer" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        mode: BlobVerificationMode,
        destination_requests: usize,
    }{
        .{ .mode = .contradictory_head_digest, .destination_requests = 13 },
        .{ .mode = .contradictory_get_digest, .destination_requests = 14 },
    };
    for (cases) |case| {
        var source_fixture = try Fixture.init(allocator, io, .anonymous, 7, null);
        defer source_fixture.deinit();
        var destination_fixture = try PublishFixture.init(allocator, io, case.destination_requests);
        defer destination_fixture.deinit();
        try source_fixture.start();
        try destination_fixture.start();
        var source = try sourceFor(&source_fixture, null);
        defer source.deinit();
        const source_ref = referenceFor(&source_fixture);
        const destination_ref = oci.reference.RegistryReference{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        };
        var first = try source.copyToRegistry(source_ref, destination_ref, .{ .plain_http = true }, .{});
        defer first.deinit(allocator);
        destination_fixture.blob_verification = case.mode;
        try std.testing.expectError(error.InvalidContentDigest, source.copyToRegistry(
            source_ref,
            destination_ref,
            .{ .plain_http = true },
            .{},
        ));
        try source_fixture.finish();
        try destination_fixture.finish();
        try std.testing.expectEqual(@as(usize, 2), destination_fixture.blob_uploads);
        try std.testing.expectEqual(@as(usize, 1), destination_fixture.manifests.items.len);
    }
}

test "blob upload ambiguity confirms or starts a fresh session from the verified spool" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        behavior: UploadBehavior,
        destination_requests: usize,
        upload_posts: usize,
    }{
        .{ .behavior = .interrupt_before_store_once, .destination_requests = 14, .upload_posts = 3 },
        .{ .behavior = .interrupt_after_store_once, .destination_requests = 11, .upload_posts = 2 },
    };
    for (cases) |case| {
        var source_fixture = try Fixture.init(allocator, io, .anonymous, 5, null);
        defer source_fixture.deinit();
        var destination_fixture = try PublishFixture.init(allocator, io, case.destination_requests);
        defer destination_fixture.deinit();
        destination_fixture.upload_behavior = case.behavior;
        try source_fixture.start();
        try destination_fixture.start();
        var source = try sourceFor(&source_fixture, null);
        defer source.deinit();
        const destination_ref = oci.reference.RegistryReference{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        };
        var result = try source.copyToRegistry(
            referenceFor(&source_fixture),
            destination_ref,
            .{ .plain_http = true },
            .{},
        );
        defer result.deinit(allocator);
        try source_fixture.finish();
        try destination_fixture.finish();
        try std.testing.expectEqual(case.upload_posts, countPublishEvents(&destination_fixture, .upload_post));
        try std.testing.expectEqual(@as(usize, 2), destination_fixture.blob_uploads);
        try std.testing.expectEqual(@as(usize, 2), sourceBlobRequests(&source_fixture));
    }
}

test "challenged blob PUT authenticates and restarts with a fresh upload session" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-upload-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};
    var source_fixture = try Fixture.init(allocator, io, .anonymous, 5, null);
    defer source_fixture.deinit();
    var destination_fixture = try PublishFixture.init(allocator, io, 14);
    defer destination_fixture.deinit();
    destination_fixture.upload_behavior = .challenge_once;
    try writeAuthfile(allocator, io, authfile, destination_fixture.authority);
    try source_fixture.start();
    try destination_fixture.start();
    var source = try sourceFor(&source_fixture, null);
    defer source.deinit();
    var result = try source.copyToRegistry(
        referenceFor(&source_fixture),
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        },
        .{ .plain_http = true, .authfile = authfile },
        .{},
    );
    defer result.deinit(allocator);
    try source_fixture.finish();
    try destination_fixture.finish();
    try std.testing.expectEqual(@as(usize, 1), destination_fixture.upload_challenges);
    try std.testing.expectEqual(@as(usize, 3), countPublishEvents(&destination_fixture, .upload_post));
    try std.testing.expectEqual(@as(usize, 2), destination_fixture.authorized_upload_posts);
    try std.testing.expectEqual(@as(usize, 2), destination_fixture.blob_uploads);
}

test "successful blob uploads require a valid completion Location" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]UploadCompletionBehavior{ .missing_location, .malformed_location };
    for (cases) |behavior| {
        var source_fixture = try Fixture.init(allocator, io, .anonymous, 4, null);
        defer source_fixture.deinit();
        var destination_fixture = try PublishFixture.init(allocator, io, 4);
        defer destination_fixture.deinit();
        destination_fixture.upload_completion_behavior = behavior;
        try source_fixture.start();
        try destination_fixture.start();
        var source = try sourceFor(&source_fixture, null);
        defer source.deinit();
        try std.testing.expectError(error.InvalidRedirect, source.copyToRegistry(
            referenceFor(&source_fixture),
            .{
                .authority = destination_fixture.authority,
                .repository = "dest",
                .selection = .{ .tag = "copied" },
            },
            .{ .plain_http = true },
            .{},
        ));
        try source_fixture.finish();
        try destination_fixture.finish();
        try std.testing.expectEqual(@as(usize, 1), destination_fixture.blob_uploads);
        try std.testing.expectEqual(@as(usize, 0), destination_fixture.manifests.items.len);
    }
}

test "rejected final root manifest leaves blobs unreferenced and no tag update" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_fixture = try Fixture.init(allocator, io, .anonymous, 5, null);
    defer source_fixture.deinit();
    var destination_fixture = try PublishFixture.init(allocator, io, 10);
    defer destination_fixture.deinit();
    destination_fixture.manifest_behavior = .reject_root;
    try source_fixture.start();
    try destination_fixture.start();
    var source = try sourceFor(&source_fixture, null);
    defer source.deinit();
    const destination_ref = oci.reference.RegistryReference{
        .authority = destination_fixture.authority,
        .repository = "dest",
        .selection = .{ .tag = "copied" },
    };
    try std.testing.expectError(error.RegistryRequestFailed, source.copyToRegistry(
        referenceFor(&source_fixture),
        destination_ref,
        .{ .plain_http = true },
        .{},
    ));
    try source_fixture.finish();
    try destination_fixture.finish();
    try std.testing.expectEqual(@as(usize, 2), destination_fixture.blobs.items.len);
    try std.testing.expectEqual(@as(usize, 0), destination_fixture.manifests.items.len);
    try std.testing.expectEqual(PublishEvent.manifest_put, destination_fixture.events.items[destination_fixture.events.items.len - 1]);
}

test "ambiguous final manifest PUT is confirmed by its digest reference" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_fixture = try Fixture.init(allocator, io, .anonymous, 5, null);
    defer source_fixture.deinit();
    var destination_fixture = try PublishFixture.init(allocator, io, 12);
    defer destination_fixture.deinit();
    destination_fixture.manifest_behavior = .interrupt_after_store_once;
    destination_fixture.manifest_verification = .omit_head_digest;
    try source_fixture.start();
    try destination_fixture.start();
    var source = try sourceFor(&source_fixture, null);
    defer source.deinit();
    const destination_ref = oci.reference.RegistryReference{
        .authority = destination_fixture.authority,
        .repository = "dest",
        .selection = .{ .tag = "copied" },
    };
    var result = try source.copyToRegistry(
        referenceFor(&source_fixture),
        destination_ref,
        .{ .plain_http = true },
        .{},
    );
    defer result.deinit(allocator);
    try source_fixture.finish();
    try destination_fixture.finish();
    const manifest = destination_fixture.findManifest("copied").?;
    try std.testing.expectEqualSlices(u8, source_fixture.manifest, manifest.bytes);
    try std.testing.expectEqual(@as(usize, 1), destination_fixture.manifest_gets);
}

test "digestless manifest confirmation hashes the GET response" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_fixture = try Fixture.init(allocator, io, .anonymous, 5, null);
    defer source_fixture.deinit();
    var destination_fixture = try PublishFixture.init(allocator, io, 12);
    defer destination_fixture.deinit();
    destination_fixture.manifest_verification = .omit_head_digest_wrong_get;
    try source_fixture.start();
    try destination_fixture.start();
    var source = try sourceFor(&source_fixture, null);
    defer source.deinit();
    try std.testing.expectError(error.DescriptorMismatch, source.copyToRegistry(
        referenceFor(&source_fixture),
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        },
        .{ .plain_http = true },
        .{},
    ));
    try source_fixture.finish();
    try destination_fixture.finish();
    try std.testing.expectEqual(@as(usize, 1), destination_fixture.manifest_gets);
}

test "malformed upload locations and denied push do not publish a manifest" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        behavior: UploadStartBehavior,
        expected_error: anyerror,
    }{
        .{ .behavior = .malformed_location, .expected_error = error.InvalidRedirect },
        .{ .behavior = .denied, .expected_error = error.RegistryRequestFailed },
    };
    for (cases) |case| {
        var source_fixture = try Fixture.init(allocator, io, .anonymous, 4, null);
        defer source_fixture.deinit();
        var destination_fixture = try PublishFixture.init(allocator, io, 3);
        defer destination_fixture.deinit();
        destination_fixture.upload_start_behavior = case.behavior;
        try source_fixture.start();
        try destination_fixture.start();
        var source = try sourceFor(&source_fixture, null);
        defer source.deinit();
        const destination_ref = oci.reference.RegistryReference{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        };
        try std.testing.expectError(case.expected_error, source.copyToRegistry(
            referenceFor(&source_fixture),
            destination_ref,
            .{ .plain_http = true },
            .{},
        ));
        try source_fixture.finish();
        try destination_fixture.finish();
        try std.testing.expectEqual(@as(usize, 0), destination_fixture.blob_uploads);
        try std.testing.expectEqual(@as(usize, 0), destination_fixture.manifests.items.len);
    }
}

test "malformed and denied mounts do not download source blobs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        behavior: MountBehavior,
        expected_error: anyerror,
    }{
        .{ .behavior = .malformed_location, .expected_error = error.InvalidRedirect },
        .{ .behavior = .complete_missing_location, .expected_error = error.InvalidRedirect },
        .{ .behavior = .complete_malformed_location, .expected_error = error.InvalidRedirect },
        .{ .behavior = .denied, .expected_error = error.RegistryRequestFailed },
    };
    for (cases) |case| {
        var seed = try Fixture.init(allocator, io, .anonymous, 0, null);
        defer seed.deinit();
        var fixture = try PublishFixture.init(allocator, io, 6);
        defer fixture.deinit();
        try fixture.configureSource(&seed, case.behavior);
        try fixture.start();
        const source_ref = oci.reference.RegistryReference{
            .authority = fixture.authority,
            .repository = "team/source",
            .selection = .{ .tag = "latest" },
        };
        const destination_ref = oci.reference.RegistryReference{
            .authority = fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        };
        var source = try oci.registry.Source.init(
            io,
            allocator,
            std.process.Environ.empty,
            source_ref,
            .{ .plain_http = true },
        );
        defer source.deinit();
        try std.testing.expectError(case.expected_error, source.copyToRegistry(
            source_ref,
            destination_ref,
            .{ .plain_http = true },
            .{},
        ));
        try fixture.finish();
        try std.testing.expectEqual(@as(usize, 0), fixture.source_blob_gets);
        try std.testing.expectEqual(@as(usize, 0), fixture.blob_uploads);
    }
}

test "layout to registry uses the shared dependency-first graph engine" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-layout-to-registry";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    var pull_fixture = try Fixture.init(allocator, io, .anonymous, 6, null);
    defer pull_fixture.deinit();
    try pull_fixture.start();
    var pull_source = try sourceFor(&pull_fixture, null);
    defer pull_source.deinit();
    var pulled = try pull_source.copyToLayout(
        referenceFor(&pull_fixture),
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer pulled.deinit(allocator);
    try pull_fixture.finish();

    var destination_fixture = try PublishFixture.init(allocator, io, 11);
    defer destination_fixture.deinit();
    try destination_fixture.start();
    const destination_ref = oci.reference.RegistryReference{
        .authority = destination_fixture.authority,
        .repository = "dest",
        .selection = .{ .tag = "copied" },
    };
    var published = try oci.registry.copyLayoutToRegistry(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        destination_ref,
        .{ .plain_http = true },
        .{},
    );
    defer published.deinit(allocator);
    try destination_fixture.finish();
    const manifest = destination_fixture.findManifest("copied").?;
    try std.testing.expectEqualSlices(u8, pull_fixture.manifest, manifest.bytes);
    try std.testing.expectEqualStrings(pull_fixture.manifest_digest, published.root.digest);
}

test "anonymous non-loopback plain HTTP registry publication is permitted explicitly" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-anonymous-remote-http-layout";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    var pull_fixture = try Fixture.init(allocator, io, .anonymous, 6, null);
    defer pull_fixture.deinit();
    try pull_fixture.start();
    var pull_source = try sourceFor(&pull_fixture, null);
    defer pull_source.deinit();
    var pulled = try pull_source.copyToLayout(
        referenceFor(&pull_fixture),
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer pulled.deinit(allocator);
    try pull_fixture.finish();

    var destination_fixture = try PublishFixture.initNonLoopback(allocator, io, 11);
    defer destination_fixture.deinit();
    try destination_fixture.start();
    var published = try oci.registry.copyLayoutToRegistry(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        },
        .{ .plain_http = true },
        .{},
    );
    defer published.deinit(allocator);
    try destination_fixture.finish();
    try std.testing.expectEqualStrings(pull_fixture.manifest_digest, published.root.digest);
}

test "authenticated cross-origin HTTPS uploads preserve signed queries and strip Authorization" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-cross-origin-upload-layout";
    const authfile = "test-oci-cross-origin-upload-auth.json";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};

    var destination_fixture = try PublishFixture.initTlsCrossOrigin(allocator, io, 12);
    defer destination_fixture.deinit();
    destination_fixture.source_documents = try makeSmallPublishLayout(allocator, io, layout_path, "copied");
    try writeAuthfile(allocator, io, authfile, destination_fixture.authority);
    try destination_fixture.start();
    var published = try oci.registry.copyLayoutToRegistry(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        },
        .{
            .authfile = authfile,
            .tls_ca = "tests/fixtures/oci-registry/test-ca-cert.pem",
            .plain_http = true,
        },
        .{},
    );
    defer published.deinit(allocator);
    try destination_fixture.finish();
    try std.testing.expect(destination_fixture.signed_query_preserved);
    try std.testing.expect(!destination_fixture.cross_upload_authorization_seen);
    const manifest = destination_fixture.findManifest("copied").?;
    try std.testing.expectEqualSlices(u8, destination_fixture.source_documents.?.manifest, manifest.bytes);
}

test "all-mode registry publication puts child manifests before the root index" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-all-layout-to-registry";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    var pull_fixture = try Fixture.init(allocator, io, .anonymous, 6, null);
    defer pull_fixture.deinit();
    try pull_fixture.start();
    var pull_source = try sourceFor(&pull_fixture, null);
    defer pull_source.deinit();
    var pulled = try pull_source.copyToLayout(
        referenceFor(&pull_fixture),
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer pulled.deinit(allocator);
    try pull_fixture.finish();
    const root_index = try addIndexRoot(
        allocator,
        io,
        layout_path,
        pull_fixture.manifest_digest,
        pull_fixture.manifest.len,
        "multi",
    );
    defer allocator.free(root_index.digest);
    defer allocator.free(root_index.bytes);

    var destination_fixture = try PublishFixture.init(allocator, io, 13);
    defer destination_fixture.deinit();
    try destination_fixture.start();
    const destination_ref = oci.reference.RegistryReference{
        .authority = destination_fixture.authority,
        .repository = "dest",
        .selection = .{ .tag = "multi" },
    };
    var published = try oci.registry.copyLayoutToRegistry(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .path = layout_path, .selection = .{ .tag = "multi" } },
        destination_ref,
        .{ .plain_http = true },
        .{},
    );
    defer published.deinit(allocator);
    try destination_fixture.finish();
    try std.testing.expectEqualStrings(root_index.digest, published.root.digest);
    try std.testing.expectEqual(@as(usize, 2), destination_fixture.manifests.items.len);
    const child = destination_fixture.findManifest(pull_fixture.manifest_digest).?;
    const root = destination_fixture.findManifest("multi").?;
    try std.testing.expectEqualSlices(u8, pull_fixture.manifest, child.bytes);
    try std.testing.expectEqualSlices(u8, root_index.bytes, root.bytes);
    try std.testing.expectEqualStrings(oci.model.media_type_oci_index, root.media_type);
    try std.testing.expectEqualStrings(pull_fixture.manifest_digest, destination_fixture.manifests.items[0].selector);
    try std.testing.expectEqualStrings("multi", destination_fixture.manifests.items[1].selector);
    const first_manifest_put = std.mem.indexOfScalar(PublishEvent, destination_fixture.events.items, .manifest_put).?;
    const last_upload = lastPublishEvent(&destination_fixture, .upload_put).?;
    try std.testing.expect(first_manifest_put > last_upload);
}

test "selected registry publication commits only the selected leaf graph" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-selected-layout-to-registry";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    var pull_fixture = try Fixture.init(allocator, io, .anonymous, 6, null);
    defer pull_fixture.deinit();
    try pull_fixture.start();
    var pull_source = try sourceFor(&pull_fixture, null);
    defer pull_source.deinit();
    var pulled = try pull_source.copyToLayout(
        referenceFor(&pull_fixture),
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer pulled.deinit(allocator);
    try pull_fixture.finish();
    const root_index = try addIndexRoot(
        allocator,
        io,
        layout_path,
        pull_fixture.manifest_digest,
        pull_fixture.manifest.len,
        "multi",
    );
    defer allocator.free(root_index.digest);
    defer allocator.free(root_index.bytes);

    var destination_fixture = try PublishFixture.init(allocator, io, 11);
    defer destination_fixture.deinit();
    try destination_fixture.start();
    const destination_ref = oci.reference.RegistryReference{
        .authority = destination_fixture.authority,
        .repository = "dest",
        .selection = .{ .tag = "selected" },
    };
    var published = try oci.registry.copyLayoutToRegistry(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .path = layout_path, .selection = .{ .tag = "multi" } },
        destination_ref,
        .{ .plain_http = true },
        .{ .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } } },
    );
    defer published.deinit(allocator);
    try destination_fixture.finish();
    try std.testing.expectEqualStrings(pull_fixture.manifest_digest, published.root.digest);
    try std.testing.expectEqual(@as(usize, 1), destination_fixture.manifests.items.len);
    const leaf = destination_fixture.findManifest("selected").?;
    try std.testing.expectEqualSlices(u8, pull_fixture.manifest, leaf.bytes);
}

test "selected registry publication validates a digest destination against the selected leaf" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-selected-digest-layout-to-registry";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    var pull_fixture = try Fixture.init(allocator, io, .anonymous, 6, null);
    defer pull_fixture.deinit();
    try pull_fixture.start();
    var pull_source = try sourceFor(&pull_fixture, null);
    defer pull_source.deinit();
    var pulled = try pull_source.copyToLayout(
        referenceFor(&pull_fixture),
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer pulled.deinit(allocator);
    try pull_fixture.finish();
    const root_index = try addIndexRoot(
        allocator,
        io,
        layout_path,
        pull_fixture.manifest_digest,
        pull_fixture.manifest.len,
        "multi",
    );
    defer allocator.free(root_index.digest);
    defer allocator.free(root_index.bytes);

    var destination_fixture = try PublishFixture.init(allocator, io, 11);
    defer destination_fixture.deinit();
    try destination_fixture.start();
    const selected_digest = try oci.content.Digest.parse(pull_fixture.manifest_digest);
    var published = try oci.registry.copyLayoutToRegistry(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .path = layout_path, .selection = .{ .tag = "multi" } },
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .digest = selected_digest },
        },
        .{ .plain_http = true },
        .{ .mode = .{ .selected = .{ .os = "linux", .architecture = "amd64" } } },
    );
    defer published.deinit(allocator);
    try destination_fixture.finish();
    try std.testing.expectEqualStrings(pull_fixture.manifest_digest, published.root.digest);
    try std.testing.expect(destination_fixture.findManifest(pull_fixture.manifest_digest) != null);
}

test "all-mode registry publication retains unknown opaque index leaves as manifests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-opaque-layout-to-registry";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    var pull_fixture = try Fixture.init(allocator, io, .anonymous, 6, null);
    defer pull_fixture.deinit();
    try pull_fixture.start();
    var pull_source = try sourceFor(&pull_fixture, null);
    defer pull_source.deinit();
    var pulled = try pull_source.copyToLayout(
        referenceFor(&pull_fixture),
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer pulled.deinit(allocator);
    try pull_fixture.finish();
    var opaque_index = try addIndexRootWithOpaque(
        allocator,
        io,
        layout_path,
        pull_fixture.manifest_digest,
        pull_fixture.manifest.len,
        "multi",
    );
    defer opaque_index.deinit(allocator);

    var destination_fixture = try PublishFixture.init(allocator, io, 15);
    defer destination_fixture.deinit();
    try destination_fixture.start();
    var published = try oci.registry.copyLayoutToRegistry(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .path = layout_path, .selection = .{ .tag = "multi" } },
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "multi" },
        },
        .{ .plain_http = true },
        .{},
    );
    defer published.deinit(allocator);
    try destination_fixture.finish();
    try std.testing.expectEqualStrings(opaque_index.root.digest, published.root.digest);
    const stored = destination_fixture.findManifest(opaque_index.opaque_digest).?;
    try std.testing.expectEqualSlices(u8, opaque_index.opaque_bytes, stored.bytes);
    try std.testing.expectEqual(@as(usize, 2), destination_fixture.blobs.items.len);
    try std.testing.expectEqual(@as(usize, 3), destination_fixture.manifests.items.len);
}

test "registry all-mode fetches unknown index children through the manifest endpoint" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-opaque-registry-to-layout";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    var fixture = try PublishFixture.init(allocator, io, 5);
    defer fixture.deinit();
    try fixture.configureOpaqueSource();
    try fixture.start();
    const source_ref = oci.reference.RegistryReference{
        .authority = fixture.authority,
        .repository = "team/source",
        .selection = .{ .tag = "latest" },
    };
    var source = try oci.registry.Source.init(
        io,
        allocator,
        std.process.Environ.empty,
        source_ref,
        .{ .plain_http = true },
    );
    defer source.deinit();
    var copied = try source.copyToLayout(
        source_ref,
        .{ .path = layout_path, .selection = .{ .tag = "copied" } },
        .{},
    );
    defer copied.deinit(allocator);
    try fixture.finish();
    const documents = fixture.opaque_source_documents.?;
    try std.testing.expectEqualStrings(documents.index_digest, copied.root.digest);
    var directory = try Io.Dir.cwd().openDir(io, layout_path, .{});
    defer directory.close(io);
    var path_buffer: [80]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &path_buffer,
        "blobs/sha256/{s}",
        .{documents.opaque_digest["sha256:".len..]},
    );
    var file = try directory.openFile(io, path, .{});
    defer file.close(io);
    const stored = try allocator.alloc(u8, @intCast(try file.length(io)));
    defer allocator.free(stored);
    try std.testing.expectEqual(stored.len, try file.readPositionalAll(io, stored, 0));
    try std.testing.expectEqualSlices(u8, documents.opaque_bytes, stored);
}

test "invalid opaque media types fail planning before destination requests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_fixture = try PublishFixture.init(allocator, io, 2);
    defer source_fixture.deinit();
    try source_fixture.configureOpaqueSourceWithMediaType(
        "application/example.opaque\r\nAuthorization: injected",
    );
    var destination_fixture = try PublishFixture.init(allocator, io, 0);
    defer destination_fixture.deinit();
    try source_fixture.start();
    const source_ref = oci.reference.RegistryReference{
        .authority = source_fixture.authority,
        .repository = "team/source",
        .selection = .{ .tag = "latest" },
    };
    var source = try oci.registry.Source.init(
        io,
        allocator,
        std.process.Environ.empty,
        source_ref,
        .{ .plain_http = true },
    );
    defer source.deinit();
    try std.testing.expectError(error.InvalidManifest, source.copyToRegistry(
        source_ref,
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        },
        .{ .plain_http = true },
        .{},
    ));
    try source_fixture.finish();
    try std.testing.expectEqual(@as(usize, 0), destination_fixture.handled);
}

test "graph depth failures occur before registry destination requests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const layout_path = "test-oci-depth-planning-layout";
    deleteLayout(io, layout_path);
    defer deleteLayout(io, layout_path);
    var documents = try makeSmallPublishLayout(allocator, io, layout_path, "leaf");
    defer documents.deinit(allocator);
    const inner = try addIndexRoot(
        allocator,
        io,
        layout_path,
        documents.manifest_digest,
        documents.manifest.len,
        "inner",
    );
    defer {
        allocator.free(inner.digest);
        allocator.free(inner.bytes);
    }
    const outer = try addIndexRootWithChildMediaType(
        allocator,
        io,
        layout_path,
        oci.model.media_type_oci_index,
        inner.digest,
        inner.bytes.len,
        "outer",
    );
    defer {
        allocator.free(outer.digest);
        allocator.free(outer.bytes);
    }
    var destination_fixture = try PublishFixture.init(allocator, io, 0);
    defer destination_fixture.deinit();
    try std.testing.expectError(error.MaximumDepthExceeded, oci.registry.copyLayoutToRegistry(
        io,
        allocator,
        std.process.Environ.empty,
        .{ .path = layout_path, .selection = .{ .tag = "outer" } },
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        },
        .{ .plain_http = true },
        .{ .max_depth = 0 },
    ));
    try std.testing.expectEqual(@as(usize, 0), destination_fixture.handled);
}

test "digest-pinned registry destination rejects a different root before publication" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_fixture = try Fixture.init(allocator, io, .anonymous, 3, null);
    defer source_fixture.deinit();
    var destination_fixture = try PublishFixture.init(allocator, io, 0);
    defer destination_fixture.deinit();
    try source_fixture.start();
    var source = try sourceFor(&source_fixture, null);
    defer source.deinit();
    const requested = try oci.content.Digest.parse(badDigest);
    try std.testing.expectError(error.DescriptorMismatch, source.copyToRegistry(
        referenceFor(&source_fixture),
        .{
            .authority = destination_fixture.authority,
            .repository = "dest",
            .selection = .{ .digest = requested },
        },
        .{ .plain_http = true },
        .{},
    ));
    try source_fixture.finish();
    try std.testing.expectEqual(@as(usize, 0), destination_fixture.handled);
}

test "same-registry mounts avoid source reads and 202 falls back to a verified spool" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cases = [_]struct {
        behavior: MountBehavior,
        requests: usize,
        mounts: u64,
        source_blob_gets: usize,
        uploads: usize,
    }{
        .{ .behavior = .complete, .requests = 12, .mounts = 2, .source_blob_gets = 0, .uploads = 0 },
        .{ .behavior = .interrupt_after_store, .requests = 12, .mounts = 2, .source_blob_gets = 0, .uploads = 0 },
        .{ .behavior = .accepted, .requests = 16, .mounts = 0, .source_blob_gets = 2, .uploads = 2 },
    };
    for (cases) |case| {
        var seed = try Fixture.init(allocator, io, .anonymous, 0, null);
        defer seed.deinit();
        var fixture = try PublishFixture.init(allocator, io, case.requests);
        defer fixture.deinit();
        try fixture.configureSource(&seed, case.behavior);
        try fixture.start();
        const source_ref = oci.reference.RegistryReference{
            .authority = fixture.authority,
            .repository = "team/source",
            .selection = .{ .tag = "latest" },
        };
        const destination_ref = oci.reference.RegistryReference{
            .authority = fixture.authority,
            .repository = "dest",
            .selection = .{ .tag = "copied" },
        };
        var source = try oci.registry.Source.init(
            io,
            allocator,
            std.process.Environ.empty,
            source_ref,
            .{ .plain_http = true },
        );
        defer source.deinit();
        var result = try source.copyToRegistry(source_ref, destination_ref, .{ .plain_http = true }, .{});
        defer result.deinit(allocator);
        try fixture.finish();
        try std.testing.expectEqual(case.mounts, result.mounted);
        try std.testing.expectEqual(case.source_blob_gets, fixture.source_blob_gets);
        try std.testing.expectEqual(case.uploads, fixture.blob_uploads);
        try std.testing.expectEqual(@as(usize, 2), fixture.mount_posts);
    }
}

test "authenticated same-registry mounts retain push authorization without source downloads" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const authfile = "test-oci-registry-mount-auth.json";
    defer Io.Dir.cwd().deleteFile(io, authfile) catch {};
    var seed = try Fixture.init(allocator, io, .anonymous, 0, null);
    defer seed.deinit();
    var fixture = try PublishFixture.init(allocator, io, 14);
    defer fixture.deinit();
    try fixture.configureSource(&seed, .complete);
    fixture.require_basic_auth = true;
    try writeAuthfile(allocator, io, authfile, fixture.authority);
    try fixture.start();
    const source_ref = oci.reference.RegistryReference{
        .authority = fixture.authority,
        .repository = "team/source",
        .selection = .{ .tag = "latest" },
    };
    const destination_ref = oci.reference.RegistryReference{
        .authority = fixture.authority,
        .repository = "dest",
        .selection = .{ .tag = "copied" },
    };
    var source = try oci.registry.Source.init(
        io,
        allocator,
        std.process.Environ.empty,
        source_ref,
        .{ .plain_http = true, .authfile = authfile },
    );
    defer source.deinit();
    var copied = try source.copyToRegistry(
        source_ref,
        destination_ref,
        .{ .plain_http = true, .authfile = authfile },
        .{},
    );
    defer copied.deinit(allocator);
    try fixture.finish();
    try std.testing.expectEqual(@as(u64, 2), copied.mounted);
    try std.testing.expectEqual(@as(usize, 0), fixture.source_blob_gets);
    try std.testing.expectEqual(@as(usize, 2), fixture.authorized_upload_posts);
}

fn referenceFor(fixture: *const Fixture) oci.reference.RegistryReference {
    return .{
        .authority = fixture.authority,
        .repository = "team/image",
        .selection = .{ .tag = "latest" },
    };
}

fn countPublishEvents(fixture: *const PublishFixture, expected: PublishEvent) usize {
    var count: usize = 0;
    for (fixture.events.items) |event| {
        if (event == expected) count += 1;
    }
    return count;
}

const AddedIndex = struct {
    digest: []u8,
    bytes: []u8,
};

const AddedOpaqueIndex = struct {
    root: AddedIndex,
    opaque_bytes: []u8,
    opaque_digest: []u8,

    fn deinit(self: *AddedOpaqueIndex, allocator: std.mem.Allocator) void {
        allocator.free(self.root.digest);
        allocator.free(self.root.bytes);
        allocator.free(self.opaque_bytes);
        allocator.free(self.opaque_digest);
        self.* = undefined;
    }
};

fn addIndexRoot(
    allocator: std.mem.Allocator,
    io: Io,
    layout_path: []const u8,
    child_digest: []const u8,
    child_size: usize,
    name: []const u8,
) !AddedIndex {
    return addIndexRootWithChildMediaType(
        allocator,
        io,
        layout_path,
        oci.model.media_type_oci_manifest,
        child_digest,
        child_size,
        name,
    );
}

fn addIndexRootWithChildMediaType(
    allocator: std.mem.Allocator,
    io: Io,
    layout_path: []const u8,
    child_media_type: []const u8,
    child_digest: []const u8,
    child_size: usize,
    name: []const u8,
) !AddedIndex {
    const bytes = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ oci.model.media_type_oci_index, child_media_type, child_digest, child_size },
    );
    errdefer allocator.free(bytes);
    const digest = try digestText(allocator, bytes);
    errdefer allocator.free(digest);
    var directory = try Io.Dir.cwd().openDir(io, layout_path, .{});
    defer directory.close(io);
    var blob_path_buffer: [80]u8 = undefined;
    const blob_path = try std.fmt.bufPrint(&blob_path_buffer, "blobs/sha256/{s}", .{digest["sha256:".len..]});
    try directory.writeFile(io, .{ .sub_path = blob_path, .data = bytes });
    const index = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"{s}\"}}}}]}}",
        .{ oci.model.media_type_oci_index, digest, bytes.len, name },
    );
    defer allocator.free(index);
    try directory.writeFile(io, .{ .sub_path = "index.json", .data = index });
    return .{ .digest = digest, .bytes = bytes };
}

fn makeSmallPublishLayout(
    allocator: std.mem.Allocator,
    io: Io,
    layout_path: []const u8,
    name: []const u8,
) !PublishSourceDocuments {
    const config = try allocator.dupe(u8, "{\"architecture\":\"amd64\",\"os\":\"linux\"}");
    errdefer allocator.free(config);
    const layer = try allocator.dupe(u8, "small layer");
    errdefer allocator.free(layer);
    const config_digest = try digestText(allocator, config);
    errdefer allocator.free(config_digest);
    const layer_digest = try digestText(allocator, layer);
    errdefer allocator.free(layer_digest);
    const manifest = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{
            oci.model.media_type_oci_manifest,
            oci.model.media_type_oci_config,
            config_digest,
            config.len,
            oci.model.media_type_oci_layer,
            layer_digest,
            layer.len,
        },
    );
    errdefer allocator.free(manifest);
    const manifest_digest = try digestText(allocator, manifest);
    errdefer allocator.free(manifest_digest);

    try Io.Dir.cwd().createDirPath(io, layout_path);
    var directory = try Io.Dir.cwd().openDir(io, layout_path, .{});
    defer directory.close(io);
    try directory.createDirPath(io, "blobs/sha256");
    try directory.writeFile(io, .{
        .sub_path = "oci-layout",
        .data = "{\"imageLayoutVersion\":\"1.0.0\"}\n",
    });
    try writePublishLayoutBlob(io, directory, config_digest, config);
    try writePublishLayoutBlob(io, directory, layer_digest, layer);
    try writePublishLayoutBlob(io, directory, manifest_digest, manifest);
    const index = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"{s}\"}}}}]}}\n",
        .{ oci.model.media_type_oci_manifest, manifest_digest, manifest.len, name },
    );
    defer allocator.free(index);
    try directory.writeFile(io, .{ .sub_path = "index.json", .data = index });
    return .{
        .config = config,
        .layer = layer,
        .manifest = manifest,
        .config_digest = config_digest,
        .layer_digest = layer_digest,
        .manifest_digest = manifest_digest,
    };
}

fn writePublishLayoutBlob(
    io: Io,
    directory: Io.Dir,
    digest: []const u8,
    bytes: []const u8,
) !void {
    var path_buffer: [80]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "blobs/sha256/{s}", .{digest["sha256:".len..]});
    try directory.writeFile(io, .{ .sub_path = path, .data = bytes });
}

fn addIndexRootWithOpaque(
    allocator: std.mem.Allocator,
    io: Io,
    layout_path: []const u8,
    child_digest: []const u8,
    child_size: usize,
    name: []const u8,
) !AddedOpaqueIndex {
    const opaque_bytes = try allocator.dupe(u8, "opaque index leaf");
    errdefer allocator.free(opaque_bytes);
    const opaque_digest = try digestText(allocator, opaque_bytes);
    errdefer allocator.free(opaque_digest);
    var directory = try Io.Dir.cwd().openDir(io, layout_path, .{});
    defer directory.close(io);
    var opaque_path_buffer: [80]u8 = undefined;
    const opaque_path = try std.fmt.bufPrint(
        &opaque_path_buffer,
        "blobs/sha256/{s}",
        .{opaque_digest["sha256:".len..]},
    );
    try directory.writeFile(io, .{ .sub_path = opaque_path, .data = opaque_bytes });
    const bytes = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},{{\"mediaType\":\"application/example.opaque\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{
            oci.model.media_type_oci_index,
            oci.model.media_type_oci_manifest,
            child_digest,
            child_size,
            opaque_digest,
            opaque_bytes.len,
        },
    );
    errdefer allocator.free(bytes);
    const digest = try digestText(allocator, bytes);
    errdefer allocator.free(digest);
    var root_path_buffer: [80]u8 = undefined;
    const root_path = try std.fmt.bufPrint(
        &root_path_buffer,
        "blobs/sha256/{s}",
        .{digest["sha256:".len..]},
    );
    try directory.writeFile(io, .{ .sub_path = root_path, .data = bytes });
    const index = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"{s}\"}}}}]}}",
        .{ oci.model.media_type_oci_index, digest, bytes.len, name },
    );
    defer allocator.free(index);
    try directory.writeFile(io, .{ .sub_path = "index.json", .data = index });
    return .{
        .root = .{ .digest = digest, .bytes = bytes },
        .opaque_bytes = opaque_bytes,
        .opaque_digest = opaque_digest,
    };
}

fn lastPublishEvent(fixture: *const PublishFixture, expected: PublishEvent) ?usize {
    var result: ?usize = null;
    for (fixture.events.items, 0..) |event, index| {
        if (event == expected) result = index;
    }
    return result;
}
