//! Reusable host-side acquisition and decompression primitives for image
//! builders. Outputs are written through owned atomic file handles and replace
//! existing artifacts only after validation succeeds.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Sha256 = std.crypto.hash.sha2.Sha256;
const image = @import("image.zig");
const qcow2 = @import("qcow2.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const vhd = @import("vhd.zig");

pub const Digest = [Sha256.digest_length]u8;

pub const Metadata = struct {
    path: []const u8,
    sha256: Digest,
    size: u64,
};

pub const Acquisition = struct {
    artifact: Metadata,
    reused_cache: bool,
};

/// Download implementations receive only a writer for the pipeline-owned
/// stage. They cannot replace the stage path or redirect publication.
pub const Downloader = struct {
    context: ?*anyopaque = null,
    downloadFn: *const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        url: []const u8,
        max_size: u64,
        output: *Io.Writer,
    ) anyerror!void,

    pub fn download(
        self: Downloader,
        allocator: Allocator,
        io: Io,
        url: []const u8,
        max_size: u64,
        output: *Io.Writer,
    ) !void {
        return self.downloadFn(
            self.context,
            allocator,
            io,
            url,
            max_size,
            output,
        );
    }
};

pub const CurlDownloader = struct {
    executable_path: []const u8,
    retries: u8 = 3,

    pub fn downloader(self: *CurlDownloader) Downloader {
        return .{
            .context = self,
            .downloadFn = download,
        };
    }

    fn download(
        context_ptr: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        url: []const u8,
        _: u64,
        output: *Io.Writer,
    ) !void {
        const self: *CurlDownloader = @ptrCast(@alignCast(context_ptr.?));
        const retries = try std.fmt.allocPrint(
            allocator,
            "{d}",
            .{self.retries},
        );
        defer allocator.free(retries);
        var child = try std.process.spawn(io, .{
            .argv = &.{
                self.executable_path,
                "-fLsS",
                "--retry",
                retries,
                url,
            },
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .inherit,
        });
        defer child.kill(io);

        var pipe_buffer: [64 * 1024]u8 = undefined;
        var pipe_reader = child.stdout.?.readerStreaming(io, &pipe_buffer);
        var buffer: [64 * 1024]u8 = undefined;
        while (true) {
            const read = try pipe_reader.interface.readSliceShort(&buffer);
            if (read == 0) break;
            try output.writeAll(buffer[0..read]);
        }
        const term = try child.wait(io);
        switch (term) {
            .exited => |code| if (code != 0) return error.CurlFailed,
            else => return error.CurlFailed,
        }
    }
};

pub const NativeHttpsResponse = struct {
    status: u16,
    redirect_location: ?[]const u8 = null,
    /// Set only when `redirect_location` was allocated with the downloader's
    /// request allocator and must be released after redirect processing.
    redirect_location_owned: bool = false,
    content_length: ?u64 = null,
};

/// The native HTTPS transport is replaceable so callers can exercise its
/// security policy without network access. Production uses Zig's TLS client.
pub const NativeHttpsTransport = struct {
    context: ?*anyopaque = null,
    getFn: *const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        url: []const u8,
        max_size: u64,
        output: *Io.Writer,
    ) anyerror!NativeHttpsResponse,

    pub fn get(
        self: NativeHttpsTransport,
        allocator: Allocator,
        io: Io,
        url: []const u8,
        max_size: u64,
        output: *Io.Writer,
    ) !NativeHttpsResponse {
        return self.getFn(
            self.context,
            allocator,
            io,
            url,
            max_size,
            output,
        );
    }
};

pub const Sleep = struct {
    context: ?*anyopaque,
    call: *const fn (
        context: ?*anyopaque,
        io: Io,
        seconds: u64,
    ) anyerror!void,
};

/// HTTPS-only downloader for pinned public artifacts. It uses Zig's native
/// TLS client (which negotiates TLS 1.2 or newer), follows only bounded HTTPS
/// redirects, and retries only before any response body is published.
pub const NativeHttpsDownloader = struct {
    retries: u8 = native_https_max_retries,
    max_redirects: u8 = native_https_max_redirects,
    max_backoff_seconds: u64 = native_https_max_backoff_seconds,
    sleep: ?Sleep = null,
    transport: ?NativeHttpsTransport = null,
    client: ?std.http.Client = null,
    /// Storage for the parsed proxy, owned here because `std.http.Client`
    /// holds a pointer to it for as long as the client exists. The client's
    /// pointers are bound at fetch time rather than here, so they always name
    /// this field at its current address even though `initProxied` returns by
    /// value and a caller may then move or copy the downloader.
    proxy: ?std.http.Client.Proxy = null,

    pub fn init(allocator: Allocator, io: Io) NativeHttpsDownloader {
        return .{
            .client = .{
                .allocator = allocator,
                .io = io,
                .read_buffer_size = native_https_response_head_limit,
                .write_buffer_size = native_https_write_buffer_size,
            },
        };
    }

    /// As `init`, but reaching the artifact host through an HTTP proxy.
    ///
    /// The proxy is named explicitly rather than read from the environment, so
    /// a build's egress path is a stated input like every other one and cannot
    /// change because of an ambient variable. TLS is unaffected: the proxy is
    /// asked to `CONNECT`, and the session is negotiated end to end with the
    /// artifact host, so pinned digests and signature checks still verify the
    /// bytes that host served.
    pub fn initProxied(
        allocator: Allocator,
        io: Io,
        proxy_url: []const u8,
    ) !NativeHttpsDownloader {
        var self = init(allocator, io);
        self.proxy = try parseProxy(proxy_url);
        return self;
    }

    pub fn deinit(self: *NativeHttpsDownloader) void {
        if (self.client) |*client| client.deinit();
        self.* = undefined;
    }

    pub fn downloader(self: *NativeHttpsDownloader) Downloader {
        return .{
            .context = self,
            .downloadFn = download,
        };
    }

    fn download(
        context_ptr: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        url: []const u8,
        max_size: u64,
        output: *Io.Writer,
    ) !void {
        const self: *NativeHttpsDownloader = @ptrCast(@alignCast(context_ptr.?));
        if (max_size == 0) return error.ArtifactTooLarge;
        try validateHttpsUrl(url);
        var current_url = try allocator.dupe(u8, url);
        defer allocator.free(current_url);
        var redirects: u8 = 0;
        var retry_count: u8 = 0;

        while (true) {
            const response = self.fetch(
                allocator,
                io,
                current_url,
                max_size,
                output,
            ) catch |err| {
                if (!isRetryableNativeHttpsError(err)) return err;
                try self.retry(io, &retry_count);
                continue;
            };
            if (response.status == 200) {
                if (response.content_length) |length|
                    if (length > max_size) return error.ArtifactTooLarge;
                return;
            }
            if (isRedirectStatus(response.status)) {
                const location = response.redirect_location orelse return error.InvalidRedirect;
                defer if (response.redirect_location_owned) allocator.free(location);
                if (redirects >= @min(self.max_redirects, native_https_max_redirects))
                    return error.RedirectLimitExceeded;
                const next_url = try resolveHttpsRedirectAlloc(
                    allocator,
                    current_url,
                    location,
                );
                allocator.free(current_url);
                current_url = next_url;
                redirects += 1;
                continue;
            }
            if (isRetryableNativeHttpsStatus(response.status)) {
                try self.retry(io, &retry_count);
                continue;
            }
            return error.HttpsUnexpectedStatus;
        }
    }

    fn fetch(
        self: *NativeHttpsDownloader,
        allocator: Allocator,
        io: Io,
        url: []const u8,
        max_size: u64,
        output: *Io.Writer,
    ) !NativeHttpsResponse {
        if (self.transport) |transport|
            return transport.get(allocator, io, url, max_size, output);
        if (self.client) |*client| {
            self.bindProxy();
            return fetchNativeHttps(client, url, max_size, output);
        }
        return error.HttpsTransportUnavailable;
    }

    /// Points the client at this downloader's own proxy storage.
    ///
    /// Done here, where the downloader is behind a pointer and therefore at
    /// its final address, because `initProxied` hands back a value: an
    /// interior pointer taken there would name a copy the caller no longer
    /// keeps. Both schemes are set, because a redirect may cross from one to
    /// the other and the far side is unreachable either way without the proxy.
    fn bindProxy(self: *NativeHttpsDownloader) void {
        const proxy = if (self.proxy) |*proxy| proxy else return;
        if (self.client) |*client| {
            client.http_proxy = proxy;
            client.https_proxy = proxy;
        }
    }

    fn retry(self: *const NativeHttpsDownloader, io: Io, retry_count: *u8) !void {
        if (retry_count.* >= @min(self.retries, native_https_max_retries))
            return error.HttpsRetryExhausted;
        const backoff = @as(u64, 1) << @intCast(@min(retry_count.*, @as(u8, 63)));
        const seconds = @min(
            backoff,
            @min(self.max_backoff_seconds, native_https_max_backoff_seconds),
        );
        if (self.sleep) |sleep| {
            try sleep.call(sleep.context, io, seconds);
        } else {
            try io.sleep(Io.Duration.fromSeconds(@intCast(seconds)), .real);
        }
        retry_count.* += 1;
    }
};

const native_https_max_retries: u8 = 3;
const native_https_max_redirects: u8 = 5;
const native_https_max_backoff_seconds: u64 = 4;
const native_https_response_head_limit = 16 * 1024;
// ghr/src/http.zig (MIT, Cameron Taggart) documents that signed CDN redirect
// URLs exceed Zig's default request buffer. This larger bounded allowance also
// covers miz's maximum accepted redirect URL plus its request headers.
const native_https_write_buffer_size = 16 * 1024;
const native_https_response_buffer_size = 64 * 1024;
const native_https_max_location_size = 8 * 1024;

fn fetchNativeHttps(
    client: *std.http.Client,
    url: []const u8,
    max_size: u64,
    output: *Io.Writer,
) !NativeHttpsResponse {
    const uri = std.Uri.parse(url) catch return error.InvalidHttpsUrl;
    try validateHttpsUri(uri);
    var request = try client.request(.GET, uri, .{
        .redirect_behavior = .unhandled,
        .keep_alive = false,
        .headers = .{ .accept_encoding = .{ .override = "identity" } },
    });
    defer request.deinit();
    try request.sendBodiless();
    var response = try request.receiveHead(&.{});
    if (response.head.content_encoding != .identity)
        return error.InvalidResponseContentEncoding;
    const status = @intFromEnum(response.head.status);
    if (status != 200) {
        const location: ?[]u8 = if (isRedirectStatus(status)) blk: {
            const raw_location = response.head.location orelse return error.InvalidRedirect;
            break :blk try client.allocator.dupe(u8, raw_location);
        } else null;
        return .{
            .status = status,
            .redirect_location = location,
            .redirect_location_owned = location != null,
            .content_length = response.head.content_length,
        };
    }
    if (response.head.content_length) |length|
        if (length > max_size) return error.ArtifactTooLarge;

    var response_buffer: [native_https_response_buffer_size]u8 = undefined;
    const reader = response.reader(&response_buffer);
    var transfer_buffer: [native_https_response_buffer_size]u8 = undefined;
    while (true) {
        const count = try reader.readSliceShort(&transfer_buffer);
        if (count == 0) break;
        try output.writeAll(transfer_buffer[0..count]);
    }
    return .{
        .status = status,
        .content_length = response.head.content_length,
    };
}

fn isRedirectStatus(status: u16) bool {
    return status >= 300 and status < 400;
}

fn isRetryableNativeHttpsStatus(status: u16) bool {
    return switch (status) {
        408, 429, 500, 502, 503, 504 => true,
        else => false,
    };
}

/// Only errors before a response body is received are retried. Retrying a
/// partial stream would concatenate it with a later attempt in the stage.
fn isRetryableNativeHttpsError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.BrokenPipe,
        error.HttpConnectionClosing,
        error.Timeout,
        => true,
        else => false,
    };
}

fn validateHttpsUrl(value: []const u8) !void {
    const uri = std.Uri.parse(value) catch return error.InvalidHttpsUrl;
    try validateHttpsUri(uri);
}

/// Parses a proxy URL into the form `std.http.Client` wants.
///
/// `value` is borrowed, not copied: the returned host points into it, so it
/// must outlive the client. Command-line arguments and environment values both
/// do.
///
/// Credentials are refused rather than forwarded. A proxy that needs them is a
/// proxy whose secret would have to travel in an argument or an environment
/// variable to reach here, and neither is a place for one; debz refuses them
/// on the same grounds, so a build cannot end up with miz accepting a
/// credential-bearing proxy that debz would then reject.
pub fn parseProxy(value: []const u8) !std.http.Client.Proxy {
    const uri = std.Uri.parse(value) catch return error.InvalidProxyUrl;
    const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.InvalidProxyUrl;
    if (uri.user != null or uri.password != null) return error.CredentialBearingProxy;
    const host = uri.host orelse return error.InvalidProxyUrl;
    // A proxy is named, not fetched from, so the host is taken as written
    // rather than percent-decoded into a fresh allocation.
    const name = switch (host) {
        .raw => |raw| raw,
        .percent_encoded => |encoded| encoded,
    };
    std.Io.net.HostName.validate(name) catch return error.InvalidProxyUrl;
    return .{
        .protocol = protocol,
        .host = .{ .bytes = name },
        .authorization = null,
        .port = uri.port orelse switch (protocol) {
            .plain => 80,
            .tls => 443,
        },
        // Anything less would send the artifact URL, and a plaintext body,
        // to the proxy instead of tunnelling TLS through to the origin.
        .supports_connect = true,
    };
}

test "a proxy URL is parsed, and one carrying a credential is refused" {
    const plain = try parseProxy("http://127.0.0.1:18080");
    try std.testing.expectEqual(std.http.Client.Protocol.plain, plain.protocol);
    try std.testing.expectEqual(@as(u16, 18080), plain.port);
    try std.testing.expectEqualStrings("127.0.0.1", plain.host.bytes);
    try std.testing.expect(plain.supports_connect);
    try std.testing.expect(plain.authorization == null);

    // Default ports come from the scheme, so a proxy may be named without one.
    try std.testing.expectEqual(@as(u16, 80), (try parseProxy("http://proxy.example")).port);
    try std.testing.expectEqual(@as(u16, 443), (try parseProxy("https://proxy.example")).port);

    // Forwarding a credential would mean carrying it in an argument or an
    // environment variable to get here. debz refuses these too.
    try std.testing.expectError(
        error.CredentialBearingProxy,
        parseProxy("http://user:secret@proxy.example:8080"),
    );
    try std.testing.expectError(error.InvalidProxyUrl, parseProxy("ftp://proxy.example"));
    try std.testing.expectError(error.InvalidProxyUrl, parseProxy("not a url"));
    try std.testing.expectError(error.InvalidProxyUrl, parseProxy("http://"));
}

test "a proxied downloader points its client at the proxy it still owns" {
    // `initProxied` returns by value, so the downloader a caller keeps is not
    // the one the constructor built. The client must name the surviving copy.
    var moved = try NativeHttpsDownloader.initProxied(
        std.testing.allocator,
        undefined,
        "http://127.0.0.1:18080",
    );
    try std.testing.expect(moved.client.?.http_proxy == null);
    moved.bindProxy();
    try std.testing.expectEqual(&moved.proxy.?, moved.client.?.http_proxy.?);
    try std.testing.expectEqual(&moved.proxy.?, moved.client.?.https_proxy.?);

    // An unproxied downloader is left alone, so nothing can reach the network
    // through a proxy that was never asked for.
    var direct = NativeHttpsDownloader.init(std.testing.allocator, undefined);
    direct.bindProxy();
    try std.testing.expect(direct.client.?.http_proxy == null);
    try std.testing.expect(direct.client.?.https_proxy == null);
}

fn validateHttpsUri(uri: std.Uri) !void {
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https") or
        uri.host == null or
        uri.user != null or
        uri.password != null or
        uri.fragment != null)
    {
        return error.InvalidHttpsUrl;
    }
}

fn resolveHttpsRedirectAlloc(
    allocator: Allocator,
    base_text: []const u8,
    location: []const u8,
) ![]u8 {
    if (location.len == 0 or location.len > native_https_max_location_size or
        std.mem.indexOfAny(u8, location, "\r\n") != null)
    {
        return error.InvalidRedirect;
    }
    const base = std.Uri.parse(base_text) catch return error.InvalidRedirect;
    validateHttpsUri(base) catch return error.InvalidRedirect;
    const required = std.math.add(usize, base_text.len, location.len) catch
        return error.InvalidRedirect;
    const storage = try allocator.alloc(u8, std.math.add(usize, required, 1) catch
        return error.InvalidRedirect);
    defer allocator.free(storage);
    @memcpy(storage[0..location.len], location);
    var auxiliary = storage;
    const resolved = base.resolveInPlace(location.len, &auxiliary) catch
        return error.InvalidRedirect;
    validateHttpsUri(resolved) catch return error.HttpsDowngrade;
    var text = std.Io.Writer.Allocating.init(allocator);
    defer text.deinit();
    resolved.format(&text.writer) catch return error.InvalidRedirect;
    const result = try text.toOwnedSlice();
    errdefer allocator.free(result);
    if (result.len == 0 or result.len > native_https_max_location_size)
        return error.InvalidRedirect;
    validateHttpsUrl(result) catch return error.HttpsDowngrade;
    return result;
}

pub const AcquireOptions = struct {
    url: []const u8,
    destination_path: []const u8,
    expected_sha256: Digest,
    max_size: u64,
};

pub const DecompressXzOptions = struct {
    input_path: []const u8,
    expected_input_sha256: Digest,
    output_path: []const u8,
    max_output_size: u64,
    max_memory_size: u64,
};

pub const Qcow2SourceFormat = enum {
    raw,
    qcow2,

    fn qemuName(self: Qcow2SourceFormat) []const u8 {
        return switch (self) {
            .raw => "raw",
            .qcow2 => "qcow2",
        };
    }
};

pub const Qcow2Compression = enum {
    none,
    deflate,
    zstd,

    fn qemuName(self: Qcow2Compression) ?[]const u8 {
        return switch (self) {
            .none => null,
            .deflate => "zlib",
            .zstd => "zstd",
        };
    }

    fn headerValue(self: Qcow2Compression) u8 {
        return switch (self) {
            .none, .deflate => 0,
            .zstd => 1,
        };
    }
};

pub const FinalizeQcow2Options = struct {
    input_path: []const u8,
    expected_input_sha256: Digest,
    max_input_size: u64,
    source_format: Qcow2SourceFormat,
    expected_virtual_size: ?u64 = null,
    max_virtual_size: u64,
    output_path: []const u8,
    max_output_size: u64,
    qemu_img_path: []const u8 = "",
    compression: Qcow2Compression = .zstd,
    cluster_size: u32 = 64 * 1024,
    convert_environ_map: ?*const std.process.Environ.Map = null,
};

pub const FinalizedQcow2 = struct {
    artifact: Metadata,
    virtual_size: u64,
    compression: Qcow2Compression,
    cluster_size: u32,
};

pub const DeriveFixedVhdOptions = struct {
    input_path: []const u8,
    expected_input_sha256: Digest,
    max_input_size: u64,
    expected_virtual_size: ?u64 = null,
    max_virtual_size: u64,
    output_path: []const u8,
    max_output_size: u64,
    max_partition_array_bytes: u64 = 1024 * 1024,
    unique_id: ?[16]u8 = null,
    timestamp_unix: ?i64 = null,
};

pub const DerivedFixedVhd = struct {
    artifact: Metadata,
    source_virtual_size: u64,
    virtual_size: u64,
    partition_count: usize,
    relocation: gpt.RelocationResult,
};

pub fn sha256Bytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub fn formatSha256(digest: Digest) [Sha256.digest_length * 2]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn parseSha256(text: []const u8) error{InvalidSha256}!Digest {
    const hex = if (std.mem.startsWith(u8, text, "sha256:"))
        text["sha256:".len..]
    else
        text;
    if (hex.len != Sha256.digest_length * 2) return error.InvalidSha256;
    var digest: Digest = undefined;
    _ = std.fmt.hexToBytes(&digest, hex) catch return error.InvalidSha256;
    return digest;
}

pub fn hashFile(io: Io, path: []const u8) !Metadata {
    const file = try Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    return hashOpenFile(io, file, path);
}

pub fn acquireVerified(
    allocator: Allocator,
    io: Io,
    options: AcquireOptions,
    downloader: Downloader,
) !Acquisition {
    if (options.max_size == 0) return error.ArtifactTooLarge;
    var output = try OutputLocation.open(io, options.destination_path);
    defer output.close(io);

    if (try matchingArtifact(
        io,
        output.dir,
        output.basename,
        options.destination_path,
        options.expected_sha256,
        options.max_size,
    )) |artifact| {
        return .{ .artifact = artifact, .reused_cache = true };
    }

    var stage = try output.dir.createFileAtomic(io, output.basename, .{
        .replace = true,
    });
    defer stage.deinit(io);

    var output_buffer: [64 * 1024]u8 = undefined;
    var output_writer = stage.file.writer(io, &output_buffer);
    var hashing_writer = HashingWriter.init(
        &output_writer.interface,
        options.max_size,
    );
    downloader.download(
        allocator,
        io,
        options.url,
        options.max_size,
        &hashing_writer.writer,
    ) catch |err| {
        if (hashing_writer.limit_exceeded) return error.ArtifactTooLarge;
        return err;
    };
    try hashing_writer.writer.flush();
    try output_writer.interface.flush();
    try validateStage(io, stage.file);

    const downloaded = try hashing_writer.finish(options.destination_path);
    if (!std.mem.eql(u8, &downloaded.sha256, &options.expected_sha256)) {
        return error.ChecksumMismatch;
    }

    try stage.replace(io);
    return .{
        .artifact = downloaded,
        .reused_cache = false,
    };
}

/// Download a separately authenticated input through a pipeline-owned atomic
/// stage. Callers that use this instead of `acquireVerified` must perform
/// their own authentication before trusting the returned metadata.
pub fn downloadBoundedAtomic(
    allocator: Allocator,
    io: Io,
    url: []const u8,
    destination_path: []const u8,
    max_size: u64,
    downloader: Downloader,
) !Metadata {
    if (max_size == 0) return error.ArtifactTooLarge;
    var output = try OutputLocation.open(io, destination_path);
    defer output.close(io);
    var stage = try output.dir.createFileAtomic(io, output.basename, .{
        .replace = true,
    });
    defer stage.deinit(io);

    var output_buffer: [64 * 1024]u8 = undefined;
    var output_writer = stage.file.writer(io, &output_buffer);
    var hashing_writer = HashingWriter.init(
        &output_writer.interface,
        max_size,
    );
    downloader.download(
        allocator,
        io,
        url,
        max_size,
        &hashing_writer.writer,
    ) catch |err| {
        if (hashing_writer.limit_exceeded) return error.ArtifactTooLarge;
        return err;
    };
    try hashing_writer.writer.flush();
    try output_writer.interface.flush();
    try validateStage(io, stage.file);
    const downloaded = try hashing_writer.finish(destination_path);
    try stage.replace(io);
    return downloaded;
}

/// Decompress one digest-pinned XZ stream with the native Zig decoder.
///
/// Source images are a single XZ stream.  Concatenated streams and trailing
/// bytes are rejected rather than silently choosing an interpretation.  The
/// compressed input and decoder allocations are bounded by `max_memory_size`;
/// output is streamed into an atomic stage through a size-limited writer.
pub fn decompressXz(
    allocator: Allocator,
    io: Io,
    options: DecompressXzOptions,
) !Metadata {
    if (options.max_output_size == 0) return error.OutputTooLarge;
    if (options.max_memory_size < 64 * 1024) return error.MemoryLimitTooSmall;

    const input_file = try Dir.cwd().openFile(io, options.input_path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer input_file.close(io);
    const input_stat = try input_file.stat(io);
    if (input_stat.kind != .file) return error.NotRegularFile;
    const input = try hashOpenFileLength(
        io,
        input_file,
        options.input_path,
        input_stat.size,
    );
    if (!sameFileSnapshot(input_stat, try input_file.stat(io))) {
        return error.InputChanged;
    }
    if (!std.mem.eql(u8, &input.sha256, &options.expected_input_sha256)) {
        return error.InputChecksumMismatch;
    }
    if (input_stat.size > options.max_memory_size or
        input_stat.size > std.math.maxInt(usize))
    {
        return error.MemoryLimitTooSmall;
    }

    var output = try OutputLocation.open(io, options.output_path);
    defer output.close(io);
    if (try aliasesExistingOutput(io, output, input_file)) {
        return error.InputOutputAliased;
    }

    var stage = try output.dir.createFileAtomic(io, output.basename, .{
        .replace = true,
    });
    defer stage.deinit(io);

    const compressed = try allocator.alloc(u8, @intCast(input_stat.size));
    defer allocator.free(compressed);
    if (try input_file.readPositionalAll(io, compressed, 0) != compressed.len) {
        return error.InputChanged;
    }
    const decoder_limit: usize = @intCast(options.max_memory_size - input_stat.size);
    const declared_dictionary = xzFirstLzma2Dictionary(compressed) catch
        return error.XzDecompressionFailed;
    if (declared_dictionary > decoder_limit) return error.MemoryLimitTooSmall;
    var decoder_allocator = CappedAllocator.init(allocator, decoder_limit);
    var input_reader = Io.Reader.fixed(compressed);
    var decompressor = std.compress.xz.Decompress.init(
        &input_reader,
        decoder_allocator.allocator(),
        &.{},
    ) catch return error.XzDecompressionFailed;
    defer decompressor.deinit();
    var output_buffer: [64 * 1024]u8 = undefined;
    var output_writer = stage.file.writer(io, &output_buffer);
    var hashing_writer = HashingWriter.init(&output_writer.interface, options.max_output_size);
    _ = decompressor.reader.streamRemaining(&hashing_writer.writer) catch {
        return if (hashing_writer.limit_exceeded) error.OutputTooLarge else error.XzDecompressionFailed;
    };
    if (hashing_writer.limit_exceeded) return error.OutputTooLarge;
    if (input_reader.seek != input_reader.end) return error.XzDecompressionFailed;
    try hashing_writer.writer.flush();
    try output_writer.interface.flush();
    const readable_stage = try openProcFdReadOnly(io, stage.file);
    defer readable_stage.close(io);
    try validateXzIntegrity(io, compressed, readable_stage, hashing_writer.count);

    if (!sameFileSnapshot(input_stat, try input_file.stat(io))) {
        return error.InputChanged;
    }
    try validateStage(io, stage.file);
    const decompressed = try hashing_writer.finish(options.output_path);
    try stage.replace(io);
    return decompressed;
}

/// Convert a standalone raw or qcow2 source into a standalone qcow2 output.
/// zstd output is emitted natively by the in-tree compressed qcow2 writer and
/// never invokes qemu-img; other compression types fall back to qemu-img
/// through inherited descriptors (the shared paths are never reopened by the
/// child). Publication occurs only after native miz validation succeeds (plus
/// an independent qemu-img check for the non-native fallback path).
pub fn finalizeQcow2(
    allocator: Allocator,
    io: Io,
    options: FinalizeQcow2Options,
) !FinalizedQcow2 {
    if (builtin.os.tag != .linux) return error.UnsupportedHost;
    if (options.compression != .zstd and options.qemu_img_path.len == 0) {
        return error.InvalidQemuImgPath;
    }
    if (options.max_input_size == 0) return error.InvalidInputSizeLimit;
    if (options.max_virtual_size == 0) return error.InvalidVirtualSizeLimit;
    if (options.max_output_size == 0) return error.InvalidOutputSizeLimit;
    if (options.cluster_size < 512 or
        options.cluster_size > 2 * 1024 * 1024 or
        !std.math.isPowerOfTwo(options.cluster_size))
    {
        return error.InvalidClusterSize;
    }

    const source_file = try Dir.cwd().openFile(io, options.input_path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    var source_file_open = true;
    defer if (source_file_open) source_file.close(io);
    const source_stat = try source_file.stat(io);
    if (source_stat.kind != .file) return error.NotRegularFile;
    if (source_stat.size > options.max_input_size) return error.InputTooLarge;
    const source = try hashOpenFileLength(
        io,
        source_file,
        options.input_path,
        source_stat.size,
    );
    if (!sameFileSnapshot(source_stat, try source_file.stat(io))) {
        return error.InputChanged;
    }
    if (!std.mem.eql(u8, &source.sha256, &options.expected_input_sha256)) {
        return error.InputChecksumMismatch;
    }

    var source_image: ?image.Image = null;
    defer if (source_image) |*opened| opened.close(io);
    const virtual_size = switch (options.source_format) {
        .raw => source_stat.size,
        .qcow2 => size: {
            source_image = image.Image.openStandaloneQcow2File(
                io,
                source_file,
            ) catch |err| switch (err) {
                error.BackingFileNotSupported,
                error.ExternalDataFileNotSupported,
                => return error.SourceNotStandalone,
                else => return err,
            };
            source_file_open = false;
            const opened = &source_image.?;
            break :size opened.virtual_size;
        },
    };
    if (virtual_size == 0 or virtual_size > options.max_virtual_size) {
        return error.VirtualSizeTooLarge;
    }
    if (options.expected_virtual_size) |expected| {
        if (virtual_size != expected) return error.UnexpectedVirtualSize;
    }
    if (source_image) |opened| {
        const source_check = try opened.check(io);
        if (!source_check.ok) return error.SourceImageInvalid;
    }
    const source_handle = if (source_image) |opened|
        opened.file
    else
        source_file;

    var output = try OutputLocation.open(io, options.output_path);
    defer output.close(io);
    if (try aliasesExistingOutput(io, output, source_handle)) {
        return error.InputOutputAliased;
    }
    var stage = try output.dir.createFileAtomic(io, output.basename, .{
        .replace = true,
    });
    defer stage.deinit(io);

    if (options.compression == .zstd) {
        const cluster_bits: u32 = std.math.log2_int(u32, options.cluster_size);
        switch (options.source_format) {
            .raw => {
                var source_ctx = qcow2.RawSourceContext{
                    .file = source_handle,
                    .readable_len = source_stat.size,
                };
                _ = try qcow2.writeStandaloneCompressed(
                    allocator,
                    io,
                    stage.file,
                    virtual_size,
                    source_ctx.reader(),
                    .{ .cluster_bits = cluster_bits },
                );
            },
            .qcow2 => {
                var source_ctx = qcow2.Qcow2SourceContext{
                    .file = source_handle,
                    .info = &source_image.?.qcow2.?,
                };
                _ = try qcow2.writeStandaloneCompressed(
                    allocator,
                    io,
                    stage.file,
                    virtual_size,
                    source_ctx.reader(),
                    .{ .cluster_bits = cluster_bits },
                );
            },
        }
        try validateStageBounded(io, stage.file, options.max_output_size);
    } else {
        const create_options = if (options.compression.qemuName()) |compression|
            try std.fmt.allocPrint(
                allocator,
                "compression_type={s},cluster_size={d}",
                .{ compression, options.cluster_size },
            )
        else
            try std.fmt.allocPrint(
                allocator,
                "cluster_size={d}",
                .{options.cluster_size},
            );
        defer allocator.free(create_options);
        const virtual_size_text = try std.fmt.allocPrint(
            allocator,
            "{d}",
            .{virtual_size},
        );
        defer allocator.free(virtual_size_text);

        try runQemuImg(io, .{
            .argv = &.{
                options.qemu_img_path,
                "create",
                "-q",
                "-f",
                "qcow2",
                "-o",
                create_options,
                "/proc/self/fd/1",
                virtual_size_text,
            },
            .stdin = .ignore,
            .stdout = .{ .file = stage.file },
            .failure = error.QemuImgCreateFailed,
        });
        try validateStageBounded(io, stage.file, options.max_output_size);

        var convert_argv: std.array_list.Managed([]const u8) = .init(allocator);
        defer convert_argv.deinit();
        try convert_argv.appendSlice(&.{
            options.qemu_img_path,
            "convert",
            "--target-image-opts",
            "-n",
            "-q",
        });
        if (options.compression != .none) try convert_argv.append("-c");
        try convert_argv.appendSlice(&.{
            "-f",
            options.source_format.qemuName(),
            "/proc/self/fd/0",
            "driver=qcow2,file.driver=file,file.filename=/proc/self/fd/1",
        });
        try runQemuImg(io, .{
            .argv = convert_argv.items,
            .stdin = .{ .file = source_handle },
            .stdout = .{ .file = stage.file },
            .environ_map = options.convert_environ_map,
            .failure = error.QemuImgConvertFailed,
        });
        try validateStageBounded(io, stage.file, options.max_output_size);
    }

    if (!sameFileSnapshot(source_stat, try source_handle.stat(io))) {
        return error.InputChanged;
    }
    const source_after = try hashOpenFileLength(
        io,
        source_handle,
        options.input_path,
        source_stat.size,
    );
    if (!sameFileSnapshot(source_stat, try source_handle.stat(io))) {
        return error.InputChanged;
    }
    if (!std.mem.eql(u8, &source_after.sha256, &options.expected_input_sha256)) {
        return error.InputChanged;
    }

    if (options.compression != .zstd) {
        try runQemuImg(io, .{
            .argv = &.{
                options.qemu_img_path,
                "check",
                "-q",
                "-f",
                "qcow2",
                "/proc/self/fd/0",
            },
            .stdin = .{ .file = stage.file },
            .stdout = .inherit,
            .failure = error.QemuImgCheckFailed,
        });
        try validateStageBounded(io, stage.file, options.max_output_size);
    }

    const stage_reader = try openProcFdReadOnly(io, stage.file);
    var finalized = image.Image.openFile(io, stage_reader) catch |err| {
        stage_reader.close(io);
        return err;
    };
    var finalized_open = true;
    defer if (finalized_open) finalized.close(io);
    if (finalized.format != .qcow2) return error.FinalImageNotQcow2;
    if (finalized.virtual_size != virtual_size) {
        return error.VirtualSizeMismatch;
    }
    const finalized_info = finalized.qcow2.?;
    if (finalized_info.backing_file_len != 0 or
        finalized_info.data_file_len != 0)
    {
        return error.FinalImageNotStandalone;
    }
    if (finalized_info.cluster_size != options.cluster_size) {
        return error.ClusterSizeMismatch;
    }
    if (finalized_info.compression_type != options.compression.headerValue()) {
        return error.CompressionTypeMismatch;
    }
    const final_check = try finalized.check(io);
    if (!final_check.ok) return error.FinalImageInvalid;
    const artifact = try hashOpenFile(io, finalized.file, options.output_path);
    finalized.close(io);
    finalized_open = false;

    try stage.replace(io);
    return .{
        .artifact = artifact,
        .virtual_size = virtual_size,
        .compression = options.compression,
        .cluster_size = options.cluster_size,
    };
}

/// Transactionally converts a standalone GPT qcow2 into an Azure-ready fixed
/// VHD. The data region is rounded up to 1 MiB, while the verified backup GPT
/// is relocated without changing partition-array bytes or partition extents.
/// The source is descriptor-pinned and revalidated before atomic publication.
pub fn deriveFixedVhd(
    allocator: Allocator,
    io: Io,
    options: DeriveFixedVhdOptions,
) !DerivedFixedVhd {
    if (builtin.os.tag != .linux) return error.UnsupportedHost;
    if (options.max_input_size == 0) return error.InvalidInputSizeLimit;
    if (options.max_virtual_size == 0) return error.InvalidVirtualSizeLimit;
    if (options.max_output_size == 0) return error.InvalidOutputSizeLimit;
    if (options.max_partition_array_bytes == 0) {
        return error.InvalidPartitionArraySizeLimit;
    }

    const source_file = try Dir.cwd().openFile(io, options.input_path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    var source_file_open = true;
    defer if (source_file_open) source_file.close(io);
    const source_stat = try source_file.stat(io);
    if (source_stat.kind != .file) return error.NotRegularFile;
    if (source_stat.size > options.max_input_size) return error.InputTooLarge;
    const source = try hashOpenFileLength(
        io,
        source_file,
        options.input_path,
        source_stat.size,
    );
    if (!sameFileSnapshot(source_stat, try source_file.stat(io))) {
        return error.InputChanged;
    }
    if (!std.mem.eql(u8, &source.sha256, &options.expected_input_sha256)) {
        return error.InputChecksumMismatch;
    }

    var source_image = image.Image.openStandaloneQcow2File(
        io,
        source_file,
    ) catch |err| switch (err) {
        error.BackingFileNotSupported,
        error.ExternalDataFileNotSupported,
        => return error.SourceNotStandalone,
        error.BadFileSignature => return error.SourceFormatMismatch,
        else => return err,
    };
    source_file_open = false;
    defer source_image.close(io);
    const source_virtual_size = source_image.virtual_size;
    if (source_virtual_size == 0 or
        source_virtual_size > options.max_virtual_size)
    {
        return error.VirtualSizeTooLarge;
    }
    if (options.expected_virtual_size) |expected| {
        if (source_virtual_size != expected) return error.UnexpectedVirtualSize;
    }
    const source_check = try source_image.check(io);
    if (!source_check.ok) return error.SourceImageInvalid;

    var source_gpt = try gpt.readVerifiedGpt(
        source_image,
        io,
        allocator,
        options.max_partition_array_bytes,
    );
    defer source_gpt.deinit(allocator);

    const rounded = std.math.add(
        u64,
        source_virtual_size,
        (1024 * 1024) - 1,
    ) catch return error.VirtualSizeTooLarge;
    const target_virtual_size = rounded / (1024 * 1024) * (1024 * 1024);
    if (target_virtual_size > options.max_virtual_size) {
        return error.VirtualSizeTooLarge;
    }
    const target_file_size = std.math.add(
        u64,
        target_virtual_size,
        vhd.footer_size,
    ) catch return error.OutputTooLarge;
    if (target_file_size > options.max_output_size) {
        return error.OutputTooLarge;
    }

    var output = try OutputLocation.open(io, options.output_path);
    defer output.close(io);
    if (try aliasesExistingOutput(io, output, source_image.file)) {
        return error.InputOutputAliased;
    }
    var stage = try output.dir.createFileAtomic(io, output.basename, .{
        .replace = true,
    });
    defer stage.deinit(io);
    try validateStageBounded(io, stage.file, options.max_output_size);

    const stage_image_file = try openProcFdReadWrite(io, stage.file);
    var finalized = try image.Image.createFile(
        io,
        stage_image_file,
        .vhd,
        target_virtual_size,
        .{
            .vhd_subformat = .fixed,
            .unique_id = options.unique_id,
            .timestamp_unix = options.timestamp_unix,
        },
    );
    var finalized_open = true;
    defer if (finalized_open) finalized.close(io);
    try validateStageBounded(io, stage.file, options.max_output_size);

    _ = try image.copyAll(io, source_image, &finalized, allocator);
    const relocation = try gpt.relocateBackup(
        &finalized,
        io,
        allocator,
        source_gpt,
    );

    var final_gpt = try gpt.readVerifiedGpt(
        finalized,
        io,
        allocator,
        options.max_partition_array_bytes,
    );
    defer final_gpt.deinit(allocator);
    if (!std.mem.eql(
        u8,
        source_gpt.partition_array,
        final_gpt.partition_array,
    )) return error.PartitionArrayChanged;
    if (source_gpt.partitions.len != final_gpt.partitions.len) {
        return error.PartitionArrayChanged;
    }
    if (final_gpt.primary_header.backup_lba !=
        target_virtual_size / gpt.sector_size - 1)
    {
        return error.BackupGptNotAtEnd;
    }

    if (finalized.format != .vhd or finalized.dynamic != null) {
        return error.FinalImageNotFixedVhd;
    }
    if (finalized.virtual_size != target_virtual_size) {
        return error.VirtualSizeMismatch;
    }
    const final_check = try finalized.check(io);
    if (!final_check.ok) return error.FinalImageInvalid;
    const final_stat = try finalized.file.stat(io);
    if (final_stat.kind != .file or final_stat.size != target_file_size) {
        return error.FinalImageSizeMismatch;
    }
    try validateStageBounded(io, stage.file, options.max_output_size);

    if (!sameFileSnapshot(source_stat, try source_image.file.stat(io))) {
        return error.InputChanged;
    }
    const source_after = try hashOpenFileLength(
        io,
        source_image.file,
        options.input_path,
        source_stat.size,
    );
    if (!sameFileSnapshot(source_stat, try source_image.file.stat(io)) or
        !std.mem.eql(
            u8,
            &source_after.sha256,
            &options.expected_input_sha256,
        ))
    {
        return error.InputChanged;
    }

    try finalized.file.sync(io);
    const artifact = try hashOpenFile(
        io,
        finalized.file,
        options.output_path,
    );
    finalized.close(io);
    finalized_open = false;
    try validateStageBounded(io, stage.file, options.max_output_size);
    if (artifact.size != target_file_size) {
        return error.FinalImageSizeMismatch;
    }
    try stage.replace(io);
    return .{
        .artifact = artifact,
        .source_virtual_size = source_virtual_size,
        .virtual_size = target_virtual_size,
        .partition_count = source_gpt.partitions.len,
        .relocation = relocation,
    };
}

const QemuImgRunOptions = struct {
    argv: []const []const u8,
    stdin: std.process.SpawnOptions.StdIo,
    stdout: std.process.SpawnOptions.StdIo,
    environ_map: ?*const std.process.Environ.Map = null,
    failure: anyerror,
};

fn runQemuImg(io: Io, options: QemuImgRunOptions) !void {
    var child = try std.process.spawn(io, .{
        .argv = options.argv,
        .stdin = options.stdin,
        .stdout = options.stdout,
        .stderr = .inherit,
        .environ_map = options.environ_map,
    });
    defer child.kill(io);
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return options.failure,
        else => return options.failure,
    }
}

fn openProcFdReadOnly(io: Io, file: File) !File {
    var path_buffer: [64]u8 = undefined;
    const fd_directory = if (builtin.os.tag == .linux) "/proc/self/fd" else "/dev/fd";
    const path = try std.fmt.bufPrint(
        &path_buffer,
        "{s}/{d}",
        .{ fd_directory, file.handle },
    );
    return Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = true,
    });
}

fn openProcFdReadWrite(io: Io, file: File) !File {
    var path_buffer: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &path_buffer,
        "/proc/self/fd/{d}",
        .{file.handle},
    );
    return Dir.cwd().openFile(io, path, .{
        .mode = .read_write,
        .allow_directory = false,
        .follow_symlinks = true,
    });
}

const OutputLocation = struct {
    dir: Dir,
    basename: []const u8,

    fn open(io: Io, path: []const u8) !OutputLocation {
        if (path.len == 0) return error.InvalidOutputPath;
        const basename = std.fs.path.basename(path);
        if (std.mem.eql(u8, basename, ".") or
            std.mem.eql(u8, basename, ".."))
        {
            return error.InvalidOutputPath;
        }
        const parent = std.fs.path.dirname(path) orelse ".";
        return .{
            .dir = try Dir.cwd().openDir(io, parent, .{}),
            .basename = basename,
        };
    }

    fn close(self: OutputLocation, io: Io) void {
        self.dir.close(io);
    }
};

fn hashOpenFile(io: Io, file: File, path: []const u8) !Metadata {
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.NotRegularFile;
    return hashOpenFileLength(io, file, path, stat.size);
}

fn hashOpenFileLength(
    io: Io,
    file: File,
    path: []const u8,
    size: u64,
) !Metadata {
    var hash = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const length: usize = @intCast(@min(size - offset, buffer.len));
        const read = try file.readPositionalAll(io, buffer[0..length], offset);
        if (read != length) return error.ShortRead;
        hash.update(buffer[0..length]);
        offset += length;
    }
    var digest: Digest = undefined;
    hash.final(&digest);
    return .{
        .path = path,
        .sha256 = digest,
        .size = size,
    };
}

fn matchingArtifact(
    io: Io,
    dir: Dir,
    basename: []const u8,
    path: []const u8,
    expected_sha256: Digest,
    max_size: u64,
) !?Metadata {
    const stat = dir.statFile(io, basename, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (stat.kind != .file) return null;
    if (stat.size > max_size) return null;
    const file = dir.openFile(io, basename, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound, error.SymLinkLoop => return null,
        else => return err,
    };
    defer file.close(io);
    const initial_stat = try file.stat(io);
    if (initial_stat.kind != .file or initial_stat.size > max_size) return null;
    const artifact = hashOpenFileLength(
        io,
        file,
        path,
        initial_stat.size,
    ) catch |err| switch (err) {
        error.ShortRead => return null,
        else => return err,
    };
    if (!sameFileSnapshot(initial_stat, try file.stat(io))) return null;
    if (!std.mem.eql(u8, &artifact.sha256, &expected_sha256)) return null;

    const current_file = dir.openFile(io, basename, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound, error.SymLinkLoop => return null,
        else => return err,
    };
    defer current_file.close(io);
    if (!try sameFileIdentity(io, file, current_file)) return null;
    if (!sameFileSnapshot(initial_stat, try current_file.stat(io))) return null;
    return artifact;
}

fn aliasesExistingOutput(
    io: Io,
    output: OutputLocation,
    input_file: File,
) !bool {
    const output_stat = output.dir.statFile(io, output.basename, .{
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    if (output_stat.kind != .file) return false;
    const output_file = output.dir.openFile(io, output.basename, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound, error.SymLinkLoop => return false,
        else => return err,
    };
    defer output_file.close(io);
    const input_stat = try input_file.stat(io);
    const opened_output_stat = try output_file.stat(io);
    if (opened_output_stat.kind != .file or
        opened_output_stat.inode != input_stat.inode)
    {
        return false;
    }
    return sameFileIdentity(io, input_file, output_file);
}

fn validateStage(io: Io, file: File) !void {
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.OutputStageNotRegularFile;
    if (stat.nlink != 1) return error.OutputStageAliased;
}

fn validateStageBounded(io: Io, file: File, max_size: u64) !void {
    try validateStage(io, file);
    if ((try file.stat(io)).size > max_size) return error.OutputTooLarge;
}

fn sameFileSnapshot(expected: File.Stat, actual: File.Stat) bool {
    return actual.kind == .file and
        actual.inode == expected.inode and
        actual.nlink == expected.nlink and
        actual.size == expected.size and
        actual.mtime.nanoseconds == expected.mtime.nanoseconds and
        actual.ctime.nanoseconds == expected.ctime.nanoseconds;
}

pub fn sameFileIdentity(io: Io, a: File, b: File) !bool {
    const a_stat = try a.stat(io);
    const b_stat = try b.stat(io);
    if (a_stat.inode != b_stat.inode) return false;
    return try fileSystemId(a) == try fileSystemId(b);
}

fn fileSystemId(file: File) !u64 {
    return switch (builtin.os.tag) {
        .linux => linuxFileSystemId(file),
        .windows => windowsFileSystemId(file),
        .wasi => error.FileIdentityUnavailable,
        else => posixFileSystemId(file),
    };
}

fn linuxFileSystemId(file: File) !u64 {
    const linux = std.os.linux;
    while (true) {
        var statx = std.mem.zeroes(linux.Statx);
        switch (linux.errno(linux.statx(
            file.handle,
            "",
            linux.AT.EMPTY_PATH,
            .{ .INO = true },
            &statx,
        ))) {
            .SUCCESS => {
                if (!statx.mask.INO) return error.FileIdentityUnavailable;
                return (@as(u64, statx.dev_major) << 32) | statx.dev_minor;
            },
            .INTR => continue,
            else => return error.FileIdentityUnavailable,
        }
    }
}

fn windowsFileSystemId(file: File) !u64 {
    const windows = std.os.windows;
    var io_status: windows.IO_STATUS_BLOCK = undefined;
    var volume_info: windows.FILE.FS_VOLUME_INFORMATION = undefined;
    switch (windows.ntdll.NtQueryVolumeInformationFile(
        file.handle,
        &io_status,
        &volume_info,
        @sizeOf(windows.FILE.FS_VOLUME_INFORMATION),
        .Volume,
    )) {
        .SUCCESS, .BUFFER_OVERFLOW => {},
        else => return error.FileIdentityUnavailable,
    }
    return volume_info.VolumeSerialNumber;
}

fn posixFileSystemId(file: File) !u64 {
    const posix = std.posix;
    if (posix.Stat == void) return error.FileIdentityUnavailable;
    const fstat = if (posix.lfs64_abi)
        posix.system.fstat64
    else
        posix.system.fstat;
    while (true) {
        var stat = std.mem.zeroes(posix.Stat);
        switch (posix.errno(fstat(file.handle, &stat))) {
            .SUCCESS => return @intCast(stat.dev),
            .INTR => continue,
            else => return error.FileIdentityUnavailable,
        }
    }
}

/// The Zig 0.16 XZ decoder validates stream framing but does not compare the
/// per-block check bytes.  Verify the checked output independently, using the
/// XZ index to bind each stored check to its exact decoded byte range.
fn validateXzIntegrity(
    io: Io,
    encoded: []const u8,
    output: File,
    output_size: u64,
) !void {
    if (encoded.len < 24 or
        !std.mem.eql(u8, encoded[0..6], &.{ 0xFD, '7', 'z', 'X', 'Z', 0 }) or
        !std.mem.eql(u8, encoded[encoded.len - 2 ..], "YZ"))
    {
        return error.XzDecompressionFailed;
    }
    const check = encoded[7] & 0x0F;
    const check_size: usize = switch (check) {
        0 => 0,
        1 => 4,
        4 => 8,
        10 => Sha256.digest_length,
        else => return error.XzDecompressionFailed,
    };
    if (!std.mem.eql(u8, encoded[encoded.len - 4 .. encoded.len - 2], encoded[6..8])) {
        return error.XzDecompressionFailed;
    }
    const backward_size = readU32Le(encoded[encoded.len - 8 .. encoded.len - 4]);
    const index_size = std.math.mul(usize, @as(usize, backward_size) + 1, 4) catch
        return error.XzDecompressionFailed;
    if (index_size > encoded.len - 12) return error.XzDecompressionFailed;
    const index_start = encoded.len - 12 - index_size;
    const index_with_checksum = encoded[index_start .. encoded.len - 12];
    if (index_with_checksum.len < 5 or index_with_checksum[0] != 0) {
        return error.XzDecompressionFailed;
    }

    var index_offset: usize = 1;
    const records = try xzLeb128(index_with_checksum, &index_offset);
    if (records > std.math.maxInt(usize)) return error.XzDecompressionFailed;
    var block_offset: usize = 12;
    var output_offset: u64 = 0;
    var block_index: u64 = 0;
    while (block_index < records) : (block_index += 1) {
        const unpadded_size = try xzLeb128(index_with_checksum, &index_offset);
        const unpacked_size = try xzLeb128(index_with_checksum, &index_offset);
        if (unpadded_size == 0 or unpadded_size > std.math.maxInt(usize)) {
            return error.XzDecompressionFailed;
        }
        if (block_offset >= index_start) return error.XzDecompressionFailed;
        const header_size = std.math.add(
            usize,
            @as(usize, encoded[block_offset]),
            1,
        ) catch return error.XzDecompressionFailed;
        const header_bytes = std.math.mul(usize, header_size, 4) catch
            return error.XzDecompressionFailed;
        if (header_bytes > unpadded_size -| check_size) return error.XzDecompressionFailed;
        const content_end = std.math.add(
            usize,
            block_offset,
            @intCast(unpadded_size - check_size),
        ) catch
            return error.XzDecompressionFailed;
        const check_start = std.math.add(
            usize,
            content_end,
            (4 - (content_end % 4)) % 4,
        ) catch return error.XzDecompressionFailed;
        const block_end = std.math.add(usize, check_start, check_size) catch
            return error.XzDecompressionFailed;
        if (block_end > index_start) return error.XzDecompressionFailed;
        if (unpacked_size > output_size -| output_offset) return error.XzDecompressionFailed;
        for (encoded[content_end..check_start]) |byte| {
            if (byte != 0) return error.XzDecompressionFailed;
        }
        const output_end = std.math.add(u64, output_offset, unpacked_size) catch
            return error.XzDecompressionFailed;
        if (output_end > output_size) return error.XzDecompressionFailed;
        try validateXzCheck(
            io,
            output,
            output_offset,
            unpacked_size,
            check,
            encoded[check_start..block_end],
        );
        block_offset = block_end;
        output_offset = output_end;
    }
    while (index_offset < index_with_checksum.len - 4) : (index_offset += 1) {
        if (index_with_checksum[index_offset] != 0) return error.XzDecompressionFailed;
    }
    if (index_offset != index_with_checksum.len - 4 or block_offset != index_start or output_offset != output_size) {
        return error.XzDecompressionFailed;
    }
    const stored_index_crc = readU32Le(index_with_checksum[index_with_checksum.len - 4 ..]);
    if (std.hash.Crc32.hash(index_with_checksum[0 .. index_with_checksum.len - 4]) != stored_index_crc) {
        return error.XzDecompressionFailed;
    }
}

fn xzLeb128(bytes: []const u8, offset: *usize) !u64 {
    var value: u64 = 0;
    var shift: u6 = 0;
    var count: usize = 0;
    while (count < 9) : (count += 1) {
        if (offset.* == bytes.len) return error.XzDecompressionFailed;
        const byte = bytes[offset.*];
        offset.* += 1;
        if (count == 8 and byte > 1) return error.XzDecompressionFailed;
        value |= @as(u64, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) return value;
        shift += 7;
    }
    return error.XzDecompressionFailed;
}

/// Returns the LZMA2 dictionary declared by the first XZ block.  XZ streams
/// use one filter chain throughout in miz's supported single-filter profile;
/// unsupported filter layouts fail before allocating a decoder dictionary.
fn xzFirstLzma2Dictionary(encoded: []const u8) !usize {
    if (encoded.len < 13 or
        !std.mem.eql(u8, encoded[0..6], &.{ 0xFD, '7', 'z', 'X', 'Z', 0 }))
    {
        return error.XzDecompressionFailed;
    }
    if (encoded[12] == 0) return 0;
    const header_len = std.math.mul(usize, @as(usize, encoded[12]) + 1, 4) catch
        return error.XzDecompressionFailed;
    const header_end = std.math.add(usize, 12, header_len) catch
        return error.XzDecompressionFailed;
    if (header_len < 8 or header_end > encoded.len) return error.XzDecompressionFailed;
    const header = encoded[12..header_end];
    const flags = header[1];
    if (flags & 0x3F != 0) return error.XzDecompressionFailed;
    var offset: usize = 2;
    const fields = header[0 .. header.len - 4];
    if (flags & 0x40 != 0) _ = try xzLeb128(fields, &offset);
    if (flags & 0x80 != 0) _ = try xzLeb128(fields, &offset);
    if (try xzLeb128(fields, &offset) != 0x21 or
        try xzLeb128(fields, &offset) != 1 or
        offset >= fields.len)
    {
        return error.XzDecompressionFailed;
    }
    const property = fields[offset];
    offset += 1;
    while (offset < fields.len) : (offset += 1) {
        if (fields[offset] != 0) return error.XzDecompressionFailed;
    }
    if (property > 40) return error.XzDecompressionFailed;
    const dictionary: u64 = if (property == 40)
        std.math.maxInt(u32)
    else
        (@as(u64, 2 | (property & 1)) << @intCast(property / 2 + 11));
    if (dictionary > std.math.maxInt(usize)) return error.MemoryLimitTooSmall;
    return @intCast(dictionary);
}

fn validateXzCheck(
    io: Io,
    output: File,
    offset: u64,
    len: u64,
    check: u8,
    expected: []const u8,
) !void {
    if (check == 0) return;
    var buffer: [64 * 1024]u8 = undefined;
    var current = offset;
    switch (check) {
        1 => {
            var hasher = std.hash.Crc32.init();
            while (current - offset < len) {
                const amount: usize = @intCast(@min(len - (current - offset), buffer.len));
                if (try output.readPositionalAll(io, buffer[0..amount], current) != amount) return error.XzDecompressionFailed;
                hasher.update(buffer[0..amount]);
                current += amount;
            }
            if (hasher.final() != readU32Le(expected[0..4])) return error.XzDecompressionFailed;
        },
        4 => {
            var hasher = std.hash.crc.Crc64Xz.init();
            while (current - offset < len) {
                const amount: usize = @intCast(@min(len - (current - offset), buffer.len));
                if (try output.readPositionalAll(io, buffer[0..amount], current) != amount) return error.XzDecompressionFailed;
                hasher.update(buffer[0..amount]);
                current += amount;
            }
            if (hasher.final() != readU64Le(expected[0..8])) return error.XzDecompressionFailed;
        },
        10 => {
            var hasher = Sha256.init(.{});
            while (current - offset < len) {
                const amount: usize = @intCast(@min(len - (current - offset), buffer.len));
                if (try output.readPositionalAll(io, buffer[0..amount], current) != amount) return error.XzDecompressionFailed;
                hasher.update(buffer[0..amount]);
                current += amount;
            }
            var actual: [Sha256.digest_length]u8 = undefined;
            hasher.final(&actual);
            if (!std.mem.eql(u8, &actual, expected)) return error.XzDecompressionFailed;
        },
        else => return error.XzDecompressionFailed,
    }
}

fn readU32Le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 4);
    return @as(u32, bytes[0]) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

fn readU64Le(bytes: []const u8) u64 {
    std.debug.assert(bytes.len == 8);
    var value: u64 = 0;
    for (bytes, 0..) |byte, index| {
        value |= @as(u64, byte) << @intCast(index * 8);
    }
    return value;
}

const HashingWriter = struct {
    child: *Io.Writer,
    hash: Sha256,
    count: u64,
    overflowed: bool,
    max_size: u64,
    limit_exceeded: bool,
    writer: Io.Writer,

    fn init(child: *Io.Writer, max_size: u64) HashingWriter {
        return .{
            .child = child,
            .hash = Sha256.init(.{}),
            .count = 0,
            .overflowed = false,
            .max_size = max_size,
            .limit_exceeded = false,
            .writer = .{
                .vtable = &.{ .drain = drain },
                .buffer = &.{},
            },
        };
    }

    fn drain(
        writer: *Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) Io.Writer.Error!usize {
        const self: *HashingWriter = @alignCast(@fieldParentPtr("writer", writer));
        const slices = data[0 .. data.len - 1];
        const pattern = data[data.len - 1];
        var written: usize = 0;
        for (slices) |bytes| {
            try self.write(bytes);
            written += bytes.len;
        }
        for (0..splat) |_| {
            try self.write(pattern);
            written += pattern.len;
        }
        writer.end = 0;
        return written;
    }

    fn write(self: *HashingWriter, bytes: []const u8) Io.Writer.Error!void {
        const new_count = std.math.add(u64, self.count, bytes.len) catch {
            self.overflowed = true;
            return error.WriteFailed;
        };
        if (new_count > self.max_size) {
            self.limit_exceeded = true;
            return error.WriteFailed;
        }
        self.child.writeAll(bytes) catch return error.WriteFailed;
        self.hash.update(bytes);
        self.count = new_count;
    }

    fn finish(self: *HashingWriter, path: []const u8) !Metadata {
        if (self.overflowed) return error.ArtifactTooLarge;
        var digest: Digest = undefined;
        self.hash.final(&digest);
        return .{
            .path = path,
            .sha256 = digest,
            .size = self.count,
        };
    }
};

/// Caps decoder-owned allocations without constraining the file-backed output.
/// `std.compress.xz` grows its LZMA2 buffers through the allocator it receives,
/// so this prevents a malformed stream from turning a declared resource limit
/// into an unbounded heap allocation.
const CappedAllocator = struct {
    child: Allocator,
    limit: usize,
    used: usize = 0,

    fn init(child: Allocator, limit: usize) CappedAllocator {
        return .{ .child = child, .limit = limit };
    }

    fn allocator(self: *CappedAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        if (len > self.limit -| self.used) return null;
        const memory = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.used += len;
        return memory;
    }

    fn resize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and new_len - memory.len > self.limit -| self.used) {
            return false;
        }
        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        if (new_len >= memory.len) {
            self.used += new_len - memory.len;
        } else {
            self.used -= memory.len - new_len;
        }
        return true;
    }

    fn remap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and new_len - memory.len > self.limit -| self.used) {
            return null;
        }
        const remapped = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse
            return null;
        if (new_len >= memory.len) {
            self.used += new_len - memory.len;
        } else {
            self.used -= memory.len - new_len;
        }
        return remapped;
    }

    fn free(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *CappedAllocator = @ptrCast(@alignCast(ctx));
        std.debug.assert(memory.len <= self.used);
        self.used -= memory.len;
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

const test_xz = [_]u8{
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04,
    0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21, 0x01,
    0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3,
    0x01, 0x00, 0x19, 0x46, 0x72, 0x65, 0x65, 0x42,
    0x53, 0x44, 0x20, 0x61, 0x72, 0x74, 0x69, 0x66,
    0x61, 0x63, 0x74, 0x20, 0x70, 0x69, 0x70, 0x65,
    0x6c, 0x69, 0x6e, 0x65, 0x0a, 0x00, 0x00, 0x00,
    0x2d, 0x64, 0x31, 0x7a, 0xcc, 0xb4, 0xa3, 0x0b,
    0x00, 0x01, 0x32, 0x1a, 0x20, 0x18, 0x94, 0x30,
    0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x59, 0x5a,
};

test "parse and format SHA-256" {
    const expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    const digest = try parseSha256("sha256:" ++ expected);
    try std.testing.expectEqualStrings(expected, &formatSha256(digest));
    try std.testing.expectError(error.InvalidSha256, parseSha256("short"));
    try std.testing.expectError(
        error.InvalidSha256,
        parseSha256("z" ** 64),
    );
}

test "verified acquisition publishes once and then reuses cache" {
    const io = std.testing.io;
    const output_path = "test-artifact-acquire.bin";
    defer Dir.cwd().deleteFile(io, output_path) catch {};

    var context = TestDownloader{ .payload = "verified artifact\n" };
    const expected = sha256Bytes(context.payload);
    const downloader = Downloader{
        .context = &context,
        .downloadFn = TestDownloader.download,
    };
    const options = AcquireOptions{
        .url = "https://example.invalid/artifact",
        .destination_path = output_path,
        .expected_sha256 = expected,
        .max_size = 1024,
    };
    const acquired = try acquireVerified(
        std.testing.allocator,
        io,
        options,
        downloader,
    );
    try std.testing.expect(!acquired.reused_cache);
    try std.testing.expectEqual(@as(usize, 1), context.calls);
    try std.testing.expectEqual(@as(u64, context.payload.len), acquired.artifact.size);

    const cached = try acquireVerified(
        std.testing.allocator,
        io,
        options,
        downloader,
    );
    try std.testing.expect(cached.reused_cache);
    try std.testing.expectEqual(@as(usize, 1), context.calls);
}

test "verified acquisition ignores a corrupt legacy partial and downloads fresh" {
    const io = std.testing.io;
    const output_path = "test-artifact-fresh.bin";
    const legacy_partial = output_path ++ ".part";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, legacy_partial) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = legacy_partial,
        .data = "corrupt complete partial\n",
    });

    var context = TestDownloader{ .payload = "fresh artifact\n" };
    const result = try acquireVerified(
        std.testing.allocator,
        io,
        .{
            .url = "https://example.invalid/artifact",
            .destination_path = output_path,
            .expected_sha256 = sha256Bytes(context.payload),
            .max_size = 1024,
        },
        .{
            .context = &context,
            .downloadFn = TestDownloader.download,
        },
    );
    try std.testing.expect(!result.reused_cache);
    try std.testing.expectEqual(@as(usize, 1), context.calls);
    const legacy = try Dir.cwd().readFileAlloc(
        io,
        legacy_partial,
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(legacy);
    try std.testing.expectEqualStrings("corrupt complete partial\n", legacy);
}

test "verified acquisition does not follow a legacy stage symlink" {
    const io = std.testing.io;
    const output_path = "test-artifact-symlink.bin";
    const legacy_partial = output_path ++ ".part";
    const protected_path = "test-artifact-protected.bin";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, legacy_partial) catch {};
    defer Dir.cwd().deleteFile(io, protected_path) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = protected_path,
        .data = "protected\n",
    });
    try Dir.cwd().symLink(
        io,
        protected_path,
        legacy_partial,
        .{},
    );

    var context = TestDownloader{ .payload = "verified\n" };
    _ = try acquireVerified(
        std.testing.allocator,
        io,
        .{
            .url = "https://example.invalid/artifact",
            .destination_path = output_path,
            .expected_sha256 = sha256Bytes(context.payload),
            .max_size = 1024,
        },
        .{
            .context = &context,
            .downloadFn = TestDownloader.download,
        },
    );
    const protected = try Dir.cwd().readFileAlloc(
        io,
        protected_path,
        std.testing.allocator,
        .limited(64),
    );
    defer std.testing.allocator.free(protected);
    try std.testing.expectEqualStrings("protected\n", protected);
    const legacy_stat = try Dir.cwd().statFile(io, legacy_partial, .{
        .follow_symlinks = false,
    });
    try std.testing.expectEqual(File.Kind.sym_link, legacy_stat.kind);
}

test "verified acquisition preserves output on checksum mismatch" {
    const io = std.testing.io;
    const output_path = "test-artifact-mismatch.bin";
    defer Dir.cwd().deleteFile(io, output_path) catch {};

    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });
    var context = TestDownloader{ .payload = "wrong\n" };
    try std.testing.expectError(
        error.ChecksumMismatch,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("expected\n"),
                .max_size = 1024,
            },
            .{
                .context = &context,
                .downloadFn = TestDownloader.download,
            },
        ),
    );

    var interrupted_steps = [_]TestNativeHttpsStep{
        .{ .partial_failure = "partial" },
    };
    var interrupted_transport = TestNativeHttpsTransport{ .steps = &interrupted_steps };
    defer interrupted_transport.deinit(std.testing.allocator);
    var interrupted = NativeHttpsDownloader{
        .transport = .{ .context = &interrupted_transport, .getFn = TestNativeHttpsTransport.get },
    };
    try std.testing.expectError(
        error.EndOfStream,
        downloadBoundedAtomic(
            std.testing.allocator,
            io,
            "https://example.invalid/key",
            output_path,
            1024,
            interrupted.downloader(),
        ),
    );
    try expectFileContent(io, output_path, "existing\n");
}

test "verified acquisition preserves output when download exceeds limit" {
    const io = std.testing.io;
    const output_path = "test-artifact-limit.bin";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });
    var context = TestDownloader{ .payload = "too large\n" };
    try std.testing.expectError(
        error.ArtifactTooLarge,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes(context.payload),
                .max_size = 4,
            },
            .{
                .context = &context,
                .downloadFn = TestDownloader.download,
            },
        ),
    );
    try expectFileContent(io, output_path, "existing\n");
}

test "verified acquisition replaces oversized cache without hashing it" {
    const io = std.testing.io;
    const output_path = "test-artifact-oversized-cache.bin";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "oversized cache\n",
    });
    var context = TestDownloader{ .payload = "new\n" };
    const result = try acquireVerified(
        std.testing.allocator,
        io,
        .{
            .url = "https://example.invalid/artifact",
            .destination_path = output_path,
            .expected_sha256 = sha256Bytes(context.payload),
            .max_size = context.payload.len,
        },
        .{
            .context = &context,
            .downloadFn = TestDownloader.download,
        },
    );
    try std.testing.expect(!result.reused_cache);
    try std.testing.expectEqual(@as(usize, 1), context.calls);
    try expectFileContent(io, output_path, context.payload);
}

test "native HTTPS acquisition follows bounded redirects and retries" {
    const io = std.testing.io;
    const output_path = "test-native-https-acquire.bin";
    Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};

    var steps = [_]TestNativeHttpsStep{
        .{ .response = .{ .status = 302, .location = "/release/artifact" } },
        .{ .response = .{ .status = 503 } },
        .{ .response = .{ .status = 200, .content_length = 17, .payload = "native artifact\n" } },
    };
    var transport = TestNativeHttpsTransport{ .steps = &steps };
    defer transport.deinit(std.testing.allocator);
    var sleep = TestNativeHttpsSleep{};
    var native = NativeHttpsDownloader{
        .retries = 2,
        .transport = .{ .context = &transport, .getFn = TestNativeHttpsTransport.get },
        .sleep = .{ .context = &sleep, .call = TestNativeHttpsSleep.call },
    };
    const acquired = try acquireVerified(
        std.testing.allocator,
        io,
        .{
            .url = "https://example.invalid/artifact",
            .destination_path = output_path,
            .expected_sha256 = sha256Bytes("native artifact\n"),
            .max_size = 1024,
        },
        native.downloader(),
    );
    try std.testing.expect(!acquired.reused_cache);
    try std.testing.expectEqual(@as(usize, 3), transport.calls);
    try std.testing.expectEqualStrings(
        "https://example.invalid/artifact",
        transport.urls[0].?,
    );
    try std.testing.expectEqualStrings(
        "https://example.invalid/release/artifact",
        transport.urls[1].?,
    );
    try std.testing.expectEqual(@as(usize, 1), sleep.calls);
    try std.testing.expectEqual(@as(u64, 1), sleep.seconds[0]);
}

test "native HTTPS acquisition fails closed on unsafe redirects and retry exhaustion" {
    const io = std.testing.io;
    const output_path = "test-native-https-fail-closed.bin";
    Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });

    var downgrade_steps = [_]TestNativeHttpsStep{
        .{ .response = .{ .status = 302, .location = "http://example.invalid/artifact" } },
    };
    var downgrade_transport = TestNativeHttpsTransport{ .steps = &downgrade_steps };
    defer downgrade_transport.deinit(std.testing.allocator);
    var downgrade = NativeHttpsDownloader{
        .transport = .{ .context = &downgrade_transport, .getFn = TestNativeHttpsTransport.get },
    };
    try std.testing.expectError(
        error.HttpsDowngrade,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("expected\n"),
                .max_size = 1024,
            },
            downgrade.downloader(),
        ),
    );
    try expectFileContent(io, output_path, "existing\n");

    var retry_steps = [_]TestNativeHttpsStep{
        .connection_refused,
        .connection_refused,
    };
    var retry_transport = TestNativeHttpsTransport{ .steps = &retry_steps };
    defer retry_transport.deinit(std.testing.allocator);
    var retry_sleep = TestNativeHttpsSleep{};
    var retrying = NativeHttpsDownloader{
        .retries = 1,
        .transport = .{ .context = &retry_transport, .getFn = TestNativeHttpsTransport.get },
        .sleep = .{ .context = &retry_sleep, .call = TestNativeHttpsSleep.call },
    };
    try std.testing.expectError(
        error.HttpsRetryExhausted,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("expected\n"),
                .max_size = 1024,
            },
            retrying.downloader(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), retry_transport.calls);
    try std.testing.expectEqual(@as(usize, 1), retry_sleep.calls);
    try expectFileContent(io, output_path, "existing\n");

    var bounded_steps = [_]TestNativeHttpsStep{
        .{ .response = .{ .status = 503 } },
        .{ .response = .{ .status = 503 } },
        .{ .response = .{ .status = 503 } },
        .{ .response = .{ .status = 503 } },
    };
    var bounded_transport = TestNativeHttpsTransport{ .steps = &bounded_steps };
    defer bounded_transport.deinit(std.testing.allocator);
    var bounded_sleep = TestNativeHttpsSleep{};
    var bounded = NativeHttpsDownloader{
        .retries = 10,
        .max_backoff_seconds = 60,
        .transport = .{ .context = &bounded_transport, .getFn = TestNativeHttpsTransport.get },
        .sleep = .{ .context = &bounded_sleep, .call = TestNativeHttpsSleep.call },
    };
    try std.testing.expectError(
        error.HttpsRetryExhausted,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("expected\n"),
                .max_size = 1024,
            },
            bounded.downloader(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 4), bounded_transport.calls);
    try std.testing.expectEqual(@as(usize, 3), bounded_sleep.calls);
    try std.testing.expectEqualSlices(
        u64,
        &.{ 1, 2, 4 },
        bounded_sleep.seconds[0..bounded_sleep.calls],
    );
}

test "native HTTPS acquisition rejects TLS failures, oversized, and partial bodies" {
    const io = std.testing.io;
    const output_path = "test-native-https-body.bin";
    Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });

    var tls_steps = [_]TestNativeHttpsStep{.tls_failure};
    var tls_transport = TestNativeHttpsTransport{ .steps = &tls_steps };
    defer tls_transport.deinit(std.testing.allocator);
    var tls = NativeHttpsDownloader{
        .transport = .{ .context = &tls_transport, .getFn = TestNativeHttpsTransport.get },
    };
    try std.testing.expectError(
        error.TlsCertificateInvalid,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("expected\n"),
                .max_size = 1024,
            },
            tls.downloader(),
        ),
    );

    var oversized_steps = [_]TestNativeHttpsStep{
        .{ .response = .{ .status = 200, .content_length = 1025 } },
    };
    var oversized_transport = TestNativeHttpsTransport{ .steps = &oversized_steps };
    defer oversized_transport.deinit(std.testing.allocator);
    var oversized = NativeHttpsDownloader{
        .transport = .{ .context = &oversized_transport, .getFn = TestNativeHttpsTransport.get },
    };
    try std.testing.expectError(
        error.ArtifactTooLarge,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("expected\n"),
                .max_size = 1024,
            },
            oversized.downloader(),
        ),
    );

    var partial_steps = [_]TestNativeHttpsStep{
        .{ .response = .{ .status = 200, .content_length = 7, .payload = "partial" } },
    };
    var partial_transport = TestNativeHttpsTransport{ .steps = &partial_steps };
    defer partial_transport.deinit(std.testing.allocator);
    var partial = NativeHttpsDownloader{
        .transport = .{ .context = &partial_transport, .getFn = TestNativeHttpsTransport.get },
    };
    try std.testing.expectError(
        error.ChecksumMismatch,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("complete artifact\n"),
                .max_size = 1024,
            },
            partial.downloader(),
        ),
    );
    try expectFileContent(io, output_path, "existing\n");
}

test "native HTTPS acquisition rejects redirect loops and non-HTTPS URLs" {
    const io = std.testing.io;
    const output_path = "test-native-https-redirects.bin";
    Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    var loop_steps = [_]TestNativeHttpsStep{
        .{ .response = .{ .status = 302, .location = "/one" } },
        .{ .response = .{ .status = 302, .location = "/two" } },
        .{ .response = .{ .status = 302, .location = "/one" } },
    };
    var loop_transport = TestNativeHttpsTransport{ .steps = &loop_steps };
    defer loop_transport.deinit(std.testing.allocator);
    var loop = NativeHttpsDownloader{
        .max_redirects = 2,
        .transport = .{ .context = &loop_transport, .getFn = TestNativeHttpsTransport.get },
    };
    try std.testing.expectError(
        error.RedirectLimitExceeded,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "https://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("expected\n"),
                .max_size = 1024,
            },
            loop.downloader(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 3), loop_transport.calls);

    var rejected = NativeHttpsDownloader{};
    try std.testing.expectError(
        error.InvalidHttpsUrl,
        acquireVerified(
            std.testing.allocator,
            io,
            .{
                .url = "http://example.invalid/artifact",
                .destination_path = output_path,
                .expected_sha256 = sha256Bytes("expected\n"),
                .max_size = 1024,
            },
            rejected.downloader(),
        ),
    );
}

test "native HTTPS request buffer covers bounded signed redirects" {
    // Keep enough room for a maximum Location plus request-line, Host,
    // Accept-Encoding, and connection headers on the next HTTPS request.
    const minimum_request_overhead = 1024;
    try std.testing.expect(
        native_https_write_buffer_size >=
            native_https_max_location_size + minimum_request_overhead,
    );
}

test "XZ decompression validates and publishes bounded output" {
    const io = std.testing.io;
    const input_path = "test-artifact.xz";
    const output_path = "test-artifact.out";
    defer Dir.cwd().deleteFile(io, input_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = input_path,
        .data = &test_xz,
    });
    const result = try decompressXz(
        std.testing.allocator,
        io,
        testXzOptions(input_path, output_path, &test_xz, 1024),
    );
    const expected = "FreeBSD artifact pipeline\n";
    try std.testing.expectEqual(@as(u64, expected.len), result.size);
    try expectFileContent(io, output_path, expected);
}

test "XZ decompression rejects concatenated streams" {
    const io = std.testing.io;
    const input_path = "test-artifact-concatenated.xz";
    const output_path = "test-artifact-concatenated.out";
    defer Dir.cwd().deleteFile(io, input_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    const input = test_xz ++ test_xz;
    try Dir.cwd().writeFile(io, .{
        .sub_path = input_path,
        .data = &input,
    });
    try std.testing.expectError(
        error.XzDecompressionFailed,
        decompressXz(
            std.testing.allocator,
            io,
            testXzOptions(input_path, output_path, &input, 1024),
        ),
    );
    try std.testing.expectError(error.FileNotFound, Dir.cwd().statFile(io, output_path, .{}));
}

test "XZ decompression rejects corrupt stream checks and trailing bytes" {
    const io = std.testing.io;
    const corrupt_path = "test-artifact-corrupt.xz";
    const trailing_path = "test-artifact-trailing.xz";
    const output_path = "test-artifact-invalid.out";
    defer Dir.cwd().deleteFile(io, corrupt_path) catch {};
    defer Dir.cwd().deleteFile(io, trailing_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    var corrupt = test_xz;
    // This is the CRC64 check, not a framing byte: native verification must
    // reject a stream whose decoder can otherwise reconstruct the payload.
    corrupt[56] ^= 0x01;
    const trailing = test_xz ++ [_]u8{0x7f};
    try Dir.cwd().writeFile(io, .{
        .sub_path = corrupt_path,
        .data = &corrupt,
    });
    try Dir.cwd().writeFile(io, .{
        .sub_path = trailing_path,
        .data = &trailing,
    });
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });

    try std.testing.expectError(
        error.XzDecompressionFailed,
        decompressXz(
            std.testing.allocator,
            io,
            testXzOptions(corrupt_path, output_path, &corrupt, 1024),
        ),
    );
    try expectFileContent(io, output_path, "existing\n");
    try std.testing.expectError(
        error.XzDecompressionFailed,
        decompressXz(
            std.testing.allocator,
            io,
            testXzOptions(trailing_path, output_path, &trailing, 1024),
        ),
    );
    try expectFileContent(io, output_path, "existing\n");
}

test "XZ decompression preserves output on digest and resource limits" {
    const io = std.testing.io;
    const input_path = "test-artifact-limits.xz";
    const output_path = "test-artifact-limits.out";
    defer Dir.cwd().deleteFile(io, input_path) catch {};
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = input_path,
        .data = &test_xz,
    });
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });

    var options = testXzOptions(input_path, output_path, &test_xz, 8);
    try std.testing.expectError(
        error.OutputTooLarge,
        decompressXz(std.testing.allocator, io, options),
    );
    try expectFileContent(io, output_path, "existing\n");

    options.max_output_size = 1024;
    options.max_memory_size = 1;
    try std.testing.expectError(
        error.MemoryLimitTooSmall,
        decompressXz(std.testing.allocator, io, options),
    );
    try expectFileContent(io, output_path, "existing\n");

    options.max_memory_size = 4 * 1024 * 1024;
    try std.testing.expectError(
        error.MemoryLimitTooSmall,
        decompressXz(std.testing.allocator, io, options),
    );
    try expectFileContent(io, output_path, "existing\n");

    options.max_memory_size = 64 * 1024 * 1024;
    options.expected_input_sha256 = sha256Bytes("different");
    try std.testing.expectError(
        error.InputChecksumMismatch,
        decompressXz(std.testing.allocator, io, options),
    );
    try expectFileContent(io, output_path, "existing\n");
}

test "XZ decompression rejects hard-linked input and output" {
    const io = std.testing.io;
    const input_path = "test-artifact-alias.xz";
    const output_path = "test-artifact-alias.out";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};
    try Dir.cwd().writeFile(io, .{
        .sub_path = input_path,
        .data = &test_xz,
    });
    const input_file = try Dir.cwd().openFile(io, input_path, .{
        .mode = .read_only,
    });
    defer input_file.close(io);
    try input_file.hardLink(io, Dir.cwd(), output_path, .{});

    try std.testing.expectError(
        error.InputOutputAliased,
        decompressXz(
            std.testing.allocator,
            io,
            testXzOptions(input_path, output_path, &test_xz, 1024),
        ),
    );
    try expectFileContent(io, input_path, &test_xz);
}

test "QCOW2 finalization publishes standalone zstd output" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!qemuImgAvailable(std.testing.allocator, std.testing.io)) {
        return error.SkipZigTest;
    }
    const io = std.testing.io;
    const input_path = "test-finalize-input.qcow2";
    const output_path = "test-finalize-output.qcow2";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};

    var source = try image.Image.create(
        io,
        input_path,
        .qcow2,
        2 * 1024 * 1024,
        .{},
    );
    const payload = "transactional qcow2 finalization";
    try source.pwrite(io, payload, 64 * 1024);
    source.close(io);
    const before = try hashFile(io, input_path);

    const result = try finalizeQcow2(
        std.testing.allocator,
        io,
        .{
            .input_path = input_path,
            .expected_input_sha256 = before.sha256,
            .max_input_size = 4 * 1024 * 1024,
            .source_format = .qcow2,
            .expected_virtual_size = 2 * 1024 * 1024,
            .max_virtual_size = 2 * 1024 * 1024,
            .output_path = output_path,
            .max_output_size = 4 * 1024 * 1024,
            .qemu_img_path = "qemu-img",
            .compression = .zstd,
        },
    );
    try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024), result.virtual_size);
    try std.testing.expectEqual(Qcow2Compression.zstd, result.compression);
    try std.testing.expectEqual(@as(u32, 64 * 1024), result.cluster_size);

    const source_after = try hashFile(io, input_path);
    try std.testing.expectEqualSlices(u8, &before.sha256, &source_after.sha256);
    var finalized = try image.Image.openPathReadOnly(io, output_path);
    defer finalized.close(io);
    try std.testing.expectEqual(image.Format.qcow2, finalized.format);
    try std.testing.expectEqual(@as(u8, 1), finalized.qcow2.?.compression_type);
    try std.testing.expectEqual(@as(u16, 0), finalized.qcow2.?.backing_file_len);
    var actual: [payload.len]u8 = undefined;
    _ = try finalized.pread(io, &actual, 64 * 1024);
    try std.testing.expectEqualStrings(payload, &actual);
}

test "QCOW2 finalization honors an explicit raw source format" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!qemuImgAvailable(std.testing.allocator, std.testing.io)) {
        return error.SkipZigTest;
    }
    const io = std.testing.io;
    const input_path = "test-finalize-input.raw";
    const output_path = "test-finalize-raw-output.qcow2";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};

    const raw_size = 2 * 1024 * 1024;
    const raw = try Dir.cwd().createFile(io, input_path, .{
        .read = true,
        .truncate = true,
    });
    try raw.setLength(io, raw_size);
    const payload = "QFI\xfb raw payload";
    try raw.writePositionalAll(io, payload, 0);
    raw.close(io);
    const before = try hashFile(io, input_path);

    const result = try finalizeQcow2(
        std.testing.allocator,
        io,
        .{
            .input_path = input_path,
            .expected_input_sha256 = before.sha256,
            .max_input_size = raw_size,
            .source_format = .raw,
            .expected_virtual_size = raw_size,
            .max_virtual_size = raw_size,
            .output_path = output_path,
            .max_output_size = 4 * 1024 * 1024,
            .qemu_img_path = "qemu-img",
            .compression = .zstd,
        },
    );
    try std.testing.expectEqual(@as(u64, raw_size), result.virtual_size);

    var finalized = try image.Image.openPathReadOnly(io, output_path);
    defer finalized.close(io);
    var actual: [payload.len]u8 = undefined;
    _ = try finalized.pread(io, &actual, 0);
    try std.testing.expectEqualStrings(payload, &actual);
}

test "QCOW2 finalization preserves output when the qemu-img fallback cannot start" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const input_path = "test-finalize-failure-input.qcow2";
    const output_path = "test-finalize-failure-output.qcow2";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};
    var source = try image.Image.create(
        io,
        input_path,
        .qcow2,
        1024 * 1024,
        .{},
    );
    source.close(io);
    const input = try hashFile(io, input_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });

    // `.none` exercises the qemu-img fallback path (zstd is emitted natively),
    // so a missing qemu-img binary must fail closed and leave the prior output.
    if (finalizeQcow2(
        std.testing.allocator,
        io,
        .{
            .input_path = input_path,
            .expected_input_sha256 = input.sha256,
            .max_input_size = 2 * 1024 * 1024,
            .source_format = .qcow2,
            .expected_virtual_size = 1024 * 1024,
            .max_virtual_size = 1024 * 1024,
            .output_path = output_path,
            .max_output_size = 2 * 1024 * 1024,
            .compression = .none,
            .qemu_img_path = "miz-qemu-img-does-not-exist",
        },
    )) |_| {
        return error.ExpectedQemuImgFailure;
    } else |_| {}
    try expectFileContent(io, output_path, "existing\n");
}

test "QCOW2 finalization emits standalone zstd output natively without qemu-img" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const input_path = "test-finalize-native-input.qcow2";
    const output_path = "test-finalize-native-output.qcow2";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};

    var source = try image.Image.create(
        io,
        input_path,
        .qcow2,
        2 * 1024 * 1024,
        .{},
    );
    const payload = "native zstd finalization without qemu-img";
    try source.pwrite(io, payload, 128 * 1024);
    source.close(io);
    const before = try hashFile(io, input_path);

    // An empty qemu_img_path proves the zstd path never shells out to qemu-img.
    const result = try finalizeQcow2(
        std.testing.allocator,
        io,
        .{
            .input_path = input_path,
            .expected_input_sha256 = before.sha256,
            .max_input_size = 4 * 1024 * 1024,
            .source_format = .qcow2,
            .expected_virtual_size = 2 * 1024 * 1024,
            .max_virtual_size = 2 * 1024 * 1024,
            .output_path = output_path,
            .max_output_size = 4 * 1024 * 1024,
            .qemu_img_path = "",
            .compression = .zstd,
        },
    );
    try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024), result.virtual_size);
    try std.testing.expectEqual(Qcow2Compression.zstd, result.compression);
    try std.testing.expectEqual(@as(u32, 64 * 1024), result.cluster_size);

    const after = try hashFile(io, input_path);
    try std.testing.expectEqualSlices(u8, &before.sha256, &after.sha256);
    var finalized = try image.Image.openPathReadOnly(io, output_path);
    defer finalized.close(io);
    try std.testing.expectEqual(image.Format.qcow2, finalized.format);
    try std.testing.expectEqual(@as(u8, 1), finalized.qcow2.?.compression_type);
    try std.testing.expectEqual(@as(u16, 0), finalized.qcow2.?.backing_file_len);
    const check = try finalized.check(io);
    try std.testing.expect(check.ok);
    var actual: [payload.len]u8 = undefined;
    _ = try finalized.pread(io, &actual, 128 * 1024);
    try std.testing.expectEqualStrings(payload, &actual);
}

test "QCOW2 finalization rejects hard-linked input and output" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const input_path = "test-finalize-alias-input.qcow2";
    const output_path = "test-finalize-alias-output.qcow2";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};
    var source = try image.Image.create(
        io,
        input_path,
        .qcow2,
        1024 * 1024,
        .{},
    );
    source.close(io);
    const input = try hashFile(io, input_path);
    const input_file = try Dir.cwd().openFile(io, input_path, .{
        .mode = .read_only,
    });
    defer input_file.close(io);
    try input_file.hardLink(io, Dir.cwd(), output_path, .{});

    try std.testing.expectError(
        error.InputOutputAliased,
        finalizeQcow2(
            std.testing.allocator,
            io,
            .{
                .input_path = input_path,
                .expected_input_sha256 = input.sha256,
                .max_input_size = 2 * 1024 * 1024,
                .source_format = .qcow2,
                .expected_virtual_size = 1024 * 1024,
                .max_virtual_size = 1024 * 1024,
                .output_path = output_path,
                .max_output_size = 2 * 1024 * 1024,
                .qemu_img_path = "qemu-img",
            },
        ),
    );
}

test "fixed VHD derivation relocates mirrored GPT transactionally" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const input_path = "test-derive-vhd-input.qcow2";
    const output_path = "test-derive-vhd-output.vhd";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};

    const source_size: u64 = 16 * 1024 * 1024 - gpt.sector_size;
    var source = try image.Image.create(
        io,
        input_path,
        .qcow2,
        source_size,
        .{},
    );
    const specs = [_]gpt.PartitionSpec{
        .{
            .type_guid = guid.esp,
            .unique_guid = guid.parse("11111111-2222-3333-4444-555555555555"),
            .size_sectors = 2048,
            .name_utf16le = gpt.asciiName("efi"),
        },
        .{
            .type_guid = guid.linux_filesystem_data,
            .unique_guid = guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            .size_sectors = 4096,
            .name_utf16le = gpt.asciiName("root"),
        },
    };
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(
        &source,
        io,
        guid.parse("01234567-89ab-cdef-0123-456789abcdef"),
        &specs,
        &placements,
    );
    source.close(io);
    const source_before = try hashFile(io, input_path);

    const result = try deriveFixedVhd(
        std.testing.allocator,
        io,
        .{
            .input_path = input_path,
            .expected_input_sha256 = source_before.sha256,
            .max_input_size = 32 * 1024 * 1024,
            .expected_virtual_size = source_size,
            .max_virtual_size = 32 * 1024 * 1024,
            .output_path = output_path,
            .max_output_size = 32 * 1024 * 1024,
            .unique_id = [_]u8{0x42} ** 16,
            .timestamp_unix = 0,
        },
    );
    try std.testing.expectEqual(source_size, result.source_virtual_size);
    try std.testing.expectEqual(
        @as(u64, 16 * 1024 * 1024),
        result.virtual_size,
    );
    try std.testing.expectEqual(@as(usize, specs.len), result.partition_count);
    try std.testing.expect(result.relocation.was_relocated);

    const source_after = try hashFile(io, input_path);
    try std.testing.expectEqualSlices(
        u8,
        &source_before.sha256,
        &source_after.sha256,
    );
    var source_reopened = try image.Image.openPathReadOnly(io, input_path);
    defer source_reopened.close(io);
    var source_gpt = try gpt.readVerifiedGpt(
        source_reopened,
        io,
        std.testing.allocator,
        1024 * 1024,
    );
    defer source_gpt.deinit(std.testing.allocator);

    var output = try image.Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    try std.testing.expectEqual(image.Format.vhd, output.format);
    try std.testing.expect(output.dynamic == null);
    try std.testing.expectEqual(result.virtual_size, output.virtual_size);
    try std.testing.expectEqual(
        result.virtual_size + vhd.footer_size,
        (try output.info(io)).file_size,
    );
    var output_gpt = try gpt.readVerifiedGpt(
        output,
        io,
        std.testing.allocator,
        1024 * 1024,
    );
    defer output_gpt.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        source_gpt.partition_array,
        output_gpt.partition_array,
    );
    for (source_gpt.partitions, output_gpt.partitions) |before, after| {
        try std.testing.expectEqual(before.first_lba, after.first_lba);
        try std.testing.expectEqual(before.last_lba, after.last_lba);
    }
}

test "fixed VHD derivation preserves output on digest failure and rejects aliases" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const input_path = "test-derive-vhd-safety.qcow2";
    const output_path = "test-derive-vhd-safety.vhd";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};

    var source = try image.Image.create(
        io,
        input_path,
        .qcow2,
        8 * 1024 * 1024,
        .{},
    );
    const specs = [_]gpt.PartitionSpec{.{
        .type_guid = guid.esp,
        .unique_guid = guid.parse("99999999-8888-7777-6666-555555555555"),
        .size_sectors = 2048,
    }};
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(
        &source,
        io,
        guid.parse("12345678-1234-5678-9abc-def012345678"),
        &specs,
        &placements,
    );
    source.close(io);
    const metadata = try hashFile(io, input_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });
    var options = DeriveFixedVhdOptions{
        .input_path = input_path,
        .expected_input_sha256 = sha256Bytes("wrong"),
        .max_input_size = 16 * 1024 * 1024,
        .max_virtual_size = 16 * 1024 * 1024,
        .output_path = output_path,
        .max_output_size = 16 * 1024 * 1024,
    };
    try std.testing.expectError(
        error.InputChecksumMismatch,
        deriveFixedVhd(std.testing.allocator, io, options),
    );
    try expectFileContent(io, output_path, "existing\n");

    try Dir.cwd().deleteFile(io, output_path);
    const input_file = try Dir.cwd().openFile(io, input_path, .{
        .mode = .read_only,
    });
    defer input_file.close(io);
    try input_file.hardLink(io, Dir.cwd(), output_path, .{});
    options.expected_input_sha256 = metadata.sha256;
    try std.testing.expectError(
        error.InputOutputAliased,
        deriveFixedVhd(std.testing.allocator, io, options),
    );
}

test "fixed VHD derivation rejects backing paths before opening them" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    const input_path = "test-derive-vhd-backed.qcow2";
    const output_path = "test-derive-vhd-backed.vhd";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};

    var source = try image.Image.create(
        io,
        input_path,
        .qcow2,
        8 * 1024 * 1024,
        .{},
    );
    source.close(io);
    const backing_path = "/path/that/must/not/be-opened";
    const backing_offset: u64 = 128;
    const file = try Dir.cwd().openFile(io, input_path, .{
        .mode = .read_write,
    });
    try file.writePositionalAll(io, backing_path, backing_offset);
    var backing_offset_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &backing_offset_bytes, backing_offset, .big);
    try file.writePositionalAll(io, &backing_offset_bytes, 8);
    var backing_length_bytes: [4]u8 = undefined;
    std.mem.writeInt(
        u32,
        &backing_length_bytes,
        backing_path.len,
        .big,
    );
    try file.writePositionalAll(io, &backing_length_bytes, 16);
    file.close(io);

    const metadata = try hashFile(io, input_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });
    try std.testing.expectError(
        error.SourceNotStandalone,
        deriveFixedVhd(
            std.testing.allocator,
            io,
            .{
                .input_path = input_path,
                .expected_input_sha256 = metadata.sha256,
                .max_input_size = 16 * 1024 * 1024,
                .max_virtual_size = 16 * 1024 * 1024,
                .output_path = output_path,
                .max_output_size = 16 * 1024 * 1024,
            },
        ),
    );
    try expectFileContent(io, output_path, "existing\n");
}

test "QCOW2 finalization enforces virtual and output size limits" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (!qemuImgAvailable(std.testing.allocator, std.testing.io)) {
        return error.SkipZigTest;
    }
    const io = std.testing.io;
    const input_path = "test-finalize-limits-input.qcow2";
    const output_path = "test-finalize-limits-output.qcow2";
    defer Dir.cwd().deleteFile(io, output_path) catch {};
    defer Dir.cwd().deleteFile(io, input_path) catch {};
    var source = try image.Image.create(
        io,
        input_path,
        .qcow2,
        2 * 1024 * 1024,
        .{},
    );
    source.close(io);
    const input = try hashFile(io, input_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = output_path,
        .data = "existing\n",
    });

    var options = FinalizeQcow2Options{
        .input_path = input_path,
        .expected_input_sha256 = input.sha256,
        .max_input_size = 4 * 1024 * 1024,
        .source_format = .qcow2,
        .expected_virtual_size = 2 * 1024 * 1024,
        .max_virtual_size = 1024 * 1024,
        .output_path = output_path,
        .max_output_size = 4 * 1024 * 1024,
        .qemu_img_path = "qemu-img",
    };
    options.max_input_size = 1;
    try std.testing.expectError(
        error.InputTooLarge,
        finalizeQcow2(std.testing.allocator, io, options),
    );
    try expectFileContent(io, output_path, "existing\n");

    options.max_input_size = 4 * 1024 * 1024;
    try std.testing.expectError(
        error.VirtualSizeTooLarge,
        finalizeQcow2(std.testing.allocator, io, options),
    );
    try expectFileContent(io, output_path, "existing\n");

    options.max_virtual_size = 2 * 1024 * 1024;
    options.max_output_size = 1;
    try std.testing.expectError(
        error.OutputTooLarge,
        finalizeQcow2(std.testing.allocator, io, options),
    );
    try expectFileContent(io, output_path, "existing\n");
}

fn testXzOptions(
    input_path: []const u8,
    output_path: []const u8,
    input: []const u8,
    max_output_size: u64,
) DecompressXzOptions {
    return .{
        .input_path = input_path,
        .expected_input_sha256 = sha256Bytes(input),
        .output_path = output_path,
        .max_output_size = max_output_size,
        .max_memory_size = 64 * 1024 * 1024,
    };
}

fn qemuImgAvailable(allocator: Allocator, io: Io) bool {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "qemu-img", "--version" },
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn expectFileContent(io: Io, path: []const u8, expected: []const u8) !void {
    const actual = try Dir.cwd().readFileAlloc(
        io,
        path,
        std.testing.allocator,
        .limited(expected.len + 1),
    );
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

const TestNativeHttpsStep = union(enum) {
    response: struct {
        status: u16,
        location: ?[]const u8 = null,
        content_length: ?u64 = null,
        payload: []const u8 = "",
    },
    connection_refused,
    tls_failure,
    partial_failure: []const u8,
};

const TestNativeHttpsTransport = struct {
    steps: []const TestNativeHttpsStep,
    calls: usize = 0,
    urls: [8]?[]u8 = .{null} ** 8,

    fn deinit(self: *TestNativeHttpsTransport, allocator: Allocator) void {
        for (&self.urls) |*url| {
            if (url.*) |value| allocator.free(value);
            url.* = null;
        }
    }

    fn get(
        context_ptr: ?*anyopaque,
        allocator: Allocator,
        _: Io,
        url: []const u8,
        _: u64,
        output: *Io.Writer,
    ) !NativeHttpsResponse {
        const context: *TestNativeHttpsTransport = @ptrCast(@alignCast(context_ptr.?));
        if (context.calls == context.steps.len or context.calls == context.urls.len)
            return error.UnexpectedNativeHttpsRequest;
        const step = context.steps[context.calls];
        context.urls[context.calls] = try allocator.dupe(u8, url);
        context.calls += 1;
        return switch (step) {
            .response => |response| blk: {
                if (response.status == 200) try output.writeAll(response.payload);
                break :blk .{
                    .status = response.status,
                    .redirect_location = response.location,
                    .content_length = response.content_length,
                };
            },
            .connection_refused => error.ConnectionRefused,
            .tls_failure => error.TlsCertificateInvalid,
            .partial_failure => |payload| {
                try output.writeAll(payload);
                return error.EndOfStream;
            },
        };
    }
};

const TestNativeHttpsSleep = struct {
    calls: usize = 0,
    seconds: [8]u64 = .{0} ** 8,

    fn call(context_ptr: ?*anyopaque, _: Io, seconds: u64) !void {
        const context: *TestNativeHttpsSleep = @ptrCast(@alignCast(context_ptr.?));
        if (context.calls == context.seconds.len) return error.UnexpectedNativeHttpsSleep;
        context.seconds[context.calls] = seconds;
        context.calls += 1;
    }
};

const TestDownloader = struct {
    payload: []const u8,
    calls: usize = 0,

    fn download(
        context_ptr: ?*anyopaque,
        _: Allocator,
        _: Io,
        _: []const u8,
        _: u64,
        output: *Io.Writer,
    ) !void {
        const context: *TestDownloader = @ptrCast(@alignCast(context_ptr.?));
        context.calls += 1;
        try output.writeAll(context.payload);
    }
};
