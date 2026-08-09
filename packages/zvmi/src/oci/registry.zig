//! OCI Distribution registry transport.
//!
//! Registry manifests and error documents are bounded allocations. Blob
//! transfers are deliberately kept outside that path and stream through a
//! destination-owned temporary file while a SHA-256 verifier runs.
const std = @import("std");
const auth = @import("auth.zig");
const content = @import("content.zig");
const copy = @import("copy.zig");
const layout = @import("layout.zig");
const model = @import("model.zig");
const reference = @import("reference.zig");
const transport = @import("transport.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const http_write_buffer_size = 4096;
pub const response_head_limit = 64 * 1024;
pub const metadata_limit_default = layout.max_metadata_size;
pub const error_body_limit = 64 * 1024;
pub const max_redirects: u8 = 5;
pub const max_attempts: u8 = 3;
pub const max_retry_delay_seconds: u64 = 60;
pub const max_tag_pages: usize = 128;
pub const transfer_buffer_size = 64 * 1024;
pub const max_location_size = 16 * 1024;

pub const Error = error{
    InvalidRegistryUrl,
    InvalidRedirect,
    RedirectLimitExceeded,
    HttpsDowngrade,
    CrossOriginRedirect,
    InsecureAuthorization,
    AuthenticationFailed,
    RegistryRequestFailed,
    HttpRequestFailed,
    MetadataTooLarge,
    InvalidResponseContentEncoding,
    InvalidResponseContentLength,
    InvalidContentDigest,
    DescriptorMismatch,
    InvalidManifest,
    InvalidTagList,
    InvalidTagLink,
    TagPageLimitExceeded,
    BlobVerificationFailed,
    CertificateAuthorityLoadFailed,
} || Allocator.Error;

pub const Sleep = struct {
    context: ?*anyopaque,
    call: *const fn (context: ?*anyopaque, io: Io, seconds: u64) anyerror!void,
};

pub const Options = struct {
    plain_http: bool = false,
    /// A credential file to search before the ambient locations. Ignored when
    /// `credential` is supplied, because nothing is searched at all then.
    authfile: ?[]const u8 = null,
    /// The credential to authenticate with, stated rather than discovered.
    ///
    /// Supplying one **disables ambient discovery entirely**: `authfile`,
    /// `REGISTRY_AUTH_FILE`, `$XDG_RUNTIME_DIR/containers/auth.json`, the
    /// `containers` and Docker configuration files under `$HOME`, and any
    /// credential helper they name are never consulted. A caller that must
    /// account for every input it depends on can therefore state this one and
    /// know that a registry needing authentication fails as an authentication
    /// error rather than succeeding because the machine happened to be logged
    /// in. Leaving it `null` keeps the discovery behaviour a command-line tool
    /// wants.
    credential: ?auth.SuppliedCredential = null,
    tls_ca: ?[]const u8 = null,
    metadata_limit: usize = metadata_limit_default,
    sleep: ?Sleep = null,
    process_runner: auth.ProcessRunner = .{},
};

/// Sanitized, bounded Distribution API failure information. Raw response
/// bodies and request URLs are intentionally never retained here.
pub const StatusError = struct {
    status: u16,
    code: ?[]u8 = null,
    detail: ?[]u8 = null,

    pub fn deinit(self: *StatusError, allocator: Allocator) void {
        if (self.code) |value| allocator.free(value);
        if (self.detail) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const TagList = struct {
    allocator: Allocator,
    tags: [][]u8,

    pub fn deinit(self: *TagList) void {
        for (self.tags) |tag| self.allocator.free(tag);
        self.allocator.free(self.tags);
        self.* = undefined;
    }
};

pub const InspectKind = enum { manifest, index, @"opaque" };

pub const Platform = struct {
    os: []u8,
    architecture: []u8,
    variant: ?[]u8 = null,

    fn deinit(self: *Platform, allocator: Allocator) void {
        allocator.free(self.os);
        allocator.free(self.architecture);
        if (self.variant) |value| allocator.free(value);
        self.* = undefined;
    }
};

/// JSON-ready, owned descriptor data. Annotations are retained as exact JSON
/// values, preserving arbitrary extension keys without exposing parser memory.
pub const Descriptor = struct {
    media_type: ?[]u8,
    digest: []u8,
    size: u64,
    annotations_json: ?[]u8 = null,
    platform: ?Platform = null,

    fn deinit(self: *Descriptor, allocator: Allocator) void {
        if (self.media_type) |value| allocator.free(value);
        allocator.free(self.digest);
        if (self.annotations_json) |value| allocator.free(value);
        if (self.platform) |*value| value.deinit(allocator);
        self.* = undefined;
    }
};

pub const InspectNode = struct {
    descriptor: Descriptor,
    kind: InspectKind,
    config: ?Descriptor = null,
    layers: []Descriptor = &.{},
    manifests: []InspectNode = &.{},

    fn deinit(self: *InspectNode, allocator: Allocator) void {
        self.descriptor.deinit(allocator);
        if (self.config) |*value| value.deinit(allocator);
        for (self.layers) |*value| value.deinit(allocator);
        if (self.layers.len != 0) allocator.free(self.layers);
        for (self.manifests) |*value| value.deinit(allocator);
        if (self.manifests.len != 0) allocator.free(self.manifests);
        self.* = undefined;
    }
};

pub const InspectResult = struct {
    allocator: Allocator,
    schema_version: u32 = 1,
    reference: []u8,
    root: InspectNode,

    pub fn deinit(self: *InspectResult) void {
        self.allocator.free(self.reference);
        self.root.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const InspectOptions = struct {
    mode: model.GraphMode = .all,
    max_depth: usize = 32,
};

/// An immutable name for what a mutable one pointed at, and what that name was
/// found to be.
pub const Pin = struct {
    allocator: Allocator,
    /// The digest-form reference, ready to be written where an immutable name
    /// is wanted: `docker://<authority>/<repository>@sha256:<hex>`.
    reference: []u8,
    /// The digest of the document the selection named at the moment of pinning.
    digest: []u8,
    /// The media type of that document.
    media_type: []u8,
    /// The size in bytes of that document.
    size: u64,
    /// What the digest names.
    kind: InspectKind,
    /// The platform of the pinned image, present only when the digest names a
    /// single manifest whose image configuration states one. An index covers
    /// many platforms and pins to none of them: which one a build uses is
    /// settled when the image is loaded, not when it is pinned.
    platform: ?Platform = null,

    pub fn deinit(self: *Pin) void {
        self.allocator.free(self.reference);
        self.allocator.free(self.digest);
        self.allocator.free(self.media_type);
        if (self.platform) |*value| value.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Source = struct {
    io: Io,
    allocator: Allocator,
    environ: std.process.Environ,
    authority: []u8,
    repository: []u8,
    plain_http: bool,
    authfile: ?[]u8,
    metadata_limit: usize,
    sleep_callback: ?Sleep,
    process_runner: auth.ProcessRunner,
    client: std.http.Client,
    token_cache: auth.TokenCache,
    credential: ?auth.Credential = null,
    credential_loaded: bool = false,
    authorization: ?[]u8 = null,
    pinged: bool = false,
    last_error: ?StatusError = null,

    pub fn init(
        io: Io,
        allocator: Allocator,
        environ: std.process.Environ,
        source: reference.RegistryReference,
        options: Options,
    ) !Source {
        if (options.metadata_limit == 0 or options.metadata_limit > metadata_limit_default) return error.MetadataTooLarge;
        const authority = try allocator.dupe(u8, source.authority);
        const repository = allocator.dupe(u8, source.repository) catch |err| {
            allocator.free(authority);
            return err;
        };
        const authfile = if (options.authfile) |path| allocator.dupe(u8, path) catch |err| {
            allocator.free(authority);
            allocator.free(repository);
            return err;
        } else null;
        var result = Source{
            .io = io,
            .allocator = allocator,
            .environ = environ,
            .authority = authority,
            .repository = repository,
            .plain_http = options.plain_http,
            .authfile = authfile,
            .metadata_limit = options.metadata_limit,
            .sleep_callback = options.sleep,
            .process_runner = options.process_runner,
            .client = .{
                .allocator = allocator,
                .io = io,
                .read_buffer_size = response_head_limit,
                .write_buffer_size = http_write_buffer_size,
            },
            .token_cache = auth.TokenCache.init(allocator),
        };
        errdefer result.deinit();
        if (options.credential) |supplied| {
            result.credential = try supplied.toOwned(allocator);
            result.credential_loaded = true;
        }
        if (options.tls_ca) |ca_path| try result.addCertificateAuthority(ca_path);
        return result;
    }

    pub fn deinit(self: *Source) void {
        if (self.last_error) |*value| value.deinit(self.allocator);
        if (self.credential) |*value| value.deinit(self.allocator);
        if (self.authorization) |value| {
            std.crypto.secureZero(u8, value);
            self.allocator.free(value);
        }
        self.token_cache.deinit();
        self.client.deinit();
        self.allocator.free(self.authority);
        self.allocator.free(self.repository);
        if (self.authfile) |value| self.allocator.free(value);
        self.* = undefined;
    }

    /// Returns the last structured Distribution error, if any. The returned
    /// values remain owned by the source and are invalidated by another request.
    pub fn lastError(self: *const Source) ?*const StatusError {
        return if (self.last_error) |*value| value else null;
    }

    pub fn asTransport(self: *Source) transport.Source {
        return .{
            .context = self,
            .read_metadata = readMetadataTransport,
            .read_manifest_metadata = readManifestMetadataTransport,
            .copy_verified_to = copyVerifiedToTransport,
            .registry_identity = .{
                .authority = self.authority,
                .repository = self.repository,
                .plain_http = self.plain_http,
            },
        };
    }

    /// GET /v2/ establishes API availability and authentication state.
    pub fn ping(self: *Source) !void {
        if (self.pinged) return;
        const url = try self.urlFor("/v2/");
        defer self.allocator.free(url);
        var response = try self.fetchBounded(.GET, url, .{
            .class = .registry,
            .limit = self.metadata_limit,
        });
        defer response.deinit(self.allocator);
        if (!isSuccess(response.status)) return error.RegistryRequestFailed;
        self.pinged = true;
    }

    /// Resolves a tag or digest into an exact root manifest/index descriptor.
    pub fn resolve(self: *Source, source: reference.RegistryReference) !layout.ResolvedRoot {
        if (!std.mem.eql(u8, source.authority, self.authority) or
            !std.mem.eql(u8, source.repository, self.repository))
        {
            return error.InvalidRegistryUrl;
        }
        const selection = source.selection orelse return error.InvalidRegistryUrl;
        try self.ping();
        var selector_buffer: [71]u8 = undefined;
        const selector = switch (selection) {
            .tag => |tag| tag,
            .digest => |digest| blk: {
                selector_buffer = digest.format();
                break :blk &selector_buffer;
            },
        };
        const url = try self.manifestUrl(selector);
        defer self.allocator.free(url);
        var response = try self.fetchBounded(.GET, url, .{
            .class = .registry,
            .accept = manifest_accept,
            .limit = self.metadata_limit,
        });
        errdefer response.deinit(self.allocator);
        try verifyManifestResponse(selection, response.body, response.content_digest);
        const media_type = response.content_type orelse return error.InvalidManifest;
        const root_digest = switch (selection) {
            .tag => content.digestBytes(response.body),
            .digest => |value| value,
        };
        const digest_text = root_digest.format();
        const descriptor_json = try std.fmt.allocPrint(
            self.allocator,
            "{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}",
            .{ media_type, &digest_text, response.body.len },
        );
        errdefer self.allocator.free(descriptor_json);
        var descriptor_parsed = std.json.parseFromSlice(model.Descriptor, self.allocator, descriptor_json, .{ .ignore_unknown_fields = true }) catch return error.InvalidManifest;
        errdefer descriptor_parsed.deinit();
        model.validateRootDescriptor(descriptor_parsed.value) catch return error.InvalidManifest;
        try validateDocument(self.allocator, descriptor_parsed.value, response.body, media_type);
        const bytes = response.takeBody();
        response.deinit(self.allocator);
        return .{
            .descriptor = descriptor_parsed.value,
            .bytes = bytes,
            .descriptor_json = descriptor_json,
            .descriptor_parsed = descriptor_parsed,
            .allocator = self.allocator,
        };
    }

    /// Performs a manifest HEAD with the same content negotiation as GET.
    pub fn headManifest(self: *Source, source: reference.RegistryReference) !model.Descriptor {
        if (!std.mem.eql(u8, source.authority, self.authority) or
            !std.mem.eql(u8, source.repository, self.repository))
        {
            return error.InvalidRegistryUrl;
        }
        const selection = source.selection orelse return error.InvalidRegistryUrl;
        try self.ping();
        var selector_buffer: [71]u8 = undefined;
        const selector = switch (selection) {
            .tag => |tag| tag,
            .digest => |digest| blk: {
                selector_buffer = digest.format();
                break :blk &selector_buffer;
            },
        };
        const url = try self.manifestUrl(selector);
        defer self.allocator.free(url);
        var response = try self.fetchBounded(.HEAD, url, .{
            .class = .registry,
            .accept = manifest_accept,
            .limit = self.metadata_limit,
        });
        defer response.deinit(self.allocator);
        const response_media_type = response.content_type orelse return error.InvalidManifest;
        const response_class = model.classifyMediaType(response_media_type);
        if (!response_class.isManifest() and !response_class.isIndex()) return error.InvalidManifest;
        const media_type = try self.allocator.dupe(u8, response_media_type);
        errdefer self.allocator.free(media_type);
        const size = response.content_length orelse return error.InvalidResponseContentLength;
        const digest = if (response.content_digest) |value| blk: {
            const header_digest = content.Digest.parse(value) catch return error.InvalidContentDigest;
            switch (selection) {
                .digest => |requested| {
                    if (!std.mem.eql(u8, &header_digest.bytes, &requested.bytes)) return error.DescriptorMismatch;
                },
                .tag => {},
            }
            break :blk try self.allocator.dupe(u8, value);
        } else switch (selection) {
            .digest => |value| blk: {
                const text = value.format();
                break :blk try self.allocator.dupe(u8, &text);
            },
            .tag => return error.InvalidContentDigest,
        };
        errdefer self.allocator.free(digest);
        _ = content.Digest.parse(digest) catch return error.InvalidContentDigest;
        return .{
            .mediaType = media_type,
            .digest = digest,
            .size = size,
        };
    }

    /// Reads and validates a bounded manifest/index/config document by digest.
    pub fn readMetadata(self: *Source, descriptor: model.Descriptor) ![]u8 {
        return self.readMetadataFrom(descriptor, null);
    }

    /// Reads an index child through the Distribution manifest endpoint even
    /// when its media type is an extension unknown to this implementation.
    pub fn readManifestMetadata(self: *Source, descriptor: model.Descriptor) ![]u8 {
        return self.readMetadataFrom(descriptor, .manifest);
    }

    fn readMetadataFrom(
        self: *Source,
        descriptor: model.Descriptor,
        forced_role: ?transport.DescriptorRole,
    ) ![]u8 {
        if (descriptor.size > self.metadata_limit or descriptor.size > std.math.maxInt(usize)) return error.MetadataTooLarge;
        const digest = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
        const digest_text = digest.format();
        const class = model.classifyMediaType(descriptor.mediaType);
        const is_manifest_document = forced_role == .manifest or class.isManifest() or class.isIndex();
        const expected_media_type = if (is_manifest_document)
            descriptor.mediaType orelse return error.InvalidManifest
        else
            null;
        if (expected_media_type) |value| model.validateMediaType(value) catch return error.InvalidManifest;
        const url = if (is_manifest_document)
            try self.manifestUrl(&digest_text)
        else
            try self.blobUrl(&digest_text);
        defer self.allocator.free(url);
        var response = try self.fetchBounded(.GET, url, .{
            .class = if (is_manifest_document) .registry else .blob,
            .accept = if (is_manifest_document) expected_media_type else null,
            .limit = self.metadata_limit,
        });
        errdefer response.deinit(self.allocator);
        try verifyDescriptorBytes(descriptor, response.body, response.content_digest);
        if (is_manifest_document) {
            const received = response.content_type orelse return error.InvalidManifest;
            if (!std.mem.eql(u8, received, expected_media_type.?)) return error.InvalidManifest;
            if (class.isManifest() or class.isIndex()) {
                try validateDocument(self.allocator, descriptor, response.body, received);
            }
        }
        const body = response.takeBody();
        response.deinit(self.allocator);
        return body;
    }

    /// Streams a blob directly into `destination`, restarting the destination
    /// and hasher before every retry. No allocation is proportional to blob
    /// size.
    pub fn copyVerifiedTo(self: *Source, descriptor: model.Descriptor, destination: Io.File) !void {
        const digest = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
        const text = digest.format();
        const class = model.classifyMediaType(descriptor.mediaType);
        const url = if (class.isManifest() or class.isIndex())
            try self.manifestUrl(&text)
        else
            try self.blobUrl(&text);
        defer self.allocator.free(url);
        try self.streamBlob(url, descriptor, destination, !(class.isManifest() or class.isIndex()));
    }

    /// Streams a remote blob through the normal size/digest verifier without
    /// retaining its body. Registry destinations use this only to verify a
    /// HEAD hit that did not provide Docker-Content-Digest.
    fn verifyBlob(self: *Source, descriptor: model.Descriptor) !void {
        const digest = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
        const text = digest.format();
        const url = try self.blobUrl(&text);
        defer self.allocator.free(url);
        try self.streamBlob(url, descriptor, null, true);
    }

    /// A destination blob is reusable only after its descriptor has been
    /// verified. A digest-less HEAD is deliberately followed by a streaming
    /// GET; it is never treated as a cache hit based on its path alone.
    fn blobState(self: *Source, descriptor: model.Descriptor) !BlobState {
        const digest = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
        const text = digest.format();
        try self.ping();
        const url = try self.blobUrl(&text);
        defer self.allocator.free(url);
        var response = try self.fetchBounded(.HEAD, url, .{
            .class = .blob,
            .limit = 0,
            .accepted_statuses = &.{ .ok, .not_found },
        });
        defer response.deinit(self.allocator);
        switch (response.status) {
            .not_found => return .missing,
            .ok => {},
            else => unreachable,
        }
        const length = response.content_length orelse return error.InvalidResponseContentLength;
        if (length != descriptor.size) return error.DescriptorMismatch;
        if (response.content_digest) |header| {
            const actual = content.Digest.parse(header) catch return error.InvalidContentDigest;
            if (!std.mem.eql(u8, &actual.bytes, &digest.bytes)) return error.InvalidContentDigest;
        } else {
            // Do not turn a failed GET into a transfer. A successful HEAD and
            // a contradictory GET is remote corruption, not a cache miss.
            try self.verifyBlob(descriptor);
        }
        return .valid;
    }

    fn confirmManifest(
        self: *Source,
        selector: []const u8,
        descriptor: model.Descriptor,
    ) !void {
        const expected = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
        const expected_media_type = descriptor.mediaType orelse return error.InvalidManifest;
        try self.ping();
        const url = try self.manifestUrl(selector);
        defer self.allocator.free(url);
        var response = try self.fetchBounded(.HEAD, url, .{
            .class = .registry,
            .accept = expected_media_type,
            .limit = 0,
        });
        defer response.deinit(self.allocator);
        if (response.content_length) |length| {
            if (length != descriptor.size) return error.DescriptorMismatch;
        } else return error.InvalidResponseContentLength;
        const media_type = response.content_type orelse return error.InvalidManifest;
        if (!std.mem.eql(u8, media_type, expected_media_type)) return error.InvalidManifest;
        if (response.content_digest) |header| {
            const actual = content.Digest.parse(header) catch return error.InvalidContentDigest;
            if (!std.mem.eql(u8, &actual.bytes, &expected.bytes)) return error.InvalidContentDigest;
        } else {
            var get = try self.fetchBounded(.GET, url, .{
                .class = .registry,
                .accept = expected_media_type,
                .limit = self.metadata_limit,
            });
            defer get.deinit(self.allocator);
            try verifyDescriptorBytes(descriptor, get.body, get.content_digest);
            const received_media_type = get.content_type orelse return error.InvalidManifest;
            if (!std.mem.eql(u8, received_media_type, expected_media_type)) return error.InvalidManifest;
            const class = model.classifyMediaType(descriptor.mediaType);
            if (class.isManifest() or class.isIndex()) {
                try validateDocument(self.allocator, descriptor, get.body, received_media_type);
            }
        }
    }

    /// Pulls a registry source into an OCI layout through the same copy graph
    /// and destination commit path used by local-to-local copies.
    pub fn copyToLayout(
        self: *Source,
        source: reference.RegistryReference,
        destination: reference.LayoutReference,
        options: copy.Options,
    ) !copy.Result {
        var resolved = try self.resolve(source);
        defer resolved.deinit();
        return copy.resolvedToLayout(self.io, self.allocator, self.asTransport(), &resolved, destination, options);
    }

    /// Copies a registry source into another registry through the same graph
    /// planner used by layout copies. The destination owns separate push
    /// authentication and upload state.
    pub fn copyToRegistry(
        self: *Source,
        source: reference.RegistryReference,
        destination: reference.RegistryReference,
        destination_options: Options,
        options: copy.Options,
    ) !copy.Result {
        var target = try Destination.init(
            self.io,
            self.allocator,
            self.environ,
            destination,
            destination_options,
        );
        defer target.deinit();
        return self.copyToDestination(source, &target, options);
    }

    /// Copies into an already initialized destination so callers can inspect
    /// the source and destination status contexts if publication fails.
    pub fn copyToDestination(
        self: *Source,
        source: reference.RegistryReference,
        target: *Destination,
        options: copy.Options,
    ) !copy.Result {
        var resolved = try self.resolve(source);
        defer resolved.deinit();
        return copy.resolvedToDestination(
            self.allocator,
            self.asTransport(),
            &resolved,
            target.asTransport(),
            target.selection,
            options,
        );
    }

    pub fn listTags(self: *Source, source: reference.RegistryReference) !TagList {
        if (!std.mem.eql(u8, source.authority, self.authority) or
            !std.mem.eql(u8, source.repository, self.repository) or source.selection != null)
        {
            return error.InvalidRegistryUrl;
        }
        try self.ping();
        var tags = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (tags.items) |tag| self.allocator.free(tag);
            tags.deinit();
        }
        var seen = std.StringHashMap(void).init(self.allocator);
        defer seen.deinit();
        var url = try self.tagsUrl();
        defer self.allocator.free(url);
        var pages: usize = 0;
        while (true) {
            if (pages >= max_tag_pages) return error.TagPageLimitExceeded;
            pages += 1;
            var response = try self.fetchBounded(.GET, url, .{
                .class = .registry,
                .accept = "application/json",
                .limit = self.metadata_limit,
            });
            defer response.deinit(self.allocator);
            try self.appendTags(response.body, &tags, &seen);
            const next_location = try nextLink(self.allocator, response.links);
            if (next_location) |location| {
                defer self.allocator.free(location);
                const next_url = try resolveUrlAlloc(self.allocator, url, location);
                if (!sameOriginUrl(url, next_url)) {
                    self.allocator.free(next_url);
                    return error.InvalidTagLink;
                }
                self.allocator.free(url);
                url = next_url;
            } else break;
        }
        std.mem.sort([]u8, tags.items, {}, lessString);
        return .{ .allocator = self.allocator, .tags = try tags.toOwnedSlice() };
    }

    pub fn inspect(self: *Source, source: reference.RegistryReference, options: InspectOptions) !InspectResult {
        var resolved = try self.resolve(source);
        defer resolved.deinit();
        const original = try registryReferenceText(self.allocator, source);
        defer self.allocator.free(original);
        return inspectResolved(
            self.allocator,
            self.asTransport(),
            original,
            resolved.descriptor,
            options,
        );
    }

    /// Resolves a reference to the digest it names *right now*, so a caller can
    /// record an immutable name for a mutable one.
    ///
    /// This is deliberately impure and deliberately not part of any plan: two
    /// calls against the same tag may disagree, because the tag may have moved
    /// between them. That is what makes pinning something a person does once
    /// and commits, the way a lock file is written once and committed, rather
    /// than something a build repeats and hopes stays still.
    ///
    /// A reference that already names a digest pins to itself and the round
    /// trip confirms the registry serves it.
    ///
    /// The platform is reported only for a single manifest, whose image
    /// configuration states one. An index is pinned as an index: it covers many
    /// platforms, and choosing among them belongs to the load that consumes it.
    pub fn pin(self: *Source, source: reference.RegistryReference) !Pin {
        var resolved = try self.resolve(source);
        defer resolved.deinit();
        var active = std.StringHashMap(void).init(self.allocator);
        defer active.deinit();
        var inspector = Inspector{ .allocator = self.allocator, .source = self.asTransport() };
        // Depth zero and no recursion: the pinned document is the only one that
        // matters, and walking an index's children would be a request per
        // platform to learn nothing the pin records.
        var node = try inspector.inspectDocument(resolved.descriptor, resolved.bytes, 0, 0, &active, false);
        defer node.deinit(self.allocator);
        const reference_text = try std.fmt.allocPrint(
            self.allocator,
            "docker://{s}/{s}@{s}",
            .{ self.authority, self.repository, resolved.descriptor.digest },
        );
        errdefer self.allocator.free(reference_text);
        const digest_text = try self.allocator.dupe(u8, resolved.descriptor.digest);
        errdefer self.allocator.free(digest_text);
        const media_type = try self.allocator.dupe(u8, resolved.descriptor.mediaType orelse return error.InvalidManifest);
        errdefer self.allocator.free(media_type);
        var platform: ?Platform = null;
        if (node.kind == .manifest) {
            if (node.descriptor.platform) |*found| {
                platform = try ownedPlatform(self.allocator, .{
                    .os = found.os,
                    .architecture = found.architecture,
                    .variant = found.variant,
                });
            }
        }
        return .{
            .allocator = self.allocator,
            .reference = reference_text,
            .digest = digest_text,
            .media_type = media_type,
            .size = resolved.descriptor.size,
            .kind = node.kind,
            .platform = platform,
        };
    }

    fn addCertificateAuthority(self: *Source, path: []const u8) !void {        const now = Io.Clock.real.now(self.io);
        self.client.ca_bundle.rescan(self.allocator, self.io, now) catch return error.CertificateAuthorityLoadFailed;
        var file = if (std.fs.path.isAbsolute(path))
            Io.Dir.openFileAbsolute(self.io, path, .{}) catch return error.CertificateAuthorityLoadFailed
        else
            Io.Dir.cwd().openFile(self.io, path, .{}) catch return error.CertificateAuthorityLoadFailed;
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        self.client.ca_bundle.addCertsFromFile(self.allocator, &reader, now.toSeconds()) catch return error.CertificateAuthorityLoadFailed;
        self.client.now = now;
    }

    fn urlFor(self: *const Source, suffix: []const u8) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}://{s}{s}",
            .{ if (self.plain_http) "http" else "https", self.authority, suffix },
        );
    }

    fn manifestUrl(self: *const Source, selector: []const u8) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}://{s}/v2/{s}/manifests/{s}",
            .{ if (self.plain_http) "http" else "https", self.authority, self.repository, selector },
        );
    }

    fn blobUrl(self: *const Source, digest: []const u8) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}://{s}/v2/{s}/blobs/{s}",
            .{ if (self.plain_http) "http" else "https", self.authority, self.repository, digest },
        );
    }

    fn tagsUrl(self: *const Source) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}://{s}/v2/{s}/tags/list",
            .{ if (self.plain_http) "http" else "https", self.authority, self.repository },
        );
    }

    fn fetchBounded(
        self: *Source,
        method: std.http.Method,
        initial_url: []const u8,
        spec: RequestSpec,
    ) !ResponseBytes {
        var current_url = try self.allocator.dupe(u8, initial_url);
        defer self.allocator.free(current_url);
        var redirects: u8 = 0;
        var retries: u8 = 0;
        var refreshed = false;
        var authorization_stripped = false;

        while (true) {
            const authorization = if (spec.explicit_authorization) |value|
                value
            else if (spec.class != .token and !authorization_stripped)
                self.authorization
            else
                null;
            var result = try self.fetchAttempt(
                method,
                current_url,
                spec,
                authorization,
                authorization_stripped,
            );
            switch (result) {
                .response => |response| return response,
                .transport_failure => {
                    if (retries + 1 >= max_attempts) return error.HttpRequestFailed;
                    try self.sleepForRetry(null, retries);
                    retries += 1;
                },
                .retry => |after| {
                    if (retries + 1 >= max_attempts) return error.RegistryRequestFailed;
                    try self.sleepForRetry(after, retries);
                    retries += 1;
                },
                .authenticate => |*challenges| {
                    defer challenges.deinit();
                    try self.handleAuthentication(
                        challenges.*,
                        current_url,
                        authorization,
                        authorization_stripped,
                        &refreshed,
                    );
                },
                .redirect => |location| {
                    defer self.allocator.free(location);
                    if (redirects >= max_redirects) return error.RedirectLimitExceeded;
                    const next_url = resolveUrlAlloc(self.allocator, current_url, location) catch return error.InvalidRedirect;
                    const same_origin = sameOriginUrl(current_url, next_url);
                    const current_uri = std.Uri.parse(current_url) catch {
                        self.allocator.free(next_url);
                        return error.InvalidRegistryUrl;
                    };
                    const next_uri = std.Uri.parse(next_url) catch {
                        self.allocator.free(next_url);
                        return error.InvalidRedirect;
                    };
                    if (std.ascii.eqlIgnoreCase(current_uri.scheme, "https") and
                        std.ascii.eqlIgnoreCase(next_uri.scheme, "http"))
                    {
                        self.allocator.free(next_url);
                        return error.HttpsDowngrade;
                    }
                    switch (spec.class) {
                        .token => if (!same_origin) {
                            self.allocator.free(next_url);
                            return error.CrossOriginRedirect;
                        },
                        .registry => if (!same_origin) {
                            self.allocator.free(next_url);
                            return error.CrossOriginRedirect;
                        },
                        .blob => {
                            if (!same_origin) authorization_stripped = true;
                        },
                    }
                    self.allocator.free(current_url);
                    current_url = next_url;
                    redirects += 1;
                },
            }
        }
    }

    fn fetchAttempt(
        self: *Source,
        method: std.http.Method,
        url: []const u8,
        spec: RequestSpec,
        authorization: ?[]const u8,
        authorization_stripped: bool,
    ) !Attempt {
        const uri = std.Uri.parse(url) catch return error.InvalidRegistryUrl;
        if (uri.user != null or uri.password != null) return error.InvalidRedirect;
        if (spec.class == .token and isPlainNonLoopback(uri)) return error.InsecureAuthorization;
        if (authorization != null and isPlainNonLoopback(uri)) return error.InsecureAuthorization;

        var headers: [2]std.http.Header = undefined;
        var header_count: usize = 0;
        if (spec.accept) |value| {
            headers[header_count] = .{ .name = "Accept", .value = value };
            header_count += 1;
        }
        if (authorization) |value| {
            // Zig 0.16 does not write privileged_headers on the initial
            // request, so this must remain an extra header.
            headers[header_count] = .{ .name = "Authorization", .value = value };
            header_count += 1;
        }
        var request = self.client.request(method, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{ .accept_encoding = .{ .override = "identity" } },
            .extra_headers = headers[0..header_count],
        }) catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return error.HttpRequestFailed;
        };
        defer request.deinit();
        request.sendBodiless() catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return error.HttpRequestFailed;
        };
        var response = request.receiveHead(&.{}) catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return error.HttpRequestFailed;
        };
        if (response.head.content_encoding != .identity) return error.InvalidResponseContentEncoding;

        if (response.head.status.class() == .redirect) {
            const location = response.head.location orelse return error.InvalidRedirect;
            if (location.len == 0 or location.len > max_location_size) return error.InvalidRedirect;
            const copy_location = try self.allocator.dupe(u8, location);
            errdefer self.allocator.free(copy_location);
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return .{ .redirect = copy_location };
        }
        if (response.head.status == .unauthorized and spec.class != .token and spec.explicit_authorization == null) {
            if (authorization_stripped) return error.AuthenticationFailed;
            var values: [auth.max_challenges][]const u8 = undefined;
            var count: usize = 0;
            var headers_it = response.head.iterateHeaders();
            while (headers_it.next()) |header| {
                if (!std.ascii.eqlIgnoreCase(header.name, "WWW-Authenticate")) continue;
                if (count == values.len) return error.AuthenticationFailed;
                values[count] = header.value;
                count += 1;
            }
            if (count == 0) return error.AuthenticationFailed;
            var challenges = try auth.parseChallenges(self.allocator, values[0..count]);
            errdefer challenges.deinit();
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return .{ .authenticate = challenges };
        }
        if (isRetryableStatus(response.head.status)) {
            const retry_after = retryAfterSeconds(response.head.iterateHeaders(), Io.Clock.real.now(self.io).toSeconds());
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return .{ .retry = retry_after };
        }
        if (!acceptsStatus(spec, response.head.status)) {
            self.setStatusError(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return err;
            };
            return error.RegistryRequestFailed;
        }
        const collected = self.collectResponse(&response, spec.limit, method != .HEAD) catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return err;
        };
        return .{ .response = collected };
    }

    /// Executes one mutating request, permitting only an authentication
    /// challenge retry. Transport and retryable-status outcomes are returned
    /// to the upload state machine, which first confirms blob existence before
    /// it starts a fresh upload session.
    fn mutate(
        self: *Source,
        method: std.http.Method,
        url: []const u8,
        body: MutationBody,
        authorization_stripped: bool,
    ) !MutationOutcome {
        var refreshed = false;
        const replay_safe = switch (body) {
            .file => false,
            .empty, .bytes => true,
        };
        while (true) {
            const authorization = if (authorization_stripped) null else self.authorization;
            var result = try self.mutateAttempt(
                method,
                url,
                body,
                authorization,
                authorization_stripped,
            );
            switch (result) {
                .response => |response| return .{ .response = response },
                .transport_failure => return .transport_failure,
                .retry => |after| return .{ .retry = after },
                .authenticate => |*challenges| {
                    defer challenges.deinit();
                    try self.handleAuthentication(
                        challenges.*,
                        url,
                        authorization,
                        authorization_stripped,
                        &refreshed,
                    );
                    if (!replay_safe) return .{ .retry = null };
                },
            }
        }
    }

    fn mutateAttempt(
        self: *Source,
        method: std.http.Method,
        url: []const u8,
        body: MutationBody,
        authorization: ?[]const u8,
        authorization_stripped: bool,
    ) !MutationAttempt {
        const uri = std.Uri.parse(url) catch return error.InvalidRegistryUrl;
        if (uri.user != null or uri.password != null or uri.fragment != null) return error.InvalidRedirect;
        if (authorization != null and isPlainNonLoopback(uri)) return error.InsecureAuthorization;

        var extra_headers: [1]std.http.Header = undefined;
        const headers: []const std.http.Header = if (authorization) |value| blk: {
            // Zig 0.16 does not write privileged_headers on the initial
            // request, so this remains an extra header.
            extra_headers[0] = .{ .name = "Authorization", .value = value };
            break :blk &extra_headers;
        } else &.{};
        var request = self.client.request(method, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{
                .accept_encoding = .{ .override = "identity" },
                .content_type = .{ .override = body.contentType() },
            },
            .extra_headers = headers,
        }) catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return error.HttpRequestFailed;
        };
        defer request.deinit();

        switch (body) {
            .empty => request.sendBodyComplete(&.{}) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            },
            .bytes => |value| request.sendBodyComplete(@constCast(value.bytes)) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            },
            .file => |value| {
                request.transfer_encoding = .{ .content_length = value.descriptor.size };
                var writer_buffer: [transfer_buffer_size]u8 = undefined;
                var body_writer = request.sendBodyUnflushed(&writer_buffer) catch |err| {
                    if (isRetryableTransportError(err)) return .transport_failure;
                    return error.HttpRequestFailed;
                };
                if ((value.file.length(self.io) catch return error.HttpRequestFailed) != value.descriptor.size) {
                    return error.BlobVerificationFailed;
                }
                const expected = content.Digest.parse(value.descriptor.digest) catch return error.DescriptorMismatch;
                var verifier = content.Verifier.init(expected, value.descriptor.size);
                var transfer_buffer: [transfer_buffer_size]u8 = undefined;
                var offset: u64 = 0;
                while (offset < value.descriptor.size) {
                    const remaining: usize = @intCast(@min(value.descriptor.size - offset, transfer_buffer.len));
                    const count = value.file.readPositional(self.io, &.{transfer_buffer[0..remaining]}, offset) catch |err| {
                        if (isRetryableTransportError(err)) return .transport_failure;
                        return error.HttpRequestFailed;
                    };
                    if (count == 0) return error.BlobVerificationFailed;
                    verifier.update(transfer_buffer[0..count]) catch return error.BlobVerificationFailed;
                    body_writer.writer.writeAll(transfer_buffer[0..count]) catch |err| {
                        if (isRetryableTransportError(err)) return .transport_failure;
                        return error.HttpRequestFailed;
                    };
                    offset += count;
                }
                verifier.finish() catch return error.BlobVerificationFailed;
                body_writer.end() catch |err| {
                    if (isRetryableTransportError(err)) return .transport_failure;
                    return error.HttpRequestFailed;
                };
                request.connection.?.flush() catch |err| {
                    if (isRetryableTransportError(err)) return .transport_failure;
                    return error.HttpRequestFailed;
                };
            },
        }

        var response = request.receiveHead(&.{}) catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return error.HttpRequestFailed;
        };
        if (response.head.content_encoding != .identity) return error.InvalidResponseContentEncoding;
        if (response.head.status.class() == .redirect) {
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return error.InvalidRedirect;
        }
        if (response.head.status == .unauthorized) {
            if (authorization_stripped) return error.AuthenticationFailed;
            var values: [auth.max_challenges][]const u8 = undefined;
            var count: usize = 0;
            var headers_it = response.head.iterateHeaders();
            while (headers_it.next()) |header| {
                if (!std.ascii.eqlIgnoreCase(header.name, "WWW-Authenticate")) continue;
                if (count == values.len) return error.AuthenticationFailed;
                values[count] = header.value;
                count += 1;
            }
            if (count == 0) return error.AuthenticationFailed;
            var challenges = try auth.parseChallenges(self.allocator, values[0..count]);
            errdefer challenges.deinit();
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return .{ .authenticate = challenges };
        }
        if (isRetryableStatus(response.head.status)) {
            const retry_after = retryAfterSeconds(response.head.iterateHeaders(), Io.Clock.real.now(self.io).toSeconds());
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return .{ .retry = retry_after };
        }

        const content_digest = try duplicateSingleHeader(
            self.allocator,
            response.head.iterateHeaders(),
            "Docker-Content-Digest",
        );
        errdefer if (content_digest) |value| self.allocator.free(value);
        const location = try duplicateSingleHeader(self.allocator, response.head.iterateHeaders(), "Location");
        errdefer if (location) |value| self.allocator.free(value);
        if (response.head.status.class() != .success) {
            self.setStatusError(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return err;
            };
        } else {
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
        }
        return .{ .response = .{
            .status = response.head.status,
            .content_digest = content_digest,
            .location = location,
        } };
    }

    fn collectResponse(
        self: *Source,
        response: *std.http.Client.Response,
        limit: usize,
        require_complete_body: bool,
    ) !ResponseBytes {
        const content_type = if (response.head.content_type) |value|
            try self.allocator.dupe(u8, mediaTypeBase(value))
        else
            null;
        errdefer if (content_type) |value| self.allocator.free(value);
        const content_digest = try duplicateSingleHeader(self.allocator, response.head.iterateHeaders(), "Docker-Content-Digest");
        errdefer if (content_digest) |value| self.allocator.free(value);
        const links = try duplicateHeaders(self.allocator, response.head.iterateHeaders(), "Link");
        errdefer freeHeaderValues(self.allocator, links);
        if (require_complete_body) {
            if (response.head.content_length) |length| {
                if (length > limit) return error.MetadataTooLarge;
            }
        }
        const body = try readResponseBodyAlloc(self.allocator, response, limit, false);
        errdefer self.allocator.free(body);
        if (require_complete_body) {
            if (response.head.content_length) |length| {
                if (@as(u64, @intCast(body.len)) != length) return error.EndOfStream;
            }
        }
        return .{
            .status = response.head.status,
            .body = body,
            .content_type = content_type,
            .content_digest = content_digest,
            .content_length = response.head.content_length,
            .links = links,
        };
    }

    fn establishAuthorization(self: *Source, challenges: auth.ChallengeSet, force_refresh: bool) anyerror!void {
        var basic: ?auth.Challenge = null;
        var bearer_realm: ?[]const u8 = null;
        var bearer_service: ?[]const u8 = null;
        var scopes = std.array_list.Managed([]const u8).init(self.allocator);
        defer scopes.deinit();
        for (challenges.challenges) |challenge| {
            if (challenge.isScheme("Bearer")) {
                const realm = challenge.parameter("realm") orelse return error.AuthenticationFailed;
                const service = challenge.parameter("service");
                if (bearer_realm) |previous| {
                    if (!std.mem.eql(u8, previous, realm)) return error.AuthenticationFailed;
                    if ((bearer_service == null) != (service == null)) return error.AuthenticationFailed;
                    if (bearer_service) |previous_service| {
                        if (!std.mem.eql(u8, previous_service, service.?)) return error.AuthenticationFailed;
                    }
                } else {
                    bearer_realm = realm;
                    bearer_service = service;
                }
                for (challenge.parameters) |parameter| {
                    if (std.ascii.eqlIgnoreCase(parameter.name, "scope")) try scopes.append(parameter.value);
                }
                continue;
            }
            if (challenge.isScheme("Basic") and basic == null) basic = challenge;
        }
        if (bearer_realm) |realm| {
            const realm_uri = std.Uri.parse(realm) catch return error.AuthenticationFailed;
            if (isPlainNonLoopback(realm_uri)) return error.InsecureAuthorization;
            if (force_refresh) self.token_cache.clear();
            var token_value = self.token_cache.get(self.io, realm, bearer_service, scopes.items);
            if (token_value == null) {
                const token_url = auth.buildBearerTokenUrlAlloc(self.allocator, realm, bearer_service, scopes.items) catch return error.AuthenticationFailed;
                defer self.allocator.free(token_url);
                var basic_header: ?[]u8 = null;
                defer if (basic_header) |value| {
                    std.crypto.secureZero(u8, value);
                    self.allocator.free(value);
                };
                if (try self.credentialForAuth()) |credential| {
                    basic_header = try auth.basicAuthorizationAlloc(self.allocator, credential.*);
                }
                var token_response = try self.fetchBounded(.GET, token_url, .{
                    .class = .token,
                    .accept = "application/json",
                    .explicit_authorization = basic_header,
                    .limit = auth.max_token_response_size,
                });
                defer token_response.deinit(self.allocator);
                var token = auth.parseTokenResponse(self.allocator, token_response.body) catch return error.AuthenticationFailed;
                defer token.deinit(self.allocator);
                token_value = try self.token_cache.put(self.io, realm, bearer_service, scopes.items, token);
            }
            const header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{token_value.?});
            self.setAuthorization(header);
            return;
        }
        if (basic) |_| {
            const credential = (try self.credentialForAuth()) orelse return error.AuthenticationFailed;
            const header = try auth.basicAuthorizationAlloc(self.allocator, credential.*);
            self.setAuthorization(header);
            return;
        }
        return error.AuthenticationFailed;
    }

    fn handleAuthentication(
        self: *Source,
        challenges: auth.ChallengeSet,
        current_url: []const u8,
        authorization: ?[]const u8,
        authorization_stripped: bool,
        refreshed: *bool,
    ) !void {
        if (authorization_stripped) return error.AuthenticationFailed;
        const uri = std.Uri.parse(current_url) catch return error.InvalidRegistryUrl;
        if (isPlainNonLoopback(uri)) return error.InsecureAuthorization;
        if (authorization) |value| {
            if (!isBearerAuthorization(value)) return error.AuthenticationFailed;
            if (refreshed.* or challenges.first("Bearer") == null) return error.AuthenticationFailed;
            try self.establishAuthorization(challenges, true);
            refreshed.* = true;
            return;
        }
        try self.establishAuthorization(challenges, false);
    }

    /// Returns the credential to authenticate with, discovering one on first
    /// use. A credential supplied through `Options.credential` was installed at
    /// `init` with `credential_loaded` already set, so discovery is skipped
    /// entirely rather than merely overridden.
    fn credentialForAuth(self: *Source) !?*const auth.Credential {
        if (!self.credential_loaded) {
            self.credential = try auth.findCredential(
                self.io,
                self.allocator,
                self.environ,
                self.authority,
                self.repository,
                .{
                    .authfile = self.authfile,
                    .process_runner = self.process_runner,
                },
            );
            self.credential_loaded = true;
        }
        return if (self.credential) |*value| value else null;
    }

    fn setAuthorization(self: *Source, value: []u8) void {
        if (self.authorization) |old| {
            std.crypto.secureZero(u8, old);
            self.allocator.free(old);
        }
        self.authorization = value;
    }

    fn sleepForRetry(self: *Source, retry_after: ?u64, retry_index: u8) !void {
        const backoff = @min(@as(u64, 1) << @intCast(retry_index), max_retry_delay_seconds);
        const seconds = @min(retry_after orelse backoff, max_retry_delay_seconds);
        if (self.sleep_callback) |callback| {
            try callback.call(callback.context, self.io, seconds);
        } else {
            try self.io.sleep(Io.Duration.fromSeconds(@intCast(seconds)), .real);
        }
    }

    fn openTemporaryDirectory(self: *Source) !Io.Dir {
        if (@import("builtin").os.tag == .windows) {
            if (try self.openEnvironmentDirectory("TEMP")) |dir| return dir;
            if (try self.openEnvironmentDirectory("TMP")) |dir| return dir;
            return Io.Dir.cwd().openDir(self.io, ".", .{});
        }
        if (try self.openEnvironmentDirectory("XDG_RUNTIME_DIR")) |dir| return dir;
        if (try self.openEnvironmentDirectory("TMPDIR")) |dir| return dir;
        return Io.Dir.cwd().openDir(self.io, "/tmp", .{});
    }

    fn openEnvironmentDirectory(self: *Source, name: []const u8) !?Io.Dir {
        const path = std.process.Environ.getAlloc(self.environ, self.allocator, name) catch |err| switch (err) {
            error.EnvironmentVariableMissing => return null,
            else => return err,
        };
        defer self.allocator.free(path);
        if (path.len == 0) return null;
        return try Io.Dir.cwd().openDir(self.io, path, .{});
    }

    fn streamBlob(
        self: *Source,
        initial_url: []const u8,
        descriptor: model.Descriptor,
        destination: ?Io.File,
        allow_cross_origin: bool,
    ) !void {
        var current_url = try self.allocator.dupe(u8, initial_url);
        defer self.allocator.free(current_url);
        var redirects: u8 = 0;
        var retries: u8 = 0;
        var refreshed = false;
        var authorization_stripped = false;

        while (true) {
            if (destination) |file| try file.setLength(self.io, 0);
            const authorization = if (!authorization_stripped) self.authorization else null;
            var result = try self.streamBlobAttempt(
                current_url,
                descriptor,
                destination,
                authorization,
                authorization_stripped,
            );
            switch (result) {
                .success => return,
                .transport_failure => {
                    if (retries + 1 >= max_attempts) return error.HttpRequestFailed;
                    try self.sleepForRetry(null, retries);
                    retries += 1;
                },
                .retry => |after| {
                    if (retries + 1 >= max_attempts) return error.RegistryRequestFailed;
                    try self.sleepForRetry(after, retries);
                    retries += 1;
                },
                .authenticate => |*challenges| {
                    defer challenges.deinit();
                    try self.handleAuthentication(
                        challenges.*,
                        current_url,
                        authorization,
                        authorization_stripped,
                        &refreshed,
                    );
                },
                .redirect => |location| {
                    defer self.allocator.free(location);
                    if (redirects >= max_redirects) return error.RedirectLimitExceeded;
                    const next_url = resolveUrlAlloc(self.allocator, current_url, location) catch return error.InvalidRedirect;
                    const current_uri = std.Uri.parse(current_url) catch {
                        self.allocator.free(next_url);
                        return error.InvalidRegistryUrl;
                    };
                    const next_uri = std.Uri.parse(next_url) catch {
                        self.allocator.free(next_url);
                        return error.InvalidRedirect;
                    };
                    if (std.ascii.eqlIgnoreCase(current_uri.scheme, "https") and
                        std.ascii.eqlIgnoreCase(next_uri.scheme, "http"))
                    {
                        self.allocator.free(next_url);
                        return error.HttpsDowngrade;
                    }
                    if (!sameOriginUrl(current_url, next_url)) {
                        if (!allow_cross_origin) {
                            self.allocator.free(next_url);
                            return error.CrossOriginRedirect;
                        }
                        authorization_stripped = true;
                    }
                    self.allocator.free(current_url);
                    current_url = next_url;
                    redirects += 1;
                },
            }
        }
    }

    fn streamBlobAttempt(
        self: *Source,
        url: []const u8,
        descriptor: model.Descriptor,
        destination: ?Io.File,
        authorization: ?[]const u8,
        authorization_stripped: bool,
    ) !BlobAttempt {
        const uri = std.Uri.parse(url) catch return error.InvalidRegistryUrl;
        if (uri.user != null or uri.password != null) return error.InvalidRedirect;
        if (authorization != null and isPlainNonLoopback(uri)) return error.InsecureAuthorization;
        var headers: [1]std.http.Header = undefined;
        const extra_headers: []const std.http.Header = if (authorization) |value| blk: {
            headers[0] = .{ .name = "Authorization", .value = value };
            break :blk &headers;
        } else &.{};
        var request = self.client.request(.GET, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{ .accept_encoding = .{ .override = "identity" } },
            .extra_headers = extra_headers,
        }) catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return error.HttpRequestFailed;
        };
        defer request.deinit();
        request.sendBodiless() catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return error.HttpRequestFailed;
        };
        var response = request.receiveHead(&.{}) catch |err| {
            if (isRetryableTransportError(err)) return .transport_failure;
            return error.HttpRequestFailed;
        };
        if (response.head.content_encoding != .identity) return error.InvalidResponseContentEncoding;
        if (response.head.status.class() == .redirect) {
            const location = response.head.location orelse return error.InvalidRedirect;
            if (location.len == 0 or location.len > max_location_size) return error.InvalidRedirect;
            const copy_location = try self.allocator.dupe(u8, location);
            errdefer self.allocator.free(copy_location);
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return .{ .redirect = copy_location };
        }
        if (response.head.status == .unauthorized) {
            if (authorization_stripped) return error.AuthenticationFailed;
            var values: [auth.max_challenges][]const u8 = undefined;
            var count: usize = 0;
            var headers_it = response.head.iterateHeaders();
            while (headers_it.next()) |header| {
                if (!std.ascii.eqlIgnoreCase(header.name, "WWW-Authenticate")) continue;
                if (count == values.len) return error.AuthenticationFailed;
                values[count] = header.value;
                count += 1;
            }
            if (count == 0) return error.AuthenticationFailed;
            var challenges = try auth.parseChallenges(self.allocator, values[0..count]);
            errdefer challenges.deinit();
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return .{ .authenticate = challenges };
        }
        if (isRetryableStatus(response.head.status)) {
            const retry_after = retryAfterSeconds(response.head.iterateHeaders(), Io.Clock.real.now(self.io).toSeconds());
            discardResponse(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            return .{ .retry = retry_after };
        }
        if (!isSuccess(response.head.status)) {
            self.setStatusError(&response) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return err;
            };
            return error.RegistryRequestFailed;
        }
        if (response.head.content_length) |length| {
            if (length != descriptor.size) return error.InvalidResponseContentLength;
        }
        if (try duplicateSingleHeader(self.allocator, response.head.iterateHeaders(), "Docker-Content-Digest")) |header_digest| {
            defer self.allocator.free(header_digest);
            const expected = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
            const actual = content.Digest.parse(header_digest) catch return error.InvalidContentDigest;
            if (!std.mem.eql(u8, &expected.bytes, &actual.bytes)) return error.InvalidContentDigest;
        }
        const expected = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
        var verifier = content.Verifier.init(expected, descriptor.size);
        var response_buffer: [16 * 1024]u8 = undefined;
        var transfer_buffer: [transfer_buffer_size]u8 = undefined;
        const reader = response.reader(&response_buffer);
        var offset: u64 = 0;
        while (true) {
            const count = reader.readSliceShort(&transfer_buffer) catch |err| {
                if (isRetryableTransportError(err)) return .transport_failure;
                return error.HttpRequestFailed;
            };
            if (count == 0) break;
            verifier.update(transfer_buffer[0..count]) catch return error.BlobVerificationFailed;
            if (destination) |file| {
                file.writePositionalAll(self.io, transfer_buffer[0..count], offset) catch return error.HttpRequestFailed;
            }
            offset += count;
        }
        if (response.head.content_length) |length| {
            if (offset != length) return .transport_failure;
        }
        verifier.finish() catch return error.BlobVerificationFailed;
        return .success;
    }

    fn setStatusError(self: *Source, response: *std.http.Client.Response) !void {
        const body = try readResponseBodyAlloc(self.allocator, response, error_body_limit, true);
        defer self.allocator.free(body);
        if (self.last_error) |*value| value.deinit(self.allocator);
        self.last_error = .{ .status = @intFromEnum(response.head.status) };
        if (body.len == 0) return;
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, body, .{}) catch return;
        defer parsed.deinit();
        const root = switch (parsed.value) {
            .object => |value| value,
            else => return,
        };
        const errors = root.get("errors") orelse return;
        if (errors != .array or errors.array.items.len == 0) return;
        const first = switch (errors.array.items[0]) {
            .object => |value| value,
            else => return,
        };
        if (first.get("code")) |value| {
            if (value == .string) self.last_error.?.code = try duplicateBounded(self.allocator, value.string, 4096);
        }
        if (first.get("detail")) |value| {
            if (value == .string) self.last_error.?.detail = try duplicateBounded(self.allocator, value.string, 4096);
        }
    }

    fn appendTags(
        self: *Source,
        bytes: []const u8,
        tags: *std.array_list.Managed([]u8),
        seen: *std.StringHashMap(void),
    ) !void {
        const Document = struct {
            name: []const u8,
            tags: ?[]const []const u8 = null,
        };
        var parsed = std.json.parseFromSlice(Document, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidTagList;
        defer parsed.deinit();
        if (!std.mem.eql(u8, parsed.value.name, self.repository)) return error.InvalidTagList;
        for (parsed.value.tags orelse &.{}) |tag| {
            if (!validTag(tag)) return error.InvalidTagList;
            if (seen.contains(tag)) continue;
            const copy_tag = try self.allocator.dupe(u8, tag);
            errdefer self.allocator.free(copy_tag);
            try seen.put(copy_tag, {});
            try tags.append(copy_tag);
        }
    }
};

/// Inspects an already-resolved root through either a registry or local-layout
/// source while returning the same owned, JSON-ready result.
pub fn inspectResolved(
    allocator: Allocator,
    source: transport.Source,
    original_reference: []const u8,
    descriptor: model.Descriptor,
    options: InspectOptions,
) !InspectResult {
    const original = try allocator.dupe(u8, original_reference);
    errdefer allocator.free(original);
    var inspector = Inspector{ .allocator = allocator, .source = source };
    var active = std.StringHashMap(void).init(allocator);
    defer active.deinit();
    const root = switch (options.mode) {
        .all => try inspector.inspectAll(descriptor, 0, options.max_depth, &active),
        .selected => |platform| try inspector.inspectSelected(
            descriptor,
            platform,
            0,
            options.max_depth,
            true,
            &active,
        ),
    };
    return .{ .allocator = allocator, .reference = original, .root = root };
}

const Inspector = struct {
    allocator: Allocator,
    source: transport.Source,

    fn inspectAll(
        self: *Inspector,
        descriptor: model.Descriptor,
        depth: usize,
        max_depth: usize,
        active: *std.StringHashMap(void),
    ) !InspectNode {
        if (depth > max_depth) return error.MaximumDepthExceeded;
        if (active.contains(descriptor.digest)) return error.CycleDetected;
        try active.put(descriptor.digest, {});
        defer _ = active.remove(descriptor.digest);
        const bytes = try self.source.readMetadata(descriptor);
        defer self.allocator.free(bytes);
        return self.inspectDocument(descriptor, bytes, depth, max_depth, active, true);
    }

    fn inspectSelected(
        self: *Inspector,
        descriptor: model.Descriptor,
        requested: model.Platform,
        depth: usize,
        max_depth: usize,
        allow_unannotated: bool,
        active: *std.StringHashMap(void),
    ) anyerror!InspectNode {
        if (depth > max_depth) return error.MaximumDepthExceeded;
        const class = model.classifyMediaType(descriptor.mediaType);
        if (class.isManifest()) {
            if (descriptor.platform == null and !allow_unannotated) return error.PlatformNotFound;
            var inspected = try self.inspectAll(descriptor, depth, max_depth, active);
            errdefer inspected.deinit(self.allocator);
            const resolved = inspected.descriptor.platform orelse return error.InvalidManifest;
            if (!platformMatchesRequested(resolved, requested)) return error.PlatformConfigMismatch;
            return inspected;
        }
        if (!class.isIndex()) return error.UnsupportedSelectedObject;
        if (active.contains(descriptor.digest)) return error.CycleDetected;
        try active.put(descriptor.digest, {});
        defer _ = active.remove(descriptor.digest);
        const bytes = try self.source.readMetadata(descriptor);
        defer self.allocator.free(bytes);
        var parsed = std.json.parseFromSlice(
            model.Index,
            self.allocator,
            bytes,
            .{ .ignore_unknown_fields = true },
        ) catch return error.InvalidManifest;
        defer parsed.deinit();
        model.validateIndex(parsed.value) catch return error.InvalidManifest;
        for (parsed.value.manifests) |child| {
            const platform = child.platform orelse continue;
            if (!descriptorMayMatchRequested(platform, requested)) continue;
            if (model.classifyMediaType(child.mediaType).isIndex()) {
                return self.inspectSelected(
                    child,
                    requested,
                    depth + 1,
                    max_depth,
                    true,
                    active,
                );
            }
            if (!model.classifyMediaType(child.mediaType).isManifest()) {
                return error.UnsupportedSelectedObject;
            }
            return self.inspectSelected(
                child,
                requested,
                depth + 1,
                max_depth,
                false,
                active,
            );
        }
        if (allow_unannotated and parsed.value.manifests.len == 1) {
            const child = parsed.value.manifests[0];
            if (child.platform == null and model.classifyMediaType(child.mediaType).isManifest()) {
                return self.inspectSelected(
                    child,
                    requested,
                    depth + 1,
                    max_depth,
                    true,
                    active,
                );
            }
        }
        var fallback: ?InspectNode = null;
        errdefer if (fallback) |*value| value.deinit(self.allocator);
        for (parsed.value.manifests) |child| {
            if (child.platform != null or !model.classifyMediaType(child.mediaType).isIndex()) continue;
            var candidate = self.inspectSelected(
                child,
                requested,
                depth + 1,
                max_depth,
                false,
                active,
            ) catch |err| switch (err) {
                error.PlatformNotFound => continue,
                else => return err,
            };
            if (fallback != null) {
                candidate.deinit(self.allocator);
                return error.AmbiguousPlatform;
            }
            fallback = candidate;
        }
        return fallback orelse error.PlatformNotFound;
    }

    fn resolveConfigPlatform(
        self: *Inspector,
        config_descriptor: model.Descriptor,
    ) !Platform {
        const config_bytes = try self.source.readMetadata(config_descriptor);
        defer self.allocator.free(config_bytes);
        var parsed = std.json.parseFromSlice(
            model.ImageConfigPlatform,
            self.allocator,
            config_bytes,
            .{ .ignore_unknown_fields = true },
        ) catch return error.PlatformConfigMismatch;
        defer parsed.deinit();
        const os = parsed.value.os orelse return error.PlatformConfigMismatch;
        const architecture = parsed.value.architecture orelse
            return error.PlatformConfigMismatch;
        return ownedPlatform(self.allocator, .{
            .os = os,
            .architecture = architecture,
            .variant = parsed.value.variant,
        });
    }

    fn inspectDocument(
        self: *Inspector,
        descriptor: model.Descriptor,
        bytes: []const u8,
        depth: usize,
        max_depth: usize,
        active: *std.StringHashMap(void),
        recurse: bool,
    ) !InspectNode {
        var owned_descriptor = try ownedDescriptor(self.allocator, descriptor);
        errdefer owned_descriptor.deinit(self.allocator);
        switch (model.classifyMediaType(descriptor.mediaType)) {
            .oci_manifest, .docker_manifest => {
                var parsed = std.json.parseFromSlice(
                    model.Manifest,
                    self.allocator,
                    bytes,
                    .{ .ignore_unknown_fields = true },
                ) catch return error.InvalidManifest;
                defer parsed.deinit();
                model.validateManifest(parsed.value) catch return error.InvalidManifest;
                var resolved_platform: ?Platform = try self.resolveConfigPlatform(
                    parsed.value.config,
                );
                errdefer if (resolved_platform) |*value| value.deinit(self.allocator);
                try validateDescriptorPlatform(descriptor.platform, resolved_platform.?);
                if (owned_descriptor.platform) |*value| value.deinit(self.allocator);
                owned_descriptor.platform = resolved_platform.?;
                resolved_platform = null;
                var config = try ownedDescriptor(self.allocator, parsed.value.config);
                errdefer config.deinit(self.allocator);
                var layers = try self.allocator.alloc(Descriptor, parsed.value.layers.len);
                var count: usize = 0;
                errdefer {
                    for (layers[0..count]) |*value| value.deinit(self.allocator);
                    self.allocator.free(layers);
                }
                for (parsed.value.layers, 0..) |layer, index| {
                    layers[index] = try ownedDescriptor(self.allocator, layer);
                    count += 1;
                }
                return .{
                    .descriptor = owned_descriptor,
                    .kind = .manifest,
                    .config = config,
                    .layers = layers,
                };
            },
            .oci_index, .docker_manifest_list => {
                var parsed = std.json.parseFromSlice(
                    model.Index,
                    self.allocator,
                    bytes,
                    .{ .ignore_unknown_fields = true },
                ) catch return error.InvalidManifest;
                defer parsed.deinit();
                model.validateIndex(parsed.value) catch return error.InvalidManifest;
                var children = try self.allocator.alloc(
                    InspectNode,
                    parsed.value.manifests.len,
                );
                var count: usize = 0;
                errdefer {
                    for (children[0..count]) |*value| value.deinit(self.allocator);
                    self.allocator.free(children);
                }
                for (parsed.value.manifests, 0..) |child, index| {
                    const class = model.classifyMediaType(child.mediaType);
                    if (recurse and (class.isIndex() or class.isManifest())) {
                        children[index] = try self.inspectAll(
                            child,
                            depth + 1,
                            max_depth,
                            active,
                        );
                    } else {
                        children[index] = .{
                            .descriptor = try ownedDescriptor(self.allocator, child),
                            .kind = .@"opaque",
                        };
                    }
                    count += 1;
                }
                return .{
                    .descriptor = owned_descriptor,
                    .kind = .index,
                    .manifests = children,
                };
            },
            else => return .{
                .descriptor = owned_descriptor,
                .kind = .@"opaque",
            },
        }
    }
};

/// Writable OCI Distribution destination. It owns an independent client and
/// authorization state because pull and push challenges commonly require
/// different scopes.
pub const Destination = struct {
    remote: Source,
    selection: reference.Selection,

    pub fn init(
        io: Io,
        allocator: Allocator,
        environ: std.process.Environ,
        destination: reference.RegistryReference,
        options: Options,
    ) !Destination {
        const selection = destination.selection orelse return error.InvalidRegistryUrl;
        return .{
            .remote = try Source.init(io, allocator, environ, destination, options),
            .selection = selection,
        };
    }

    pub fn deinit(self: *Destination) void {
        self.remote.deinit();
        self.* = undefined;
    }

    pub fn lastError(self: *const Destination) ?*const StatusError {
        return self.remote.lastError();
    }

    pub fn asTransport(self: *Destination) transport.Destination {
        return .{
            .context = self,
            .prepare = prepareTransport,
            .ensure_descriptor = ensureDescriptorTransport,
            .stage_root = stageRootTransport,
            .commit = commitTransport,
            .finish = finishTransport,
        };
    }

    pub fn copyFromLayout(
        self: *Destination,
        source: reference.LayoutReference,
        options: copy.Options,
    ) !copy.Result {
        var local = layout.Source.init(self.remote.io, self.remote.allocator, source.path);
        var resolved = try local.resolve(source);
        defer resolved.deinit();
        return copy.resolvedToDestination(
            self.remote.allocator,
            local.asTransport(),
            &resolved,
            self.asTransport(),
            self.selection,
            options,
        );
    }

    fn prepareTransport(
        context: *anyopaque,
        root: model.Descriptor,
        selection: ?reference.Selection,
    ) anyerror!void {
        const self: *Destination = @ptrCast(@alignCast(context));
        const requested = selection orelse return error.InvalidRegistryUrl;
        try self.validateRoot(root, requested);
        try self.remote.ping();
    }

    fn ensureDescriptorTransport(
        context: *anyopaque,
        source: transport.Source,
        descriptor: model.Descriptor,
        role: transport.DescriptorRole,
        metadata: ?[]const u8,
        counts: *transport.Counts,
    ) anyerror!void {
        const self: *Destination = @ptrCast(@alignCast(context));
        if (role == .manifest) {
            const bytes = metadata orelse return error.InvalidManifest;
            var selector: [71]u8 = undefined;
            const digest_selector = try descriptorDigestSelector(descriptor, &selector);
            return self.publishManifest(descriptor, bytes, digest_selector, counts);
        }
        return self.ensureBlob(source, descriptor, counts);
    }

    fn commitTransport(
        context: *anyopaque,
        _: transport.Source,
        root: model.Descriptor,
        _: []const u8,
        root_bytes: []const u8,
        selection: ?reference.Selection,
        counts: *transport.Counts,
    ) anyerror!void {
        const self: *Destination = @ptrCast(@alignCast(context));
        const requested = selection orelse return error.InvalidRegistryUrl;
        try self.validateRoot(root, requested);
        var selector_buffer: [71]u8 = undefined;
        const selector = try selectionSelector(requested, &selector_buffer);
        return self.publishManifest(root, root_bytes, selector, counts);
    }

    fn stageRootTransport(
        _: *anyopaque,
        _: transport.Source,
        _: model.Descriptor,
        _: *transport.Counts,
    ) anyerror!void {}

    fn finishTransport(_: *anyopaque) anyerror!void {}

    fn validateRoot(self: *const Destination, root: model.Descriptor, requested: reference.Selection) !void {
        _ = self;
        _ = root.mediaType orelse return error.InvalidManifest;
        const root_digest = content.Digest.parse(root.digest) catch return error.DescriptorMismatch;
        switch (requested) {
            .tag => {},
            .digest => |expected| {
                if (!std.mem.eql(u8, &root_digest.bytes, &expected.bytes)) return error.DescriptorMismatch;
            },
        }
    }

    fn ensureBlob(
        self: *Destination,
        source: transport.Source,
        descriptor: model.Descriptor,
        counts: *transport.Counts,
    ) !void {
        switch (try self.remote.blobState(descriptor)) {
            .valid => {
                counts.reused += 1;
                return;
            },
            .missing => {},
        }

        var mount_session: ?UploadSession = null;
        defer if (mount_session) |*value| value.deinit(self.remote.allocator);
        if (source.registry_identity) |identity| {
            if (sameRegistry(identity, .{
                .authority = self.remote.authority,
                .repository = self.remote.repository,
                .plain_http = self.remote.plain_http,
            }) and !std.mem.eql(u8, identity.repository, self.remote.repository)) {
                switch (try self.tryMount(identity, descriptor)) {
                    .complete => {
                        counts.mounted += 1;
                        return;
                    },
                    .session => |session| mount_session = session,
                    .fallback => {},
                }
            }
        }

        var spool = try self.spoolVerified(source, descriptor);
        defer spool.deinit(self.remote.io, self.remote.allocator);

        var next_session = mount_session;
        mount_session = null;
        defer if (next_session) |*value| value.deinit(self.remote.allocator);
        var attempt: u8 = 0;
        while (attempt < max_attempts) : (attempt += 1) {
            var session = next_session orelse switch (try self.beginUpload(descriptor)) {
                .session => |value| value,
                .ambiguous => |retry_after| {
                    if (try self.remote.blobState(descriptor) == .valid) {
                        counts.transferred += 1;
                        return;
                    }
                    if (attempt + 1 >= max_attempts) return error.HttpRequestFailed;
                    try self.remote.sleepForRetry(retry_after, attempt);
                    continue;
                },
            };
            next_session = null;
            defer session.deinit(self.remote.allocator);

            switch (try self.uploadFile(&session, spool.file, descriptor)) {
                .complete => {
                    counts.transferred += 1;
                    return;
                },
                .ambiguous => |retry_after| {
                    if (try self.remote.blobState(descriptor) == .valid) {
                        counts.transferred += 1;
                        return;
                    }
                    if (attempt + 1 >= max_attempts) return error.HttpRequestFailed;
                    try self.remote.sleepForRetry(retry_after, attempt);
                },
            }
        }
        return error.HttpRequestFailed;
    }

    fn tryMount(
        self: *Destination,
        source: transport.RegistryIdentity,
        descriptor: model.Descriptor,
    ) !MountOutcome {
        const url = try self.mountUrl(descriptor, source.repository);
        defer self.remote.allocator.free(url);
        switch (try self.remote.mutate(.POST, url, .empty, false)) {
            .response => |response_value| {
                var response = response_value;
                defer response.deinit(self.remote.allocator);
                switch (response.status) {
                    .created => {
                        try validateOptionalDigest(descriptor, response.content_digest);
                        const location = response.location orelse return error.InvalidRedirect;
                        var completed = try self.resolveUploadLocation(url, location);
                        completed.deinit(self.remote.allocator);
                        if (try self.remote.blobState(descriptor) != .valid) return error.BlobVerificationFailed;
                        return .complete;
                    },
                    .accepted => {
                        const location = response.location orelse return error.InvalidRedirect;
                        const session = try self.resolveUploadLocation(url, location);
                        return .{ .session = session };
                    },
                    else => return error.RegistryRequestFailed,
                }
            },
            .transport_failure => {
                if (try self.remote.blobState(descriptor) == .valid) return .complete;
                return .fallback;
            },
            .retry => |retry_after| {
                if (try self.remote.blobState(descriptor) == .valid) return .complete;
                _ = retry_after;
                return .fallback;
            },
        }
    }

    fn spoolVerified(self: *Destination, source: transport.Source, descriptor: model.Descriptor) !SpoolFile {
        const dir = try self.remote.openTemporaryDirectory();
        errdefer dir.close(self.remote.io);
        const temporary = try createUniqueTempFile(self.remote.io, self.remote.allocator, dir, "upload");
        var spool = SpoolFile{
            .dir = dir,
            .name = temporary.name,
            .file = temporary.file,
        };
        errdefer spool.deinit(self.remote.io, self.remote.allocator);
        try source.copyVerifiedTo(descriptor, spool.file);
        try spool.file.sync(self.remote.io);
        return spool;
    }

    fn beginUpload(self: *Destination, _: model.Descriptor) !BeginUploadOutcome {
        const url = try self.uploadUrl();
        defer self.remote.allocator.free(url);
        switch (try self.remote.mutate(.POST, url, .empty, false)) {
            .response => |response_value| {
                var response = response_value;
                defer response.deinit(self.remote.allocator);
                if (response.status != .accepted) return error.RegistryRequestFailed;
                const location = response.location orelse return error.InvalidRedirect;
                return .{ .session = try self.resolveUploadLocation(url, location) };
            },
            .transport_failure => return .{ .ambiguous = null },
            .retry => |retry_after| return .{ .ambiguous = retry_after },
        }
    }

    fn uploadFile(
        self: *Destination,
        session: *const UploadSession,
        spool_file: Io.File,
        descriptor: model.Descriptor,
    ) !UploadOutcome {
        const url = try appendDigestQueryAlloc(self.remote.allocator, session.url, descriptor.digest);
        defer self.remote.allocator.free(url);
        switch (try self.remote.mutate(.PUT, url, .{
            .file = .{
                .file = spool_file,
                .descriptor = descriptor,
                .content_type = "application/octet-stream",
            },
        }, session.authorization_stripped)) {
            .response => |response_value| {
                var response = response_value;
                defer response.deinit(self.remote.allocator);
                if (response.status != .created) return error.RegistryRequestFailed;
                try validateOptionalDigest(descriptor, response.content_digest);
                const location = response.location orelse return error.InvalidRedirect;
                var completed = try self.resolveUploadLocation(url, location);
                completed.deinit(self.remote.allocator);
                if (try self.remote.blobState(descriptor) != .valid) return error.BlobVerificationFailed;
                return .complete;
            },
            .transport_failure => return .{ .ambiguous = null },
            .retry => |retry_after| return .{ .ambiguous = retry_after },
        }
    }

    fn publishManifest(
        self: *Destination,
        descriptor: model.Descriptor,
        bytes: []const u8,
        selector: []const u8,
        counts: *transport.Counts,
    ) !void {
        const expected = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
        content.verifyBytes(expected, descriptor.size, bytes) catch return error.DescriptorMismatch;
        const media_type = descriptor.mediaType orelse return error.InvalidManifest;
        model.validateMediaType(media_type) catch return error.InvalidManifest;
        const url = try self.remote.manifestUrl(selector);
        defer self.remote.allocator.free(url);
        switch (try self.remote.mutate(.PUT, url, .{
            .bytes = .{ .bytes = bytes, .content_type = media_type },
        }, false)) {
            .response => |response_value| {
                var response = response_value;
                defer response.deinit(self.remote.allocator);
                if (response.status != .created) return error.RegistryRequestFailed;
                try validateOptionalDigest(descriptor, response.content_digest);
                try self.remote.confirmManifest(selector, descriptor);
                counts.transferred += 1;
            },
            .transport_failure => {
                try self.remote.confirmManifest(selector, descriptor);
                counts.transferred += 1;
            },
            .retry => {
                try self.remote.confirmManifest(selector, descriptor);
                counts.transferred += 1;
            },
        }
    }

    fn uploadUrl(self: *const Destination) ![]u8 {
        return std.fmt.allocPrint(
            self.remote.allocator,
            "{s}://{s}/v2/{s}/blobs/uploads/",
            .{
                if (self.remote.plain_http) "http" else "https",
                self.remote.authority,
                self.remote.repository,
            },
        );
    }

    fn mountUrl(self: *const Destination, descriptor: model.Descriptor, source_repository: []const u8) ![]u8 {
        const digest = try percentEncodeAlloc(self.remote.allocator, descriptor.digest);
        defer self.remote.allocator.free(digest);
        const source = try percentEncodeAlloc(self.remote.allocator, source_repository);
        defer self.remote.allocator.free(source);
        return std.fmt.allocPrint(
            self.remote.allocator,
            "{s}://{s}/v2/{s}/blobs/uploads/?mount={s}&from={s}",
            .{
                if (self.remote.plain_http) "http" else "https",
                self.remote.authority,
                self.remote.repository,
                digest,
                source,
            },
        );
    }

    fn resolveUploadLocation(self: *Destination, base: []const u8, location: []const u8) !UploadSession {
        const url = if (hasUriScheme(location))
            try duplicateAbsoluteUploadLocation(self.remote.allocator, location)
        else
            try resolveUrlAlloc(self.remote.allocator, base, location);
        errdefer self.remote.allocator.free(url);
        const uri = std.Uri.parse(url) catch return error.InvalidRedirect;
        if (uri.user != null or uri.password != null or uri.fragment != null) return error.InvalidRedirect;
        const cross_origin = !sameOriginUrl(base, url);
        if (cross_origin) {
            if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.HttpsDowngrade;
        }
        return .{ .url = url, .authorization_stripped = cross_origin };
    }
};

/// Convenience high-level API for layout-to-registry publication.
pub fn copyLayoutToRegistry(
    io: Io,
    allocator: Allocator,
    environ: std.process.Environ,
    source: reference.LayoutReference,
    destination: reference.RegistryReference,
    destination_options: Options,
    options: copy.Options,
) !copy.Result {
    var target = try Destination.init(io, allocator, environ, destination, destination_options);
    defer target.deinit();
    return target.copyFromLayout(source, options);
}

/// Convenience high-level API for pinning a registry reference to a digest.
/// The reference text is parsed in `.source` mode, so a selection is required
/// and a bare repository is refused.
pub fn pinReference(
    io: Io,
    allocator: Allocator,
    environ: std.process.Environ,
    reference_text: []const u8,
    options: Options,
) !Pin {
    const parsed = try reference.parse(reference_text, .source);
    const source = switch (parsed) {
        .registry => |value| value,
        .layout => return error.InvalidRegistryUrl,
    };
    var client = try Source.init(io, allocator, environ, source, options);
    defer client.deinit();
    return client.pin(source);
}

const manifest_accept =
    model.media_type_oci_manifest ++ ", " ++
    model.media_type_oci_index ++ ", " ++
    model.media_type_docker_manifest ++ ", " ++
    model.media_type_docker_manifest_list;

const RequestClass = enum { registry, blob, token };

const BlobState = enum { missing, valid };

const RequestSpec = struct {
    class: RequestClass,
    accept: ?[]const u8 = null,
    explicit_authorization: ?[]const u8 = null,
    limit: usize,
    /// Read operations normally require 200. Blob existence checks opt into
    /// 404 so absence is not conflated with a structured registry failure.
    accepted_statuses: ?[]const std.http.Status = null,
};

const MutationBody = union(enum) {
    empty,
    bytes: struct {
        bytes: []const u8,
        content_type: []const u8,
    },
    file: struct {
        file: Io.File,
        descriptor: model.Descriptor,
        content_type: []const u8,
    },

    fn contentType(self: MutationBody) []const u8 {
        return switch (self) {
            .empty => "application/octet-stream",
            .bytes => |value| value.content_type,
            .file => |value| value.content_type,
        };
    }
};

const MutationResponse = struct {
    status: std.http.Status,
    content_digest: ?[]u8 = null,
    location: ?[]u8 = null,

    fn deinit(self: *MutationResponse, allocator: Allocator) void {
        if (self.content_digest) |value| allocator.free(value);
        if (self.location) |value| allocator.free(value);
        self.* = undefined;
    }
};

const MutationAttempt = union(enum) {
    response: MutationResponse,
    authenticate: auth.ChallengeSet,
    retry: ?u64,
    transport_failure,
};

const MutationOutcome = union(enum) {
    response: MutationResponse,
    retry: ?u64,
    transport_failure,
};

const UploadSession = struct {
    url: []u8,
    authorization_stripped: bool,

    fn deinit(self: *UploadSession, allocator: Allocator) void {
        allocator.free(self.url);
        self.* = undefined;
    }
};

const MountOutcome = union(enum) {
    complete,
    session: UploadSession,
    fallback,
};

const BeginUploadOutcome = union(enum) {
    session: UploadSession,
    ambiguous: ?u64,
};

const UploadOutcome = union(enum) {
    complete,
    ambiguous: ?u64,
};

const TempFile = struct {
    name: []u8,
    file: Io.File,
};

const SpoolFile = struct {
    dir: Io.Dir,
    name: []u8,
    file: Io.File,

    fn deinit(self: *SpoolFile, io: Io, allocator: Allocator) void {
        self.file.close(io);
        self.dir.deleteFile(io, self.name) catch {};
        self.dir.close(io);
        allocator.free(self.name);
        self.* = undefined;
    }
};

const ResponseBytes = struct {
    status: std.http.Status,
    body: []u8,
    content_type: ?[]u8 = null,
    content_digest: ?[]u8 = null,
    content_length: ?u64 = null,
    links: [][]u8 = &.{},

    fn deinit(self: *ResponseBytes, allocator: Allocator) void {
        allocator.free(self.body);
        if (self.content_type) |value| allocator.free(value);
        if (self.content_digest) |value| allocator.free(value);
        for (self.links) |value| allocator.free(value);
        if (self.links.len != 0) allocator.free(self.links);
        self.* = undefined;
    }

    fn takeBody(self: *ResponseBytes) []u8 {
        const result = self.body;
        self.body = &.{};
        return result;
    }
};

const Attempt = union(enum) {
    response: ResponseBytes,
    redirect: []u8,
    authenticate: auth.ChallengeSet,
    retry: ?u64,
    transport_failure,
};

const BlobAttempt = union(enum) {
    success,
    redirect: []u8,
    authenticate: auth.ChallengeSet,
    retry: ?u64,
    transport_failure,
};

fn readMetadataTransport(context: *anyopaque, descriptor: model.Descriptor) anyerror![]u8 {
    const self: *Source = @ptrCast(@alignCast(context));
    return self.readMetadata(descriptor);
}

fn readManifestMetadataTransport(context: *anyopaque, descriptor: model.Descriptor) anyerror![]u8 {
    const self: *Source = @ptrCast(@alignCast(context));
    return self.readManifestMetadata(descriptor);
}

fn copyVerifiedToTransport(context: *anyopaque, descriptor: model.Descriptor, destination: Io.File) anyerror!void {
    const self: *Source = @ptrCast(@alignCast(context));
    return self.copyVerifiedTo(descriptor, destination);
}

fn verifyManifestResponse(
    selection: reference.Selection,
    bytes: []const u8,
    content_digest: ?[]const u8,
) !void {
    const actual = content.digestBytes(bytes);
    switch (selection) {
        .tag => {},
        .digest => |expected| {
            if (!std.mem.eql(u8, &expected.bytes, &actual.bytes)) return error.DescriptorMismatch;
        },
    }
    if (content_digest) |header| {
        const value = content.Digest.parse(header) catch return error.InvalidContentDigest;
        if (!std.mem.eql(u8, &value.bytes, &actual.bytes)) return error.InvalidContentDigest;
    }
}

fn verifyDescriptorBytes(descriptor: model.Descriptor, bytes: []const u8, content_digest: ?[]const u8) !void {
    const expected = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
    content.verifyBytes(expected, descriptor.size, bytes) catch return error.DescriptorMismatch;
    if (content_digest) |header| {
        const actual = content.Digest.parse(header) catch return error.InvalidContentDigest;
        if (!std.mem.eql(u8, &expected.bytes, &actual.bytes)) return error.InvalidContentDigest;
    }
}

fn validateDocument(
    allocator: Allocator,
    descriptor: model.Descriptor,
    bytes: []const u8,
    response_media_type: []const u8,
) !void {
    const response_class = model.classifyMediaType(response_media_type);
    if (!response_class.isManifest() and !response_class.isIndex()) return error.InvalidManifest;
    if (descriptor.mediaType) |expected| {
        if (!std.mem.eql(u8, expected, response_media_type)) return error.InvalidManifest;
    }
    switch (model.classifyMediaType(descriptor.mediaType)) {
        .oci_index, .docker_manifest_list => {
            var parsed = std.json.parseFromSlice(model.Index, allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidManifest;
            defer parsed.deinit();
            model.validateIndex(parsed.value) catch return error.InvalidManifest;
            if (parsed.value.mediaType) |document_media_type| {
                if (!std.mem.eql(u8, document_media_type, response_media_type)) return error.InvalidManifest;
            }
        },
        .oci_manifest, .docker_manifest => {
            var parsed = std.json.parseFromSlice(model.Manifest, allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidManifest;
            defer parsed.deinit();
            model.validateManifest(parsed.value) catch return error.InvalidManifest;
            if (parsed.value.mediaType) |document_media_type| {
                if (!std.mem.eql(u8, document_media_type, response_media_type)) return error.InvalidManifest;
            }
        },
        else => return error.InvalidManifest,
    }
}

fn isSuccess(status: std.http.Status) bool {
    return status == .ok;
}

fn acceptsStatus(spec: RequestSpec, status: std.http.Status) bool {
    if (spec.accepted_statuses) |statuses| {
        for (statuses) |accepted| {
            if (status == accepted) return true;
        }
        return false;
    }
    return isSuccess(status);
}

fn isRetryableStatus(status: std.http.Status) bool {
    return switch (@intFromEnum(status)) {
        408, 429, 500, 502, 503, 504 => true,
        else => false,
    };
}

fn isRetryableTransportError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.BrokenPipe,
        error.ReadFailed,
        error.WriteFailed,
        error.EndOfStream,
        error.HttpConnectionClosing,
        error.HttpChunkTruncated,
        error.Timeout,
        => true,
        else => false,
    };
}

/// Whether the response to this request can carry a body at all.
///
/// `std.http.Client.Response.reader` hands back the shared `Io.Reader.ending`
/// sentinel for methods whose responses never have one. That sentinel is a
/// `const` the standard library `@constCast`s, so reading from it writes the
/// seek position into constant memory: on targets where the relocated
/// read-only data really is mapped read-only, a HEAD response is a segfault,
/// and elsewhere it silently scribbles on a global shared by every caller.
/// A HEAD response has no body to read either way, so never touch the reader.
fn responseCanHaveBody(response: *const std.http.Client.Response) bool {
    return response.request.method.responseHasBody();
}

fn discardResponse(response: *std.http.Client.Response) !void {
    if (!responseCanHaveBody(response)) return;
    var buffer: [8192]u8 = undefined;
    const reader = response.reader(&buffer);
    var discarded: usize = 0;
    while (discarded < error_body_limit) {
        const count = try reader.readSliceShort(buffer[0..@min(buffer.len, error_body_limit - discarded)]);
        if (count == 0) return;
        discarded += count;
    }
}

fn readResponseBodyAlloc(
    allocator: Allocator,
    response: *std.http.Client.Response,
    limit: usize,
    truncate: bool,
) ![]u8 {
    if (!responseCanHaveBody(response)) return allocator.alloc(u8, 0);
    var response_buffer: [16 * 1024]u8 = undefined;
    var transfer_buffer: [16 * 1024]u8 = undefined;
    const reader = response.reader(&response_buffer);
    var result = std.array_list.Managed(u8).init(allocator);
    errdefer result.deinit();
    while (true) {
        if (truncate and result.items.len == limit) break;
        const count = reader.readSliceShort(&transfer_buffer) catch |err| return err;
        if (count == 0) break;
        if (result.items.len + count > limit) {
            if (!truncate) return error.MetadataTooLarge;
            const available = limit - result.items.len;
            if (available != 0) try result.appendSlice(transfer_buffer[0..available]);
            break;
        }
        try result.appendSlice(transfer_buffer[0..count]);
    }
    return result.toOwnedSlice();
}

fn isBearerAuthorization(value: []const u8) bool {
    return std.mem.startsWith(u8, value, "Bearer ");
}

fn duplicateSingleHeader(
    allocator: Allocator,
    headers: std.http.HeaderIterator,
    name: []const u8,
) !?[]u8 {
    var iterator = headers;
    var result: ?[]u8 = null;
    errdefer if (result) |value| allocator.free(value);
    while (iterator.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        if (result != null) return error.InvalidResponseContentLength;
        result = try allocator.dupe(u8, header.value);
    }
    return result;
}

fn duplicateHeaders(
    allocator: Allocator,
    headers: std.http.HeaderIterator,
    name: []const u8,
) ![][]u8 {
    var values = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (values.items) |value| allocator.free(value);
        values.deinit();
    }
    var iterator = headers;
    while (iterator.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        try values.append(try allocator.dupe(u8, header.value));
    }
    return values.toOwnedSlice();
}

fn freeHeaderValues(allocator: Allocator, values: [][]u8) void {
    for (values) |value| allocator.free(value);
    if (values.len != 0) allocator.free(values);
}

fn duplicateBounded(allocator: Allocator, value: []const u8, limit: usize) ![]u8 {
    return allocator.dupe(u8, value[0..@min(value.len, limit)]);
}

fn mediaTypeBase(value: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, value, ';') orelse value.len;
    return std.mem.trim(u8, value[0..end], " \t");
}

fn retryAfterSeconds(headers: std.http.HeaderIterator, now: i64) ?u64 {
    var iterator = headers;
    while (iterator.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "Retry-After")) continue;
        const value = std.mem.trim(u8, header.value, " \t");
        if (std.fmt.parseInt(u64, value, 10)) |seconds| {
            return @min(seconds, max_retry_delay_seconds);
        } else |_| {}
        if (parseHttpDate(value)) |timestamp| {
            if (timestamp <= now) return 0;
            return @min(@as(u64, @intCast(timestamp - now)), max_retry_delay_seconds);
        }
    }
    return null;
}

/// Parses the IMF-fixdate form required for HTTP dates. RFC 850 and asctime
/// variants are intentionally not accepted because retry behavior remains
/// safely bounded when an obsolete date is ignored.
fn parseHttpDate(value: []const u8) ?i64 {
    if (value.len != 29 or value[3] != ',' or value[4] != ' ' or value[7] != ' ' or
        value[11] != ' ' or value[16] != ' ' or value[19] != ':' or value[22] != ':' or
        !std.mem.eql(u8, value[26..], "GMT"))
    {
        return null;
    }
    const day = parseTwo(value[5..7]) orelse return null;
    const month = monthNumber(value[8..11]) orelse return null;
    const year = std.fmt.parseInt(i64, value[12..16], 10) catch return null;
    const hour = parseTwo(value[17..19]) orelse return null;
    const minute = parseTwo(value[20..22]) orelse return null;
    const second = parseTwo(value[23..25]) orelse return null;
    if (day == 0 or day > daysInMonth(year, month) or hour > 23 or minute > 59 or second > 59) return null;
    const days = daysFromCivil(year, month, day);
    return days * 86_400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

fn parseTwo(value: []const u8) ?u8 {
    if (value.len != 2 or !std.ascii.isDigit(value[0]) or !std.ascii.isDigit(value[1])) return null;
    return (value[0] - '0') * 10 + (value[1] - '0');
}

fn monthNumber(value: []const u8) ?u8 {
    const names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    for (names, 1..) |name, index| {
        if (std.mem.eql(u8, value, name)) return @intCast(index);
    }
    return null;
}

fn daysInMonth(year: i64, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: i64) bool {
    return @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
}

/// Days since 1970-01-01; Howard Hinnant's civil-date conversion.
fn daysFromCivil(year_input: i64, month_input: u8, day: u8) i64 {
    var year = year_input;
    const month: i64 = month_input;
    year -= @intFromBool(month <= 2);
    const era = @divFloor(year, 400);
    const yoe = year - era * 400;
    const adjusted_month: i64 = if (month > 2) -3 else 9;
    const doy = @divFloor(153 * (month + adjusted_month) + 2, 5) + @as(i64, day) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn resolveUrlAlloc(allocator: Allocator, base_text: []const u8, location: []const u8) ![]u8 {
    if (location.len == 0 or location.len > max_location_size or std.mem.indexOfAny(u8, location, "\r\n") != null) return error.InvalidRedirect;
    if (hasUriScheme(location)) _ = std.Uri.parse(location) catch return error.InvalidRedirect;
    const base = std.Uri.parse(base_text) catch return error.InvalidRedirect;
    if (base.user != null or base.password != null or base.fragment != null) return error.InvalidRedirect;
    const required = std.math.add(usize, base_text.len, location.len) catch return error.InvalidRedirect;
    const storage = try allocator.alloc(u8, std.math.add(usize, required, 1) catch return error.InvalidRedirect);
    defer allocator.free(storage);
    @memcpy(storage[0..location.len], location);
    var aux = storage;
    const resolved = base.resolveInPlace(location.len, &aux) catch return error.InvalidRedirect;
    if (resolved.user != null or resolved.password != null or resolved.fragment != null or resolved.host == null) {
        return error.InvalidRedirect;
    }
    if (!std.ascii.eqlIgnoreCase(resolved.scheme, "http") and !std.ascii.eqlIgnoreCase(resolved.scheme, "https")) {
        return error.InvalidRedirect;
    }
    var text = std.Io.Writer.Allocating.init(allocator);
    defer text.deinit();
    resolved.format(&text.writer) catch return error.InvalidRedirect;
    const result = try text.toOwnedSlice();
    errdefer allocator.free(result);
    if (result.len == 0 or result.len > max_location_size) return error.InvalidRedirect;
    const validated = std.Uri.parse(result) catch return error.InvalidRedirect;
    if (validated.user != null or validated.password != null or validated.fragment != null or validated.host == null) {
        return error.InvalidRedirect;
    }
    if (!std.ascii.eqlIgnoreCase(validated.scheme, "http") and !std.ascii.eqlIgnoreCase(validated.scheme, "https")) {
        return error.InvalidRedirect;
    }
    return result;
}

/// Absolute upload locations carry provider-signed queries. Validate them
/// without formatting the URI again so every query byte and parameter order
/// remains exactly as supplied by the registry.
fn duplicateAbsoluteUploadLocation(allocator: Allocator, location: []const u8) ![]u8 {
    if (location.len == 0 or location.len > max_location_size or
        std.mem.indexOfAny(u8, location, "\r\n") != null)
    {
        return error.InvalidRedirect;
    }
    const uri = std.Uri.parse(location) catch return error.InvalidRedirect;
    if (uri.user != null or uri.password != null or uri.fragment != null or uri.host == null) {
        return error.InvalidRedirect;
    }
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and !std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
        return error.InvalidRedirect;
    }
    return allocator.dupe(u8, location);
}

fn hasUriScheme(value: []const u8) bool {
    if (value.len == 0 or !std.ascii.isAlphabetic(value[0])) return false;
    for (value[1..]) |byte| {
        if (byte == ':') return true;
        if (!std.ascii.isAlphanumeric(byte) and byte != '+' and byte != '-' and byte != '.') {
            return false;
        }
    }
    return false;
}

fn sameOriginUrl(left_text: []const u8, right_text: []const u8) bool {
    const left = std.Uri.parse(left_text) catch return false;
    const right = std.Uri.parse(right_text) catch return false;
    if (!std.ascii.eqlIgnoreCase(left.scheme, right.scheme)) return false;
    var left_host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    var right_host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const left_host = left.getHost(&left_host_buffer) catch return false;
    const right_host = right.getHost(&right_host_buffer) catch return false;
    if (!std.ascii.eqlIgnoreCase(left_host.bytes, right_host.bytes)) return false;
    return uriPort(left) == uriPort(right);
}

fn sameRegistry(left: transport.RegistryIdentity, right: transport.RegistryIdentity) bool {
    return left.plain_http == right.plain_http and
        sameNormalizedAuthority(left.authority, right.authority, left.plain_http);
}

fn sameNormalizedAuthority(left: []const u8, right: []const u8, plain_http: bool) bool {
    const default_port: u16 = if (plain_http) 80 else 443;
    const left_parts = splitAuthority(left, default_port) orelse return false;
    const right_parts = splitAuthority(right, default_port) orelse return false;
    return left_parts.port == right_parts.port and
        std.ascii.eqlIgnoreCase(left_parts.host, right_parts.host);
}

const AuthorityParts = struct {
    host: []const u8,
    port: u16,
};

fn splitAuthority(authority: []const u8, default_port: u16) ?AuthorityParts {
    if (authority.len == 0) return null;
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return null;
        const host = authority[0 .. close + 1];
        if (close + 1 == authority.len) return .{ .host = host, .port = default_port };
        if (authority[close + 1] != ':') return null;
        const port = std.fmt.parseInt(u16, authority[close + 2 ..], 10) catch return null;
        return .{ .host = host, .port = port };
    }
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse
        return .{ .host = authority, .port = default_port };
    const port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return null;
    return .{ .host = authority[0..colon], .port = port };
}

fn descriptorDigestSelector(descriptor: model.Descriptor, buffer: *[71]u8) ![]const u8 {
    const digest = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
    buffer.* = digest.format();
    return buffer;
}

fn selectionSelector(selection: reference.Selection, buffer: *[71]u8) ![]const u8 {
    return switch (selection) {
        .tag => |tag| tag,
        .digest => |digest| blk: {
            buffer.* = digest.format();
            break :blk buffer;
        },
    };
}

fn validateOptionalDigest(descriptor: model.Descriptor, header: ?[]const u8) !void {
    const value = header orelse return;
    const expected = content.Digest.parse(descriptor.digest) catch return error.DescriptorMismatch;
    const actual = content.Digest.parse(value) catch return error.InvalidContentDigest;
    if (!std.mem.eql(u8, &expected.bytes, &actual.bytes)) return error.InvalidContentDigest;
}

fn createUniqueTempFile(io: Io, allocator: Allocator, dir: Io.Dir, kind: []const u8) !TempFile {
    var random: [16]u8 = undefined;
    for (0..64) |_| {
        try io.randomSecure(&random);
        const suffix = std.fmt.bytesToHex(random, .lower);
        const name = try std.fmt.allocPrint(allocator, ".zvmi-oci-{s}-{s}.tmp", .{ kind, suffix });
        const file = dir.createFile(io, name, .{
            .read = true,
            .exclusive = true,
            .permissions = .fromMode(0o600),
        }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                allocator.free(name);
                continue;
            },
            else => {
                allocator.free(name);
                return err;
            },
        };
        return .{ .name = name, .file = file };
    }
    return error.PathAlreadyExists;
}

fn percentEncodeAlloc(allocator: Allocator, value: []const u8) ![]u8 {
    const hex = "0123456789ABCDEF";
    const capacity = try std.math.mul(usize, value.len, 3);
    var result = try allocator.alloc(u8, capacity);
    var used: usize = 0;
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~') {
            result[used] = byte;
            used += 1;
        } else {
            result[used] = '%';
            result[used + 1] = hex[byte >> 4];
            result[used + 2] = hex[byte & 0x0f];
            used += 3;
        }
    }
    return allocator.realloc(result, used);
}

fn appendDigestQueryAlloc(allocator: Allocator, url: []const u8, digest: []const u8) ![]u8 {
    if (std.mem.indexOfScalar(u8, url, '#') != null) return error.InvalidRedirect;
    const encoded = try percentEncodeAlloc(allocator, digest);
    defer allocator.free(encoded);
    const separator: []const u8 = if (std.mem.indexOfScalar(u8, url, '?')) |question|
        if (question + 1 == url.len or url[url.len - 1] == '&') "" else "&"
    else
        "?";
    return std.fmt.allocPrint(allocator, "{s}{s}digest={s}", .{ url, separator, encoded });
}

fn uriPort(uri: std.Uri) u16 {
    return uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
}

fn isPlainNonLoopback(uri: std.Uri) bool {
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return false;
    var host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = uri.getHost(&host_buffer) catch return true;
    return !isLoopbackHost(host.bytes);
}

fn isLoopbackHost(host: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, "localhost") or
        std.mem.eql(u8, host, "::1") or
        std.mem.eql(u8, host, "[::1]"))
    {
        return true;
    }
    var parts = std.mem.splitScalar(u8, host, '.');
    const first = parts.next() orelse return false;
    if (!std.mem.eql(u8, first, "127")) return false;
    var count: usize = 1;
    while (parts.next()) |part| {
        _ = std.fmt.parseInt(u8, part, 10) catch return false;
        count += 1;
    }
    return count == 4;
}

fn nextLink(allocator: Allocator, values: []const []const u8) !?[]u8 {
    var selected: ?[]u8 = null;
    errdefer if (selected) |value| allocator.free(value);
    for (values) |value| {
        var parser = LinkParser{ .value = value };
        while (try parser.next()) |link| {
            if (!link.next) continue;
            if (selected) |existing| {
                if (!std.mem.eql(u8, existing, link.location)) return error.InvalidTagLink;
            } else {
                selected = try allocator.dupe(u8, link.location);
            }
        }
    }
    return selected;
}

const LinkValue = struct {
    location: []const u8,
    next: bool,
};

const LinkParser = struct {
    value: []const u8,
    index: usize = 0,

    fn next(self: *LinkParser) !?LinkValue {
        self.skipOws();
        if (self.index == self.value.len) return null;
        if (self.value[self.index] == ',') return error.InvalidTagLink;
        if (self.value[self.index] != '<') return error.InvalidTagLink;
        self.index += 1;
        const location_start = self.index;
        while (self.index < self.value.len and self.value[self.index] != '>') : (self.index += 1) {
            if (self.value[self.index] == '\r' or self.value[self.index] == '\n') return error.InvalidTagLink;
        }
        if (self.index == self.value.len) return error.InvalidTagLink;
        const location = self.value[location_start..self.index];
        self.index += 1;

        var is_next = false;
        while (true) {
            self.skipOws();
            if (self.index == self.value.len) break;
            if (self.value[self.index] == ',') {
                self.index += 1;
                break;
            }
            if (self.value[self.index] != ';') return error.InvalidTagLink;
            self.index += 1;
            self.skipOws();
            const name = try self.token();
            self.skipOws();
            if (self.index == self.value.len or self.value[self.index] != '=') return error.InvalidTagLink;
            self.index += 1;
            self.skipOws();
            const parameter_value = try self.parameter();
            if (std.ascii.eqlIgnoreCase(name, "rel") and relationContainsNext(parameter_value.value, parameter_value.quoted)) {
                is_next = true;
            }
        }
        return .{ .location = location, .next = is_next };
    }

    fn skipOws(self: *LinkParser) void {
        while (self.index < self.value.len and (self.value[self.index] == ' ' or self.value[self.index] == '\t')) : (self.index += 1) {}
    }

    fn token(self: *LinkParser) ![]const u8 {
        const start = self.index;
        while (self.index < self.value.len and isLinkToken(self.value[self.index])) : (self.index += 1) {}
        if (self.index == start) return error.InvalidTagLink;
        return self.value[start..self.index];
    }

    fn parameter(self: *LinkParser) !LinkParameter {
        if (self.index == self.value.len) return error.InvalidTagLink;
        if (self.value[self.index] != '"') return .{ .value = try self.token() };
        self.index += 1;
        const start = self.index;
        while (self.index < self.value.len and self.value[self.index] != '"') : (self.index += 1) {
            switch (self.value[self.index]) {
                '\r', '\n' => return error.InvalidTagLink,
                '\\' => {
                    self.index += 1;
                    if (self.index == self.value.len or self.value[self.index] == '\r' or self.value[self.index] == '\n') {
                        return error.InvalidTagLink;
                    }
                },
                else => {},
            }
        }
        if (self.index == self.value.len) return error.InvalidTagLink;
        const result = self.value[start..self.index];
        self.index += 1;
        return .{ .value = result, .quoted = true };
    }
};

const LinkParameter = struct {
    value: []const u8,
    quoted: bool = false,
};

fn relationContainsNext(value: []const u8, quoted: bool) bool {
    var index: usize = 0;
    var token_len: usize = 0;
    var matches_next = true;
    while (true) {
        const delimiter = if (index == value.len) true else blk: {
            var byte = value[index];
            index += 1;
            if (quoted and byte == '\\') {
                if (index == value.len) return false;
                byte = value[index];
                index += 1;
            }
            if (isRelationWhitespace(byte)) break :blk true;
            if (token_len >= "next".len or std.ascii.toLower(byte) != "next"[token_len]) {
                matches_next = false;
            }
            token_len += 1;
            break :blk false;
        };
        if (!delimiter) continue;
        if (matches_next and token_len == "next".len) return true;
        if (index == value.len) return false;
        token_len = 0;
        matches_next = true;
    }
}

fn isRelationWhitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

fn isLinkToken(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn validTag(tag: []const u8) bool {
    if (tag.len == 0 or tag.len > 128 or (!std.ascii.isAlphanumeric(tag[0]) and tag[0] != '_')) return false;
    for (tag) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '.' and byte != '-') return false;
    }
    return true;
}

fn lessString(_: void, left: []u8, right: []u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn ownedDescriptor(allocator: Allocator, descriptor: model.Descriptor) !Descriptor {
    const media_type = if (descriptor.mediaType) |value| try allocator.dupe(u8, value) else null;
    errdefer if (media_type) |value| allocator.free(value);
    const digest = try allocator.dupe(u8, descriptor.digest);
    errdefer allocator.free(digest);
    const annotations_json = if (descriptor.annotations) |value| try std.json.Stringify.valueAlloc(allocator, value, .{}) else null;
    errdefer if (annotations_json) |value| allocator.free(value);
    const platform = if (descriptor.platform) |value| try ownedPlatform(allocator, value) else null;
    errdefer if (platform) |*value| value.deinit(allocator);
    return .{
        .media_type = media_type,
        .digest = digest,
        .size = descriptor.size,
        .annotations_json = annotations_json,
        .platform = platform,
    };
}

fn ownedPlatform(allocator: Allocator, platform: model.Platform) !Platform {
    const os = try allocator.dupe(u8, platform.os);
    errdefer allocator.free(os);
    const architecture = try allocator.dupe(u8, platform.architecture);
    errdefer allocator.free(architecture);
    const variant = if (platform.variant) |value| try allocator.dupe(u8, value) else null;
    errdefer if (variant) |value| allocator.free(value);
    return .{ .os = os, .architecture = architecture, .variant = variant };
}

fn validateDescriptorPlatform(annotation: ?model.Platform, resolved: Platform) !void {
    const declared = annotation orelse return;
    if (!std.mem.eql(u8, declared.os, resolved.os) or
        !std.mem.eql(u8, declared.architecture, resolved.architecture))
    {
        return error.PlatformConfigMismatch;
    }
    if (declared.variant) |variant| {
        const resolved_variant = resolved.variant orelse return error.PlatformConfigMismatch;
        if (!std.mem.eql(u8, variant, resolved_variant)) return error.PlatformConfigMismatch;
    }
}

fn platformMatchesRequested(resolved: Platform, requested: model.Platform) bool {
    return model.platformMatches(.{
        .os = resolved.os,
        .architecture = resolved.architecture,
        .variant = resolved.variant,
    }, requested);
}

fn descriptorMayMatchRequested(descriptor: model.Platform, requested: model.Platform) bool {
    return model.platformMatches(descriptor, requested);
}

fn registryReferenceText(allocator: Allocator, source: reference.RegistryReference) ![]u8 {
    const selection = source.selection orelse return std.fmt.allocPrint(allocator, "docker://{s}/{s}", .{ source.authority, source.repository });
    return switch (selection) {
        .tag => |tag| std.fmt.allocPrint(allocator, "docker://{s}/{s}:{s}", .{ source.authority, source.repository, tag }),
        .digest => |digest| blk: {
            const text = digest.format();
            break :blk std.fmt.allocPrint(allocator, "docker://{s}/{s}@{s}", .{ source.authority, source.repository, &text });
        },
    };
}

test "registry source initializes explicit transport state" {
    var source = try Source.init(
        std.testing.io,
        std.testing.allocator,
        std.process.Environ.empty,
        .{ .authority = "127.0.0.1:1", .repository = "team/image", .selection = .{ .tag = "latest" } },
        .{ .plain_http = true },
    );
    defer source.deinit();
    try std.testing.expect(source.plain_http);
}

test "only concrete loopback hosts permit plain credentials" {
    try std.testing.expect(isLoopbackHost("127.0.0.1"));
    try std.testing.expect(isLoopbackHost("localhost"));
    try std.testing.expect(!isLoopbackHost("127.evil.example"));
    try std.testing.expect(!isLoopbackHost("127.0.0.999"));
}

test "Link parser accepts repeated list fields and quoted pairs" {
    const values = [_][]const u8{
        "</ignored>; rel=\"prev\"; title=\"comma, \\\"quoted\\\"\"",
        "<../tags/list?n=2>; title=\"comma, \\\"quoted\\\"\"; rel=\"prev\\ next\"",
    };
    const location = (try nextLink(std.testing.allocator, &values)).?;
    defer std.testing.allocator.free(location);
    try std.testing.expectEqualStrings("../tags/list?n=2", location);

    const conflicting = [_][]const u8{
        "</one>; rel=next",
        "</two>; rel=\"next\"",
    };
    try std.testing.expectError(error.InvalidTagLink, nextLink(std.testing.allocator, &conflicting));
}

test "URI resolution removes dot segments and rejects fragments" {
    const resolved = try resolveUrlAlloc(
        std.testing.allocator,
        "https://registry.example/v2/team/image/tags/list?old=1",
        "../tags/list?n=2",
    );
    defer std.testing.allocator.free(resolved);
    try std.testing.expectEqualStrings("https://registry.example/v2/team/image/tags/list?n=2", resolved);
    try std.testing.expectError(
        error.InvalidRedirect,
        resolveUrlAlloc(std.testing.allocator, "https://registry.example/v2/", "../tags#fragment"),
    );
    try std.testing.expectError(
        error.InvalidRedirect,
        resolveUrlAlloc(std.testing.allocator, "https://registry.example/v2/", "http://[bad"),
    );
}

test "upload digest append preserves an opaque signed query" {
    const url = try appendDigestQueryAlloc(
        std.testing.allocator,
        "https://upload.example/session?ticket=opaque%2Fvalue&x=1",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings(
        "https://upload.example/session?ticket=opaque%2Fvalue&x=1&digest=sha256%3A0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        url,
    );
    const trailing = try appendDigestQueryAlloc(
        std.testing.allocator,
        "https://upload.example/session?ticket=opaque%2Fvalue&",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    defer std.testing.allocator.free(trailing);
    try std.testing.expectEqualStrings(
        "https://upload.example/session?ticket=opaque%2Fvalue&digest=sha256%3A0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        trailing,
    );
    try std.testing.expect(sameNormalizedAuthority("registry.example", "registry.example:443", false));
    try std.testing.expect(!sameNormalizedAuthority("registry.example", "registry.example:5000", false));
}

test "upload locations require loopback HTTP or cross-origin HTTPS" {
    var destination = try Destination.init(
        std.testing.io,
        std.testing.allocator,
        std.process.Environ.empty,
        .{
            .authority = "127.0.0.1:5000",
            .repository = "dest",
            .selection = .{ .tag = "latest" },
        },
        .{ .plain_http = true },
    );
    defer destination.deinit();
    var same = try destination.resolveUploadLocation(
        "http://127.0.0.1:5000/v2/dest/blobs/uploads/",
        "/uploads/session?ticket=opaque%2Fvalue",
    );
    defer same.deinit(std.testing.allocator);
    try std.testing.expect(!same.authorization_stripped);
    var cross = try destination.resolveUploadLocation(
        "http://127.0.0.1:5000/v2/dest/blobs/uploads/",
        "https://upload.example/session?ticket=opaque%2Fvalue",
    );
    defer cross.deinit(std.testing.allocator);
    try std.testing.expect(cross.authorization_stripped);
    try std.testing.expectEqualStrings(
        "https://upload.example/session?ticket=opaque%2Fvalue",
        cross.url,
    );
    try std.testing.expectError(
        error.HttpsDowngrade,
        destination.resolveUploadLocation(
            "http://127.0.0.1:5000/v2/dest/blobs/uploads/",
            "http://upload.example/session",
        ),
    );
    try std.testing.expectError(
        error.InvalidRedirect,
        destination.resolveUploadLocation(
            "http://127.0.0.1:5000/v2/dest/blobs/uploads/",
            "https://user@upload.example/session",
        ),
    );
}
