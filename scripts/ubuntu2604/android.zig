//! Fetches and verifies the external Android container smoke inputs.
//!
//! The core image never embeds an Android OCI runtime or bundle. Both are
//! supplied at acceptance time by an architecture-specific repository secret,
//! and this command is the only place that secret is read. It enforces a hard
//! boundary: the secret's URL, its bearer token, and the archive itself stay
//! inside the private output directory, and the only values exported to the
//! rest of the workflow are digests and paths -- never the URL, never the
//! token, never anything derived from the producer's private identity.
//!
//! Every artifact is bound before it is used: the archive to the secret's
//! digest, the provenance manifest to the secret's digest, and the runtime,
//! bundle, and extracted bundle config to the manifest. Any failure removes
//! the whole output directory, so a partially verified input set cannot be
//! left behind for a later step to pick up.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const archive = @import("archive.zig");
const contracts = @import("contracts.zig");
const download = @import("download.zig");
const support = @import("support.zig");
const url = @import("url.zig");

const Diagnostic = support.Diagnostic;
const Error = support.Error;
const fail = support.fail;

pub const input_env = "ANDROID_SMOKE_INPUT_VALUE";
pub const token_env = "ANDROID_ARTIFACT_TOKEN_VALUE";
pub const provenance_schema = "android-smoke-provenance.v1";
pub const provenance_type = "application/vnd.android-smoke.v1+json";
pub const manifest_max_bytes: u64 = 1024 * 1024;
pub const config_max_bytes: u64 = 16 * 1024 * 1024;

/// `ANDROID_SMOKE_ARCHIVE_MEMBERS`.
pub const archive_members = [_][]const u8{
    "android-bundle.tar",
    "android-runtime",
    "provenance.json",
};

/// `ANDROID_SMOKE_SECRET_FIELDS`.
pub const secret_fields = [_][]const u8{
    "artifact_sha256",
    "artifact_url",
    "provenance_sha256",
};

/// `ANDROID_SMOKE_PROVENANCE_FIELDS`.
pub const provenance_fields = [_][]const u8{
    "android_immutable_reference",
    "android_manifest_digest",
    "architecture",
    "bundle_archive_sha256",
    "config_json_sha256",
    "producer_source_commit",
    "runtime_sha256",
    "schema",
    "type",
};

pub const Secret = struct {
    artifact_url: []const u8,
    artifact_sha256: []const u8,
    provenance_sha256: []const u8,
};

/// `parse_android_smoke_secret`.
pub fn parseSecret(
    value: ?[]const u8,
    parsed: *std.json.Parsed(std.json.Value),
    allocator: Allocator,
    diagnostic: *Diagnostic,
) Error!Secret {
    const text = value orelse return fail(
        diagnostic,
        "architecture-specific Android smoke input secret is absent",
        .{},
    );
    if (text.len == 0) return fail(
        diagnostic,
        "architecture-specific Android smoke input secret is absent",
        .{},
    );
    parsed.* = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        text,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "architecture-specific Android smoke input secret is malformed",
            .{},
        ),
    };
    const object = support.objectOf(parsed.value);
    if (object == null or !support.hasExactFields(object.?, &secret_fields)) {
        return fail(
            diagnostic,
            "architecture-specific Android smoke input secret has unexpected fields",
            .{},
        );
    }
    const artifact_url = support.stringOf(object.?.get("artifact_url"));
    if (artifact_url == null or artifact_url.?.len == 0) return fail(
        diagnostic,
        "Android smoke artifact URL is absent",
        .{},
    );
    url.requirePrivateHttps(artifact_url.?) catch return fail(
        diagnostic,
        "Android smoke artifact URL is not an HTTPS URL",
        .{},
    );
    return .{
        .artifact_url = artifact_url.?,
        .artifact_sha256 = try support.requireSha256(
            object.?.get("artifact_sha256"),
            "Android smoke archive digest",
            diagnostic,
        ),
        .provenance_sha256 = try support.requireSha256(
            object.?.get("provenance_sha256"),
            "Android smoke provenance digest",
            diagnostic,
        ),
    };
}

pub const Provenance = struct {
    runtime_sha256: []const u8,
    bundle_sha256: []const u8,
    config_sha256: []const u8,
};

/// `parse_android_smoke_provenance`.
pub fn parseProvenance(
    value: std.json.Value,
    architecture: []const u8,
    diagnostic: *Diagnostic,
) Error!Provenance {
    if (contracts.parseArchitecture(architecture) == null) return fail(
        diagnostic,
        "Android smoke architecture is unsupported",
        .{},
    );
    const object = support.objectOf(value);
    if (object == null or !support.hasExactFields(object.?, &provenance_fields)) {
        return fail(
            diagnostic,
            "Android smoke provenance manifest has unexpected fields",
            .{},
        );
    }
    if (!support.stringIs(object.?.get("schema"), provenance_schema) or
        !support.stringIs(object.?.get("type"), provenance_type))
    {
        return fail(
            diagnostic,
            "Android smoke provenance schema or type is invalid",
            .{},
        );
    }
    if (!support.stringIs(object.?.get("architecture"), architecture)) return fail(
        diagnostic,
        "Android smoke provenance architecture mismatch",
        .{},
    );
    _ = try support.requireCommit(
        object.?.get("producer_source_commit"),
        "Android smoke producer commit",
        diagnostic,
    );
    const reference = support.stringOf(object.?.get("android_immutable_reference"));
    if (reference == null or !isImmutableReference(reference.?)) return fail(
        diagnostic,
        "Android smoke immutable image reference is invalid",
        .{},
    );
    _ = try support.requireSha256(
        object.?.get("android_manifest_digest"),
        "Android smoke source manifest digest",
        diagnostic,
    );
    return .{
        .runtime_sha256 = try support.requireSha256(
            object.?.get("runtime_sha256"),
            "Android smoke runtime digest",
            diagnostic,
        ),
        .bundle_sha256 = try support.requireSha256(
            object.?.get("bundle_archive_sha256"),
            "Android smoke bundle digest",
            diagnostic,
        ),
        .config_sha256 = try support.requireSha256(
            object.?.get("config_json_sha256"),
            "Android smoke config digest",
            diagnostic,
        ),
    };
}

/// `.+@sha256:[0-9a-f]{64}`: the image must be named by digest, so the smoke
/// run cannot silently follow a moved tag.
fn isImmutableReference(text: []const u8) bool {
    const marker = "@sha256:";
    const index = std.mem.lastIndexOf(u8, text, marker) orelse return false;
    if (index == 0) return false;
    return support.isSha256(text[index + marker.len ..]);
}

pub const Options = struct {
    architecture: []const u8,
    output_dir: []const u8,
    github_env: []const u8,
    /// Injected in tests; production reads the process environment.
    secret: ?[]const u8,
    token: ?[]const u8,
    /// Injected in tests so the archive can be staged without a network.
    local_archive: ?[]const u8 = null,
};

/// `prepare_android_smoke_inputs_command`.
pub fn prepare(
    allocator: Allocator,
    io: Io,
    options: Options,
    diagnostic: *Diagnostic,
) Error!void {
    var parsed: std.json.Parsed(std.json.Value) = undefined;
    var parsed_alive = false;
    defer if (parsed_alive) parsed.deinit();
    const secret = try parseSecret(options.secret, &parsed, allocator, diagnostic);
    parsed_alive = true;

    if (support.pathExists(io, options.output_dir)) return fail(
        diagnostic,
        "Android smoke input directory already exists",
        .{},
    );
    Dir.cwd().createDirPath(io, options.output_dir) catch return fail(
        diagnostic,
        "Android smoke input directory already exists",
        .{},
    );
    Dir.cwd().setFilePermissions(
        io,
        options.output_dir,
        .fromMode(0o700),
        .{},
    ) catch {};

    prepareVerified(allocator, io, options, secret, diagnostic) catch |err| {
        removeTree(io, options.output_dir);
        return err;
    };
}

fn removeTree(io: Io, path: []const u8) void {
    Dir.cwd().deleteTree(io, path) catch {};
}

fn prepareVerified(
    allocator: Allocator,
    io: Io,
    options: Options,
    secret: Secret,
    diagnostic: *Diagnostic,
) Error!void {
    const archive_path = try support.joinPath(
        allocator,
        &.{ options.output_dir, "artifact.zip" },
    );
    defer allocator.free(archive_path);

    if (options.local_archive) |source| {
        const bytes = support.file_support.readBounded(
            allocator,
            io,
            source,
            support.artifact_max_bytes,
        ) catch return fail(
            diagnostic,
            "private Android smoke artifact download failed",
            .{},
        );
        defer allocator.free(bytes);
        Dir.cwd().writeFile(io, .{
            .sub_path = archive_path,
            .data = bytes,
            .flags = .{ .permissions = .fromMode(0o600) },
        }) catch return fail(
            diagnostic,
            "private Android smoke artifact download failed",
            .{},
        );
    } else {
        const partial = try std.fmt.allocPrint(
            allocator,
            "{s}/.artifact.zip.partial",
            .{options.output_dir},
        );
        defer allocator.free(partial);
        Dir.cwd().deleteFile(io, partial) catch {};
        if (options.token) |token| {
            if (std.mem.indexOfAny(u8, token, "\r\n") != null) return fail(
                diagnostic,
                "Android artifact bearer token is malformed",
                .{},
            );
        }
        download.fetch(allocator, io, secret.artifact_url, partial, .{
            .token = options.token,
        }) catch |err| switch (err) {
            error.OutOfMemory => {
                Dir.cwd().deleteFile(io, partial) catch {};
                return error.OutOfMemory;
            },
            else => {
                Dir.cwd().deleteFile(io, partial) catch {};
                return fail(
                    diagnostic,
                    "private Android smoke artifact download failed",
                    .{},
                );
            },
        };
        Dir.cwd().rename(partial, Dir.cwd(), archive_path, io) catch {
            Dir.cwd().deleteFile(io, partial) catch {};
            return fail(
                diagnostic,
                "private Android smoke artifact download failed",
                .{},
            );
        };
    }

    const archive_digest = support.hashArtifact(io, archive_path) catch return fail(
        diagnostic,
        "Android smoke archive digest mismatch",
        .{},
    );
    if (!std.mem.eql(u8, &archive_digest.hex, secret.artifact_sha256)) return fail(
        diagnostic,
        "Android smoke archive digest mismatch",
        .{},
    );

    try extractArchive(allocator, io, archive_path, options.output_dir, diagnostic);
    Dir.cwd().deleteFile(io, archive_path) catch return fail(
        diagnostic,
        "Android smoke archive is malformed",
        .{},
    );

    const provenance_path = try support.joinPath(
        allocator,
        &.{ options.output_dir, "provenance.json" },
    );
    defer allocator.free(provenance_path);
    const provenance_size = support.file_support.regularFileSize(
        io,
        provenance_path,
    ) catch return fail(
        diagnostic,
        "Android smoke provenance manifest exceeds size bound",
        .{},
    );
    if (provenance_size > manifest_max_bytes) return fail(
        diagnostic,
        "Android smoke provenance manifest exceeds size bound",
        .{},
    );
    const provenance_digest = support.hashArtifact(io, provenance_path) catch
        return fail(diagnostic, "Android smoke provenance digest mismatch", .{});
    if (!std.mem.eql(u8, &provenance_digest.hex, secret.provenance_sha256)) {
        return fail(diagnostic, "Android smoke provenance digest mismatch", .{});
    }

    const provenance_bytes = support.file_support.readBounded(
        allocator,
        io,
        provenance_path,
        manifest_max_bytes,
    ) catch return fail(
        diagnostic,
        "Android smoke provenance manifest is malformed",
        .{},
    );
    defer allocator.free(provenance_bytes);
    var provenance_document = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        provenance_bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "Android smoke provenance manifest is malformed",
            .{},
        ),
    };
    defer provenance_document.deinit();
    const provenance = try parseProvenance(
        provenance_document.value,
        options.architecture,
        diagnostic,
    );

    const runtime_path = try support.joinPath(
        allocator,
        &.{ options.output_dir, "android-runtime" },
    );
    defer allocator.free(runtime_path);
    const bundle_path = try support.joinPath(
        allocator,
        &.{ options.output_dir, "android-bundle.tar" },
    );
    defer allocator.free(bundle_path);

    const runtime_digest = support.hashArtifact(io, runtime_path) catch return fail(
        diagnostic,
        "Android smoke runtime digest mismatch",
        .{},
    );
    if (!std.mem.eql(u8, &runtime_digest.hex, provenance.runtime_sha256)) {
        return fail(diagnostic, "Android smoke runtime digest mismatch", .{});
    }
    const bundle_digest = support.hashArtifact(io, bundle_path) catch return fail(
        diagnostic,
        "Android smoke bundle digest mismatch",
        .{},
    );
    if (!std.mem.eql(u8, &bundle_digest.hex, provenance.bundle_sha256)) {
        return fail(diagnostic, "Android smoke bundle digest mismatch", .{});
    }
    const config_digest = archive.bundleConfigDigest(
        io,
        bundle_path,
        config_max_bytes,
    ) catch |err| switch (err) {
        error.InvalidConfigEntry => return fail(
            diagnostic,
            "Android smoke bundle config entry is invalid",
            .{},
        ),
        error.TruncatedConfigEntry => return fail(
            diagnostic,
            "Android smoke bundle config entry is truncated",
            .{},
        ),
        else => return fail(
            diagnostic,
            "Android smoke bundle archive is malformed",
            .{},
        ),
    };
    if (!std.mem.eql(u8, &config_digest.hex, provenance.config_sha256)) {
        return fail(diagnostic, "Android smoke bundle config digest mismatch", .{});
    }

    const absolute_runtime = try absolutePath(allocator, io, runtime_path);
    defer allocator.free(absolute_runtime);
    const absolute_bundle = try absolutePath(allocator, io, bundle_path);
    defer allocator.free(absolute_bundle);

    const values = [_][2][]const u8{
        .{
            "MIZ_UBUNTU2604_ANDROID_PROVENANCE_SHA256",
            &provenance_digest.hex,
        },
        .{ "MIZ_UBUNTU2604_ANDROID_RUNTIME", absolute_runtime },
        .{
            "MIZ_UBUNTU2604_ANDROID_RUNTIME_SHA256",
            provenance.runtime_sha256,
        },
        .{ "MIZ_UBUNTU2604_ANDROID_BUNDLE", absolute_bundle },
        .{ "MIZ_UBUNTU2604_ANDROID_BUNDLE_SHA256", provenance.bundle_sha256 },
        .{ "MIZ_UBUNTU2604_ANDROID_CONFIG_SHA256", provenance.config_sha256 },
    };
    var lines: std.ArrayList(u8) = .empty;
    defer lines.deinit(allocator);
    for (values) |entry| {
        if (std.mem.indexOfAny(u8, entry[1], "\r\n") != null) return fail(
            diagnostic,
            "Android smoke verified environment value is malformed",
            .{},
        );
        try lines.print(allocator, "{s}={s}\n", .{ entry[0], entry[1] });
    }
    appendFile(io, options.github_env, lines.items) catch return fail(
        diagnostic,
        "Android smoke verified environment value is malformed",
        .{},
    );
}

fn absolutePath(allocator: Allocator, io: Io, path: []const u8) Error![]u8 {
    if (std.fs.path.isAbsolute(path)) return allocator.dupe(u8, path);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = Dir.cwd().realPathFile(io, ".", &buffer) catch
        return allocator.dupe(u8, path);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ buffer[0..length], path });
}

fn appendFile(io: Io, path: []const u8, data: []const u8) !void {
    const file = try Dir.cwd().createFile(io, path, .{
        .truncate = false,
        .read = false,
    });
    defer file.close(io);
    const end = (try file.stat(io)).size;
    try file.writePositionalAll(io, data, end);
}

/// `_extract_android_smoke_archive`.
fn extractArchive(
    allocator: Allocator,
    io: Io,
    archive_path: []const u8,
    output_dir: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    var directory = archive.readDirectory(
        allocator,
        io,
        archive_path,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(diagnostic, "Android smoke archive is malformed", .{}),
    };
    defer directory.deinit(allocator);

    if (directory.members.len != archive_members.len) return fail(
        diagnostic,
        "Android smoke archive member set is not exact",
        .{},
    );
    for (archive_members) |name| {
        var seen = false;
        for (directory.members) |member| {
            if (std.mem.eql(u8, member.name, name)) seen = true;
        }
        if (!seen) return fail(
            diagnostic,
            "Android smoke archive member set is not exact",
            .{},
        );
    }
    for (directory.members) |member| {
        if (member.isDirectory() or member.isEncrypted() or !member.isRegular()) {
            return fail(
                diagnostic,
                "Android smoke archive contains an unsafe member",
                .{},
            );
        }
    }
    for (directory.members) |member| {
        const destination = try support.joinPath(
            allocator,
            &.{ output_dir, member.name },
        );
        defer allocator.free(destination);
        archive.extractMember(
            io,
            archive_path,
            member,
            destination,
        ) catch return fail(
            diagnostic,
            "Android smoke archive is malformed",
            .{},
        );
    }
}

test "immutable image references must be digest-pinned" {
    try std.testing.expect(isImmutableReference(
        "registry.example.invalid/android@sha256:" ++ "b" ** 64,
    ));
    try std.testing.expect(!isImmutableReference("registry.example.invalid/android"));
    try std.testing.expect(!isImmutableReference("@sha256:" ++ "b" ** 64));
    try std.testing.expect(!isImmutableReference(
        "registry.example.invalid/android@sha256:" ++ "B" ** 64,
    ));
    try std.testing.expect(!isImmutableReference(
        "registry.example.invalid/android:tag",
    ));
}

test "the secret must be exactly three fields with a private HTTPS URL" {
    var diagnostic: Diagnostic = .{};
    var parsed: std.json.Parsed(std.json.Value) = undefined;
    var alive = false;
    defer if (alive) parsed.deinit();

    const good =
        \\{"artifact_url": "https://artifacts.example.invalid/a.zip",
        \\ "artifact_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        \\ "provenance_sha256": "2222222222222222222222222222222222222222222222222222222222222222"}
    ;
    const secret = try parseSecret(
        good,
        &parsed,
        std.testing.allocator,
        &diagnostic,
    );
    alive = true;
    try std.testing.expectEqualStrings(
        "https://artifacts.example.invalid/a.zip",
        secret.artifact_url,
    );
    parsed.deinit();
    alive = false;

    try std.testing.expectError(error.Failed, parseSecret(
        null,
        &parsed,
        std.testing.allocator,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "architecture-specific Android smoke input secret is absent",
        diagnostic.message(),
    );

    try std.testing.expectError(error.Failed, parseSecret(
        "{",
        &parsed,
        std.testing.allocator,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "architecture-specific Android smoke input secret is malformed",
        diagnostic.message(),
    );

    const extra =
        \\{"artifact_url": "https://a.invalid/a.zip",
        \\ "artifact_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        \\ "provenance_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
        \\ "producer": "private"}
    ;
    try std.testing.expectError(error.Failed, parseSecret(
        extra,
        &parsed,
        std.testing.allocator,
        &diagnostic,
    ));
    parsed.deinit();
    try std.testing.expectEqualStrings(
        "architecture-specific Android smoke input secret has unexpected fields",
        diagnostic.message(),
    );

    const insecure =
        \\{"artifact_url": "http://artifacts.example.invalid/a.zip",
        \\ "artifact_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        \\ "provenance_sha256": "2222222222222222222222222222222222222222222222222222222222222222"}
    ;
    try std.testing.expectError(error.Failed, parseSecret(
        insecure,
        &parsed,
        std.testing.allocator,
        &diagnostic,
    ));
    parsed.deinit();
    try std.testing.expectEqualStrings(
        "Android smoke artifact URL is not an HTTPS URL",
        diagnostic.message(),
    );
}
