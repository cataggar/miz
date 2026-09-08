//! One-way GitHub release publication.
//!
//! A release is mutable only while it is a draft. This module validates the
//! complete local allowlist, discovers an exact resumable draft, uploads and
//! independently downloads every asset, and publishes exactly once. After the
//! publish request succeeds, every remaining operation is read-only.

const std = @import("std");
const contract = @import("contract.zig");
const digest = @import("digest.zig");
const file_support = @import("file.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;

pub const Diagnostic = contract.Diagnostic;
pub const Error = error{ Failed, OutOfMemory };

pub const repository = "cataggar/miz";
pub const github_api_version = "2026-03-10";
pub const immutable_tag_ruleset_name = "miz-immutable-release-tags-v1";
pub const platforms = [_][]const u8{
    "linux-musl-x64",
    "linux-musl-arm64",
    "macos-x64",
    "macos-arm64",
    "windows-x64",
    "windows-arm64",
};

const maximum_asset_bytes: u64 = 8 * 1024 * 1024 * 1024;
const maximum_gh_output_bytes: usize = 16 * 1024 * 1024;

pub const ExpectedMetadata = struct {
    tag: []const u8,
    commit: []const u8,
    title: []const u8,
    body: []const u8,
    prerelease: bool,
};

pub const Asset = struct {
    name: []const u8,
    path: []const u8,
    digest_hex: digest.Hex,
    size: u64,
    identity: file_support.Identity,
    remote_id: i64 = 0,
};

const Release = struct {
    id: i64,
    draft: bool,
    immutable: bool,
    body: []const u8,
    assets: []RemoteAsset,

    fn deinit(self: *Release, allocator: Allocator) void {
        allocator.free(self.body);
        for (self.assets) |asset| {
            allocator.free(asset.name);
            if (asset.digest_text) |text| allocator.free(text);
        }
        allocator.free(self.assets);
        self.* = undefined;
    }
};

const RemoteAsset = struct {
    id: i64,
    name: []const u8,
    size: u64,
    digest_text: ?[]const u8,
    state: AssetState,
};

const AssetState = enum {
    starter,
    uploaded,
};

const AssetPolicy = enum {
    allow_incomplete,
    require_uploaded,
};

const MetadataPolicy = enum {
    exact,
    retained_draft,
};

const DeleteReason = enum {
    unexpected,
    duplicate,
    incomplete,
    wrong_size,
    wrong_digest,
};

pub const PublishOptions = struct {
    repository_name: []const u8,
    tag: []const u8,
    version: []const u8,
    commit: []const u8,
    assets_directory: []const u8,
    workspace: []const u8,
    gh_executable: []const u8 = "gh",
    summary_path: ?[]const u8 = null,
    environment: std.process.Environ,
    policy_token: ?[]const u8 = null,
};

const GhResult = struct {
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: GhResult, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }
};

const Publisher = struct {
    allocator: Allocator,
    io: Io,
    diagnostic: *Diagnostic,
    options: PublishOptions,
    metadata: ExpectedMetadata,
    assets: []Asset,
    release_id: i64 = 0,
    previous_main_tag: ?[]u8 = null,

    fn fail(
        self: *Publisher,
        comptime format: []const u8,
        arguments: anytype,
    ) Error {
        self.diagnostic.set(format, arguments);
        return error.Failed;
    }

    fn ghWithToken(
        self: *Publisher,
        arguments: []const []const u8,
        token: ?[]const u8,
    ) Error!GhResult {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        argv.append(self.allocator, self.options.gh_executable) catch
            return error.OutOfMemory;
        argv.appendSlice(self.allocator, arguments) catch
            return error.OutOfMemory;
        var environment = std.process.Environ.createMap(
            self.options.environment,
            self.allocator,
        ) catch return error.OutOfMemory;
        defer environment.deinit();
        environment.put("MIZ_RELEASE_POLICY_GH_TOKEN", "") catch
            return error.OutOfMemory;
        if (token) |value| {
            environment.put("GH_TOKEN", value) catch return error.OutOfMemory;
        }
        const result = std.process.run(self.allocator, self.io, .{
            .argv = argv.items,
            .environ_map = &environment,
            .stdout_limit = .limited(maximum_gh_output_bytes),
            .stderr_limit = .limited(maximum_gh_output_bytes),
        }) catch |err| return self.fail(
            "cannot execute GitHub CLI: {t}",
            .{err},
        );
        const succeeded = switch (result.term) {
            .exited => |code| code == 0,
            else => false,
        };
        if (!succeeded) {
            defer self.allocator.free(result.stdout);
            defer self.allocator.free(result.stderr);
            return self.fail(
                "GitHub CLI command failed: {s}",
                .{std.mem.trim(u8, result.stderr, " \t\r\n")},
            );
        }
        return .{ .stdout = result.stdout, .stderr = result.stderr };
    }

    fn gh(self: *Publisher, arguments: []const []const u8) Error!GhResult {
        return self.ghWithToken(arguments, null);
    }

    fn ghJson(self: *Publisher, arguments: []const []const u8) Error!std.json.Parsed(Value) {
        const result = try self.gh(arguments);
        defer result.deinit(self.allocator);
        return std.json.parseFromSlice(
            Value,
            self.allocator,
            result.stdout,
            .{},
        ) catch |err| self.fail("GitHub CLI returned invalid JSON: {t}", .{err});
    }

    fn ghJsonWithToken(
        self: *Publisher,
        arguments: []const []const u8,
        token: []const u8,
    ) Error!std.json.Parsed(Value) {
        const result = try self.ghWithToken(arguments, token);
        defer result.deinit(self.allocator);
        return std.json.parseFromSlice(
            Value,
            self.allocator,
            result.stdout,
            .{},
        ) catch |err| self.fail("GitHub CLI returned invalid JSON: {t}", .{err});
    }

    fn verifyTag(self: *Publisher) Error!void {
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/git/ref/tags/{s}",
            .{ self.options.repository_name, self.options.tag },
        ) catch return self.fail("release tag is too long", .{});
        var ref = try self.ghJson(&.{ "api", endpoint });
        defer ref.deinit();
        var object = objectField(
            self,
            &ref.value,
            "object",
            "tag ref object",
        ) catch return error.Failed;
        var object_type = self.allocator.dupe(u8, stringField(
            self,
            object,
            "type",
            "tag ref object type",
        ) catch return error.Failed) catch return error.OutOfMemory;
        defer self.allocator.free(object_type);
        var object_sha = self.allocator.dupe(u8, stringField(
            self,
            object,
            "sha",
            "tag ref object SHA",
        ) catch return error.Failed) catch return error.OutOfMemory;
        defer self.allocator.free(object_sha);

        var depth: usize = 0;
        while (std.mem.eql(u8, object_type, "tag")) : (depth += 1) {
            if (depth == 8) return self.fail(
                "release tag annotation chain is too deep",
                .{},
            );
            var object_endpoint_buffer: [512]u8 = undefined;
            const object_endpoint = std.fmt.bufPrint(
                &object_endpoint_buffer,
                "repos/{s}/git/tags/{s}",
                .{ self.options.repository_name, object_sha },
            ) catch return self.fail("tag object endpoint is too long", .{});
            var tag_object = try self.ghJson(&.{ "api", object_endpoint });
            defer tag_object.deinit();
            object = objectField(
                self,
                &tag_object.value,
                "object",
                "annotated tag target",
            ) catch return error.Failed;
            const next_type = self.allocator.dupe(u8, stringField(
                self,
                object,
                "type",
                "annotated tag target type",
            ) catch return error.Failed) catch return error.OutOfMemory;
            const next_sha = self.allocator.dupe(u8, stringField(
                self,
                object,
                "sha",
                "annotated tag target SHA",
            ) catch return error.Failed) catch return error.OutOfMemory;
            self.allocator.free(object_type);
            self.allocator.free(object_sha);
            object_type = next_type;
            object_sha = next_sha;
            if (!std.mem.eql(u8, object_type, "tag")) {
                if (!std.mem.eql(u8, object_type, "commit") or
                    !std.mem.eql(u8, object_sha, self.options.commit))
                {
                    return self.fail(
                        "release tag resolves to {s} {s}, not workflow commit {s}",
                        .{ object_type, object_sha, self.options.commit },
                    );
                }
                return;
            }
        }
        if (!std.mem.eql(u8, object_type, "commit") or
            !std.mem.eql(u8, object_sha, self.options.commit))
        {
            return self.fail(
                "release tag resolves to {s} {s}, not workflow commit {s}",
                .{ object_type, object_sha, self.options.commit },
            );
        }
    }

    fn discover(self: *Publisher) Error!?Release {
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases?per_page=100",
            .{self.options.repository_name},
        ) catch return self.fail("repository name is too long", .{});
        var pages = try self.ghJson(&.{ "api", "--paginate", "--slurp", endpoint });
        defer pages.deinit();
        if (pages.value != .array) return self.fail(
            "paginated release listing is not an array",
            .{},
        );

        var exact: ?Release = null;
        const current_version = std.SemanticVersion.parse(
            self.options.version,
        ) catch unreachable;
        for (pages.value.array.items) |page| {
            if (page != .array) return self.fail(
                "paginated release page is not an array",
                .{},
            );
            for (page.array.items) |candidate| {
                if (candidate != .object) return self.fail(
                    "release listing entry is not an object",
                    .{},
                );
                const draft = boolField(
                    self,
                    &candidate.object,
                    "draft",
                    "release draft state",
                ) catch return error.Failed;
                const tag_value = candidate.object.get("tag_name");
                if (draft and (tag_value == null or tag_value.? == .null or
                    (tag_value.? == .string and tag_value.?.string.len == 0)))
                {
                    continue;
                }
                const tag = if (tag_value) |value| blk: {
                    if (value != .string) return self.fail(
                        "release tag is not a string",
                        .{},
                    );
                    break :blk value.string;
                } else return self.fail("release tag is missing", .{});
                if (std.mem.eql(u8, tag, self.metadata.tag)) {
                    if (exact) |*previous| {
                        previous.deinit(self.allocator);
                        return self.fail(
                            "more than one release has exact tag {s}",
                            .{self.metadata.tag},
                        );
                    }
                    exact = try self.parseRelease(
                        candidate,
                        .retained_draft,
                        .allow_incomplete,
                    );
                    continue;
                }
                if (draft) continue;
                if (!std.mem.startsWith(u8, tag, "v")) continue;
                const candidate_version = std.SemanticVersion.parse(tag[1..]) catch
                    continue;
                const listed_prerelease = boolField(
                    self,
                    &candidate.object,
                    "prerelease",
                    "published release prerelease state",
                ) catch return error.Failed;
                const tag_is_prerelease = std.mem.indexOfScalar(
                    u8,
                    std.mem.sliceTo(tag[1..], '+'),
                    '-',
                ) != null;
                if (listed_prerelease != tag_is_prerelease) return self.fail(
                    "published release {s} prerelease state does not match its SemVer tag",
                    .{tag},
                );
                if (tag_is_prerelease) continue;
                if (candidate_version.order(current_version) != .lt) continue;
                if (self.previous_main_tag) |previous| {
                    const previous_version = std.SemanticVersion.parse(previous[1..]) catch
                        unreachable;
                    if (candidate_version.order(previous_version) != .gt) continue;
                    self.allocator.free(previous);
                }
                self.previous_main_tag = self.allocator.dupe(u8, tag) catch
                    return error.OutOfMemory;
            }
        }
        if (exact) |release| {
            if (!release.draft) return self.fail(
                "release {s} is already published and immutable",
                .{self.metadata.tag},
            );
        }
        return exact;
    }

    fn generateNotes(self: *Publisher) Error![]u8 {
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases/generate-notes",
            .{self.options.repository_name},
        ) catch return self.fail("release notes endpoint is too long", .{});
        const tag_field = try fieldAlloc(self, "tag_name", self.metadata.tag);
        defer self.allocator.free(tag_field);
        const target_field = try fieldAlloc(
            self,
            "target_commitish",
            self.metadata.commit,
        );
        defer self.allocator.free(target_field);
        var arguments: std.ArrayList([]const u8) = .empty;
        defer arguments.deinit(self.allocator);
        arguments.appendSlice(self.allocator, &.{
            "api",
            "--method",
            "POST",
            endpoint,
            "-f",
            tag_field,
            "-f",
            target_field,
        }) catch return error.OutOfMemory;
        var previous_field: ?[]const u8 = null;
        defer if (previous_field) |field| self.allocator.free(field);
        if (self.previous_main_tag) |previous| {
            previous_field = try fieldAlloc(self, "previous_tag_name", previous);
            arguments.append(self.allocator, "-f") catch return error.OutOfMemory;
            arguments.append(
                self.allocator,
                previous_field.?,
            ) catch return error.OutOfMemory;
        }
        var result = try self.ghJson(arguments.items);
        defer result.deinit();
        if (result.value != .object) return self.fail(
            "generated release notes response is not an object",
            .{},
        );
        const body = stringField(
            self,
            &result.value.object,
            "body",
            "generated release notes body",
        ) catch return error.Failed;
        return self.allocator.dupe(u8, body) catch return error.OutOfMemory;
    }

    fn createDraft(self: *Publisher) Error!Release {
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases",
            .{self.options.repository_name},
        ) catch return self.fail("repository name is too long", .{});
        const prerelease = if (self.metadata.prerelease) "true" else "false";
        const tag_field = try fieldAlloc(self, "tag_name", self.metadata.tag);
        defer self.allocator.free(tag_field);
        const target_field = try fieldAlloc(
            self,
            "target_commitish",
            self.metadata.commit,
        );
        defer self.allocator.free(target_field);
        const name_field = try fieldAlloc(self, "name", self.metadata.title);
        defer self.allocator.free(name_field);
        const body_field = try fieldAlloc(self, "body", self.metadata.body);
        defer self.allocator.free(body_field);
        const prerelease_field = try fieldAlloc(self, "prerelease", prerelease);
        defer self.allocator.free(prerelease_field);
        const latest_field = try fieldAlloc(self, "make_latest", "false");
        defer self.allocator.free(latest_field);
        var result = try self.ghJson(&.{
            "api",
            "--method",
            "POST",
            endpoint,
            "-f",
            tag_field,
            "-f",
            target_field,
            "-f",
            name_field,
            "-f",
            body_field,
            "-F",
            "draft=true",
            "-F",
            prerelease_field,
            "-F",
            "generate_release_notes=false",
            "-f",
            latest_field,
        });
        defer result.deinit();
        const release = try self.parseRelease(
            result.value,
            .exact,
            .require_uploaded,
        );
        if (!release.draft) return self.fail(
            "GitHub did not create release {s} as a draft",
            .{self.metadata.tag},
        );
        return release;
    }

    fn fetch(
        self: *Publisher,
        expected_draft: bool,
        asset_policy: AssetPolicy,
    ) Error!Release {
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases/{d}",
            .{ self.options.repository_name, self.release_id },
        ) catch return self.fail("release endpoint is too long", .{});
        var result = try self.ghJson(&.{ "api", endpoint });
        defer result.deinit();
        const release = try self.parseRelease(
            result.value,
            .exact,
            asset_policy,
        );
        if (release.id != self.release_id) return self.fail(
            "GitHub returned release {d}, expected {d}",
            .{ release.id, self.release_id },
        );
        if (release.draft != expected_draft) return self.fail(
            "release {s} changed publication state unexpectedly",
            .{self.metadata.tag},
        );
        return release;
    }

    fn parseRelease(
        self: *Publisher,
        value: Value,
        metadata_policy: MetadataPolicy,
        asset_policy: AssetPolicy,
    ) Error!Release {
        if (value != .object) return self.fail(
            "release response is not an object",
            .{},
        );
        const object = &value.object;
        const id = integerField(self, object, "id", "release id") catch
            return error.Failed;
        if (id <= 0) return self.fail("release id is invalid", .{});
        const draft = boolField(self, object, "draft", "release draft") catch
            return error.Failed;
        const immutable_optional = optionalBoolField(
            self,
            object,
            "immutable",
            "release immutable",
        ) catch return error.Failed;
        const immutable = immutable_optional orelse false;
        const body = stringField(
            self,
            object,
            "body",
            "release body",
        ) catch return error.Failed;
        switch (metadata_policy) {
            .exact => try validateMetadataObject(
                object,
                self.metadata,
                self.diagnostic,
            ),
            .retained_draft => {
                try validateCoreMetadataObject(
                    object,
                    self.metadata,
                    self.diagnostic,
                );
                try validateRetainedReleaseBody(
                    body,
                    self.metadata.body,
                    self.diagnostic,
                );
            },
        }
        const assets_value = object.get("assets") orelse return self.fail(
            "release assets are missing",
            .{},
        );
        if (assets_value != .array) return self.fail(
            "release assets are not an array",
            .{},
        );
        const assets = self.allocator.alloc(
            RemoteAsset,
            assets_value.array.items.len,
        ) catch return error.OutOfMemory;
        var initialized: usize = 0;
        errdefer {
            for (assets[0..initialized]) |asset| {
                self.allocator.free(asset.name);
                if (asset.digest_text) |text| self.allocator.free(text);
            }
            self.allocator.free(assets);
        }
        for (assets_value.array.items, assets) |asset_value, *asset| {
            if (asset_value != .object) return self.fail(
                "release asset is not an object",
                .{},
            );
            const size = integerField(
                self,
                &asset_value.object,
                "size",
                "release asset size",
            ) catch return error.Failed;
            if (size < 0) return self.fail("release asset size is invalid", .{});
            const name = stringField(
                self,
                &asset_value.object,
                "name",
                "release asset name",
            ) catch return error.Failed;
            const digest_text = optionalStringField(
                self,
                &asset_value.object,
                "digest",
                "release asset digest",
            ) catch return error.Failed;
            const state = stringField(
                self,
                &asset_value.object,
                "state",
                "release asset state",
            ) catch return error.Failed;
            const parsed_state: AssetState = if (std.mem.eql(u8, state, "uploaded"))
                .uploaded
            else if (std.mem.eql(u8, state, "starter"))
                .starter
            else
                return self.fail(
                    "release asset {s} has unknown state {s}",
                    .{ name, state },
                );
            if (asset_policy == .require_uploaded and parsed_state != .uploaded) {
                return self.fail(
                    "release asset {s} is not fully uploaded",
                    .{name},
                );
            }
            asset.* = .{
                .id = integerField(
                    self,
                    &asset_value.object,
                    "id",
                    "release asset id",
                ) catch return error.Failed,
                .name = self.allocator.dupe(u8, name) catch return error.OutOfMemory,
                .size = @intCast(size),
                .digest_text = if (digest_text) |text|
                    self.allocator.dupe(u8, text) catch return error.OutOfMemory
                else
                    null,
                .state = parsed_state,
            };
            initialized += 1;
            if (asset.id <= 0) return self.fail(
                "release asset id is invalid",
                .{},
            );
        }
        return .{
            .id = id,
            .draft = draft,
            .immutable = immutable,
            .body = self.allocator.dupe(u8, body) catch return error.OutOfMemory,
            .assets = assets,
        };
    }

    fn revalidateLocal(self: *Publisher, asset: *const Asset) Error!void {
        const current = hashRegularNoSymlink(self.io, asset.path) catch |err|
            return self.fail("cannot revalidate {s}: {t}", .{ asset.name, err });
        if (!asset.identity.eql(current.identity) or
            asset.size != current.size or
            !std.mem.eql(u8, &asset.digest_hex, &current.hex))
        {
            return self.fail(
                "local release asset changed after validation: {s}",
                .{asset.name},
            );
        }
    }

    fn upload(self: *Publisher, asset: *const Asset) Error!void {
        var draft = try self.fetch(true, .allow_incomplete);
        defer draft.deinit(self.allocator);
        try self.validateRemoteSubset(&draft);
        var same_name_count: usize = 0;
        var matching_remote: ?RemoteAsset = null;
        for (draft.assets) |remote| {
            if (!std.mem.eql(u8, remote.name, asset.name)) continue;
            same_name_count += 1;
            matching_remote = remote;
        }
        try self.revalidateLocal(asset);
        if (same_name_count == 1 and
            remoteMatchesLocal(matching_remote.?, asset)) return;
        if (same_name_count != 0) return self.fail(
            "draft asset {s} changed before upload",
            .{asset.name},
        );
        if (!safeUploadAssetName(asset.name)) return self.fail(
            "release asset name is not safe for a fixed upload URL: {s}",
            .{asset.name},
        );
        var endpoint_buffer: [1024]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "https://uploads.github.com/repos/{s}/releases/{d}/assets?name={s}",
            .{ self.options.repository_name, self.release_id, asset.name },
        ) catch return self.fail("asset upload endpoint is too long", .{});
        const result = try self.gh(&.{
            "api",
            "--method",
            "POST",
            "-H",
            "Content-Type: application/octet-stream",
            "--input",
            asset.path,
            endpoint,
        });
        result.deinit(self.allocator);
        var uploaded = try self.fetch(true, .allow_incomplete);
        defer uploaded.deinit(self.allocator);
        try self.validateRemoteSubset(&uploaded);
        try self.validateOneRemoteAsset(&uploaded, asset);
    }

    fn deleteRemoteAsset(
        self: *Publisher,
        asset_id: i64,
        expected_name: []const u8,
        reason: DeleteReason,
    ) Error!void {
        var checked = try self.fetch(true, .allow_incomplete);
        defer checked.deinit(self.allocator);
        var current: ?RemoteAsset = null;
        for (checked.assets) |asset| {
            if (asset.id == asset_id) {
                if (current != null) return self.fail(
                    "draft asset id {d} is duplicated",
                    .{asset_id},
                );
                current = asset;
            }
        }
        const asset = current orelse return self.fail(
            "draft asset {d} changed before deletion",
            .{asset_id},
        );
        const current_reason = classifyRemoteAsset(
            self.assets,
            checked.assets,
            asset,
        );
        if (!std.mem.eql(u8, asset.name, expected_name) or
            current_reason == null or current_reason.? != reason)
        {
            return self.fail(
                "draft asset {d} changed classification before deletion",
                .{asset_id},
            );
        }
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases/assets/{d}",
            .{ self.options.repository_name, asset_id },
        ) catch return self.fail("asset endpoint is too long", .{});
        const result = try self.gh(&.{ "api", "--method", "DELETE", endpoint });
        result.deinit(self.allocator);
    }

    fn repairDraftAssets(self: *Publisher) Error!void {
        while (true) {
            var release = try self.fetch(true, .allow_incomplete);
            defer release.deinit(self.allocator);
            var planned: ?struct {
                id: i64,
                name: []const u8,
                reason: DeleteReason,
            } = null;
            for (release.assets) |remote| {
                const reason = classifyRemoteAsset(
                    self.assets,
                    release.assets,
                    remote,
                ) orelse continue;
                planned = .{
                    .id = remote.id,
                    .name = remote.name,
                    .reason = reason,
                };
                break;
            }
            if (planned) |item| {
                try self.deleteRemoteAsset(item.id, item.name, item.reason);
                continue;
            }
            return;
        }
    }

    fn deleteStale(self: *Publisher) Error!void {
        while (true) {
            var release = try self.fetch(true, .require_uploaded);
            defer release.deinit(self.allocator);
            var stale: ?RemoteAsset = null;
            for (release.assets) |remote| {
                if (findAsset(self.assets, remote.name) != null) continue;
                stale = remote;
                break;
            }
            if (stale) |asset| {
                try self.deleteRemoteAsset(
                    asset.id,
                    asset.name,
                    .unexpected,
                );
                continue;
            }
            return;
        }
    }

    fn validateRemoteAssets(
        self: *Publisher,
        release: *const Release,
    ) Error!void {
        if (release.assets.len != self.assets.len) return self.fail(
            "remote release has {d} assets, expected {d}",
            .{ release.assets.len, self.assets.len },
        );
        for (self.assets) |*local| {
            var match: ?RemoteAsset = null;
            for (release.assets) |remote| {
                if (!std.mem.eql(u8, local.name, remote.name)) continue;
                if (match != null) return self.fail(
                    "remote release has duplicate asset {s}",
                    .{local.name},
                );
                match = remote;
            }
            const remote = match orelse return self.fail(
                "remote release is missing asset {s}",
                .{local.name},
            );
            if (remote.size != local.size) return self.fail(
                "remote release asset {s} has size {d}, expected {d}",
                .{ local.name, remote.size, local.size },
            );
            if (remote.state != .uploaded) return self.fail(
                "remote release asset {s} is not fully uploaded",
                .{local.name},
            );
            const remote_digest = remote.digest_text orelse return self.fail(
                "remote release asset {s} has no digest",
                .{local.name},
            );
            const expected = try std.fmt.allocPrint(
                self.allocator,
                "sha256:{s}",
                .{&local.digest_hex},
            );
            defer self.allocator.free(expected);
            if (!std.mem.eql(u8, remote_digest, expected)) return self.fail(
                "remote release asset {s} has digest {s}, expected {s}",
                .{ local.name, remote_digest, expected },
            );
            local.remote_id = remote.id;
        }
        for (release.assets) |remote| {
            if (findAsset(self.assets, remote.name) == null) return self.fail(
                "remote release has unexpected asset {s}",
                .{remote.name},
            );
        }
    }

    fn validateOneRemoteAsset(
        self: *Publisher,
        release: *const Release,
        local: *const Asset,
    ) Error!void {
        var match: ?RemoteAsset = null;
        for (release.assets) |remote| {
            if (!std.mem.eql(u8, local.name, remote.name)) continue;
            if (match != null) return self.fail(
                "remote release has duplicate asset {s}",
                .{local.name},
            );
            match = remote;
        }
        const remote = match orelse return self.fail(
            "remote release is missing newly uploaded asset {s}",
            .{local.name},
        );
        if (!remoteMatchesLocal(remote, local)) return self.fail(
            "newly uploaded release asset {s} does not match its local digest, size, and uploaded state",
            .{local.name},
        );
    }

    fn validateRemoteSubset(
        self: *Publisher,
        release: *const Release,
    ) Error!void {
        for (release.assets, 0..) |remote, index| {
            const local_index = findAsset(self.assets, remote.name) orelse
                return self.fail(
                    "draft release has unexpected asset {s}",
                    .{remote.name},
                );
            for (release.assets[0..index]) |previous| {
                if (std.mem.eql(u8, previous.name, remote.name)) {
                    return self.fail(
                        "draft release has duplicate asset {s}",
                        .{remote.name},
                    );
                }
            }
            if (!remoteMatchesLocal(remote, &self.assets[local_index])) {
                return self.fail(
                    "draft release asset {s} is not an exact uploaded local asset",
                    .{remote.name},
                );
            }
        }
    }

    fn downloadAndVerify(self: *Publisher, asset: *const Asset) Error!void {
        if (asset.remote_id <= 0) return self.fail(
            "remote id for {s} was not validated",
            .{asset.name},
        );
        const remote_directory = std.fs.path.join(
            self.allocator,
            &.{ self.options.workspace, "remote" },
        ) catch return error.OutOfMemory;
        defer self.allocator.free(remote_directory);
        Dir.cwd().createDirPath(self.io, remote_directory) catch |err|
            return self.fail("cannot create release verification directory: {t}", .{err});
        const output_path = std.fs.path.join(
            self.allocator,
            &.{ remote_directory, asset.name },
        ) catch return error.OutOfMemory;
        defer self.allocator.free(output_path);
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases/assets/{d}",
            .{ self.options.repository_name, asset.remote_id },
        ) catch return self.fail("asset endpoint is too long", .{});
        try self.ghToFile(&.{
            "api",
            "-H",
            "Accept: application/octet-stream",
            endpoint,
        }, output_path);
        const downloaded = hashRegularNoSymlink(self.io, output_path) catch |err|
            return self.fail("cannot hash downloaded asset {s}: {t}", .{ asset.name, err });
        if (downloaded.size != asset.size or
            !std.mem.eql(u8, &downloaded.hex, &asset.digest_hex))
        {
            return self.fail(
                "downloaded release asset does not match local revision: {s}",
                .{asset.name},
            );
        }
    }

    fn ghToFile(
        self: *Publisher,
        arguments: []const []const u8,
        output_path: []const u8,
    ) Error!void {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        argv.append(self.allocator, self.options.gh_executable) catch
            return error.OutOfMemory;
        argv.appendSlice(self.allocator, arguments) catch
            return error.OutOfMemory;
        var environment = std.process.Environ.createMap(
            self.options.environment,
            self.allocator,
        ) catch return error.OutOfMemory;
        defer environment.deinit();
        environment.put("MIZ_RELEASE_POLICY_GH_TOKEN", "") catch
            return error.OutOfMemory;
        var child = std.process.spawn(self.io, .{
            .argv = argv.items,
            .environ_map = &environment,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch |err| return self.fail("cannot execute GitHub CLI: {t}", .{err});
        var child_alive = true;
        defer if (child_alive) child.kill(self.io);
        var output = Dir.cwd().createFile(self.io, output_path, .{
            .truncate = true,
            .exclusive = false,
        }) catch |err| return self.fail(
            "cannot create downloaded asset {s}: {t}",
            .{ output_path, err },
        );
        defer output.close(self.io);
        var stdout_buffer: [64 * 1024]u8 = undefined;
        var stdout = child.stdout.?.readerStreaming(self.io, &stdout_buffer);
        var copy_buffer: [64 * 1024]u8 = undefined;
        while (true) {
            const count = stdout.interface.readSliceShort(&copy_buffer) catch |err|
                return self.fail("cannot download release asset: {t}", .{err});
            if (count == 0) break;
            output.writeStreamingAll(self.io, copy_buffer[0..count]) catch |err|
                return self.fail("cannot write downloaded release asset: {t}", .{err});
        }
        var stderr_buffer: [16 * 1024]u8 = undefined;
        var stderr = child.stderr.?.readerStreaming(self.io, &stderr_buffer);
        const stderr_text = stderr.interface.allocRemaining(
            self.allocator,
            .limited(stderr_buffer.len),
        ) catch |err| return self.fail(
            "cannot read GitHub CLI diagnostics: {t}",
            .{err},
        );
        defer self.allocator.free(stderr_text);
        const term = child.wait(self.io) catch |err|
            return self.fail("cannot wait for GitHub CLI: {t}", .{err});
        child_alive = false;
        const succeeded = switch (term) {
            .exited => |code| code == 0,
            else => false,
        };
        if (!succeeded) return self.fail(
            "GitHub CLI download failed: {s}",
            .{std.mem.trim(u8, stderr_text, " \t\r\n")},
        );
    }

    fn publish(self: *Publisher) Error!void {
        var draft = try self.fetch(true, .require_uploaded);
        defer draft.deinit(self.allocator);
        try self.validateRemoteAssets(&draft);
        for (self.assets) |*asset| try self.revalidateLocal(asset);

        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases/{d}",
            .{ self.options.repository_name, self.release_id },
        ) catch return self.fail("release endpoint is too long", .{});
        const prerelease = if (self.metadata.prerelease) "true" else "false";
        const latest = if (self.metadata.prerelease) "false" else "true";
        const tag_field = try fieldAlloc(self, "tag_name", self.metadata.tag);
        defer self.allocator.free(tag_field);
        const target_field = try fieldAlloc(
            self,
            "target_commitish",
            self.metadata.commit,
        );
        defer self.allocator.free(target_field);
        const name_field = try fieldAlloc(self, "name", self.metadata.title);
        defer self.allocator.free(name_field);
        const body_field = try fieldAlloc(self, "body", self.metadata.body);
        defer self.allocator.free(body_field);
        const prerelease_field = try fieldAlloc(self, "prerelease", prerelease);
        defer self.allocator.free(prerelease_field);
        const latest_field = try fieldAlloc(self, "make_latest", latest);
        defer self.allocator.free(latest_field);
        try self.verifyTag();
        try self.requireReleasePolicy();
        var result = try self.ghJson(&.{
            "api",
            "--method",
            "PATCH",
            endpoint,
            "-f",
            tag_field,
            "-f",
            target_field,
            "-f",
            name_field,
            "-f",
            body_field,
            "-F",
            "draft=false",
            "-F",
            prerelease_field,
            "-f",
            latest_field,
        });
        defer result.deinit();
        var published_response = try self.parseRelease(
            result.value,
            .exact,
            .require_uploaded,
        );
        defer published_response.deinit(self.allocator);
        if (published_response.draft) return self.fail(
            "GitHub did not publish release {s}",
            .{self.metadata.tag},
        );
    }

    fn validateFinal(self: *Publisher) Error!void {
        try self.verifyTag();
        var release = try self.fetch(false, .require_uploaded);
        defer release.deinit(self.allocator);
        try self.validateRemoteAssets(&release);
        if (!release.immutable) return self.fail(
            "published release is not immutable",
            .{},
        );
        // GitHub excludes prereleases from the latest-release endpoint. The
        // publish request also sets make_latest=false explicitly, so there is
        // no stable latest release that must exist merely to prove exclusion.
        if (self.metadata.prerelease) return;

        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases/latest",
            .{self.options.repository_name},
        ) catch return self.fail("latest release endpoint is too long", .{});
        var latest = try self.ghJson(&.{ "api", endpoint });
        defer latest.deinit();
        if (latest.value != .object) return self.fail(
            "latest release response is not an object",
            .{},
        );
        const latest_id = integerField(
            self,
            &latest.value.object,
            "id",
            "latest release id",
        ) catch return error.Failed;
        if (latest_id != self.release_id) {
            return self.fail(
                "stable release {s} was not made latest",
                .{self.metadata.tag},
            );
        }
    }

    fn requireReleasePolicy(self: *Publisher) Error!void {
        const token = self.options.policy_token orelse return self.fail(
            "release policy token is missing",
            .{},
        );
        if (std.mem.trim(u8, token, " \t\r\n").len == 0) return self.fail(
            "release policy token is missing",
            .{},
        );
        var immutable_endpoint_buffer: [512]u8 = undefined;
        const immutable_endpoint = std.fmt.bufPrint(
            &immutable_endpoint_buffer,
            "repos/{s}/immutable-releases",
            .{self.options.repository_name},
        ) catch return self.fail("immutable release endpoint is too long", .{});
        var immutable_response = try self.ghJsonWithToken(&.{
            "api",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: " ++ github_api_version,
            immutable_endpoint,
        }, token);
        defer immutable_response.deinit();
        try validateImmutableReleasesValue(
            immutable_response.value,
            self.diagnostic,
        );

        var ruleset_list_endpoint_buffer: [512]u8 = undefined;
        const ruleset_list_endpoint = std.fmt.bufPrint(
            &ruleset_list_endpoint_buffer,
            "repos/{s}/rulesets?includes_parents=true&targets=tag&per_page=100",
            .{self.options.repository_name},
        ) catch return self.fail("rulesets endpoint is too long", .{});
        var ruleset_list_response = try self.ghJsonWithToken(&.{
            "api",
            "--method",
            "GET",
            "--paginate",
            "--slurp",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: " ++ github_api_version,
            ruleset_list_endpoint,
        }, token);
        defer ruleset_list_response.deinit();
        const ruleset_id = try selectImmutableTagRulesetIdValue(
            ruleset_list_response.value,
            self.options.repository_name,
            self.diagnostic,
        );

        var ruleset_detail_endpoint_buffer: [512]u8 = undefined;
        const ruleset_detail_endpoint = std.fmt.bufPrint(
            &ruleset_detail_endpoint_buffer,
            "repos/{s}/rulesets/{d}?includes_parents=true",
            .{ self.options.repository_name, ruleset_id },
        ) catch return self.fail("ruleset detail endpoint is too long", .{});
        var ruleset_detail_response = try self.ghJsonWithToken(&.{
            "api",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: " ++ github_api_version,
            ruleset_detail_endpoint,
        }, token);
        defer ruleset_detail_response.deinit();
        try validateImmutableTagRulesetDetailValue(
            ruleset_detail_response.value,
            ruleset_id,
            self.options.repository_name,
            self.diagnostic,
        );
    }

    fn writeSummary(self: *Publisher) Error!void {
        const path = self.options.summary_path orelse return;
        var file = Dir.cwd().openFile(self.io, path, .{
            .mode = .write_only,
        }) catch |err| return self.fail(
            "cannot open GitHub step summary: {t}",
            .{err},
        );
        defer file.close(self.io);
        const size = file.stat(self.io) catch |err| return self.fail(
            "cannot stat GitHub step summary: {t}",
            .{err},
        );
        var buffer: [4096]u8 = undefined;
        const text = std.fmt.bufPrint(
            &buffer,
            "### miz release published\n\n- Release: https://github.com/{s}/releases/tag/{s}\n- Commit: `{s}`\n- Assets: {d}, independently downloaded and verified\n",
            .{
                self.options.repository_name,
                self.metadata.tag,
                self.metadata.commit,
                self.assets.len,
            },
        ) catch return self.fail("release summary is too long", .{});
        file.writePositionalAll(self.io, text, size.size) catch |err|
            return self.fail("cannot write GitHub step summary: {t}", .{err});
    }
};

pub fn publish(
    allocator: Allocator,
    io: Io,
    options: PublishOptions,
    diagnostic: *Diagnostic,
) Error!void {
    if (!std.mem.eql(u8, options.repository_name, repository)) return diagnostic.fail(
        error.Failed,
        "release repository must be {s}",
        .{repository},
    );
    if (!validCommit(options.commit)) return diagnostic.fail(
        error.Failed,
        "workflow commit must be a lowercase 40-character SHA",
        .{},
    );
    try validateVersionTag(options.version, options.tag, diagnostic);

    const title = std.fmt.allocPrint(
        allocator,
        "miz {s}",
        .{options.version},
    ) catch return error.OutOfMemory;
    defer allocator.free(title);
    const install_preamble = std.fmt.allocPrint(
        allocator,
        "**Install:**\n\n```console\nghr install {s}@{s}\n```\n",
        .{ options.repository_name, options.tag },
    ) catch return error.OutOfMemory;
    defer allocator.free(install_preamble);
    const prerelease = std.mem.indexOfScalar(
        u8,
        std.mem.sliceTo(options.version, '+'),
        '-',
    ) != null;

    const assets = try validateLocalAssets(
        allocator,
        io,
        options.assets_directory,
        options.version,
        diagnostic,
    );
    defer {
        for (assets) |asset| {
            allocator.free(asset.name);
            allocator.free(asset.path);
        }
        allocator.free(assets);
    }
    Dir.cwd().deleteTree(io, options.workspace) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot reset release workspace: {t}",
        .{err},
    );
    Dir.cwd().createDirPath(io, options.workspace) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot create release workspace: {t}",
        .{err},
    );

    var publisher: Publisher = .{
        .allocator = allocator,
        .io = io,
        .diagnostic = diagnostic,
        .options = options,
        .metadata = .{
            .tag = options.tag,
            .commit = options.commit,
            .title = title,
            .body = install_preamble,
            .prerelease = prerelease,
        },
        .assets = assets,
    };
    defer if (publisher.previous_main_tag) |tag| allocator.free(tag);
    try publisher.requireReleasePolicy();
    try publisher.verifyTag();
    const discovered = try publisher.discover();
    var owned_body: ?[]u8 = null;
    defer if (owned_body) |body| allocator.free(body);
    var release: Release = if (discovered) |existing| retained: {
        owned_body = allocator.dupe(u8, existing.body) catch
            return error.OutOfMemory;
        publisher.metadata.body = owned_body.?;
        break :retained existing;
    } else fresh: {
        const generated_notes = try publisher.generateNotes();
        defer allocator.free(generated_notes);
        owned_body = std.mem.concat(
            allocator,
            u8,
            &.{ install_preamble, "\n\n", generated_notes },
        ) catch return error.OutOfMemory;
        publisher.metadata.body = owned_body.?;
        break :fresh try publisher.createDraft();
    };
    defer release.deinit(allocator);
    publisher.release_id = release.id;
    if (!release.draft) return publisher.fail(
        "release {s} is not a draft",
        .{options.tag},
    );
    var fresh_draft = try publisher.fetch(true, .allow_incomplete);
    fresh_draft.deinit(allocator);
    try publisher.repairDraftAssets();
    for (assets) |*asset| try publisher.upload(asset);
    try publisher.deleteStale();
    var uploaded = try publisher.fetch(true, .require_uploaded);
    defer uploaded.deinit(allocator);
    try publisher.validateRemoteAssets(&uploaded);
    for (assets) |*asset| try publisher.downloadAndVerify(asset);
    try publisher.publish();
    publisher.validateFinal() catch |err| {
        if (err == error.Failed) {
            const detail = allocator.dupe(u8, diagnostic.message()) catch
                return error.OutOfMemory;
            defer allocator.free(detail);
            diagnostic.set(
                "published release {s} failed final verification; quarantine and inspect it without mutation: {s}",
                .{ options.tag, detail },
            );
        }
        return err;
    };
    publisher.writeSummary() catch |err| {
        if (err == error.Failed) {
            const detail = allocator.dupe(u8, diagnostic.message()) catch
                return error.OutOfMemory;
            defer allocator.free(detail);
            diagnostic.set(
                "published release {s} could not be fully reported; inspect it without mutation: {s}",
                .{ options.tag, detail },
            );
        }
        return err;
    };
}

fn remoteMatchesLocal(remote: RemoteAsset, local: *const Asset) bool {
    if (remote.state != .uploaded or remote.size != local.size) return false;
    const remote_digest = remote.digest_text orelse return false;
    if (!std.mem.startsWith(u8, remote_digest, "sha256:")) return false;
    return std.mem.eql(u8, remote_digest["sha256:".len..], &local.digest_hex);
}

fn classifyRemoteAsset(
    local_assets: []const Asset,
    remote_assets: []const RemoteAsset,
    remote: RemoteAsset,
) ?DeleteReason {
    const local_index = findAsset(local_assets, remote.name) orelse
        return .unexpected;
    var same_name_count: usize = 0;
    var exact_same_name_count: usize = 0;
    for (remote_assets) |candidate| {
        if (!std.mem.eql(u8, candidate.name, remote.name)) continue;
        same_name_count += 1;
        if (remoteMatchesLocal(candidate, &local_assets[local_index])) {
            exact_same_name_count += 1;
        }
    }
    const local = &local_assets[local_index];
    if (same_name_count > 1 and remoteMatchesLocal(remote, local)) {
        if (exact_same_name_count == 1) return null;
        return .duplicate;
    }
    if (remote.state != .uploaded) return .incomplete;
    if (remote.size != local.size) return .wrong_size;
    const remote_digest = remote.digest_text orelse return .wrong_digest;
    if (!std.mem.startsWith(u8, remote_digest, "sha256:") or
        !std.mem.eql(u8, remote_digest["sha256:".len..], &local.digest_hex))
    {
        return .wrong_digest;
    }
    return null;
}

fn safeUploadAssetName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |character| switch (character) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
        else => return false,
    };
    return true;
}

fn isLowerSha256(text: []const u8) bool {
    if (text.len != 64) return false;
    for (text) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

fn validateCoreMetadataObject(
    object: *const std.json.ObjectMap,
    expected: ExpectedMetadata,
    diagnostic: *Diagnostic,
) Error!void {
    const fields = [_]struct {
        key: []const u8,
        label: []const u8,
        expected: []const u8,
    }{
        .{ .key = "tag_name", .label = "release tag", .expected = expected.tag },
        .{
            .key = "target_commitish",
            .label = "release target",
            .expected = expected.commit,
        },
        .{ .key = "name", .label = "release title", .expected = expected.title },
    };
    for (fields) |field| {
        const value = object.get(field.key) orelse return diagnostic.fail(
            error.Failed,
            "{s} is missing",
            .{field.label},
        );
        if (value != .string or !std.mem.eql(u8, value.string, field.expected)) {
            return diagnostic.fail(
                error.Failed,
                "{s} does not match the publication contract",
                .{field.label},
            );
        }
    }
    const prerelease = object.get("prerelease") orelse return diagnostic.fail(
        error.Failed,
        "release prerelease state is missing",
        .{},
    );
    if (prerelease != .bool or prerelease.bool != expected.prerelease) {
        return diagnostic.fail(
            error.Failed,
            "release prerelease state does not match the publication contract",
            .{},
        );
    }
}

pub fn validateMetadataObject(
    object: *const std.json.ObjectMap,
    expected: ExpectedMetadata,
    diagnostic: *Diagnostic,
) Error!void {
    try validateCoreMetadataObject(object, expected, diagnostic);
    const body = object.get("body") orelse return diagnostic.fail(
        error.Failed,
        "release body is missing",
        .{},
    );
    if (body != .string or !std.mem.eql(u8, body.string, expected.body)) {
        return diagnostic.fail(
            error.Failed,
            "release body does not match the publication contract",
            .{},
        );
    }
}

fn validateRetainedReleaseBody(
    body: []const u8,
    install_preamble: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    if (!std.mem.startsWith(u8, body, install_preamble)) {
        return diagnostic.fail(
            error.Failed,
            "retained release body does not begin with the exact install preamble",
            .{},
        );
    }
    const remainder = body[install_preamble.len..];
    if (!std.mem.startsWith(u8, remainder, "\n\n")) {
        return diagnostic.fail(
            error.Failed,
            "retained release body does not preserve the generated-notes separator",
            .{},
        );
    }
    if (std.mem.trim(u8, remainder["\n\n".len..], " \t\r\n").len == 0) {
        return diagnostic.fail(
            error.Failed,
            "retained release body has no generated notes",
            .{},
        );
    }
}

pub fn validateImmutableReleasesValue(
    value: Value,
    diagnostic: *Diagnostic,
) Error!void {
    if (value != .object) return diagnostic.fail(
        error.Failed,
        "immutable releases response is not an object",
        .{},
    );
    const enabled = value.object.get("enabled") orelse return diagnostic.fail(
        error.Failed,
        "immutable releases enabled state is missing",
        .{},
    );
    if (enabled != .bool) return diagnostic.fail(
        error.Failed,
        "immutable releases enabled state is not boolean",
        .{},
    );
    if (!enabled.bool) return diagnostic.fail(
        error.Failed,
        "immutable releases are disabled",
        .{},
    );
}

pub fn selectImmutableTagRulesetIdValue(
    value: Value,
    expected_repository: []const u8,
    diagnostic: *Diagnostic,
) Error!i64 {
    if (value != .array) return diagnostic.fail(
        error.Failed,
        "paginated ruleset response is not an array",
        .{},
    );

    var matching_id: ?i64 = null;
    for (value.array.items) |page| {
        if (page != .array) return diagnostic.fail(
            error.Failed,
            "paginated ruleset page is not an array",
            .{},
        );
        for (page.array.items) |entry| {
            if (entry != .object) return diagnostic.fail(
                error.Failed,
                "ruleset listing entry is not an object",
                .{},
            );
            const id = entry.object.get("id") orelse return diagnostic.fail(
                error.Failed,
                "ruleset listing id is missing",
                .{},
            );
            if (id != .integer or id.integer <= 0) return diagnostic.fail(
                error.Failed,
                "ruleset listing id is invalid",
                .{},
            );
            const name = entry.object.get("name") orelse return diagnostic.fail(
                error.Failed,
                "ruleset listing name is missing",
                .{},
            );
            if (name != .string) return diagnostic.fail(
                error.Failed,
                "ruleset listing name is not a string",
                .{},
            );
            if (!std.mem.eql(u8, name.string, immutable_tag_ruleset_name)) continue;
            if (matching_id != null) return diagnostic.fail(
                error.Failed,
                "immutable release tag ruleset is ambiguous",
                .{},
            );
            const expected_fields = [_]struct {
                key: []const u8,
                expected: []const u8,
                label: []const u8,
            }{
                .{ .key = "target", .expected = "tag", .label = "target" },
                .{ .key = "source_type", .expected = "Repository", .label = "source type" },
                .{ .key = "source", .expected = expected_repository, .label = "source" },
                .{ .key = "enforcement", .expected = "active", .label = "enforcement" },
            };
            for (expected_fields) |field| {
                const actual = entry.object.get(field.key) orelse
                    return diagnostic.fail(
                        error.Failed,
                        "immutable release tag ruleset listing {s} is missing",
                        .{field.label},
                    );
                if (actual != .string or
                    !std.mem.eql(u8, actual.string, field.expected))
                {
                    return diagnostic.fail(
                        error.Failed,
                        "immutable release tag ruleset listing {s} is not {s}",
                        .{ field.label, field.expected },
                    );
                }
            }
            matching_id = id.integer;
        }
    }
    return matching_id orelse return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset is missing",
        .{},
    );
}

pub fn validateImmutableTagRulesetDetailValue(
    value: Value,
    expected_id: i64,
    expected_repository: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    if (value != .object) return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset detail is not an object",
        .{},
    );
    const ruleset = &value.object;
    const id = ruleset.get("id") orelse return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset detail id is missing",
        .{},
    );
    if (id != .integer or id.integer <= 0) return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset detail id is invalid",
        .{},
    );
    if (id.integer != expected_id) return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset detail id does not match the listing",
        .{},
    );
    const name = ruleset.get("name") orelse return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset detail name is missing",
        .{},
    );
    if (name != .string or
        !std.mem.eql(u8, name.string, immutable_tag_ruleset_name))
    {
        return diagnostic.fail(
            error.Failed,
            "immutable release tag ruleset detail name is not {s}",
            .{immutable_tag_ruleset_name},
        );
    }

    const expected_fields = [_]struct {
        key: []const u8,
        expected: []const u8,
        label: []const u8,
    }{
        .{ .key = "target", .expected = "tag", .label = "target" },
        .{ .key = "source_type", .expected = "Repository", .label = "source type" },
        .{ .key = "source", .expected = expected_repository, .label = "source" },
        .{ .key = "enforcement", .expected = "active", .label = "enforcement" },
    };
    for (expected_fields) |field| {
        const actual = ruleset.get(field.key) orelse return diagnostic.fail(
            error.Failed,
            "immutable release tag ruleset detail {s} is missing",
            .{field.label},
        );
        if (actual != .string or !std.mem.eql(u8, actual.string, field.expected)) {
            return diagnostic.fail(
                error.Failed,
                "immutable release tag ruleset detail {s} is not {s}",
                .{ field.label, field.expected },
            );
        }
    }

    const bypass_actors = ruleset.get("bypass_actors") orelse
        return diagnostic.fail(
            error.Failed,
            "immutable release tag ruleset bypass actors are not visible; Administration: write is required",
            .{},
        );
    if (bypass_actors != .array) return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset bypass actors are not an array",
        .{},
    );
    if (bypass_actors.array.items.len != 0) return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset has a bypass actor",
        .{},
    );

    const conditions = ruleset.get("conditions") orelse return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset conditions are missing",
        .{},
    );
    if (conditions != .object or conditions.object.count() != 1) {
        return diagnostic.fail(
            error.Failed,
            "immutable release tag ruleset conditions are not exact",
            .{},
        );
    }
    const ref_name = conditions.object.get("ref_name") orelse
        return diagnostic.fail(
            error.Failed,
            "immutable release tag ruleset ref-name condition is missing",
            .{},
        );
    if (ref_name != .object or ref_name.object.count() != 2) {
        return diagnostic.fail(
            error.Failed,
            "immutable release tag ruleset ref-name condition is not exact",
            .{},
        );
    }
    const include = ref_name.object.get("include") orelse return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset includes are missing",
        .{},
    );
    if (include != .array) return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset includes are not an array",
        .{},
    );
    if (include.array.items.len != 1 or
        include.array.items[0] != .string or
        !std.mem.eql(u8, include.array.items[0].string, "~ALL"))
    {
        return diagnostic.fail(
            error.Failed,
            "immutable release tag ruleset does not include exactly ~ALL",
            .{},
        );
    }
    const exclude = ref_name.object.get("exclude") orelse return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset exclusions are missing",
        .{},
    );
    if (exclude != .array or exclude.array.items.len != 0) {
        return diagnostic.fail(
            error.Failed,
            "immutable release tag ruleset has exclusions",
            .{},
        );
    }

    const rules = ruleset.get("rules") orelse return diagnostic.fail(
        error.Failed,
        "immutable release tag rules are missing",
        .{},
    );
    if (rules != .array) return diagnostic.fail(
        error.Failed,
        "immutable release tag rules are not an array",
        .{},
    );
    var update_count: usize = 0;
    var deletion_count: usize = 0;
    for (rules.array.items) |rule| {
        if (rule != .object) return diagnostic.fail(
            error.Failed,
            "immutable release tag rule is not an object",
            .{},
        );
        const rule_type = rule.object.get("type") orelse return diagnostic.fail(
            error.Failed,
            "immutable release tag rule type is missing",
            .{},
        );
        if (rule_type != .string) return diagnostic.fail(
            error.Failed,
            "immutable release tag rule type is not a string",
            .{},
        );
        if (std.mem.eql(u8, rule_type.string, "update")) {
            update_count += 1;
        } else if (std.mem.eql(u8, rule_type.string, "deletion")) {
            deletion_count += 1;
        } else {
            return diagnostic.fail(
                error.Failed,
                "immutable release tag ruleset contains unsupported rule {s}",
                .{rule_type.string},
            );
        }
    }
    if (update_count != 1 or deletion_count != 1) return diagnostic.fail(
        error.Failed,
        "immutable release tag ruleset must contain exactly one update and one deletion rule",
        .{},
    );
}

pub fn validateImmutableReleasesFile(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const bytes = file_support.readBounded(
        allocator,
        io,
        path,
        1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read immutable releases response: {t}",
        .{err},
    );
    defer allocator.free(bytes);
    var parsed = std.json.parseFromSlice(
        Value,
        allocator,
        bytes,
        .{},
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot parse immutable releases response: {t}",
        .{err},
    );
    defer parsed.deinit();
    try validateImmutableReleasesValue(parsed.value, diagnostic);
}

pub fn selectImmutableTagRulesetIdFile(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    expected_repository: []const u8,
    diagnostic: *Diagnostic,
) Error!i64 {
    const bytes = file_support.readBounded(
        allocator,
        io,
        path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read rulesets response: {t}",
        .{err},
    );
    defer allocator.free(bytes);
    var parsed = std.json.parseFromSlice(
        Value,
        allocator,
        bytes,
        .{},
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot parse ruleset list response: {t}",
        .{err},
    );
    defer parsed.deinit();
    return selectImmutableTagRulesetIdValue(
        parsed.value,
        expected_repository,
        diagnostic,
    );
}

pub fn validateImmutableTagRulesetDetailFile(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    expected_id: i64,
    expected_repository: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const bytes = file_support.readBounded(
        allocator,
        io,
        path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read ruleset detail response: {t}",
        .{err},
    );
    defer allocator.free(bytes);
    var parsed = std.json.parseFromSlice(
        Value,
        allocator,
        bytes,
        .{},
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot parse ruleset detail response: {t}",
        .{err},
    );
    defer parsed.deinit();
    try validateImmutableTagRulesetDetailValue(
        parsed.value,
        expected_id,
        expected_repository,
        diagnostic,
    );
}

pub fn validateRepositoryReleasePolicyFiles(
    allocator: Allocator,
    io: Io,
    immutable_releases_path: []const u8,
    ruleset_list_path: []const u8,
    ruleset_detail_path: []const u8,
    expected_repository: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    try validateImmutableReleasesFile(
        allocator,
        io,
        immutable_releases_path,
        diagnostic,
    );
    const ruleset_id = try selectImmutableTagRulesetIdFile(
        allocator,
        io,
        ruleset_list_path,
        expected_repository,
        diagnostic,
    );
    try validateImmutableTagRulesetDetailFile(
        allocator,
        io,
        ruleset_detail_path,
        ruleset_id,
        expected_repository,
        diagnostic,
    );
}

pub fn validateDraftMetadataFiles(
    allocator: Allocator,
    io: Io,
    release_path: []const u8,
    notes_path: []const u8,
    expected_without_body: ExpectedMetadata,
    diagnostic: *Diagnostic,
) Error!void {
    const release_bytes = file_support.readBounded(
        allocator,
        io,
        release_path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read release metadata: {t}",
        .{err},
    );
    defer allocator.free(release_bytes);
    var parsed = std.json.parseFromSlice(
        Value,
        allocator,
        release_bytes,
        .{},
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot parse release metadata: {t}",
        .{err},
    );
    defer parsed.deinit();
    if (parsed.value != .object) return diagnostic.fail(
        error.Failed,
        "release metadata is not an object",
        .{},
    );
    const notes = file_support.readBounded(
        allocator,
        io,
        notes_path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read release notes: {t}",
        .{err},
    );
    defer allocator.free(notes);
    var expected = expected_without_body;
    expected.body = notes;
    try validateMetadataObject(&parsed.value.object, expected, diagnostic);
    const draft = parsed.value.object.get("draft") orelse return diagnostic.fail(
        error.Failed,
        "release draft state is missing",
        .{},
    );
    if (draft != .bool or !draft.bool) return diagnostic.fail(
        error.Failed,
        "existing release is not a resumable draft",
        .{},
    );
}

pub const SingleAssetMode = enum {
    repair,
    final,
    published,
};

pub const DraftAssetTableMode = enum {
    repair,
    asset,
    subset,
    exact,
    published,
};

const ExpectedTableAsset = struct {
    name: []const u8,
    digest_hex: []const u8,
    size: u64,
};

pub fn validateDraftAssetTableFiles(
    allocator: Allocator,
    io: Io,
    release_path: []const u8,
    notes_path: []const u8,
    expected_path: []const u8,
    expected_release_id: i64,
    expected_without_body: ExpectedMetadata,
    mode: DraftAssetTableMode,
    asset_name: ?[]const u8,
    out: *std.Io.Writer,
    diagnostic: *Diagnostic,
) Error!void {
    const expected_text = file_support.readBounded(
        allocator,
        io,
        expected_path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read expected release assets: {t}",
        .{err},
    );
    defer allocator.free(expected_text);
    var expected: std.ArrayList(ExpectedTableAsset) = .empty;
    defer expected.deinit(allocator);
    var lines = std.mem.splitScalar(u8, expected_text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const name = fields.next() orelse return diagnostic.fail(
            error.Failed,
            "expected release asset row is invalid",
            .{},
        );
        const digest_hex = fields.next() orelse return diagnostic.fail(
            error.Failed,
            "expected release asset row is invalid",
            .{},
        );
        const size_text = fields.next() orelse return diagnostic.fail(
            error.Failed,
            "expected release asset row is invalid",
            .{},
        );
        if (fields.next() != null or !safeUploadAssetName(name) or
            !isLowerSha256(digest_hex))
        {
            return diagnostic.fail(
                error.Failed,
                "expected release asset row is invalid",
                .{},
            );
        }
        const size = std.fmt.parseInt(u64, size_text, 10) catch
            return diagnostic.fail(
                error.Failed,
                "expected release asset row is invalid",
                .{},
            );
        for (expected.items) |previous| {
            if (std.mem.eql(u8, previous.name, name)) return diagnostic.fail(
                error.Failed,
                "expected release asset name is duplicated: {s}",
                .{name},
            );
        }
        expected.append(allocator, .{
            .name = name,
            .digest_hex = digest_hex,
            .size = size,
        }) catch return error.OutOfMemory;
    }
    if (expected.items.len == 0) return diagnostic.fail(
        error.Failed,
        "expected release asset table is empty",
        .{},
    );

    const release_bytes = file_support.readBounded(
        allocator,
        io,
        release_path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read release metadata: {t}",
        .{err},
    );
    defer allocator.free(release_bytes);
    var parsed = std.json.parseFromSlice(
        Value,
        allocator,
        release_bytes,
        .{},
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot parse release metadata: {t}",
        .{err},
    );
    defer parsed.deinit();
    if (parsed.value != .object) return diagnostic.fail(
        error.Failed,
        "release metadata is not an object",
        .{},
    );
    const release_id = parsed.value.object.get("id") orelse
        return diagnostic.fail(
            error.Failed,
            "release id is missing",
            .{},
        );
    if (expected_release_id <= 0 or release_id != .integer or
        release_id.integer != expected_release_id)
    {
        return diagnostic.fail(
            error.Failed,
            "release id does not match the fixed numeric draft",
            .{},
        );
    }
    const notes = file_support.readBounded(
        allocator,
        io,
        notes_path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read release notes: {t}",
        .{err},
    );
    defer allocator.free(notes);
    var expected_metadata = expected_without_body;
    expected_metadata.body = notes;
    const object = &parsed.value.object;
    try validateMetadataObject(object, expected_metadata, diagnostic);
    const draft = object.get("draft") orelse return diagnostic.fail(
        error.Failed,
        "release draft state is missing",
        .{},
    );
    if (draft != .bool) return diagnostic.fail(
        error.Failed,
        "release draft state is missing",
        .{},
    );
    if (mode == .published) {
        if (draft.bool) return diagnostic.fail(
            error.Failed,
            "published release remained a draft",
            .{},
        );
        const immutable = object.get("immutable") orelse
            return diagnostic.fail(
                error.Failed,
                "published release immutable state is missing",
                .{},
            );
        if (immutable != .bool or !immutable.bool) return diagnostic.fail(
            error.Failed,
            "published release is not immutable",
            .{},
        );
    } else if (!draft.bool) return diagnostic.fail(
        error.Failed,
        "release is published and must not be mutated",
        .{},
    );
    const assets_value = object.get("assets") orelse return diagnostic.fail(
        error.Failed,
        "release assets are missing",
        .{},
    );
    if (assets_value != .array) return diagnostic.fail(
        error.Failed,
        "release assets are not an array",
        .{},
    );

    const wanted_asset = if (mode == .asset) asset_name orelse
        return diagnostic.fail(
            error.Failed,
            "asset validation requires an asset name",
            .{},
        ) else null;
    if (mode != .asset and asset_name != null) return diagnostic.fail(
        error.Failed,
        "asset name is valid only for asset validation",
        .{},
    );
    var wanted_index: ?usize = null;
    if (wanted_asset) |name| {
        for (expected.items, 0..) |item, index| {
            if (std.mem.eql(u8, item.name, name)) wanted_index = index;
        }
        if (wanted_index == null) return diagnostic.fail(
            error.Failed,
            "asset is outside the publication allowlist: {s}",
            .{name},
        );
    }

    const claimed = allocator.alloc(bool, expected.items.len) catch
        return error.OutOfMemory;
    defer allocator.free(claimed);
    @memset(claimed, false);
    for (assets_value.array.items, 0..) |asset_value, asset_position| {
        if (asset_value != .object) return diagnostic.fail(
            error.Failed,
            "release asset is not an object",
            .{},
        );
        const asset = &asset_value.object;
        const id_value = asset.get("id") orelse return diagnostic.fail(
            error.Failed,
            "release asset id is missing",
            .{},
        );
        if (id_value != .integer or id_value.integer <= 0) return diagnostic.fail(
            error.Failed,
            "release asset id is invalid",
            .{},
        );
        const id = id_value.integer;
        for (assets_value.array.items[0..asset_position]) |previous_value| {
            if (previous_value != .object) return diagnostic.fail(
                error.Failed,
                "release asset is not an object",
                .{},
            );
            const previous_id = previous_value.object.get("id") orelse
                return diagnostic.fail(
                    error.Failed,
                    "release asset id is missing",
                    .{},
                );
            if (previous_id != .integer) return diagnostic.fail(
                error.Failed,
                "release asset id is invalid",
                .{},
            );
            if (previous_id.integer == id) return diagnostic.fail(
                error.Failed,
                "release asset id is duplicated",
                .{},
            );
        }
        const name_value = asset.get("name") orelse return diagnostic.fail(
            error.Failed,
            "release asset name is missing",
            .{},
        );
        if (name_value != .string) return diagnostic.fail(
            error.Failed,
            "release asset name is invalid",
            .{},
        );
        const state_value = asset.get("state") orelse return diagnostic.fail(
            error.Failed,
            "release asset state is missing",
            .{},
        );
        if (state_value != .string or
            (!std.mem.eql(u8, state_value.string, "uploaded") and
                !std.mem.eql(u8, state_value.string, "starter")))
        {
            return diagnostic.fail(
                error.Failed,
                "release asset {s} has unknown state",
                .{name_value.string},
            );
        }
        const size_value = asset.get("size") orelse return diagnostic.fail(
            error.Failed,
            "release asset size is missing",
            .{},
        );
        if (size_value != .integer or size_value.integer < 0) {
            return diagnostic.fail(
                error.Failed,
                "release asset size is invalid",
                .{},
            );
        }
        const digest_value = asset.get("digest");
        if (digest_value != null and digest_value.? != .null and
            digest_value.? != .string)
        {
            return diagnostic.fail(
                error.Failed,
                "release asset digest is invalid",
                .{},
            );
        }

        var table_index: ?usize = null;
        var same_name_count: usize = 0;
        for (expected.items, 0..) |item, index| {
            if (std.mem.eql(u8, item.name, name_value.string)) {
                table_index = index;
            }
        }
        for (assets_value.array.items) |candidate_value| {
            if (candidate_value != .object) continue;
            const candidate_name = candidate_value.object.get("name") orelse
                continue;
            if (candidate_name == .string and
                std.mem.eql(u8, candidate_name.string, name_value.string))
            {
                same_name_count += 1;
            }
        }
        const exact = if (table_index) |index| blk: {
            const remote_digest = if (digest_value) |value|
                if (value == .string) value.string else null
            else
                null;
            const expected_digest = std.fmt.allocPrint(
                allocator,
                "sha256:{s}",
                .{expected.items[index].digest_hex},
            ) catch return error.OutOfMemory;
            defer allocator.free(expected_digest);
            break :blk same_name_count == 1 and
                std.mem.eql(u8, state_value.string, "uploaded") and
                @as(u64, @intCast(size_value.integer)) ==
                    expected.items[index].size and
                remote_digest != null and
                std.mem.eql(u8, remote_digest.?, expected_digest);
        } else false;
        if (mode == .repair) {
            if (!exact) out.print("{d}\n", .{id}) catch return diagnostic.fail(
                error.Failed,
                "cannot write release asset repair plan",
                .{},
            );
            continue;
        }
        if (!exact) return diagnostic.fail(
            error.Failed,
            "draft release asset is not an exact uploaded allowlist asset: {s}",
            .{name_value.string},
        );
        claimed[table_index.?] = true;
    }
    if (mode == .repair) return;
    if ((mode == .exact or mode == .published) and
        assets_value.array.items.len != expected.items.len)
    {
        return diagnostic.fail(
            error.Failed,
            "draft release does not have the exact asset cardinality",
            .{},
        );
    }
    if (mode == .exact or mode == .published) {
        for (claimed) |present| {
            if (!present) return diagnostic.fail(
                error.Failed,
                "draft release is missing an exact uploaded allowlist asset",
                .{},
            );
        }
        return;
    }
    if (mode == .asset) {
        out.writeAll(if (claimed[wanted_index.?]) "keep\n" else "upload\n") catch
            return diagnostic.fail(
                error.Failed,
                "cannot write release asset status",
                .{},
            );
    }
}

pub fn validateSingleDraftAssetFiles(
    allocator: Allocator,
    io: Io,
    release_path: []const u8,
    notes_path: []const u8,
    expected_without_body: ExpectedMetadata,
    expected_name: []const u8,
    expected_digest_hex: []const u8,
    expected_size: u64,
    mode: SingleAssetMode,
    out: *std.Io.Writer,
    diagnostic: *Diagnostic,
) Error!void {
    if (expected_digest_hex.len != 64) return diagnostic.fail(
        error.Failed,
        "expected release asset digest is not lowercase SHA-256",
        .{},
    );
    for (expected_digest_hex) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return diagnostic.fail(
            error.Failed,
            "expected release asset digest is not lowercase SHA-256",
            .{},
        ),
    };
    if (expected_size == 0) return diagnostic.fail(
        error.Failed,
        "expected release asset is empty",
        .{},
    );
    const release_bytes = file_support.readBounded(
        allocator,
        io,
        release_path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read release metadata: {t}",
        .{err},
    );
    defer allocator.free(release_bytes);
    var parsed = std.json.parseFromSlice(
        Value,
        allocator,
        release_bytes,
        .{},
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot parse release metadata: {t}",
        .{err},
    );
    defer parsed.deinit();
    if (parsed.value != .object) return diagnostic.fail(
        error.Failed,
        "release metadata is not an object",
        .{},
    );
    const notes = file_support.readBounded(
        allocator,
        io,
        notes_path,
        4 * 1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read release notes: {t}",
        .{err},
    );
    defer allocator.free(notes);
    var expected = expected_without_body;
    expected.body = notes;
    const object = &parsed.value.object;
    try validateMetadataObject(object, expected, diagnostic);
    const draft = object.get("draft") orelse return diagnostic.fail(
        error.Failed,
        "release draft state is missing",
        .{},
    );
    const immutable = object.get("immutable") orelse return diagnostic.fail(
        error.Failed,
        "release immutable state is missing",
        .{},
    );
    if (mode == .published) {
        if (draft != .bool or draft.bool) return diagnostic.fail(
            error.Failed,
            "published release remained a draft",
            .{},
        );
        if (immutable != .bool or !immutable.bool) return diagnostic.fail(
            error.Failed,
            "published release is not immutable",
            .{},
        );
    } else {
        if (draft != .bool or !draft.bool) return diagnostic.fail(
            error.Failed,
            "release is published and must not be repaired",
            .{},
        );
        if (immutable != .bool or immutable.bool) return diagnostic.fail(
            error.Failed,
            "draft release immutable state is invalid",
            .{},
        );
    }
    const assets_value = object.get("assets") orelse return diagnostic.fail(
        error.Failed,
        "release assets are missing",
        .{},
    );
    if (assets_value != .array) return diagnostic.fail(
        error.Failed,
        "release assets are not an array",
        .{},
    );

    const expected_digest = std.fmt.allocPrint(
        allocator,
        "sha256:{s}",
        .{expected_digest_hex},
    ) catch return error.OutOfMemory;
    defer allocator.free(expected_digest);
    var exact = assets_value.array.items.len == 1;
    for (assets_value.array.items, 0..) |asset_value, index| {
        if (asset_value != .object) return diagnostic.fail(
            error.Failed,
            "release asset is not an object",
            .{},
        );
        const asset = &asset_value.object;
        const id_value = asset.get("id") orelse return diagnostic.fail(
            error.Failed,
            "release asset id is missing",
            .{},
        );
        if (id_value != .integer or id_value.integer <= 0) return diagnostic.fail(
            error.Failed,
            "release asset id is invalid",
            .{},
        );
        for (assets_value.array.items[0..index]) |previous_value| {
            if (previous_value.object.get("id").?.integer == id_value.integer) {
                return diagnostic.fail(
                    error.Failed,
                    "release asset id is duplicated",
                    .{},
                );
            }
        }
        const name = asset.get("name") orelse return diagnostic.fail(
            error.Failed,
            "release asset name is missing",
            .{},
        );
        if (name != .string) return diagnostic.fail(
            error.Failed,
            "release asset name is invalid",
            .{},
        );
        const state = asset.get("state") orelse return diagnostic.fail(
            error.Failed,
            "release asset state is missing",
            .{},
        );
        if (state != .string) return diagnostic.fail(
            error.Failed,
            "release asset state is invalid",
            .{},
        );
        if (!std.mem.eql(u8, state.string, "uploaded") and
            !std.mem.eql(u8, state.string, "starter"))
        {
            return diagnostic.fail(
                error.Failed,
                "release asset {s} has unknown state {s}",
                .{ name.string, state.string },
            );
        }
        const size = asset.get("size") orelse return diagnostic.fail(
            error.Failed,
            "release asset size is missing",
            .{},
        );
        if (size != .integer or size.integer < 0) return diagnostic.fail(
            error.Failed,
            "release asset size is invalid",
            .{},
        );
        const digest_value = asset.get("digest");
        const digest_matches = if (digest_value) |value|
            value == .string and std.mem.eql(
                u8,
                value.string,
                expected_digest,
            )
        else
            false;
        exact = exact and
            std.mem.eql(u8, name.string, expected_name) and
            std.mem.eql(u8, state.string, "uploaded") and
            @as(u64, @intCast(size.integer)) == expected_size and
            digest_matches;
    }
    if (mode == .final or mode == .published) {
        if (!exact) return diagnostic.fail(
            error.Failed,
            "release asset set is not the exact uploaded publication asset",
            .{},
        );
        return;
    }
    if (exact) {
        out.writeAll("keep\n") catch return diagnostic.fail(
            error.Failed,
            "cannot write release asset repair plan",
            .{},
        );
        return;
    }
    out.writeAll("replace\n") catch return diagnostic.fail(
        error.Failed,
        "cannot write release asset repair plan",
        .{},
    );
    for (assets_value.array.items) |asset_value| {
        out.print("{d}\n", .{asset_value.object.get("id").?.integer}) catch
            return diagnostic.fail(
                error.Failed,
                "cannot write release asset repair plan",
                .{},
            );
    }
}

pub fn validateVersionTag(
    version: []const u8,
    tag: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    if (tag.len != version.len + 1 or tag[0] != 'v' or
        !std.mem.eql(u8, tag[1..], version))
    {
        return diagnostic.fail(
            error.Failed,
            "release tag {s} does not exactly match package version {s}",
            .{ tag, version },
        );
    }
    _ = std.SemanticVersion.parse(version) catch return diagnostic.fail(
        error.Failed,
        "release version {s} is not supported SemVer",
        .{version},
    );
}

pub fn manifestVersion(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) Error![]u8 {
    const source = file_support.readBounded(
        allocator,
        io,
        path,
        1024 * 1024,
    ) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot read package manifest: {t}",
        .{err},
    );
    defer allocator.free(source);
    const marker = ".version";
    var found: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, marker)) continue;
        var rest = std.mem.trimStart(u8, trimmed[marker.len..], " \t");
        if (rest.len == 0 or rest[0] != '=') continue;
        rest = std.mem.trimStart(u8, rest[1..], " \t");
        if (rest.len < 4 or rest[0] != '"') continue;
        const close = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse continue;
        const tail = std.mem.trim(u8, rest[close + 1 ..], " \t");
        if (!std.mem.eql(u8, tail, ",")) continue;
        if (found != null) return diagnostic.fail(
            error.Failed,
            "package manifest has more than one version",
            .{},
        );
        found = rest[1..close];
    }
    return allocator.dupe(u8, found orelse return diagnostic.fail(
        error.Failed,
        "package manifest has no exact version",
        .{},
    )) catch return error.OutOfMemory;
}

fn validateLocalAssets(
    allocator: Allocator,
    io: Io,
    directory_path: []const u8,
    version: []const u8,
    diagnostic: *Diagnostic,
) Error![]Asset {
    var expected_names: [platforms.len * 2][]u8 = undefined;
    var expected_count: usize = 0;
    defer for (expected_names[0..expected_count]) |name| allocator.free(name);
    for (platforms) |platform| {
        expected_names[expected_count] = std.fmt.allocPrint(
            allocator,
            "miz-{s}-{s}.tar.gz",
            .{ version, platform },
        ) catch return error.OutOfMemory;
        expected_count += 1;
        expected_names[expected_count] = std.fmt.allocPrint(
            allocator,
            "miz-{s}-{s}.sbom.spdx.json",
            .{ version, platform },
        ) catch return error.OutOfMemory;
        expected_count += 1;
    }

    var directory = Dir.cwd().openDir(io, directory_path, .{
        .iterate = true,
    }) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot open release asset directory: {t}",
        .{err},
    );
    defer directory.close(io);
    const prefix = std.fmt.allocPrint(
        allocator,
        "miz-{s}-",
        .{version},
    ) catch return error.OutOfMemory;
    defer allocator.free(prefix);
    var iterator = directory.iterate();
    while (iterator.next(io) catch |err| return diagnostic.fail(
        error.Failed,
        "cannot enumerate release assets: {t}",
        .{err},
    )) |entry| {
        const matching = std.mem.startsWith(u8, entry.name, prefix) and
            (std.mem.endsWith(u8, entry.name, ".tar.gz") or
                std.mem.endsWith(u8, entry.name, ".sbom.spdx.json"));
        if (!matching) continue;
        var allowed = false;
        for (expected_names[0..expected_count]) |name| {
            if (std.mem.eql(u8, entry.name, name)) allowed = true;
        }
        if (!allowed) return diagnostic.fail(
            error.Failed,
            "unexpected matching release asset: {s}",
            .{entry.name},
        );
    }

    const assets = allocator.alloc(Asset, expected_count) catch
        return error.OutOfMemory;
    errdefer allocator.free(assets);
    var initialized: usize = 0;
    errdefer for (assets[0..initialized]) |asset| {
        allocator.free(asset.name);
        allocator.free(asset.path);
    };
    for (expected_names[0..expected_count], assets) |name, *asset| {
        const path = std.fs.path.join(
            allocator,
            &.{ directory_path, name },
        ) catch return error.OutOfMemory;
        errdefer allocator.free(path);
        const hashed = hashRegularNoSymlink(io, path) catch |err| return diagnostic.fail(
            error.Failed,
            "release asset {s} is not a stable regular file: {t}",
            .{ name, err },
        );
        if (hashed.size == 0) return diagnostic.fail(
            error.Failed,
            "release asset is empty: {s}",
            .{name},
        );
        asset.* = .{
            .name = allocator.dupe(u8, name) catch return error.OutOfMemory,
            .path = path,
            .digest_hex = hashed.hex,
            .size = hashed.size,
            .identity = hashed.identity,
        };
        initialized += 1;
    }
    return assets;
}

fn hashRegularNoSymlink(io: Io, path: []const u8) !digest.FileDigest {
    const file = try Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    return digest.hashOpenFile(io, file, maximum_asset_bytes);
}

fn findAsset(assets: []const Asset, name: []const u8) ?usize {
    for (assets, 0..) |asset, index| {
        if (std.mem.eql(u8, asset.name, name)) return index;
    }
    return null;
}

fn validCommit(text: []const u8) bool {
    if (text.len != 40) return false;
    for (text) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

fn fieldAlloc(
    self: *Publisher,
    name: []const u8,
    value: []const u8,
) Error![]const u8 {
    return std.fmt.allocPrint(
        self.allocator,
        "{s}={s}",
        .{ name, value },
    ) catch error.OutOfMemory;
}

fn objectField(
    self: *Publisher,
    value: *const Value,
    name: []const u8,
    label: []const u8,
) Error!*const std.json.ObjectMap {
    if (value.* != .object) return self.fail("{s} parent is not an object", .{label});
    const field = value.object.getPtr(name) orelse return self.fail(
        "{s} is missing",
        .{label},
    );
    if (field.* != .object) return self.fail("{s} is not an object", .{label});
    return &field.object;
}

fn stringField(
    self: *Publisher,
    object: *const std.json.ObjectMap,
    name: []const u8,
    label: []const u8,
) Error![]const u8 {
    const value = object.get(name) orelse return self.fail("{s} is missing", .{label});
    if (value != .string) return self.fail("{s} is not a string", .{label});
    return value.string;
}

fn optionalStringField(
    self: *Publisher,
    object: *const std.json.ObjectMap,
    name: []const u8,
    label: []const u8,
) Error!?[]const u8 {
    const value = object.get(name) orelse return null;
    if (value == .null) return null;
    if (value != .string) return self.fail("{s} is not a string", .{label});
    return value.string;
}

fn integerField(
    self: *Publisher,
    object: *const std.json.ObjectMap,
    name: []const u8,
    label: []const u8,
) Error!i64 {
    const value = object.get(name) orelse return self.fail("{s} is missing", .{label});
    if (value != .integer) return self.fail("{s} is not an integer", .{label});
    return value.integer;
}

fn boolField(
    self: *Publisher,
    object: *const std.json.ObjectMap,
    name: []const u8,
    label: []const u8,
) Error!bool {
    const value = object.get(name) orelse return self.fail("{s} is missing", .{label});
    if (value != .bool) return self.fail("{s} is not a boolean", .{label});
    return value.bool;
}

fn optionalBoolField(
    self: *Publisher,
    object: *const std.json.ObjectMap,
    name: []const u8,
    label: []const u8,
) Error!?bool {
    const value = object.get(name) orelse return null;
    if (value == .null) return null;
    if (value != .bool) return self.fail("{s} is not a boolean", .{label});
    return value.bool;
}

test "version and tag contract distinguishes prerelease SemVer" {
    var diagnostic: Diagnostic = .{};
    try validateVersionTag("1.2.3", "v1.2.3", &diagnostic);
    try validateVersionTag("1.2.3-rc.1", "v1.2.3-rc.1", &diagnostic);
    try std.testing.expectError(
        error.Failed,
        validateVersionTag("1.2.3", "v1.2.4", &diagnostic),
    );
    try std.testing.expectError(
        error.Failed,
        validateVersionTag("01.2.3", "v01.2.3", &diagnostic),
    );
}

fn expectImmutableTagListFailure(
    json: []const u8,
    expected_diagnostic: []const u8,
) !void {
    var parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        json,
        .{},
    );
    defer parsed.deinit();
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(
        error.Failed,
        selectImmutableTagRulesetIdValue(
            parsed.value,
            repository,
            &diagnostic,
        ),
    );
    try std.testing.expect(
        std.mem.indexOf(u8, diagnostic.message(), expected_diagnostic) != null,
    );
}

fn expectImmutableTagDetailFailure(
    json: []const u8,
    expected_diagnostic: []const u8,
) !void {
    var parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        json,
        .{},
    );
    defer parsed.deinit();
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(
        error.Failed,
        validateImmutableTagRulesetDetailValue(
            parsed.value,
            665,
            repository,
            &diagnostic,
        ),
    );
    try std.testing.expect(
        std.mem.indexOf(u8, diagnostic.message(), expected_diagnostic) != null,
    );
}

test "global immutable tag ruleset list summaries fail closed" {
    const valid =
        \\[[{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active"}]]
    ;
    var parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        valid,
        .{},
    );
    defer parsed.deinit();
    var diagnostic: Diagnostic = .{};
    try std.testing.expectEqual(
        @as(i64, 665),
        try selectImmutableTagRulesetIdValue(
            parsed.value,
            repository,
            &diagnostic,
        ),
    );

    try expectImmutableTagListFailure(
        \\[[{"id":1,"name":"other"}]]
    ,
        "ruleset is missing",
    );
    try expectImmutableTagListFailure(
        \\[[{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active"},
        \\{"id":666,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active"}]]
    ,
        "ruleset is ambiguous",
    );
    try expectImmutableTagListFailure(
        \\[[{"id":0,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active"}]]
    ,
        "listing id is invalid",
    );
    try expectImmutableTagListFailure(
        \\[[{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"disabled"}]]
    ,
        "enforcement is not active",
    );
    try expectImmutableTagListFailure(
        \\[[{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"branch","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active"}]]
    ,
        "target is not tag",
    );
    try expectImmutableTagListFailure(
        \\[[{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Organization","source":"cataggar",
        \\"enforcement":"active"}]]
    ,
        "source type is not Repository",
    );
}

test "global immutable tag ruleset detail fixtures fail closed" {
    const prefix =
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
    ;
    const suffix =
        \\,"bypass_actors":[],"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
        \\"rules":[{"type":"update"},{"type":"deletion"}]}
    ;
    const valid = prefix ++ "\"enforcement\":\"active\"" ++ suffix;
    var parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        valid,
        .{},
    );
    defer parsed.deinit();
    var diagnostic: Diagnostic = .{};
    try validateImmutableTagRulesetDetailValue(
        parsed.value,
        665,
        repository,
        &diagnostic,
    );

    try expectImmutableTagDetailFailure(
        \\{"id":666,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active","bypass_actors":[],
        \\"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
        \\"rules":[{"type":"update"},{"type":"deletion"}]}
    ,
        "id does not match the listing",
    );
    try expectImmutableTagDetailFailure(
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"branch","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active","bypass_actors":[],
        \\"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
        \\"rules":[{"type":"update"},{"type":"deletion"}]}
    ,
        "target is not tag",
    );
    try expectImmutableTagDetailFailure(
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Organization","source":"cataggar",
        \\"enforcement":"active","bypass_actors":[],
        \\"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
        \\"rules":[{"type":"update"},{"type":"deletion"}]}
    ,
        "source type is not Repository",
    );
    try expectImmutableTagDetailFailure(
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active","bypass_actors":[],
        \\"conditions":{"ref_name":{"include":["refs/tags/v*"],"exclude":[]}},
        \\"rules":[{"type":"update"},{"type":"deletion"}]}
    ,
        "does not include exactly ~ALL",
    );
    try expectImmutableTagDetailFailure(
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active","bypass_actors":[],
        \\"conditions":{"ref_name":{"include":["~ALL"],"exclude":["refs/tags/test"]}},
        \\"rules":[{"type":"update"},{"type":"deletion"}]}
    ,
        "has exclusions",
    );
    try expectImmutableTagDetailFailure(
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active","bypass_actors":[],
        \\"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
        \\"rules":[{"type":"deletion"}]}
    ,
        "exactly one update and one deletion",
    );
    try expectImmutableTagDetailFailure(
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active","bypass_actors":[],
        \\"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
        \\"rules":[{"type":"creation"},{"type":"update"},{"type":"deletion"}]}
    ,
        "unsupported rule creation",
    );
    try expectImmutableTagDetailFailure(
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active","bypass_actors":[
        \\{"actor_id":123,"actor_type":"Integration","bypass_mode":"always"}],
        \\"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
        \\"rules":[{"type":"update"},{"type":"deletion"}]}
    ,
        "has a bypass actor",
    );
    try expectImmutableTagDetailFailure(
        \\{"id":665,"name":"miz-immutable-release-tags-v1",
        \\"target":"tag","source_type":"Repository","source":"cataggar/miz",
        \\"enforcement":"active",
        \\"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
        \\"rules":[{"type":"update"},{"type":"deletion"}]}
    ,
        "Administration: write is required",
    );
}

test "single draft asset repair plans fail closed and replace invalid sets" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const notes_path = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/notes.md",
        .{&tmp.sub_path},
    );
    defer allocator.free(notes_path);
    const release_path = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/release.json",
        .{&tmp.sub_path},
    );
    defer allocator.free(release_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = notes_path,
        .data = "exact notes",
    });
    const prefix =
        \\{"id":42,"tag_name":"capture-v1","target_commitish":"0123456789abcdef0123456789abcdef01234567","name":"capture","body":"exact notes","draft":
    ;
    const suffix = ",\"prerelease\":false,\"immutable\":false,\"assets\":";
    const cases = [_]struct {
        draft: []const u8,
        assets: []const u8,
        expected: ?[]const u8,
        error_needle: ?[]const u8 = null,
    }{
        .{
            .draft = "true",
            .assets =
            \\[{"id":1,"name":"result.json","size":0,"state":"starter","digest":null}]}
            ,
            .expected = "replace\n1\n",
        },
        .{
            .draft = "true",
            .assets =
            \\[{"id":2,"name":"result.json","size":7,"state":"uploaded","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}
            ,
            .expected = "replace\n2\n",
        },
        .{
            .draft = "true",
            .assets =
            \\[{"id":3,"name":"result.json","size":7,"state":"uploaded","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"id":4,"name":"unexpected.bin","size":1,"state":"uploaded","digest":null}]}
            ,
            .expected = "replace\n3\n4\n",
        },
        .{
            .draft = "true",
            .assets =
            \\[{"id":5,"name":"result.json","size":7,"state":"uploaded","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"id":6,"name":"result.json","size":0,"state":"starter","digest":null}]}
            ,
            .expected = "replace\n5\n6\n",
        },
        .{
            .draft = "true",
            .assets =
            \\[{"id":7,"name":"result.json","size":0,"state":"pending","digest":null}]}
            ,
            .expected = null,
            .error_needle = "unknown state",
        },
        .{
            .draft = "false",
            .assets = "[]}",
            .expected = null,
            .error_needle = "published",
        },
    };
    for (cases) |case| {
        const document = try std.mem.concat(
            allocator,
            u8,
            &.{ prefix, case.draft, suffix, case.assets },
        );
        defer allocator.free(document);
        try Dir.cwd().writeFile(io, .{
            .sub_path = release_path,
            .data = document,
        });
        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        var diagnostic: Diagnostic = .{};
        const result = validateSingleDraftAssetFiles(
            allocator,
            io,
            release_path,
            notes_path,
            .{
                .tag = "capture-v1",
                .commit = "0123456789abcdef0123456789abcdef01234567",
                .title = "capture",
                .body = "",
                .prerelease = false,
            },
            "result.json",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            7,
            .repair,
            &output.writer,
            &diagnostic,
        );
        if (case.expected) |expected| {
            try result;
            try std.testing.expectEqualStrings(expected, output.written());
        } else {
            try std.testing.expectError(error.Failed, result);
            try std.testing.expect(
                std.mem.indexOf(
                    u8,
                    diagnostic.message(),
                    case.error_needle.?,
                ) != null,
            );
        }
    }
}

test "single draft asset final validation requires one uploaded exact asset" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const notes_path = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/notes.md",
        .{&tmp.sub_path},
    );
    defer allocator.free(notes_path);
    const release_path = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/release.json",
        .{&tmp.sub_path},
    );
    defer allocator.free(release_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = notes_path, .data = "notes" });
    try Dir.cwd().writeFile(io, .{
        .sub_path = release_path,
        .data =
        \\{"id":42,"tag_name":"capture-v1","target_commitish":"0123456789abcdef0123456789abcdef01234567","name":"capture","body":"notes","draft":true,"prerelease":false,"immutable":false,"assets":[{"id":1,"name":"result.json","size":7,"state":"uploaded","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}
        ,
    });
    var output: std.Io.Writer.Discarding = .init(&.{});
    var diagnostic: Diagnostic = .{};
    try validateSingleDraftAssetFiles(
        allocator,
        io,
        release_path,
        notes_path,
        .{
            .tag = "capture-v1",
            .commit = "0123456789abcdef0123456789abcdef01234567",
            .title = "capture",
            .body = "",
            .prerelease = false,
        },
        "result.json",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        7,
        .final,
        &output.writer,
        &diagnostic,
    );
    const invalid_assets = [_][]const u8{
        \\{"id":1,"name":"result.json","size":7,"state":"uploaded","digest":null}
        ,
        \\{"id":1,"name":"result.json","size":7,"state":"starter","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        ,
        \\{"id":1,"name":"result.json","size":7,"state":"uploaded","digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
        ,
    };
    for (invalid_assets) |asset| {
        const document = try std.mem.concat(
            allocator,
            u8,
            &.{
                "{\"id\":42,\"tag_name\":\"capture-v1\",\"target_commitish\":\"0123456789abcdef0123456789abcdef01234567\",\"name\":\"capture\",\"body\":\"notes\",\"draft\":true,\"prerelease\":false,\"immutable\":false,\"assets\":[",
                asset,
                "]}",
            },
        );
        defer allocator.free(document);
        try Dir.cwd().writeFile(io, .{
            .sub_path = release_path,
            .data = document,
        });
        try std.testing.expectError(error.Failed, validateSingleDraftAssetFiles(
            allocator,
            io,
            release_path,
            notes_path,
            .{
                .tag = "capture-v1",
                .commit = "0123456789abcdef0123456789abcdef01234567",
                .title = "capture",
                .body = "",
                .prerelease = false,
            },
            "result.json",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            7,
            .final,
            &output.writer,
            &diagnostic,
        ));
    }
    try Dir.cwd().writeFile(io, .{
        .sub_path = release_path,
        .data =
        \\{"id":42,"tag_name":"capture-v1","target_commitish":"0123456789abcdef0123456789abcdef01234567","name":"capture","body":"notes","draft":false,"prerelease":false,"immutable":true,"assets":[{"id":1,"name":"result.json","size":7,"state":"uploaded","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}
        ,
    });
    try validateSingleDraftAssetFiles(
        allocator,
        io,
        release_path,
        notes_path,
        .{
            .tag = "capture-v1",
            .commit = "0123456789abcdef0123456789abcdef01234567",
            .title = "capture",
            .body = "",
            .prerelease = false,
        },
        "result.json",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        7,
        .published,
        &output.writer,
        &diagnostic,
    );
    try Dir.cwd().writeFile(io, .{
        .sub_path = release_path,
        .data =
        \\{"id":42,"tag_name":"capture-v1","target_commitish":"0123456789abcdef0123456789abcdef01234567","name":"capture","body":"notes","draft":false,"prerelease":false,"immutable":false,"assets":[{"id":1,"name":"result.json","size":7,"state":"uploaded","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}
        ,
    });
    try std.testing.expectError(error.Failed, validateSingleDraftAssetFiles(
        allocator,
        io,
        release_path,
        notes_path,
        .{
            .tag = "capture-v1",
            .commit = "0123456789abcdef0123456789abcdef01234567",
            .title = "capture",
            .body = "",
            .prerelease = false,
        },
        "result.json",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        7,
        .published,
        &output.writer,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "published release is not immutable",
        diagnostic.message(),
    );
}

test "asset table mutation gates require exact uploaded API digests" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}",
        .{&tmp.sub_path},
    );
    defer allocator.free(root);
    const notes_path = try std.fs.path.join(allocator, &.{ root, "notes.md" });
    defer allocator.free(notes_path);
    const expected_path = try std.fs.path.join(allocator, &.{ root, "expected.tsv" });
    defer allocator.free(expected_path);
    const release_path = try std.fs.path.join(allocator, &.{ root, "release.json" });
    defer allocator.free(release_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = notes_path, .data = "notes" });
    try Dir.cwd().writeFile(io, .{
        .sub_path = expected_path,
        .data = "result.json\t" ++ "a" ** 64 ++ "\t7\n",
    });
    const metadata =
        "\"id\":42,\"tag_name\":\"capture-v1\",\"target_commitish\":" ++
        "\"0123456789abcdef0123456789abcdef01234567\",\"name\":\"capture\"," ++
        "\"body\":\"notes\",\"prerelease\":false";
    const expected_metadata: ExpectedMetadata = .{
        .tag = "capture-v1",
        .commit = "0123456789abcdef0123456789abcdef01234567",
        .title = "capture",
        .body = "",
        .prerelease = false,
    };

    try Dir.cwd().writeFile(io, .{
        .sub_path = release_path,
        .data = "{" ++ metadata ++ ",\"draft\":true,\"assets\":[]}",
    });
    var status: std.Io.Writer.Allocating = .init(allocator);
    defer status.deinit();
    var diagnostic: Diagnostic = .{};
    try validateDraftAssetTableFiles(
        allocator,
        io,
        release_path,
        notes_path,
        expected_path,
        42,
        expected_metadata,
        .asset,
        "result.json",
        &status.writer,
        &diagnostic,
    );
    try std.testing.expectEqualStrings("upload\n", status.written());

    const exact_asset =
        "{\"id\":1,\"name\":\"result.json\",\"size\":7,\"state\":\"uploaded\"," ++
        "\"digest\":\"sha256:" ++ "a" ** 64 ++ "\"}";
    try Dir.cwd().writeFile(io, .{
        .sub_path = release_path,
        .data = "{" ++ metadata ++ ",\"draft\":true,\"assets\":[" ++
            exact_asset ++ "]}",
    });
    var discard: std.Io.Writer.Discarding = .init(&.{});
    try validateDraftAssetTableFiles(
        allocator,
        io,
        release_path,
        notes_path,
        expected_path,
        42,
        expected_metadata,
        .exact,
        null,
        &discard.writer,
        &diagnostic,
    );

    const invalid_assets = [_]struct {
        json: []const u8,
        plan: []const u8,
    }{
        .{
            .json = "{\"id\":2,\"name\":\"result.json\",\"size\":7,\"state\":\"uploaded\",\"digest\":null}",
            .plan = "2\n",
        },
        .{
            .json = "{\"id\":3,\"name\":\"result.json\",\"size\":7,\"state\":\"starter\",\"digest\":\"sha256:" ++ "a" ** 64 ++ "\"}",
            .plan = "3\n",
        },
        .{
            .json = "{\"id\":4,\"name\":\"result.json\",\"size\":7,\"state\":\"uploaded\",\"digest\":\"sha256:" ++ "b" ** 64 ++ "\"}",
            .plan = "4\n",
        },
    };
    for (invalid_assets) |invalid_asset| {
        const document = try std.mem.concat(
            allocator,
            u8,
            &.{ "{", metadata, ",\"draft\":true,\"assets\":[", invalid_asset.json, "]}" },
        );
        defer allocator.free(document);
        try Dir.cwd().writeFile(io, .{
            .sub_path = release_path,
            .data = document,
        });
        status.clearRetainingCapacity();
        try validateDraftAssetTableFiles(
            allocator,
            io,
            release_path,
            notes_path,
            expected_path,
            42,
            expected_metadata,
            .repair,
            null,
            &status.writer,
            &diagnostic,
        );
        try std.testing.expectEqualStrings(invalid_asset.plan, status.written());
        try std.testing.expectError(error.Failed, validateDraftAssetTableFiles(
            allocator,
            io,
            release_path,
            notes_path,
            expected_path,
            42,
            expected_metadata,
            .exact,
            null,
            &discard.writer,
            &diagnostic,
        ));
    }

    try Dir.cwd().writeFile(io, .{
        .sub_path = release_path,
        .data = "{" ++ metadata ++
            ",\"draft\":false,\"immutable\":true,\"assets\":[" ++
            exact_asset ++ "]}",
    });
    try validateDraftAssetTableFiles(
        allocator,
        io,
        release_path,
        notes_path,
        expected_path,
        42,
        expected_metadata,
        .published,
        null,
        &discard.writer,
        &diagnostic,
    );
    try Dir.cwd().writeFile(io, .{
        .sub_path = release_path,
        .data = "{" ++ metadata ++
            ",\"draft\":false,\"immutable\":false,\"assets\":[" ++
            exact_asset ++ "]}",
    });
    try std.testing.expectError(error.Failed, validateDraftAssetTableFiles(
        allocator,
        io,
        release_path,
        notes_path,
        expected_path,
        42,
        expected_metadata,
        .published,
        null,
        &discard.writer,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "published release is not immutable",
        diagnostic.message(),
    );
}
