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
    assets: []RemoteAsset,

    fn deinit(self: *Release, allocator: Allocator) void {
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
    immutable_was_true: bool = false,

    fn fail(
        self: *Publisher,
        comptime format: []const u8,
        arguments: anytype,
    ) Error {
        self.diagnostic.set(format, arguments);
        return error.Failed;
    }

    fn gh(self: *Publisher, arguments: []const []const u8) Error!GhResult {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.allocator);
        argv.append(self.allocator, self.options.gh_executable) catch
            return error.OutOfMemory;
        argv.appendSlice(self.allocator, arguments) catch
            return error.OutOfMemory;
        const result = std.process.run(self.allocator, self.io, .{
            .argv = argv.items,
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
                const tag = stringField(
                    self,
                    &candidate.object,
                    "tag_name",
                    "release tag",
                ) catch return error.Failed;
                if (!std.mem.eql(u8, tag, self.metadata.tag)) continue;
                if (exact) |*previous| {
                    previous.deinit(self.allocator);
                    return self.fail(
                        "more than one release has exact tag {s}",
                        .{self.metadata.tag},
                    );
                }
                exact = try self.parseRelease(candidate, true);
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

    fn createDraft(self: *Publisher) Error!Release {
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases",
            .{self.options.repository_name},
        ) catch return self.fail("repository name is too long", .{});
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
        const release = try self.parseRelease(result.value, true);
        if (!release.draft) return self.fail(
            "GitHub did not create release {s} as a draft",
            .{self.metadata.tag},
        );
        return release;
    }

    fn fetch(self: *Publisher, expected_draft: bool) Error!Release {
        var endpoint_buffer: [512]u8 = undefined;
        const endpoint = std.fmt.bufPrint(
            &endpoint_buffer,
            "repos/{s}/releases/{d}",
            .{ self.options.repository_name, self.release_id },
        ) catch return self.fail("release endpoint is too long", .{});
        var result = try self.ghJson(&.{ "api", endpoint });
        defer result.deinit();
        const release = try self.parseRelease(result.value, true);
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
        require_metadata: bool,
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
        if (immutable) self.immutable_was_true = true;
        if (require_metadata) try validateMetadataObject(
            object,
            self.metadata,
            self.diagnostic,
        );
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
            if (!std.mem.eql(u8, state, "uploaded")) return self.fail(
                "release asset {s} is not fully uploaded",
                .{name},
            );
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
        var draft = try self.fetch(true);
        defer draft.deinit(self.allocator);
        try self.revalidateLocal(asset);
        const result = try self.gh(&.{
            "release",
            "upload",
            self.metadata.tag,
            asset.path,
            "--clobber",
            "--repo",
            self.options.repository_name,
        });
        result.deinit(self.allocator);
    }

    fn deleteStale(self: *Publisher) Error!void {
        var release = try self.fetch(true);
        defer release.deinit(self.allocator);
        for (release.assets) |remote| {
            if (findAsset(self.assets, remote.name) != null) continue;
            var checked = try self.fetch(true);
            defer checked.deinit(self.allocator);
            var endpoint_buffer: [512]u8 = undefined;
            const endpoint = std.fmt.bufPrint(
                &endpoint_buffer,
                "repos/{s}/releases/assets/{d}",
                .{ self.options.repository_name, remote.id },
            ) catch return self.fail("asset endpoint is too long", .{});
            const result = try self.gh(&.{ "api", "--method", "DELETE", endpoint });
            result.deinit(self.allocator);
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
            if (remote.digest_text) |remote_digest| {
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
            }
            local.remote_id = remote.id;
        }
        for (release.assets) |remote| {
            if (findAsset(self.assets, remote.name) == null) return self.fail(
                "remote release has unexpected asset {s}",
                .{remote.name},
            );
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
        var child = std.process.spawn(self.io, .{
            .argv = argv.items,
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
        try self.verifyTag();
        var draft = try self.fetch(true);
        defer self.allocator.free(draft.assets);
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
        var published_response = try self.parseRelease(result.value, true);
        defer published_response.deinit(self.allocator);
        if (published_response.draft) return self.fail(
            "GitHub did not publish release {s}",
            .{self.metadata.tag},
        );
    }

    fn validateFinal(self: *Publisher) Error!void {
        try self.verifyTag();
        var release = try self.fetch(false);
        defer release.deinit(self.allocator);
        try self.validateRemoteAssets(&release);
        if (self.immutable_was_true and !release.immutable) return self.fail(
            "release immutable state regressed after publication",
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
    const body = std.fmt.allocPrint(
        allocator,
        "**Install:**\n\n```console\nghr install {s}@{s}\n```\n",
        .{ options.repository_name, options.tag },
    ) catch return error.OutOfMemory;
    defer allocator.free(body);
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
            .body = body,
            .prerelease = prerelease,
        },
        .assets = assets,
    };
    try publisher.verifyTag();
    var release = if (try publisher.discover()) |existing|
        existing
    else
        try publisher.createDraft();
    defer release.deinit(allocator);
    publisher.release_id = release.id;
    if (!release.draft) return publisher.fail(
        "release {s} is not a draft",
        .{options.tag},
    );
    for (assets) |*asset| try publisher.upload(asset);
    try publisher.deleteStale();
    var uploaded = try publisher.fetch(true);
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

pub fn validateMetadataObject(
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
        .{ .key = "body", .label = "release body", .expected = expected.body },
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
