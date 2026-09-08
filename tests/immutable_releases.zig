//! Adversarial transaction tests for the main immutable-release publisher.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const commit = "0123456789abcdef0123456789abcdef01234567";
const max_output = 4 * 1024 * 1024;
const platforms = [_][]const u8{
    "linux-musl-x64",
    "linux-musl-arm64",
    "macos-x64",
    "macos-arm64",
    "windows-x64",
    "windows-arm64",
};

const Run = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: Run, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }

    fn succeeded(self: Run) bool {
        return switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
};

const Fixture = struct {
    allocator: Allocator,
    tmp: std.testing.TmpDir,
    root: []u8,
    assets: []u8,
    workspace: []u8,
    publisher: []u8,
    mock_gh: []u8,

    fn create(allocator: Allocator, version: []const u8) !Fixture {
        const tmp = std.testing.tmpDir(.{});
        const repository = try std.testing.environ.getAlloc(
            allocator,
            "MIZ_IMMUTABLE_RELEASE_ROOT",
        );
        defer allocator.free(repository);
        const root = try std.fmt.allocPrint(
            allocator,
            "{s}/.zig-cache/tmp/{s}",
            .{ repository, tmp.sub_path },
        );
        errdefer allocator.free(root);
        const assets = try std.fs.path.join(
            allocator,
            &.{ root, "assets; argv remains literal" },
        );
        errdefer allocator.free(assets);
        const workspace = try std.fs.path.join(allocator, &.{ root, "work" });
        errdefer allocator.free(workspace);
        try Dir.cwd().createDirPath(std.testing.io, assets);
        for (platforms) |platform| {
            inline for ([_][]const u8{ ".tar.gz", ".sbom.spdx.json" }) |suffix| {
                const name = try std.fmt.allocPrint(
                    allocator,
                    "miz-{s}-{s}{s}",
                    .{ version, platform, suffix },
                );
                defer allocator.free(name);
                const path = try std.fs.path.join(allocator, &.{ assets, name });
                defer allocator.free(path);
                const contents = try std.fmt.allocPrint(
                    allocator,
                    "fixture:{s}\n",
                    .{name},
                );
                defer allocator.free(contents);
                try Dir.cwd().writeFile(
                    std.testing.io,
                    .{ .sub_path = path, .data = contents },
                );
            }
        }
        const publisher = try std.testing.environ.getAlloc(
            allocator,
            "MIZ_RELEASE_PUBLISHER",
        );
        errdefer allocator.free(publisher);
        const mock_gh = try std.testing.environ.getAlloc(
            allocator,
            "MIZ_RELEASE_MOCK_GH",
        );
        return .{
            .allocator = allocator,
            .tmp = tmp,
            .root = root,
            .assets = assets,
            .workspace = workspace,
            .publisher = publisher,
            .mock_gh = mock_gh,
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.free(self.mock_gh);
        self.allocator.free(self.publisher);
        self.allocator.free(self.workspace);
        self.allocator.free(self.assets);
        self.allocator.free(self.root);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn setStage(self: *Fixture, state: []const u8) !void {
        const path = try std.fs.path.join(
            self.allocator,
            &.{ self.root, "stage" },
        );
        defer self.allocator.free(path);
        try Dir.cwd().writeFile(
            std.testing.io,
            .{ .sub_path = path, .data = state },
        );
    }

    fn addRemote(self: *Fixture, name: []const u8, contents: []const u8) !void {
        const remote = try std.fs.path.join(
            self.allocator,
            &.{ self.root, "remote" },
        );
        defer self.allocator.free(remote);
        try Dir.cwd().createDirPath(std.testing.io, remote);
        const path = try std.fs.path.join(self.allocator, &.{ remote, name });
        defer self.allocator.free(path);
        try Dir.cwd().writeFile(
            std.testing.io,
            .{ .sub_path = path, .data = contents },
        );
    }

    fn run(
        self: *Fixture,
        scenario: []const u8,
        version: []const u8,
    ) !Run {
        const tag = try std.fmt.allocPrint(self.allocator, "v{s}", .{version});
        defer self.allocator.free(tag);
        var environment = try std.process.Environ.createMap(
            std.testing.environ,
            self.allocator,
        );
        defer environment.deinit();
        try environment.put("MIZ_GH", self.mock_gh);
        try environment.put("MIZ_MOCK_GH_ROOT", self.root);
        try environment.put("MIZ_MOCK_GH_SCENARIO", scenario);
        try environment.put("MIZ_MOCK_GH_TAG", tag);
        try environment.put("MIZ_MOCK_GH_VERSION", version);
        try environment.put("MIZ_MOCK_GH_COMMIT", commit);
        const result = try std.process.run(self.allocator, std.testing.io, .{
            .argv = &.{
                self.publisher,
                "publish",
                "--repository",
                "cataggar/miz",
                "--tag",
                tag,
                "--version",
                version,
                "--commit",
                commit,
                "--assets-directory",
                self.assets,
                "--workspace",
                self.workspace,
            },
            .environ_map = &environment,
            .stdout_limit = .limited(max_output),
            .stderr_limit = .limited(max_output),
        });
        return .{
            .term = result.term,
            .stdout = result.stdout,
            .stderr = result.stderr,
        };
    }

    fn log(self: *Fixture) ![]u8 {
        const path = try std.fs.path.join(
            self.allocator,
            &.{ self.root, "commands.log" },
        );
        defer self.allocator.free(path);
        return Dir.cwd().readFileAlloc(
            std.testing.io,
            path,
            self.allocator,
            .limited(max_output),
        );
    }

    fn stage(self: *Fixture) ![]u8 {
        const path = try std.fs.path.join(
            self.allocator,
            &.{ self.root, "stage" },
        );
        defer self.allocator.free(path);
        return Dir.cwd().readFileAlloc(
            std.testing.io,
            path,
            self.allocator,
            .limited(32),
        );
    }
};

fn expectContains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) != null) return;
    std.debug.print("missing text: {s}\nactual:\n{s}\n", .{ needle, text });
    return error.MissingText;
}

fn expectAbsent(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) return;
    std.debug.print("unexpected text: {s}\n", .{needle});
    return error.UnexpectedText;
}

fn expectOrder(text: []const u8, first: []const u8, second: []const u8) !void {
    const first_at = std.mem.indexOf(u8, text, first) orelse {
        std.debug.print("missing order marker {s} in:\n{s}\n", .{ first, text });
        return error.MissingText;
    };
    const second_at = std.mem.indexOfPos(u8, text, first_at + first.len, second) orelse
        {
            std.debug.print("missing later marker {s} in:\n{s}\n", .{ second, text });
            return error.MissingText;
        };
    try std.testing.expect(first_at < second_at);
}

fn expectSucceeded(result: Run) !void {
    if (result.succeeded()) return;
    std.debug.print("publisher failed:\n{s}\n", .{result.stderr});
    return error.PublisherFailed;
}

test "fresh draft uploads verifies downloads and publishes once in order" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const result = try fixture.run("fresh", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectOrder(log, "8:--method\x1f4:POST", "7:release\x1f6:upload");
    try expectOrder(
        log,
        "7:release\x1f6:upload",
        "32:Accept: application/octet-stream",
    );
    try expectOrder(
        log,
        "32:Accept: application/octet-stream",
        "8:--method\x1f5:PATCH",
    );
    try expectContains(log, "11:draft=false");
    try expectContains(log, "16:make_latest=true");
    try expectContains(log, "assets; argv remains literal");
    try expectAbsent(log, "sh -c");
    const stage = try fixture.stage();
    defer std.testing.allocator.free(stage);
    try std.testing.expectEqualStrings("published", stage);
}

test "an exact retained draft resumes without creating another release" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    try fixture.setStage("draft");
    const result = try fixture.run("resume", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectAbsent(log, "8:--method\x1f4:POST");
    try expectContains(log, "8:--method\x1f5:PATCH");
}

test "a published release is refused before every mutation" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    try fixture.setStage("published");
    const result = try fixture.run("published", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.succeeded());
    try expectContains(result.stderr, "already published and immutable");
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    for ([_][]const u8{
        "7:release\x1f6:upload",
        "8:--method\x1f6:DELETE",
        "8:--method\x1f5:PATCH",
        "8:--method\x1f4:POST",
    }) |needle| {
        try expectAbsent(log, needle);
    }
}

test "duplicate exact-tag releases are refused before mutation" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    try fixture.setStage("draft");
    const result = try fixture.run("duplicate-release", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.succeeded());
    try expectContains(result.stderr, "more than one release has exact tag");
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectAbsent(log, "7:release\x1f6:upload");
    try expectAbsent(log, "8:--method\x1f5:PATCH");
}

test "upload failure leaves a resumable draft and never publishes" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const result = try fixture.run("upload-failure", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.succeeded());
    const stage = try fixture.stage();
    defer std.testing.allocator.free(stage);
    try std.testing.expectEqualStrings("draft", stage);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectAbsent(log, "8:--method\x1f5:PATCH");
}

test "stale assets are deleted only after a draft check and before publish" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    try fixture.setStage("draft");
    try fixture.addRemote("stale.bin", "stale");
    const result = try fixture.run("resume", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectOrder(
        log,
        "30:repos/cataggar/miz/releases/42",
        "8:--method\x1f6:DELETE",
    );
    try expectOrder(log, "8:--method\x1f6:DELETE", "8:--method\x1f5:PATCH");
}

test "corrupt independent download fails while the release is a draft" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const result = try fixture.run("corrupt-download", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.succeeded());
    try expectContains(result.stderr, "downloaded release asset does not match");
    const stage = try fixture.stage();
    defer std.testing.allocator.free(stage);
    try std.testing.expectEqualStrings("draft", stage);
}

test "missing and changed remote assets fail before publish" {
    inline for ([_][]const u8{ "missing-remote", "changed-remote" }) |scenario| {
        var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
        defer fixture.deinit();
        const result = try fixture.run(scenario, "1.2.3");
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
        const log = try fixture.log();
        defer std.testing.allocator.free(log);
        try expectAbsent(log, "8:--method\x1f5:PATCH");
    }
}

test "foreign metadata and wrong tag target fail before asset mutation" {
    inline for ([_][]const u8{ "metadata-mismatch", "tag-mismatch" }) |scenario| {
        var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
        defer fixture.deinit();
        try fixture.setStage("draft");
        const result = try fixture.run(scenario, "1.2.3");
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
        const log = try fixture.log();
        defer std.testing.allocator.free(log);
        for ([_][]const u8{
            "7:release\x1f6:upload",
            "8:--method\x1f6:DELETE",
            "8:--method\x1f5:PATCH",
        }) |needle| {
            try expectAbsent(log, needle);
        }
    }
}

test "prerelease publication explicitly preserves the latest stable release" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3-rc.1");
    defer fixture.deinit();
    const result = try fixture.run("fresh", "1.2.3-rc.1");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectContains(log, "17:make_latest=false");
    try expectContains(log, "15:prerelease=true");
}

test "post-publication verification failure performs no later mutation" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const result = try fixture.run("post-publish-failure", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.succeeded());
    const stage = try fixture.stage();
    defer std.testing.allocator.free(stage);
    try std.testing.expectEqualStrings("published", stage);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    const publish_marker = "8:--method\x1f5:PATCH";
    const publish_at = std.mem.indexOf(u8, log, publish_marker) orelse
        return error.MissingText;
    const after = log[publish_at + publish_marker.len ..];
    try expectAbsent(after, "7:release\x1f6:upload");
    try expectAbsent(after, "8:--method\x1f6:DELETE");
    try expectAbsent(after, "draft=true");
}

test "an immutable response must remain immutable on the final read" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const result = try fixture.run("immutable-regression", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.succeeded());
    try expectContains(result.stderr, "immutable state regressed");
    const stage = try fixture.stage();
    defer std.testing.allocator.free(stage);
    try std.testing.expectEqualStrings("published", stage);
}

test "missing unexpected and changed local assets fail closed" {
    var missing = try Fixture.create(std.testing.allocator, "1.2.3");
    defer missing.deinit();
    const missing_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ missing.assets, "miz-1.2.3-windows-arm64.tar.gz" },
    );
    defer std.testing.allocator.free(missing_path);
    try Dir.cwd().deleteFile(std.testing.io, missing_path);
    const missing_result = try missing.run("fresh", "1.2.3");
    defer missing_result.deinit(std.testing.allocator);
    try std.testing.expect(!missing_result.succeeded());

    var unexpected = try Fixture.create(std.testing.allocator, "1.2.3");
    defer unexpected.deinit();
    const unexpected_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ unexpected.assets, "miz-1.2.3-plan9-x64.tar.gz" },
    );
    defer std.testing.allocator.free(unexpected_path);
    try Dir.cwd().writeFile(
        std.testing.io,
        .{ .sub_path = unexpected_path, .data = "unexpected" },
    );
    const unexpected_result = try unexpected.run("fresh", "1.2.3");
    defer unexpected_result.deinit(std.testing.allocator);
    try std.testing.expect(!unexpected_result.succeeded());
    try expectContains(unexpected_result.stderr, "unexpected matching release asset");

    var changed = try Fixture.create(std.testing.allocator, "1.2.3");
    defer changed.deinit();
    const changed_result = try changed.run("change-local", "1.2.3");
    defer changed_result.deinit(std.testing.allocator);
    try std.testing.expect(!changed_result.succeeded());
    try expectContains(changed_result.stderr, "local release asset changed");
}
