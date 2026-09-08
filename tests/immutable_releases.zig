//! Adversarial transaction tests for the main immutable-release publisher.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const commit = "0123456789abcdef0123456789abcdef01234567";
const max_output = 4 * 1024 * 1024;
const create_endpoint = "repos/cataggar/miz/releases\x1f";
const upload_endpoint =
    "https://uploads.github.com/repos/cataggar/miz/releases/42/assets?name=";
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

    fn addStarter(self: *Fixture, name: []const u8) !void {
        const remote = try std.fs.path.join(
            self.allocator,
            &.{ self.root, "remote" },
        );
        defer self.allocator.free(remote);
        try Dir.cwd().createDirPath(std.testing.io, remote);
        for ([_][2][]const u8{
            .{ "starter-asset", name },
            .{ "starter-created", "true" },
        }) |marker| {
            const path = try std.fs.path.join(
                self.allocator,
                &.{ self.root, marker[0] },
            );
            defer self.allocator.free(path);
            try Dir.cwd().writeFile(
                std.testing.io,
                .{ .sub_path = path, .data = marker[1] },
            );
        }
    }

    fn addExactAssets(self: *Fixture, version: []const u8) !void {
        for (platforms) |platform| {
            inline for ([_][]const u8{ ".tar.gz", ".sbom.spdx.json" }) |suffix| {
                const name = try std.fmt.allocPrint(
                    self.allocator,
                    "miz-{s}-{s}{s}",
                    .{ version, platform, suffix },
                );
                defer self.allocator.free(name);
                const contents = try std.fmt.allocPrint(
                    self.allocator,
                    "fixture:{s}\n",
                    .{name},
                );
                defer self.allocator.free(contents);
                try self.addRemote(name, contents);
            }
        }
    }

    fn run(
        self: *Fixture,
        scenario: []const u8,
        version: []const u8,
    ) !Run {
        return self.runWithPolicy(scenario, version, "policy-token");
    }

    fn runWithPolicy(
        self: *Fixture,
        scenario: []const u8,
        version: []const u8,
        policy_token: ?[]const u8,
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
        try environment.put("GH_TOKEN", "content-token");
        if (policy_token) |token| {
            try environment.put("MIZ_RELEASE_POLICY_GH_TOKEN", token);
        }
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
        ) catch |err| switch (err) {
            error.FileNotFound => self.allocator.dupe(u8, ""),
            else => return err,
        };
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

fn expectFreshNumericMutationChecks(log: []const u8) !void {
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(std.testing.allocator);
    var iterator = std.mem.splitScalar(u8, log, '\n');
    while (iterator.next()) |line| {
        if (line.len != 0) try lines.append(std.testing.allocator, line);
    }
    var mutations: usize = 0;
    for (lines.items, 0..) |line, index| {
        const is_delete = std.mem.indexOf(
            u8,
            line,
            "8:--method\x1f6:DELETE",
        ) != null;
        const is_upload = std.mem.indexOf(u8, line, upload_endpoint) != null;
        if (!is_delete and !is_upload) continue;
        mutations += 1;
        try std.testing.expect(index != 0);
        try expectContains(
            lines.items[index - 1],
            "repos/cataggar/miz/releases/42",
        );
        if (is_upload) {
            try std.testing.expect(index + 1 < lines.items.len);
            try expectContains(
                lines.items[index + 1],
                "repos/cataggar/miz/releases/42",
            );
        }
    }
    try std.testing.expect(mutations != 0);
}

test "fresh draft uploads verifies downloads and publishes once in order" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const result = try fixture.run("fresh", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectOrder(
        log,
        "repos/cataggar/miz/releases/generate-notes",
        create_endpoint,
    );
    try expectOrder(log, create_endpoint, upload_endpoint);
    try expectOrder(
        log,
        upload_endpoint,
        "32:Accept: application/octet-stream",
    );
    try expectOrder(
        log,
        "32:Accept: application/octet-stream",
        "8:--method\x1f5:PATCH",
    );
    const create_at = std.mem.indexOf(u8, log, create_endpoint) orelse
        return error.MissingText;
    const first_immutable = std.mem.indexOf(
        u8,
        log,
        "repos/cataggar/miz/immutable-releases",
    ) orelse return error.MissingText;
    const first_ruleset = std.mem.indexOf(
        u8,
        log,
        "rulesets?includes_parents=true&targets=tag&per_page=100",
    ) orelse return error.MissingText;
    try std.testing.expect(first_immutable < first_ruleset);
    try std.testing.expect(first_ruleset < create_at);
    const publish_at = std.mem.indexOf(
        u8,
        log,
        "8:--method\x1f5:PATCH",
    ) orelse return error.MissingText;
    const before_publish = log[0..publish_at];
    const final_tag = std.mem.lastIndexOf(
        u8,
        before_publish,
        "repos/cataggar/miz/git/ref/tags/v1.2.3",
    ) orelse return error.MissingText;
    const final_immutable = std.mem.indexOfPos(
        u8,
        before_publish,
        final_tag,
        "repos/cataggar/miz/immutable-releases",
    ) orelse return error.MissingText;
    const final_ruleset = std.mem.indexOfPos(
        u8,
        before_publish,
        final_immutable,
        "rulesets?includes_parents=true&targets=tag&per_page=100",
    ) orelse return error.MissingText;
    try std.testing.expect(final_tag < final_immutable);
    try std.testing.expect(final_immutable < final_ruleset);
    const tag_after_publish = std.mem.indexOfPos(
        u8,
        log,
        publish_at + 1,
        "repos/cataggar/miz/git/ref/tags/v1.2.3",
    ) orelse return error.MissingText;
    try std.testing.expect(publish_at < tag_after_publish);
    try expectContains(log, "11:draft=false");
    try expectContains(log, "10:draft=true");
    try expectContains(log, "17:make_latest=false");
    try expectContains(log, "16:make_latest=true");
    try expectContains(log, "Generated fixture changelog");
    try expectContains(log, "previous_tag_name=v1.2.2");
    try expectContains(
        log,
        "``\\n\\n\\n## What's Changed",
    );
    try expectContains(
        log,
        "target_commitish=0123456789abcdef0123456789abcdef01234567",
    );
    try expectContains(log, "assets; argv remains literal");
    try expectContains(log, "Content-Type: application/octet-stream");
    try expectAbsent(log, "7:release\x1f6:upload");
    try expectAbsent(log, "--clobber");
    try expectAbsent(log, "sh -c");
    try expectFreshNumericMutationChecks(log);
    const stage = try fixture.stage();
    defer std.testing.allocator.free(stage);
    try std.testing.expectEqualStrings("published", stage);
}

test "fresh release body preserves the byte-exact generated-notes separator" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const result = try fixture.run("fresh", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectContains(
        log,
        "body=**Install:**\\n\\n```console\\nghr install cataggar/miz@v1.2.3" ++
            "\\n```\\n\\n\\n## What's Changed\\n\\n* Generated fixture changelog\\n",
    );
}

test "a missing or legacy draft target is refused before upload" {
    inline for ([_][]const u8{ "missing-target", "legacy-target" }) |scenario| {
        var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
        defer fixture.deinit();
        const result = try fixture.run(scenario, "1.2.3");
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
        try expectContains(result.stderr, "release target");
        const log = try fixture.log();
        defer std.testing.allocator.free(log);
        try expectAbsent(log, upload_endpoint);
        try expectAbsent(log, "8:--method\x1f5:PATCH");
    }
}

test "a starter asset left by a failed upload is repaired on the next run" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const first = try fixture.run("starter-first-upload", "1.2.3");
    defer first.deinit(std.testing.allocator);
    try std.testing.expect(!first.succeeded());
    const draft = try fixture.stage();
    defer std.testing.allocator.free(draft);
    try std.testing.expectEqualStrings("draft", draft);

    const second = try fixture.run("starter-first-upload", "1.2.3");
    defer second.deinit(std.testing.allocator);
    try expectSucceeded(second);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectOrder(log, "8:--method\x1f6:DELETE", upload_endpoint);
    const stage = try fixture.stage();
    defer std.testing.allocator.free(stage);
    try std.testing.expectEqualStrings("published", stage);
}

test "unknown draft asset states fail closed before repair" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    try fixture.setStage("draft");
    try fixture.addStarter("miz-1.2.3-linux-musl-x64.tar.gz");
    const result = try fixture.run("unknown-asset-state", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.succeeded());
    try expectContains(result.stderr, "unknown state");
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectAbsent(log, "8:--method\x1f6:DELETE");
    try expectAbsent(log, upload_endpoint);
}

test "duplicate uploaded and incomplete entries are replaced safely" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    try fixture.setStage("draft");
    const name = "miz-1.2.3-linux-musl-x64.tar.gz";
    try fixture.addRemote(name, "old uploaded asset");
    try fixture.addStarter(name);
    const result = try fixture.run("resume", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    const first_delete = std.mem.indexOf(
        u8,
        log,
        "8:--method\x1f6:DELETE",
    ) orelse return error.MissingText;
    const second_delete = std.mem.indexOfPos(
        u8,
        log,
        first_delete + 1,
        "8:--method\x1f6:DELETE",
    ) orelse return error.MissingText;
    const upload = std.mem.indexOfPos(
        u8,
        log,
        second_delete + 1,
        upload_endpoint,
    ) orelse return error.MissingText;
    try std.testing.expect(second_delete < upload);
    try expectFreshNumericMutationChecks(log);
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
    try expectAbsent(log, create_endpoint);
    try expectAbsent(log, "repos/cataggar/miz/releases/generate-notes");
    try expectContains(log, "8:--method\x1f5:PATCH");
}

test "an exact retained draft asset set is not reuploaded" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    try fixture.setStage("draft");
    try fixture.addExactAssets("1.2.3");
    const result = try fixture.run("resume", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectAbsent(log, upload_endpoint);
    try expectAbsent(log, "8:--method\x1f6:DELETE");
    try expectContains(log, "8:--method\x1f5:PATCH");
}

test "retained draft notes survive changed generated-note inputs" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    try fixture.setStage("draft");
    const result = try fixture.run("notes-mismatch", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try expectSucceeded(result);
    const log = try fixture.log();
    defer std.testing.allocator.free(log);
    try expectAbsent(log, "repos/cataggar/miz/releases/generate-notes");
    try expectAbsent(log, create_endpoint);
    try expectContains(log, "Generated fixture changelog");
    try expectAbsent(log, "Regenerated fixture changelog changed");
}

test "malformed or foreign retained draft bodies are refused" {
    inline for ([_]struct {
        scenario: []const u8,
        diagnostic: []const u8,
    }{
        .{
            .scenario = "malformed-body",
            .diagnostic = "generated-notes separator",
        },
        .{
            .scenario = "foreign-body",
            .diagnostic = "exact install preamble",
        },
    }) |case| {
        var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
        defer fixture.deinit();
        try fixture.setStage("draft");
        const result = try fixture.run(case.scenario, "1.2.3");
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
        try expectContains(result.stderr, case.diagnostic);
        const log = try fixture.log();
        defer std.testing.allocator.free(log);
        try expectAbsent(log, "repos/cataggar/miz/releases/generate-notes");
        try expectAbsent(log, upload_endpoint);
        try expectAbsent(log, "8:--method\x1f6:DELETE");
        try expectAbsent(log, "8:--method\x1f5:PATCH");
    }
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
        upload_endpoint,
        "8:--method\x1f6:DELETE",
        "8:--method\x1f5:PATCH",
        create_endpoint,
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
    try expectAbsent(log, upload_endpoint);
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

test "repository release policy failures occur before draft mutation" {
    inline for ([_]struct {
        scenario: []const u8,
        policy_token: ?[]const u8,
        diagnostic: []const u8,
    }{
        .{
            .scenario = "immutable-disabled",
            .policy_token = "policy-token",
            .diagnostic = "immutable releases are disabled",
        },
        .{
            .scenario = "immutable-missing",
            .policy_token = "policy-token",
            .diagnostic = "enabled state is missing",
        },
        .{
            .scenario = "policy-unauthorized",
            .policy_token = "expired-policy-token",
            .diagnostic = "GitHub CLI command failed",
        },
        .{
            .scenario = "fresh",
            .policy_token = null,
            .diagnostic = "policy token is missing",
        },
        .{
            .scenario = "ruleset-missing",
            .policy_token = "policy-token",
            .diagnostic = "tag ruleset is missing",
        },
        .{
            .scenario = "ruleset-inactive",
            .policy_token = "policy-token",
            .diagnostic = "enforcement is not active",
        },
        .{
            .scenario = "ruleset-bypass",
            .policy_token = "policy-token",
            .diagnostic = "has a bypass actor",
        },
    }) |case| {
        var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
        defer fixture.deinit();
        const result = try fixture.runWithPolicy(
            case.scenario,
            "1.2.3",
            case.policy_token,
        );
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
        try expectContains(result.stderr, case.diagnostic);
        const log = try fixture.log();
        defer std.testing.allocator.free(log);
        try expectAbsent(log, create_endpoint);
        try expectAbsent(log, upload_endpoint);
        try expectAbsent(log, "8:--method\x1f5:PATCH");
    }
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

test "the last numeric draft fetch requires exact uploaded API digests" {
    inline for ([_]struct {
        scenario: []const u8,
        diagnostic: []const u8,
    }{
        .{ .scenario = "final-null-digest", .diagnostic = "has no digest" },
        .{ .scenario = "final-starter-state", .diagnostic = "not fully uploaded" },
        .{ .scenario = "final-wrong-digest", .diagnostic = "has digest" },
    }) |case| {
        var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
        defer fixture.deinit();
        const result = try fixture.run(case.scenario, "1.2.3");
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
        try expectContains(result.stderr, case.diagnostic);
        const stage = try fixture.stage();
        defer std.testing.allocator.free(stage);
        try std.testing.expectEqualStrings("draft", stage);
        const log = try fixture.log();
        defer std.testing.allocator.free(log);
        try expectContains(log, "32:Accept: application/octet-stream");
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
            upload_endpoint,
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
    try expectAbsent(after, upload_endpoint);
    try expectAbsent(after, "8:--method\x1f6:DELETE");
    try expectAbsent(after, "draft=true");
}

test "the final numeric release response must be immutable" {
    var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
    defer fixture.deinit();
    const result = try fixture.run("final-immutable-false", "1.2.3");
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(!result.succeeded());
    try expectContains(result.stderr, "published release is not immutable");
    const stage = try fixture.stage();
    defer std.testing.allocator.free(stage);
    try std.testing.expectEqualStrings("published", stage);
}

test "asset deletion aborts when the fresh predicate no longer matches" {
    inline for ([_]struct {
        scenario: []const u8,
        setup: enum { starter, stale, duplicate },
    }{
        .{ .scenario = "race-starter-valid", .setup = .starter },
        .{ .scenario = "race-stale-changed", .setup = .stale },
        .{ .scenario = "race-duplicate-resolved", .setup = .duplicate },
    }) |case| {
        var fixture = try Fixture.create(std.testing.allocator, "1.2.3");
        defer fixture.deinit();
        try fixture.setStage("draft");
        const name = "miz-1.2.3-linux-musl-x64.tar.gz";
        switch (case.setup) {
            .starter => try fixture.addStarter(name),
            .stale => try fixture.addRemote("stale.bin", "stale"),
            .duplicate => {
                try fixture.addStarter(name);
                try fixture.addRemote(name, "fixture:miz-1.2.3-linux-musl-x64.tar.gz\n");
            },
        }
        const result = try fixture.run(case.scenario, "1.2.3");
        defer result.deinit(std.testing.allocator);
        try std.testing.expect(!result.succeeded());
        try expectContains(result.stderr, "changed");
        const log = try fixture.log();
        defer std.testing.allocator.free(log);
        try expectAbsent(log, "8:--method\x1f6:DELETE");
        try expectAbsent(log, "8:--method\x1f5:PATCH");
        const stage = try fixture.stage();
        defer std.testing.allocator.free(stage);
        try std.testing.expectEqualStrings("draft", stage);
    }
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
