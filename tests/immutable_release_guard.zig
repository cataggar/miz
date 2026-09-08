//! Repository-wide structural guard for GitHub release producers.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const max_source_bytes = 8 * 1024 * 1024;

const producers = [_][]const u8{
    ".github/workflows/release.yml",
    ".github/workflows/ubuntu2404-confidential-capture.yml",
    "scripts/azurelinux4_publish.sh",
    "scripts/freebsd15_publish.sh",
    "scripts/miz_release.zig",
    "scripts/release/github_release.zig",
    "scripts/ubuntu2404_confidential_publish.sh",
    "scripts/ubuntu2404_confidential_publish_release.sh",
    "scripts/ubuntu2604_gallery_reissue.sh",
    "scripts/ubuntu2604_publish.sh",
};

const asset_publishers = [_][]const u8{
    "scripts/azurelinux4_publish.sh",
    "scripts/freebsd15_publish.sh",
    "scripts/ubuntu2404_confidential_publish.sh",
    "scripts/ubuntu2604_gallery_reissue.sh",
    "scripts/ubuntu2604_publish.sh",
};

fn rootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(
        allocator,
        "MIZ_IMMUTABLE_RELEASE_ROOT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
        else => return err,
    };
}

fn readSource(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    relative: []const u8,
) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(max_source_bytes),
    );
}

fn expectContains(path: []const u8, source: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, source, needle) != null) return;
    std.debug.print("{s}: missing required release guard text:\n{s}\n", .{
        path,
        needle,
    });
    return error.RequiredTextMissing;
}

fn expectAbsent(path: []const u8, source: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, source, needle) == null) return;
    std.debug.print("{s}: forbidden release mutation text:\n{s}\n", .{
        path,
        needle,
    });
    return error.ForbiddenTextPresent;
}

fn expectOrder(
    path: []const u8,
    source: []const u8,
    first: []const u8,
    second: []const u8,
) !void {
    const first_at = std.mem.indexOf(u8, source, first) orelse
        return error.RequiredTextMissing;
    const second_at = std.mem.indexOfPos(u8, source, first_at + first.len, second) orelse
        return error.RequiredTextMissing;
    if (first_at < second_at) return;
    std.debug.print("{s}: release operations are out of order\n", .{path});
    return error.ReleaseOperationsOutOfOrder;
}

fn isKnownProducer(path: []const u8) bool {
    for (producers) |known| {
        if (std.mem.eql(u8, known, path)) return true;
    }
    return false;
}

fn looksLikeProducer(path: []const u8, source: []const u8) bool {
    if (std.mem.indexOf(u8, source, "softprops/action-gh-release") != null or
        std.mem.indexOf(u8, source, "gh release create") != null or
        std.mem.indexOf(u8, source, "gh release edit") != null or
        std.mem.indexOf(u8, source, "gh release upload") != null or
        std.mem.indexOf(u8, source, "uploads.github.com/repos/") != null or
        std.mem.indexOf(u8, source, "miz_release publish") != null or
        (std.mem.indexOf(u8, source, "gh api --method PATCH") != null and
            std.mem.indexOf(u8, source, "/releases/$release_id") != null))
    {
        return true;
    }
    return std.mem.indexOf(u8, source, "github_release.publish") != null or
        (std.mem.endsWith(u8, path, ".zig") and
            std.mem.indexOf(u8, source, "\"upload\",") != null and
            std.mem.indexOf(u8, source, "releases/assets/") != null);
}

test "producer discovery is exact and catches unreviewed publication surfaces" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const result = try std.process.run(allocator, io, .{
        .argv = &.{
            "git",
            "-C",
            root,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            ".github",
            "scripts",
        },
        .stdout_limit = .limited(max_source_bytes),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try std.testing.expect(switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    });

    var found: std.ArrayList([]const u8) = .empty;
    defer found.deinit(allocator);
    var paths = std.mem.splitScalar(u8, result.stdout, 0);
    while (paths.next()) |path| {
        if (path.len == 0) continue;
        const source = try readSource(allocator, io, root, path);
        defer allocator.free(source);
        if (!looksLikeProducer(path, source)) continue;
        try found.append(allocator, path);
        if (!isKnownProducer(path)) {
            std.debug.print("unreviewed GitHub release producer: {s}\n", .{path});
            return error.UnreviewedReleaseProducer;
        }
    }
    try std.testing.expectEqual(producers.len, found.items.len);
    for (producers) |expected| {
        var present = false;
        for (found.items) |actual| {
            if (std.mem.eql(u8, actual, expected)) present = true;
        }
        if (!present) {
            std.debug.print("guard allowlist entry is no longer a producer: {s}\n", .{
                expected,
            });
            return error.StaleReleaseProducerAllowlist;
        }
    }
}

test "main release workflow delegates the complete draft transaction to Zig" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const path = ".github/workflows/release.yml";
    const source = try readSource(allocator, std.testing.io, root, path);
    defer allocator.free(source);
    try expectAbsent(path, source, "softprops/action-gh-release");
    try expectAbsent(path, source, "gh release upload");
    try expectContains(path, source, "zig build install-miz-release");
    try expectContains(path, source, "miz_release verify-version");
    try expectContains(path, source, "miz_release publish");
    try expectContains(path, source, "--commit \"$GITHUB_SHA\"");
    try expectContains(path, source, "--workspace \"$GITHUB_WORKSPACE/.miz-release\"");
}

test "every shell asset publisher is draft-only until one-way publication" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    for (asset_publishers) |path| {
        const source = try readSource(allocator, std.testing.io, root, path);
        defer allocator.free(source);
        try expectContains(path, source, "--json isDraft");
        try expectContains(path, source, "!= true");
        try expectContains(path, source, "release_published=true");
        try expectContains(path, source, "publish_attempted=true");
        try expectContains(path, source, "--latest=false");
        try expectContains(path, source, "--clobber");
        try expectContains(path, source, "quarantine and inspect immutable");
        try expectAbsent(
            path,
            source,
            "--draft >/dev/null 2>&1 || true",
        );
        try expectOrder(path, source, "--draft", "gh release upload");
        try expectOrder(path, source, "gh release upload", "gh release download");
        try expectOrder(path, source, "gh release download", "publish_attempted=true");
        if (std.mem.indexOf(u8, source, "--method DELETE") != null) {
            try expectOrder(
                path,
                source,
                "--method DELETE",
                "publish_attempted=true",
            );
        }
        try expectOrder(path, source, "publish_attempted=true", "--draft=false");
        try expectOrder(path, source, "--draft=false", "release_published=true");
        const published_at = std.mem.indexOf(
            u8,
            source,
            "release_published=true",
        ).?;
        const published_path = source[published_at..];
        try expectAbsent(path, published_path, "gh release upload");
        try expectAbsent(path, published_path, "--method DELETE");
        try expectAbsent(path, published_path, "--draft");
    }
}

test "retained drafts are identity-checked by native release tools" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const requirements = [_][2][]const u8{
        .{ "scripts/azurelinux4_publish.sh", "check-release-metadata" },
        .{ "scripts/freebsd15_publish.sh", "verify-release-metadata" },
        .{
            "scripts/ubuntu2404_confidential_publish.sh",
            "check-release-metadata",
        },
        .{ "scripts/ubuntu2604_gallery_reissue.sh", "github-release-metadata" },
        .{ "scripts/ubuntu2604_publish.sh", "github-release-metadata" },
    };
    for (requirements) |requirement| {
        const source = try readSource(
            allocator,
            std.testing.io,
            root,
            requirement[0],
        );
        defer allocator.free(source);
        try expectOrder(
            requirement[0],
            source,
            "--json isDraft",
            requirement[1],
        );
        try expectOrder(
            requirement[0],
            source,
            requirement[1],
            "gh release upload",
        );
    }
}

test "protected capture publisher remains a prepared-draft one-way transition" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const script_path = "scripts/ubuntu2404_confidential_publish_release.sh";
    const script = try readSource(
        allocator,
        std.testing.io,
        root,
        script_path,
    );
    defer allocator.free(script);
    try expectContains(script_path, script, "draft: false");
    try expectContains(script_path, script, "make_latest: \"false\"");
    try expectContains(script_path, script, "gh api --method PATCH");
    for ([_][]const u8{
        "gh release upload",
        "releases/assets/",
        "--draft",
        "draft: true",
    }) |needle| try expectAbsent(script_path, script, needle);

    const workflow_path =
        ".github/workflows/ubuntu2404-confidential-capture.yml";
    const workflow = try readSource(
        allocator,
        std.testing.io,
        root,
        workflow_path,
    );
    defer allocator.free(workflow);
    try expectContains(workflow_path, workflow, "draft: true");
    try expectContains(workflow_path, workflow, "validate_release_identity");
    try expectContains(workflow_path, workflow, "Accept: application/octet-stream");
    try expectContains(
        workflow_path,
        workflow,
        "scripts/ubuntu2404_confidential_publish_release.sh",
    );
    try expectOrder(
        workflow_path,
        workflow,
        "draft: true",
        "uploads.github.com/repos/",
    );
    try expectOrder(
        workflow_path,
        workflow,
        "uploads.github.com/repos/",
        "Accept: application/octet-stream",
    );
    try expectOrder(
        workflow_path,
        workflow,
        "verify-capture-publication",
        "ubuntu2404_confidential_publish_release.sh",
    );
}
