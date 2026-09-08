//! Repository-wide structural guard for ordinary reviewable GitHub release
//! capabilities. It deliberately does not claim to decode encrypted or
//! arbitrarily obfuscated producer code.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const max_source_bytes = 8 * 1024 * 1024;
const max_git_output_bytes = 32 * 1024 * 1024;

const producers = [_][]const u8{
    ".github/workflows/azurelinux4-release.yml",
    ".github/workflows/freebsd15-release.yml",
    ".github/workflows/release.yml",
    ".github/workflows/ubuntu2404-confidential-capture.yml",
    ".github/workflows/ubuntu2404-confidential-release.yml",
    ".github/workflows/ubuntu2604-gallery-reissue.yml",
    ".github/workflows/ubuntu2604-release.yml",
    "scripts/azurelinux4_publish.sh",
    "scripts/freebsd15_publish.sh",
    "scripts/miz_release.zig",
    "scripts/release/github_release.zig",
    "scripts/ubuntu2404_confidential_publish.sh",
    "scripts/ubuntu2404_confidential_publish_release.sh",
    "scripts/ubuntu2604_gallery_reissue.sh",
    "scripts/ubuntu2604_publish.sh",
};

const write_workflows = [_][]const u8{
    ".github/workflows/azurelinux4-release.yml",
    ".github/workflows/freebsd15-release.yml",
    ".github/workflows/release.yml",
    ".github/workflows/ubuntu2404-confidential-capture.yml",
    ".github/workflows/ubuntu2404-confidential-release.yml",
    ".github/workflows/ubuntu2604-gallery-reissue.yml",
    ".github/workflows/ubuntu2604-release.yml",
};

const pattern_fixtures = [_][]const u8{
    "tests/azurelinux4_release_contract.zig",
    "tests/freebsd15_release.zig",
    "tests/fixtures/mock_gh.zig",
    "tests/immutable_release_guard.zig",
    "tests/immutable_releases.zig",
    "tests/ubuntu2404_confidential_capture_workflow.zig",
    "tests/ubuntu2404_confidential_workflow.zig",
    "tests/ubuntu2604_core_workflow.zig",
    "tests/ubuntu2604_release.zig",
    "tests/ubuntu2604_workflow.zig",
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

fn lowerNormalized(
    allocator: Allocator,
    source: []const u8,
) ![]u8 {
    var normalized = try allocator.alloc(u8, source.len);
    var write: usize = 0;
    var index: usize = 0;
    while (index < source.len) : (index += 1) {
        const byte = source[index];
        if (byte == '\\' and index + 1 < source.len and
            source[index + 1] == '\n')
        {
            index += 1;
            continue;
        }
        if (byte == '\'' or byte == '"' or byte == '`') continue;
        normalized[write] = switch (byte) {
            'A'...'Z' => byte + ('a' - 'A'),
            '\n' => '\n',
            '\r', '\t', ';', '|', '&', '(', ')', '[', ']', '{', '}', ',' => ' ',
            else => byte,
        };
        write += 1;
    }
    return allocator.realloc(normalized, write);
}

fn isWorkflow(path: []const u8) bool {
    return std.mem.startsWith(u8, path, ".github/workflows/") and
        (std.mem.endsWith(u8, path, ".yml") or
            std.mem.endsWith(u8, path, ".yaml"));
}

fn isAction(path: []const u8) bool {
    if (!std.mem.startsWith(u8, path, ".github/actions/")) return false;
    return std.mem.endsWith(u8, path, "/action.yml") or
        std.mem.endsWith(u8, path, "/action.yaml");
}

fn isListed(path: []const u8, list: []const []const u8) bool {
    for (list) |entry| {
        if (std.mem.eql(u8, entry, path)) return true;
    }
    return false;
}

fn hasYamlValue(
    source: []const u8,
    key: []const u8,
    expected: []const u8,
) bool {
    var search_at: usize = 0;
    while (std.mem.indexOfPos(u8, source, search_at, key)) |at| {
        if (at != 0 and source[at - 1] != ' ' and source[at - 1] != '\t' and
            source[at - 1] != '\r' and source[at - 1] != '\n')
        {
            search_at = at + 1;
            continue;
        }
        var index = at + key.len;
        while (index < source.len and
            (source[index] == ' ' or source[index] == '\t')) : (index += 1)
        {}
        if (index >= source.len or source[index] != ':') {
            search_at = at + 1;
            continue;
        }
        index += 1;
        while (index < source.len and
            (source[index] == ' ' or source[index] == '\t')) : (index += 1)
        {}
        if (std.mem.startsWith(u8, source[index..], expected)) {
            const end = index + expected.len;
            if (end == source.len or source[end] == ' ' or
                source[end] == '\r' or source[end] == '\n')
            {
                return true;
            }
        }
        search_at = at + 1;
    }
    return false;
}

fn workflowCanWrite(normalized: []const u8) bool {
    return hasYamlValue(normalized, "contents", "write") or
        (std.mem.indexOf(u8, normalized, "create-github-app-token") != null and
            hasYamlValue(normalized, "permission-contents", "write"));
}

fn tokenHasReleaseEndpoint(token: []const u8) bool {
    if (std.mem.indexOf(u8, token, "immutable-releases") != null) return false;
    return std.mem.indexOf(u8, token, "/releases") != null or
        std.mem.indexOf(u8, token, "releases/") != null or
        std.mem.indexOf(u8, token, "releases?") != null;
}

fn tokenIsWriteMethod(token: []const u8) bool {
    return std.mem.eql(u8, token, "post") or
        std.mem.eql(u8, token, "patch") or
        std.mem.eql(u8, token, "delete") or
        std.mem.eql(u8, token, "-xpost") or
        std.mem.eql(u8, token, "-xpatch") or
        std.mem.eql(u8, token, "-xdelete") or
        std.mem.eql(u8, token, "--method=post") or
        std.mem.eql(u8, token, "--method=patch") or
        std.mem.eql(u8, token, "--method=delete") or
        std.mem.eql(u8, token, "--request=post") or
        std.mem.eql(u8, token, "--request=patch") or
        std.mem.eql(u8, token, "--request=delete");
}

fn tokenContainsWriteMethod(token: []const u8) bool {
    if (tokenIsWriteMethod(token)) return true;
    for ([_][]const u8{ "post", "patch", "delete" }) |method| {
        if (std.mem.eql(u8, token, method)) return true;
        if (std.mem.endsWith(u8, token, method) and token.len > method.len) {
            const separator = token[token.len - method.len - 1];
            if (separator == '.' or separator == ':' or separator == '=') {
                return true;
            }
        }
        if (token.len == method.len + 1 and token[token.len - 1] == ':' and
            std.mem.eql(u8, token[0..method.len], method))
        {
            return true;
        }
    }
    return false;
}

fn tokenIsGetMethod(token: []const u8) bool {
    return std.mem.eql(u8, token, "get") or
        std.mem.eql(u8, token, "-xget") or
        std.mem.eql(u8, token, "--method=get") or
        std.mem.eql(u8, token, "--request=get");
}

fn tokenIsGhBodyFlag(token: []const u8) bool {
    return std.mem.eql(u8, token, "-f") or
        std.mem.startsWith(u8, token, "-f=") or
        std.mem.eql(u8, token, "--raw-field") or
        std.mem.startsWith(u8, token, "--raw-field=") or
        std.mem.eql(u8, token, "--field") or
        std.mem.startsWith(u8, token, "--field=") or
        std.mem.eql(u8, token, "--input") or
        std.mem.startsWith(u8, token, "--input=");
}

fn endpointWindowIsReleaseWrite(tokens: []const []const u8, index: usize) bool {
    const token = tokens[index];
    const release_endpoint = tokenHasReleaseEndpoint(token);
    const upload_endpoint = std.mem.indexOf(
        u8,
        token,
        "uploads.github.com",
    ) != null and release_endpoint;
    if (!release_endpoint) return false;
    const start = index -| 24;
    const end = @min(tokens.len, index + 25);
    var write_method = false;
    var explicit_get = false;
    var body = false;
    var pending_method = false;
    for (tokens[start..end]) |nearby| {
        if (std.mem.eql(u8, nearby, "-x") or
            std.mem.eql(u8, nearby, "--method") or
            std.mem.eql(u8, nearby, "--request"))
        {
            pending_method = true;
            continue;
        }
        if (pending_method) {
            write_method = write_method or tokenContainsWriteMethod(nearby);
            explicit_get = explicit_get or tokenIsGetMethod(nearby);
            pending_method = false;
        }
        write_method = write_method or tokenContainsWriteMethod(nearby);
        explicit_get = explicit_get or tokenIsGetMethod(nearby);
        body = body or tokenIsGhBodyFlag(nearby);
    }
    return upload_endpoint or write_method or (body and !explicit_get);
}

fn commandWindowIsReleaseWrite(tokens: []const []const u8, start: usize) bool {
    const end = @min(tokens.len, start + 48);
    var release_index: ?usize = null;
    var api_index: ?usize = null;
    var write_method = false;
    var release_endpoint = false;
    var upload_endpoint = false;
    var pending_method = false;
    var explicit_get = false;
    var body = false;
    for (tokens[start..end], start..) |token, index| {
        if (std.mem.eql(u8, token, "release") and release_index == null) {
            release_index = index;
        }
        if (std.mem.eql(u8, token, "api") and api_index == null) api_index = index;
        if (std.mem.eql(u8, token, "-x") or
            std.mem.eql(u8, token, "--method") or
            std.mem.eql(u8, token, "--request"))
        {
            pending_method = true;
            continue;
        }
        if (pending_method) {
            write_method = write_method or tokenContainsWriteMethod(token);
            explicit_get = explicit_get or tokenIsGetMethod(token);
            pending_method = false;
        }
        write_method = write_method or tokenIsWriteMethod(token);
        explicit_get = explicit_get or tokenIsGetMethod(token);
        body = body or tokenIsGhBodyFlag(token);
        release_endpoint = release_endpoint or tokenHasReleaseEndpoint(token);
        upload_endpoint = upload_endpoint or
            std.mem.indexOf(u8, token, "uploads.github.com") != null;
    }
    if (release_index) |at| {
        const command_end = @min(tokens.len, at + 16);
        for (tokens[at + 1 .. command_end]) |token| {
            if (std.mem.eql(u8, token, "create") or
                std.mem.eql(u8, token, "edit") or
                std.mem.eql(u8, token, "upload") or
                std.mem.startsWith(u8, token, "delete"))
            {
                return true;
            }
        }
    }
    return api_index != null and release_endpoint and
        (write_method or upload_endpoint or (body and !explicit_get));
}

fn looksLikeReleaseAction(normalized: []const u8) bool {
    var lines = std.mem.splitScalar(u8, normalized, '\n');
    while (lines.next()) |line| {
        const uses = std.mem.indexOf(u8, line, "uses:") orelse continue;
        const action = std.mem.trim(u8, line[uses + "uses:".len ..], " ");
        const reference = if (std.mem.indexOfScalar(u8, action, '@')) |at|
            action[0..at]
        else
            action;
        if (std.mem.indexOf(u8, reference, "release") != null or
            std.mem.indexOf(u8, reference, "publish") != null or
            std.mem.indexOf(u8, reference, "publication") != null or
            (std.mem.indexOf(u8, reference, "upload") != null and
                std.mem.indexOf(u8, reference, "asset") != null))
        {
            return true;
        }
    }
    return false;
}

fn looksLikeProducer(
    allocator: Allocator,
    path: []const u8,
    source: []const u8,
) !bool {
    const normalized = try lowerNormalized(allocator, source);
    defer allocator.free(normalized);
    if (isWorkflow(path) and workflowCanWrite(normalized)) return true;
    if (looksLikeReleaseAction(normalized)) return true;
    if (std.mem.indexOf(u8, normalized, "github_release.publish") != null or
        std.mem.indexOf(u8, normalized, "miz_release publish") != null)
    {
        return true;
    }
    if (std.mem.indexOf(u8, normalized, "self.gh") != null and
        std.mem.indexOf(u8, normalized, "/releases") != null and
        std.mem.indexOf(u8, normalized, "--method") != null and
        (std.mem.indexOf(u8, normalized, "post") != null or
            std.mem.indexOf(u8, normalized, "patch") != null or
            std.mem.indexOf(u8, normalized, "delete") != null))
    {
        return true;
    }
    for ([_][]const u8{
        "createrelease",
        "updaterelease",
        "deleterelease",
        "uploadreleaseasset",
        "deletereleaseasset",
        "create_release",
        "update_release",
        "delete_release",
        "upload_release_asset",
        "delete_release_asset",
    }) |surface| {
        if (std.mem.indexOf(u8, normalized, surface) != null) return true;
    }
    var tokens_list: std.ArrayList([]const u8) = .empty;
    defer tokens_list.deinit(allocator);
    var tokens = std.mem.tokenizeAny(u8, normalized, " \t\r\n");
    while (tokens.next()) |token| try tokens_list.append(allocator, token);
    for (tokens_list.items, 0..) |token, index| {
        if (endpointWindowIsReleaseWrite(tokens_list.items, index)) return true;
        if (std.mem.eql(u8, token, "gh") and
            commandWindowIsReleaseWrite(tokens_list.items, index))
        {
            return true;
        }
        if (std.mem.eql(u8, token, "curl") or std.mem.eql(u8, token, "wget")) {
            const end = @min(tokens_list.items.len, index + 48);
            var release_url = false;
            var upload_url = false;
            var write_method = false;
            var pending_method = false;
            for (tokens_list.items[index..end]) |argument| {
                release_url = release_url or
                    ((std.mem.indexOf(u8, argument, "api.github.com") != null or
                        std.mem.indexOf(u8, argument, "github.com/api/") != null) and
                        tokenHasReleaseEndpoint(argument));
                upload_url = upload_url or
                    (std.mem.indexOf(u8, argument, "uploads.github.com") != null and
                        tokenHasReleaseEndpoint(argument));
                if (std.mem.eql(u8, argument, "-x") or
                    std.mem.eql(u8, argument, "--request"))
                {
                    pending_method = true;
                    continue;
                }
                if (pending_method) {
                    write_method = write_method or tokenIsWriteMethod(argument);
                    pending_method = false;
                }
                write_method = write_method or tokenIsWriteMethod(argument);
                write_method = write_method or
                    std.mem.eql(u8, argument, "-d") or
                    std.mem.startsWith(u8, argument, "-d=") or
                    std.mem.eql(u8, argument, "--data") or
                    std.mem.startsWith(u8, argument, "--data=") or
                    std.mem.eql(u8, argument, "--data-binary") or
                    std.mem.startsWith(u8, argument, "--data-binary=");
            }
            if (upload_url or (release_url and write_method)) return true;
        }
    }
    return false;
}

fn isBinary(source: []const u8) bool {
    return std.mem.indexOfScalar(u8, source, 0) != null;
}

fn isExecutableContext(path: []const u8, mode: []const u8, source: []const u8) bool {
    if (std.mem.eql(u8, mode, "100755") or isWorkflow(path) or isAction(path) or
        std.mem.startsWith(u8, source, "#!"))
    {
        return true;
    }
    for ([_][]const u8{
        ".bash", ".c",      ".cc",  ".clj",  ".cljs", ".cpp", ".cs",
        ".csx",  ".dart",   ".ex",  ".exs",  ".fish", ".fs",  ".fsx",
        ".go",   ".groovy", ".hs",  ".java", ".js",   ".jsx", ".kt",
        ".kts",  ".lhs",    ".lua", ".m",    ".mjs",  ".mm",  ".php",
        ".pl",   ".ps1",    ".py",  ".r",    ".rb",   ".rs",  ".scala",
        ".sh",   ".swift",  ".ts",  ".tsx",  ".vb",   ".zig", ".zsh",
    }) |extension| {
        if (std.mem.endsWith(u8, path, extension)) return true;
    }
    return false;
}

fn validateTrackedSource(
    allocator: Allocator,
    path: []const u8,
    mode: []const u8,
    source: []const u8,
    report_unreviewed: bool,
) !bool {
    if (isBinary(source) or !isExecutableContext(path, mode, source)) return false;
    const producer = try looksLikeProducer(allocator, path, source);
    if (!producer) return false;
    if (isListed(path, &pattern_fixtures) and
        std.mem.eql(u8, mode, "100644"))
    {
        return false;
    }
    if (!isListed(path, &producers)) {
        if (report_unreviewed) {
            std.debug.print("unreviewed GitHub release producer: {s}\n", .{path});
        }
        return error.UnreviewedReleaseProducer;
    }
    return true;
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
            "--stage",
            "-z",
        },
        .stdout_limit = .limited(max_git_output_bytes),
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
    var entries = std.mem.splitScalar(u8, result.stdout, 0);
    while (entries.next()) |entry| {
        if (entry.len == 0) continue;
        const tab = std.mem.indexOfScalar(u8, entry, '\t') orelse
            return error.InvalidGitIndexEntry;
        const metadata = entry[0..tab];
        const path = entry[tab + 1 ..];
        const space = std.mem.indexOfScalar(u8, metadata, ' ') orelse
            return error.InvalidGitIndexEntry;
        const mode = metadata[0..space];
        if (!std.mem.eql(u8, mode, "100644") and
            !std.mem.eql(u8, mode, "100755"))
        {
            continue;
        }
        const source = try readSource(allocator, io, root, path);
        defer allocator.free(source);
        if (try validateTrackedSource(allocator, path, mode, source, true)) {
            try found.append(allocator, path);
        }
        if (isWorkflow(path)) {
            const normalized = try lowerNormalized(allocator, source);
            defer allocator.free(normalized);
            const capable = workflowCanWrite(normalized);
            if (capable != isListed(path, &write_workflows)) {
                std.debug.print(
                    "workflow Contents:write allowlist mismatch: {s}\n",
                    .{path},
                );
                return error.WriteWorkflowAllowlistMismatch;
            }
        }
    }
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
    try std.testing.expectEqual(producers.len, found.items.len);
}

test "producer capability detection resists ordinary spelling variants" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        path: []const u8,
        source: []const u8,
    }{
        .{
            .path = "tools/publish.sh",
            .source = "gh api -X POST repos/acme/project/releases",
        },
        .{
            .path = "tools/publish.sh",
            .source = "gh api repos/acme/project/releases --method=PATCH",
        },
        .{
            .path = "tools/publish.sh",
            .source = "command g\"\"h api \\\n -X DELETE \\\n repos/acme/project/releases/7",
        },
        .{
            .path = "tools/publish.sh",
            .source = "gh api repos/acme/project/releases -f tag_name=v1",
        },
        .{
            .path = "tools/publish.sh",
            .source = "gh api repos/acme/project/releases --raw-field tag_name=v1",
        },
        .{
            .path = "tools/publish.sh",
            .source = "gh api repos/acme/project/releases -F draft=true",
        },
        .{
            .path = "tools/publish.sh",
            .source = "gh api repos/acme/project/releases --field draft=true",
        },
        .{
            .path = "tools/publish.sh",
            .source = "gh api repos/acme/project/releases --input request.json",
        },
        .{
            .path = "tools/publish.sh",
            .source = "curl --request POST https://api.github.com/repos/acme/project/releases",
        },
        .{
            .path = "tools/publish.sh",
            .source = "wget https://uploads.github.com/repos/acme/project/releases/7/assets?name=x",
        },
        .{
            .path = "src/publish.ts",
            .source = "await octokit.rest.repos.uploadReleaseAsset(options);",
        },
        .{
            .path = "src/publish.go",
            .source = "client.Repositories.CreateRelease(ctx, owner, repo, release)",
        },
        .{
            .path = "src/publish.ts",
            .source = "graphql(`mutation { createRelease(input: $input) { id } }`)",
        },
        .{
            .path = "src/fetch-client.js",
            .source =
            \\await fetch("https://api.github.com/repos/acme/project/releases", {
            \\  method: "POST", body: payload
            \\});
            ,
        },
        .{
            .path = "src/axios-client.ts",
            .source = "await transport.post('https://api.github.com/repos/acme/project/releases', payload);",
        },
        .{
            .path = "src/generic-client.rb",
            .source = "http.request('PATCH', 'https://api.github.com/repos/acme/project/releases/7')",
        },
        .{
            .path = "tools/non-executable." ++ "p" ++ "y",
            .source = "#!/usr/bin/env " ++ "py" ++ "thon\nrequest(url='https://uploads.github.com/repos/acme/project/releases/7/assets?name=x', method='POST')",
        },
        .{
            .path = "tools/release.kts",
            .source = "client.request(\"https://api.github.com/repos/acme/project/releases/7\", method = \"DELETE\")",
        },
        .{
            .path = ".github/workflows/other.yml",
            .source = "steps:\n  - uses: ncipollo/release-action@v1\n",
        },
        .{
            .path = ".github/workflows/other.yml",
            .source = "permissions:\n  contents:    write\n",
        },
        .{
            .path = "tools/publish.sh",
            .source = "gh --repo acme/project release --verify-tag create v1",
        },
    };
    for (cases) |case| {
        try std.testing.expect(
            try looksLikeProducer(allocator, case.path, case.source),
        );
        try std.testing.expectError(
            error.UnreviewedReleaseProducer,
            validateTrackedSource(
                allocator,
                case.path,
                if (std.mem.endsWith(u8, case.path, ".sh")) "100755" else "100644",
                case.source,
                false,
            ),
        );
    }
}

test "explicit GET keeps gh API body fields read-only" {
    const allocator = std.testing.allocator;
    inline for ([_][]const u8{
        "gh api --method GET repos/acme/project/releases -f per_page=100",
        "gh api -X GET repos/acme/project/releases --field per_page=100",
        "gh api repos/acme/project/releases --method=GET --input query.json",
    }) |source| {
        try std.testing.expect(!try looksLikeProducer(
            allocator,
            "tools/query.sh",
            source,
        ));
    }
}

test "composite actions are executable release producer contexts" {
    const allocator = std.testing.allocator;
    const source =
        \\name: hidden publisher
        \\runs:
        \\  using: composite
        \\  steps:
        \\    - shell: bash
        \\      run: gh api repos/acme/project/releases -f tag_name=v1
    ;
    try std.testing.expect(try looksLikeProducer(
        allocator,
        ".github/actions/publish/action.yml",
        source,
    ));
    try std.testing.expectError(
        error.UnreviewedReleaseProducer,
        validateTrackedSource(
            allocator,
            ".github/actions/publish/action.yml",
            "100644",
            source,
            false,
        ),
    );
}

test "non-executable exact pattern fixtures do not become producers" {
    const allocator = std.testing.allocator;
    try std.testing.expect(!try validateTrackedSource(
        allocator,
        "tests/immutable_release_guard.zig",
        "100644",
        "const fixture = \"gh api -X POST repos/x/y/releases\";",
        false,
    ));
    try std.testing.expectError(
        error.UnreviewedReleaseProducer,
        validateTrackedSource(
            allocator,
            "tests/new_release_fixture.zig",
            "100644",
            "const fixture = \"gh api -X POST repos/x/y/releases\";",
            false,
        ),
    );
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

test "every publishing workflow mints the shared protected policy token" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const pinned =
        "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349";
    for (write_workflows) |path| {
        const source = try readSource(allocator, std.testing.io, root, path);
        defer allocator.free(source);
        try expectContains(path, source, pinned);
        try expectContains(path, source, "secrets.RELEASE_GITHUB_APP_ID");
        try expectContains(
            path,
            source,
            "secrets.RELEASE_GITHUB_APP_PRIVATE_KEY",
        );
        if (std.mem.endsWith(u8, path, "ubuntu2404-confidential-capture.yml")) {
            try expectContains(path, source, "permission-administration: write");
            try expectContains(path, source, "POLICY_GH_TOKEN");
        } else {
            try expectContains(path, source, "permission-administration: read");
            try expectContains(
                path,
                source,
                if (std.mem.endsWith(u8, path, "/release.yml"))
                    "MIZ_RELEASE_POLICY_GH_TOKEN"
                else
                    "RELEASE_POLICY_GH_TOKEN",
            );
        }
    }
    const main = try readSource(
        allocator,
        std.testing.io,
        root,
        ".github/workflows/release.yml",
    );
    defer allocator.free(main);
    try expectContains(".github/workflows/release.yml", main, "environment: miz-release");
    try expectContains(
        ".github/workflows/release.yml",
        main,
        "MIZ_RELEASE_POLICY_GH_TOKEN",
    );
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
        try expectAbsent(path, source, "gh release upload");
        try expectAbsent(path, source, "--clobber");
        try expectContains(
            path,
            source,
            "https://uploads.github.com/repos/$REPOSITORY/releases/$release_id/assets?name=",
        );
        try expectContains(path, source, "Content-Type: application/octet-stream");
        try expectContains(path, source, "quarantine and inspect immutable");
        try expectAbsent(
            path,
            source,
            "--draft >/dev/null 2>&1 || true",
        );
        try expectOrder(path, source, "--draft", "uploads.github.com/repos/");
        try expectOrder(path, source, "uploads.github.com/repos/", "gh release download");
        try expectOrder(path, source, "gh release download", "publish_attempted=true");
        try expectOrder(
            path,
            source,
            "repos/$REPOSITORY/immutable-releases",
            "publish_attempted=true",
        );
        try expectContains(path, source, "RELEASE_POLICY_GH_TOKEN");
        try expectContains(path, source, "GH_TOKEN=\"$policy_token\" gh api");
        if (std.mem.indexOf(u8, source, "--method DELETE") != null) {
            try expectOrder(
                path,
                source,
                "--method DELETE",
                "publish_attempted=true",
            );
        }
        try expectOrder(path, source, "publish_attempted=true", "draft=false");
        try expectOrder(path, source, "draft=false", "release_published=true");
        const published_at = std.mem.indexOf(
            u8,
            source,
            "release_published=true",
        ).?;
        const published_path = source[published_at..];
        try expectAbsent(path, published_path, "uploads.github.com/repos/");
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
            "uploads.github.com/repos/",
        );
    }
}

test "shell-created drafts bind and refetch the exact target before upload" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const requirements = [_]struct {
        path: []const u8,
        tag: []const u8,
        target: []const u8,
        validator: []const u8,
    }{
        .{
            .path = "scripts/azurelinux4_publish.sh",
            .tag = "$RELEASE_TAG",
            .target = "$SOURCE_COMMIT",
            .validator = "check-release-metadata",
        },
        .{
            .path = "scripts/freebsd15_publish.sh",
            .tag = "$RELEASE_TAG",
            .target = "$SOURCE_COMMIT",
            .validator = "verify-release-metadata",
        },
        .{
            .path = "scripts/ubuntu2404_confidential_publish.sh",
            .tag = "$RELEASE_TAG",
            .target = "$SOURCE_COMMIT",
            .validator = "check-release-metadata",
        },
        .{
            .path = "scripts/ubuntu2604_publish.sh",
            .tag = "$RELEASE_TAG",
            .target = "$SOURCE_COMMIT",
            .validator = "github-release-metadata",
        },
        .{
            .path = "scripts/ubuntu2604_gallery_reissue.sh",
            .tag = "$REISSUE_TAG",
            .target = "$TOOLING_COMMIT",
            .validator = "github-release-metadata",
        },
    };
    for (requirements) |requirement| {
        const source = try readSource(
            allocator,
            std.testing.io,
            root,
            requirement.path,
        );
        defer allocator.free(source);
        const create_marker = try std.fmt.allocPrint(
            allocator,
            "gh release create \"{s}\"",
            .{requirement.tag},
        );
        defer allocator.free(create_marker);
        const create_at = std.mem.indexOf(u8, source, create_marker) orelse
            return error.RequiredTextMissing;
        const transaction = source[create_at..];
        const target_marker = try std.fmt.allocPrint(
            allocator,
            "--target \"{s}\"",
            .{requirement.target},
        );
        defer allocator.free(target_marker);
        try expectContains(requirement.path, transaction, target_marker);
        try expectOrder(
            requirement.path,
            transaction,
            target_marker,
            "gh api \"$release_api\"",
        );
        try expectOrder(
            requirement.path,
            transaction,
            "gh api \"$release_api\"",
            requirement.validator,
        );
        try expectOrder(
            requirement.path,
            transaction,
            requirement.validator,
            "uploads.github.com/repos/",
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
