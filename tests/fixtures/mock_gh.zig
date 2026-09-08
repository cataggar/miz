//! Stateful GitHub CLI stand-in for immutable-release transaction tests.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const release_id: i64 = 42;
const stable_latest_id: i64 = 7;
const starter_asset_id: i64 = 41;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const root = init.environ_map.get("MIZ_MOCK_GH_ROOT") orelse
        return error.MissingMockRoot;
    const scenario = init.environ_map.get("MIZ_MOCK_GH_SCENARIO") orelse "fresh";
    const tag = init.environ_map.get("MIZ_MOCK_GH_TAG") orelse "v1.2.3";
    const version = init.environ_map.get("MIZ_MOCK_GH_VERSION") orelse "1.2.3";
    const commit = init.environ_map.get("MIZ_MOCK_GH_COMMIT") orelse
        "0123456789abcdef0123456789abcdef01234567";
    const gh_token = init.environ_map.get("GH_TOKEN") orelse "";
    try appendLog(allocator, io, root, argv[1..]);
    if (argv.len < 2) return error.MissingCommand;

    var stdout_buffer: [64 * 1024]u8 = undefined;
    var stdout_file: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_file.interface;
    if (std.mem.eql(u8, argv[1], "release")) {
        try releaseCommand(allocator, io, root, scenario, argv[2..]);
    } else if (std.mem.eql(u8, argv[1], "api")) {
        try apiCommand(
            allocator,
            io,
            root,
            scenario,
            tag,
            version,
            commit,
            gh_token,
            argv[2..],
            out,
        );
    } else {
        return error.UnsupportedCommand;
    }
    try out.flush();
}

fn apiCommand(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    scenario: []const u8,
    tag: []const u8,
    version: []const u8,
    commit: []const u8,
    gh_token: []const u8,
    argv: []const []const u8,
    out: *std.Io.Writer,
) !void {
    const endpoint = for (argv) |argument| {
        if (std.mem.startsWith(u8, argument, "repos/") or
            std.mem.startsWith(
                u8,
                argument,
                "https://uploads.github.com/repos/",
            ))
        {
            break argument;
        }
    } else return error.MissingApiEndpoint;
    const method = optionValue(argv, "--method") orelse "GET";

    if (std.mem.endsWith(u8, endpoint, "/immutable-releases")) {
        if (!std.mem.eql(u8, gh_token, "policy-token") or
            std.mem.eql(u8, scenario, "policy-unauthorized"))
        {
            return error.MockPolicyUnauthorized;
        }
        if (std.mem.eql(u8, scenario, "immutable-missing")) {
            try out.writeAll("{}\n");
        } else {
            try out.print(
                "{{\"enabled\":{s}}}\n",
                .{if (std.mem.eql(u8, scenario, "immutable-disabled"))
                    "false"
                else
                    "true"},
            );
        }
        return;
    }
    if (std.mem.indexOf(u8, endpoint, "/git/ref/tags/") != null) {
        const sha = if (std.mem.eql(u8, scenario, "tag-mismatch"))
            "ffffffffffffffffffffffffffffffffffffffff"
        else
            commit;
        try out.print(
            "{{\"object\":{{\"type\":\"commit\",\"sha\":\"{s}\"}}}}\n",
            .{sha},
        );
        return;
    }
    if (std.mem.endsWith(u8, endpoint, "/releases?per_page=100")) {
        const stage = try readStage(allocator, io, root);
        defer allocator.free(stage);
        if (std.mem.eql(u8, stage, "absent")) {
            try out.writeAll("[[{\"tag_name\":\"v1.2.2\"}]]\n");
        } else {
            try out.writeAll("[[");
            try writeRelease(allocator, io, root, scenario, tag, version, commit, out);
            if (std.mem.eql(u8, scenario, "duplicate-release")) {
                try out.writeByte(',');
                try writeRelease(
                    allocator,
                    io,
                    root,
                    scenario,
                    tag,
                    version,
                    commit,
                    out,
                );
            }
            try out.writeAll(",{\"tag_name\":\"v1.2.2\"}]]\n");
        }
        return;
    }
    if (std.mem.endsWith(u8, endpoint, "/releases/latest")) {
        const prerelease = std.mem.indexOfScalar(u8, version, '-') != null;
        try out.print(
            "{{\"id\":{d}}}\n",
            .{if (prerelease) stable_latest_id else release_id},
        );
        return;
    }
    if (std.mem.endsWith(u8, endpoint, "/releases/generate-notes") and
        std.mem.eql(u8, method, "POST"))
    {
        if (!std.mem.eql(u8, fieldValue(argv, "tag_name") orelse "", tag) or
            !std.mem.eql(
                u8,
                fieldValue(argv, "target_commitish") orelse "",
                commit,
            ) or
            !std.mem.eql(
                u8,
                fieldValue(argv, "previous_tag_name") orelse "",
                "v1.2.2",
            ))
        {
            return error.MockInvalidGeneratedNotesIdentity;
        }
        try out.writeAll("{\"body\":");
        try writeJsonString(out, generatedNotes(scenario));
        try out.writeAll("}\n");
        return;
    }
    if (std.mem.endsWith(u8, endpoint, "/releases") and
        std.mem.eql(u8, method, "POST"))
    {
        if (!std.mem.eql(u8, fieldValue(argv, "draft") orelse "", "true") or
            !std.mem.eql(
                u8,
                fieldValue(argv, "generate_release_notes") orelse "",
                "false",
            ))
        {
            return error.MockInvalidDraftCreation;
        }
        if (!std.mem.eql(
            u8,
            fieldValue(argv, "make_latest") orelse "",
            "false",
        )) {
            return error.MockInvalidDraftLatest;
        }
        const expected_body = try expectedReleaseBody(allocator, tag, scenario);
        defer allocator.free(expected_body);
        if (!std.mem.eql(
            u8,
            fieldValue(argv, "body") orelse "",
            expected_body,
        )) {
            return error.MockMissingGeneratedNotes;
        }
        try writeStage(io, root, "draft");
        try ensureRemoteDirectory(allocator, io, root);
        try writeRelease(allocator, io, root, scenario, tag, version, commit, out);
        return;
    }
    if (std.mem.startsWith(
        u8,
        endpoint,
        "https://uploads.github.com/repos/cataggar/miz/releases/42/assets?name=",
    ) and std.mem.eql(u8, method, "POST")) {
        const name_marker = "?name=";
        const name_at = std.mem.indexOf(u8, endpoint, name_marker) orelse
            return error.MissingAssetName;
        const name = endpoint[name_at + name_marker.len ..];
        const source = optionValue(argv, "--input") orelse
            return error.MissingUploadInput;
        try uploadAsset(allocator, io, root, scenario, source, name);
        try out.writeAll("{}\n");
        return;
    }
    if (std.mem.endsWith(u8, endpoint, "/releases/42") and
        std.mem.eql(u8, method, "PATCH"))
    {
        const expected_body = try expectedReleaseBody(allocator, tag, "fresh");
        defer allocator.free(expected_body);
        if (!std.mem.eql(
            u8,
            fieldValue(argv, "body") orelse "",
            expected_body,
        )) return error.MockChangedStoredBody;
        try writeStage(io, root, "published");
        const response_scenario = if (std.mem.eql(
            u8,
            scenario,
            "post-publish-failure",
        ))
            "fresh"
        else
            scenario;
        try writeRelease(
            allocator,
            io,
            root,
            response_scenario,
            tag,
            version,
            commit,
            out,
        );
        return;
    }
    if (std.mem.endsWith(u8, endpoint, "/releases/42")) {
        if (std.mem.eql(u8, method, "GET") and
            (std.mem.startsWith(u8, scenario, "race-")))
        {
            _ = try incrementMarker(allocator, io, root, "numeric-fetch-count");
        }
        try writeRelease(allocator, io, root, scenario, tag, version, commit, out);
        return;
    }
    if (std.mem.indexOf(u8, endpoint, "/releases/assets/") != null and
        std.mem.eql(u8, method, "DELETE"))
    {
        const id = try parseTrailingId(endpoint);
        try deleteAssetById(allocator, io, root, id);
        return;
    }
    if (std.mem.indexOf(u8, endpoint, "/releases/assets/") != null) {
        const id = try parseTrailingId(endpoint);
        const bytes = try readAssetById(allocator, io, root, id);
        defer allocator.free(bytes);
        try writeMarker(io, root, "download-started", "true");
        try out.writeAll(bytes);
        if (std.mem.eql(u8, scenario, "corrupt-download")) {
            try out.writeAll("corrupt");
        }
        return;
    }
    return error.UnsupportedApiEndpoint;
}

fn releaseCommand(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    scenario: []const u8,
    argv: []const []const u8,
) !void {
    if (argv.len < 3 or !std.mem.eql(u8, argv[0], "upload")) {
        return error.UnsupportedReleaseCommand;
    }
    if (std.mem.eql(u8, scenario, "upload-failure")) {
        return error.MockUploadFailure;
    }
    const source = argv[2];
    const name = std.fs.path.basename(source);
    try uploadAsset(allocator, io, root, scenario, source, name);
}

fn uploadAsset(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    scenario: []const u8,
    source: []const u8,
    name: []const u8,
) !void {
    if (std.mem.eql(u8, scenario, "upload-failure")) {
        return error.MockUploadFailure;
    }
    if (std.mem.eql(u8, scenario, "starter-first-upload") and
        !try markerExists(allocator, io, root, "starter-created"))
    {
        try writeMarker(io, root, "starter-asset", name);
        try writeMarker(io, root, "starter-created", "true");
        return error.MockUploadFailure;
    }
    if (std.mem.eql(u8, scenario, "missing-remote") and
        std.mem.endsWith(u8, name, "windows-arm64.sbom.spdx.json"))
    {
        return;
    }
    const bytes = try Dir.cwd().readFileAlloc(
        io,
        source,
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(bytes);
    try ensureRemoteDirectory(allocator, io, root);
    const destination = try std.fs.path.join(
        allocator,
        &.{ root, "remote", name },
    );
    defer allocator.free(destination);
    if (std.mem.eql(u8, scenario, "changed-remote") and
        std.mem.endsWith(u8, name, "windows-arm64.sbom.spdx.json"))
    {
        const changed = try std.mem.concat(allocator, u8, &.{ bytes, "changed" });
        defer allocator.free(changed);
        try Dir.cwd().writeFile(io, .{ .sub_path = destination, .data = changed });
    } else {
        try Dir.cwd().writeFile(io, .{ .sub_path = destination, .data = bytes });
    }
    if (std.mem.eql(u8, scenario, "change-local") and
        std.mem.endsWith(u8, name, "linux-musl-x64.tar.gz"))
    {
        try Dir.cwd().writeFile(io, .{ .sub_path = source, .data = "changed locally" });
    }
}

fn writeRelease(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    scenario: []const u8,
    tag: []const u8,
    version: []const u8,
    commit: []const u8,
    out: *std.Io.Writer,
) !void {
    const stage = try readStage(allocator, io, root);
    defer allocator.free(stage);
    const draft = std.mem.eql(u8, stage, "draft");
    const published = std.mem.eql(u8, stage, "published");
    const bad_after_publish = published and
        std.mem.eql(u8, scenario, "post-publish-failure");
    const title = if (std.mem.eql(u8, scenario, "metadata-mismatch") or
        bad_after_publish)
        "foreign title"
    else
        try std.fmt.allocPrint(allocator, "miz {s}", .{version});
    defer if (!std.mem.eql(u8, title, "foreign title")) allocator.free(title);
    const body = if (std.mem.eql(u8, scenario, "malformed-body"))
        try std.fmt.allocPrint(
            allocator,
            "**Install:**\n\n```console\nghr install cataggar/miz@{s}\n```\n",
            .{tag},
        )
    else if (std.mem.eql(u8, scenario, "foreign-body"))
        try allocator.dupe(u8, "foreign release body")
    else
        try expectedReleaseBody(allocator, tag, "fresh");
    defer allocator.free(body);
    try out.print(
        "{{\"id\":{d},\"tag_name\":",
        .{release_id},
    );
    try writeJsonString(out, tag);
    try out.writeAll(",\"target_commitish\":");
    if (std.mem.eql(u8, scenario, "missing-target")) {
        try out.writeAll("null");
    } else if (std.mem.eql(u8, scenario, "legacy-target")) {
        try writeJsonString(out, "main");
    } else {
        try writeJsonString(out, commit);
    }
    try out.writeAll(",\"name\":");
    try writeJsonString(out, title);
    try out.writeAll(",\"body\":");
    try writeJsonString(out, body);
    try out.print(
        ",\"draft\":{s},\"prerelease\":{s},\"immutable\":{s},\"assets\":[",
        .{
            if (draft) "true" else "false",
            if (std.mem.indexOfScalar(u8, version, '-') != null) "true" else "false",
            if (published and
                !std.mem.eql(u8, scenario, "final-immutable-false"))
                "true"
            else
                "false",
        },
    );
    try writeAssets(allocator, io, root, scenario, version, out);
    try out.writeAll("]}");
}

fn writeAssets(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    scenario: []const u8,
    version: []const u8,
    out: *std.Io.Writer,
) !void {
    const remote = try std.fs.path.join(allocator, &.{ root, "remote" });
    defer allocator.free(remote);
    var directory = Dir.cwd().openDir(io, remote, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer directory.close(io);
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file) continue;
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]u8, names.items, {}, struct {
        fn less(_: void, left: []u8, right: []u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.less);
    var wrote_asset = false;
    const starter_name = readMarker(
        allocator,
        io,
        root,
        "starter-asset",
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (starter_name) |name| allocator.free(name);
    if (starter_name) |name| {
        const fetch_count = readMarkerInt(
            allocator,
            io,
            root,
            "numeric-fetch-count",
        ) catch 0;
        if ((std.mem.eql(u8, scenario, "race-starter-valid") and
            fetch_count >= 3) or
            (std.mem.eql(u8, scenario, "race-duplicate-resolved") and
                fetch_count < 3))
        {
            const local_path = try std.fs.path.join(
                allocator,
                &.{ root, "assets; argv remains literal", name },
            );
            defer allocator.free(local_path);
            const bytes = try Dir.cwd().readFileAlloc(
                io,
                local_path,
                allocator,
                .limited(1024 * 1024),
            );
            defer allocator.free(bytes);
            try writeAssetRecord(out, starter_asset_id, name, bytes);
            wrote_asset = true;
        } else if (!(std.mem.eql(u8, scenario, "race-duplicate-resolved") and
            fetch_count >= 3))
        {
            try out.print("{{\"id\":{d},\"name\":", .{starter_asset_id});
            try writeJsonString(out, name);
            try out.print(
                ",\"size\":0,\"state\":\"{s}\",\"digest\":null}}",
                .{if (std.mem.eql(u8, scenario, "unknown-asset-state"))
                    "pending"
                else
                    "starter"},
            );
            wrote_asset = true;
        }
    }
    const corrupt_final_gate =
        (std.mem.eql(u8, scenario, "final-null-digest") or
            std.mem.eql(u8, scenario, "final-starter-state") or
            std.mem.eql(u8, scenario, "final-wrong-digest")) and
        try markerExists(allocator, io, root, "download-started");
    var corrupted = false;
    for (names.items) |name| {
        if (wrote_asset) try out.writeByte(',');
        const path = try std.fs.path.join(allocator, &.{ remote, name });
        defer allocator.free(path);
        const fetch_count = readMarkerInt(
            allocator,
            io,
            root,
            "numeric-fetch-count",
        ) catch 0;
        if (std.mem.eql(u8, scenario, "race-stale-changed") and
            fetch_count >= 3 and std.mem.eql(u8, name, "stale.bin"))
        {
            const expected_name = try std.fmt.allocPrint(
                allocator,
                "miz-{s}-linux-musl-x64.tar.gz",
                .{version},
            );
            defer allocator.free(expected_name);
            const local_path = try std.fs.path.join(
                allocator,
                &.{ root, "assets; argv remains literal", expected_name },
            );
            defer allocator.free(local_path);
            const local_bytes = try Dir.cwd().readFileAlloc(
                io,
                local_path,
                allocator,
                .limited(1024 * 1024),
            );
            defer allocator.free(local_bytes);
            try writeAssetRecord(
                out,
                assetId("stale.bin"),
                expected_name,
                local_bytes,
            );
            wrote_asset = true;
            continue;
        }
        const bytes = try Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(1024 * 1024),
        );
        defer allocator.free(bytes);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
        const hex = std.fmt.bytesToHex(hash, .lower);
        try out.print("{{\"id\":{d},\"name\":", .{assetId(name)});
        try writeJsonString(out, name);
        try out.print(",\"size\":{d},\"state\":", .{bytes.len});
        if (corrupt_final_gate and !corrupted and
            std.mem.eql(u8, scenario, "final-starter-state"))
        {
            try out.writeAll("\"starter\",\"digest\":\"sha256:");
            try out.writeAll(&hex);
            try out.writeAll("\"}");
            corrupted = true;
        } else if (corrupt_final_gate and !corrupted and
            std.mem.eql(u8, scenario, "final-null-digest"))
        {
            try out.writeAll("\"uploaded\",\"digest\":null}");
            corrupted = true;
        } else if (corrupt_final_gate and !corrupted and
            std.mem.eql(u8, scenario, "final-wrong-digest"))
        {
            try out.writeAll(
                "\"uploaded\",\"digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"}",
            );
            corrupted = true;
        } else {
            try out.print(
                "\"uploaded\",\"digest\":\"sha256:{s}\"}}",
                .{&hex},
            );
        }
        wrote_asset = true;
    }
}

fn writeAssetRecord(
    out: *std.Io.Writer,
    id: i64,
    name: []const u8,
    bytes: []const u8,
) !void {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    const hex = std.fmt.bytesToHex(hash, .lower);
    try out.print("{{\"id\":{d},\"name\":", .{id});
    try writeJsonString(out, name);
    try out.print(
        ",\"size\":{d},\"state\":\"uploaded\",\"digest\":\"sha256:{s}\"}}",
        .{ bytes.len, &hex },
    );
}

fn appendLog(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    argv: []const []const u8,
) !void {
    const path = try std.fs.path.join(allocator, &.{ root, "commands.log" });
    defer allocator.free(path);
    var file = Dir.cwd().openFile(io, path, .{ .mode = .write_only }) catch |err| switch (err) {
        error.FileNotFound => try Dir.cwd().createFile(io, path, .{}),
        else => return err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    var allocating: std.Io.Writer.Allocating = .init(allocator);
    defer allocating.deinit();
    for (argv) |argument| {
        try allocating.writer.print("{d}:", .{argument.len});
        for (argument) |character| switch (character) {
            '\n' => try allocating.writer.writeAll("\\n"),
            '\r' => try allocating.writer.writeAll("\\r"),
            else => try allocating.writer.writeByte(character),
        };
        try allocating.writer.writeByte('\x1f');
    }
    try allocating.writer.writeByte('\n');
    try file.writePositionalAll(io, allocating.written(), stat.size);
}

fn writeJsonString(out: *std.Io.Writer, text: []const u8) !void {
    var stringify: std.json.Stringify = .{
        .writer = out,
        .options = .{},
    };
    try stringify.write(text);
}

fn readStage(allocator: Allocator, io: Io, root: []const u8) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, "stage" });
    defer allocator.free(path);
    const bytes = Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(32),
    ) catch |err| switch (err) {
        error.FileNotFound => return allocator.dupe(u8, "absent"),
        else => return err,
    };
    return bytes;
}

fn writeStage(io: Io, root: []const u8, stage: []const u8) !void {
    var buffer: [1024]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, "{s}/stage", .{root});
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = stage });
}

fn ensureRemoteDirectory(allocator: Allocator, io: Io, root: []const u8) !void {
    const remote = try std.fs.path.join(allocator, &.{ root, "remote" });
    defer allocator.free(remote);
    try Dir.cwd().createDirPath(io, remote);
}

fn optionValue(argv: []const []const u8, name: []const u8) ?[]const u8 {
    for (argv, 0..) |argument, index| {
        if (std.mem.eql(u8, argument, name) and index + 1 < argv.len) {
            return argv[index + 1];
        }
    }
    return null;
}

fn fieldValue(argv: []const []const u8, name: []const u8) ?[]const u8 {
    for (argv) |argument| {
        if (!std.mem.startsWith(u8, argument, name) or
            argument.len <= name.len or argument[name.len] != '=')
        {
            continue;
        }
        return argument[name.len + 1 ..];
    }
    return null;
}

fn generatedNotes(scenario: []const u8) []const u8 {
    if (std.mem.eql(u8, scenario, "notes-mismatch")) {
        return "## What's Changed\n\n* Regenerated fixture changelog changed\n";
    }
    return "## What's Changed\n\n* Generated fixture changelog\n";
}

fn expectedReleaseBody(
    allocator: Allocator,
    tag: []const u8,
    scenario: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "**Install:**\n\n```console\nghr install cataggar/miz@{s}\n```\n\n\n{s}",
        .{ tag, generatedNotes(scenario) },
    );
}

fn parseTrailingId(endpoint: []const u8) !i64 {
    const slash = std.mem.lastIndexOfScalar(u8, endpoint, '/') orelse
        return error.InvalidAssetId;
    return std.fmt.parseInt(i64, endpoint[slash + 1 ..], 10);
}

fn assetId(name: []const u8) i64 {
    var value: u64 = 1000;
    for (name, 0..) |byte, index| value += @as(u64, byte) * (index + 1);
    return @intCast(value);
}

fn deleteAssetById(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    id: i64,
) !void {
    if (id == starter_asset_id) {
        const path = try std.fs.path.join(
            allocator,
            &.{ root, "starter-asset" },
        );
        defer allocator.free(path);
        try Dir.cwd().deleteFile(io, path);
        return;
    }
    const remote = try std.fs.path.join(allocator, &.{ root, "remote" });
    defer allocator.free(remote);
    var directory = try Dir.cwd().openDir(io, remote, .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind == .file and assetId(entry.name) == id) {
            try directory.deleteFile(io, entry.name);
            return;
        }
    }
    return error.AssetNotFound;
}

fn markerExists(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    name: []const u8,
) !bool {
    const path = try std.fs.path.join(allocator, &.{ root, name });
    defer allocator.free(path);
    var file = Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    file.close(io);
    return true;
}

fn incrementMarker(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    name: []const u8,
) !u64 {
    const current = readMarkerInt(allocator, io, root, name) catch 0;
    const next = current + 1;
    var buffer: [32]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{d}", .{next});
    try writeMarker(io, root, name, text);
    return next;
}

fn readMarkerInt(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    name: []const u8,
) !u64 {
    const text = try readMarker(allocator, io, root, name);
    defer allocator.free(text);
    return std.fmt.parseInt(u64, text, 10);
}

fn writeMarker(
    io: Io,
    root: []const u8,
    name: []const u8,
    contents: []const u8,
) !void {
    var buffer: [1024]u8 = undefined;
    const path = try std.fmt.bufPrint(&buffer, "{s}/{s}", .{ root, name });
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = contents });
}

fn readMarker(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    name: []const u8,
) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, name });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(1024),
    );
}

fn readAssetById(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    id: i64,
) ![]u8 {
    const remote = try std.fs.path.join(allocator, &.{ root, "remote" });
    defer allocator.free(remote);
    var directory = try Dir.cwd().openDir(io, remote, .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file or assetId(entry.name) != id) continue;
        const path = try std.fs.path.join(allocator, &.{ remote, entry.name });
        defer allocator.free(path);
        return Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(1024 * 1024),
        );
    }
    return error.AssetNotFound;
}
