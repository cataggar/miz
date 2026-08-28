//! Shared fixtures and process helpers for the FreeBSD 15.1 release tests.
//!
//! Both suites read the tracked tree -- the release workflow, the shell
//! harness, the Zig builder profiles -- and both drive real files through the
//! release tooling, so the plumbing for "where is the repository", "run this
//! bash fragment", and "build a candidate that would pass" lives once here.

const std = @import("std");
const freebsd15 = @import("freebsd15");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;
const profiles = freebsd15.profiles;
const candidate_support = freebsd15.candidate;
const document = freebsd15.document;

pub const Context = freebsd15.Context;

/// No tracked file this suite reads is anywhere near this size.
pub const max_source_bytes: u64 = 4 * 1024 * 1024;
/// A generated bash harness plus its captured output.
pub const max_process_output: u64 = 1024 * 1024;

/// The build root, named outright by `build.zig` so the suites do not depend
/// on which directory the test binary was started in.
pub fn repositoryRoot(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(allocator, "MIZ_FREEBSD15_ROOT") catch |err|
        switch (err) {
            error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
            else => return err,
        };
}

/// Reads a tracked file, relative to the build root. Caller owns the bytes.
pub fn readSource(allocator: Allocator, relative: []const u8) ![]u8 {
    const root = try repositoryRoot(allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(max_source_bytes),
    );
}

pub fn sourcePath(allocator: Allocator, relative: []const u8) ![]u8 {
    const root = try repositoryRoot(allocator);
    defer allocator.free(root);
    return std.fs.path.join(allocator, &.{ root, relative });
}

// ---- Text assertions ------------------------------------------------------

/// The interpreter name these suites assert is absent from the FreeBSD release
/// scripts and workflow. Spelled in halves so this suite's own tracked bytes
/// never look like an invocation site to `tests/python_inventory.zig`, the same
/// way the stale brand guard avoids carrying what it rejects.
pub const interpreter_name = "pyt" ++ "hon";

pub fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

pub fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (contains(haystack, needle)) return;
    std.debug.print("\nexpected to find:\n{s}\n", .{needle});
    return error.MissingExpectedText;
}

pub fn expectAbsent(haystack: []const u8, needle: []const u8) !void {
    if (!contains(haystack, needle)) return;
    std.debug.print("\nexpected not to find:\n{s}\n", .{needle});
    return error.UnexpectedText;
}

/// Position of `needle` at or after `from`, as a hard failure when absent, so
/// ordering assertions read like the Python `content.index(...)` they replace.
pub fn indexFrom(haystack: []const u8, needle: []const u8, from: usize) !usize {
    const at = std.mem.indexOfPos(u8, haystack, from, needle) orelse {
        std.debug.print("\nexpected to find after {d}:\n{s}\n", .{ from, needle });
        return error.MissingExpectedText;
    };
    return at;
}

pub fn indexOf(haystack: []const u8, needle: []const u8) !usize {
    return indexFrom(haystack, needle, 0);
}

/// The slice between two markers, both of which must be present in order.
pub fn between(
    haystack: []const u8,
    start_marker: []const u8,
    end_marker: []const u8,
) ![]const u8 {
    const start = try indexOf(haystack, start_marker);
    const end = try indexFrom(haystack, end_marker, start);
    return haystack[start..end];
}

// ---- Process helpers ------------------------------------------------------

pub const Run = struct {
    stdout: []u8,
    stderr: []u8,
    code: u8,

    pub fn deinit(self: *Run, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }
};

/// Runs `argv`, capturing both streams and the exit status. A signal is
/// reported as a distinct, impossible exit code rather than silently passing.
pub fn runProcess(allocator: Allocator, argv: []const []const u8) !Run {
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = argv,
        .stdout_limit = .limited(max_process_output),
        .stderr_limit = .limited(max_process_output),
    });
    return .{
        .stdout = result.stdout,
        .stderr = result.stderr,
        .code = switch (result.term) {
            .exited => |code| code,
            else => 255,
        },
    };
}

/// Runs a generated shell fragment with the named interpreter. The fragment
/// carries its own variable assignments, so no environment is inherited from
/// the test beyond `PATH`.
pub fn runShell(
    allocator: Allocator,
    interpreter: []const u8,
    script: []const u8,
) !Run {
    return runProcess(allocator, &.{ interpreter, "-c", script });
}

/// Extracts one shell function from the harness, from its `name() {` header to
/// the first line that is exactly `}`.
pub fn shellFunction(
    allocator: Allocator,
    source: []const u8,
    name: []const u8,
) ![]const u8 {
    const header = try std.fmt.allocPrint(allocator, "{s}() {{", .{name});
    defer allocator.free(header);
    const start = try indexOf(source, header);
    const end = try indexFrom(source, "\n}\n", start);
    return source[start .. end + 3];
}

/// Extracts a run of consecutive shell functions, from the first one's header
/// to the end of the `count`-th function body.
pub fn shellFunctionRun(
    allocator: Allocator,
    source: []const u8,
    name: []const u8,
    count: usize,
) ![]const u8 {
    const header = try std.fmt.allocPrint(allocator, "{s}() {{", .{name});
    defer allocator.free(header);
    const start = try indexOf(source, header);
    var end = try indexFrom(source, "\n}\n", start) + 3;
    for (1..count) |_| end = try indexFrom(source, "\n}\n", end) + 3;
    return source[start..end];
}

// ---- Scratch trees --------------------------------------------------------

/// A private directory per test, reachable by a working-directory-relative
/// path so the tooling is exercised exactly as its callers use it.
pub const Tree = struct {
    tmp: std.testing.TmpDir,
    arena: std.heap.ArenaAllocator,
    root: []const u8,

    pub fn create(gpa: Allocator) !Tree {
        const tmp = std.testing.tmpDir(.{});
        var arena: std.heap.ArenaAllocator = .init(gpa);
        const root = try std.fmt.allocPrint(
            arena.allocator(),
            ".zig-cache/tmp/{s}",
            .{tmp.sub_path},
        );
        return .{ .tmp = tmp, .arena = arena, .root = root };
    }

    pub fn deinit(self: *Tree) void {
        self.arena.deinit();
        self.tmp.cleanup();
        self.* = undefined;
    }

    pub fn allocator(self: *Tree) Allocator {
        return self.arena.allocator();
    }

    pub fn path(self: *Tree, parts: []const []const u8) ![]const u8 {
        var joined: std.ArrayList([]const u8) = .empty;
        try joined.append(self.allocator(), self.root);
        for (parts) |part| try joined.append(self.allocator(), part);
        return std.fs.path.join(self.allocator(), joined.items);
    }

    pub fn context(self: *Tree, gpa: Allocator) Context {
        return .{ .gpa = gpa, .arena = self.allocator(), .io = std.testing.io };
    }

    pub fn write(self: *Tree, relative: []const u8, data: []const u8) ![]const u8 {
        const full = try self.path(&.{relative});
        if (std.fs.path.dirname(full)) |parent| {
            try Dir.cwd().createDirPath(std.testing.io, parent);
        }
        try Dir.cwd().writeFile(std.testing.io, .{ .sub_path = full, .data = data });
        return full;
    }

    pub fn read(self: *Tree, relative: []const u8) ![]u8 {
        const full = try self.path(&.{relative});
        return Dir.cwd().readFileAlloc(
            std.testing.io,
            full,
            self.allocator(),
            .limited(max_source_bytes),
        );
    }

    pub fn readAbsolute(self: *Tree, full: []const u8) ![]u8 {
        return Dir.cwd().readFileAlloc(
            std.testing.io,
            full,
            self.allocator(),
            .limited(max_source_bytes),
        );
    }

    /// Base names of the regular files directly inside `relative`, sorted.
    pub fn list(self: *Tree, relative: []const u8) ![]const []const u8 {
        const full = try self.path(&.{relative});
        var directory = try Dir.cwd().openDir(std.testing.io, full, .{ .iterate = true });
        defer directory.close(std.testing.io);
        var names: std.ArrayList([]const u8) = .empty;
        var iterator = directory.iterate();
        while (try iterator.next(std.testing.io)) |entry| {
            if (entry.kind != .file) continue;
            try names.append(
                self.allocator(),
                try self.allocator().dupe(u8, entry.name),
            );
        }
        std.mem.sort([]const u8, names.items, {}, lessThan);
        return names.items;
    }

    pub fn remove(self: *Tree, relative: []const u8) !void {
        const full = try self.path(&.{relative});
        Dir.cwd().deleteTree(std.testing.io, full) catch {};
    }
};

fn lessThan(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

pub fn expectNames(actual: []const []const u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected) |wanted| {
        var found = false;
        for (actual) |name| {
            if (std.mem.eql(u8, name, wanted)) found = true;
        }
        if (!found) {
            std.debug.print("\nmissing entry: {s}\n", .{wanted});
            return error.MissingExpectedText;
        }
    }
}

// ---- Release fixtures -----------------------------------------------------

pub const source_commit = "a" ** 40;
pub const release_date = "20260812";

/// The recorded `<asset>.packages.txt` a builder would have produced, with
/// optional additions and omissions so a test can express a defect.
pub fn writePackageManifest(
    tree: *Tree,
    key: []const u8,
    directory: []const u8,
    extra: []const []const u8,
    drop: []const []const u8,
) ![]const u8 {
    const variant = profiles.findVariant(key).?;
    const manifest = profiles.packageManifest(
        variant.filesystem,
        variant.flavor,
    ).?;
    var text: std.Io.Writer.Allocating = .init(tree.allocator());
    for ([_][]const []const u8{ manifest.required, manifest.library_roots }) |group| {
        for (group) |name| {
            var dropped = false;
            for (drop) |unwanted| {
                if (std.mem.eql(u8, unwanted, name)) dropped = true;
            }
            if (dropped) continue;
            try text.writer.print("{s} 15.1 1024\n", .{name});
        }
    }
    for (extra) |name| try text.writer.print("{s} 15.1 1024\n", .{name});
    const relative = try std.fmt.allocPrint(
        tree.allocator(),
        "{s}/{s}.packages.txt",
        .{ directory, variant.asset_name },
    );
    return tree.write(relative, text.written());
}

/// The trusted `qemu-img info --output=json` document the build job captured.
pub fn writeQemuInfo(
    tree: *Tree,
    key: []const u8,
    directory: []const u8,
    allocated_size: u64,
) ![]const u8 {
    const variant = profiles.findVariant(key).?;
    const text = try std.fmt.allocPrint(tree.allocator(),
        \\{{"format": "qcow2", "virtual-size": {d}, "actual-size": {d},
        \\ "backing-filename": "",
        \\ "format-specific": {{"data": {{"compression-type": "zstd"}}}}}}
    , .{ variant.virtual_size, allocated_size });
    const relative = try std.fmt.allocPrint(
        tree.allocator(),
        "{s}/{s}-qemu-info.json",
        .{ directory, key },
    );
    return tree.write(relative, text);
}

pub const CandidateOptions = struct {
    allocated_size: ?u64 = null,
    compressed_size: ?u64 = null,
    source_commit: []const u8 = source_commit,
};

/// A complete candidate directory: the asset, its recorded package manifest,
/// the trusted qemu-img document, and the candidate manifest binding them.
pub fn makeCandidate(
    tree: *Tree,
    gpa: Allocator,
    key: []const u8,
    options: CandidateOptions,
) ![]const u8 {
    const variant = profiles.findVariant(key).?;
    const default_size: u64 = if (std.mem.eql(u8, variant.flavor, "full")) 1000 else 800;
    const allocated = options.allocated_size orelse default_size;
    const compressed = options.compressed_size orelse allocated;

    const directory = try std.fmt.allocPrint(
        tree.allocator(),
        "candidates/{s}",
        .{key},
    );
    const asset_relative = try std.fmt.allocPrint(
        tree.allocator(),
        "{s}/{s}",
        .{ directory, variant.asset_name },
    );
    const body = try tree.allocator().alloc(u8, @intCast(compressed));
    @memset(body, 'x');
    const asset = try tree.write(asset_relative, body);
    const package_manifest = try writePackageManifest(tree, key, directory, &.{}, &.{});
    const qemu_info = try writeQemuInfo(tree, key, directory, allocated);
    const output = try tree.path(&.{ directory, "candidate.json" });

    var url_buffer: [profiles.max_source_url_len]u8 = undefined;
    var context = tree.context(gpa);
    const digest = try candidate_support.hashFile(&context, asset);
    try candidate_support.candidateCommand(&context, .{
        .architecture = variant.architecture,
        .filesystem = variant.filesystem,
        .flavor = variant.flavor,
        .package_manifest = package_manifest,
        .asset = asset,
        .validated_sha256 = try tree.allocator().dupe(u8, &digest),
        .virtual_size = @intCast(variant.virtual_size),
        .qemu_info = qemu_info,
        .source_name = variant.source_name,
        .source_url = try tree.allocator().dupe(u8, variant.sourceUrl(&url_buffer)),
        .source_sha256 = variant.source_sha256,
        .source_bytes = 123456789,
        .source_commit = options.source_commit,
        .qemu_version = "QEMU emulator version 10.0.2",
        .runner = variant.runner,
        .run_id = "5001",
        .run_attempt = "7",
        .output = output,
    });
    return output;
}

/// An Azure acceptance result for a candidate, written directly so a test can
/// then corrupt exactly one field.
pub fn makeAzureResult(
    tree: *Tree,
    gpa: Allocator,
    key: []const u8,
) ![]const u8 {
    const candidate_path = try tree.path(&.{ "candidates", key, "candidate.json" });
    if (!candidate_support.isRegularFile(std.testing.io, candidate_path)) {
        _ = try makeCandidate(tree, gpa, key, .{});
    }
    const variant = profiles.findVariant(key).?;
    const raw = try tree.readAbsolute(candidate_path);
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    const candidate = parsed.value.object;
    const validation = candidate.get("validation").?.object;
    const contracts = profiles.azureContracts(variant.filesystem).?;

    var text: std.Io.Writer.Allocating = .init(tree.allocator());
    try text.writer.print(
        \\{{"schema": {d}, "type": "miz-freebsd15-azure-acceptance",
        \\ "variant": "{s}", "architecture": "{s}", "filesystem": "{s}",
        \\ "flavor": "{s}", "asset_name": "{s}", "source_commit": "{s}",
        \\ "qcow_sha256": "{s}", "qcow_virtual_size": {d},
        \\ "qcow_allocated_size": {d}, "qcow_compressed_size": {d},
        \\ "derived_vhd_sha256": "{s}", "derived_vhd_bytes": 7340544,
        \\ "derived_vhd_current_size": 7340032, "status": "success",
        \\ "location": "eastus2", "vm_size": "Standard_D2s_v5",
        \\ "resource_group": "rg-miz-release", "contracts": [
    , .{
        profiles.candidate_schema,
        key,
        variant.architecture,
        variant.filesystem,
        variant.flavor,
        variant.asset_name,
        document.stringOf(candidate.get("source_commit")).?,
        document.stringOf(candidate.get("asset_sha256")).?,
        document.integerOf(candidate.get("virtual_size")).?,
        document.integerOf(candidate.get("allocated_size")).?,
        document.integerOf(candidate.get("compressed_size")).?,
        "d" ** 64,
    });
    for (contracts, 0..) |name, index| {
        if (index > 0) try text.writer.writeAll(", ");
        try text.writer.print("\"{s}\"", .{name});
    }
    try text.writer.print(
        \\], "workflow": {{"run_id": "{s}", "run_attempt": "{s}"}}}}
    , .{
        document.stringOf(validation.get("run_id")).?,
        document.stringOf(validation.get("run_attempt")).?,
    });

    const relative = try std.fmt.allocPrint(
        tree.allocator(),
        "azure-results/{s}/azure-result.json",
        .{key},
    );
    return tree.write(relative, text.written());
}

/// Replaces or removes one dotted field of a JSON document in place, so a test
/// can state exactly which claim it is corrupting.
pub fn mutateDocument(
    tree: *Tree,
    path: []const u8,
    field: []const u8,
    value_text: ?[]const u8,
) !void {
    const raw = try tree.readAbsolute(path);
    var parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    var owner: *Value = &parsed.value;
    var components = std.mem.splitScalar(u8, field, '.');
    var last: []const u8 = "";
    while (components.next()) |component| {
        if (components.peek() == null) {
            last = component;
            break;
        }
        owner = owner.object.getPtr(component).?;
    }
    if (value_text) |text| {
        const value = try std.json.parseFromSlice(Value, tree.allocator(), text, .{});
        try owner.object.put(tree.allocator(), last, value.value);
    } else {
        _ = owner.object.orderedRemove(last);
    }

    var out: std.Io.Writer.Allocating = .init(tree.allocator());
    var stringify: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    try stringify.write(parsed.value);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = out.written(),
    });
}

/// Appends a value to a JSON array reached by a dotted path.
pub fn appendToDocumentArray(
    tree: *Tree,
    path: []const u8,
    field: []const u8,
    value_text: []const u8,
) !void {
    const raw = try tree.readAbsolute(path);
    var parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    var owner: *Value = &parsed.value;
    var components = std.mem.splitScalar(u8, field, '.');
    while (components.next()) |component| {
        owner = owner.object.getPtr(component).?;
    }
    const value = try std.json.parseFromSlice(Value, tree.allocator(), value_text, .{});
    try owner.array.append(value.value);

    var out: std.Io.Writer.Allocating = .init(tree.allocator());
    var stringify: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    try stringify.write(parsed.value);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = out.written(),
    });
}

test "the repository root resolves and holds this suite's subjects" {
    const allocator = std.testing.allocator;
    const workflow = try readSource(allocator, ".github/workflows/freebsd15-release.yml");
    defer allocator.free(workflow);
    try expectContains(workflow, "name: Publish FreeBSD 15.1 images");
}

test "shell function extraction returns exactly one function" {
    const allocator = std.testing.allocator;
    const source =
        \\prefix() {
        \\  :
        \\}
        \\
        \\wanted() {
        \\  echo one
        \\}
        \\
        \\after() {
        \\  echo two
        \\}
        \\
    ;
    const extracted = try shellFunction(allocator, source, "wanted");
    try std.testing.expectEqualStrings("wanted() {\n  echo one\n}\n", extracted);
    const run = try shellFunctionRun(allocator, source, "wanted", 2);
    try expectContains(run, "after() {");
    try expectAbsent(run, "prefix() {");
}

test "a scratch tree is private and cleans itself up" {
    var tree = try Tree.create(std.testing.allocator);
    var alive = true;
    defer if (alive) tree.deinit();
    const path = try tree.write("nested/file.txt", "contents\n");
    try std.testing.expectEqualStrings("contents\n", try tree.read("nested/file.txt"));
    tree.deinit();
    alive = false;
    try std.testing.expect(
        !candidate_support.isRegularFile(std.testing.io, path),
    );
}
