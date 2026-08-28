//! Permanent guard against repository-owned Python.
//!
//! The migration to Zig is complete: no tracked `*.py` file may exist, and no
//! tracked file may execute a Python interpreter on the host or in a guest.
//! This test enforces both statements in CI.
//!
//! An invocation site is a `python`, `python3`, or `python3.12` token used as a
//! command (see `isCommandUse`), which is what an execution dependency looks
//! like in a shell script, a workflow, a build file, or an `argv` array. Prose
//! is deliberately invisible to this scan: a Zig doc comment saying a module
//! replaced a Python script names no command.
//!
//! A few compatibility strings have the shape of commands but execute nothing
//! here, such as interpreter lines used as test data. They are explicitly
//! allowlisted with exact site counts so any new interpreter-shaped string
//! still requires review.
//!
//! `.tools/` is excluded: it holds locally provisioned toolchains this
//! repository does not own, and it is not tracked by Git in any case. This file
//! is excluded from the invocation scan because its own fixtures are, by
//! construction, the command spellings the scanner must detect.
//!
const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Writer = std.Io.Writer;

const Entry = struct {
    path: []const u8,
    /// Inert compatibility-reference sites in the file, always at least one.
    sites: usize,
    note: []const u8,
};

/// This file's fixtures are the command spellings the scanner detects, so it
/// cannot be a subject of its own scan.
const guard_path = "tests/python_inventory.zig";

/// Inert compatibility references, sorted by path for review.
const inventory = [_]Entry{
    .{
        .path = "packages/miz/src/customize.zig",
        .sites = 2,
        .note = "hook interpreter lines in test data; nothing runs them",
    },
    .{
        .path = "packages/miz/src/unsafe_chroot.zig",
        .sites = 2,
        .note = "hook interpreter lines in test data; nothing runs them",
    },
    .{
        .path = "packages/miz/src/vm_backend.zig",
        .sites = 2,
        .note = "customization interpreter strings in test data",
    },
};

/// These are permanent invariants, not migration counters: neither may rise.
const remaining_source_files = 0;
const remaining_execution_sites = 0;

/// No tracked file is anywhere near this size, and the limit keeps a stray
/// large blob from being read into memory by this scan.
const max_tracked_file_bytes = 4 * 1024 * 1024;

/// Characters that continue a word. `-`, `.`, and `/` are included so a
/// command is read as one whole word: `python3-libs` and
/// `/usr/lib/python3/dist-packages` are single words whose final component is
/// not the interpreter, while `/usr/bin/python3` is a single word whose final
/// component is.
fn isWordByte(byte: u8) bool {
    return switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '.', '/', '-' => true,
        else => false,
    };
}

/// Whether `name` is exactly a lowercase `python`, `python3`, or `python3.12`.
/// The spelling is deliberately case-sensitive: a command is lowercase, while
/// prose about the language is capitalized.
fn isInterpreterName(name: []const u8) bool {
    if (!std.mem.startsWith(u8, name, "python")) return false;
    var index = "python".len;
    if (index == name.len) return true;
    if (!std.ascii.isDigit(name[index])) return false;
    while (index < name.len and std.ascii.isDigit(name[index])) index += 1;
    if (index == name.len) return true;
    if (name[index] != '.') return false;
    index += 1;
    if (index == name.len) return false;
    while (index < name.len and std.ascii.isDigit(name[index])) index += 1;
    return index == name.len;
}

/// Whether an interpreter word spanning `[start, end)` is being used as a
/// command.
///
/// Four spellings count, and they cover everything this repository could
/// plausibly write:
///
/// * a path spelling -- `/usr/bin/python3`, `#!/usr/bin/python3`,
///   `./.venv/bin/python3` -- which names the interpreter outright and is a
///   command wherever it appears;
/// * `"python3"` as an element of an `argv` array;
/// * `env python3`, which covers both a real `env` exec and a shebang; and
/// * a bare token followed by an argument, meaning an option, a redirect or
///   line continuation, a quoted or shell-expanded word, a path, or a `.py`
///   file.
///
/// A bare token followed by a bare word is not a command: that is a package
/// list (`file jq python3 systemd-boot-efi`) or a tool-presence loop.
fn isCommandUse(line: []const u8, start: usize, end: usize, path_spelled: bool) bool {
    if (path_spelled) return true;
    if (start > 0 and line[start - 1] == '"' and
        end < line.len and line[end] == '"') return true;
    if (start >= 4 and std.mem.eql(u8, line[start - 4 .. start], "env ")) return true;

    var index = end;
    while (index < line.len and (line[index] == ' ' or line[index] == '\t')) {
        index += 1;
    }
    if (index == end or index == line.len) return false;

    const argument = line[index..];
    const length = std.mem.indexOfAny(u8, argument, " \t") orelse argument.len;
    const word = argument[0..length];
    if (std.mem.indexOfScalar(u8, "-\\\"'$<", word[0]) != null) return true;
    if (std.mem.indexOfScalar(u8, word, '/') != null) return true;
    return std.mem.endsWith(u8, word, ".py");
}

/// Invocation sites on one line. The line is split into whole words so a word
/// is judged by its final path component: `/usr/bin/python3` is the
/// interpreter, `/usr/lib/python3/dist-packages` is a library directory, and
/// `python3-libs` is a package.
fn scanLine(line: []const u8) usize {
    var found: usize = 0;
    var index: usize = 0;
    while (index < line.len) {
        if (!isWordByte(line[index])) {
            index += 1;
            continue;
        }
        const start = index;
        while (index < line.len and isWordByte(line[index])) index += 1;
        const word = line[start..index];
        const separator = std.mem.lastIndexOfScalar(u8, word, '/');
        const name = if (separator) |at| word[at + 1 ..] else word;
        if (!isInterpreterName(name)) continue;
        if (isCommandUse(line, start, index, separator != null)) found += 1;
    }
    return found;
}

/// Invocation sites in a whole file. When `detail` is given, each site is
/// reported with its line number so a failure names what to look at.
fn scanFile(contents: []const u8, path: []const u8, detail: ?*Writer) !usize {
    var found: usize = 0;
    var number: usize = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw| {
        number += 1;
        const line = std.mem.trimEnd(u8, raw, "\r");
        const sites = scanLine(line);
        if (sites == 0) continue;
        found += sites;
        if (detail) |writer| try writer.print("    {s}:{d}: {s}\n", .{
            path,
            number,
            std.mem.trim(u8, line, " \t"),
        });
    }
    return found;
}

fn isTools(path: []const u8) bool {
    return std.mem.startsWith(u8, path, ".tools/");
}

fn isPythonSourcePath(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".py");
}

fn find(path: []const u8) ?Entry {
    for (inventory) |entry| {
        if (std.mem.eql(u8, entry.path, path)) return entry;
    }
    return null;
}

const TrackedFiles = struct {
    bytes: []u8,
    allocator: Allocator,

    fn deinit(self: *TrackedFiles) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    fn iterator(self: *const TrackedFiles) std.mem.SplitIterator(u8, .scalar) {
        return std.mem.splitScalar(u8, self.bytes, 0);
    }
};

/// The tree to scan. `build.zig` names the build root outright, so the guard
/// does not depend on which directory the test binary was started in, matching
/// the stale brand guard next to it. Caller owns the returned path.
fn repositoryRootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(
        allocator,
        "MIZ_PYTHON_INVENTORY_ROOT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
        else => return err,
    };
}

fn trackedFiles(allocator: Allocator, io: Io, root: []const u8) !TrackedFiles {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "git", "-C", root, "ls-files", "-z" },
        .stdout_limit = .limited(4 * 1024 * 1024),
    });
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);
    switch (result.term) {
        .exited => |code| if (code != 0) return error.GitListFailed,
        else => return error.GitListFailed,
    }
    return .{ .bytes = result.stdout, .allocator = allocator };
}

fn report(failures: *Writer.Allocating) !void {
    if (failures.written().len == 0) return;
    std.debug.print("\n{s}", .{failures.written()});
    return error.PythonInventoryStale;
}

test "the inventory is sorted, unique, and internally consistent" {
    var previous: []const u8 = "";
    for (inventory) |entry| {
        try std.testing.expect(std.mem.lessThan(u8, previous, entry.path));
        previous = entry.path;
        try std.testing.expect(entry.note.len > 0);
        try std.testing.expect(!isPythonSourcePath(entry.path));
        try std.testing.expect(entry.sites > 0);
        try std.testing.expect(!isTools(entry.path));
        try std.testing.expect(!std.mem.eql(u8, entry.path, guard_path));
    }
    try std.testing.expectEqual(@as(usize, 0), remaining_execution_sites);
}

test "nothing in this repository executes Python" {
    try std.testing.expectEqual(@as(usize, 0), remaining_execution_sites);
}

test "no tracked file is Python source" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);
    var tracked = try trackedFiles(allocator, io, root);
    defer tracked.deinit();

    var failures: Writer.Allocating = .init(allocator);
    defer failures.deinit();

    var sources: usize = 0;
    var paths = tracked.iterator();
    while (paths.next()) |path| {
        if (path.len == 0 or isTools(path)) continue;
        if (!isPythonSourcePath(path)) continue;
        sources += 1;
        try failures.writer.print(
            "{s}: tracked Python source; this repository owns no Python " ++
                "programs. Port it to Zig or delete it.\n",
            .{path},
        );
    }

    try report(&failures);
    try std.testing.expectEqual(remaining_source_files, sources);
}

test "every Python invocation site outside a Python file is inventoried" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);
    var tracked = try trackedFiles(allocator, io, root);
    defer tracked.deinit();

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var failures: Writer.Allocating = .init(allocator);
    defer failures.deinit();

    var paths = tracked.iterator();
    while (paths.next()) |path| {
        if (path.len == 0 or isTools(path)) continue;
        // A `*.py` file is rejected whole by the source guard; counting its
        // interior sites here would only restate that failure.
        if (isPythonSourcePath(path)) continue;
        if (std.mem.eql(u8, path, guard_path)) continue;

        const full_path = try std.fs.path.join(allocator, &.{ root, path });
        defer allocator.free(full_path);

        const stat = Dir.cwd().statFile(io, full_path, .{}) catch |err| switch (err) {
            // A tracked symlink pointing outside the tree is not a file to
            // scan; nothing else may fail silently.
            error.FileNotFound => continue,
            else => return err,
        };
        if (stat.kind != .file) continue;
        try std.testing.expect(stat.size <= max_tracked_file_bytes);

        const contents = try Dir.cwd().readFileAlloc(
            io,
            full_path,
            allocator,
            .limited(max_tracked_file_bytes),
        );
        defer allocator.free(contents);

        const sites = try scanFile(contents, path, null);
        const entry = find(path);
        if (sites == 0) {
            if (entry != null) {
                // Recorded as seen so the sweep below does not repeat this.
                try seen.put(path, {});
                try failures.writer.print(
                    "{s}: inventoried but invokes Python nowhere; remove the entry\n",
                    .{path},
                );
            }
            continue;
        }

        try seen.put(path, {});
        const listed = entry orelse {
            try failures.writer.print(
                "{s}: {d} Python invocation site(s) are not inventoried\n",
                .{ path, sites },
            );
            _ = try scanFile(contents, path, &failures.writer);
            continue;
        };
        if (listed.sites != sites) {
            try failures.writer.print(
                "{s}: reference allowlist records {d} invocation site(s), found {d}\n",
                .{ path, listed.sites, sites },
            );
            _ = try scanFile(contents, path, &failures.writer);
        }
    }

    for (inventory) |entry| {
        if (seen.contains(entry.path)) continue;
        try failures.writer.print(
            "{s}: allowlisted but no longer tracked or no longer contains a Python reference; remove the entry\n",
            .{entry.path},
        );
    }

    try report(&failures);
}

test "command spellings this repository uses are detected" {
    const commands = [_][]const u8{
        "          python3 scripts/azurelinux4_release.py candidate \\",
        "        run: python3 -m unittest tests.stale_brand_test",
        "  python3 - \"$manifest\" <<'PY'",
        "matrix=$(python3 scripts/freebsd15_release.py matrix \\",
        "test \"$(python3 -c 'import json,sys; print(1)' \"$matrix\")\" -eq 4",
        "python3 \"$RELEASE_SCHEMA\" verify-candidate \\",
        "readarray -t object < <(python3 - \"$refs_file\" <<'PY'",
        "sudo -E python3 scripts/ubuntu2604_image_benchmark.py \\",
        "          python3 - \\",
        "        .argv = &.{ \"python3\", \"-c\", script, encoded },",
        "status=$(cloud-init status --format json | python3 -c 'import sys')",
        "#!/usr/bin/env python3",
        "#! /usr/bin/env python3  ",
        "        .interpreter = \"/usr/bin/env python3\",",
        "python3.12 -m venv .venv",
        "python <<'PY'",
        "/usr/bin/python3 -c 'import sys'",
        "#!/usr/bin/python3",
        "#!/usr/bin/python3 -u",
        "        ./.venv/bin/python3 -m pip install --require-hashes -r r.txt",
        "        .argv = &.{ \"/usr/bin/python3\", \"-c\", script },",
        "exec /usr/local/bin/python3.12 \"$@\"",
    };
    for (commands) |line| {
        try std.testing.expectEqual(@as(usize, 1), scanLine(line));
    }
}

test "package names, tool checks, paths, and prose are not invocations" {
    // Every line here is one this repository actually contains. The first two
    // are the migration commentary a completed port leaves behind: naming the
    // Python package a Zig module replaced, and saying the module needs no
    // Python at all. Neither may enter the inventory, or a port would appear
    // to add the dependency it removed.
    const not_commands = [_][]const u8{
        "//! `python3-virt-firmware`. It understands the exact on-media layout that the",
        "`virt-fw-vars` host tool: no Python, no subprocess. Only a raw flash image",
        "  for tool in az azcopy qemu-img ssh ssh-keygen python3; do",
        "  for tool in python3 sha256sum; do",
        "            file jq python3 systemd-boot-efi",
        "  /usr/lib/python3/dist-packages/cloudinit \\",
        "\\\\  /usr/lib/python3/dist-packages/azurelinuxagent",
        "  /usr/lib/python3.12/site-packages/pip/__init__.py",
        "  install -d \"$root/usr/lib/python3/dist-packages\"",
        "(`systemd-boot-efi`), `python3`, `file`, and `jq`. HTTPS/OpenPGP",
        "longer installs or invokes `systemd-ukify`, `python3-pefile`, or a",
        "//! Native Zig replacement for the provisioning portion of Python",
        "//! The Python release scripts share two JSON contracts. `read_json`",
        "/// `require_sha256` from the Python release scripts: the value must",
        "    const hyphenated = parseRecord(\"python3-libs-0:3.12.9-1.azl3\").?;",
        "// `python3-` and is a different package, not a different version of",
        "    // Python's lzma module (lzma.compress(..., format=FORMAT_XZ,",
        "            .root_source_file = b.path(\"tests/python_inventory.zig\"),",
        "    const run_python_inventory_tests = b.addRunArtifact(tests);",
        "        \"test-python-inventory\",",
        "        run: zig build test-python-inventory",
        "  if ! pgrep -f 'python.*waagent' >/dev/null 2>&1 && \\",
        "# python3 parser below into an empty string exactly like any other",
        "not use libapt-pkg or python-apt. Static init, guest, and cross-target",
    };
    for (not_commands) |line| {
        try std.testing.expectEqual(@as(usize, 0), scanLine(line));
    }
}

test "sites are counted per occurrence and reported with line numbers" {
    try std.testing.expectEqual(
        @as(usize, 2),
        scanLine("python3 -c 'a' && python3 -c 'b'"),
    );

    const contents =
        "first line\n" ++
        "python3 -m unittest\n" ++
        "no command here\n" ++
        "  python3 scripts/thing.py\r\n";
    try std.testing.expectEqual(
        @as(usize, 2),
        try scanFile(contents, "sample.sh", null),
    );

    var detail: Writer.Allocating = .init(std.testing.allocator);
    defer detail.deinit();
    _ = try scanFile(contents, "sample.sh", &detail.writer);
    try std.testing.expectEqualStrings(
        "    sample.sh:2: python3 -m unittest\n" ++
            "    sample.sh:4: python3 scripts/thing.py\n",
        detail.written(),
    );
}
