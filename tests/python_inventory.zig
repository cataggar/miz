//! Temporary inventory of the Python this repository still owns.
//!
//! The repository is migrating every repository-owned Python program and every
//! Python invocation to Zig. Until that finishes, a partially migrated tree has
//! to be able to state precisely what Python is left, so review can see each
//! port shrink the list and can catch a new dependency being added by accident.
//! This test is that statement, enforced by CI rather than by convention.
//!
//! Two things are tracked, because they are removed differently.
//!
//! * Every tracked `*.py` file is listed as `.source`. A port deletes these
//!   whole, so only their presence is tracked.
//! * Every *invocation site* in any other tracked file is counted. An
//!   invocation site is a `python`, `python3`, or `python3.12` token used as a
//!   command (see `isCommandUse`), which is what an execution dependency
//!   actually looks like in a shell script, a workflow, a build file, or an
//!   `argv` array. Prose is deliberately invisible to this scan: a Zig doc
//!   comment saying a module replaced a Python script names no command, so
//!   migration commentary never enters the inventory and the list can only
//!   shrink as ports land.
//!
//! Each non-source entry declares what its sites are: `.execution` runs Python
//! on the host or in a guest, `.documentation` shows a Python command to a
//! reader, and `.reference` is an explicitly exempted compatibility string --
//! an interpreter line in test data, for example -- that has the shape of a
//! command but executes nothing here. Only `.execution` blocks the zero-Python
//! goal; `.reference` entries may outlive the migration.
//!
//! `.tools/` is excluded: it holds locally provisioned toolchains this
//! repository does not own, and it is not tracked by Git in any case. This file
//! is excluded from the invocation scan because its own fixtures are, by
//! construction, the command spellings the scanner must detect.
//!
//! When the last entry is gone, this file is replaced by a permanent
//! zero-Python guard.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Writer = std.Io.Writer;

/// What a tracked file's invocation sites actually are.
const Kind = enum {
    /// A repository-owned Python program or test.
    source,
    /// The file executes Python, on the host or inside a guest.
    execution,
    /// Documentation that shows a Python command to a reader.
    documentation,
    /// An explicitly exempted compatibility string: it has the shape of a
    /// command but nothing in this repository executes it.
    reference,
};

const Entry = struct {
    path: []const u8,
    kind: Kind,
    /// Invocation sites in the file. `null` for `.source` entries, whose unit
    /// of removal is the whole file.
    sites: ?usize = null,
    note: []const u8,
};

/// This file's fixtures are the command spellings the scanner detects, so it
/// cannot be a subject of its own scan.
const guard_path = "tests/python_inventory.zig";

/// Sorted by path. Keep it sorted: review reads this as a checklist.
const inventory = [_]Entry{
    .{
        .path = ".github/workflows/azurelinux4-release.yml",
        .kind = .execution,
        .sites = 3,
        .note = "inline Python plus azurelinux4_release.py",
    },
    .{
        .path = ".github/workflows/boot-smoke.yml",
        .kind = .execution,
        .sites = 3,
        .note = "the three OCI fixture generators under scripts/ci",
    },
    .{
        .path = ".github/workflows/ci.yml",
        .kind = .execution,
        .sites = 4,
        .note = "unittest invocations for the remaining Python test suites",
    },
    .{
        .path = ".github/workflows/freebsd15-release.yml",
        .kind = .execution,
        .sites = 6,
        .note = "matrix, describe, candidate, and inline Python",
    },
    .{
        .path = ".github/workflows/ubuntu2604-core-validation.yml",
        .kind = .execution,
        .sites = 10,
        .note = "ubuntu2604_release.py and inline Python",
    },
    .{
        .path = ".github/workflows/ubuntu2604-image-benchmark.yml",
        .kind = .execution,
        .sites = 4,
        .note = "the benchmark driver and inline evidence Python",
    },
    .{
        .path = ".github/workflows/ubuntu2604-release.yml",
        .kind = .execution,
        .sites = 7,
        .note = "ubuntu2604_release.py and inline Python",
    },
    .{
        .path = "doc/freebsd.md",
        .kind = .documentation,
        .sites = 1,
        .note = "shows freebsd15_release.py compare",
    },
    .{
        .path = "doc/ubuntu.md",
        .kind = .documentation,
        .sites = 1,
        .note = "shows the image benchmark command",
    },
    .{
        .path = "packages/miz/src/customize.zig",
        .kind = .reference,
        .sites = 2,
        .note = "hook interpreter lines in test data; nothing runs them",
    },
    .{
        .path = "packages/miz/src/kernel_modules.zig",
        .kind = .execution,
        .sites = 1,
        .note = "test-only XZ fixture built by spawning python3",
    },
    .{
        .path = "packages/miz/src/squashfs.zig",
        .kind = .execution,
        .sites = 1,
        .note = "test-only XZ fixture built by spawning python3",
    },
    .{
        .path = "packages/miz/src/unsafe_chroot.zig",
        .kind = .reference,
        .sites = 2,
        .note = "hook interpreter lines in test data; nothing runs them",
    },
    .{
        .path = "packages/miz/src/vm_backend.zig",
        .kind = .reference,
        .sites = 2,
        .note = "customization interpreter strings in test data",
    },
    .{
        .path = "scripts/azure_vhd.py",
        .kind = .source,
        .note = "superseded by scripts/azure_vhd.zig; callers still run the Python",
    },
    .{
        .path = "scripts/azurelinux4_azure_acceptance.sh",
        .kind = .execution,
        .sites = 14,
        .note = "inline Python and azurelinux4_release.py",
    },
    .{
        .path = "scripts/azurelinux4_publish.sh",
        .kind = .execution,
        .sites = 8,
        .note = "inline Python and azurelinux4_release.py",
    },
    .{
        .path = "scripts/azurelinux4_release.py",
        .kind = .source,
        .note = "ported by the Azure Linux release slice",
    },
    .{
        .path = "scripts/ci/make-minimal-oci-fixture.py",
        .kind = .source,
        .note = "ported by the OCI fixture slice",
    },
    .{
        .path = "scripts/ci/make-uki-stub-oci-fixture.py",
        .kind = .source,
        .note = "ported by the OCI fixture slice",
    },
    .{
        .path = "scripts/ci/make-verity-initramfs-oci-fixture.py",
        .kind = .source,
        .note = "ported by the OCI fixture slice",
    },
    .{
        .path = "scripts/ci/oci_layout.py",
        .kind = .source,
        .note = "ported by the OCI fixture slice",
    },
    .{
        .path = "scripts/freebsd15_azure_acceptance.sh",
        .kind = .execution,
        .sites = 15,
        .note = "inline Python, azure_vhd.py, and freebsd15_release.py",
    },
    .{
        .path = "scripts/freebsd15_azure_metadata.py",
        .kind = .source,
        .note = "ported by the FreeBSD release slice",
    },
    .{
        .path = "scripts/freebsd15_publish.sh",
        .kind = .execution,
        .sites = 6,
        .note = "inline Python and freebsd15_release.py",
    },
    .{
        .path = "scripts/freebsd15_release.py",
        .kind = .source,
        .note = "ported by the FreeBSD release slice",
    },
    .{
        .path = "scripts/freebsd15_stage_release.sh",
        .kind = .execution,
        .sites = 5,
        .note = "inline Python and freebsd15_release.py",
    },
    .{
        .path = "scripts/ubuntu2604_azure_acceptance.sh",
        .kind = .execution,
        .sites = 22,
        .note = "inline Python and ubuntu2604_release.py",
    },
    .{
        .path = "scripts/ubuntu2604_image_benchmark.py",
        .kind = .source,
        .note = "ported by the benchmark slice",
    },
    .{
        .path = "scripts/ubuntu2604_local_e2e.sh",
        .kind = .execution,
        .sites = 1,
        .note = "inline Python that checks the local image-info document",
    },
    .{
        .path = "scripts/ubuntu2604_publish.sh",
        .kind = .execution,
        .sites = 8,
        .note = "inline Python and ubuntu2604_release.py",
    },
    .{
        .path = "scripts/ubuntu2604_release.py",
        .kind = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "tests/azurelinux4_release_test.py",
        .kind = .source,
        .note = "ported by the Azure Linux release slice",
    },
    .{
        .path = "tests/freebsd15_azure_acceptance_test.py",
        .kind = .source,
        .note = "ported by the FreeBSD release slice",
    },
    .{
        .path = "tests/freebsd15_release_test.py",
        .kind = .source,
        .note = "ported by the FreeBSD release slice",
    },
    .{
        .path = "tests/stale_brand_test.py",
        .kind = .source,
        .note = "ported by the stale brand guard slice",
    },
    .{
        .path = "tests/ubuntu2604_acceptance.zig",
        .kind = .execution,
        .sites = 1,
        .note = "guest-side script parses cloud-init status with python3",
    },
    .{
        .path = "tests/ubuntu2604_azure_acceptance_test.py",
        .kind = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "tests/ubuntu2604_core_workflow_test.py",
        .kind = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "tests/ubuntu2604_image_benchmark_test.py",
        .kind = .source,
        .note = "ported by the benchmark slice",
    },
    .{
        .path = "tests/ubuntu2604_image_benchmark_workflow_test.py",
        .kind = .source,
        .note = "ported by the benchmark slice",
    },
    .{
        .path = "tests/ubuntu2604_release_test.py",
        .kind = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "tests/ubuntu2604_workflow_test.py",
        .kind = .source,
        .note = "ported by the Ubuntu release slice",
    },
};

/// Totals restated so a diff shows the migration moving. Both must only ever
/// decrease; an increase means a new Python dependency was introduced.
const remaining_source_files = 20;
const remaining_execution_sites = 119;

/// No tracked file is anywhere near this size, and the limit keeps a stray
/// large blob from being read into memory by this scan.
const max_tracked_file_bytes = 4 * 1024 * 1024;

/// Characters that continue a word for the purpose of token boundaries.
/// `-`, `.`, and `/` are included so `python3-libs`, `python3.12-dev`, and
/// `/usr/lib/python3/dist-packages` are never mistaken for a command.
fn isWordByte(byte: u8) bool {
    return switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '.', '/', '-' => true,
        else => false,
    };
}

/// End of a lowercase `python`, `python3`, or `python3.12` token starting at
/// `start`, or null when no such token starts there. The spelling is
/// deliberately case-sensitive: a command is lowercase, while prose about the
/// language is capitalized.
fn tokenEnd(line: []const u8, start: usize) ?usize {
    if (!std.mem.startsWith(u8, line[start..], "python")) return null;
    var index = start + "python".len;
    if (index < line.len and std.ascii.isDigit(line[index])) {
        while (index < line.len and std.ascii.isDigit(line[index])) index += 1;
        if (index + 1 < line.len and
            line[index] == '.' and
            std.ascii.isDigit(line[index + 1]))
        {
            index += 1;
            while (index < line.len and std.ascii.isDigit(line[index])) index += 1;
        }
    }
    return index;
}

/// Whether a Python token spanning `[start, end)` is being used as a command.
///
/// Three spellings count, and they are the only ones this repository uses:
///
/// * `"python3"` as an element of an `argv` array;
/// * `env python3`, which covers both a real `env` exec and a shebang; and
/// * a token followed by an argument, meaning an option, a redirect or line
///   continuation, a quoted or shell-expanded word, a path, or a `.py` file.
///
/// A token followed by a bare word is not a command: that is a package list
/// (`file jq python3 systemd-boot-efi`) or a tool-presence loop.
fn isCommandUse(line: []const u8, start: usize, end: usize) bool {
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

/// Invocation sites on one line.
fn scanLine(line: []const u8) usize {
    var found: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, line, index, "python")) |start| {
        const end = tokenEnd(line, start) orelse {
            index = start + 1;
            continue;
        };
        index = end;
        if (start > 0 and isWordByte(line[start - 1])) continue;
        if (end < line.len and isWordByte(line[end])) continue;
        if (isCommandUse(line, start, end)) found += 1;
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

fn trackedFiles(allocator: Allocator, io: Io) !TrackedFiles {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "git", "ls-files", "-z" },
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
    var sources: usize = 0;
    var execution_sites: usize = 0;
    for (inventory) |entry| {
        try std.testing.expect(std.mem.lessThan(u8, previous, entry.path));
        previous = entry.path;
        try std.testing.expect(entry.note.len > 0);
        try std.testing.expectEqual(
            isPythonSourcePath(entry.path),
            entry.kind == .source,
        );
        if (entry.kind == .source) {
            try std.testing.expectEqual(@as(?usize, null), entry.sites);
            sources += 1;
        } else {
            try std.testing.expect(entry.sites.? > 0);
            if (entry.kind == .execution) execution_sites += entry.sites.?;
        }
        try std.testing.expect(!isTools(entry.path));
        try std.testing.expect(!std.mem.eql(u8, entry.path, guard_path));
    }
    try std.testing.expectEqual(remaining_source_files, sources);
    try std.testing.expectEqual(remaining_execution_sites, execution_sites);
}

test "every tracked Python file is inventoried as a source entry" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tracked = try trackedFiles(allocator, io);
    defer tracked.deinit();

    var failures: Writer.Allocating = .init(allocator);
    defer failures.deinit();

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var paths = tracked.iterator();
    while (paths.next()) |path| {
        if (path.len == 0 or isTools(path)) continue;
        if (!isPythonSourcePath(path)) continue;
        try seen.put(path, {});
        const entry = find(path) orelse {
            try failures.writer.print(
                "{s}: Python source is not inventoried\n",
                .{path},
            );
            continue;
        };
        if (entry.kind != .source) try failures.writer.print(
            "{s}: Python source is inventoried as .{s}\n",
            .{ path, @tagName(entry.kind) },
        );
    }

    for (inventory) |entry| {
        if (entry.kind != .source) continue;
        if (seen.contains(entry.path)) continue;
        try failures.writer.print(
            "{s}: inventoried source is no longer tracked; remove the entry\n",
            .{entry.path},
        );
    }

    try report(&failures);
    try std.testing.expectEqual(remaining_source_files, seen.count());
}

test "every Python invocation site outside a Python file is inventoried" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tracked = try trackedFiles(allocator, io);
    defer tracked.deinit();

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var failures: Writer.Allocating = .init(allocator);
    defer failures.deinit();

    var paths = tracked.iterator();
    while (paths.next()) |path| {
        if (path.len == 0 or isTools(path)) continue;
        if (isPythonSourcePath(path)) continue;
        if (std.mem.eql(u8, path, guard_path)) continue;

        const stat = Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
            // A tracked symlink pointing outside the tree is not a file to
            // scan; nothing else may fail silently.
            error.FileNotFound => continue,
            else => return err,
        };
        if (stat.kind != .file) continue;
        try std.testing.expect(stat.size <= max_tracked_file_bytes);

        const contents = try Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(max_tracked_file_bytes),
        );
        defer allocator.free(contents);

        const sites = try scanFile(contents, path, null);
        const entry = find(path);
        if (sites == 0) {
            if (entry != null) try failures.writer.print(
                "{s}: inventoried but invokes Python nowhere; remove the entry\n",
                .{path},
            );
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
        if (listed.sites.? != sites) {
            try failures.writer.print(
                "{s}: inventory records {d} invocation site(s), found {d}\n",
                .{ path, listed.sites.?, sites },
            );
            _ = try scanFile(contents, path, &failures.writer);
        }
    }

    for (inventory) |entry| {
        if (entry.kind == .source) continue;
        if (seen.contains(entry.path)) continue;
        try failures.writer.print(
            "{s}: inventoried but no longer tracked or no longer invokes Python; remove the entry\n",
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
    };
    for (commands) |line| {
        try std.testing.expectEqual(@as(usize, 1), scanLine(line));
    }
}

test "package names, tool checks, paths, and prose are not invocations" {
    const not_commands = [_][]const u8{
        "            curl dnf file jq python3-virt-firmware qemu-utils rpm tar",
        "  for tool in az azcopy qemu-img ssh ssh-keygen python3; do",
        "  for tool in python3 sha256sum; do",
        "            file jq python3 systemd-boot-efi",
        "  /usr/lib/python3/dist-packages/cloudinit \\",
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
