//! Temporary inventory of the Python this repository still owns.
//!
//! The repository is migrating every repository-owned Python file and every
//! Python invocation to Zig. Until that finishes, a partially migrated tree
//! has to be able to state precisely what Python is left, so review can see
//! each port shrink the list and can catch a new dependency being added by
//! accident. This test is that statement, enforced by the compiler and CI
//! rather than by convention.
//!
//! The inventory is expected to shrink and then disappear: when the last entry
//! is gone this file is replaced by the permanent zero-Python guard.
//!
//! Two independent things are enforced, because they shrink differently.
//!
//! * Every tracked `*.py` file must be listed as `.source`. These files are
//!   removed whole by the ports, so only their presence is tracked.
//! * Every other tracked file that mentions Python must be listed with the
//!   exact number of lines that mention it. A file that runs Python and a file
//!   that merely names a Debian package both mention it, so each entry also
//!   declares which it is: `.execution` actually runs Python, `.documentation`
//!   shows a Python command to a reader, and `.reference` is a compatibility
//!   or descriptive string with no execution behind it.
//!
//! Only `.execution` entries block the "no Python at runtime" goal;
//! `.reference` entries are allowed to outlive the migration where they name
//! something that is genuinely called Python.
//!
//! `.tools/` is excluded: it holds locally provisioned toolchains that this
//! repository does not own, and it is not tracked by Git in any case.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

/// What a tracked file's Python mentions actually are.
const Classification = enum {
    /// A repository-owned Python program or test.
    source,
    /// The file executes Python, on the host or inside a guest.
    execution,
    /// Documentation that shows a Python command to a reader.
    documentation,
    /// A compatibility or descriptive string only: a package name, a shebang
    /// in test data, prose about what was replaced.
    reference,
};

const Entry = struct {
    path: []const u8,
    classification: Classification,
    /// Lines mentioning Python, case-insensitively. `null` for `.source`
    /// entries, whose unit of removal is the whole file.
    mentions: ?usize = null,
    note: []const u8,
};

/// This file is the inventory, so its own mentions are not inventory items.
const guard_path = "tests/python_inventory.zig";

/// Sorted by path. Keep it sorted: review reads this as a checklist.
const inventory = [_]Entry{
    .{
        .path = ".github/workflows/azurelinux4-release.yml",
        .classification = .execution,
        .mentions = 5,
        .note = "Azure Linux release job: inline Python plus azurelinux4_release.py",
    },
    .{
        .path = ".github/workflows/boot-smoke.yml",
        .classification = .execution,
        .mentions = 3,
        .note = "OCI fixture generators under scripts/ci",
    },
    .{
        .path = ".github/workflows/ci.yml",
        .classification = .execution,
        .mentions = 4,
        .note = "unittest invocations for the remaining Python test suites",
    },
    .{
        .path = ".github/workflows/freebsd15-release.yml",
        .classification = .execution,
        .mentions = 7,
        .note = "FreeBSD release job: matrix, describe, candidate, inline Python",
    },
    .{
        .path = ".github/workflows/ubuntu2604-core-validation.yml",
        .classification = .execution,
        .mentions = 13,
        .note = "Ubuntu core validation: ubuntu2604_release.py and inline Python",
    },
    .{
        .path = ".github/workflows/ubuntu2604-image-benchmark.yml",
        .classification = .execution,
        .mentions = 5,
        .note = "benchmark driver and inline evidence Python",
    },
    .{
        .path = ".github/workflows/ubuntu2604-release.yml",
        .classification = .execution,
        .mentions = 10,
        .note = "Ubuntu release job: ubuntu2604_release.py and inline Python",
    },
    .{
        .path = "azagent/main.zig",
        .classification = .reference,
        .mentions = 1,
        .note = "doc comment naming the Python agent this binary replaced",
    },
    .{
        .path = "azagent/resource_disk.zig",
        .classification = .reference,
        .mentions = 1,
        .note = "doc comment naming the Python agent this module replaced",
    },
    .{
        .path = "build.zig",
        .classification = .reference,
        .mentions = 12,
        .note = "wires this inventory guard into the test steps",
    },
    .{
        .path = "cli/src/commands/qemu.zig",
        .classification = .reference,
        .mentions = 1,
        .note = "names the python3-virt-firmware package in an operator hint",
    },
    .{
        .path = "doc/debian-package-family.md",
        .classification = .reference,
        .mentions = 1,
        .note = "prose: the package family does not use python-apt",
    },
    .{
        .path = "doc/development.md",
        .classification = .documentation,
        .mentions = 8,
        .note = "describes the CI Python workflow and this inventory",
    },
    .{
        .path = "doc/freebsd.md",
        .classification = .documentation,
        .mentions = 2,
        .note = "shows freebsd15_release.py compare",
    },
    .{
        .path = "doc/library-api.md",
        .classification = .reference,
        .mentions = 1,
        .note = "prose: python3-libs is not a differently-versioned python3",
    },
    .{
        .path = "doc/qemu.md",
        .classification = .reference,
        .mentions = 1,
        .note = "names the python3-virt-firmware package",
    },
    .{
        .path = "doc/ubuntu.md",
        .classification = .documentation,
        .mentions = 6,
        .note = "host dependency lists and the benchmark command",
    },
    .{
        .path = "mizguest/main.zig",
        .classification = .reference,
        .mentions = 2,
        .note = "comment about parsing python3-libs as a distinct package name",
    },
    .{
        .path = "packages/miz/src/customize.zig",
        .classification = .reference,
        .mentions = 5,
        .note = "shebang and package-name test data",
    },
    .{
        .path = "packages/miz/src/deprovision.zig",
        .classification = .reference,
        .mentions = 1,
        .note = "doc comment: deprovisioning needs no Python",
    },
    .{
        .path = "packages/miz/src/kernel_modules.zig",
        .classification = .execution,
        .mentions = 1,
        .note = "test-only XZ fixture built with python3 -c",
    },
    .{
        .path = "packages/miz/src/packages.zig",
        .classification = .reference,
        .mentions = 5,
        .note = "python3-libs parsing test data",
    },
    .{
        .path = "packages/miz/src/squashfs.zig",
        .classification = .execution,
        .mentions = 1,
        .note = "test-only XZ fixture built with python3 -c",
    },
    .{
        .path = "packages/miz/src/unsafe_chroot.zig",
        .classification = .reference,
        .mentions = 4,
        .note = "shebang and package-name test data",
    },
    .{
        .path = "packages/miz/src/verity_tooling.zig",
        .classification = .reference,
        .mentions = 1,
        .note = "comment describing the XZ container Python's lzma writes",
    },
    .{
        .path = "packages/miz/src/vm_backend.zig",
        .classification = .reference,
        .mentions = 2,
        .note = "interpreter string in customization test data",
    },
    .{
        .path = "qmp/tools/qapi_schema.zig",
        .classification = .reference,
        .mentions = 2,
        .note = "QAPI schema files are Python literals, not JSON",
    },
    .{
        .path = "scripts/azure_vhd.py",
        .classification = .source,
        .note = "superseded by scripts/azure_vhd.zig; callers still invoke the Python",
    },
    .{
        .path = "scripts/azurelinux4_azure_acceptance.sh",
        .classification = .execution,
        .mentions = 15,
        .note = "Azure Linux acceptance: inline Python and azurelinux4_release.py",
    },
    .{
        .path = "scripts/azurelinux4_publish.sh",
        .classification = .execution,
        .mentions = 9,
        .note = "Azure Linux publish: inline Python and azurelinux4_release.py",
    },
    .{
        .path = "scripts/azurelinux4_release.py",
        .classification = .source,
        .note = "ported by the Azure Linux release slice",
    },
    .{
        .path = "scripts/ci/make-minimal-oci-fixture.py",
        .classification = .source,
        .note = "ported by the OCI fixture slice",
    },
    .{
        .path = "scripts/ci/make-uki-stub-oci-fixture.py",
        .classification = .source,
        .note = "ported by the OCI fixture slice",
    },
    .{
        .path = "scripts/ci/make-verity-initramfs-oci-fixture.py",
        .classification = .source,
        .note = "ported by the OCI fixture slice",
    },
    .{
        .path = "scripts/ci/oci_layout.py",
        .classification = .source,
        .note = "ported by the OCI fixture slice",
    },
    .{
        .path = "scripts/freebsd15_azure_acceptance.sh",
        .classification = .execution,
        .mentions = 17,
        .note = "FreeBSD acceptance: inline Python, azure_vhd.py, freebsd15_release.py",
    },
    .{
        .path = "scripts/freebsd15_azure_metadata.py",
        .classification = .source,
        .note = "ported by the FreeBSD release slice",
    },
    .{
        .path = "scripts/freebsd15_publish.sh",
        .classification = .execution,
        .mentions = 7,
        .note = "FreeBSD publish: inline Python and freebsd15_release.py",
    },
    .{
        .path = "scripts/freebsd15_release.py",
        .classification = .source,
        .note = "ported by the FreeBSD release slice",
    },
    .{
        .path = "scripts/freebsd15_stage_release.sh",
        .classification = .execution,
        .mentions = 6,
        .note = "FreeBSD staging: inline Python and freebsd15_release.py",
    },
    .{
        .path = "scripts/ubuntu2604_azure_acceptance.sh",
        .classification = .execution,
        .mentions = 26,
        .note = "Ubuntu acceptance: inline Python and ubuntu2604_release.py",
    },
    .{
        .path = "scripts/ubuntu2604_image_benchmark.py",
        .classification = .source,
        .note = "ported by the benchmark slice",
    },
    .{
        .path = "scripts/ubuntu2604_local_e2e.sh",
        .classification = .execution,
        .mentions = 1,
        .note = "inline Python that checks the local image-info document",
    },
    .{
        .path = "scripts/ubuntu2604_publish.sh",
        .classification = .execution,
        .mentions = 9,
        .note = "Ubuntu publish: inline Python and ubuntu2604_release.py",
    },
    .{
        .path = "scripts/ubuntu2604_release.py",
        .classification = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "tests/azurelinux4_release_test.py",
        .classification = .source,
        .note = "ported by the Azure Linux release slice",
    },
    .{
        .path = "tests/freebsd15_azure_acceptance_test.py",
        .classification = .source,
        .note = "ported by the FreeBSD release slice",
    },
    .{
        .path = "tests/freebsd15_release_test.py",
        .classification = .source,
        .note = "ported by the FreeBSD release slice",
    },
    .{
        .path = "tests/stale_brand_test.py",
        .classification = .source,
        .note = "ported by the stale brand guard slice",
    },
    .{
        .path = "tests/ubuntu2604_acceptance.zig",
        .classification = .execution,
        .mentions = 3,
        .note = "guest-side acceptance script parses cloud-init status with python3",
    },
    .{
        .path = "tests/ubuntu2604_azure_acceptance_test.py",
        .classification = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "tests/ubuntu2604_core_workflow_test.py",
        .classification = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "tests/ubuntu2604_image_benchmark_test.py",
        .classification = .source,
        .note = "ported by the benchmark slice",
    },
    .{
        .path = "tests/ubuntu2604_image_benchmark_workflow_test.py",
        .classification = .source,
        .note = "ported by the benchmark slice",
    },
    .{
        .path = "tests/ubuntu2604_release_test.py",
        .classification = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "tests/ubuntu2604_workflow_test.py",
        .classification = .source,
        .note = "ported by the Ubuntu release slice",
    },
    .{
        .path = "wireserver/xml.zig",
        .classification = .reference,
        .mentions = 1,
        .note = "comment naming the Python escaping this matches",
    },
};

/// Totals restated so a diff shows the migration moving. Both must only ever
/// decrease; an increase means a new Python dependency was introduced.
const remaining_source_files = 20;
const remaining_execution_files = 18;

/// No tracked file is anywhere near this size, and the limit keeps a stray
/// large blob from being read into memory by this scan.
const max_tracked_file_bytes = 4 * 1024 * 1024;

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

/// Lines that mention Python, case-insensitively. Counting whole lines rather
/// than occurrences keeps the number stable against a line being reworded and
/// makes it readable next to `grep -in python`.
fn countMentions(contents: []const u8) usize {
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        if (std.ascii.indexOfIgnoreCase(line, "python") != null) count += 1;
    }
    return count;
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

test "the inventory is sorted, unique, and internally consistent" {
    var previous: []const u8 = "";
    var sources: usize = 0;
    var executions: usize = 0;
    for (inventory) |entry| {
        try std.testing.expect(std.mem.lessThan(u8, previous, entry.path));
        previous = entry.path;
        try std.testing.expect(entry.note.len > 0);
        try std.testing.expectEqual(
            isPythonSourcePath(entry.path),
            entry.classification == .source,
        );
        if (entry.classification == .source) {
            try std.testing.expectEqual(@as(?usize, null), entry.mentions);
            sources += 1;
        } else {
            try std.testing.expect(entry.mentions.? > 0);
            if (entry.classification == .execution) executions += 1;
        }
        try std.testing.expect(!isTools(entry.path));
        try std.testing.expect(!std.mem.eql(u8, entry.path, guard_path));
    }
    try std.testing.expectEqual(remaining_source_files, sources);
    try std.testing.expectEqual(remaining_execution_files, executions);
}

test "every tracked file that mentions Python is inventoried with its count" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tracked = try trackedFiles(allocator, io);
    defer tracked.deinit();

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var failures: std.Io.Writer.Allocating = .init(allocator);
    defer failures.deinit();

    var paths = tracked.iterator();
    while (paths.next()) |path| {
        if (path.len == 0) continue;
        if (isTools(path)) continue;
        if (std.mem.eql(u8, path, guard_path)) continue;

        const stat = Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
            // A tracked symlink to something outside the tree is not a file to
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

        const mentions = countMentions(contents);
        const is_source = isPythonSourcePath(path);
        if (mentions == 0 and !is_source) {
            if (find(path) != null) try failures.writer.print(
                "{s}: inventoried but no longer mentions Python; remove the entry\n",
                .{path},
            );
            continue;
        }

        try seen.put(path, {});
        const entry = find(path) orelse {
            try failures.writer.print(
                "{s}: mentions Python on {d} line(s) but is not inventoried\n",
                .{ path, mentions },
            );
            continue;
        };
        if (is_source) continue;
        if (entry.mentions.? != mentions) try failures.writer.print(
            "{s}: inventory records {d} Python mention(s), found {d}\n",
            .{ path, entry.mentions.?, mentions },
        );
    }

    for (inventory) |entry| {
        if (seen.contains(entry.path)) continue;
        try failures.writer.print(
            "{s}: inventoried but no longer tracked or no longer mentions Python; remove the entry\n",
            .{entry.path},
        );
    }

    if (failures.written().len > 0) {
        std.debug.print("\n{s}", .{failures.written()});
        return error.PythonInventoryStale;
    }
}

test "every tracked Python file is inventoried as a source entry" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tracked = try trackedFiles(allocator, io);
    defer tracked.deinit();

    var failures: std.Io.Writer.Allocating = .init(allocator);
    defer failures.deinit();

    var found: usize = 0;
    var paths = tracked.iterator();
    while (paths.next()) |path| {
        if (path.len == 0) continue;
        if (isTools(path)) continue;
        if (!isPythonSourcePath(path)) continue;
        found += 1;
        const entry = find(path) orelse {
            try failures.writer.print(
                "{s}: Python source is not inventoried\n",
                .{path},
            );
            continue;
        };
        if (entry.classification != .source) try failures.writer.print(
            "{s}: Python source is inventoried as .{s}\n",
            .{ path, @tagName(entry.classification) },
        );
    }

    if (failures.written().len > 0) {
        std.debug.print("\n{s}", .{failures.written()});
        return error.PythonInventoryStale;
    }
    try std.testing.expectEqual(remaining_source_files, found);
}

test "mention counting is case-insensitive and line-based" {
    try std.testing.expectEqual(@as(usize, 0), countMentions("zig build test\n"));
    try std.testing.expectEqual(@as(usize, 1), countMentions("run python3 x\n"));
    try std.testing.expectEqual(
        @as(usize, 1),
        countMentions("Python and python on one line\n"),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        countMentions("PYTHON3\nnothing\npython3-libs\n"),
    );
}
