//! Behavioral coverage for the Ubuntu 26.04 size-inventory measurement.
//!
//! The contracts under test are the ones #677 step 1 depends on: a measured
//! root attributes every byte it walked to a package, the shared payload, an
//! explicit unowned allowlist, or a named remainder; the aggregates equal the
//! parts; phases are appended by the stage that observes them and never
//! declared without being carried; and a document that does not add up is
//! refused with a message naming what failed.

const std = @import("std");

const release = @import("ubuntu2604_release");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;
const size_inventory = release.size_inventory;
const Diagnostic = size_inventory.Diagnostic;

/// A private, absolute root tree plus the arenas the measurement API takes.
const Fixture = struct {
    tmp: std.testing.TmpDir,
    arena_state: *std.heap.ArenaAllocator,
    scratch_state: *std.heap.ArenaAllocator,
    root: []const u8,
    io: Io,
    diagnostic: Diagnostic = .{},

    fn create() !Fixture {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const arena_state = try std.testing.allocator.create(std.heap.ArenaAllocator);
        errdefer std.testing.allocator.destroy(arena_state);
        arena_state.* = .init(std.testing.allocator);
        errdefer arena_state.deinit();
        const scratch_state = try std.testing.allocator.create(std.heap.ArenaAllocator);
        errdefer std.testing.allocator.destroy(scratch_state);
        scratch_state.* = .init(std.testing.allocator);
        errdefer scratch_state.deinit();

        const arena = arena_state.allocator();
        const relative = try std.fmt.allocPrint(
            arena,
            ".zig-cache/tmp/{s}",
            .{tmp.sub_path},
        );
        const root = try Dir.cwd().realPathFileAlloc(std.testing.io, relative, arena);
        return .{
            .tmp = tmp,
            .arena_state = arena_state,
            .scratch_state = scratch_state,
            .root = root,
            .io = std.testing.io,
        };
    }

    fn deinit(self: *Fixture) void {
        self.arena_state.deinit();
        std.testing.allocator.destroy(self.arena_state);
        self.scratch_state.deinit();
        std.testing.allocator.destroy(self.scratch_state);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn allocator(self: *Fixture) Allocator {
        return self.arena_state.allocator();
    }

    fn scratch(self: *Fixture) Allocator {
        return self.scratch_state.allocator();
    }

    fn write(self: *Fixture, guest_path: []const u8, data: []const u8) !void {
        const target = try std.fs.path.join(
            self.allocator(),
            &.{ self.root, guest_path[1..] },
        );
        if (std.fs.path.dirname(target)) |parent| {
            try Dir.cwd().createDirPath(self.io, parent);
        }
        try Dir.cwd().writeFile(self.io, .{ .sub_path = target, .data = data });
    }

    fn message(self: *const Fixture) []const u8 {
        return self.diagnostic.message();
    }
};

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print(
            "expected message to contain \"{s}\", found \"{s}\"\n",
            .{ needle, haystack },
        );
        return error.TestExpectedContains;
    }
}

const kernel_release = "6.20.0-1001-azure";

/// A root that exercises every attribution bucket exactly once: two owned
/// packages, a directory both of them claim, an allowlisted injection, and one
/// unowned file no rule covers.
fn writeMeasuredRoot(fixture: *Fixture) !void {
    try fixture.write(
        size_inventory.package_lock_path,
        "alpha\t1.0-1\tamd64\nbeta\t2.0-1\tamd64\n",
    );
    try fixture.write(
        "/var/lib/dpkg/info/alpha.list",
        "/usr\n/usr/bin\n/usr/bin/alpha\n",
    );
    try fixture.write(
        "/var/lib/dpkg/info/beta.list",
        "/usr\n/usr/bin\n/usr/bin/beta\n/usr/lib/beta.so\n",
    );
    try fixture.write("/usr/bin/alpha", "alpha" ** 8);
    try fixture.write("/usr/bin/beta", "beta" ** 4);
    try fixture.write("/usr/lib/beta.so", "shared object");
    try fixture.write("/usr/sbin/mizinit", "injected pid 1");
    try fixture.write("/etc/unexpected.conf", "no package owns this");
    try fixture.write(
        try std.fmt.allocPrint(
            fixture.allocator(),
            "/boot/vmlinuz-{s}",
            .{kernel_release},
        ),
        "kernel image",
    );
    try fixture.write(
        try std.fmt.allocPrint(
            fixture.allocator(),
            "/boot/initrd.img-{s}",
            .{kernel_release},
        ),
        "initramfs",
    );
    try fixture.write(
        try std.fmt.allocPrint(
            fixture.allocator(),
            "/usr/lib/modules/{s}/modules.dep",
            .{kernel_release},
        ),
        "module index",
    );
}

fn measure(fixture: *Fixture, flavor: size_inventory.Flavor) !Value {
    return size_inventory.measureRootBuild(
        fixture.allocator(),
        fixture.scratch(),
        fixture.io,
        .{
            .root_path = fixture.root,
            .flavor = flavor,
            .kernel_release = kernel_release,
        },
        &fixture.diagnostic,
    );
}

fn field(value: Value, path: []const []const u8) Value {
    var current = value;
    for (path) |key| current = current.object.get(key).?;
    return current;
}

fn count(value: Value, path: []const []const u8) i64 {
    return field(value, path).integer;
}

/// Locates one entry of an array by its `name`/`rule`/`path` key.
fn entryBy(value: Value, key: []const u8, wanted: []const u8) ?Value {
    for (value.array.items) |item| {
        const found = item.object.get(key) orelse continue;
        if (found == .string and std.mem.eql(u8, found.string, wanted)) return item;
    }
    return null;
}

fn buildReport(fixture: *Fixture, flavor: size_inventory.Flavor) !size_inventory.Report {
    var report = try size_inventory.Report.init(
        std.testing.allocator,
        .{ .architecture = .x86_64, .flavor = flavor },
    );
    errdefer report.deinit();
    const section = try size_inventory.measureRootBuild(
        report.allocator(),
        fixture.scratch(),
        fixture.io,
        .{
            .root_path = fixture.root,
            .flavor = flavor,
            .kernel_release = kernel_release,
        },
        &fixture.diagnostic,
    );
    try report.addPhase(.root_build, section, &fixture.diagnostic);
    return report;
}

fn sampleImageBuild(arena: Allocator, diagnostic: *Diagnostic) !Value {
    return size_inventory.imageBuildValue(arena, .{
        .virtual_size = 3758096384,
        .root = .{
            .block_size = 4096,
            .total_blocks = 900_000,
            .free_blocks = 300_000,
            .total_inodes = 60_000,
            .free_inodes = 40_000,
        },
        .uki_bytes = 60 * 1024 * 1024,
        .esp_partition_bytes = 128 * 1024 * 1024,
        .esp_total_bytes = 127 * 1024 * 1024,
        .esp_free_bytes = 60 * 1024 * 1024,
    }, diagnostic);
}

fn samplePublication(arena: Allocator) !Value {
    return size_inventory.publicationValue(arena, .{
        .artifact_name = "Ubuntu-26.04-x86_64.core.qcow2",
        .compressed_artifact_bytes = 975 * 1024 * 1024,
        .qcow2_allocated_bytes = 976 * 1024 * 1024,
    });
}

test "a measured root attributes every walked byte to exactly one bucket" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    const section = try measure(&fixture, .core);
    try std.testing.expectEqual(@as(i64, 2), count(section, &.{"package_count"}));

    const alpha = entryBy(field(section, &.{"packages"}), "name", "alpha").?;
    try std.testing.expectEqualStrings("1.0-1", alpha.object.get("version").?.string);
    try std.testing.expectEqual(@as(i64, 1), alpha.object.get("file_count").?.integer);
    try std.testing.expectEqual(
        @as(i64, 40),
        alpha.object.get("installed_bytes").?.integer,
    );
    const beta = entryBy(field(section, &.{"packages"}), "name", "beta").?;
    try std.testing.expectEqual(@as(i64, 2), beta.object.get("file_count").?.integer);

    // `/usr` and `/usr/bin` are claimed by both packages, so they are shared
    // rather than charged to whichever package happened to be indexed first.
    try std.testing.expectEqual(@as(i64, 2), count(section, &.{ "shared", "file_count" }));
    try std.testing.expectEqual(
        @as(i64, 0),
        count(section, &.{ "unmatched", "file_count" }),
    );

    const injected = entryBy(
        field(section, &.{ "unowned", "allowed" }),
        "rule",
        "/usr/sbin/mizinit",
    ).?;
    try std.testing.expectEqual(@as(i64, 1), injected.object.get("file_count").?.integer);
    try std.testing.expectEqualStrings(
        "injected miz PID 1",
        injected.object.get("reason").?.string,
    );

    const unexpected = field(section, &.{ "unowned", "unexpected" });
    try std.testing.expectEqual(false, unexpected.object.get("truncated").?.bool);
    var found_unexpected = false;
    for (unexpected.object.get("paths").?.array.items) |item| {
        if (std.mem.eql(u8, item.string, "/etc/unexpected.conf")) found_unexpected = true;
    }
    try std.testing.expect(found_unexpected);

    const boot = field(section, &.{"boot"});
    try std.testing.expectEqualStrings(
        kernel_release,
        boot.object.get("kernel_release").?.string,
    );
    try std.testing.expect(boot.object.get("kernel_bytes").?.integer > 0);
    try std.testing.expect(boot.object.get("initramfs_bytes").?.integer > 0);
    try std.testing.expect(boot.object.get("modules_bytes").?.integer > 0);

    // The generated module index is unowned but explicitly allowed -- by a
    // rule derived from the kernel release the root boots, not by a subtree
    // glob that would have made the module tree a place to hide things.
    const modules = entryBy(
        field(section, &.{ "unowned", "allowed" }),
        "rule",
        "/usr/lib/modules/" ++ kernel_release ++ "/modules.dep",
    ).?;
    try std.testing.expectEqualStrings(
        "regular_file",
        modules.object.get("kind").?.string,
    );
    try std.testing.expect(modules.object.get("file_count").?.integer > 0);
    try std.testing.expect(entryBy(
        field(section, &.{"root_directories"}),
        "path",
        "/usr",
    ) != null);
}

test "a measured root produces a document validation accepts" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var report = try buildReport(&fixture, .core);
    defer report.deinit();
    const text = try report.toJsonAlloc(std.testing.allocator);
    defer std.testing.allocator.free(text);

    const parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        text,
        .{},
    );
    defer parsed.deinit();
    const summary = try size_inventory.validateDocument(
        std.testing.allocator,
        parsed.value,
        .{ .architecture = "x86_64", .flavor = "core" },
        &fixture.diagnostic,
    );
    try std.testing.expectEqual(@as(u64, 2), summary.package_count);
    try std.testing.expect(summary.has(.root_build));
    try std.testing.expect(!summary.has(.image_build));
    try std.testing.expect(summary.unexpected_unowned_count >= 1);
    try std.testing.expectEqual(@as(usize, 64), summary.closure_sha256.len);
}

test "the closure digest tracks the closure and not the file layout" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);
    const first = try measure(&fixture, .core);

    try fixture.write("/usr/bin/alpha", "a different payload entirely");
    const second = try measure(&fixture, .core);
    try std.testing.expectEqualStrings(
        field(first, &.{"closure_sha256"}).string,
        field(second, &.{"closure_sha256"}).string,
    );

    try fixture.write(
        size_inventory.package_lock_path,
        "alpha\t1.0-2\tamd64\nbeta\t2.0-1\tamd64\n",
    );
    const third = try measure(&fixture, .core);
    try std.testing.expect(!std.mem.eql(
        u8,
        field(first, &.{"closure_sha256"}).string,
        field(third, &.{"closure_sha256"}).string,
    ));
}

test "a file list naming a package outside the closure is reported, not hidden" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);
    try fixture.write("/var/lib/dpkg/info/gamma.list", "/usr/bin/gamma\n");
    try fixture.write("/usr/bin/gamma", "not in the closure");

    const section = try measure(&fixture, .core);
    try std.testing.expectEqual(
        @as(i64, 1),
        count(section, &.{ "unmatched", "file_count" }),
    );
    try std.testing.expectEqualStrings(
        "gamma",
        field(section, &.{ "unmatched", "packages" }).array.items[0].string,
    );
}

test "an unreadable package lock fails clearly" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    const result = measure(&fixture, .core);
    try std.testing.expectError(error.Failed, result);
    try expectContains(fixture.message(), "exact package lock");
}

test "a malformed package lock line fails clearly" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);
    try fixture.write(size_inventory.package_lock_path, "alpha\t1.0-1\n");
    const result = measure(&fixture, .core);
    try std.testing.expectError(error.Failed, result);
    try expectContains(fixture.message(), "malformed package lock");
}

test "allowlist rules match exact paths, prefixes, and subtrees" {
    const rules = try size_inventory.unownedRulesAlloc(
        std.testing.allocator,
        .core,
    );
    defer std.testing.allocator.free(rules);

    var matched_exact = false;
    var matched_prefix = false;
    var matched_subtree = false;
    for (rules) |rule| {
        if (std.mem.eql(u8, rule.pattern, "/etc/ld.so.cache")) matched_exact = true;
        if (std.mem.eql(u8, rule.pattern, "/etc/passwd*")) matched_prefix = true;
        if (std.mem.eql(u8, rule.pattern, "/var/lib/miz/**")) matched_subtree = true;
    }
    try std.testing.expect(matched_exact and matched_prefix and matched_subtree);

    // The core allowlist names the injected guest; the full flavor does not,
    // because the full flavor does not inject one.
    const full = try size_inventory.unownedRulesAlloc(std.testing.allocator, .full);
    defer std.testing.allocator.free(full);
    var full_has_mizinit = false;
    for (full) |rule| {
        if (std.mem.eql(u8, rule.pattern, "/usr/sbin/mizinit")) full_has_mizinit = true;
    }
    try std.testing.expect(!full_has_mizinit);
}

test "phases are recorded in stage order and never twice" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var report = try buildReport(&fixture, .core);
    defer report.deinit();

    const publication = try samplePublication(report.allocator());
    try std.testing.expectError(
        error.Failed,
        report.addPhase(.publication, publication, &fixture.diagnostic),
    );
    try expectContains(fixture.message(), "cannot precede image_build");

    const image = try sampleImageBuild(report.allocator(), &fixture.diagnostic);
    try report.addPhase(.image_build, image, &fixture.diagnostic);
    try std.testing.expectError(
        error.Failed,
        report.addPhase(.image_build, image, &fixture.diagnostic),
    );
    try expectContains(fixture.message(), "already recorded");

    try report.addPhase(.publication, publication, &fixture.diagnostic);
    const text = try report.toJsonAlloc(std.testing.allocator);
    defer std.testing.allocator.free(text);
    const parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        text,
        .{},
    );
    defer parsed.deinit();
    const summary = try size_inventory.validateDocument(
        std.testing.allocator,
        parsed.value,
        .{ .required_phases = &.{ .root_build, .image_build, .publication } },
        &fixture.diagnostic,
    );
    try std.testing.expect(summary.has(.publication));
    try std.testing.expect(!summary.has(.first_boot));
}

test "a required phase the document never measured is refused by name" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var report = try buildReport(&fixture, .core);
    defer report.deinit();
    const text = try report.toJsonAlloc(std.testing.allocator);
    defer std.testing.allocator.free(text);
    const parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        text,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectError(error.Failed, size_inventory.validateDocument(
        std.testing.allocator,
        parsed.value,
        .{ .required_phases = &.{ .root_build, .first_boot } },
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "missing required phase first_boot");
}

test "the first-boot phase is appended by the stage that observes it" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var report = try buildReport(&fixture, .core);
    defer report.deinit();
    try report.addPhase(
        .image_build,
        try sampleImageBuild(report.allocator(), &fixture.diagnostic),
        &fixture.diagnostic,
    );
    try report.addPhase(
        .publication,
        try samplePublication(report.allocator()),
        &fixture.diagnostic,
    );
    const text = try report.toJsonAlloc(std.testing.allocator);
    defer std.testing.allocator.free(text);
    const parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        text,
        .{},
    );
    defer parsed.deinit();

    const first_boot = try size_inventory.firstBootValue(fixture.allocator(), .{
        .block_size = 4096,
        .total_blocks = 900_000,
        .free_blocks = 280_000,
        .total_inodes = 60_000,
        .free_inodes = 39_000,
    }, &fixture.diagnostic);
    const updated = try size_inventory.appendPhaseAlloc(
        fixture.allocator(),
        parsed.value,
        .first_boot,
        first_boot,
        &fixture.diagnostic,
    );
    const summary = try size_inventory.validateDocument(
        std.testing.allocator,
        updated,
        .{ .required_phases = &.{ .root_build, .first_boot } },
        &fixture.diagnostic,
    );
    try std.testing.expect(summary.has(.first_boot));

    // Growth is measured, not assumed: the after-boot document carries fewer
    // free blocks than the before-boot one.
    try std.testing.expect(
        field(updated, &.{ "first_boot", "root_free_blocks" }).integer <
            field(updated, &.{ "image_build", "root_free_blocks" }).integer,
    );

    try std.testing.expectError(error.Failed, size_inventory.appendPhaseAlloc(
        fixture.allocator(),
        updated,
        .first_boot,
        first_boot,
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "already recorded");
}

test "a section that is not declared, or declared and not carried, is refused" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var report = try buildReport(&fixture, .core);
    defer report.deinit();
    const text = try report.toJsonAlloc(std.testing.allocator);
    defer std.testing.allocator.free(text);

    {
        const parsed = try std.json.parseFromSlice(
            Value,
            std.testing.allocator,
            text,
            .{},
        );
        defer parsed.deinit();
        var mutated = parsed.value.object;
        try mutated.put(
            std.testing.allocator,
            "publication",
            try samplePublication(fixture.allocator()),
        );
        try std.testing.expectError(error.Failed, size_inventory.validateDocument(
            std.testing.allocator,
            .{ .object = mutated },
            .{},
            &fixture.diagnostic,
        ));
        try expectContains(fixture.message(), "do not match phases_present");
    }

    {
        const parsed = try std.json.parseFromSlice(
            Value,
            std.testing.allocator,
            text,
            .{},
        );
        defer parsed.deinit();
        var phases = parsed.value.object.get("phases_present").?.array;
        try phases.append(.{ .string = "publication" });
        var mutated = parsed.value.object;
        try mutated.put(std.testing.allocator, "phases_present", .{ .array = phases });
        try std.testing.expectError(error.Failed, size_inventory.validateDocument(
            std.testing.allocator,
            .{ .object = mutated },
            .{},
            &fixture.diagnostic,
        ));
        try expectContains(fixture.message(), "do not match phases_present");
        phases.deinit();
    }
}

test "totals that do not equal their parts are refused" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var report = try buildReport(&fixture, .core);
    defer report.deinit();
    const text = try report.toJsonAlloc(std.testing.allocator);
    defer std.testing.allocator.free(text);

    const parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        text,
        .{},
    );
    defer parsed.deinit();
    // The document's maps belong to the parser's arena, so a mutation that
    // grows one has to allocate from the same arena.
    const arena = parsed.arena.allocator();
    var root_build = parsed.value.object.get("root_build").?.object;
    const inflated = root_build.get("installed_bytes").?.integer + 4096;
    try root_build.put(arena, "installed_bytes", .{ .integer = inflated });
    var mutated = parsed.value.object;
    try mutated.put(arena, "root_build", .{ .object = root_build });

    try std.testing.expectError(error.Failed, size_inventory.validateDocument(
        std.testing.allocator,
        .{ .object = mutated },
        .{},
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "totals do not match");
}

test "image geometry that does not add up is refused" {
    var fixture = try Fixture.create();
    defer fixture.deinit();

    try std.testing.expectError(error.Failed, size_inventory.imageBuildValue(
        fixture.allocator(),
        .{
            .virtual_size = 3758096384,
            .root = .{
                .block_size = 4096,
                .total_blocks = 900_000,
                .free_blocks = 300_000,
                .total_inodes = 60_000,
                .free_inodes = 40_000,
            },
            // A UKI larger than the ESP has room for is a broken measurement,
            // not a small ESP.
            .uki_bytes = 200 * 1024 * 1024,
            .esp_partition_bytes = 128 * 1024 * 1024,
            .esp_total_bytes = 127 * 1024 * 1024,
            .esp_free_bytes = 60 * 1024 * 1024,
        },
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "ESP usage is inconsistent");

    try std.testing.expectError(error.Failed, size_inventory.firstBootValue(
        fixture.allocator(),
        .{
            .block_size = 4096,
            .total_blocks = 900_000,
            .free_blocks = 900_001,
            .total_inodes = 60_000,
            .free_inodes = 40_000,
        },
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "filesystem usage is inconsistent");
}

test "comparison reports closure, package, and phase deltas" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var baseline = try buildReport(&fixture, .core);
    defer baseline.deinit();
    try baseline.addPhase(
        .image_build,
        try sampleImageBuild(baseline.allocator(), &fixture.diagnostic),
        &fixture.diagnostic,
    );
    const baseline_value = try baseline.value();

    // The candidate drops `beta` and grows `alpha`.
    try fixture.write(size_inventory.package_lock_path, "alpha\t1.0-1\tamd64\n");
    try fixture.write("/usr/bin/alpha", "alpha" ** 16);
    var candidate = try buildReport(&fixture, .core);
    defer candidate.deinit();
    try candidate.addPhase(
        .image_build,
        try size_inventory.imageBuildValue(candidate.allocator(), .{
            .virtual_size = 3758096384,
            .root = .{
                .block_size = 4096,
                .total_blocks = 900_000,
                .free_blocks = 320_000,
                .total_inodes = 60_000,
                .free_inodes = 40_000,
            },
            .uki_bytes = 60 * 1024 * 1024,
            .esp_partition_bytes = 128 * 1024 * 1024,
            .esp_total_bytes = 127 * 1024 * 1024,
            .esp_free_bytes = 60 * 1024 * 1024,
        }, &fixture.diagnostic),
        &fixture.diagnostic,
    );
    const candidate_value = try candidate.value();

    const comparison = try size_inventory.compareAlloc(
        fixture.allocator(),
        fixture.scratch(),
        baseline_value,
        candidate_value,
        &fixture.diagnostic,
    );
    try std.testing.expectEqualStrings(
        size_inventory.comparison_type,
        field(comparison, &.{"type"}).string,
    );
    try std.testing.expectEqual(
        true,
        field(comparison, &.{ "root_build", "closure_changed" }).bool,
    );
    try std.testing.expectEqual(
        @as(i64, -1),
        count(comparison, &.{ "root_build", "package_count_delta" }),
    );
    try std.testing.expectEqualStrings(
        "beta",
        field(comparison, &.{ "root_build", "packages", "removed" })
            .array.items[0].object.get("name").?.string,
    );
    const changed = field(comparison, &.{ "root_build", "packages", "changed" });
    try std.testing.expectEqualStrings(
        "alpha",
        changed.array.items[0].object.get("name").?.string,
    );
    try std.testing.expect(
        changed.array.items[0].object.get("installed_bytes_delta").?.integer > 0,
    );
    try std.testing.expectEqual(
        @as(i64, 20_000),
        count(comparison, &.{ "image_build", "root_free_blocks_delta" }),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        field(comparison, &.{"phases_compared"}).array.items.len,
    );
}

test "comparing documents from different architectures is refused" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var baseline = try buildReport(&fixture, .core);
    defer baseline.deinit();
    var candidate = try size_inventory.Report.init(
        std.testing.allocator,
        .{ .architecture = .aarch64, .flavor = .core },
    );
    defer candidate.deinit();
    try candidate.addPhase(
        .root_build,
        try size_inventory.measureRootBuild(
            candidate.allocator(),
            fixture.scratch(),
            fixture.io,
            .{
                .root_path = fixture.root,
                .flavor = .core,
                .kernel_release = kernel_release,
            },
            &fixture.diagnostic,
        ),
        &fixture.diagnostic,
    );

    try std.testing.expectError(error.Failed, size_inventory.compareAlloc(
        fixture.allocator(),
        fixture.scratch(),
        try baseline.value(),
        try candidate.value(),
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "architecture is invalid");
}

test "a validated document round-trips through the filesystem" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var report = try buildReport(&fixture, .core);
    defer report.deinit();
    const path = try std.fs.path.join(
        fixture.allocator(),
        &.{ fixture.root, "inventory.json" },
    );
    try report.write(std.testing.allocator, fixture.io, path, &fixture.diagnostic);

    var parsed = try size_inventory.readValidated(
        std.testing.allocator,
        fixture.io,
        path,
        .{ .architecture = "x86_64", .flavor = "core" },
        &fixture.diagnostic,
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        size_inventory.document_type,
        field(parsed.value, &.{"type"}).string,
    );

    try Dir.cwd().writeFile(fixture.io, .{ .sub_path = path, .data = "{" });
    try std.testing.expectError(error.Failed, size_inventory.readValidated(
        std.testing.allocator,
        fixture.io,
        path,
        .{},
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "cannot read size inventory");
}

test "a fresh root fails closed on unowned payload outside the allowlist" {
    // Issue #677 step 3: the fresh-root flavors are assembled from an exact
    // closure, so every file they carry is either claimed by a package in that
    // closure or named by an explicit injected-file rule. `/etc/unexpected.conf`
    // is neither, so the measurement that finds it refuses the root and names
    // the path instead of reporting a remainder nobody reads.
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    try std.testing.expectError(error.Failed, size_inventory.measureRootBuild(
        fixture.allocator(),
        fixture.scratch(),
        fixture.io,
        .{
            .root_path = fixture.root,
            .flavor = .core,
            .kernel_release = kernel_release,
            .require_allowlisted_unowned = true,
        },
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "outside the explicit injected-file allowlist");
    try expectContains(fixture.message(), "/etc/unexpected.conf");

    // The same root measures without the gate, which is what the `full` flavor
    // and the pre-change comparisons need.
    const reported = try measure(&fixture, .core);
    try std.testing.expect(count(reported, &.{ "unowned", "unexpected", "file_count" }) > 0);
}

test "an accounted fresh root passes the closed gate" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try fixture.write(size_inventory.package_lock_path, "alpha\t1.0-1\tamd64\n");
    try fixture.write(
        "/var/lib/dpkg/info/alpha.list",
        "/usr\n/usr/bin\n/usr/bin/alpha\n/usr/sbin\n/etc\n/boot\n/var\n/var/lib\n" ++
            "/var/lib/dpkg\n/var/lib/dpkg/info\n/usr/lib\n/usr/lib/modules\n" ++
            "/usr/lib/modules/" ++ kernel_release ++ "\n" ++
            "/boot/vmlinuz-" ++ kernel_release ++ "\n",
    );
    try fixture.write("/usr/bin/alpha", "owned payload");
    try fixture.write("/boot/vmlinuz-" ++ kernel_release, "kernel image");
    // Everything else is named by a rule: the injected PID 1, the generated
    // initramfs, the depmod index, the package database, and the exact lock.
    try fixture.write("/usr/sbin/mizinit", "injected pid 1");
    try fixture.write("/boot/initrd.img-" ++ kernel_release, "initramfs");
    try fixture.write("/usr/lib/modules/" ++ kernel_release ++ "/modules.dep", "module index");

    const section = try size_inventory.measureRootBuild(
        fixture.allocator(),
        fixture.scratch(),
        fixture.io,
        .{
            .root_path = fixture.root,
            .flavor = .core,
            .kernel_release = kernel_release,
            .require_allowlisted_unowned = true,
        },
        &fixture.diagnostic,
    );
    try std.testing.expectEqual(
        @as(i64, 0),
        count(section, &.{ "unowned", "unexpected", "file_count" }),
    );

    // A convenience file dropped into the same root fails it.
    try fixture.write("/usr/bin/convenient", "a tool nobody asked for");
    try std.testing.expectError(error.Failed, size_inventory.measureRootBuild(
        fixture.allocator(),
        fixture.scratch(),
        fixture.io,
        .{
            .root_path = fixture.root,
            .flavor = .core,
            .kernel_release = kernel_release,
            .require_allowlisted_unowned = true,
        },
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "/usr/bin/convenient");
}

test "dpkg file lists answer who owns a path and everything under it" {
    // What keeps #677's "nothing is installed only to be deleted later" honest:
    // the builder asks this before it generalizes a fresh root.
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try fixture.write(
        "/var/lib/dpkg/info/alpha.list",
        "/usr\n/usr/bin\n/usr/bin/alpha\n/etc/alpha\n/etc/alpha/keep.conf\n" ++
            "/etc/beta/keep.conf\n",
    );
    try fixture.write("/usr/bin/alpha", "owned payload");

    var owned = try size_inventory.readOwnedPaths(
        std.testing.allocator,
        fixture.io,
        fixture.root,
    );
    defer owned.deinit();
    try std.testing.expect(owned.count() > 0);
    try std.testing.expectEqualStrings("alpha", owned.owner("/usr/bin/alpha").?);
    try std.testing.expect(owned.owner("/var/lib/azagent") == null);

    // A recursive removal takes the subtree with it, so the subtree is what is
    // asked about.
    try std.testing.expectEqualStrings("alpha", owned.subtreeOwner("/etc/alpha").?.package);
    // `/etc/beta` is claimed only through a file beneath it, and a recursive
    // removal of the directory would still take that file.
    try std.testing.expect(owned.owner("/etc/beta") == null);
    try std.testing.expectEqualStrings(
        "/etc/beta/keep.conf",
        owned.subtreeOwner("/etc/beta").?.path,
    );
    try std.testing.expect(owned.subtreeOwner("/var/lib/azagent") == null);
    // A prefix that is not a path component boundary is not a subtree.
    try std.testing.expect(owned.subtreeOwner("/usr/bin/alph") == null);
    try std.testing.expect(owned.subtreeOwner("/etc/bet") == null);

    // A root with no dpkg database answers "nothing", not an error.
    var empty_fixture = try Fixture.create();
    defer empty_fixture.deinit();
    var empty = try size_inventory.readOwnedPaths(
        std.testing.allocator,
        empty_fixture.io,
        empty_fixture.root,
    );
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.count());
}

// ---------------------------------------------------------------------------
// Issue #677 remediation: generated-but-unowned classification.
//
// The path classes below are the ones a real `x86_64` core build produced --
// `update-alternatives` links, `update-rc.d` runlevel links,
// `deb-systemd-helper` link farms, the canonical `/boot` symlinks, `depmod`
// index files, debz's transaction metadata, and the FHS scaffolding
// `base-files.postinst` creates. Each test pairs the real shape with the
// near-miss an attacker would reach for, because a rule that accepts the first
// and the second is not a classification, it is an exemption.
// ---------------------------------------------------------------------------

/// A root with exactly the ownership records and metadata a fresh core root
/// carries, and nothing else: every unowned path is added by the test itself.
const GeneratedRoot = struct {
    fixture: Fixture,

    const kernel = kernel_release;

    fn create() !GeneratedRoot {
        var fixture = try Fixture.create();
        errdefer fixture.deinit();
        try fixture.write(
            size_inventory.package_lock_path,
            "alpha\t1.0-1\tamd64\ngawk\t5.3-1\tamd64\nopenssh-server\t10.0-1\tamd64\n",
        );
        try fixture.write(
            "/var/lib/dpkg/info/alpha.list",
            "/usr\n/usr/bin\n/usr/sbin\n/usr/lib\n/usr/lib/modules\n" ++
                "/usr/lib/modules/" ++ kernel ++ "\n" ++
                "/usr/lib/systemd\n/usr/lib/systemd/system\n" ++
                "/etc\n/etc/init.d\n/etc/init.d/ssh\n/etc/rc2.d\n/etc/alternatives\n" ++
                "/var/spool\n" ++
                "/etc/systemd\n/etc/systemd/system\n" ++
                "/boot\n/boot/vmlinuz-" ++ kernel ++ "\n" ++
                "/var\n/var/lib\n/var/lib/dpkg\n/var/lib/dpkg/info\n" ++
                "/var/lib/systemd\n" ++
                "/usr/lib/systemd/system/ssh.socket\n",
        );
        try fixture.write("/etc/init.d/ssh", "#!/bin/sh\n");
        try fixture.write("/boot/vmlinuz-" ++ kernel, "kernel image");
        try fixture.write("/usr/lib/systemd/system/ssh.socket", "[Socket]\n");
        try fixture.write("/var/lib/dpkg/info/gawk.list", "/usr/bin/gawk\n");
        try fixture.write("/usr/bin/gawk", "gawk");
        return .{ .fixture = fixture };
    }

    fn deinit(self: *GeneratedRoot) void {
        self.fixture.deinit();
        self.* = undefined;
    }

    fn host(self: *GeneratedRoot, guest: []const u8) ![]const u8 {
        return std.fs.path.join(
            self.fixture.allocator(),
            &.{ self.fixture.root, guest[1..] },
        );
    }

    fn link(self: *GeneratedRoot, guest: []const u8, target: []const u8) !void {
        const path = try self.host(guest);
        if (std.fs.path.dirname(path)) |parent| {
            try Dir.cwd().createDirPath(self.fixture.io, parent);
        }
        Dir.cwd().deleteFile(self.fixture.io, path) catch {};
        try Dir.cwd().symLink(self.fixture.io, target, path, .{});
    }

    fn directory(self: *GeneratedRoot, guest: []const u8) !void {
        try Dir.cwd().createDirPath(self.fixture.io, try self.host(guest));
    }

    /// Registers an `update-alternatives` group exactly the way dpkg's admin
    /// file spells one: status, master link, `name`/`link` slave pairs, a blank
    /// line, then the alternative and its priority.
    fn alternatives(
        self: *GeneratedRoot,
        group: []const u8,
        master: []const u8,
        choice: []const u8,
    ) !void {
        try self.fixture.write(
            try std.fmt.allocPrint(
                self.fixture.allocator(),
                "/var/lib/dpkg/alternatives/{s}",
                .{group},
            ),
            try std.fmt.allocPrint(
                self.fixture.allocator(),
                "auto\n{s}\n\n{s}\n10\n\n",
                .{ master, choice },
            ),
        );
    }

    /// Records one `deb-systemd-helper` enabled link the way the helper does:
    /// an empty marker file under a mirrored `<unit>.wants` directory.
    fn enabled(self: *GeneratedRoot, farm: []const u8, unit: []const u8) !void {
        try self.fixture.write(
            try std.fmt.allocPrint(
                self.fixture.allocator(),
                "/var/lib/systemd/deb-systemd-helper-enabled/{s}/{s}",
                .{ farm, unit },
            ),
            "",
        );
    }

    fn measure(self: *GeneratedRoot) !Value {
        return size_inventory.measureRootBuild(
            self.fixture.allocator(),
            self.fixture.scratch(),
            self.fixture.io,
            .{
                .root_path = self.fixture.root,
                .flavor = .core,
                .kernel_release = kernel,
                .require_allowlisted_unowned = true,
            },
            &self.fixture.diagnostic,
        );
    }

    /// The paths the gate would have refused, as a sorted, joined string.
    fn refused(self: *GeneratedRoot) ![]const u8 {
        const section = size_inventory.measureRootBuild(
            self.fixture.allocator(),
            self.fixture.scratch(),
            self.fixture.io,
            .{
                .root_path = self.fixture.root,
                .flavor = .core,
                .kernel_release = kernel,
            },
            &self.fixture.diagnostic,
        ) catch return "<measurement failed>";
        var text: std.ArrayList(u8) = .empty;
        for (field(section, &.{ "unowned", "unexpected", "paths" }).array.items) |item| {
            try text.append(self.fixture.allocator(), ' ');
            try text.appendSlice(self.fixture.allocator(), item.string);
        }
        return text.items;
    }

    fn expectAccepted(self: *GeneratedRoot) !void {
        const section = self.measure() catch |err| {
            std.debug.print(
                "expected an accounted root, refused:{s}\n",
                .{try self.refused()},
            );
            return err;
        };
        try std.testing.expectEqual(
            @as(i64, 0),
            count(section, &.{ "unowned", "unexpected", "file_count" }),
        );
    }

    fn expectRefused(self: *GeneratedRoot, path: []const u8) !void {
        try std.testing.expectError(error.Failed, self.measure());
        try expectContains(self.fixture.message(), path);
    }
};

test "update-alternatives links are classified from dpkg's own database" {
    var root = try GeneratedRoot.create();
    defer root.deinit();

    // What a real build ships: `/usr/bin/awk -> /etc/alternatives/awk ->
    // /usr/bin/gawk`, with both links registered in dpkg's admin file.
    try root.alternatives("awk", "/usr/bin/awk", "/usr/bin/gawk");
    try root.link("/usr/bin/awk", "/etc/alternatives/awk");
    try root.link("/etc/alternatives/awk", "/usr/bin/gawk");
    try root.expectAccepted();

    const section = try root.measure();
    const entry = entryBy(
        field(section, &.{ "unowned", "allowed" }),
        "rule",
        "/usr/bin/awk",
    ).?;
    try std.testing.expectEqualStrings(
        "alternatives_link",
        entry.object.get("category").?.string,
    );
    try std.testing.expectEqualStrings(
        "dpkg_alternatives",
        entry.object.get("source").?.string,
    );
    try std.testing.expectEqualStrings("symlink", entry.object.get("kind").?.string);
    try std.testing.expectEqualStrings(
        "literal:/etc/alternatives/awk",
        entry.object.get("target").?.string,
    );
    // The rule names the metadata file it was read out of, so a reviewer can
    // check the claim instead of taking it.
    try std.testing.expectEqualStrings(
        "/var/lib/dpkg/alternatives/awk",
        entry.object.get("origin").?.string,
    );
}

test "an alternatives-shaped path dpkg never registered is refused" {
    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.alternatives("awk", "/usr/bin/awk", "/usr/bin/gawk");
    try root.link("/usr/bin/awk", "/etc/alternatives/awk");
    try root.link("/etc/alternatives/awk", "/usr/bin/gawk");

    // Nothing registered `pager`, so neither half of the pair is derived.
    try root.link("/etc/alternatives/pager", "/usr/bin/gawk");
    try root.expectRefused("/etc/alternatives/pager");
}

test "an alternatives link that is a file, or points elsewhere, is refused" {
    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.alternatives("awk", "/usr/bin/awk", "/usr/bin/gawk");
    try root.link("/etc/alternatives/awk", "/usr/bin/gawk");

    // A regular file standing where the registered symlink belongs is exactly
    // the substitution a name-only allowlist would have accepted.
    try root.fixture.write("/usr/bin/awk", "#!/bin/sh\nexec /tmp/payload\n");
    try root.expectRefused("/usr/bin/awk");

    // A symlink is not enough either: it has to point at the switchable link
    // dpkg registered, not at somewhere the payload can be swapped in later.
    try root.link("/usr/bin/awk", "/usr/local/bin/awk");
    try root.expectRefused("/usr/bin/awk");

    try root.link("/usr/bin/awk", "/etc/alternatives/awk");
    try root.expectAccepted();
}

test "an alternatives selection must resolve to package-owned content" {
    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.alternatives("awk", "/usr/bin/awk", "/usr/bin/gawk");
    try root.link("/usr/bin/awk", "/etc/alternatives/awk");

    // Registered name, registered type, unowned destination: the selection is
    // the one place a link farm could be pointed at smuggled content, so the
    // rule requires the destination to be claimed by the exact closure.
    try root.fixture.write("/usr/local/bin/awk", "payload");
    try root.link("/etc/alternatives/awk", "/usr/local/bin/awk");
    try root.expectRefused("/etc/alternatives/awk");

    try root.link("/etc/alternatives/awk", "/usr/bin/gawk");
    try root.expectAccepted();
}

test "update-rc.d runlevel links are accepted only for package-owned scripts" {
    var root = try GeneratedRoot.create();
    defer root.deinit();

    try root.link("/etc/rc2.d/S01ssh", "../init.d/ssh");
    try root.expectAccepted();

    const section = try root.measure();
    const entry = entryBy(
        field(section, &.{ "unowned", "allowed" }),
        "rule",
        "/etc/rc2.d/S01ssh",
    ).?;
    try std.testing.expectEqualStrings(
        "sysv_service_link",
        entry.object.get("category").?.string,
    );
    try std.testing.expectEqualStrings(
        "literal:../init.d/ssh",
        entry.object.get("target").?.string,
    );

    // `/etc/init.d/rootkit` is not package-owned, so no rule is derived for a
    // runlevel link that would start it on every boot.
    try root.fixture.write("/etc/init.d/rootkit", "#!/bin/sh\n");
    try root.link("/etc/rc2.d/S99rootkit", "../init.d/rootkit");
    try root.expectRefused("/etc/rc2.d/S99rootkit");
}

test "a runlevel entry that is not a link to its own init script is refused" {
    var root = try GeneratedRoot.create();
    defer root.deinit();

    // Well-formed name, package-owned service, but a regular file: a runlevel
    // directory is not a place to put a script of one's own.
    try root.fixture.write("/etc/rc2.d/S01ssh", "#!/bin/sh\nexec /tmp/payload\n");
    try root.expectRefused("/etc/rc2.d/S01ssh");

    // A link that borrows a package-owned name but points somewhere else.
    try root.link("/etc/rc2.d/S01ssh", "../../usr/local/bin/ssh");
    try root.expectRefused("/etc/rc2.d/S01ssh");

    try root.link("/etc/rc2.d/S01ssh", "../init.d/ssh");
    try root.expectAccepted();
}

test "systemd link farms come from deb-systemd-helper's own record" {
    var root = try GeneratedRoot.create();
    defer root.deinit();

    try root.enabled("sockets.target.wants", "ssh.socket");
    try root.directory("/etc/systemd/system/sockets.target.wants");
    try root.link(
        "/etc/systemd/system/sockets.target.wants/ssh.socket",
        "/lib/systemd/system/ssh.socket",
    );
    // `/lib` is the merged-`/usr` compatibility spelling; dpkg records
    // `/usr/lib`, and a classifier that did not normalize would call a
    // correctly enabled unit link unattributable payload.
    try root.expectAccepted();

    const section = try root.measure();
    const entry = entryBy(
        field(section, &.{ "unowned", "allowed" }),
        "rule",
        "/etc/systemd/system/sockets.target.wants/ssh.socket",
    ).?;
    try std.testing.expectEqualStrings(
        "systemd_service_link",
        entry.object.get("category").?.string,
    );
    try std.testing.expectEqualStrings(
        "package_owned_same_name",
        entry.object.get("target").?.string,
    );
    try std.testing.expectEqualStrings(
        "/var/lib/systemd/deb-systemd-helper-enabled/sockets.target.wants/ssh.socket",
        entry.object.get("origin").?.string,
    );
}

test "a .wants farm nothing enabled, or one holding payload, is refused" {
    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.enabled("sockets.target.wants", "ssh.socket");
    try root.directory("/etc/systemd/system/sockets.target.wants");
    try root.link(
        "/etc/systemd/system/sockets.target.wants/ssh.socket",
        "/lib/systemd/system/ssh.socket",
    );

    // A second farm no maintainer script enabled: the directory alone fails,
    // which is what keeps `/etc/systemd/system` from becoming a subtree glob.
    try root.directory("/etc/systemd/system/multi-user.target.wants");
    try root.expectRefused("/etc/systemd/system/multi-user.target.wants");
}

test "an enabled unit link must point at package-owned content of its own name" {
    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.enabled("sockets.target.wants", "ssh.socket");
    try root.directory("/etc/systemd/system/sockets.target.wants");

    // Enabled name, enabled directory, but the unit it starts is a drop-in
    // nobody shipped.
    try root.fixture.write("/usr/local/lib/ssh.socket", "[Socket]\nExecStartPre=/tmp/x\n");
    try root.link(
        "/etc/systemd/system/sockets.target.wants/ssh.socket",
        "/usr/local/lib/ssh.socket",
    );
    try root.expectRefused("/etc/systemd/system/sockets.target.wants/ssh.socket");

    // Package-owned, but under a name the record does not enable: the link
    // would start a different unit than the one review looked at.
    try root.link(
        "/etc/systemd/system/sockets.target.wants/ssh.socket",
        "/lib/systemd/system/ssh.service",
    );
    try root.expectRefused("/etc/systemd/system/sockets.target.wants/ssh.socket");

    try root.link(
        "/etc/systemd/system/sockets.target.wants/ssh.socket",
        "/lib/systemd/system/ssh.socket",
    );
    try root.expectAccepted();
}

test "the canonical boot symlinks are bound to the kernel release the root boots" {
    var root = try GeneratedRoot.create();
    defer root.deinit();

    try root.link("/boot/vmlinuz", "vmlinuz-" ++ kernel_release);
    try root.link("/boot/vmlinuz.old", "vmlinuz-" ++ kernel_release);
    try root.fixture.write("/boot/initrd.img-" ++ kernel_release, "initramfs");
    try root.link("/boot/initrd.img", "initrd.img-" ++ kernel_release);
    try root.expectAccepted();

    const section = try root.measure();
    const entry = entryBy(
        field(section, &.{ "unowned", "allowed" }),
        "rule",
        "/boot/vmlinuz",
    ).?;
    try std.testing.expectEqualStrings(
        "kernel_boot_symlink",
        entry.object.get("category").?.string,
    );
    try std.testing.expectEqualStrings(
        "literal:vmlinuz-" ++ kernel_release,
        entry.object.get("target").?.string,
    );

    // A second kernel's image is not the one this root boots, and `/boot` is
    // not a directory anything may be left in.
    try root.link("/boot/vmlinuz", "vmlinuz-9.9.9-1-generic");
    try root.expectRefused("/boot/vmlinuz");
}

test "a kernel-shaped regular file cannot take a boot symlink's place" {
    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.fixture.write("/boot/vmlinuz", "not the kernel the closure shipped");
    try root.expectRefused("/boot/vmlinuz");

    // Nor can an initramfs for a release the root does not boot.
    try root.link("/boot/vmlinuz", "vmlinuz-" ++ kernel_release);
    try root.fixture.write("/boot/initrd.img-9.9.9-1-generic", "stale initramfs");
    try root.expectRefused("/boot/initrd.img-9.9.9-1-generic");
}

test "the depmod index is named file by file, not by its directory" {
    var root = try GeneratedRoot.create();
    defer root.deinit();

    for ([_][]const u8{ "modules.dep", "modules.dep.bin", "modules.alias" }) |name| {
        try root.fixture.write(
            try std.fmt.allocPrint(
                root.fixture.allocator(),
                "/usr/lib/modules/" ++ kernel_release ++ "/{s}",
                .{name},
            ),
            "generated index",
        );
    }
    try root.expectAccepted();

    // The module tree is where a payload would be least conspicuous, so the
    // rules name depmod's outputs rather than the directory holding them.
    try root.fixture.write(
        "/usr/lib/modules/" ++ kernel_release ++ "/modules.payload",
        "not something depmod writes",
    );
    try root.expectRefused("/usr/lib/modules/" ++ kernel_release ++ "/modules.payload");
}

test "debz metadata and base-files scaffolding are typed, not blanket-allowed" {
    var root = try GeneratedRoot.create();
    defer root.deinit();

    try root.fixture.write("/var/lib/debz/transaction.lock", "");
    try root.directory("/etc/opt");
    try root.directory("/var/opt");
    try root.directory("/var/mail");
    try root.link("/var/spool/mail", "../mail");
    try root.fixture.write("/etc/environment", "PATH=/usr/bin\n");
    try root.fixture.write("/etc/shells", "/bin/sh\n");
    try root.expectAccepted();

    // `/var/spool/mail` is allowed because it is the FHS compatibility link,
    // and for no other reason: a directory of the same name is unaccounted
    // payload.
    const path = try root.host("/var/spool/mail");
    try Dir.cwd().deleteFile(root.fixture.io, path);
    try Dir.cwd().createDirPath(root.fixture.io, path);
    try root.expectRefused("/var/spool/mail");
}

test "a conffile a package's file list no longer names is still owned" {
    // dpkg states ownership in three places, and a root whose `.list` has been
    // rewritten -- or whose conffile was only ever recorded as one -- must not
    // turn a package's own configuration into unattributable payload.
    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.fixture.write(
        "/var/lib/dpkg/info/alpha.conffiles",
        "/etc/alpha.conf\nremove-on-upgrade /etc/alpha-legacy.conf\n",
    );
    try root.fixture.write("/etc/alpha.conf", "key = value\n");
    try root.fixture.write("/etc/alpha-legacy.conf", "old = value\n");
    try root.expectAccepted();

    const section = try root.measure();
    const alpha = entryBy(field(section, &.{"packages"}), "name", "alpha").?;
    try std.testing.expect(alpha.object.get("file_count").?.integer >= 2);
}

test "a diverted file is attributed to the package that diverted it" {
    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.fixture.write(
        "/var/lib/dpkg/diversions",
        "/usr/bin/gawk\n/usr/bin/gawk.distrib\nalpha\n",
    );
    try root.fixture.write("/usr/bin/gawk.distrib", "the relocated original");
    try root.expectAccepted();

    // A local diversion -- dpkg spells the package `:` -- belongs to no
    // package, so a fresh root that carries one still fails.
    try root.fixture.write(
        "/var/lib/dpkg/diversions",
        "/usr/bin/gawk\n/usr/bin/gawk.local\n:\n",
    );
    try root.fixture.write("/usr/bin/gawk.local", "an administrator's own file");
    try root.expectRefused("/usr/bin/gawk.local");
}

test "the published allowlist is bound to a digest of the reviewed policy" {
    var root = try GeneratedRoot.create();
    defer root.deinit();
    const section = try root.measure();

    const expected = try size_inventory.unownedPolicyDigest(std.testing.allocator, .core);
    try std.testing.expectEqualStrings(
        &expected,
        field(section, &.{ "unowned", "policy_sha256" }).string,
    );

    // The digest is what makes the allowlist a reviewed artifact: a flavor with
    // a different policy cannot publish this one's digest, and an edit to
    // either table changes it.
    const full = try size_inventory.unownedPolicyDigest(std.testing.allocator, .full);
    try std.testing.expect(!std.mem.eql(u8, &expected, &full));
}

test "a document whose allowlist policy digest does not match is refused" {
    var fixture = try Fixture.create();
    defer fixture.deinit();
    try writeMeasuredRoot(&fixture);

    var report = try buildReport(&fixture, .core);
    defer report.deinit();
    const text = try report.toJsonAlloc(std.testing.allocator);
    defer std.testing.allocator.free(text);

    const parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        text,
        .{},
    );
    defer parsed.deinit();
    _ = try size_inventory.validateDocument(
        std.testing.allocator,
        parsed.value,
        .{ .architecture = "x86_64", .flavor = "core" },
        &fixture.diagnostic,
    );

    // A builder that widened its allowlist locally still has to publish the
    // digest of the table it classified with, and this tool recomputes the
    // reviewed one rather than believing the document.
    const arena = parsed.arena.allocator();
    const unowned = field(parsed.value, &.{ "root_build", "unowned" }).object;
    var mutable = unowned;
    try mutable.put(arena, "policy_sha256", .{ .string = "0" ** 64 });
    var root_build = field(parsed.value, &.{"root_build"}).object;
    try root_build.put(arena, "unowned", .{ .object = mutable });
    var document = parsed.value.object;
    try document.put(arena, "root_build", .{ .object = root_build });

    try std.testing.expectError(error.Failed, size_inventory.validateDocument(
        std.testing.allocator,
        .{ .object = document },
        .{ .architecture = "x86_64", .flavor = "core" },
        &fixture.diagnostic,
    ));
    try expectContains(fixture.message(), "policy digest");
}

test "the bare-metal flavor classifies the same generated payload as core" {
    // AArch64's fresh root is the same construction with a different kernel
    // suffix, and `baremetal` is the flavor only that architecture builds. It
    // shares core's policy exactly, so a rule that landed for one and not the
    // other would be a silent per-architecture exemption.
    try std.testing.expectEqualStrings(
        &try size_inventory.unownedPolicyDigest(std.testing.allocator, .core),
        &try size_inventory.unownedPolicyDigest(std.testing.allocator, .baremetal),
    );

    var root = try GeneratedRoot.create();
    defer root.deinit();
    try root.alternatives("awk", "/usr/bin/awk", "/usr/bin/gawk");
    try root.link("/usr/bin/awk", "/etc/alternatives/awk");
    try root.link("/etc/alternatives/awk", "/usr/bin/gawk");
    try root.link("/etc/rc2.d/S01ssh", "../init.d/ssh");
    try root.enabled("sockets.target.wants", "ssh.socket");
    try root.directory("/etc/systemd/system/sockets.target.wants");
    try root.link(
        "/etc/systemd/system/sockets.target.wants/ssh.socket",
        "/lib/systemd/system/ssh.socket",
    );
    try root.link("/boot/vmlinuz", "vmlinuz-" ++ kernel_release);

    const section = try size_inventory.measureRootBuild(
        root.fixture.allocator(),
        root.fixture.scratch(),
        root.fixture.io,
        .{
            .root_path = root.fixture.root,
            .flavor = .baremetal,
            .kernel_release = kernel_release,
            .require_allowlisted_unowned = true,
        },
        &root.fixture.diagnostic,
    );
    try std.testing.expectEqual(
        @as(i64, 0),
        count(section, &.{ "unowned", "unexpected", "file_count" }),
    );
}

test "the full flavor keeps its broad rules and its own policy" {
    // `full` inherits Canonical's server root, is measured rather than gated,
    // and must not acquire the fresh roots' derived rules -- nor lose the
    // subtree rules that make that root describable.
    const full = try size_inventory.unownedRulesAlloc(std.testing.allocator, .full);
    defer std.testing.allocator.free(full);
    var has_alternatives_subtree = false;
    var has_modules_subtree = false;
    for (full) |rule| {
        if (std.mem.eql(u8, rule.pattern, "/etc/alternatives/**")) {
            has_alternatives_subtree = true;
        }
        if (std.mem.eql(u8, rule.pattern, "/usr/lib/modules/**")) has_modules_subtree = true;
        try std.testing.expectEqualStrings(
            size_inventory.contract_origin,
            rule.origin,
        );
    }
    try std.testing.expect(has_alternatives_subtree and has_modules_subtree);

    const fresh = try size_inventory.unownedRulesAlloc(std.testing.allocator, .core);
    defer std.testing.allocator.free(fresh);
    for (fresh) |rule| {
        try std.testing.expect(!std.mem.eql(u8, rule.pattern, "/etc/alternatives/**"));
        try std.testing.expect(!std.mem.eql(u8, rule.pattern, "/usr/lib/modules/**"));
        try std.testing.expect(!std.mem.eql(u8, rule.pattern, "/etc/systemd/system/**"));
    }
}
