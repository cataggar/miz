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

    // The generated module index is unowned but explicitly allowed, and the
    // top-level table has to account for the same bytes the totals do.
    const modules = entryBy(
        field(section, &.{ "unowned", "allowed" }),
        "rule",
        "/usr/lib/modules/**",
    ).?;
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
        if (std.mem.eql(u8, rule.pattern, "/boot/initrd.img*")) matched_prefix = true;
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
    var root_build = parsed.value.object.get("root_build").?.object;
    const inflated = root_build.get("installed_bytes").?.integer + 4096;
    try root_build.put(
        std.testing.allocator,
        "installed_bytes",
        .{ .integer = inflated },
    );
    var mutated = parsed.value.object;
    try mutated.put(std.testing.allocator, "root_build", .{ .object = root_build });

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
