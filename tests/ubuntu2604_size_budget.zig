//! Behavioral coverage for the hard size and content gates (issue #677 step 6).
//!
//! The contracts under test are the ones that decide whether a minimized image
//! stays minimized: the reviewed budget is pinned by digest so it cannot widen
//! quietly, every limit follows from a recorded measurement and a named
//! allowance rather than from a round number, a metric whose phase has not
//! happened is skipped rather than passed, an architecture nobody has measured
//! records a baseline and cannot be published, and a failure names the metric,
//! the observation, the bound, and the delta.

const std = @import("std");

const release = @import("ubuntu2604_release");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const size_budget = release.size_budget;
const size_inventory = release.size_inventory;
const Diagnostic = size_budget.Diagnostic;

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print(
            "expected message to contain \"{s}\", found \"{s}\"\n",
            .{ needle, haystack },
        );
        return error.TestExpectedContains;
    }
}

/// One architecture's real core build, as the production workflow measured it.
///
/// These are the numbers a real, unmodified core build of this tree produced,
/// so a document assembled from them is the document the gate has to pass. A
/// fixture that merely satisfied the schema would prove the validator parses;
/// this proves the shipped appliance fits its own budget.
const Measured = struct {
    deb_architecture: []const u8,
    kernel_release: []const u8,
    artifact_name: []const u8,
    package_count: u64,
    installed_bytes: u64,
    allocated_bytes: u64,
    file_count: u64,
    kernel_bytes: u64,
    initramfs_bytes: u64,
    modules_bytes: u64,
    virtual_size: u64,
    uki_bytes: u64,
    esp_partition_bytes: u64,
    esp_total_bytes: u64,
    esp_free_bytes: u64,
    root_block_size: u64 = 4096,
    root_total_blocks: u64,
    root_free_blocks: u64,
    root_total_inodes: u64,
    root_free_inodes: u64,
    compressed_artifact_bytes: u64,
    qcow2_allocated_bytes: u64,
};

const ContentBytes = struct { id: []const u8, bytes: u64 };

/// The measured x86_64 core build the reviewed x86_64 budget is derived from.
const x86_64_measured: Measured = .{
    .deb_architecture = "amd64",
    .kernel_release = "7.0.0-1010-azure",
    .artifact_name = "Ubuntu-26.04-x86_64.core.qcow2",
    .package_count = 100,
    .installed_bytes = 312_455_680,
    .allocated_bytes = 335_888_384,
    .file_count = 13_346,
    .kernel_bytes = 17_403_904,
    .initramfs_bytes = 40_538_112,
    .modules_bytes = 155_000_832,
    .virtual_size = 611_319_808,
    .uki_bytes = 58_015_648,
    .esp_partition_bytes = 118_489_088,
    .esp_total_bytes = 116_621_312,
    .esp_free_bytes = 58_604_032,
    .root_total_blocks = 119_797,
    .root_free_blocks = 32_768,
    .root_total_inodes = 29_952,
    .root_free_inodes = 16_584,
    .compressed_artifact_bytes = 294_322_176,
    .qcow2_allocated_bytes = 294_256_640,
};

/// The bounded content classes as the same x86_64 build measured them.
const x86_64_content = [_]ContentBytes{
    .{ .id = "documentation", .bytes = 4_043_205 },
    .{ .id = "manual-pages", .bytes = 4_173_089 },
    .{ .id = "info-pages", .bytes = 575_134 },
    .{ .id = "locale-data", .bytes = 7_184_724 },
    .{ .id = "packaging-metadata", .bytes = 84_120 },
    .{ .id = "inert-systemd-units", .bytes = 351_824 },
    .{ .id = "build-tool-hooks", .bytes = 9_242 },
    .{ .id = "debconf-state", .bytes = 1_185_333 },
};

/// The measured AArch64 core build the reviewed AArch64 budget is derived from.
///
/// Recorded from the candidate baseline the same production run published for
/// `aarch64-core`. It shares no byte count with x86_64, which is the point: a
/// fixture that reused x86_64's numbers would prove nothing about the table
/// that AArch64 candidates are actually judged against.
const aarch64_measured: Measured = .{
    .deb_architecture = "arm64",
    .kernel_release = "7.0.0-1010-azure",
    .artifact_name = "Ubuntu-26.04-aarch64.core.qcow2",
    .package_count = 100,
    .installed_bytes = 367_523_299,
    .allocated_bytes = 394_268_672,
    .file_count = 15_134,
    .kernel_bytes = 22_024_192,
    .initramfs_bytes = 58_855_424,
    .modules_bytes = 170_225_664,
    .virtual_size = 818_937_856,
    .uki_bytes = 130_871_200,
    .esp_partition_bytes = 266_338_304,
    .esp_total_bytes = 262_160_384,
    .esp_free_bytes = 131_287_552,
    .root_total_blocks = 134_310,
    .root_free_blocks = 32_768,
    .root_total_inodes = 33_600,
    .root_free_inodes = 18_444,
    .compressed_artifact_bytes = 352_911_360,
    .qcow2_allocated_bytes = 352_792_576,
};

/// The bounded content classes as the same AArch64 build measured them.
const aarch64_content = [_]ContentBytes{
    .{ .id = "documentation", .bytes = 4_043_225 },
    .{ .id = "manual-pages", .bytes = 4_173_065 },
    .{ .id = "info-pages", .bytes = 575_134 },
    .{ .id = "locale-data", .bytes = 7_184_724 },
    .{ .id = "packaging-metadata", .bytes = 84_120 },
    .{ .id = "inert-systemd-units", .bytes = 392_672 },
    .{ .id = "build-tool-hooks", .bytes = 9_242 },
    .{ .id = "debconf-state", .bytes = 1_185_333 },
};

fn contentBytes(table: []const ContentBytes, id: []const u8) u64 {
    for (table) |entry| {
        if (std.mem.eql(u8, entry.id, id)) return entry.bytes;
    }
    return 0;
}

const Builder = struct {
    arena: Allocator,

    fn object(_: Builder) std.json.ObjectMap {
        return .empty;
    }

    fn put(self: Builder, map: *std.json.ObjectMap, key: []const u8, value: Value) !void {
        try map.put(self.arena, key, value);
    }

    fn number(self: Builder, map: *std.json.ObjectMap, key: []const u8, value: u64) !void {
        try self.put(map, key, .{ .integer = @intCast(value) });
    }

    fn text(self: Builder, map: *std.json.ObjectMap, key: []const u8, value: []const u8) !void {
        try self.put(map, key, .{ .string = value });
    }

    fn bucket(self: Builder, files: u64, bytes: u64, allocated: u64) !std.json.ObjectMap {
        var map = self.object();
        try self.number(&map, "file_count", files);
        try self.number(&map, "installed_bytes", bytes);
        try self.number(&map, "allocated_bytes", allocated);
        return map;
    }
};

/// Options for bending one number of the otherwise-measured document.
const Overrides = struct {
    architecture: []const u8 = "x86_64",
    flavor: []const u8 = "core",
    /// The production measurement the document is assembled from. Naming it
    /// per test is what lets one fixture speak for either architecture instead
    /// of quietly presenting x86_64's numbers as somebody else's.
    measured: *const Measured = &x86_64_measured,
    content: []const ContentBytes = &x86_64_content,
    installed_bytes: ?u64 = null,
    package_count: ?u64 = null,
    modules_bytes: ?u64 = null,
    root_free_blocks: ?u64 = null,
    compressed_artifact_bytes: ?u64 = null,
    documentation_bytes: ?u64 = null,
    absent_content_files: u64 = 0,
    unexpected_unowned_files: u64 = 0,
    forbidden_package: ?[]const u8 = null,
    phases: []const size_inventory.Phase = &.{ .root_build, .image_build, .publication },
    first_boot_used_blocks: ?u64 = null,
    first_boot_used_inodes: ?u64 = null,
};

/// Builds a structurally valid size-inventory document carrying a named
/// architecture's measured core numbers, with one field optionally bent.
///
/// It is assembled rather than measured because a budget is a statement about
/// numbers: a real walk would re-derive the same document far more slowly and
/// would tie the budget tests to a root tree they are not about.
fn inventory(arena: Allocator, overrides: Overrides) !Value {
    const builder: Builder = .{ .arena = arena };
    const measured = overrides.measured.*;
    const installed = overrides.installed_bytes orelse measured.installed_bytes;
    const packages_count = overrides.package_count orelse measured.package_count;

    var packages: std.json.Array = .init(arena);
    // One package carries the whole payload, which keeps the arithmetic the
    // validator checks exactly satisfiable while the closure stays a list, and
    // the names are emitted in sorted order because the document contract says
    // they are.
    var names: std.ArrayList([]const u8) = .empty;
    try names.append(arena, "base-files");
    var index: u64 = 1;
    while (index < packages_count) : (index += 1) {
        try names.append(
            arena,
            try std.fmt.allocPrint(arena, "package-{d:0>4}", .{index}),
        );
    }
    if (overrides.forbidden_package) |forbidden| {
        _ = names.pop();
        try names.append(arena, forbidden);
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lessThan(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.lessThan);
    for (names.items, 0..) |name, position| {
        const carries = position == 0;
        var item = builder.object();
        try builder.text(&item, "name", name);
        try builder.text(&item, "version", "1.0-1");
        try builder.text(&item, "architecture", measured.deb_architecture);
        try builder.number(&item, "file_count", if (carries) measured.file_count else 0);
        try builder.number(&item, "installed_bytes", if (carries) installed else 0);
        try builder.number(
            &item,
            "allocated_bytes",
            if (carries) measured.allocated_bytes else 0,
        );
        try packages.append(.{ .object = item });
    }

    var content = builder.object();
    const policy = try size_inventory.contentPolicyDigest(arena);
    try builder.text(&content, "policy_sha256", try arena.dupe(u8, &policy));
    const rules = try size_inventory.contentRulesAlloc(arena);
    var classes: std.json.Array = .init(arena);
    var bounded_files: u64 = 0;
    var bounded_bytes: u64 = 0;
    for (rules) |rule| {
        var item = builder.object();
        try builder.text(&item, "id", rule.id);
        try builder.text(&item, "disposition", rule.disposition.key());
        try builder.text(&item, "reason", rule.reason);
        const bytes = switch (rule.disposition) {
            .absent => 0,
            .bounded => if (std.mem.eql(u8, rule.id, "documentation"))
                overrides.documentation_bytes orelse contentBytes(overrides.content, rule.id)
            else
                contentBytes(overrides.content, rule.id),
        };
        const files: u64 = switch (rule.disposition) {
            .absent => overrides.absent_content_files,
            .bounded => if (bytes == 0) 0 else 1,
        };
        // Only the first absent class carries the injected violation, so the
        // totals below stay the sum of the classes.
        const absent_files = if (rule.disposition == .absent and
            !std.mem.eql(u8, rule.id, rules[0].id)) 0 else files;
        try builder.number(&item, "file_count", absent_files);
        try builder.number(&item, "installed_bytes", bytes);
        try builder.number(&item, "allocated_bytes", bytes);
        if (rule.disposition == .bounded) {
            bounded_files += absent_files;
            bounded_bytes += bytes;
        }
        try classes.append(.{ .object = item });
    }
    try builder.put(&content, "classes", .{ .array = classes });
    var absent = try builder.bucket(overrides.absent_content_files, 0, 0);
    var absent_paths: std.json.Array = .init(arena);
    var written: u64 = 0;
    while (written < overrides.absent_content_files) : (written += 1) {
        try absent_paths.append(.{ .string = "/var/lib/apt/lists/lock" });
    }
    try builder.put(&absent, "paths", .{ .array = absent_paths });
    try builder.put(&absent, "truncated", .{ .bool = false });
    try builder.put(&content, "absent", .{ .object = absent });
    try builder.put(&content, "bounded", .{
        .object = try builder.bucket(bounded_files, bounded_bytes, bounded_bytes),
    });

    const flavor_tag: size_inventory.Flavor =
        if (std.mem.eql(u8, overrides.flavor, "full"))
            .full
        else if (std.mem.eql(u8, overrides.flavor, "baremetal"))
            .baremetal
        else
            .core;
    var unowned = try builder.bucket(overrides.unexpected_unowned_files, 0, 0);
    const unowned_policy = try size_inventory.unownedPolicyDigest(arena, flavor_tag);
    try builder.text(&unowned, "policy_sha256", try arena.dupe(u8, &unowned_policy));
    var allowed: std.json.Array = .init(arena);
    const unowned_rules = try size_inventory.unownedRulesAlloc(arena, flavor_tag);
    for (unowned_rules) |rule| {
        var item = builder.object();
        var target_buffer: [512]u8 = undefined;
        try builder.text(&item, "rule", rule.pattern);
        try builder.text(&item, "reason", rule.reason);
        try builder.text(&item, "category", rule.category.key());
        try builder.text(&item, "source", rule.source.key());
        try builder.text(&item, "kind", rule.kind.key());
        try builder.text(
            &item,
            "target",
            try arena.dupe(u8, rule.target.label(&target_buffer)),
        );
        try builder.text(&item, "origin", rule.origin);
        try builder.number(&item, "file_count", 0);
        try builder.number(&item, "installed_bytes", 0);
        try builder.number(&item, "allocated_bytes", 0);
        try allowed.append(.{ .object = item });
    }
    try builder.put(&unowned, "allowed", .{ .array = allowed });
    var unexpected = try builder.bucket(overrides.unexpected_unowned_files, 0, 0);
    var unexpected_paths: std.json.Array = .init(arena);
    var remaining: u64 = 0;
    while (remaining < overrides.unexpected_unowned_files) : (remaining += 1) {
        try unexpected_paths.append(.{ .string = "/etc/unexplained.conf" });
    }
    try builder.put(&unexpected, "paths", .{ .array = unexpected_paths });
    try builder.put(&unexpected, "truncated", .{ .bool = false });
    try builder.put(&unowned, "unexpected", .{ .object = unexpected });

    var boot = builder.object();
    try builder.text(&boot, "kernel_release", measured.kernel_release);
    try builder.number(&boot, "kernel_bytes", measured.kernel_bytes);
    try builder.number(&boot, "initramfs_bytes", measured.initramfs_bytes);
    try builder.number(
        &boot,
        "modules_bytes",
        overrides.modules_bytes orelse measured.modules_bytes,
    );
    try builder.number(&boot, "firmware_bytes", 0);

    var directories: std.json.Array = .init(arena);
    // An unowned remainder is a path the walk saw, so it is part of the totals
    // the validator makes add up.
    const walked = measured.file_count + overrides.unexpected_unowned_files;
    var root_directory = builder.object();
    try builder.text(&root_directory, "path", "/usr");
    try builder.number(&root_directory, "file_count", walked);
    try builder.number(&root_directory, "installed_bytes", installed);
    try builder.number(&root_directory, "allocated_bytes", measured.allocated_bytes);
    try directories.append(.{ .object = root_directory });

    var root_build = builder.object();
    try builder.number(&root_build, "package_count", packages_count);
    try builder.text(
        &root_build,
        "closure_sha256",
        "41ada9bc6354b1b3019efd96a90d0d64259f196587a666fbe5e3fd66cbed44cf",
    );
    try builder.text(
        &root_build,
        "package_lock_sha256",
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    try builder.number(&root_build, "file_count", walked);
    try builder.number(&root_build, "installed_bytes", installed);
    try builder.number(&root_build, "allocated_bytes", measured.allocated_bytes);
    try builder.number(&root_build, "unreadable_path_count", 0);
    try builder.put(&root_build, "packages", .{ .array = packages });
    try builder.put(&root_build, "owned", .{
        .object = try builder.bucket(measured.file_count, installed, measured.allocated_bytes),
    });
    try builder.put(&root_build, "shared", .{ .object = try builder.bucket(0, 0, 0) });
    var unmatched = try builder.bucket(0, 0, 0);
    try builder.put(&unmatched, "packages", .{ .array = std.json.Array.init(arena) });
    try builder.put(&root_build, "unmatched", .{ .object = unmatched });
    try builder.put(&root_build, "unowned", .{ .object = unowned });
    try builder.put(&root_build, "content", .{ .object = content });
    try builder.put(&root_build, "root_directories", .{ .array = directories });
    try builder.put(&root_build, "boot", .{ .object = boot });

    const free_blocks = overrides.root_free_blocks orelse measured.root_free_blocks;
    var image_build = builder.object();
    try builder.number(&image_build, "virtual_size", measured.virtual_size);
    try builder.number(&image_build, "root_block_size", measured.root_block_size);
    try builder.number(&image_build, "root_total_blocks", measured.root_total_blocks);
    try builder.number(
        &image_build,
        "root_used_blocks",
        measured.root_total_blocks - free_blocks,
    );
    try builder.number(&image_build, "root_free_blocks", free_blocks);
    try builder.number(&image_build, "root_total_inodes", measured.root_total_inodes);
    try builder.number(
        &image_build,
        "root_used_inodes",
        measured.root_total_inodes - measured.root_free_inodes,
    );
    try builder.number(&image_build, "root_free_inodes", measured.root_free_inodes);
    try builder.number(&image_build, "uki_bytes", measured.uki_bytes);
    try builder.number(&image_build, "esp_partition_bytes", measured.esp_partition_bytes);
    try builder.number(&image_build, "esp_total_bytes", measured.esp_total_bytes);
    try builder.number(
        &image_build,
        "esp_used_bytes",
        measured.esp_total_bytes - measured.esp_free_bytes,
    );
    try builder.number(&image_build, "esp_free_bytes", measured.esp_free_bytes);

    var publication = builder.object();
    try builder.text(&publication, "artifact_name", measured.artifact_name);
    try builder.number(
        &publication,
        "compressed_artifact_bytes",
        overrides.compressed_artifact_bytes orelse measured.compressed_artifact_bytes,
    );
    try builder.number(&publication, "qcow2_allocated_bytes", measured.qcow2_allocated_bytes);

    var first_boot = builder.object();
    const used_blocks = overrides.first_boot_used_blocks orelse
        (measured.root_total_blocks - free_blocks + 4096);
    const used_inodes = overrides.first_boot_used_inodes orelse
        (measured.root_total_inodes - measured.root_free_inodes + 100);
    try builder.number(&first_boot, "root_block_size", measured.root_block_size);
    try builder.number(&first_boot, "root_total_blocks", measured.root_total_blocks);
    try builder.number(&first_boot, "root_used_blocks", used_blocks);
    try builder.number(
        &first_boot,
        "root_free_blocks",
        measured.root_total_blocks - used_blocks,
    );
    try builder.number(&first_boot, "root_total_inodes", measured.root_total_inodes);
    try builder.number(&first_boot, "root_used_inodes", used_inodes);
    try builder.number(
        &first_boot,
        "root_free_inodes",
        measured.root_total_inodes - used_inodes,
    );

    var document = builder.object();
    try builder.number(&document, "schema", @intCast(size_inventory.schema_version));
    try builder.text(&document, "type", "miz-ubuntu2604-size-inventory");
    try builder.text(&document, "release", "26.04");
    try builder.text(&document, "architecture", overrides.architecture);
    try builder.text(&document, "flavor", overrides.flavor);
    var phases: std.json.Array = .init(arena);
    for (overrides.phases) |phase| {
        try phases.append(.{ .string = phase.key() });
        switch (phase) {
            .root_build => try builder.put(&document, "root_build", .{ .object = root_build }),
            .image_build => try builder.put(&document, "image_build", .{ .object = image_build }),
            .publication => try builder.put(&document, "publication", .{ .object = publication }),
            .first_boot => try builder.put(&document, "first_boot", .{ .object = first_boot }),
        }
    }
    try builder.put(&document, "phases_present", .{ .array = phases });
    return .{ .object = document };
}

fn evaluate(arena: Allocator, overrides: Overrides, diagnostic: *Diagnostic) !size_budget.Evaluation {
    const document = try inventory(arena, overrides);
    return size_budget.evaluate(std.testing.allocator, document, .{
        .architecture = overrides.architecture,
        .flavor = overrides.flavor,
        .required_phases = overrides.phases,
    }, diagnostic);
}

fn observationOf(evaluation: *const size_budget.Evaluation, id: []const u8) ?size_budget.Observation {
    for (evaluation.observations) |observation| {
        var buffer: [128]u8 = undefined;
        if (std.mem.eql(u8, observation.measure.id(&buffer), id)) return observation;
    }
    return null;
}

test "the reviewed budget is pinned by digest so it cannot widen quietly" {
    // This is the mechanism, not a checksum ritual. Any edit to a baseline, an
    // allowance, a direction, a basis, or the set of budgeted architectures
    // moves the digest, and this test fails until a reviewer updates the pin in
    // the same change. There is no refresh path.
    const digest = try size_budget.budgetDigest(std.testing.allocator);
    try std.testing.expectEqualStrings(
        size_budget.reviewed_budget_sha256,
        &digest,
    );
}

test "every limit follows from its recorded measurement and named allowance" {
    var saw_percent = false;
    var saw_minimum = false;
    for ([_]size_budget.Architecture{ .x86_64, .aarch64 }) |architecture| {
        const budget = size_budget.budgetFor(.core, architecture).?;
        for (budget.limits) |limit| {
            switch (limit.allowance) {
                .exact => try std.testing.expectEqual(limit.baseline, limit.value()),
                .plus => |amount| try std.testing.expectEqual(
                    limit.baseline + amount,
                    limit.value(),
                ),
                .security_update_percent => |percent| {
                    saw_percent = true;
                    // The margin is a real margin and a narrow one: strictly above
                    // the measurement, and never more than one percent past the
                    // percentage it claims once block rounding is included.
                    try std.testing.expect(limit.value() > limit.baseline);
                    try std.testing.expect(
                        limit.value() <= limit.baseline + (limit.baseline / 100) * (percent + 1) + 4096,
                    );
                },
            }
            // A bound with no stated reason is a number nobody reviewed.
            try std.testing.expect(limit.basis.len > 0);
            if (limit.direction == .at_least) {
                saw_minimum = true;
                // A minimum is a floor the image promised to deliver, so an
                // allowance would only ever weaken it.
                try std.testing.expectEqual(limit.baseline, limit.value());
            }
        }
    }
    try std.testing.expect(saw_percent);
    try std.testing.expect(saw_minimum);
}

test "the two architectures are budgeted from separate measurements" {
    // The AArch64 table exists because AArch64 was measured, not because
    // x86_64 was. Every quantity that depends on the architecture -- the tree,
    // the kernel, the module tree, the initramfs, the UKI, the disk the plan
    // calculated from them, and the artifact that came out -- has to differ. A
    // future edit that copied one table into the other fails here.
    const x86 = size_budget.budgetFor(.core, .x86_64).?;
    const arm = size_budget.budgetFor(.core, .aarch64).?;
    try std.testing.expectEqual(x86.limits.len, arm.limits.len);

    const architecture_dependent = [_][]const u8{
        "installed_bytes",
        "allocated_bytes",
        "file_count",
        "kernel_bytes",
        "initramfs_bytes",
        "modules_bytes",
        "virtual_size",
        "uki_bytes",
        "esp_used_bytes",
        "esp_partition_bytes",
        "root_total_blocks",
        "root_used_blocks",
        "root_used_inodes",
        "compressed_artifact_bytes",
        "qcow2_allocated_bytes",
    };
    var checked: usize = 0;
    for (x86.limits, arm.limits) |left, right| {
        var left_id: [128]u8 = undefined;
        var right_id: [128]u8 = undefined;
        const id = left.measure.id(&left_id);
        // The two tables bound the same metrics in the same order, so a
        // reviewer diffs numbers rather than structure.
        try std.testing.expectEqualStrings(id, right.measure.id(&right_id));
        try std.testing.expectEqual(left.direction, right.direction);
        for (architecture_dependent) |name| {
            if (!std.mem.eql(u8, id, name)) continue;
            checked += 1;
            if (left.baseline == right.baseline) {
                std.debug.print(
                    "{s} is identical on both architectures: {d}\n",
                    .{ id, left.baseline },
                );
                return error.TestUnexpectedResult;
            }
        }
    }
    try std.testing.expectEqual(architecture_dependent.len, checked);

    // The bounds that do coincide are the ones that are the same by
    // construction: zero content, zero unowned remainder, the reserves the
    // disk plan promises from the same declared first-boot growth, and the
    // architecture-independent data files inside architecture-independent
    // packages. None of them is a measurement borrowed from elsewhere.
    for (x86.limits, arm.limits) |left, right| {
        if (left.baseline != right.baseline) continue;
        var id_buffer: [128]u8 = undefined;
        const id = left.measure.id(&id_buffer);
        const shared_by_construction =
            left.baseline == 0 or
            left.allowance == .exact or
            left.direction == .at_least or
            std.mem.startsWith(u8, id, "content.") or
            std.mem.eql(u8, id, "package_count");
        if (!shared_by_construction) {
            std.debug.print("{s} coincides without a reason\n", .{id});
            return error.TestUnexpectedResult;
        }
    }
}

test "the measured x86_64 core build passes every reviewed bound" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(arena.allocator(), .{}, &diagnostic);
    defer evaluation.deinit();
    try std.testing.expectEqual(size_budget.Status.enforced, evaluation.status);
    try std.testing.expectEqual(@as(usize, 0), evaluation.failures);
    try std.testing.expectEqual(size_budget.Result.pass, size_budget.resultOf(&evaluation));
    // Every metric whose phase is present was actually evaluated.
    try std.testing.expect(observationOf(&evaluation, "installed_bytes") != null);
    try std.testing.expect(observationOf(&evaluation, "compressed_artifact_bytes") != null);
    try std.testing.expect(
        observationOf(&evaluation, "content.documentation.installed_bytes") != null,
    );
}

test "the measured AArch64 core build passes every reviewed bound" {
    // The same proof for the architecture #677 could not publish until now:
    // the document assembled from the AArch64 candidate baseline passes the
    // AArch64 table, and does so as `enforced` rather than as a recording.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(arena.allocator(), .{
        .architecture = "aarch64",
        .measured = &aarch64_measured,
        .content = &aarch64_content,
    }, &diagnostic);
    defer evaluation.deinit();
    try std.testing.expectEqual(size_budget.Status.enforced, evaluation.status);
    try std.testing.expectEqual(@as(usize, 0), evaluation.failures);
    try std.testing.expectEqual(size_budget.Result.pass, size_budget.resultOf(&evaluation));
    // And the AArch64 image is judged against AArch64's bounds: its root does
    // not fit inside x86_64's, so a table that had been copied across would
    // fail here rather than pass.
    var against_x86: Diagnostic = .{};
    var wrong = try evaluate(arena.allocator(), .{
        .architecture = "x86_64",
        .measured = &aarch64_measured,
        .content = &aarch64_content,
    }, &against_x86);
    defer wrong.deinit();
    try std.testing.expect(wrong.failures > 0);
}

test "each maximum holds exactly at its bound and fails one unit past it" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const budget = size_budget.budgetFor(.core, .x86_64).?;
    var installed_limit: u64 = 0;
    var compressed_limit: u64 = 0;
    for (budget.limits) |limit| {
        var buffer: [128]u8 = undefined;
        const id = limit.measure.id(&buffer);
        if (std.mem.eql(u8, id, "installed_bytes")) installed_limit = limit.value();
        if (std.mem.eql(u8, id, "compressed_artifact_bytes")) compressed_limit = limit.value();
    }
    try std.testing.expect(installed_limit != 0 and compressed_limit != 0);

    for ([_]struct { at: u64, over: bool }{
        .{ .at = installed_limit, .over = false },
        .{ .at = installed_limit + 1, .over = true },
    }) |boundary| {
        var diagnostic: Diagnostic = .{};
        var evaluation = try evaluate(
            allocator,
            .{ .installed_bytes = boundary.at },
            &diagnostic,
        );
        defer evaluation.deinit();
        try std.testing.expectEqual(
            @as(usize, if (boundary.over) 1 else 0),
            evaluation.failures,
        );
    }

    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(
        allocator,
        .{ .compressed_artifact_bytes = compressed_limit + 1 },
        &diagnostic,
    );
    defer evaluation.deinit();
    try std.testing.expectEqual(@as(usize, 1), evaluation.failures);
}

test "a minimum fails when the promised reserve is not delivered" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(
        arena.allocator(),
        .{ .root_free_blocks = x86_64_measured.root_free_blocks - 1 },
        &diagnostic,
    );
    defer evaluation.deinit();
    const observation = observationOf(&evaluation, "root_free_blocks").?;
    try std.testing.expectEqual(size_budget.Direction.at_least, observation.direction);
    try std.testing.expect(!observation.ok);
}

test "a failure names the metric, the observation, the bound, and the delta" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(
        arena.allocator(),
        .{ .modules_bytes = x86_64_measured.modules_bytes * 2 },
        &diagnostic,
    );
    defer evaluation.deinit();
    try std.testing.expectEqual(@as(usize, 1), evaluation.failures);

    var buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try size_budget.writeFailures(&evaluation, &writer);
    const text = writer.buffered();
    try expectContains(text, "modules_bytes");
    try expectContains(text, "root_build");
    try expectContains(text, "exceeds");
    try expectContains(text, "bytes");
    // The recorded measurement the bound came from is quoted, so a reader can
    // tell a widened bound from a grown image, and so is the delta.
    try expectContains(text, "measured baseline 155000832");
    try expectContains(text, "by 147247104");
}

test "a metric whose phase is absent is skipped rather than passed as zero" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(arena.allocator(), .{
        .phases = &.{ .root_build, .image_build },
    }, &diagnostic);
    defer evaluation.deinit();
    try std.testing.expect(observationOf(&evaluation, "installed_bytes") != null);
    // Publication has not happened, so the artifact has no size -- not a size
    // of zero, which would pass every conceivable bound.
    try std.testing.expect(observationOf(&evaluation, "compressed_artifact_bytes") == null);
    try std.testing.expect(!evaluation.has(.publication));
    try std.testing.expectEqual(@as(usize, 0), evaluation.failures);
}

test "first-boot growth is a difference and is bounded by the declared growth" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const used = x86_64_measured.root_total_blocks - x86_64_measured.root_free_blocks;
    for ([_]struct { blocks: u64, failures: usize }{
        .{ .blocks = used + 8_192, .failures = 0 },
        .{ .blocks = used + 8_193, .failures = 1 },
        // A first boot that freed space grew by nothing, not by an enormous
        // unsigned number.
        .{ .blocks = used - 1, .failures = 0 },
    }) |scenario| {
        var diagnostic: Diagnostic = .{};
        var evaluation = try evaluate(allocator, .{
            .phases = &.{ .root_build, .image_build, .publication, .first_boot },
            .first_boot_used_blocks = scenario.blocks,
        }, &diagnostic);
        defer evaluation.deinit();
        try std.testing.expectEqual(scenario.failures, evaluation.failures);
        try std.testing.expect(
            observationOf(&evaluation, "first_boot_growth_blocks") != null,
        );
    }
}

test "a flavor with no reviewed budget records a baseline instead" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    // Both published core architectures are measured now, so the unmeasured
    // case is the fresh-root flavor this release does not publish. The
    // mechanism is unchanged: no table, no judgement, a recording instead.
    try std.testing.expect(size_budget.budgetFor(.baremetal, .x86_64) == null);
    try std.testing.expect(size_budget.budgetFor(.baremetal, .aarch64) == null);
    var evaluation = try evaluate(arena.allocator(), .{
        .flavor = "baremetal",
        // Numbers that would break every core bound, to prove the recorded
        // baseline is not being judged against a budget that is not its own.
        .installed_bytes = x86_64_measured.installed_bytes * 4,
    }, &diagnostic);
    defer evaluation.deinit();
    try std.testing.expectEqual(size_budget.Status.candidate_baseline, evaluation.status);
    try std.testing.expectEqual(@as(usize, 0), evaluation.failures);
    try std.testing.expectEqual(
        size_budget.Result.baseline_recorded,
        size_budget.resultOf(&evaluation),
    );
    const observation = observationOf(&evaluation, "installed_bytes").?;
    try std.testing.expect(observation.baseline == null);
    try std.testing.expect(observation.limit == null);
    try std.testing.expectEqual(x86_64_measured.installed_bytes * 4, observation.observed);
}

test "a recorded baseline cannot be published" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(allocator, .{ .flavor = "baremetal" }, &diagnostic);
    defer evaluation.deinit();
    const document = try size_budget.documentValue(allocator, &evaluation);

    // Validation accepts it, because a baseline is a legitimate thing for a
    // validation run to produce...
    _ = try size_budget.validateDocument(allocator, document, .{
        .architecture = "x86_64",
        .flavor = "baremetal",
    }, &diagnostic);
    // ...and publication refuses it, because nobody has reviewed the numbers.
    try std.testing.expectError(error.Failed, size_budget.validateDocument(
        allocator,
        document,
        .{ .architecture = "x86_64", .flavor = "baremetal", .require_enforced = true },
        &diagnostic,
    ));
    try expectContains(diagnostic.message(), "no reviewed size budget");
}

test "an architecture mismatch is refused rather than evaluated" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(allocator, .{}, &diagnostic);
    defer evaluation.deinit();
    const document = try size_budget.documentValue(allocator, &evaluation);
    try std.testing.expectError(error.Failed, size_budget.validateDocument(
        allocator,
        document,
        .{ .architecture = "aarch64", .flavor = "core" },
        &diagnostic,
    ));
    try expectContains(diagnostic.message(), "is for x86_64");

    // And an inventory whose architecture is not one this release publishes is
    // refused before any bound is consulted.
    const foreign = try inventory(allocator, .{});
    try std.testing.expectError(error.Failed, size_budget.evaluate(
        std.testing.allocator,
        foreign,
        .{ .architecture = "riscv64", .flavor = "core" },
        &diagnostic,
    ));
}

test "forbidden content in an absent class fails the gate with its path" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(
        arena.allocator(),
        .{ .absent_content_files = 1 },
        &diagnostic,
    );
    defer evaluation.deinit();
    const observation = observationOf(&evaluation, "absent_content_files").?;
    try std.testing.expectEqual(@as(u64, 0), observation.limit.?);
    try std.testing.expect(!observation.ok);
    try std.testing.expectEqual(@as(usize, 1), evaluation.failures);
}

test "an unowned path outside the allowlist fails the reviewed bound" {
    // The measurement already fails a fresh-root build closed on this. The
    // budget states the same thing as a bound, so a document that reached a
    // gate with a remainder is refused there too rather than only at the point
    // it was measured.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(
        arena.allocator(),
        .{ .unexpected_unowned_files = 1 },
        &diagnostic,
    );
    defer evaluation.deinit();
    const observation = observationOf(&evaluation, "unexpected_unowned_files").?;
    try std.testing.expectEqual(@as(u64, 0), observation.limit.?);
    try std.testing.expect(!observation.ok);
}

test "a forbidden package in the measured closure is named, not merely counted" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.Failed, evaluate(
        arena.allocator(),
        .{ .forbidden_package = "ubuntu-minimal" },
        &diagnostic,
    ));
    try expectContains(diagnostic.message(), "ubuntu-minimal");
}

test "a bounded content class cannot grow past its measured bound" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(
        arena.allocator(),
        .{ .documentation_bytes = contentBytes(&x86_64_content, "documentation") * 2 },
        &diagnostic,
    );
    defer evaluation.deinit();
    const observation =
        observationOf(&evaluation, "content.documentation.installed_bytes").?;
    try std.testing.expect(!observation.ok);
}

test "a malformed or truncated inventory is refused rather than half-judged" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    // Not an object at all.
    try std.testing.expectError(error.Failed, size_budget.evaluate(
        std.testing.allocator,
        .{ .string = "not a document" },
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));

    // A document missing a phase the caller requires.
    const partial = try inventory(allocator, .{ .phases = &.{.root_build} });
    try std.testing.expectError(error.Failed, size_budget.evaluate(
        std.testing.allocator,
        partial,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));

    // A document whose content policy digest is not the reviewed one, which is
    // what a locally widened policy would produce.
    var tampered = try inventory(allocator, .{});
    var content = tampered.object.getPtr("root_build").?.object.getPtr("content").?;
    try content.object.put(
        allocator,
        "policy_sha256",
        .{ .string = "0" ** 64 },
    );
    try std.testing.expectError(error.Failed, size_budget.evaluate(
        std.testing.allocator,
        tampered,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));
    try expectContains(diagnostic.message(), "content policy digest");
}

test "a published verdict is re-derived rather than believed" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(allocator, .{}, &diagnostic);
    defer evaluation.deinit();
    const document = try size_budget.documentValue(allocator, &evaluation);
    const summary = try size_budget.validateDocument(allocator, document, .{
        .architecture = "x86_64",
        .flavor = "core",
        .inventory_sha256 = evaluation.inventory_sha256,
        .require_enforced = true,
    }, &diagnostic);
    try std.testing.expectEqual(size_budget.Result.pass, summary.result);
    try std.testing.expectEqualStrings(
        size_budget.reviewed_budget_sha256,
        summary.budget_sha256,
    );

    // A widened limit in the document is not the reviewed limit.
    var widened = try size_budget.documentValue(allocator, &evaluation);
    const metrics = widened.object.getPtr("metrics").?;
    var raised = metrics.array.items[0].object;
    try raised.put(allocator, "limit", .{ .integer = std.math.maxInt(i32) });
    metrics.array.items[0] = .{ .object = raised };
    try std.testing.expectError(error.Failed, size_budget.validateDocument(
        allocator,
        widened,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));
    try expectContains(diagnostic.message(), "the reviewed budget derives");

    // A verdict that does not follow from the document's own numbers.
    var lying = try size_budget.documentValue(allocator, &evaluation);
    try lying.object.put(allocator, "result", .{ .string = "fail" });
    try std.testing.expectError(error.Failed, size_budget.validateDocument(
        allocator,
        lying,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));

    // A gate document presented beside a measurement it did not judge.
    try std.testing.expectError(error.Failed, size_budget.validateDocument(
        allocator,
        document,
        .{
            .architecture = "x86_64",
            .flavor = "core",
            .inventory_sha256 = "9" ** 64,
        },
        &diagnostic,
    ));
    try expectContains(diagnostic.message(), "judged inventory");
}

test "a document that drops an inconvenient metric is refused" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    var evaluation = try evaluate(allocator, .{}, &diagnostic);
    defer evaluation.deinit();
    var document = try size_budget.documentValue(allocator, &evaluation);
    const metrics = document.object.getPtr("metrics").?;
    _ = metrics.array.orderedRemove(0);
    try std.testing.expectError(error.Failed, size_budget.validateDocument(
        allocator,
        document,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));
    try expectContains(diagnostic.message(), "omits metric");
}

test "the content policy names every class #677 forbids and justifies the rest" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const rules = try size_inventory.contentRulesAlloc(arena.allocator());
    var absent_seen: usize = 0;
    var bounded_seen: usize = 0;
    for (rules) |rule| {
        // Every class states why it is forbidden or why it survives.
        try std.testing.expect(rule.reason.len > 0);
        try std.testing.expect(rule.patterns.len > 0);
        for (rule.patterns) |pattern| {
            try std.testing.expect(pattern.len > 1 and pattern[0] == '/');
        }
        switch (rule.disposition) {
            .absent => {
                // Absent classes come first, so a forbidden subtree wins over
                // a bounded parent.
                try std.testing.expectEqual(@as(usize, 0), bounded_seen);
                absent_seen += 1;
            },
            .bounded => bounded_seen += 1,
        }
    }
    for ([_][]const u8{
        "apt-state",
        "apt-cache",
        "apt-client",
        "cloud-init",
        "walinuxagent",
        "snap",
        "systemd-service-manager",
        "initramfs-generator",
        "kernel-build-tree",
    }) |id| {
        var found = false;
        for (rules) |rule| {
            if (std.mem.eql(u8, rule.id, id)) {
                try std.testing.expectEqual(
                    size_inventory.ContentDisposition.absent,
                    rule.disposition,
                );
                found = true;
            }
        }
        try std.testing.expect(found);
    }
    // Every bounded class the reviewed budget names exists in the policy, and
    // every bounded class in the policy is budgeted: an unbudgeted class would
    // be content nobody caps.
    const budget = size_budget.budgetFor(.core, .x86_64).?;
    for (rules) |rule| {
        if (rule.disposition != .bounded) continue;
        var budgeted = false;
        for (budget.limits) |limit| {
            switch (limit.measure) {
                .content_class_bytes => |class| {
                    if (std.mem.eql(u8, class, rule.id)) budgeted = true;
                },
                else => {},
            }
        }
        if (!budgeted) {
            std.debug.print("content class {s} has no budget\n", .{rule.id});
            return error.TestUnbudgetedContentClass;
        }
    }
}
