//! Behavioral coverage for the calculated core disk geometry (issue #677
//! step 5).
//!
//! The contracts under test are the ones the shipped image stands on, and none
//! of them is a number: the ESP is partition 1 because `mizinit` looks nowhere
//! else, the root is last because `azagent`'s growth refuses a partition that
//! is not, every edge lands on a megabyte because Azure's VHD upload requires
//! it, the two architectures are planned apart, the same measurements always
//! produce the same disk, and the retired 3584 MiB geometry cannot come back
//! through any input the planner accepts.

const std = @import("std");

const release = @import("ubuntu2604_release");

const Allocator = std.mem.Allocator;
const disk_geometry = release.disk_geometry;
const Diagnostic = disk_geometry.Diagnostic;

const mib: u64 = 1024 * 1024;

const identity = disk_geometry.Identity{
    .disk_guid = "6d697a20-2604-4c6f-b165-000000000164",
    .esp_type_guid = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    .esp_partition_guid = "6d697a20-2604-4573-9001-000000000164",
    .esp_volume_id = 0x2604_0164,
    .esp_volume_label = "UEFI",
    .root_type_guid = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    .root_partition_guid = "6d697a20-2604-526f-a074-000000000164",
    .root_filesystem_uuid = "207a696d-0426-4f52-a074-00000000019b",
    .root_filesystem_label = "cloudimg-rootfs",
};

/// The measurements a real x86_64 core build produced, taken from the geometry
/// report of a build of this tree. Real rather than round so the fixture
/// exercises the arithmetic the shipped image actually goes through.
const measured_x86_64 = disk_geometry.Measurements{
    .signed_uki_bytes = 58_039_112,
    .esp_minimum_bytes = 118_489_088,
    .root_minimum_bytes = 355_033_088,
    .root_fitted_bytes = 490_651_648,
    .first_boot = undefined,
};

/// The same shape for AArch64, whose UKI and module tree are larger. The two
/// architectures are planned independently, so this exists to prove they do
/// not land on a shared size rather than to claim an AArch64 build's numbers.
const planned_aarch64 = disk_geometry.Measurements{
    .signed_uki_bytes = 71_000_000,
    .esp_minimum_bytes = 148 * mib,
    .root_minimum_bytes = 430 * mib,
    .root_fitted_bytes = 580 * mib,
    .first_boot = undefined,
};

fn measurementsFor(architecture: disk_geometry.Architecture) disk_geometry.Measurements {
    var measurements = switch (architecture) {
        .x86_64 => measured_x86_64,
        .aarch64 => planned_aarch64,
    };
    measurements.first_boot = disk_geometry.firstBootGrowth(architecture);
    return measurements;
}

fn planFor(architecture: disk_geometry.Architecture) !disk_geometry.Plan {
    return disk_geometry.plan(.{
        .architecture = architecture,
        .measurements = measurementsFor(architecture),
        .root_name = "cloudimg-rootfs",
    });
}

test "a real x86_64 build's measurements plan a disk the consumers can use" {
    const plan = try planFor(.x86_64);

    // `mizinit` mounts the ESP from partition 1 and nowhere else.
    try std.testing.expectEqual(@as(u32, 0), plan.esp.table_index);
    try std.testing.expectEqual(@as(u64, 2048), plan.esp.firstLba());
    // `azagent`'s `growPartitionToEnd` refuses a root that is not last.
    try std.testing.expectEqual(@as(u32, 1), plan.root.table_index);
    try std.testing.expect(plan.root.firstLba() > plan.esp.lastLba());
    try std.testing.expect(plan.root.lastLba() <= plan.lastUsableLba());
    // Only the reserved GPT tail follows the root, so growth has the whole
    // disk to take.
    try std.testing.expect(
        plan.lastUsableLba() - plan.root.lastLba() < mib / disk_geometry.sector_size,
    );
    // Azure accepts a whole number of MiB and nothing else.
    try std.testing.expectEqual(@as(u64, 0), plan.virtual_size % mib);
    try std.testing.expectEqual(@as(u64, 0), plan.esp.offset_bytes % mib);
    try std.testing.expectEqual(@as(u64, 0), plan.root.offset_bytes % mib);
    // The backup header is the last sector of the disk.
    try std.testing.expectEqual(
        plan.virtual_size / disk_geometry.sector_size - 1,
        plan.backupHeaderLba(),
    );
    // And the point of the exercise: much smaller than what it replaced.
    try std.testing.expect(plan.virtual_size < disk_geometry.retired_inherited_virtual_size / 4);
}

test "the ESP holds the signed UKI and one replacement, and the root holds the reserve" {
    const plan = try planFor(.x86_64);
    const measurements = measurementsFor(.x86_64);
    try std.testing.expect(
        plan.esp.length_bytes >= 2 * measurements.signed_uki_bytes,
    );
    try std.testing.expect(plan.esp.length_bytes >= measurements.esp_minimum_bytes);
    try std.testing.expectEqual(
        @as(u64, 4) * disk_geometry.firstBootGrowth(.x86_64).bytes,
        plan.requirements.root_free_bytes,
    );
    try std.testing.expect(
        plan.root.filesystem_length_bytes >= plan.requirements.root_floor_bytes,
    );
}

test "the two architectures are planned apart" {
    const x86 = try planFor(.x86_64);
    const arm = try planFor(.aarch64);
    try std.testing.expect(x86.virtual_size != arm.virtual_size);
    try std.testing.expect(x86.esp.length_bytes != arm.esp.length_bytes);
    try std.testing.expect(x86.root.length_bytes != arm.root.length_bytes);
    // Neither is the retired size, and neither is derived from the other.
    for ([_]disk_geometry.Plan{ x86, arm }) |plan| {
        try std.testing.expect(
            plan.virtual_size != disk_geometry.retired_inherited_virtual_size,
        );
    }
}

test "planning is a pure function of its measurements" {
    for ([_]disk_geometry.Architecture{ .x86_64, .aarch64 }) |architecture| {
        const first = try planFor(architecture);
        const second = try planFor(architecture);
        try std.testing.expectEqual(first.virtual_size, second.virtual_size);
        try std.testing.expectEqual(first.esp.offset_bytes, second.esp.offset_bytes);
        try std.testing.expectEqual(first.esp.length_bytes, second.esp.length_bytes);
        try std.testing.expectEqual(first.root.offset_bytes, second.root.offset_bytes);
        try std.testing.expectEqual(first.root.length_bytes, second.root.length_bytes);
        try std.testing.expectEqual(
            first.root.filesystem_length_bytes,
            second.root.filesystem_length_bytes,
        );
    }
}

test "a measurement one byte over an alignment boundary buys a whole unit" {
    var measurements = measurementsFor(.x86_64);
    measurements.esp_minimum_bytes = 112 * mib;
    const aligned = try disk_geometry.plan(.{
        .architecture = .x86_64,
        .measurements = measurements,
    });
    measurements.esp_minimum_bytes = 112 * mib + 1;
    const over = try disk_geometry.plan(.{
        .architecture = .x86_64,
        .measurements = measurements,
    });
    try std.testing.expectEqual(112 * mib, aligned.esp.length_bytes);
    try std.testing.expectEqual(113 * mib, over.esp.length_bytes);
    try std.testing.expectEqual(
        aligned.virtual_size + mib,
        over.virtual_size,
    );
    // The root moved with the ESP rather than overlapping it.
    try std.testing.expectEqual(
        aligned.root.offset_bytes + mib,
        over.root.offset_bytes,
    );
}

test "measurements that cannot be honoured are refused by name" {
    const zero_fields = [_][]const u8{
        "signed_uki_bytes",
        "esp_minimum_bytes",
        "root_minimum_bytes",
        "root_fitted_bytes",
    };
    for (zero_fields) |field| {
        var measurements = measurementsFor(.x86_64);
        if (std.mem.eql(u8, field, "signed_uki_bytes")) {
            measurements.signed_uki_bytes = 0;
        } else if (std.mem.eql(u8, field, "esp_minimum_bytes")) {
            measurements.esp_minimum_bytes = 0;
        } else if (std.mem.eql(u8, field, "root_minimum_bytes")) {
            measurements.root_minimum_bytes = 0;
        } else {
            measurements.root_fitted_bytes = 0;
        }
        try std.testing.expectError(error.InvalidGeometryInput, disk_geometry.plan(.{
            .architecture = .x86_64,
            .measurements = measurements,
        }));
    }

    // A fitted root that does not clear the reserve is a root the guest would
    // run out of on first boot.
    var short = measurementsFor(.x86_64);
    short.root_fitted_bytes = short.root_minimum_bytes;
    try std.testing.expectError(error.RootBelowMinimum, disk_geometry.plan(.{
        .architecture = .x86_64,
        .measurements = short,
    }));

    // And an overflow is an overflow, not a wrapped-around plausible number.
    var huge = measurementsFor(.x86_64);
    huge.root_fitted_bytes = std.math.maxInt(u64) - 4096;
    try std.testing.expectError(error.InvalidGeometryInput, disk_geometry.plan(.{
        .architecture = .x86_64,
        .measurements = huge,
    }));
}

fn documentFor(
    arena: Allocator,
    architecture: disk_geometry.Architecture,
) !std.json.Value {
    return disk_geometry.documentValue(
        arena,
        "core",
        try planFor(architecture),
        identity,
    );
}

test "a published report re-derives to the disk it describes" {
    for ([_]disk_geometry.Architecture{ .x86_64, .aarch64 }) |architecture| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const document = try documentFor(arena.allocator(), architecture);
        var diagnostic: Diagnostic = .{};
        const plan = try planFor(architecture);
        const summary = disk_geometry.validateDocument(document, .{
            .architecture = @tagName(architecture),
            .flavor = "core",
            .virtual_size = plan.virtual_size,
        }, &diagnostic) catch {
            std.debug.print("{s}\n", .{diagnostic.message()});
            return error.TestUnexpectedResult;
        };
        try std.testing.expectEqual(plan.virtual_size, summary.virtual_size);
        try std.testing.expectEqual(plan.esp.length_bytes, summary.esp_length_bytes);
        try std.testing.expectEqual(plan.root.length_bytes, summary.root_length_bytes);
        // Azure acceptance measures root growth from where the root starts, so
        // the plan has to say where that is rather than leave a consumer to
        // name the inherited offset core stopped using.
        try std.testing.expectEqual(plan.root.firstLba(), summary.root_first_lba);
        try std.testing.expect(
            summary.root_first_lba * disk_geometry.sector_size +
                summary.root_length_bytes <= summary.virtual_size,
        );
    }
}

test "a report edited anywhere it matters stops validating" {
    const Edit = struct {
        section: []const u8,
        key: []const u8,
        delta: i64,
    };
    const edits = [_]Edit{
        .{ .section = "disk", .key = "virtual_size", .delta = @intCast(mib) },
        .{ .section = "disk", .key = "backup_header_lba", .delta = -1 },
        .{ .section = "disk", .key = "last_usable_lba", .delta = 1 },
        .{ .section = "requirements", .key = "root_free_bytes", .delta = -4096 },
        .{ .section = "requirements", .key = "root_floor_bytes", .delta = 4096 },
        .{ .section = "measurements", .key = "root_minimum_bytes", .delta = @intCast(mib) },
        .{ .section = "measurements", .key = "esp_minimum_bytes", .delta = @intCast(mib) },
        .{ .section = "policy", .key = "first_boot_growth_reserve_multiple", .delta = -1 },
    };
    for (edits) |edit| {
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const document = try documentFor(arena.allocator(), .x86_64);
        var section = document.object.get(edit.section).?.object;
        const current = section.get(edit.key).?.integer;
        try section.put(
            arena.allocator(),
            edit.key,
            .{ .integer = current + edit.delta },
        );
        document.object.getPtr(edit.section).?.* = .{ .object = section };
        var diagnostic: Diagnostic = .{};
        try std.testing.expectError(error.Failed, disk_geometry.validateDocument(
            document,
            .{ .architecture = "x86_64", .flavor = "core" },
            &diagnostic,
        ));
    }
}

test "a report for the other architecture or flavor is refused" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const document = try documentFor(arena.allocator(), .x86_64);
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.Failed, disk_geometry.validateDocument(
        document,
        .{ .architecture = "aarch64", .flavor = "core" },
        &diagnostic,
    ));
    try std.testing.expectError(error.Failed, disk_geometry.validateDocument(
        document,
        .{ .architecture = "x86_64", .flavor = "full" },
        &diagnostic,
    ));
}

test "a report that claims to inherit the substrate's geometry is refused" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const document = try documentFor(arena.allocator(), .x86_64);
    var substrate = document.object.get("substrate").?.object;
    try substrate.put(arena.allocator(), "inherits_source_geometry", .{ .bool = true });
    document.object.getPtr("substrate").?.* = .{ .object = substrate };
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.Failed, disk_geometry.validateDocument(
        document,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));
}

test "the first-boot bound is enforced in both directions on both architectures" {
    for ([_]disk_geometry.Architecture{ .x86_64, .aarch64 }) |architecture| {
        const bound = disk_geometry.firstBootGrowth(architecture);
        try disk_geometry.assertWithinFirstBootGrowthBound(architecture, 0, 0);
        try disk_geometry.assertWithinFirstBootGrowthBound(
            architecture,
            bound.bytes,
            bound.inodes,
        );
        try std.testing.expectError(
            error.FirstBootGrowthExceedsGeometryBound,
            disk_geometry.assertWithinFirstBootGrowthBound(
                architecture,
                bound.bytes + 1,
                bound.inodes,
            ),
        );
        try std.testing.expectError(
            error.FirstBootGrowthExceedsGeometryBound,
            disk_geometry.assertWithinFirstBootGrowthBound(
                architecture,
                bound.bytes,
                @as(u64, bound.inodes) + 1,
            ),
        );
        // The reserve the plan actually leaves is several times the bound, so
        // a guest at the bound still has room afterwards.
        const plan = try planFor(architecture);
        try std.testing.expect(plan.requirements.root_free_bytes > bound.bytes);
    }
}
