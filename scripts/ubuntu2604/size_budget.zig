//! Hard minimality budgets for the Ubuntu 26.04 images (issue #677 step 6).
//!
//! Steps 1 through 5 made the appliance small and made it measurable. Nothing
//! so far stops it growing back. This module is the stop: a reviewed table of
//! per-architecture bounds, evaluated against the measured size inventory, and
//! published as a document that the provenance validator, the workflows, and
//! the release gate all re-derive rather than trust.
//!
//! Four properties are deliberate.
//!
//! **Every bound follows from a measurement.** A limit is never a round number
//! somebody liked. It is a `baseline` -- an observation from a real build of
//! this tree -- plus a named `Allowance` that says what drift is legitimate,
//! and the limit is *computed* from the two. Raising a bound therefore means
//! editing the recorded measurement or the stated allowance in reviewed source,
//! where the diff shows exactly what was widened and by how much.
//!
//! **Nothing widens itself.** `reviewed_budget_sha256` pins the digest of the
//! whole table. A change to any baseline, allowance, or metric moves the digest
//! and fails the test that pins it until a reviewer updates the pin in the same
//! change. There is no refresh mode, no `--update-baseline`, and no
//! success-shaped fallback: a document that cannot be evaluated is a failure,
//! not a pass.
//!
//! **Bounds are per architecture, and absence is explicit.** x86_64 core is
//! budgeted from a real x86_64 core build. AArch64 core has no production
//! measurement of the minimized closure yet, so it has no budget, and inventing
//! one from x86_64's numbers would be a fabrication: its kernel, module tree,
//! and UKI differ. Instead it evaluates as `candidate_baseline` -- the build
//! still records every metric, in the same document, for review -- and the
//! release gate refuses to publish a candidate whose budget was never reviewed.
//! Publication is blocked until somebody reads the recorded numbers and writes
//! them into this table.
//!
//! **Bounds are phase aware.** The size inventory records `root_build`,
//! `image_build`, `publication`, and `first_boot` as separate phases because
//! they become knowable at different times. A budget metric names the phase it
//! needs, a metric whose phase is absent is *not evaluated* rather than
//! evaluated against zero, and the document publishes which phases it saw. A
//! caller that requires a phase says so, and gets a refusal if it is missing.

const std = @import("std");

const contract = @import("../release/contract.zig");
const json_document = @import("../release/json_document.zig");
const runtime_contract = @import("ubuntu2604_runtime_contract");
const size_inventory = @import("size_inventory.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Diagnostic = contract.Diagnostic;
pub const Error = error{ Failed, OutOfMemory };

pub fn fail(
    diagnostic: *Diagnostic,
    comptime fmt: []const u8,
    args: anytype,
) Error {
    diagnostic.set(fmt, args);
    return error.Failed;
}

pub const schema_version: i64 = 1;
pub const document_type = "miz-ubuntu2604-size-budget";
pub const release_id = "26.04";
pub const document_max_bytes: u64 = 4 * 1024 * 1024;

/// Bumped whenever the reviewed table changes meaning. The digest below is what
/// actually binds the table; the version is what a reader cites.
pub const budget_version: i64 = 1;

pub const Architecture = size_inventory.Architecture;
pub const Flavor = size_inventory.Flavor;
pub const Phase = size_inventory.Phase;

/// Whether a candidate of this architecture and flavor may be published.
pub const Status = enum {
    /// A reviewed budget exists and every metric was checked against it.
    enforced,
    /// No reviewed budget exists for this architecture yet. The metrics are
    /// recorded for review and the release gate refuses to publish.
    candidate_baseline,

    pub fn key(self: Status) []const u8 {
        return @tagName(self);
    }

    pub fn parse(text: []const u8) ?Status {
        inline for (@typeInfo(Status).@"enum".fields) |field| {
            if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }
};

pub const Direction = enum {
    at_most,
    at_least,

    pub fn key(self: Direction) []const u8 {
        return @tagName(self);
    }

    pub fn parse(text: []const u8) ?Direction {
        inline for (@typeInfo(Direction).@"enum".fields) |field| {
            if (std.mem.eql(u8, text, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }
};

/// How far an observation may drift from the recorded measurement, and why.
///
/// The allowance is the reviewable part. "Five percent" is not a preference: a
/// closure pinned to an immutable snapshot only moves when a security update
/// republishes one of its packages, and the largest such move this appliance
/// has to absorb without a review is a kernel point release. Anything larger is
/// a closure change, which is exactly what this gate exists to make visible.
pub const Allowance = union(enum) {
    /// The bound is the measurement itself. Used where any drift at all is a
    /// finding: forbidden content, unowned remainder, firmware nobody ships,
    /// and the reserves the disk plan promised to deliver.
    exact,
    /// The measurement plus a percentage, rounded up to a whole 4 KiB block so
    /// the bound is a filesystem quantity rather than a fraction.
    security_update_percent: u8,
    /// The measurement plus a fixed number of the metric's own units.
    plus: u64,

    fn apply(self: Allowance, baseline: u64) u64 {
        return switch (self) {
            .exact => baseline,
            .security_update_percent => |percent| blk: {
                const raised = baseline + (baseline / 100) * percent +
                    ((baseline % 100) * percent) / 100;
                break :blk std.mem.alignForward(u64, raised, 4096);
            },
            .plus => |amount| baseline + amount,
        };
    }

    fn label(self: Allowance, buffer: []u8) []const u8 {
        return switch (self) {
            .exact => "exact",
            .security_update_percent => |percent| std.fmt.bufPrint(
                buffer,
                "security_update_percent:{d}",
                .{percent},
            ) catch "security_update_percent:?",
            .plus => |amount| std.fmt.bufPrint(buffer, "plus:{d}", .{amount}) catch
                "plus:?",
        };
    }
};

/// One measurable quantity of a published image.
///
/// Every member names something the size inventory already records, so a budget
/// can never ask a question the measurement cannot answer. `content_class` is
/// parameterized because the content policy owns the class list, and a budget
/// that hard-coded the classes would drift from it.
pub const Measure = union(enum) {
    package_count,
    installed_bytes,
    allocated_bytes,
    file_count,
    unexpected_unowned_files,
    absent_content_files,
    content_class_bytes: []const u8,
    kernel_bytes,
    initramfs_bytes,
    modules_bytes,
    firmware_bytes,
    virtual_size,
    uki_bytes,
    esp_used_bytes,
    esp_partition_bytes,
    root_total_blocks,
    root_used_blocks,
    root_free_blocks,
    root_used_inodes,
    root_free_inodes,
    compressed_artifact_bytes,
    qcow2_allocated_bytes,
    first_boot_growth_blocks,
    first_boot_growth_inodes,

    /// The stable identifier the document publishes and failures quote.
    pub fn id(self: Measure, buffer: []u8) []const u8 {
        return switch (self) {
            .content_class_bytes => |class| std.fmt.bufPrint(
                buffer,
                "content.{s}.installed_bytes",
                .{class},
            ) catch "content.<overlong>.installed_bytes",
            inline else => |_, tag| @tagName(tag),
        };
    }

    /// The phase whose section carries the observation. A metric is skipped,
    /// not failed, when the document does not carry its phase: a phase that has
    /// not happened is absent rather than zero, and treating it as zero would
    /// turn "not measured yet" into "measured as nothing".
    pub fn phase(self: Measure) Phase {
        return switch (self) {
            .package_count,
            .installed_bytes,
            .allocated_bytes,
            .file_count,
            .unexpected_unowned_files,
            .absent_content_files,
            .content_class_bytes,
            .kernel_bytes,
            .initramfs_bytes,
            .modules_bytes,
            .firmware_bytes,
            => .root_build,
            .virtual_size,
            .uki_bytes,
            .esp_used_bytes,
            .esp_partition_bytes,
            .root_total_blocks,
            .root_used_blocks,
            .root_free_blocks,
            .root_used_inodes,
            .root_free_inodes,
            => .image_build,
            .compressed_artifact_bytes,
            .qcow2_allocated_bytes,
            => .publication,
            .first_boot_growth_blocks,
            .first_boot_growth_inodes,
            => .first_boot,
        };
    }

    /// What the number counts, so a failure reads as a quantity rather than a
    /// bare integer.
    pub fn unit(self: Measure) []const u8 {
        return switch (self) {
            .package_count => "packages",
            .file_count,
            .unexpected_unowned_files,
            .absent_content_files,
            => "files",
            .root_total_blocks,
            .root_used_blocks,
            .root_free_blocks,
            .first_boot_growth_blocks,
            => "blocks",
            .root_used_inodes,
            .root_free_inodes,
            .first_boot_growth_inodes,
            => "inodes",
            else => "bytes",
        };
    }
};

/// One reviewed bound.
pub const Limit = struct {
    measure: Measure,
    direction: Direction,
    /// The observation from a real build of this tree that the bound is
    /// derived from. Changing it is the reviewable act.
    baseline: u64,
    allowance: Allowance,
    /// Why this allowance is the right one for this metric.
    basis: []const u8,

    pub fn value(self: Limit) u64 {
        return switch (self.direction) {
            // A maximum may be exceeded by the allowance; a minimum is a floor
            // the image promised to deliver, so widening it downwards would be
            // the opposite of a margin.
            .at_most => self.allowance.apply(self.baseline),
            .at_least => self.baseline,
        };
    }

    pub fn satisfied(self: Limit, observed: u64) bool {
        return switch (self.direction) {
            .at_most => observed <= self.value(),
            .at_least => observed >= self.value(),
        };
    }
};

/// The reviewed budget for one architecture and flavor.
pub const Budget = struct {
    architecture: Architecture,
    flavor: Flavor,
    limits: []const Limit,
};

/// The percentage a closure may drift on a same-snapshot security update.
///
/// The largest single move the pinned snapshot can hand this appliance without
/// a closure change is a kernel point release, which republishes the image, the
/// module tree, and therefore the initramfs. Five percent covers the moves
/// Canonical's `-azure` kernel has made inside a series while still failing a
/// package addition, which is the smallest closure change worth catching.
pub const security_update_percent: u8 = 5;

/// What a security update may add to the package count.
///
/// A republished package can gain one direct dependency, and a library
/// transition can split one package into two. Three would be a closure change.
pub const package_count_allowance: u64 = 2;

/// The measured x86_64 core budget.
///
/// Every baseline below is an observation of a real, unmodified x86_64 core
/// build of this tree against the pinned snapshot: 100 packages,
/// `linux-image-7.0.0-1010-azure`, a 583 MiB calculated disk, and a 281 MiB
/// published artifact. They are recorded as the exact integers that build
/// produced, not rounded, so the diff of a future change shows the real move.
const x86_64_core_limits = [_]Limit{
    // ---- root_build: the closure and what it puts on disk ----
    .{
        .measure = .package_count,
        .direction = .at_most,
        .baseline = 100,
        .allowance = .{ .plus = package_count_allowance },
        .basis = "measured closure of the reviewed package roots; a security " ++
            "update may add a direct dependency or split a library",
    },
    .{
        .measure = .installed_bytes,
        .direction = .at_most,
        .baseline = 305_796_307,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured root tree; absorbs a kernel point release without " ++
            "absorbing a package addition",
    },
    .{
        .measure = .allocated_bytes,
        .direction = .at_most,
        .baseline = 328_962_048,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured root allocation, which is what the ext4 minimum " ++
            "and therefore the disk plan follow from",
    },
    .{
        .measure = .file_count,
        .direction = .at_most,
        .baseline = 13_346,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured path count; the inode reserve is sized from it",
    },
    .{
        .measure = .unexpected_unowned_files,
        .direction = .at_most,
        .baseline = 0,
        .allowance = .exact,
        .basis = "#677 step 3: every path is package-owned or named by the " ++
            "typed injected-file allowlist, so the remainder is zero",
    },
    .{
        .measure = .absent_content_files,
        .direction = .at_most,
        .baseline = 0,
        .allowance = .exact,
        .basis = "#677 step 6: apt state and caches, cloud-init, " ++
            "WALinuxAgent, a systemd service manager, the initramfs " ++
            "generator, and kernel build trees are absent, not bounded",
    },
    .{
        .measure = .kernel_bytes,
        .direction = .at_most,
        .baseline = 17_403_904,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured signed kernel image; a point release moves it",
    },
    .{
        .measure = .initramfs_bytes,
        .direction = .at_most,
        .baseline = 40_538_112,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured staged initramfs; it follows the module tree",
    },
    .{
        .measure = .modules_bytes,
        .direction = .at_most,
        .baseline = 151_089_152,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured module tree, the single largest thing in the root",
    },
    .{
        .measure = .firmware_bytes,
        .direction = .at_most,
        .baseline = 0,
        .allowance = .exact,
        .basis = "the closure installs no firmware package; a byte here is a " ++
            "closure change and not a size drift",
    },
    // ---- root_build: the bounded content classes ----
    //
    // None of this is wanted. It arrives inside packages the runtime contract
    // requires, and #677 omits packages rather than deleting their files, so
    // the bound is what keeps it from growing unnoticed.
    .{
        .measure = .{ .content_class_bytes = "documentation" },
        .direction = .at_most,
        .baseline = 3_588_634,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured /usr/share/doc, kept because copyright files are a " ++
            "distribution obligation shipped in the same payload",
    },
    .{
        .measure = .{ .content_class_bytes = "manual-pages" },
        .direction = .at_most,
        .baseline = 3_890_957,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured /usr/share/man inside required packages",
    },
    .{
        .measure = .{ .content_class_bytes = "info-pages" },
        .direction = .at_most,
        .baseline = 575_134,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured /usr/share/info inside required packages",
    },
    .{
        .measure = .{ .content_class_bytes = "locale-data" },
        .direction = .at_most,
        .baseline = 6_550_535,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured message catalogues; the `locales` package itself " ++
            "is forbidden by the runtime contract",
    },
    .{
        .measure = .{ .content_class_bytes = "packaging-metadata" },
        .direction = .at_most,
        .baseline = 51_577,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured lintian, bug, menu, pixmap and apt.conf.d " ++
            "fragments inside required packages",
    },
    .{
        .measure = .{ .content_class_bytes = "inert-systemd-units" },
        .direction = .at_most,
        .baseline = 299_251,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured unit files and generators shipped by " ++
            "openssh-server, sudo and e2fsprogs; nothing starts them because " ++
            "the service manager is in the absent classes",
    },
    .{
        .measure = .{ .content_class_bytes = "build-tool-hooks" },
        .direction = .at_most,
        .baseline = 1_087,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured initramfs hook fragments shipped by kmod; the " ++
            "generator that would run them is absent",
    },
    .{
        .measure = .{ .content_class_bytes = "debconf-state" },
        .direction = .at_most,
        .baseline = 1_181_350,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured debconf database written during installation",
    },
    // ---- image_build: the disk the plan produced ----
    .{
        .measure = .virtual_size,
        .direction = .at_most,
        .baseline = 611_319_808,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "the calculated 583 MiB core disk; the geometry validator " ++
            "separately refuses the retired 3584 MiB inherited size",
    },
    .{
        .measure = .uki_bytes,
        .direction = .at_most,
        .baseline = 58_039_112,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured signed UKI; the ESP is sized from it, so its " ++
            "growth is the ESP's growth",
    },
    .{
        .measure = .esp_used_bytes,
        .direction = .at_most,
        .baseline = 58_040_832,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured ESP occupancy, which is one signed UKI plus FAT32 " ++
            "rounding",
    },
    .{
        .measure = .esp_partition_bytes,
        .direction = .at_most,
        .baseline = 118_489_088,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "the planned ESP, sized to hold two resident UKI copies so " ++
            "an update writes the new one before removing the booting one",
    },
    .{
        .measure = .root_total_blocks,
        .direction = .at_most,
        .baseline = 119_795,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "the planned 468 MiB root filesystem in 4 KiB blocks",
    },
    .{
        .measure = .root_used_blocks,
        .direction = .at_most,
        .baseline = 87_027,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured used blocks before first boot",
    },
    .{
        .measure = .root_free_blocks,
        .direction = .at_least,
        .baseline = 32_768,
        .allowance = .exact,
        .basis = "the 128 MiB reserve the disk plan promised: four times the " ++
            "declared 32 MiB first-boot growth, floored at 64 MiB",
    },
    .{
        .measure = .root_used_inodes,
        .direction = .at_most,
        .baseline = 13_368,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured used inodes before first boot",
    },
    .{
        .measure = .root_free_inodes,
        .direction = .at_least,
        .baseline = 4_096,
        .allowance = .exact,
        .basis = "the free-inode floor the disk plan requires, which first " ++
            "boot and root growth both draw from",
    },
    // ---- publication: what is actually shipped ----
    .{
        .measure = .compressed_artifact_bytes,
        .direction = .at_most,
        .baseline = 294_322_176,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "the measured published zstd QCOW2, which is the number the " ++
            "release is judged by",
    },
    .{
        .measure = .qcow2_allocated_bytes,
        .direction = .at_most,
        .baseline = 294_260_736,
        .allowance = .{ .security_update_percent = security_update_percent },
        .basis = "measured host allocation of the published artifact",
    },
    // ---- first_boot: the growth the disk plan reserved against ----
    .{
        .measure = .first_boot_growth_blocks,
        .direction = .at_most,
        .baseline = 8_192,
        .allowance = .exact,
        .basis = "the declared 32 MiB first-boot growth bound the root " ++
            "reserve is four times; exceeding it invalidates the plan rather " ++
            "than merely the size",
    },
    .{
        .measure = .first_boot_growth_inodes,
        .direction = .at_most,
        .baseline = 512,
        .allowance = .exact,
        .basis = "the declared first-boot inode growth bound from the same " ++
            "plan",
    },
};

const x86_64_core_budget: Budget = .{
    .architecture = .x86_64,
    .flavor = .core,
    .limits = &x86_64_core_limits,
};

/// The reviewed budget for an architecture and flavor, or `null` when none has
/// been reviewed.
///
/// `null` is a real answer, not a gap to be papered over. AArch64 core has no
/// production measurement of the minimized closure: its kernel, module tree,
/// and UKI are not x86_64's, so borrowing x86_64's numbers would state a
/// measurement that was never taken. Its builds record a candidate baseline
/// instead, and the release gate refuses them until this function returns a
/// table somebody reviewed.
///
/// `full` has no budget either, and for a different reason: it is Canonical's
/// server root, which #677 measures rather than minimizes.
pub fn budgetFor(flavor: Flavor, architecture: Architecture) ?Budget {
    if (flavor == .core and architecture == .x86_64) return x86_64_core_budget;
    return null;
}

pub fn statusFor(flavor: Flavor, architecture: Architecture) Status {
    return if (budgetFor(flavor, architecture) == null)
        .candidate_baseline
    else
        .enforced;
}

/// `sha256` over every reviewed budget, rendered one field-separated line per
/// limit.
///
/// Covers the architecture and flavor as well as the numbers, so removing a
/// budget entirely moves the digest exactly as widening one does.
pub fn budgetDigest(allocator: Allocator) Error![64]u8 {
    var hash: std.crypto.hash.sha2.Sha256 = .init(.{});
    for (std.enums.values(Flavor)) |flavor| {
        for (std.enums.values(Architecture)) |architecture| {
            const budget = budgetFor(flavor, architecture) orelse continue;
            for (budget.limits) |limit| {
                var id_buffer: [128]u8 = undefined;
                var allowance_buffer: [64]u8 = undefined;
                const line = try std.fmt.allocPrint(
                    allocator,
                    "{s}\t{s}\t{s}\t{s}\t{d}\t{s}\t{d}\t{s}\n",
                    .{
                        @tagName(flavor),
                        @tagName(architecture),
                        limit.measure.id(&id_buffer),
                        limit.direction.key(),
                        limit.baseline,
                        limit.allowance.label(&allowance_buffer),
                        limit.value(),
                        limit.basis,
                    },
                );
                defer allocator.free(line);
                hash.update(line);
            }
        }
    }
    var raw: [32]u8 = undefined;
    hash.final(&raw);
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&raw}) catch unreachable;
    return hex;
}

/// The digest of the reviewed budget table, pinned in source.
///
/// This is the mechanism that makes a budget change a contract change. Any edit
/// to a baseline, an allowance, a direction, a basis, or the set of budgeted
/// architectures moves `budgetDigest`, and the test that compares the two fails
/// until a reviewer updates this constant in the same change. A snapshot
/// refresh that quietly re-recorded whatever the last build measured is
/// therefore impossible: there is nowhere for it to write.
pub const reviewed_budget_sha256 =
    "649e9c4455f790438b5dfa221917a4329326d62b1baf4ddd17fd9b2df019a8d4";

// ---------------------------------------------------------------------------
// Evaluation.
// ---------------------------------------------------------------------------

/// One metric, as evaluated.
pub const Observation = struct {
    measure: Measure,
    direction: Direction,
    baseline: ?u64,
    limit: ?u64,
    observed: u64,
    ok: bool,

    pub fn phase(self: Observation) Phase {
        return self.measure.phase();
    }
};

pub const Evaluation = struct {
    arena: std.heap.ArenaAllocator,
    architecture: Architecture,
    flavor: Flavor,
    status: Status,
    phases: [size_inventory.phase_order.len]bool = @splat(false),
    observations: []Observation = &.{},
    failures: usize = 0,
    /// Carried through from the inventory so the gate document binds the exact
    /// measurement it judged rather than merely its numbers.
    closure_sha256: []const u8 = "",
    unowned_policy_sha256: []const u8 = "",
    content_policy_sha256: []const u8 = "",
    inventory_sha256: []const u8 = "",

    pub fn deinit(self: *Evaluation) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn has(self: *const Evaluation, phase: Phase) bool {
        return self.phases[@intFromEnum(phase)];
    }
};

fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const inner = value orelse return null;
    return switch (inner) {
        .object => |map| map,
        else => null,
    };
}

fn arrayOf(value: ?std.json.Value) ?[]const std.json.Value {
    const inner = value orelse return null;
    return switch (inner) {
        .array => |list| list.items,
        else => null,
    };
}

fn stringOf(value: ?std.json.Value) ?[]const u8 {
    const inner = value orelse return null;
    return switch (inner) {
        .string => |text| text,
        else => null,
    };
}

fn countOf(value: ?std.json.Value) ?u64 {
    const inner = value orelse return null;
    return switch (inner) {
        .integer => |number| if (number < 0) null else @intCast(number),
        else => null,
    };
}

fn section(document: std.json.ObjectMap, phase: Phase) ?std.json.ObjectMap {
    return objectOf(document.get(phase.key()));
}

/// Reads one measure out of a validated size-inventory document.
///
/// Returns `null` only when the phase the measure needs is absent. Every other
/// missing or malformed field is a refusal: the document was already validated
/// structurally, so a field that is not there now means the two tools disagree
/// about the schema, and guessing would be worse than stopping.
fn observe(
    document: std.json.ObjectMap,
    measure: Measure,
    diagnostic: *Diagnostic,
) Error!?u64 {
    const phase = measure.phase();
    const object = section(document, phase) orelse return null;
    const missing = "size budget cannot read {s} from the {s} phase";
    var id_buffer: [128]u8 = undefined;
    const identifier = measure.id(&id_buffer);
    switch (measure) {
        .package_count,
        .installed_bytes,
        .allocated_bytes,
        .file_count,
        => return countOf(object.get(identifier)) orelse fail(
            diagnostic,
            missing,
            .{ identifier, phase.key() },
        ),
        .unexpected_unowned_files => {
            const unowned = objectOf(object.get("unowned")) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
            const unexpected = objectOf(unowned.get("unexpected")) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
            return countOf(unexpected.get("file_count")) orelse fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
        },
        .absent_content_files => {
            const content = objectOf(object.get("content")) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
            const absent = objectOf(content.get("absent")) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
            return countOf(absent.get("file_count")) orelse fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
        },
        .content_class_bytes => |class| {
            const content = objectOf(object.get("content")) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
            const classes = arrayOf(content.get("classes")) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
            for (classes) |entry| {
                const item = objectOf(entry) orelse continue;
                if (!std.mem.eql(u8, stringOf(item.get("id")) orelse "", class)) continue;
                return countOf(item.get("installed_bytes")) orelse fail(
                    diagnostic,
                    missing,
                    .{ identifier, phase.key() },
                );
            }
            // A budget naming a class the policy does not declare is a table
            // that has drifted from the policy it budgets, not a passing build.
            return fail(
                diagnostic,
                "size budget names content class {s}, which the reviewed " ++
                    "content policy does not declare",
                .{class},
            );
        },
        .kernel_bytes, .initramfs_bytes, .modules_bytes, .firmware_bytes => {
            const boot = objectOf(object.get("boot")) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
            return countOf(boot.get(identifier)) orelse fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
        },
        .virtual_size,
        .uki_bytes,
        .esp_used_bytes,
        .esp_partition_bytes,
        .root_total_blocks,
        .root_used_blocks,
        .root_free_blocks,
        .root_used_inodes,
        .root_free_inodes,
        .compressed_artifact_bytes,
        .qcow2_allocated_bytes,
        => return countOf(object.get(identifier)) orelse fail(
            diagnostic,
            missing,
            .{ identifier, phase.key() },
        ),
        .first_boot_growth_blocks, .first_boot_growth_inodes => {
            // Growth is a difference, so it needs the phase before it as well.
            // A first-boot document without the image build it grew from
            // cannot state growth at all.
            const before = section(document, .image_build) orelse return fail(
                diagnostic,
                "size budget cannot measure first-boot growth without the " ++
                    "image_build phase it grew from",
                .{},
            );
            const field = if (measure == .first_boot_growth_blocks)
                "root_used_blocks"
            else
                "root_used_inodes";
            const start = countOf(before.get(field)) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, "image_build" },
            );
            const end = countOf(object.get(field)) orelse return fail(
                diagnostic,
                missing,
                .{ identifier, phase.key() },
            );
            // A first boot that freed space is not growth; it is zero growth,
            // and reporting a negative number as an unsigned one would be a
            // spectacular pass.
            return if (end > start) end - start else 0;
        },
    }
}

pub const EvaluateOptions = struct {
    architecture: []const u8,
    flavor: []const u8,
    /// Phases the caller insists the inventory carries. The evaluation refuses
    /// a document missing one rather than skipping its metrics.
    required_phases: []const Phase = &.{ .root_build, .image_build, .publication },
};

/// Evaluates a size-inventory document against the reviewed budget.
///
/// The document is re-validated here rather than trusted: `validateDocument`
/// re-derives the unowned and content policy digests from this tool's own
/// tables, so a measurement taken against a widened policy cannot be judged
/// against a budget at all.
pub fn evaluate(
    gpa: Allocator,
    inventory: std.json.Value,
    options: EvaluateOptions,
    diagnostic: *Diagnostic,
) Error!Evaluation {
    const architecture = std.meta.stringToEnum(Architecture, options.architecture) orelse
        return fail(
            diagnostic,
            "size budget architecture {s} is not one this release publishes",
            .{options.architecture},
        );
    const flavor = std.meta.stringToEnum(Flavor, options.flavor) orelse return fail(
        diagnostic,
        "size budget flavor {s} is not one this release publishes",
        .{options.flavor},
    );

    // The arena lives in the returned value, and every allocation below is
    // taken from *that* copy: an allocator handle borrowed from a local arena
    // would keep writing into a state the returned struct no longer carries.
    var evaluation: Evaluation = .{
        .arena = .init(gpa),
        .architecture = architecture,
        .flavor = flavor,
        .status = statusFor(flavor, architecture),
    };
    errdefer evaluation.arena.deinit();
    const allocator = evaluation.arena.allocator();

    const summary = try inventoryFailure(size_inventory.validateDocument(
        allocator,
        inventory,
        .{
            .architecture = options.architecture,
            .flavor = options.flavor,
            .required_phases = options.required_phases,
        },
        diagnostic,
    ));

    const document = objectOf(inventory) orelse return fail(
        diagnostic,
        "size budget input is not a size-inventory document",
        .{},
    );

    // The exact closure is a gate of its own, and it is cheap to state twice:
    // the debz lock proves what was installed, and this proves the measured
    // root does not contain a package the runtime contract forbids.
    try requireNoForbiddenPackages(document, diagnostic);

    evaluation.closure_sha256 = try allocator.dupe(u8, summary.closure_sha256);
    evaluation.unowned_policy_sha256 =
        try allocator.dupe(u8, summary.unowned_policy_sha256);
    evaluation.content_policy_sha256 =
        try allocator.dupe(u8, summary.content_policy_sha256);
    for (size_inventory.phase_order, 0..) |phase, index| {
        evaluation.phases[index] = summary.has(phase);
    }
    const digest = try canonicalDigest(allocator, inventory, diagnostic);
    evaluation.inventory_sha256 = digest;

    const budget = budgetFor(flavor, architecture);
    const limits: []const Limit = if (budget) |reviewed|
        reviewed.limits
    else
        &baseline_capture_measures;

    var observations: std.ArrayList(Observation) = .empty;
    errdefer observations.deinit(allocator);
    for (limits) |limit| {
        const observed = (try observe(document, limit.measure, diagnostic)) orelse continue;
        const enforced = budget != null;
        const ok = if (enforced) limit.satisfied(observed) else true;
        if (!ok) evaluation.failures += 1;
        try observations.append(allocator, .{
            .measure = limit.measure,
            .direction = limit.direction,
            .baseline = if (enforced) limit.baseline else null,
            .limit = if (enforced) limit.value() else null,
            .observed = observed,
            .ok = ok,
        });
    }
    evaluation.observations = try observations.toOwnedSlice(allocator);
    return evaluation;
}

/// The metrics a build records when no reviewed budget exists.
///
/// Exactly the measures the x86_64 budget bounds, so the recorded baseline is
/// directly comparable with a reviewed one and a reviewer can transcribe it
/// without deciding which numbers matter. The `baseline` and `allowance` fields
/// are unused in this mode and are published as `null` rather than as values
/// nobody chose.
const baseline_capture_measures = blk: {
    var list: [x86_64_core_limits.len]Limit = undefined;
    for (x86_64_core_limits, 0..) |limit, index| {
        list[index] = .{
            .measure = limit.measure,
            .direction = limit.direction,
            .baseline = 0,
            .allowance = .exact,
            .basis = "",
        };
    }
    break :blk list;
};

fn inventoryFailure(
    result: size_inventory.Error!size_inventory.Summary,
) Error!size_inventory.Summary {
    return result catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Failed => error.Failed,
    };
}

fn canonicalDigest(
    allocator: Allocator,
    value: std.json.Value,
    diagnostic: *Diagnostic,
) Error![]const u8 {
    const bytes = json_document.canonicalAlloc(allocator, value, .compact) catch
        return fail(diagnostic, "size budget cannot canonicalize its input", .{});
    defer allocator.free(bytes);
    var raw: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &raw, .{});
    return std.fmt.allocPrint(allocator, "{x}", .{&raw});
}

/// Refuses a measured root that contains a package the runtime contract
/// forbids, naming the package rather than the byte total it contributed.
fn requireNoForbiddenPackages(
    document: std.json.ObjectMap,
    diagnostic: *Diagnostic,
) Error!void {
    const root_build = section(document, .root_build) orelse return;
    const packages = arrayOf(root_build.get("packages")) orelse return;
    for (packages) |entry| {
        const item = objectOf(entry) orelse continue;
        const name = stringOf(item.get("name")) orelse continue;
        if (!runtime_contract.isForbiddenPackage(name)) continue;
        return fail(
            diagnostic,
            "forbidden package {s} is installed in the measured root, " ++
                "contributing {d} byte(s)",
            .{ name, countOf(item.get("installed_bytes")) orelse 0 },
        );
    }
}

// ---------------------------------------------------------------------------
// Failure reporting.
// ---------------------------------------------------------------------------

/// Writes the attributable failure lines for an evaluation.
///
/// Attribution is the point. A gate that says "the image got bigger" is a gate
/// nobody can act on, so each line names the metric, the phase it came from,
/// the observation, the bound it broke, the recorded measurement the bound was
/// derived from, and the exact delta.
pub fn writeFailures(
    evaluation: *const Evaluation,
    out: *std.Io.Writer,
) Error!void {
    for (evaluation.observations) |observation| {
        if (observation.ok) continue;
        var id_buffer: [128]u8 = undefined;
        const limit = observation.limit orelse continue;
        const baseline = observation.baseline orelse continue;
        const over = switch (observation.direction) {
            .at_most => observation.observed - limit,
            .at_least => limit - observation.observed,
        };
        out.print(
            "{s} {s} {s} ({s}): observed {d} {s} {s} the limit of {d} by {d} " ++
                "(measured baseline {d})\n",
            .{
                @tagName(evaluation.architecture),
                @tagName(evaluation.flavor),
                observation.measure.id(&id_buffer),
                observation.phase().key(),
                observation.observed,
                observation.measure.unit(),
                switch (observation.direction) {
                    .at_most => "exceeds",
                    .at_least => "falls below",
                },
                limit,
                over,
                baseline,
            },
        ) catch return error.Failed;
    }
}

/// Appends the per-package attribution for a failing evaluation.
///
/// The metric lines say a budget broke; this says which packages moved. It
/// reuses the size-inventory comparison from #678 rather than growing a second
/// differ, so the deltas here are the same deltas the benchmark reports.
pub fn writePackageAttribution(
    allocator: Allocator,
    baseline: std.json.Value,
    candidate: std.json.Value,
    out: *std.Io.Writer,
    diagnostic: *Diagnostic,
) Error!void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    var scratch: std.heap.ArenaAllocator = .init(allocator);
    defer scratch.deinit();
    const comparison = size_inventory.compareAlloc(
        arena.allocator(),
        scratch.allocator(),
        baseline,
        candidate,
        diagnostic,
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Failed => error.Failed,
    };
    const object = objectOf(comparison) orelse return;
    const root_build = objectOf(object.get("root_build")) orelse return;
    const packages = objectOf(root_build.get("packages")) orelse return;
    for ([_][]const u8{ "added", "removed", "changed" }) |bucket| {
        const entries = arrayOf(packages.get(bucket)) orelse continue;
        for (entries) |entry| {
            const item = objectOf(entry) orelse continue;
            const name = stringOf(item.get("name")) orelse continue;
            const bytes = item.get("installed_bytes") orelse
                item.get("installed_bytes_delta") orelse continue;
            out.print("  {s} {s}: installed_bytes {f}\n", .{
                bucket,
                name,
                std.json.fmt(bytes, .{}),
            }) catch return error.Failed;
        }
    }
}

// ---------------------------------------------------------------------------
// The published gate document.
// ---------------------------------------------------------------------------

const document_fields = [_][]const u8{
    "architecture",
    "budget_sha256",
    "budget_version",
    "closure_sha256",
    "content_policy_sha256",
    "flavor",
    "inventory_sha256",
    "metrics",
    "phases_evaluated",
    "release",
    "result",
    "schema",
    "status",
    "type",
    "unowned_policy_sha256",
};

const metric_fields = [_][]const u8{
    "baseline",
    "direction",
    "id",
    "limit",
    "observed",
    "ok",
    "phase",
    "unit",
};

/// The verdict, spelled so it cannot be confused with a pass.
pub const Result = enum {
    /// Every reviewed bound held.
    pass,
    /// No reviewed budget exists; the metrics are recorded for review and the
    /// candidate may not be published.
    baseline_recorded,
    /// At least one reviewed bound broke.
    fail,

    pub fn key(self: Result) []const u8 {
        return switch (self) {
            .pass => "pass",
            .baseline_recorded => "baseline-recorded",
            .fail => "fail",
        };
    }

    pub fn parse(text: []const u8) ?Result {
        inline for (@typeInfo(Result).@"enum".fields) |field| {
            const value: Result = @enumFromInt(field.value);
            if (std.mem.eql(u8, text, value.key())) return value;
        }
        return null;
    }
};

pub fn resultOf(evaluation: *const Evaluation) Result {
    if (evaluation.status == .candidate_baseline) return .baseline_recorded;
    return if (evaluation.failures == 0) .pass else .fail;
}

/// Renders an evaluation as the document a build publishes.
pub fn documentValue(
    arena: Allocator,
    evaluation: *const Evaluation,
) Error!std.json.Value {
    var map: std.json.ObjectMap = .empty;
    try map.put(arena, "schema", .{ .integer = schema_version });
    try map.put(arena, "type", .{ .string = document_type });
    try map.put(arena, "release", .{ .string = release_id });
    try map.put(arena, "architecture", .{
        .string = @tagName(evaluation.architecture),
    });
    try map.put(arena, "flavor", .{ .string = @tagName(evaluation.flavor) });
    try map.put(arena, "status", .{ .string = evaluation.status.key() });
    try map.put(arena, "result", .{ .string = resultOf(evaluation).key() });
    try map.put(arena, "budget_version", .{ .integer = budget_version });
    const digest = try budgetDigest(arena);
    try map.put(arena, "budget_sha256", .{ .string = try arena.dupe(u8, &digest) });
    try map.put(arena, "inventory_sha256", .{
        .string = try arena.dupe(u8, evaluation.inventory_sha256),
    });
    try map.put(arena, "closure_sha256", .{
        .string = try arena.dupe(u8, evaluation.closure_sha256),
    });
    try map.put(arena, "unowned_policy_sha256", .{
        .string = try arena.dupe(u8, evaluation.unowned_policy_sha256),
    });
    try map.put(arena, "content_policy_sha256", .{
        .string = try arena.dupe(u8, evaluation.content_policy_sha256),
    });

    var phases: std.json.Array = .init(arena);
    for (size_inventory.phase_order) |phase| {
        if (!evaluation.has(phase)) continue;
        try phases.append(.{ .string = phase.key() });
    }
    try map.put(arena, "phases_evaluated", .{ .array = phases });

    var metrics: std.json.Array = .init(arena);
    for (evaluation.observations) |observation| {
        var id_buffer: [128]u8 = undefined;
        var item: std.json.ObjectMap = .empty;
        try item.put(arena, "id", .{
            .string = try arena.dupe(u8, observation.measure.id(&id_buffer)),
        });
        try item.put(arena, "phase", .{ .string = observation.phase().key() });
        try item.put(arena, "direction", .{ .string = observation.direction.key() });
        try item.put(arena, "unit", .{ .string = observation.measure.unit() });
        try item.put(arena, "observed", .{ .integer = castCount(observation.observed) });
        // A recorded baseline states no bound, and states it as `null` rather
        // than as a zero somebody could mistake for one.
        try item.put(arena, "baseline", if (observation.baseline) |value|
            .{ .integer = castCount(value) }
        else
            .null);
        try item.put(arena, "limit", if (observation.limit) |value|
            .{ .integer = castCount(value) }
        else
            .null);
        try item.put(arena, "ok", .{ .bool = observation.ok });
        try metrics.append(.{ .object = item });
    }
    try map.put(arena, "metrics", .{ .array = metrics });
    return .{ .object = map };
}

fn castCount(number: u64) i64 {
    return @intCast(@min(number, std.math.maxInt(i64)));
}

pub const ValidateOptions = struct {
    architecture: ?[]const u8 = null,
    flavor: ?[]const u8 = null,
    /// Digest of the size-inventory document this gate is presented beside, so
    /// a passing budget document from another build cannot stand in for one.
    inventory_sha256: ?[]const u8 = null,
    /// Whether a recorded candidate baseline is acceptable. Publication says
    /// no; a validation run that exists to produce the baseline says yes.
    require_enforced: bool = false,
};

pub const Summary = struct {
    architecture: []const u8,
    flavor: []const u8,
    status: Status,
    result: Result,
    metric_count: usize,
    failures: usize,
    budget_sha256: []const u8,
    inventory_sha256: []const u8,
};

fn hasExactFields(map: std.json.ObjectMap, expected: []const []const u8) bool {
    if (map.count() != expected.len) return false;
    for (expected) |field| {
        if (!map.contains(field)) return false;
    }
    return true;
}

/// Full re-derivation of a published gate document.
///
/// Nothing in the document is taken on its own word. The budget digest is
/// recomputed from this tool's compiled-in table, every metric is looked up in
/// that table and its limit recomputed from the recorded baseline and
/// allowance, the verdict is recomputed from the metrics, and the status is
/// recomputed from whether a reviewed budget exists at all. A document that
/// claims `pass` while carrying a broken metric, or claims `enforced` for an
/// architecture with no reviewed budget, is refused.
pub fn validateDocument(
    allocator: Allocator,
    value: std.json.Value,
    options: ValidateOptions,
    diagnostic: *Diagnostic,
) Error!Summary {
    const object = objectOf(value) orelse return fail(
        diagnostic,
        "size budget is not a JSON object",
        .{},
    );
    if (!hasExactFields(object, &document_fields)) return fail(
        diagnostic,
        "size budget has unexpected fields",
        .{},
    );
    const schema = switch (object.get("schema").?) {
        .integer => |number| number,
        else => -1,
    };
    if (schema != schema_version or
        !std.mem.eql(u8, stringOf(object.get("type")) orelse "", document_type) or
        !std.mem.eql(u8, stringOf(object.get("release")) orelse "", release_id))
    {
        return fail(diagnostic, "size budget identity is invalid", .{});
    }
    const budget_claim = switch (object.get("budget_version").?) {
        .integer => |number| number,
        else => -1,
    };
    if (budget_claim != budget_version) return fail(
        diagnostic,
        "size budget document states budget version {d} where this tool " ++
            "reviews version {d}",
        .{ budget_claim, budget_version },
    );

    const architecture_text = stringOf(object.get("architecture")) orelse return fail(
        diagnostic,
        "size budget architecture is invalid",
        .{},
    );
    const flavor_text = stringOf(object.get("flavor")) orelse return fail(
        diagnostic,
        "size budget flavor is invalid",
        .{},
    );
    const architecture = std.meta.stringToEnum(Architecture, architecture_text) orelse
        return fail(
            diagnostic,
            "size budget architecture {s} is not one this release publishes",
            .{architecture_text},
        );
    const flavor = std.meta.stringToEnum(Flavor, flavor_text) orelse return fail(
        diagnostic,
        "size budget flavor {s} is not one this release publishes",
        .{flavor_text},
    );
    if (options.architecture) |expected| {
        if (!std.mem.eql(u8, architecture_text, expected)) return fail(
            diagnostic,
            "size budget is for {s}, not {s}",
            .{ architecture_text, expected },
        );
    }
    if (options.flavor) |expected| {
        if (!std.mem.eql(u8, flavor_text, expected)) return fail(
            diagnostic,
            "size budget is for the {s} flavor, not {s}",
            .{ flavor_text, expected },
        );
    }

    const declared_digest = stringOf(object.get("budget_sha256")) orelse return fail(
        diagnostic,
        "size budget digest is invalid",
        .{},
    );
    const expected_digest = try budgetDigest(allocator);
    if (!std.mem.eql(u8, declared_digest, &expected_digest)) return fail(
        diagnostic,
        "size budget digest {s} does not match the reviewed budget {s}",
        .{ declared_digest, expected_digest },
    );

    for ([_][]const u8{
        "closure_sha256",
        "content_policy_sha256",
        "inventory_sha256",
        "unowned_policy_sha256",
    }) |field| {
        const text = stringOf(object.get(field)) orelse "";
        if (text.len != 64) return fail(
            diagnostic,
            "size budget {s} is not a SHA-256 digest",
            .{field},
        );
        for (text) |character| {
            if (!std.ascii.isHex(character) or std.ascii.isUpper(character)) return fail(
                diagnostic,
                "size budget {s} is not a SHA-256 digest",
                .{field},
            );
        }
    }
    const inventory_digest = stringOf(object.get("inventory_sha256")).?;
    if (options.inventory_sha256) |expected| {
        if (!std.mem.eql(u8, inventory_digest, expected)) return fail(
            diagnostic,
            "size budget judged inventory {s}, not the {s} presented with it",
            .{ inventory_digest, expected },
        );
    }

    const declared_status = Status.parse(stringOf(object.get("status")) orelse "") orelse
        return fail(diagnostic, "size budget status is invalid", .{});
    const expected_status = statusFor(flavor, architecture);
    if (declared_status != expected_status) return fail(
        diagnostic,
        "size budget claims {s} for {s} {s}, which this tool reviews as {s}",
        .{
            declared_status.key(),
            architecture_text,
            flavor_text,
            expected_status.key(),
        },
    );
    if (options.require_enforced and declared_status != .enforced) return fail(
        diagnostic,
        "{s} {s} has no reviewed size budget: its build recorded a candidate " ++
            "baseline, which must be reviewed into scripts/ubuntu2604/" ++
            "size_budget.zig before the candidate can be published",
        .{ architecture_text, flavor_text },
    );

    const phases = arrayOf(object.get("phases_evaluated")) orelse return fail(
        diagnostic,
        "size budget phases are invalid",
        .{},
    );
    var present: [size_inventory.phase_order.len]bool = @splat(false);
    var last: i32 = -1;
    for (phases) |entry| {
        const text = stringOf(entry) orelse return fail(
            diagnostic,
            "size budget phases are invalid",
            .{},
        );
        const phase = Phase.parse(text) orelse return fail(
            diagnostic,
            "size budget names unknown phase {s}",
            .{text},
        );
        const position: i32 = @intFromEnum(phase);
        if (position <= last) return fail(
            diagnostic,
            "size budget phases are out of order at {s}",
            .{text},
        );
        last = position;
        present[@intFromEnum(phase)] = true;
    }

    const budget = budgetFor(flavor, architecture);
    const limits: []const Limit = if (budget) |reviewed|
        reviewed.limits
    else
        &baseline_capture_measures;
    const metrics = arrayOf(object.get("metrics")) orelse return fail(
        diagnostic,
        "size budget metrics are invalid",
        .{},
    );
    var failures: usize = 0;
    var index: usize = 0;
    for (metrics) |entry| {
        const item = objectOf(entry) orelse return fail(
            diagnostic,
            "size budget metric is invalid",
            .{},
        );
        if (!hasExactFields(item, &metric_fields)) return fail(
            diagnostic,
            "size budget metric has unexpected fields",
            .{},
        );
        const id = stringOf(item.get("id")) orelse return fail(
            diagnostic,
            "size budget metric is invalid",
            .{},
        );
        // The metric list is the reviewed table in the reviewed order, minus
        // the phases the document does not carry. Walking both together is what
        // catches a document that dropped an inconvenient metric.
        const limit = while (index < limits.len) {
            const candidate = limits[index];
            index += 1;
            var id_buffer: [128]u8 = undefined;
            if (!std.mem.eql(u8, candidate.measure.id(&id_buffer), id)) {
                if (present[@intFromEnum(candidate.measure.phase())]) return fail(
                    diagnostic,
                    "size budget omits metric {s}, which its phases cover",
                    .{candidate.measure.id(&id_buffer)},
                );
                continue;
            }
            break candidate;
        } else return fail(
            diagnostic,
            "size budget names metric {s}, which the reviewed budget does not",
            .{id},
        );
        if (!present[@intFromEnum(limit.measure.phase())]) return fail(
            diagnostic,
            "size budget reports metric {s} from the unevaluated {s} phase",
            .{ id, limit.measure.phase().key() },
        );
        if (!std.mem.eql(u8, stringOf(item.get("phase")) orelse "", limit.measure.phase().key()) or
            !std.mem.eql(u8, stringOf(item.get("direction")) orelse "", limit.direction.key()) or
            !std.mem.eql(u8, stringOf(item.get("unit")) orelse "", limit.measure.unit()))
        {
            return fail(
                diagnostic,
                "size budget metric {s} does not match the reviewed budget",
                .{id},
            );
        }
        const observed = countOf(item.get("observed")) orelse return fail(
            diagnostic,
            "size budget metric {s} has no observation",
            .{id},
        );
        const ok = switch (item.get("ok").?) {
            .bool => |flag| flag,
            else => return fail(
                diagnostic,
                "size budget metric {s} has no verdict",
                .{id},
            ),
        };
        switch (declared_status) {
            .candidate_baseline => {
                if (item.get("baseline").? != .null or item.get("limit").? != .null)
                    return fail(
                        diagnostic,
                        "size budget metric {s} states a bound in a recorded " ++
                            "baseline",
                        .{id},
                    );
                if (!ok) return fail(
                    diagnostic,
                    "size budget metric {s} is failed against a bound it does " ++
                        "not have",
                    .{id},
                );
            },
            .enforced => {
                const baseline = countOf(item.get("baseline")) orelse return fail(
                    diagnostic,
                    "size budget metric {s} has no baseline",
                    .{id},
                );
                const bound = countOf(item.get("limit")) orelse return fail(
                    diagnostic,
                    "size budget metric {s} has no limit",
                    .{id},
                );
                if (baseline != limit.baseline or bound != limit.value()) return fail(
                    diagnostic,
                    "size budget metric {s} states baseline {d} limit {d} " ++
                        "where the reviewed budget derives {d} and {d}",
                    .{ id, baseline, bound, limit.baseline, limit.value() },
                );
                if (ok != limit.satisfied(observed)) return fail(
                    diagnostic,
                    "size budget metric {s} states a verdict its own " ++
                        "observation {d} does not support",
                    .{ id, observed },
                );
                if (!ok) failures += 1;
            },
        }
    }
    while (index < limits.len) : (index += 1) {
        const candidate = limits[index];
        var id_buffer: [128]u8 = undefined;
        if (present[@intFromEnum(candidate.measure.phase())]) return fail(
            diagnostic,
            "size budget omits metric {s}, which its phases cover",
            .{candidate.measure.id(&id_buffer)},
        );
    }

    const declared_result = Result.parse(stringOf(object.get("result")) orelse "") orelse
        return fail(diagnostic, "size budget result is invalid", .{});
    const expected_result: Result = switch (declared_status) {
        .candidate_baseline => .baseline_recorded,
        .enforced => if (failures == 0) .pass else .fail,
    };
    if (declared_result != expected_result) return fail(
        diagnostic,
        "size budget claims {s} where its own metrics say {s}",
        .{ declared_result.key(), expected_result.key() },
    );
    if (declared_result == .fail) return fail(
        diagnostic,
        "size budget failed {d} reviewed bound(s)",
        .{failures},
    );

    return .{
        .architecture = architecture_text,
        .flavor = flavor_text,
        .status = declared_status,
        .result = declared_result,
        .metric_count = metrics.len,
        .failures = failures,
        .budget_sha256 = declared_digest,
        .inventory_sha256 = inventory_digest,
    };
}

pub fn readValidated(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    options: ValidateOptions,
    diagnostic: *Diagnostic,
) Error!std.json.Parsed(std.json.Value) {
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(document_max_bytes),
    ) catch |err| return fail(
        diagnostic,
        "cannot read size budget {s}: {s}",
        .{ path, @errorName(err) },
    );
    defer allocator.free(bytes);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch
        return fail(diagnostic, "size budget {s} is not valid JSON", .{path});
    errdefer parsed.deinit();
    _ = try validateDocument(allocator, parsed.value, options, diagnostic);
    return parsed;
}

/// Writes the gate document beside the measurement it judged.
pub fn write(
    gpa: Allocator,
    io: Io,
    path: []const u8,
    evaluation: *const Evaluation,
    diagnostic: *Diagnostic,
) Error!void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const value = try documentValue(arena.allocator(), evaluation);
    json_document.writeDocument(gpa, io, path, value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot write size budget {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
}
