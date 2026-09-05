//! Calculated disk geometry for the Ubuntu 26.04 core appliance.
//!
//! Issue #677 step 5 retires the last inherited number in the core image. Until
//! now the core output *was* Canonical's cloud disk: the builder copied the
//! signed 3584 MiB QCOW2, emptied its root partition, refilled it, and shipped
//! the result at the source's geometry. Everything about that disk -- the
//! virtual size, the ESP's length, the root partition's length, the 768 MiB the
//! root had to keep free -- described Canonical's general-purpose cloud image
//! rather than this appliance.
//!
//! This module is the replacement, and it is deliberately a *planner*: it turns
//! measurements into offsets and lengths and refuses anything it cannot derive.
//! Three inputs decide the whole disk:
//!
//!   * the signed, architecture-specific UKI, measured after signing;
//!   * the smallest ext4 that holds the finished root tree, measured by the
//!     writer that is about to write it (`ext4.minimumPopulateLengthAtLeast`
//!     through `filesystem_writer`); and
//!   * the guest's measured first-boot growth, which is what the size
//!     inventory's `first_boot` phase exists to produce (issues #678, #679).
//!
//! Every margin on top of those is named, bounded, and published. There are no
//! percentages of a number nobody chose and no round figures inherited from a
//! different image.
//!
//! The module depends on `std` alone, like `size_inventory.zig`, so the
//! builder, the release tool, and the tests can all speak one schema without
//! any of them acquiring the image library.

const std = @import("std");

const contract = @import("../release/contract.zig");
const json_document = @import("../release/json_document.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
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
pub const document_type = "miz-ubuntu2604-disk-geometry";
pub const release_id = "26.04";

/// The transform string the build provenance's `disk_layout` carries for a
/// core image. It is not `preserved` and it is not a rebuild of Canonical's
/// table: the output GPT is created here.
pub const provenance_transform = "fresh-core-gpt-v1";
/// What the signed Canonical publication is to a core build now. It is still
/// verified, still pinned, and still the only source of the guest's archive
/// keyring and its dpkg-visible base -- but its partition table is evidence,
/// not output.
pub const provenance_source = "canonical-verified-substrate";

/// The geometry the core flavor used to inherit. Recorded in every report so a
/// reader can see, in the document itself, that the source's size is no longer
/// the output's size -- and asserted against in tests so the inheritance
/// cannot quietly return.
pub const retired_inherited_virtual_size: u64 = 3584 * 1024 * 1024;

pub const sector_size: u64 = 512;
/// GPT's own reservation at each end of the disk: one header sector plus a
/// 128-entry, 128-byte partition array. Named here rather than imported so the
/// planner stays free of the image library; `gpt.zig` holds the same numbers
/// and `disk_geometry_matches_gpt_constants` in the builder proves they agree.
pub const partition_array_sectors: u64 = (128 * 128) / sector_size;
pub const gpt_reserved_sectors: u64 = 1 + partition_array_sectors;
/// Every partition boundary and the disk itself land on a 1 MiB boundary.
/// Azure requires an uploaded VHD's virtual size to be a whole number of MiB,
/// QEMU's QCOW2 conversion carries whatever it is given, and 1 MiB is the
/// alignment the rest of miz plans with (`layout.default_alignment`).
pub const alignment: u64 = 1024 * 1024;

pub const Architecture = enum {
    x86_64,
    aarch64,

    pub fn parse(text: []const u8) ?Architecture {
        if (std.mem.eql(u8, text, "x86_64")) return .x86_64;
        if (std.mem.eql(u8, text, "aarch64")) return .aarch64;
        return null;
    }
};

/// The first-boot growth a plan reserves against, and where the number's
/// authority comes from.
///
/// It is an *upper bound* rather than an estimate: the planner multiplies it
/// by `first_boot_growth_reserve_multiple`, and the QEMU acceptance harness
/// re-checks the guest's real growth against the bound every run, so an
/// appliance that starts writing more on first boot fails the run that
/// observed it instead of shipping a root with nowhere to write.
pub const FirstBootGrowth = struct {
    /// Bytes the root filesystem's used space grew by across first boot.
    bytes: u64,
    /// Inodes the root filesystem consumed across first boot.
    inodes: u32,
    /// Free-text provenance for the number, published in the report.
    source: []const u8,
};

/// The first-boot growth the core root is sized against.
///
/// This is a *declared bound*, not a claimed measurement, and it is written
/// that way on purpose. Everything the appliance writes to its root on first
/// boot is architecture-independent code with a small, bounded footprint:
/// `mizinit` creating its runtime directories and machine ID, `azagent`
/// writing provisioning state and the administrator's authorized keys, and
/// `sshd` generating host keys. 32 MiB and 512 inodes is well clear of that,
/// and the root then reserves `first_boot_growth_reserve_multiple` times it.
///
/// What keeps the bound honest is not this constant but
/// `assertWithinFirstBootGrowthBound`: on every QEMU acceptance run, on both
/// architectures, the guest's own `statfs` -- the `first_boot` phase issue #678
/// added and issue #679's probe supplies -- is differenced against the
/// `image_build` accounting and checked against this bound. A first boot that
/// starts writing more fails the run that observed it rather than shipping a
/// root planned against a figure that stopped being true.
pub fn firstBootGrowth(architecture: Architecture) FirstBootGrowth {
    return switch (architecture) {
        .x86_64, .aarch64 => .{
            .bytes = 32 * 1024 * 1024,
            .inodes = 512,
            .source = "declared-bound-verified-by-qemu-acceptance-first-boot-statfs",
        },
    };
}

/// The named, reviewable margins. Everything here is a decision; everything in
/// `Measurements` is an observation. Keeping them apart is what makes the
/// published report reviewable: a reader can see which numbers were measured
/// and which were chosen, and the chosen ones are few.
pub const Policy = struct {
    /// How many copies of the signed UKI the ESP is sized to hold.
    ///
    /// Two, and only for one reason: the ESP holds exactly one file that
    /// matters, `EFI/BOOT/BOOT{X64,AA64}.EFI`, and replacing it safely means
    /// writing the replacement before removing the copy that currently boots.
    /// FAT32 offers no other way to keep a bootable image on the volume for
    /// the whole of an update. One copy would make every future UKI update a
    /// repartition; three would be storage for an update scheme this appliance
    /// does not have.
    esp_resident_uki_copies: u8 = 2,

    /// How much of the measured first-boot growth the root keeps free.
    ///
    /// Four times: the growth itself, plus three more times over. The measured
    /// number is small and stable because the appliance's first boot writes
    /// little, so the reserve is stated as a multiple of it rather than as a
    /// figure of its own -- a change in first-boot behaviour has to more than
    /// quadruple before the image is short, and if it ever does, acceptance
    /// fails on the bound rather than the guest failing on a full root.
    first_boot_growth_reserve_multiple: u8 = 4,

    /// The floor under the free-space reserve, so an unusually small
    /// measurement cannot plan a root with no working room at all. One
    /// alignment unit per 1 MiB of a 64 MiB working set: enough for a kernel
    /// crash dump's worth of log, an administrator's copy of a file, and the
    /// dpkg state a package operation would write, before the root grows.
    root_free_bytes_floor: u64 = 64 * 1024 * 1024,

    /// The floor under the free-inode reserve. Carried across from the value
    /// the builder has always validated, which no measured first-boot inode
    /// growth has ever come close to.
    root_free_inodes_floor: u32 = 4096,

    /// `mke2fs -i`. The ratio a distro-installed root filesystem has, which is
    /// what makes the inode count a function of the filesystem's size rather
    /// than of its current contents.
    root_bytes_per_inode: u32 = 16 * 1024,

    /// The only block size this writer emits, and the unit every free-block
    /// count in the size inventory is expressed in.
    root_block_size: u32 = 4096,
};

/// What the build measured. None of these is a choice.
pub const Measurements = struct {
    /// Length of the signed UKI, after signing.
    signed_uki_bytes: u64,
    /// The smallest FAT32 volume that holds `esp_resident_uki_copies` copies
    /// of the signed UKI, from the FAT32 writer's own solver.
    esp_minimum_bytes: u64,
    /// The smallest ext4 that holds the finished root tree at all.
    root_minimum_bytes: u64,
    /// The smallest ext4 the writer accepts that is also at least
    /// `Requirements.root_floor_bytes`. Not simply the floor: whether a length
    /// is accepted is not monotone in the length, so the writer solves for it.
    root_fitted_bytes: u64,
    /// The measured first-boot growth this plan reserves against.
    first_boot: FirstBootGrowth,
};

/// What the measurements and the policy require of the root filesystem, before
/// the writer is asked to fit a length to it.
pub const Requirements = struct {
    root_free_bytes: u64,
    root_free_inodes: u32,
    /// `root_minimum_bytes` plus `root_free_bytes`: the smallest filesystem
    /// that holds the tree *and* the reserve.
    root_floor_bytes: u64,
};

pub const PlanError = error{
    /// A measurement was zero, or an arithmetic step overflowed.
    InvalidGeometryInput,
    /// The fitted root is smaller than the tree it has to hold.
    RootBelowMinimum,
    /// The ESP is smaller than the volume that holds the UKI copies.
    EspBelowMinimum,
    /// A computed offset or length is not a whole number of alignment units.
    UnalignedGeometry,
};

pub const Partition = struct {
    name: []const u8,
    role: []const u8,
    filesystem: []const u8,
    /// Zero-based GPT partition-array slot. The kernel's device name is one
    /// more than this: table index 0 is `/dev/sda1`.
    table_index: u32,
    offset_bytes: u64,
    length_bytes: u64,
    /// Bytes of the partition the filesystem spans. Equal to `length_bytes`
    /// for the ESP; for the root it is what the ext4 writer accepted, which
    /// can be below the aligned partition length.
    filesystem_length_bytes: u64,

    pub fn firstLba(self: Partition) u64 {
        return self.offset_bytes / sector_size;
    }

    pub fn lastLba(self: Partition) u64 {
        return (self.offset_bytes + self.length_bytes) / sector_size - 1;
    }
};

/// A complete, checked answer: where each partition starts, how long it is,
/// and how large the disk that holds them has to be.
pub const Plan = struct {
    architecture: Architecture,
    policy: Policy,
    measurements: Measurements,
    requirements: Requirements,
    esp: Partition,
    root: Partition,
    virtual_size: u64,

    /// The last LBA of the disk, which is where GPT's backup header goes.
    pub fn backupHeaderLba(self: Plan) u64 {
        return self.virtual_size / sector_size - 1;
    }

    pub fn firstUsableLba(_: Plan) u64 {
        return 2 + partition_array_sectors;
    }

    pub fn lastUsableLba(self: Plan) u64 {
        return self.virtual_size / sector_size - 1 - gpt_reserved_sectors;
    }
};

fn add(a: u64, b: u64) PlanError!u64 {
    return std.math.add(u64, a, b) catch error.InvalidGeometryInput;
}

fn mul(a: u64, b: u64) PlanError!u64 {
    return std.math.mul(u64, a, b) catch error.InvalidGeometryInput;
}

pub fn alignUp(value: u64) PlanError!u64 {
    if (value == 0) return 0;
    const rounded = try add(value - 1, alignment);
    return rounded / alignment * alignment;
}

/// What the root filesystem has to keep free, and therefore the smallest
/// filesystem the writer may be asked to fit.
///
/// Separated from `plan` because the caller has to go and ask the ext4 writer
/// to solve for a length at least this large before the rest of the disk can
/// be laid out: the answer is not the floor, and a plan built on the floor
/// would describe a filesystem the writer never accepted.
pub fn requirements(
    policy: Policy,
    root_minimum_bytes: u64,
    first_boot: FirstBootGrowth,
) PlanError!Requirements {
    if (root_minimum_bytes == 0 or policy.first_boot_growth_reserve_multiple == 0)
        return error.InvalidGeometryInput;
    const measured_reserve = try mul(
        first_boot.bytes,
        policy.first_boot_growth_reserve_multiple,
    );
    const free_bytes = @max(measured_reserve, policy.root_free_bytes_floor);
    const measured_inodes = std.math.mul(
        u32,
        first_boot.inodes,
        policy.first_boot_growth_reserve_multiple,
    ) catch return error.InvalidGeometryInput;
    return .{
        .root_free_bytes = free_bytes,
        .root_free_inodes = @max(measured_inodes, policy.root_free_inodes_floor),
        .root_floor_bytes = try add(root_minimum_bytes, free_bytes),
    };
}

/// The smallest FAT32 content set the ESP has to hold: `copies` copies of the
/// signed UKI. The caller hands these lengths to the FAT32 writer's own solver
/// rather than modelling FAT metadata here, because the writer is the only
/// thing that knows what its own tables cost.
pub fn espContentLengths(
    policy: Policy,
    signed_uki_bytes: u64,
    buffer: []u64,
) PlanError![]const u64 {
    if (signed_uki_bytes == 0 or policy.esp_resident_uki_copies == 0)
        return error.InvalidGeometryInput;
    if (buffer.len < policy.esp_resident_uki_copies) return error.InvalidGeometryInput;
    const copies = policy.esp_resident_uki_copies;
    for (buffer[0..copies]) |*slot| slot.* = signed_uki_bytes;
    return buffer[0..copies];
}

pub const PlanRequest = struct {
    architecture: Architecture,
    policy: Policy = .{},
    measurements: Measurements,
    /// Partition names written into the GPT. The root's name is a consumer
    /// contract: `root_resize` and the builder both find the root by it.
    esp_name: []const u8 = "ESP",
    root_name: []const u8 = "cloudimg-rootfs",
};

/// Lays out the whole disk.
///
/// The ESP comes first and the root comes last, and both facts are load
/// bearing. `mizinit` looks for the ESP on partition 1 of whichever disk
/// naming scheme the guest ended up with, so an ESP anywhere else is an ESP it
/// never mounts. `azagent`'s root growth calls `gpt.growPartitionToEnd`, which
/// refuses a partition that is not the last one on the disk, so a root that is
/// not last is a root that never grows.
pub fn plan(request: PlanRequest) PlanError!Plan {
    const measurements = request.measurements;
    if (measurements.signed_uki_bytes == 0 or
        measurements.esp_minimum_bytes == 0 or
        measurements.root_minimum_bytes == 0 or
        measurements.root_fitted_bytes == 0)
    {
        return error.InvalidGeometryInput;
    }
    const required = try requirements(
        request.policy,
        measurements.root_minimum_bytes,
        measurements.first_boot,
    );
    if (measurements.root_fitted_bytes < measurements.root_minimum_bytes)
        return error.RootBelowMinimum;
    if (measurements.root_fitted_bytes < required.root_floor_bytes)
        return error.RootBelowMinimum;

    const esp_length = try alignUp(measurements.esp_minimum_bytes);
    if (esp_length < measurements.esp_minimum_bytes) return error.EspBelowMinimum;
    const root_length = try alignUp(measurements.root_fitted_bytes);
    if (root_length < measurements.root_fitted_bytes) return error.RootBelowMinimum;

    // The head reserves the primary GPT and rounds the first partition onto an
    // alignment boundary; the tail reserves the backup array and header and
    // rounds the disk's own length onto one.
    const head = try alignUp(try mul(2 + partition_array_sectors, sector_size));
    const tail = try alignUp(try mul(gpt_reserved_sectors, sector_size));

    const esp_offset = head;
    const root_offset = try add(esp_offset, esp_length);
    const virtual_size = try add(try add(root_offset, root_length), tail);
    if (virtual_size % alignment != 0 or
        esp_offset % alignment != 0 or
        root_offset % alignment != 0)
    {
        return error.UnalignedGeometry;
    }

    const result = Plan{
        .architecture = request.architecture,
        .policy = request.policy,
        .measurements = measurements,
        .requirements = required,
        .esp = .{
            .name = request.esp_name,
            .role = "esp",
            .filesystem = "fat32",
            .table_index = 0,
            .offset_bytes = esp_offset,
            .length_bytes = esp_length,
            .filesystem_length_bytes = esp_length,
        },
        .root = .{
            .name = request.root_name,
            .role = "root",
            .filesystem = "ext4",
            .table_index = 1,
            .offset_bytes = root_offset,
            .length_bytes = root_length,
            .filesystem_length_bytes = measurements.root_fitted_bytes,
        },
        .virtual_size = virtual_size,
    };
    // The backup GPT has to fit past the last partition, and the last
    // partition has to end inside the usable range. Both are implied by the
    // arithmetic above; asserting them here is what makes an arithmetic change
    // fail in the planner rather than in a firmware nobody can attach a
    // debugger to.
    if (result.root.lastLba() > result.lastUsableLba() or
        result.esp.firstLba() < result.firstUsableLba() or
        result.esp.lastLba() >= result.root.firstLba())
    {
        return error.UnalignedGeometry;
    }
    return result;
}

/// Fails when a guest's real first-boot growth exceeded the bound the geometry
/// was planned against.
///
/// The reserve is `first_boot_growth_reserve_multiple` times the bound, so a
/// breach here is not an out-of-space image; it is the planner's input having
/// gone stale, which is exactly the thing that should be caught by the run
/// that measured it rather than by an operator months later.
pub fn assertWithinFirstBootGrowthBound(
    architecture: Architecture,
    measured_growth_bytes: u64,
    measured_growth_inodes: u64,
) error{FirstBootGrowthExceedsGeometryBound}!void {
    const bound = firstBootGrowth(architecture);
    if (measured_growth_bytes > bound.bytes or measured_growth_inodes > bound.inodes)
        return error.FirstBootGrowthExceedsGeometryBound;
}

// ---------------------------------------------------------------------------
// Document.
// ---------------------------------------------------------------------------

const Builder = struct {
    arena: Allocator,

    fn object(_: Builder) std.json.ObjectMap {
        return .empty;
    }

    fn array(self: Builder) std.json.Array {
        return .init(self.arena);
    }

    fn put(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        value: std.json.Value,
    ) Error!void {
        try map.put(self.arena, try self.arena.dupe(u8, key), value);
    }

    fn putString(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        text: []const u8,
    ) Error!void {
        try self.put(map, key, .{ .string = try self.arena.dupe(u8, text) });
    }

    fn putCount(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        number: u64,
    ) Error!void {
        try self.put(map, key, .{ .integer = castCount(number) });
    }

    fn putBool(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        value: bool,
    ) Error!void {
        try self.put(map, key, .{ .bool = value });
    }
};

/// Byte counts never approach `i64`'s range, but a cast that silently wrapped
/// would turn an impossible geometry into a plausible one, so it saturates.
fn castCount(number: u64) i64 {
    return std.math.cast(i64, number) orelse std.math.maxInt(i64);
}

fn partitionValue(
    builder: Builder,
    partition: Partition,
    type_guid: []const u8,
    unique_guid: []const u8,
) Error!std.json.Value {
    var map = builder.object();
    try builder.putString(&map, "name", partition.name);
    try builder.putString(&map, "role", partition.role);
    try builder.putString(&map, "filesystem", partition.filesystem);
    try builder.putString(&map, "type_guid", type_guid);
    try builder.putString(&map, "unique_guid", unique_guid);
    try builder.putCount(&map, "table_index", partition.table_index);
    try builder.putCount(&map, "first_lba", partition.firstLba());
    try builder.putCount(&map, "last_lba", partition.lastLba());
    try builder.putCount(&map, "offset_bytes", partition.offset_bytes);
    try builder.putCount(&map, "length_bytes", partition.length_bytes);
    try builder.putCount(&map, "filesystem_length_bytes", partition.filesystem_length_bytes);
    return .{ .object = map };
}

/// Identifiers the build chose for the assembled disk. They are inputs to the
/// document rather than to the plan: the planner decides sizes, and nothing
/// about a GUID changes a size.
pub const Identity = struct {
    disk_guid: []const u8,
    esp_type_guid: []const u8,
    esp_partition_guid: []const u8,
    esp_volume_id: u32,
    esp_volume_label: []const u8,
    root_type_guid: []const u8,
    root_partition_guid: []const u8,
    root_filesystem_uuid: []const u8,
    root_filesystem_label: []const u8,
};

/// Builds the machine-readable geometry report.
pub fn documentValue(
    arena: Allocator,
    flavor: []const u8,
    result: Plan,
    identity: Identity,
) Error!std.json.Value {
    const builder: Builder = .{ .arena = arena };

    var policy = builder.object();
    try builder.putCount(&policy, "alignment_bytes", alignment);
    try builder.putCount(&policy, "sector_size", sector_size);
    try builder.putCount(&policy, "gpt_reserved_sectors", gpt_reserved_sectors);
    try builder.putCount(&policy, "esp_resident_uki_copies", result.policy.esp_resident_uki_copies);
    try builder.putCount(
        &policy,
        "first_boot_growth_reserve_multiple",
        result.policy.first_boot_growth_reserve_multiple,
    );
    try builder.putCount(&policy, "root_free_bytes_floor", result.policy.root_free_bytes_floor);
    try builder.putCount(&policy, "root_free_inodes_floor", result.policy.root_free_inodes_floor);
    try builder.putCount(&policy, "root_bytes_per_inode", result.policy.root_bytes_per_inode);
    try builder.putCount(&policy, "root_block_size", result.policy.root_block_size);

    var first_boot = builder.object();
    try builder.putCount(&first_boot, "growth_bytes", result.measurements.first_boot.bytes);
    try builder.putCount(&first_boot, "growth_inodes", result.measurements.first_boot.inodes);
    try builder.putString(&first_boot, "source", result.measurements.first_boot.source);

    var measurements = builder.object();
    try builder.putCount(&measurements, "signed_uki_bytes", result.measurements.signed_uki_bytes);
    try builder.putCount(&measurements, "esp_minimum_bytes", result.measurements.esp_minimum_bytes);
    try builder.putCount(&measurements, "root_minimum_bytes", result.measurements.root_minimum_bytes);
    try builder.putCount(&measurements, "root_fitted_bytes", result.measurements.root_fitted_bytes);
    try builder.put(&measurements, "first_boot", .{ .object = first_boot });

    var required = builder.object();
    try builder.putCount(&required, "root_free_bytes", result.requirements.root_free_bytes);
    try builder.putCount(&required, "root_free_inodes", result.requirements.root_free_inodes);
    try builder.putCount(&required, "root_floor_bytes", result.requirements.root_floor_bytes);

    var partitions = builder.array();
    try partitions.append(try partitionValue(
        builder,
        result.esp,
        identity.esp_type_guid,
        identity.esp_partition_guid,
    ));
    try partitions.append(try partitionValue(
        builder,
        result.root,
        identity.root_type_guid,
        identity.root_partition_guid,
    ));

    var disk = builder.object();
    try builder.putString(&disk, "guid", identity.disk_guid);
    try builder.putCount(&disk, "virtual_size", result.virtual_size);
    try builder.putCount(&disk, "first_usable_lba", result.firstUsableLba());
    try builder.putCount(&disk, "last_usable_lba", result.lastUsableLba());
    try builder.putCount(&disk, "backup_header_lba", result.backupHeaderLba());

    var filesystems = builder.object();
    try builder.putCount(&filesystems, "esp_volume_id", identity.esp_volume_id);
    try builder.putString(&filesystems, "esp_volume_label", identity.esp_volume_label);
    try builder.putString(&filesystems, "root_filesystem_uuid", identity.root_filesystem_uuid);
    try builder.putString(&filesystems, "root_filesystem_label", identity.root_filesystem_label);

    var substrate = builder.object();
    try builder.putString(&substrate, "source", provenance_source);
    try builder.putString(&substrate, "transform", provenance_transform);
    try builder.putCount(&substrate, "retired_virtual_size", retired_inherited_virtual_size);
    try builder.putBool(&substrate, "inherits_source_geometry", false);

    var root = builder.object();
    try builder.put(&root, "schema", .{ .integer = schema_version });
    try builder.putString(&root, "type", document_type);
    try builder.putString(&root, "release", release_id);
    try builder.putString(&root, "architecture", @tagName(result.architecture));
    try builder.putString(&root, "flavor", flavor);
    try builder.put(&root, "substrate", .{ .object = substrate });
    try builder.put(&root, "policy", .{ .object = policy });
    try builder.put(&root, "measurements", .{ .object = measurements });
    try builder.put(&root, "requirements", .{ .object = required });
    try builder.put(&root, "partitions", .{ .array = partitions });
    try builder.put(&root, "disk", .{ .object = disk });
    try builder.put(&root, "filesystems", .{ .object = filesystems });
    return .{ .object = root };
}

/// Writes the report beside the other provenance sidecars, in the same
/// canonical shape every one of them has.
pub fn write(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    flavor: []const u8,
    result: Plan,
    identity: Identity,
    diagnostic: *Diagnostic,
) Error!void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const value = try documentValue(arena.allocator(), flavor, result, identity);
    json_document.writeDocument(allocator, io, path, value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot write disk geometry {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
}

// ---------------------------------------------------------------------------
// Validation.
// ---------------------------------------------------------------------------

fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const inner = value orelse return null;
    return switch (inner) {
        .object => |map| map,
        else => null,
    };
}

fn integerOf(value: ?std.json.Value) ?i64 {
    const inner = value orelse return null;
    return switch (inner) {
        .integer => |number| number,
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

fn stringIs(value: ?std.json.Value, expected: []const u8) bool {
    const text = stringOf(value) orelse return false;
    return std.mem.eql(u8, text, expected);
}

fn count(value: ?std.json.Value) ?u64 {
    const number = integerOf(value) orelse return null;
    if (number < 0) return null;
    return @intCast(number);
}

fn hasExactFields(map: std.json.ObjectMap, expected: []const []const u8) bool {
    if (map.count() != expected.len) return false;
    for (expected) |name| {
        if (map.get(name) == null) return false;
    }
    return true;
}

pub const ValidateOptions = struct {
    architecture: ?[]const u8 = null,
    flavor: ?[]const u8 = null,
    /// When set, the document's planned virtual size must equal this. The
    /// workflows use it to bind the geometry report to the artifact the same
    /// run produced.
    virtual_size: ?u64 = null,
};

pub const Summary = struct {
    architecture: []const u8,
    flavor: []const u8,
    virtual_size: u64,
    esp_length_bytes: u64,
    /// Where the planned root partition starts. Published because a consumer
    /// that has to reason about the root's extent -- Azure acceptance measures
    /// its growth from it -- must read it from the plan rather than name the
    /// inherited offset core stopped using.
    root_first_lba: u64,
    root_length_bytes: u64,
    root_free_bytes: u64,
    signed_uki_bytes: u64,
};

const partition_fields = [_][]const u8{
    "filesystem",
    "filesystem_length_bytes",
    "first_lba",
    "last_lba",
    "length_bytes",
    "name",
    "offset_bytes",
    "role",
    "table_index",
    "type_guid",
    "unique_guid",
};

fn validatePartition(
    map: std.json.ObjectMap,
    role: []const u8,
    table_index: u64,
    diagnostic: *Diagnostic,
) Error!Partition {
    if (!hasExactFields(map, &partition_fields) or !stringIs(map.get("role"), role))
        return fail(diagnostic, "disk geometry {s} partition is invalid", .{role});
    const offset = count(map.get("offset_bytes")) orelse
        return fail(diagnostic, "disk geometry {s} offset is invalid", .{role});
    const length = count(map.get("length_bytes")) orelse
        return fail(diagnostic, "disk geometry {s} length is invalid", .{role});
    const filesystem_length = count(map.get("filesystem_length_bytes")) orelse
        return fail(diagnostic, "disk geometry {s} filesystem length is invalid", .{role});
    const index = count(map.get("table_index")) orelse
        return fail(diagnostic, "disk geometry {s} table index is invalid", .{role});
    if (index != table_index)
        return fail(diagnostic, "disk geometry {s} is not at table index {d}", .{ role, table_index });
    if (length == 0 or filesystem_length == 0 or filesystem_length > length or
        offset % alignment != 0 or length % alignment != 0)
    {
        return fail(diagnostic, "disk geometry {s} partition is not aligned", .{role});
    }
    const partition = Partition{
        .name = stringOf(map.get("name")) orelse
            return fail(diagnostic, "disk geometry {s} name is invalid", .{role}),
        .role = role,
        .filesystem = stringOf(map.get("filesystem")) orelse
            return fail(diagnostic, "disk geometry {s} filesystem is invalid", .{role}),
        .table_index = @intCast(index),
        .offset_bytes = offset,
        .length_bytes = length,
        .filesystem_length_bytes = filesystem_length,
    };
    if (count(map.get("first_lba")) != partition.firstLba() or
        count(map.get("last_lba")) != partition.lastLba())
    {
        return fail(diagnostic, "disk geometry {s} LBA range disagrees with its offset", .{role});
    }
    return partition;
}

/// Full structural and arithmetic check of a geometry report.
///
/// Deliberately re-derives the plan from the document's own measurements and
/// policy and requires the result to equal what the document claims. A report
/// that merely parses proves nothing; a report whose offsets can be recomputed
/// from its stated inputs is a report a reviewer can argue with.
pub fn validateDocument(
    value: std.json.Value,
    options: ValidateOptions,
    diagnostic: *Diagnostic,
) Error!Summary {
    const object = objectOf(value) orelse
        return fail(diagnostic, "disk geometry is not a JSON object", .{});
    const top_fields = [_][]const u8{
        "architecture",
        "disk",
        "filesystems",
        "flavor",
        "measurements",
        "partitions",
        "policy",
        "release",
        "requirements",
        "schema",
        "substrate",
        "type",
    };
    if (!hasExactFields(object, &top_fields))
        return fail(diagnostic, "disk geometry has unexpected fields", .{});
    if (integerOf(object.get("schema")) != schema_version or
        !stringIs(object.get("type"), document_type) or
        !stringIs(object.get("release"), release_id))
    {
        return fail(diagnostic, "disk geometry identity is invalid", .{});
    }
    const architecture_text = stringOf(object.get("architecture")) orelse
        return fail(diagnostic, "disk geometry architecture is invalid", .{});
    const architecture = Architecture.parse(architecture_text) orelse
        return fail(diagnostic, "unsupported disk geometry architecture: {s}", .{architecture_text});
    if (options.architecture) |expected| {
        if (!std.mem.eql(u8, expected, architecture_text))
            return fail(diagnostic, "disk geometry is for {s}, not {s}", .{ architecture_text, expected });
    }
    const flavor_text = stringOf(object.get("flavor")) orelse
        return fail(diagnostic, "disk geometry flavor is invalid", .{});
    if (options.flavor) |expected| {
        if (!std.mem.eql(u8, expected, flavor_text))
            return fail(diagnostic, "disk geometry is for {s}, not {s}", .{ flavor_text, expected });
    }

    const substrate = objectOf(object.get("substrate")) orelse
        return fail(diagnostic, "disk geometry substrate is invalid", .{});
    const substrate_fields = [_][]const u8{
        "inherits_source_geometry",
        "retired_virtual_size",
        "source",
        "transform",
    };
    if (!hasExactFields(substrate, &substrate_fields) or
        !stringIs(substrate.get("source"), provenance_source) or
        !stringIs(substrate.get("transform"), provenance_transform) or
        count(substrate.get("retired_virtual_size")) != retired_inherited_virtual_size or
        substrate.get("inherits_source_geometry").? != .bool or
        substrate.get("inherits_source_geometry").?.bool)
    {
        return fail(diagnostic, "disk geometry does not declare a fresh output GPT", .{});
    }

    const policy_map = objectOf(object.get("policy")) orelse
        return fail(diagnostic, "disk geometry policy is invalid", .{});
    const policy_fields = [_][]const u8{
        "alignment_bytes",
        "esp_resident_uki_copies",
        "first_boot_growth_reserve_multiple",
        "gpt_reserved_sectors",
        "root_block_size",
        "root_bytes_per_inode",
        "root_free_bytes_floor",
        "root_free_inodes_floor",
        "sector_size",
    };
    if (!hasExactFields(policy_map, &policy_fields) or
        count(policy_map.get("alignment_bytes")) != alignment or
        count(policy_map.get("sector_size")) != sector_size or
        count(policy_map.get("gpt_reserved_sectors")) != gpt_reserved_sectors)
    {
        return fail(diagnostic, "disk geometry policy constants are invalid", .{});
    }
    const policy = Policy{
        .esp_resident_uki_copies = std.math.cast(
            u8,
            count(policy_map.get("esp_resident_uki_copies")) orelse
                return fail(diagnostic, "disk geometry ESP copy policy is invalid", .{}),
        ) orelse return fail(diagnostic, "disk geometry ESP copy policy is invalid", .{}),
        .first_boot_growth_reserve_multiple = std.math.cast(
            u8,
            count(policy_map.get("first_boot_growth_reserve_multiple")) orelse
                return fail(diagnostic, "disk geometry growth reserve is invalid", .{}),
        ) orelse return fail(diagnostic, "disk geometry growth reserve is invalid", .{}),
        .root_free_bytes_floor = count(policy_map.get("root_free_bytes_floor")) orelse
            return fail(diagnostic, "disk geometry free-byte floor is invalid", .{}),
        .root_free_inodes_floor = std.math.cast(
            u32,
            count(policy_map.get("root_free_inodes_floor")) orelse
                return fail(diagnostic, "disk geometry free-inode floor is invalid", .{}),
        ) orelse return fail(diagnostic, "disk geometry free-inode floor is invalid", .{}),
        .root_bytes_per_inode = std.math.cast(
            u32,
            count(policy_map.get("root_bytes_per_inode")) orelse
                return fail(diagnostic, "disk geometry inode ratio is invalid", .{}),
        ) orelse return fail(diagnostic, "disk geometry inode ratio is invalid", .{}),
        .root_block_size = std.math.cast(
            u32,
            count(policy_map.get("root_block_size")) orelse
                return fail(diagnostic, "disk geometry block size is invalid", .{}),
        ) orelse return fail(diagnostic, "disk geometry block size is invalid", .{}),
    };

    const measurement_map = objectOf(object.get("measurements")) orelse
        return fail(diagnostic, "disk geometry measurements are invalid", .{});
    const measurement_fields = [_][]const u8{
        "esp_minimum_bytes",
        "first_boot",
        "root_fitted_bytes",
        "root_minimum_bytes",
        "signed_uki_bytes",
    };
    if (!hasExactFields(measurement_map, &measurement_fields))
        return fail(diagnostic, "disk geometry measurements are invalid", .{});
    const first_boot_map = objectOf(measurement_map.get("first_boot")) orelse
        return fail(diagnostic, "disk geometry first-boot measurement is invalid", .{});
    const first_boot_fields = [_][]const u8{ "growth_bytes", "growth_inodes", "source" };
    if (!hasExactFields(first_boot_map, &first_boot_fields))
        return fail(diagnostic, "disk geometry first-boot measurement is invalid", .{});
    const measurements = Measurements{
        .signed_uki_bytes = count(measurement_map.get("signed_uki_bytes")) orelse
            return fail(diagnostic, "disk geometry UKI measurement is invalid", .{}),
        .esp_minimum_bytes = count(measurement_map.get("esp_minimum_bytes")) orelse
            return fail(diagnostic, "disk geometry ESP measurement is invalid", .{}),
        .root_minimum_bytes = count(measurement_map.get("root_minimum_bytes")) orelse
            return fail(diagnostic, "disk geometry root measurement is invalid", .{}),
        .root_fitted_bytes = count(measurement_map.get("root_fitted_bytes")) orelse
            return fail(diagnostic, "disk geometry fitted root is invalid", .{}),
        .first_boot = .{
            .bytes = count(first_boot_map.get("growth_bytes")) orelse
                return fail(diagnostic, "disk geometry first-boot growth is invalid", .{}),
            .inodes = std.math.cast(
                u32,
                count(first_boot_map.get("growth_inodes")) orelse
                    return fail(diagnostic, "disk geometry first-boot inodes are invalid", .{}),
            ) orelse return fail(diagnostic, "disk geometry first-boot inodes are invalid", .{}),
            .source = stringOf(first_boot_map.get("source")) orelse
                return fail(diagnostic, "disk geometry first-boot source is invalid", .{}),
        },
    };

    const partitions = switch (object.get("partitions") orelse .null) {
        .array => |items| items,
        else => return fail(diagnostic, "disk geometry partitions are invalid", .{}),
    };
    if (partitions.items.len != 2) return fail(
        diagnostic,
        "disk geometry must carry exactly the ESP and root entries, not {d}",
        .{partitions.items.len},
    );
    const esp = try validatePartition(
        objectOf(partitions.items[0]) orelse
            return fail(diagnostic, "disk geometry ESP entry is invalid", .{}),
        "esp",
        0,
        diagnostic,
    );
    const root = try validatePartition(
        objectOf(partitions.items[1]) orelse
            return fail(diagnostic, "disk geometry root entry is invalid", .{}),
        "root",
        1,
        diagnostic,
    );

    const recomputed = plan(.{
        .architecture = architecture,
        .policy = policy,
        .measurements = measurements,
        .esp_name = esp.name,
        .root_name = root.name,
    }) catch |err| return fail(
        diagnostic,
        "disk geometry does not follow from its own measurements: {s}",
        .{@errorName(err)},
    );
    if (recomputed.esp.offset_bytes != esp.offset_bytes or
        recomputed.esp.length_bytes != esp.length_bytes or
        recomputed.root.offset_bytes != root.offset_bytes or
        recomputed.root.length_bytes != root.length_bytes or
        recomputed.root.filesystem_length_bytes != root.filesystem_length_bytes)
    {
        return fail(diagnostic, "disk geometry offsets disagree with its measurements", .{});
    }

    const requirement_map = objectOf(object.get("requirements")) orelse
        return fail(diagnostic, "disk geometry requirements are invalid", .{});
    const requirement_fields = [_][]const u8{
        "root_floor_bytes",
        "root_free_bytes",
        "root_free_inodes",
    };
    if (!hasExactFields(requirement_map, &requirement_fields) or
        count(requirement_map.get("root_free_bytes")) != recomputed.requirements.root_free_bytes or
        count(requirement_map.get("root_free_inodes")) != recomputed.requirements.root_free_inodes or
        count(requirement_map.get("root_floor_bytes")) != recomputed.requirements.root_floor_bytes)
    {
        return fail(diagnostic, "disk geometry requirements disagree with its policy", .{});
    }

    const disk = objectOf(object.get("disk")) orelse
        return fail(diagnostic, "disk geometry disk section is invalid", .{});
    const disk_fields = [_][]const u8{
        "backup_header_lba",
        "first_usable_lba",
        "guid",
        "last_usable_lba",
        "virtual_size",
    };
    if (!hasExactFields(disk, &disk_fields) or
        count(disk.get("virtual_size")) != recomputed.virtual_size or
        count(disk.get("first_usable_lba")) != recomputed.firstUsableLba() or
        count(disk.get("last_usable_lba")) != recomputed.lastUsableLba() or
        count(disk.get("backup_header_lba")) != recomputed.backupHeaderLba())
    {
        return fail(diagnostic, "disk geometry disk section disagrees with its plan", .{});
    }
    if (recomputed.virtual_size == retired_inherited_virtual_size) return fail(
        diagnostic,
        "disk geometry still plans the retired {d}-byte inherited size",
        .{retired_inherited_virtual_size},
    );

    const filesystems = objectOf(object.get("filesystems")) orelse
        return fail(diagnostic, "disk geometry filesystem identity is invalid", .{});
    const filesystem_fields = [_][]const u8{
        "esp_volume_id",
        "esp_volume_label",
        "root_filesystem_label",
        "root_filesystem_uuid",
    };
    if (!hasExactFields(filesystems, &filesystem_fields) or
        stringOf(filesystems.get("root_filesystem_uuid")) == null or
        stringOf(filesystems.get("root_filesystem_label")) == null or
        stringOf(filesystems.get("esp_volume_label")) == null or
        count(filesystems.get("esp_volume_id")) == null)
    {
        return fail(diagnostic, "disk geometry filesystem identity is invalid", .{});
    }

    if (options.virtual_size) |expected| {
        if (expected != recomputed.virtual_size) return fail(
            diagnostic,
            "disk geometry plans {d} bytes, but the artifact is {d}",
            .{ recomputed.virtual_size, expected },
        );
    }

    return .{
        .architecture = architecture_text,
        .flavor = flavor_text,
        .virtual_size = recomputed.virtual_size,
        .esp_length_bytes = esp.length_bytes,
        .root_first_lba = root.firstLba(),
        .root_length_bytes = root.length_bytes,
        .root_free_bytes = recomputed.requirements.root_free_bytes,
        .signed_uki_bytes = measurements.signed_uki_bytes,
    };
}

pub const Parsed = struct {
    document: json_document.Document,

    pub fn value(self: *const Parsed) std.json.Value {
        return self.document.parsed.value;
    }

    pub fn deinit(self: *Parsed) void {
        self.document.deinit();
        self.* = undefined;
    }
};

pub const max_document_bytes: u64 = 256 * 1024;

/// Reads and fully validates a geometry report from disk.
pub fn readValidated(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    options: ValidateOptions,
    diagnostic: *Diagnostic,
) Error!Parsed {
    var document = json_document.readObject(
        allocator,
        io,
        path,
        max_document_bytes,
        diagnostic,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(diagnostic, "cannot read disk geometry '{s}'", .{path}),
    };
    errdefer document.deinit();
    _ = try validateDocument(document.parsed.value, options, diagnostic);
    return .{ .document = document };
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

const sample_identity = Identity{
    .disk_guid = "11111111-1111-4111-8111-111111111111",
    .esp_type_guid = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    .esp_partition_guid = "22222222-2222-4222-8222-222222222222",
    .esp_volume_id = 0x4d495a01,
    .esp_volume_label = "UEFI",
    .root_type_guid = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
    .root_partition_guid = "33333333-3333-4333-8333-333333333333",
    .root_filesystem_uuid = "44444444-4444-4444-4444-444444444444",
    .root_filesystem_label = "cloudimg-rootfs",
};

fn sampleMeasurements() Measurements {
    return .{
        .signed_uki_bytes = 62 * 1024 * 1024,
        .esp_minimum_bytes = 130 * 1024 * 1024,
        .root_minimum_bytes = 1400 * 1024 * 1024,
        .root_fitted_bytes = 1528 * 1024 * 1024,
        .first_boot = firstBootGrowth(.x86_64),
    };
}

test "the plan places the ESP first, the root last, and every edge on a MiB" {
    const result = try plan(.{
        .architecture = .x86_64,
        .measurements = sampleMeasurements(),
    });
    try testing.expectEqual(@as(u64, alignment), result.esp.offset_bytes);
    try testing.expectEqual(@as(u32, 0), result.esp.table_index);
    try testing.expectEqual(@as(u32, 1), result.root.table_index);
    try testing.expect(result.root.offset_bytes > result.esp.offset_bytes);
    try testing.expectEqual(@as(u64, 0), result.virtual_size % alignment);
    try testing.expectEqual(
        result.esp.offset_bytes + result.esp.length_bytes,
        result.root.offset_bytes,
    );
    // The backup GPT fits, and the root is the last thing before it.
    try testing.expect(result.root.lastLba() <= result.lastUsableLba());
    try testing.expect(result.backupHeaderLba() > result.root.lastLba());
    try testing.expect(result.virtual_size != retired_inherited_virtual_size);
    try testing.expect(result.virtual_size < retired_inherited_virtual_size);
}

test "the free-space reserve is a multiple of the measured growth, with a floor" {
    const policy = Policy{};
    const large = try requirements(policy, 1024, .{
        .bytes = 100 * 1024 * 1024,
        .inodes = 2000,
        .source = "test",
    });
    try testing.expectEqual(@as(u64, 400 * 1024 * 1024), large.root_free_bytes);
    try testing.expectEqual(@as(u32, 8000), large.root_free_inodes);
    try testing.expectEqual(@as(u64, 1024 + 400 * 1024 * 1024), large.root_floor_bytes);

    const tiny = try requirements(policy, 1024, .{
        .bytes = 1024,
        .inodes = 1,
        .source = "test",
    });
    try testing.expectEqual(policy.root_free_bytes_floor, tiny.root_free_bytes);
    try testing.expectEqual(policy.root_free_inodes_floor, tiny.root_free_inodes);
}

test "a fitted root below the tree or below the reserve is refused" {
    var measurements = sampleMeasurements();
    measurements.root_fitted_bytes = measurements.root_minimum_bytes - 1;
    try testing.expectError(error.RootBelowMinimum, plan(.{
        .architecture = .x86_64,
        .measurements = measurements,
    }));

    measurements = sampleMeasurements();
    measurements.root_fitted_bytes = measurements.root_minimum_bytes;
    try testing.expectError(error.RootBelowMinimum, plan(.{
        .architecture = .x86_64,
        .measurements = measurements,
    }));
}

test "zero and overflowing measurements are refused rather than rounded" {
    var measurements = sampleMeasurements();
    measurements.signed_uki_bytes = 0;
    try testing.expectError(error.InvalidGeometryInput, plan(.{
        .architecture = .x86_64,
        .measurements = measurements,
    }));

    measurements = sampleMeasurements();
    measurements.esp_minimum_bytes = std.math.maxInt(u64) - 16;
    try testing.expectError(error.InvalidGeometryInput, plan(.{
        .architecture = .x86_64,
        .measurements = measurements,
    }));

    measurements = sampleMeasurements();
    measurements.root_fitted_bytes = std.math.maxInt(u64) - 16;
    try testing.expectError(error.InvalidGeometryInput, plan(.{
        .architecture = .x86_64,
        .measurements = measurements,
    }));
}

test "both architectures plan independently from their own measurements" {
    const x86 = try plan(.{
        .architecture = .x86_64,
        .measurements = sampleMeasurements(),
    });
    var arm_measurements = sampleMeasurements();
    // A larger arm64 UKI and a larger root: nothing forces the two
    // architectures onto a common size.
    arm_measurements.signed_uki_bytes = 71 * 1024 * 1024;
    arm_measurements.esp_minimum_bytes = 148 * 1024 * 1024;
    arm_measurements.root_minimum_bytes = 1600 * 1024 * 1024;
    arm_measurements.root_fitted_bytes = 1729 * 1024 * 1024;
    arm_measurements.first_boot = firstBootGrowth(.aarch64);
    const arm = try plan(.{
        .architecture = .aarch64,
        .measurements = arm_measurements,
    });
    try testing.expect(arm.virtual_size != x86.virtual_size);
    try testing.expect(arm.esp.length_bytes > x86.esp.length_bytes);
    try testing.expect(arm.root.length_bytes > x86.root.length_bytes);
}

test "the same measurements always produce the same disk" {
    const first = try plan(.{ .architecture = .x86_64, .measurements = sampleMeasurements() });
    const second = try plan(.{ .architecture = .x86_64, .measurements = sampleMeasurements() });
    try testing.expectEqual(first.virtual_size, second.virtual_size);
    try testing.expectEqual(first.esp.offset_bytes, second.esp.offset_bytes);
    try testing.expectEqual(first.esp.length_bytes, second.esp.length_bytes);
    try testing.expectEqual(first.root.offset_bytes, second.root.offset_bytes);
    try testing.expectEqual(first.root.length_bytes, second.root.length_bytes);
}

test "the ESP is sized for exactly the resident UKI copies" {
    var buffer: [4]u64 = undefined;
    const lengths = try espContentLengths(.{}, 62 * 1024 * 1024, &buffer);
    try testing.expectEqual(@as(usize, 2), lengths.len);
    try testing.expectEqual(@as(u64, 62 * 1024 * 1024), lengths[0]);
    try testing.expectEqual(@as(u64, 62 * 1024 * 1024), lengths[1]);
    try testing.expectError(
        error.InvalidGeometryInput,
        espContentLengths(.{}, 0, &buffer),
    );
    var small: [1]u64 = undefined;
    try testing.expectError(
        error.InvalidGeometryInput,
        espContentLengths(.{}, 1024, &small),
    );
}

test "a measured first boot beyond the planned bound fails the run that saw it" {
    const bound = firstBootGrowth(.x86_64);
    try assertWithinFirstBootGrowthBound(.x86_64, bound.bytes, bound.inodes);
    try testing.expectError(
        error.FirstBootGrowthExceedsGeometryBound,
        assertWithinFirstBootGrowthBound(.x86_64, bound.bytes + 1, bound.inodes),
    );
    try testing.expectError(
        error.FirstBootGrowthExceedsGeometryBound,
        assertWithinFirstBootGrowthBound(.aarch64, bound.bytes, bound.inodes + 1),
    );
}

test "a report validates against its own measurements" {
    const result = try plan(.{ .architecture = .x86_64, .measurements = sampleMeasurements() });
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const value = try documentValue(arena.allocator(), "core", result, sample_identity);
    var diagnostic: Diagnostic = .{};
    const summary = validateDocument(
        value,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ) catch {
        std.debug.print("{s}\n", .{diagnostic.message()});
        return error.TestUnexpectedResult;
    };
    try testing.expectEqualStrings("x86_64", summary.architecture);
    try testing.expectEqualStrings("core", summary.flavor);
    try testing.expectEqual(result.virtual_size, summary.virtual_size);
    try testing.expect(summary.virtual_size != retired_inherited_virtual_size);
}

test "a report whose offsets were edited is rejected" {
    const result = try plan(.{ .architecture = .x86_64, .measurements = sampleMeasurements() });
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var value = try documentValue(arena.allocator(), "core", result, sample_identity);
    const partitions = value.object.get("partitions").?.array;
    var root = partitions.items[1].object;
    try root.put(
        arena.allocator(),
        "length_bytes",
        .{ .integer = castCount(result.root.length_bytes + alignment) },
    );
    partitions.items[1] = .{ .object = root };
    var diagnostic: Diagnostic = .{};
    try testing.expectError(error.Failed, validateDocument(
        value,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));
}

test "a report that plans the retired inherited size is rejected" {
    // The retired geometry is only reachable by claiming measurements that add
    // up to it, which is exactly the regression this refuses.
    var measurements = sampleMeasurements();
    const head = alignment;
    const tail = alignment;
    const esp = 130 * 1024 * 1024;
    measurements.esp_minimum_bytes = esp;
    measurements.root_fitted_bytes = retired_inherited_virtual_size - head - tail - esp;
    measurements.root_minimum_bytes = measurements.root_fitted_bytes - 512 * 1024 * 1024;
    const result = try plan(.{ .architecture = .x86_64, .measurements = measurements });
    try testing.expectEqual(retired_inherited_virtual_size, result.virtual_size);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const value = try documentValue(arena.allocator(), "core", result, sample_identity);
    var diagnostic: Diagnostic = .{};
    try testing.expectError(error.Failed, validateDocument(
        value,
        .{ .architecture = "x86_64", .flavor = "core" },
        &diagnostic,
    ));
}

test "a report bound to the wrong artifact size is rejected" {
    const result = try plan(.{ .architecture = .x86_64, .measurements = sampleMeasurements() });
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const value = try documentValue(arena.allocator(), "core", result, sample_identity);
    var diagnostic: Diagnostic = .{};
    _ = try validateDocument(value, .{ .virtual_size = result.virtual_size }, &diagnostic);
    try testing.expectError(error.Failed, validateDocument(
        value,
        .{ .virtual_size = result.virtual_size + alignment },
        &diagnostic,
    ));
}
