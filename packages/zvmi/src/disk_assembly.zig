//! Writes a fresh, right-sized GPT disk from trees that were imported from
//! somewhere else.
//!
//! The two assembly paths that predate this one are both closed to that.
//! `preserved_image.rebuild()` copies the source disk whole and repopulates
//! the root partition in place, so its output has the source's geometry by
//! construction -- a rebuild of a 1 TB disk is a 1 TB disk. `build_image`
//! does plan and write a fresh ESP + root disk, but takes its content from an
//! ISO and an OCI image and nothing else. Capturing an installed system needs
//! the middle of those two: an arbitrary tree in, a disk sized to it out.
//!
//! What this deliberately does not do is *make* a system bootable. The ESP is
//! copied across as it stands, kernels and signed EFI binaries included,
//! rather than regenerated from parts. A captured machine already has a boot
//! chain that works, and replacing it with one built here would substitute
//! something the operator never asked for -- and drop its Secure Boot
//! signatures on the way.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const azure = @import("azure.zig");
const bootconfig = @import("bootconfig.zig");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const filesystem_writer = @import("filesystem_writer.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const identity_rewrite = @import("identity_rewrite.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const layout_mod = @import("layout.zig");
const root_tree_mod = @import("root_tree.zig");
const tree_cursor = @import("tree_cursor.zig");
const xfs = @import("xfs.zig");
const xfs_writer = @import("xfs_writer.zig");

const mib: u64 = azure.one_mib;

/// Room left in the root filesystem beyond what the captured tree needs.
/// A captured system boots into a mutable root filesystem, so a filesystem
/// sized to exactly its content is full on first boot: package metadata,
/// logs and the journal all need somewhere to go. The number is a starting
/// point rather than a claim about any particular workload, which is why it
/// is a caller-visible default and not a constant folded into the sizing.
pub const default_root_slack: u64 = 512 * mib;

/// Room left in the EFI system partition beyond its current contents. Much
/// smaller than the root's, because what lands in an ESP after installation
/// is one more kernel at a time.
pub const default_esp_slack: u64 = 16 * mib;

/// How a partition's length is decided.
pub const Size = union(enum) {
    /// The smallest filesystem that holds the tree, plus this much room to
    /// grow. Bytes rather than a percentage: a percentage of a captured
    /// system's used space says nothing about what that system will go on to
    /// write.
    minimum_plus: u64,
    /// An exact length. Refused by name if it is below what the tree needs,
    /// rather than left to fail later inside the filesystem writer.
    exact: u64,
};

/// Which of the assembled image's filesystems now holds a source
/// filesystem's content.
pub const Successor = enum {
    /// The new root filesystem: either the source root itself, or a
    /// filesystem that was merged into it.
    root,
    /// The new EFI system partition.
    esp,
    /// Nothing. References to it are stale and there is no replacement to
    /// offer, which is exactly what the verification pass exists to report.
    none,
};

/// One filesystem the source system had, and where its content went.
pub const SourceFilesystem = struct {
    /// How the captured configuration still names it.
    before: identity_rewrite.Identifiers,
    successor: Successor,
    /// Set when this filesystem stopped being a mount of its own and is now
    /// a plain directory at this absolute path. Its `/etc/fstab` entry is
    /// dropped rather than rewritten.
    merged_at: ?[]const u8 = null,
};

/// How the assembled image's own identifiers replace the source's.
///
/// The `after` side is not a caller input: the whole point of assembling a
/// fresh disk is that its filesystem UUIDs and PARTUUIDs are created here,
/// so the caller states what the source called things and this fills in what
/// they are called now.
pub const IdentityOptions = struct {
    policy: identity_rewrite.Policy = .rewrite_and_verify,
    sources: []const SourceFilesystem = &.{},
    /// Absolute paths inside the root tree that hold EFI system partition
    /// content, for a capture that merged an ESP into the root rather than
    /// carrying it across as a partition.
    merged_esp_roots: []const []const u8 = &.{},
    /// Optional sink for the first surviving stale identifier. Reports are
    /// returned by value, so an assembly that fails on one can only hand it
    /// back through a sink the caller still owns.
    diagnostic: ?*identity_rewrite.Diagnostic = null,
};

/// Fixed values for a reproducible assembly. Everything here is otherwise
/// drawn from the system random source, and every field has to be pinned for
/// two runs of the same tree to produce the same bytes.
pub const Determinism = struct {
    disk_guid: guid.Guid,
    esp_partition_guid: guid.Guid,
    root_partition_guid: guid.Guid,
    root_filesystem_uuid: [16]u8,
    esp_volume_id: u32,
};

pub const AssembleOptions = struct {
    /// Path of the raw disk to create. Created exclusively, because an
    /// assembly that silently overwrote an existing image would destroy the
    /// thing it was most likely pointed at by mistake. A caller that wants
    /// another format, compression, or stdout converts from this and removes
    /// it, exactly as `build-image` and a preserved-image rebuild do with
    /// their own staging files.
    raw_path: []const u8,
    /// Decides the root partition's type GUID, which is what
    /// systemd's discoverable-partitions logic and every modern initramfs
    /// use to find the root without being told.
    architecture: bootconfig.Architecture,

    /// The EFI system partition's contents, already read from wherever they
    /// came from -- `RootTree.mountFat` over the source ESP is the expected
    /// caller. Null writes a root-only disk, which is what a captured data
    /// disk or a BIOS system wants.
    esp_tree: ?*root_tree_mod.RootTree = null,
    esp_size: Size = .{ .minimum_plus = default_esp_slack },
    esp_volume_label: [11]u8 = "EFI        ".*,

    root_size: Size = .{ .minimum_plus = default_root_slack },
    /// Which filesystem the root partition is assembled as. Defaults to ext4,
    /// so an assembly that does not ask for anything else keeps producing
    /// byte-identical ext4 roots. `.xfs` selects the bounded native XFS v5
    /// writer. XFS keeps its own log rather than a JBD2 journal, so pairing it
    /// with `ext4_journal` is rejected (`error.Ext4JournalWithXfsRoot`); the
    /// ESP stays FAT32 regardless.
    root_filesystem: layout_mod.FilesystemKind = .ext4,
    ext4_label: []const u8 = "",
    /// Whether the root filesystem carries a JBD2 journal. Off by default
    /// here only because `ext4.JournalOptions` is off by default everywhere;
    /// a caller assembling a machine's mutable root filesystem should turn
    /// it on, and say so in its own code rather than inherit it.
    ext4_journal: ext4.JournalOptions = .{},
    /// Optional SELinux context for the implicit ext4 root inode. The stored
    /// xattr includes the NUL terminator SELinux tooling expects.
    root_selinux_label: ?[]const u8 = null,
    /// POSIX seconds written to the superblock and to inodes that carry no
    /// time of their own.
    filesystem_timestamp: u32 = 0,

    identity: IdentityOptions = .{},
    deterministic: ?Determinism = null,
    /// Plan and size everything, then stop without creating the disk. The
    /// report is complete except for what only writing can establish.
    dry_run: bool = false,
};

pub const Error = error{
    /// `root_size` was given as an exact length below what the tree needs.
    /// The report's `root_minimum_bytes` is the number it had to clear.
    RootSizeBelowMinimum,
    /// `esp_size` was given as an exact length below what the source ESP's
    /// contents need, or below FAT32's own floor of 65525 clusters.
    EspSizeBelowMinimum,
    /// An ESP size was requested without any ESP contents to size it from.
    MissingEspContents,
    InvalidRootSelinuxLabel,
    /// `root_filesystem` was `.xfs` but `ext4_journal` was enabled. XFS carries
    /// its own internal log, so a JBD2 journal request cannot apply to it and
    /// is refused rather than silently ignored.
    Ext4JournalWithXfsRoot,
    /// `root_filesystem` named a kind this path cannot write as a bootable root
    /// (only ext4 and XFS are valid roots; the ESP's FAT32 is planned
    /// separately).
    UnsupportedRootFilesystem,
    InvalidRawPath,
};

/// The partition of one role in the assembled image.
pub const AssembledPartition = struct {
    offset_bytes: u64,
    length_bytes: u64,
    type_guid: guid.Guid,
    unique_guid: guid.Guid,
    /// Bytes of the partition the filesystem actually spans. Below
    /// `length_bytes` when rounding the filesystem up to the partition
    /// alignment would have produced a size the writer refuses; see
    /// `ext4.minimumPopulateLengthAtLeast`.
    filesystem_length: u64,
};

pub const Report = struct {
    virtual_size: u64,
    disk_guid: guid.Guid,
    root: AssembledPartition,
    esp: ?AssembledPartition,
    /// The smallest root filesystem that holds the tree at all, before any
    /// slack. Stated because it is the number an operator needs to argue
    /// with an explicit `--root-size`, and the number
    /// `RootSizeBelowMinimum` refers to.
    root_minimum_bytes: u64,
    /// The smallest ESP that holds the source ESP's contents, before slack.
    /// Usually FAT32's own floor rather than anything about the contents.
    esp_minimum_bytes: ?u64,
    root_filesystem_uuid: [16]u8,
    esp_volume_id: ?u32,
    /// Blocks the root filesystem's journal occupies, or 0.
    journal_block_count: u32,
    root_node_count: usize,
    esp_node_count: usize,
    /// What the identity reconciliation changed in the root tree, and what
    /// it could not.
    identity_rewrite: identity_rewrite.Report,
    /// The same, for the ESP tree. Zeroed when there is no ESP.
    esp_identity_rewrite: identity_rewrite.Report,
};

/// Reconciles `tree` against the identifiers the assembled image will have,
/// sizes both filesystems from their content, and writes the disk.
///
/// `tree` and `options.esp_tree` are mutated: the identity rewrite edits the
/// `/etc/fstab` and bootloader configuration they contain. That happens
/// before anything is sized, because rewriting a file changes its length and
/// a size solved from the pre-rewrite tree would be a size for a tree that
/// is not the one being written.
pub fn assemble(
    allocator: Allocator,
    io: Io,
    tree: *root_tree_mod.RootTree,
    options: AssembleOptions,
) !Report {
    if (options.raw_path.len == 0) return error.InvalidRawPath;
    if (options.esp_tree == null and options.esp_size == .exact) return error.MissingEspContents;
    // XFS has an internal metadata log, not a JBD2 journal, so an ext4 journal
    // request cannot describe it. Reject the pairing by name before any work.
    if (options.root_filesystem == .xfs and options.ext4_journal.enabled) return error.Ext4JournalWithXfsRoot;

    var root_xattr_buffer: [1]ext4.Xattr = undefined;
    var root_selinux_value: ?[]u8 = null;
    defer if (root_selinux_value) |value| allocator.free(value);
    const ext4_root_xattrs = try buildRootXattrs(
        allocator,
        options.root_selinux_label,
        &root_xattr_buffer,
        &root_selinux_value,
    );
    // XFS carries the same SELinux context faithfully in a shortform xattr, so
    // build the neutral-cursor record from the very bytes `buildRootXattrs`
    // already validated and owns.
    var xfs_root_xattr_buffer: [1]tree_cursor.Xattr = undefined;
    const xfs_root_xattrs: []const tree_cursor.Xattr = if (root_selinux_value) |value| x: {
        xfs_root_xattr_buffer[0] = .{ .name = "security.selinux", .value = value };
        break :x xfs_root_xattr_buffer[0..1];
    } else &.{};

    const identities = resolveIdentities(io, options.deterministic);

    // The rewrite runs before the sizing, and the sizing before any output
    // file exists. A tree that still names a retired identifier therefore
    // costs a rejection rather than a published image that does not boot.
    const rewrites = try applyIdentityRewrite(allocator, tree, options, identities);

    const esp_minimum: ?u64 = if (options.esp_tree) |esp_tree| blk: {
        const size = try filesystem_writer.minimumLength(allocator, esp_tree, .fat32, .{
            .fat32 = .{
                .populate = .{ .metadata_policy = .lossy_posix_metadata },
                .volume = .{ .alignment = layout_mod.default_alignment },
            },
        });
        break :blk size.length;
    } else null;
    const esp_length: ?u64 = if (esp_minimum) |minimum| switch (options.esp_size) {
        .minimum_plus => |slack| alignUp(try add(minimum, slack)),
        .exact => |exact| blk: {
            if (exact < minimum) return error.EspSizeBelowMinimum;
            break :blk alignUp(exact);
        },
    } else null;

    const ext4_populate = ext4.PopulateOptions{
        .length = 0,
        .label = options.ext4_label,
        .root_xattrs = ext4_root_xattrs,
        .uuid = identities.root_filesystem_uuid,
        .timestamp = options.filesystem_timestamp,
        .journal = options.ext4_journal,
    };
    const xfs_populate = xfs_writer.PopulateOptions{
        .format = .{
            .length = 0,
            .label = options.ext4_label,
            .uuid = identities.root_filesystem_uuid,
            .timestamp = .{ .sec = options.filesystem_timestamp, .nsec = 0 },
        },
        // The captured root inode mirrors ext4's implicit root (mode 0o755,
        // root:root); null times fall back to the filesystem-wide timestamp.
        .root = .{ .mode = 0o755, .uid = 0, .gid = 0, .xattrs = xfs_root_xattrs },
    };
    const root_size_options: filesystem_writer.SizeOptions = switch (options.root_filesystem) {
        .ext4 => .{ .ext4 = ext4_populate },
        .xfs => .{ .xfs = xfs_populate },
        .fat32 => return error.UnsupportedRootFilesystem,
    };
    const root_minimum = try filesystem_writer.minimumLength(allocator, tree, options.root_filesystem, root_size_options);
    const root_floor = switch (options.root_size) {
        .minimum_plus => |slack| try add(root_minimum.length, slack),
        .exact => |exact| blk: {
            if (exact < root_minimum.length) return error.RootSizeBelowMinimum;
            break :blk exact;
        },
    };
    // Not simply `root_floor`: whether the writer accepts a length is not
    // monotone in the length, so the aligned size a caller asked for may be
    // one the layout refuses. Solving for it here is what keeps that from
    // surfacing as a bare `NotEnoughSpace` at write time.
    const root_fit = try filesystem_writer.minimumLengthAtLeast(
        allocator,
        tree,
        options.root_filesystem,
        root_size_options,
        root_floor,
    );

    const planned = try planPartitions(allocator, options.architecture, options.root_filesystem, esp_length, root_fit.length);
    defer allocator.free(planned.partitions);

    const esp_partition: ?AssembledPartition = if (findRole(planned.partitions, .esp)) |part| .{
        .offset_bytes = part.offset_bytes,
        .length_bytes = part.length_bytes,
        .type_guid = part.type_guid,
        .unique_guid = identities.esp_partition_guid,
        .filesystem_length = part.length_bytes,
    } else null;
    const root_planned = planned.partitions[planned.partitions.len - 1];
    const root_partition = AssembledPartition{
        .offset_bytes = root_planned.offset_bytes,
        .length_bytes = root_planned.length_bytes,
        .type_guid = root_planned.type_guid,
        .unique_guid = identities.root_partition_guid,
        .filesystem_length = root_fit.length,
    };

    var report = Report{
        .virtual_size = planned.disk_size,
        .disk_guid = identities.disk_guid,
        .root = root_partition,
        .esp = esp_partition,
        .root_minimum_bytes = root_minimum.length,
        .esp_minimum_bytes = esp_minimum,
        .root_filesystem_uuid = identities.root_filesystem_uuid,
        .esp_volume_id = if (esp_partition != null) identities.esp_volume_id else null,
        .journal_block_count = root_fit.ext4_journal_block_count orelse 0,
        .root_node_count = tree.nodeCount(),
        .esp_node_count = if (options.esp_tree) |esp_tree| esp_tree.nodeCount() else 0,
        .identity_rewrite = rewrites.root,
        .esp_identity_rewrite = rewrites.esp,
    };
    if (options.dry_run) return report;

    var img = try Image.createExclusive(io, options.raw_path, .raw, planned.disk_size, .{});
    var img_open = true;
    defer if (img_open) img.close(io);
    // Creation is exclusive, so a half-written disk left behind by a failure
    // here would make the retry fail with `PathAlreadyExists` and hide what
    // actually went wrong. `createExclusive` only cleans up after its own
    // failure; everything past this point is ours to undo.
    errdefer Io.Dir.cwd().deleteFile(io, options.raw_path) catch {};

    try writeGpt(allocator, &img, io, identities.disk_guid, planned.partitions, esp_partition, root_partition);

    if (options.esp_tree) |esp_tree| {
        const partition = esp_partition.?;
        const esp_planned = findRole(planned.partitions, .esp).?;
        _ = try filesystem_writer.formatAndPopulate(io, allocator, &img, esp_tree, esp_planned.filesystem, .{
            .fat32 = .{
                .format = .{
                    .partition_offset = partition.offset_bytes,
                    .partition_len = partition.length_bytes,
                    .volume_id = identities.esp_volume_id,
                    .volume_label = options.esp_volume_label,
                },
                .populate = .{ .metadata_policy = .lossy_posix_metadata },
            },
        });
    }

    const root_format_options: filesystem_writer.FormatOptions = switch (options.root_filesystem) {
        .ext4 => blk: {
            var root_populate = ext4_populate;
            root_populate.offset = root_partition.offset_bytes;
            root_populate.length = root_partition.filesystem_length;
            break :blk .{ .ext4 = root_populate };
        },
        .xfs => blk: {
            var root_populate = xfs_populate;
            root_populate.format.offset = root_partition.offset_bytes;
            root_populate.format.length = root_partition.filesystem_length;
            break :blk .{ .xfs = root_populate };
        },
        .fat32 => return error.UnsupportedRootFilesystem,
    };
    const populate_result = try filesystem_writer.formatAndPopulate(
        io,
        allocator,
        &img,
        tree,
        root_planned.filesystem,
        root_format_options,
    );
    // Only ext4 has a journal to report; XFS's own log is not a JBD2 journal,
    // so an honest count for it is zero rather than a borrowed ext4 field.
    report.journal_block_count = switch (populate_result) {
        .ext4 => |info| info.journal_block_count,
        else => 0,
    };

    img.close(io);
    img_open = false;
    return report;
}

fn buildRootXattrs(
    allocator: Allocator,
    label: ?[]const u8,
    buffer: *[1]ext4.Xattr,
    owned: *?[]u8,
) ![]const ext4.Xattr {
    const text = label orelse return &.{};
    if (text.len == 0 or std.mem.indexOfScalar(u8, text, 0) != null) {
        return error.InvalidRootSelinuxLabel;
    }
    const value = try allocator.alloc(u8, text.len + 1);
    @memcpy(value[0..text.len], text);
    value[text.len] = 0;
    owned.* = value;
    buffer[0] = .{ .name = "security.selinux", .value = value };
    return buffer;
}

const Identities = struct {
    disk_guid: guid.Guid,
    esp_partition_guid: guid.Guid,
    root_partition_guid: guid.Guid,
    root_filesystem_uuid: [16]u8,
    esp_volume_id: u32,
};

fn resolveIdentities(io: Io, deterministic: ?Determinism) Identities {
    if (deterministic) |values| return .{
        .disk_guid = values.disk_guid,
        .esp_partition_guid = values.esp_partition_guid,
        .root_partition_guid = values.root_partition_guid,
        .root_filesystem_uuid = values.root_filesystem_uuid,
        .esp_volume_id = values.esp_volume_id,
    };
    var filesystem_uuid: [16]u8 = undefined;
    Io.random(io, &filesystem_uuid);
    var volume_id: u32 = 0;
    while (volume_id == 0) Io.random(io, std.mem.asBytes(&volume_id));
    return .{
        .disk_guid = randomGuid(io),
        .esp_partition_guid = randomGuid(io),
        .root_partition_guid = randomGuid(io),
        .root_filesystem_uuid = filesystem_uuid,
        .esp_volume_id = volume_id,
    };
}

fn randomGuid(io: Io) guid.Guid {
    var bytes: guid.Guid = undefined;
    Io.random(io, &bytes);
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    return bytes;
}

const Rewrites = struct {
    root: identity_rewrite.Report,
    esp: identity_rewrite.Report,
};

/// Reconciles both trees against the identifiers this assembly creates.
///
/// The ESP is reconciled as a tree of its own rather than through
/// `Plan.esp_roots`, which names a subtree of a root filesystem and has no
/// way to name a whole separate partition. Skipping it would leave the one
/// place a captured system most reliably records its root filesystem's UUID
/// -- the vendor `grub.cfg` next to shim -- naming a filesystem that no
/// longer exists.
fn applyIdentityRewrite(
    allocator: Allocator,
    tree: *root_tree_mod.RootTree,
    options: AssembleOptions,
    identities: Identities,
) !Rewrites {
    if (options.identity.policy == .off or options.identity.sources.len == 0) {
        return .{ .root = .{}, .esp = .{} };
    }

    var root_uuid_text: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    const root_filesystem_uuid = identity_rewrite.formatFilesystemUuid(
        &root_uuid_text,
        &identities.root_filesystem_uuid,
    );
    var root_partuuid_text: [36]u8 = undefined;
    const root_partition_uuid = guid.formatLower(&root_partuuid_text, identities.root_partition_guid);
    var esp_serial_text: [identity_rewrite.fat_serial_bytes]u8 = undefined;
    const esp_filesystem_uuid = identity_rewrite.formatFatVolumeSerial(
        &esp_serial_text,
        identities.esp_volume_id,
    );
    var esp_partuuid_text: [36]u8 = undefined;
    const esp_partition_uuid = guid.formatLower(&esp_partuuid_text, identities.esp_partition_guid);

    const has_esp = options.esp_tree != null;
    const filesystems = try allocator.alloc(identity_rewrite.Filesystem, options.identity.sources.len);
    defer allocator.free(filesystems);
    for (options.identity.sources, filesystems) |source, *slot| {
        slot.* = .{
            .before = source.before,
            .after = switch (source.successor) {
                .root => .{
                    .filesystem_uuid = root_filesystem_uuid,
                    .partition_uuid = root_partition_uuid,
                    .filesystem_label = if (options.ext4_label.len == 0) null else options.ext4_label,
                    .partition_label = root_partition_name,
                },
                // An ESP successor without an ESP retires without a
                // replacement, which is the honest answer rather than a
                // reference to a partition the image does not have.
                .esp => if (has_esp) .{
                    .filesystem_uuid = esp_filesystem_uuid,
                    .partition_uuid = esp_partition_uuid,
                    .partition_label = esp_partition_name,
                } else .{},
                .none => .{},
            },
            .merged_at = source.merged_at,
        };
    }

    const plan = identity_rewrite.Plan{
        .filesystems = filesystems,
        .esp_roots = options.identity.merged_esp_roots,
    };
    const root_report = try identity_rewrite.apply(
        allocator,
        tree,
        plan,
        options.identity.policy,
        options.identity.diagnostic,
    );

    var esp_report = identity_rewrite.Report{};
    if (options.esp_tree) |esp_tree| {
        var esp_plan = plan;
        esp_plan.esp_roots = &.{};
        esp_plan.tree_is_esp = true;
        esp_report = try identity_rewrite.apply(
            allocator,
            esp_tree,
            esp_plan,
            options.identity.policy,
            options.identity.diagnostic,
        );
    }
    return .{ .root = root_report, .esp = esp_report };
}

const esp_partition_name = "ESP";
const root_partition_name = "root";

const PlannedDisk = struct {
    disk_size: u64,
    partitions: []layout_mod.PlannedPartition,
};

/// Sizes the disk around the partitions rather than the other way round.
/// Every other caller of `layout.planLayout` starts from a disk size an
/// operator chose and divides it up; here the partition lengths are already
/// known and the disk is whatever holds them plus GPT's own reservations at
/// both ends.
fn planPartitions(
    allocator: Allocator,
    architecture: bootconfig.Architecture,
    root_filesystem: layout_mod.FilesystemKind,
    esp_length: ?u64,
    root_filesystem_length: u64,
) !PlannedDisk {
    const root_role: layout_mod.PartitionRole = switch (architecture) {
        .x86_64 => .root_x86_64,
        .aarch64 => .root_aarch64,
    };
    var requests: [2]layout_mod.PartitionRequest = undefined;
    var count: usize = 0;
    if (esp_length) |length| {
        requests[count] = .{ .name = esp_partition_name, .role = .esp, .filesystem = .fat32, .size = .{ .fixed = length } };
        count += 1;
    }
    const root_length = alignUp(root_filesystem_length);
    requests[count] = .{ .name = root_partition_name, .role = root_role, .filesystem = root_filesystem, .size = .{ .fixed = root_length } };
    count += 1;

    // The first partition starts at the first aligned offset past the
    // primary GPT, and the backup GPT sits in the last sectors. Both ends
    // are rounded to the alignment so the disk is a whole number of
    // megabytes, which is what every hypervisor and every `ls -l` expects.
    const head = layout_mod.default_alignment;
    const tail = alignUp((1 + gpt.partition_array_sectors) * gpt.sector_size);
    var payload: u64 = 0;
    for (requests[0..count]) |request| payload = try add(payload, request.size.fixed);
    const disk_size = try add(try add(head, payload), tail);

    return .{
        .disk_size = disk_size,
        .partitions = try layout_mod.planLayout(allocator, disk_size, requests[0..count], null),
    };
}

fn findRole(
    partitions: []const layout_mod.PlannedPartition,
    role: layout_mod.PartitionRole,
) ?layout_mod.PlannedPartition {
    for (partitions) |partition| {
        if (partition.role == role) return partition;
    }
    return null;
}

fn writeGpt(
    allocator: Allocator,
    img: *Image,
    io: Io,
    disk_guid: guid.Guid,
    planned: []const layout_mod.PlannedPartition,
    esp: ?AssembledPartition,
    root: AssembledPartition,
) !void {
    const specs = try allocator.alloc(gpt.PlacedPartitionSpec, planned.len);
    defer allocator.free(specs);
    for (planned, specs) |partition, *spec| {
        const unique_guid = if (partition.role == .esp) esp.?.unique_guid else root.unique_guid;
        spec.* = .{
            .type_guid = partition.type_guid,
            .unique_guid = unique_guid,
            .placement = .{
                .first_lba = partition.firstLba(),
                .last_lba = partition.lastLba(),
            },
            .name_utf16le = gpt.asciiName(partition.name),
        };
    }
    try gpt.writeGptPlaced(img, io, disk_guid, specs);
}

fn alignUp(value: u64) u64 {
    return azure.alignSizeToMib(value);
}

fn add(a: u64, b: u64) !u64 {
    return std.math.add(u64, a, b) catch error.FilesystemTooLarge;
}

// ---------------------------------------------------------------------------
// Tests
//
// The property under test throughout is that the disk is a function of what
// went into it. A capture's whole reason for existing is that the output is
// smaller than the machine it came from, so every test here checks the size
// it got as well as the bytes.
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_determinism = Determinism{
    // Written as bytes rather than parsed: a GUID string is mixed-endian,
    // and repeating one byte sidesteps both that and the comptime cost of
    // parsing three of them.
    .disk_guid = [_]u8{0x11} ** 16,
    .esp_partition_guid = [_]u8{0x22} ** 16,
    .root_partition_guid = [_]u8{0x33} ** 16,
    .root_filesystem_uuid = [_]u8{0x44} ** 16,
    .esp_volume_id = 0xABCD_1234,
};

const source_root_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const source_esp_serial = "1234-ABCD";

/// A stand-in for a captured installed system: an fstab that names the root
/// filesystem and the ESP by identifier, a few megabytes of payload, and the
/// empty `/boot/efi` directory the ESP mounts over.
fn buildSourceRoot(io: Io, spool_path: []const u8) !root_tree_mod.RootTree {
    var tree = try root_tree_mod.RootTree.init(testing.allocator, io, spool_path, .{});
    errdefer tree.deinit();
    try tree.putDirectory("boot", .{ .mode = 0o755 });
    try tree.putDirectory("boot/efi", .{ .mode = 0o755 });
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putFileBytes(
        "etc/fstab",
        "UUID=" ++ source_root_uuid ++ " / ext4 defaults 0 1\n" ++
            "UUID=" ++ source_esp_serial ++ " /boot/efi vfat umask=0077 0 2\n",
        .{ .mode = 0o644 },
    );
    try tree.putFileBytes("etc/hostname", "captured\n", .{ .mode = 0o644 });
    try tree.putDirectory("usr", .{ .mode = 0o755 });
    const payload = try testing.allocator.alloc(u8, 3 * 1024 * 1024);
    defer testing.allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);
    try tree.putFileBytes("usr/payload.bin", payload, .{ .mode = 0o644 });
    return tree;
}

/// The source ESP, holding the one thing that makes copying it across
/// non-trivial: a vendor `grub.cfg` that names the root filesystem by UUID.
fn buildSourceEsp(io: Io, spool_path: []const u8) !root_tree_mod.RootTree {
    var tree = try root_tree_mod.RootTree.init(testing.allocator, io, spool_path, .{});
    errdefer tree.deinit();
    try tree.putDirectory("EFI", .{ .mode = 0o755 });
    try tree.putDirectory("EFI/BOOT", .{ .mode = 0o755 });
    try tree.putFileBytes("EFI/BOOT/BOOTX64.EFI", "not really a PE binary", .{ .mode = 0o644 });
    try tree.putDirectory("EFI/vendor", .{ .mode = 0o755 });
    try tree.putFileBytes(
        "EFI/vendor/grub.cfg",
        "search --no-floppy --fs-uuid --set=root " ++ source_root_uuid ++ "\n" ++
            "linux /boot/vmlinuz root=UUID=" ++ source_root_uuid ++ " ro\n",
        .{ .mode = 0o644 },
    );
    return tree;
}

fn captureSources() [2]SourceFilesystem {
    return .{
        .{ .before = .{ .filesystem_uuid = source_root_uuid }, .successor = .root },
        .{ .before = .{ .filesystem_uuid = source_esp_serial }, .successor = .esp },
    };
}

/// Copies one partition out of a disk image so external tools that have no
/// concept of an offset can be pointed at it.
fn extractPartition(io: Io, disk_path: []const u8, out_path: []const u8, offset: u64, length: u64) !void {
    var disk = try Image.openPathReadOnly(io, disk_path);
    defer disk.close(io);
    var out = try Image.create(io, out_path, .raw, length, .{});
    defer out.close(io);

    const buffer = try testing.allocator.alloc(u8, 1024 * 1024);
    defer testing.allocator.free(buffer);
    var copied: u64 = 0;
    while (copied < length) {
        const chunk: usize = @intCast(@min(@as(u64, buffer.len), length - copied));
        const got = try disk.pread(io, buffer[0..chunk], offset + copied);
        if (got != chunk) return error.UnexpectedEndOfFile;
        try out.pwrite(io, buffer[0..chunk], copied);
        copied += chunk;
    }
}

test "assembles a disk sized to its content, with both filesystems readable" {
    const io = testing.io;
    const raw_path = "test-disk-assembly-basic.img";
    const root_spool = "test-disk-assembly-basic.root-spool";
    const esp_spool = "test-disk-assembly-basic.esp-spool";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};

    var root = try buildSourceRoot(io, root_spool);
    defer root.deinit();
    var esp = try buildSourceEsp(io, esp_spool);
    defer esp.deinit();

    const sources = captureSources();
    const report = try assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .x86_64,
        .esp_tree = &esp,
        .root_size = .{ .minimum_plus = 8 * mib },
        .ext4_label = "captured",
        .filesystem_timestamp = 1_717_171_717,
        .identity = .{ .sources = &sources },
        .deterministic = test_determinism,
    });

    // The whole point: a disk sized to a few megabytes of content, not to
    // the machine it was captured from. The ESP dominates, because FAT32
    // cannot have fewer than 65525 clusters however empty it is.
    try testing.expect(report.virtual_size < 96 * mib);
    try testing.expect(report.root.filesystem_length >= report.root_minimum_bytes + 8 * mib);
    try testing.expect(report.esp.?.length_bytes >= report.esp_minimum_bytes.?);
    try testing.expectEqual(@as(u32, 0), report.journal_block_count);
    try testing.expectEqualSlices(u8, &guid.esp, &report.esp.?.type_guid);
    try testing.expectEqualSlices(u8, &guid.linux_root_x86_64, &report.root.type_guid);

    var img = try Image.openPathReadOnly(io, raw_path);
    defer img.close(io);
    try testing.expectEqual(report.virtual_size, img.virtual_size);

    const parsed = try gpt.readGpt(img, io, testing.allocator);
    defer testing.allocator.free(parsed.partitions);
    try testing.expectEqual(@as(usize, 2), parsed.partitions.len);
    try testing.expectEqualSlices(u8, &test_determinism.disk_guid, &parsed.header.disk_guid);
    try testing.expectEqualSlices(u8, &test_determinism.esp_partition_guid, &parsed.partitions[0].unique_partition_guid);
    try testing.expectEqualSlices(u8, &test_determinism.root_partition_guid, &parsed.partitions[1].unique_partition_guid);
    try testing.expectEqual(report.esp.?.offset_bytes / gpt.sector_size, parsed.partitions[0].first_lba);
    try testing.expectEqual(report.root.offset_bytes / gpt.sector_size, parsed.partitions[1].first_lba);

    // The root filesystem's fstab now names the identifiers this image has,
    // not the ones the captured machine had.
    var reader = try ext4.open(io, img.file, testing.allocator, .{ .offset = report.root.offset_bytes });
    defer reader.deinit();
    const fstab = try reader.readFileAlloc(io, testing.allocator, "etc/fstab");
    defer testing.allocator.free(fstab);
    var expected_uuid: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    const new_root_uuid = identity_rewrite.formatFilesystemUuid(&expected_uuid, &test_determinism.root_filesystem_uuid);
    try testing.expect(std.mem.indexOf(u8, fstab, new_root_uuid) != null);
    try testing.expect(std.mem.indexOf(u8, fstab, source_root_uuid) == null);

    // And so does the boot chain on the ESP, which is a separate partition
    // and so a separate tree: nothing in the root filesystem's own rewrite
    // pass would ever have looked at it.
    var esp_fs = try fat32.open(&img, io, .{
        .offset = report.esp.?.offset_bytes,
        .length = report.esp.?.length_bytes,
    });
    const grub_cfg = try esp_fs.readFileAlloc(io, testing.allocator, "EFI/vendor/grub.cfg");
    defer testing.allocator.free(grub_cfg);
    try testing.expect(std.mem.indexOf(u8, grub_cfg, new_root_uuid) != null);
    try testing.expect(std.mem.indexOf(u8, grub_cfg, source_root_uuid) == null);
    const boot_efi = try esp_fs.readFileAlloc(io, testing.allocator, "EFI/BOOT/BOOTX64.EFI");
    defer testing.allocator.free(boot_efi);
    try testing.expectEqualSlices(u8, "not really a PE binary", boot_efi);

    try testing.expect(report.identity_rewrite.fstab_entries_rewritten > 0);
    try testing.expect(report.esp_identity_rewrite.config_references_rewritten > 0);
    try testing.expectEqual(@as(usize, 0), report.identity_rewrite.stale_references);
    try testing.expectEqual(@as(usize, 0), report.esp_identity_rewrite.stale_references);
}

test "the assembled root filesystem passes a real e2fsck" {
    const io = testing.io;
    const raw_path = "test-disk-assembly-e2fsck.img";
    const part_path = "test-disk-assembly-e2fsck.root";
    const root_spool = "test-disk-assembly-e2fsck.root-spool";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, part_path) catch {};

    var root = try buildSourceRoot(io, root_spool);
    defer root.deinit();

    const report = try assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .aarch64,
        .root_size = .{ .minimum_plus = 64 * mib },
        .ext4_label = "captured",
        // A captured machine boots into a mutable root filesystem, so this
        // is the setting that path uses; an unclean shutdown without it has
        // nothing to replay.
        .ext4_journal = .{ .enabled = true },
        .filesystem_timestamp = 1_717_171_717,
        .deterministic = test_determinism,
    });
    try testing.expect(report.esp == null);
    try testing.expect(report.journal_block_count > 0);
    try testing.expectEqualSlices(u8, &guid.linux_root_aarch64, &report.root.type_guid);

    try extractPartition(io, raw_path, part_path, report.root.offset_bytes, report.root.filesystem_length);
    try ext4.expectE2fsckClean(part_path);
}

test "the assembled xfs root passes a real xfs_repair" {
    const io = testing.io;
    const raw_path = "test-disk-assembly-xfs-repair.img";
    const part_path = "test-disk-assembly-xfs-repair.root";
    const root_spool = "test-disk-assembly-xfs-repair.root-spool";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, part_path) catch {};

    var root = try buildSourceRoot(io, root_spool);
    defer root.deinit();

    const report = try assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .aarch64,
        .root_filesystem = .xfs,
        .root_size = .{ .minimum_plus = 8 * mib },
        .ext4_label = "captured",
        .filesystem_timestamp = 1_717_171_717,
        .deterministic = test_determinism,
    });
    try testing.expect(report.esp == null);
    try testing.expectEqual(@as(u32, 0), report.journal_block_count);
    try testing.expectEqualSlices(u8, &guid.linux_root_aarch64, &report.root.type_guid);

    // Extract just the root filesystem so an external checker that has no
    // concept of a partition offset can be pointed at it, then let the real
    // xfsprogs verifier attest the bytes this project's writer produced.
    try extractPartition(io, raw_path, part_path, report.root.offset_bytes, report.root.filesystem_length);
    try xfs.expectXfsRepairClean(part_path);
}

test "assembles an xfs root that its own reader reads back, rewritten and journal-free" {
    const io = testing.io;
    const raw_path = "test-disk-assembly-xfs.img";
    const root_spool = "test-disk-assembly-xfs.root-spool";
    const esp_spool = "test-disk-assembly-xfs.esp-spool";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};

    var root = try buildSourceRoot(io, root_spool);
    defer root.deinit();
    var esp = try buildSourceEsp(io, esp_spool);
    defer esp.deinit();

    const sources = captureSources();
    const report = try assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .x86_64,
        .root_filesystem = .xfs,
        .esp_tree = &esp,
        // XFS keeps a 64 MiB internal log, so its minimum is far above ext4's;
        // the sizing seam finds that floor and this only asks for headroom.
        .root_size = .{ .minimum_plus = 4 * mib },
        .ext4_label = "captured",
        .filesystem_timestamp = 1_717_171_717,
        .identity = .{ .sources = &sources },
        .deterministic = test_determinism,
    });
    // XFS logs internally; the ext4 JBD2 count is honestly zero, not borrowed.
    try testing.expectEqual(@as(u32, 0), report.journal_block_count);
    try testing.expectEqualSlices(u8, &guid.linux_root_x86_64, &report.root.type_guid);
    // The ESP is unaffected by the root filesystem choice: still FAT32.
    try testing.expectEqualSlices(u8, &guid.esp, &report.esp.?.type_guid);

    var img = try Image.openPathReadOnly(io, raw_path);
    defer img.close(io);
    try testing.expectEqual(report.virtual_size, img.virtual_size);

    var reader = try xfs.Reader.openFileAt(testing.allocator, io, img.file, report.root.offset_bytes);
    defer reader.close(io);
    var rtree = try xfs.scanReadable(&reader, io, testing.allocator, .{ .available_length = report.root.filesystem_length });
    defer rtree.deinit();

    // The label the assembler was given round-trips through the XFS superblock.
    try testing.expectEqualSlices(u8, "captured\x00\x00\x00\x00", &rtree.identity.label);

    // The same identity rewrite that ext4 gets runs on the tree before the XFS
    // writer sees it, so the fstab this image carries names its own new UUID.
    var expected_uuid: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    const new_root_uuid = identity_rewrite.formatFilesystemUuid(&expected_uuid, &test_determinism.root_filesystem_uuid);

    var found_fstab = false;
    var index: usize = 0;
    while (index < rtree.nodeCount()) : (index += 1) {
        const entry = rtree.entryAt(index);
        if (!std.mem.eql(u8, entry.path, "etc/fstab")) continue;
        found_fstab = true;
        const content = entry.content orelse return error.MissingContent;
        const buffer = try testing.allocator.alloc(u8, @intCast(entry.size));
        defer testing.allocator.free(buffer);
        var done: usize = 0;
        while (done < buffer.len) {
            const got = try content.readAt(buffer[done..], done);
            if (got == 0) break;
            done += got;
        }
        try testing.expect(std.mem.indexOf(u8, buffer[0..done], new_root_uuid) != null);
        try testing.expect(std.mem.indexOf(u8, buffer[0..done], source_root_uuid) == null);
    }
    try testing.expect(found_fstab);
    try testing.expect(report.identity_rewrite.fstab_entries_rewritten > 0);

    // The ESP really is a FAT32 volume next to the XFS root, and its boot chain
    // was rewritten to the same new root UUID.
    var esp_fs = try fat32.open(&img, io, .{
        .offset = report.esp.?.offset_bytes,
        .length = report.esp.?.length_bytes,
    });
    const grub_cfg = try esp_fs.readFileAlloc(io, testing.allocator, "EFI/vendor/grub.cfg");
    defer testing.allocator.free(grub_cfg);
    try testing.expect(std.mem.indexOf(u8, grub_cfg, new_root_uuid) != null);
    try testing.expect(std.mem.indexOf(u8, grub_cfg, source_root_uuid) == null);
}

test "an ext4 journal requested with an xfs root is refused by name" {
    const io = testing.io;
    const raw_path = "test-disk-assembly-xfs-journal.img";
    const root_spool = "test-disk-assembly-xfs-journal.root-spool";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};

    var root = try buildSourceRoot(io, root_spool);
    defer root.deinit();

    try testing.expectError(error.Ext4JournalWithXfsRoot, assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .x86_64,
        .root_filesystem = .xfs,
        .ext4_journal = .{ .enabled = true },
        .deterministic = test_determinism,
        .dry_run = true,
    }));
}

test "an exact size below what the tree needs is refused by name" {
    const io = testing.io;
    const raw_path = "test-disk-assembly-too-small.img";
    const root_spool = "test-disk-assembly-too-small.root-spool";
    const esp_spool = "test-disk-assembly-too-small.esp-spool";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};

    var root = try buildSourceRoot(io, root_spool);
    defer root.deinit();
    var esp = try buildSourceEsp(io, esp_spool);
    defer esp.deinit();

    const planned = try assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .x86_64,
        .esp_tree = &esp,
        .deterministic = test_determinism,
        .dry_run = true,
    });

    try testing.expectError(error.RootSizeBelowMinimum, assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .x86_64,
        .esp_tree = &esp,
        .root_size = .{ .exact = planned.root_minimum_bytes - 1 },
        .deterministic = test_determinism,
    }));
    try testing.expectError(error.EspSizeBelowMinimum, assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .x86_64,
        .esp_tree = &esp,
        .esp_size = .{ .exact = planned.esp_minimum_bytes.? - 1 },
        .deterministic = test_determinism,
    }));

    // An exact size at the minimum is accepted, which is what makes the
    // refusals above a boundary rather than a margin.
    const exact = try assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .x86_64,
        .esp_tree = &esp,
        .root_size = .{ .exact = planned.root_minimum_bytes },
        .esp_size = .{ .exact = planned.esp_minimum_bytes.? },
        .deterministic = test_determinism,
        .dry_run = true,
    });
    try testing.expectEqual(planned.root_minimum_bytes, exact.root.filesystem_length);
}

test "a dry run plans the whole disk and writes nothing" {
    const io = testing.io;
    const raw_path = "test-disk-assembly-dry-run.img";
    const root_spool = "test-disk-assembly-dry-run.root-spool";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};

    var root = try buildSourceRoot(io, root_spool);
    defer root.deinit();

    const report = try assemble(testing.allocator, io, &root, .{
        .raw_path = raw_path,
        .architecture = .x86_64,
        .deterministic = test_determinism,
        .dry_run = true,
    });
    try testing.expect(report.virtual_size > 0);
    try testing.expect(report.root.length_bytes >= report.root.filesystem_length);
    try testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().openFile(io, raw_path, .{}),
    );
}

test "the root filesystem is sized from the tree, not from the disk it came from" {
    const io = testing.io;
    const small_path = "test-disk-assembly-small.img";
    const large_path = "test-disk-assembly-large.img";
    const small_spool = "test-disk-assembly-small.spool";
    const large_spool = "test-disk-assembly-large.spool";
    defer Io.Dir.cwd().deleteFile(io, small_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, large_path) catch {};

    var small = try buildSourceRoot(io, small_spool);
    defer small.deinit();
    var large = try buildSourceRoot(io, large_spool);
    defer large.deinit();
    const bulk = try testing.allocator.alloc(u8, 24 * 1024 * 1024);
    defer testing.allocator.free(bulk);
    for (bulk, 0..) |*byte, index| byte.* = @truncate(index *% 7);
    try large.putFileBytes("usr/bulk.bin", bulk, .{ .mode = 0o644 });

    const small_report = try assemble(testing.allocator, io, &small, .{
        .raw_path = small_path,
        .architecture = .x86_64,
        .root_size = .{ .minimum_plus = 0 },
        .deterministic = test_determinism,
        .dry_run = true,
    });
    const large_report = try assemble(testing.allocator, io, &large, .{
        .raw_path = large_path,
        .architecture = .x86_64,
        .root_size = .{ .minimum_plus = 0 },
        .deterministic = test_determinism,
        .dry_run = true,
    });

    // Twenty-four more megabytes of content buys twenty-four more megabytes
    // of disk, give or take the metadata they need. Nothing else changed.
    const growth = large_report.virtual_size - small_report.virtual_size;
    try testing.expect(growth >= 24 * mib);
    try testing.expect(growth < 26 * mib);
}

test "two assemblies of the same tree with the same identities are byte-identical" {
    const io = testing.io;
    const first_path = "test-disk-assembly-determinism-1.img";
    const second_path = "test-disk-assembly-determinism-2.img";
    const root_spool = "test-disk-assembly-determinism.root-spool";
    const esp_spool = "test-disk-assembly-determinism.esp-spool";
    defer Io.Dir.cwd().deleteFile(io, first_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, second_path) catch {};

    var root = try buildSourceRoot(io, root_spool);
    defer root.deinit();
    var esp = try buildSourceEsp(io, esp_spool);
    defer esp.deinit();

    const sources = captureSources();
    const options = AssembleOptions{
        .raw_path = first_path,
        .architecture = .x86_64,
        .esp_tree = &esp,
        .root_size = .{ .minimum_plus = 4 * mib },
        .ext4_label = "captured",
        .filesystem_timestamp = 1_717_171_717,
        .identity = .{ .sources = &sources },
        .deterministic = test_determinism,
    };

    const first = try assemble(testing.allocator, io, &root, options);
    var second_options = options;
    second_options.raw_path = second_path;
    // The same trees again: the identity rewrite has already run over them
    // once, so this also checks that a second pass finds nothing left to do
    // rather than rewriting its own output.
    const second = try assemble(testing.allocator, io, &root, second_options);

    try testing.expectEqual(first.virtual_size, second.virtual_size);
    try testing.expectEqual(first.root.offset_bytes, second.root.offset_bytes);
    try testing.expectEqual(first.esp.?.length_bytes, second.esp.?.length_bytes);
    // Nothing was left to rewrite the second time round, which is what makes
    // the rewrite idempotent rather than merely repeatable.
    try testing.expectEqual(@as(usize, 0), second.identity_rewrite.config_references_rewritten);
    try testing.expectEqual(@as(usize, 0), second.esp_identity_rewrite.config_references_rewritten);

    var first_img = try Image.openPathReadOnly(io, first_path);
    defer first_img.close(io);
    var second_img = try Image.openPathReadOnly(io, second_path);
    defer second_img.close(io);

    const chunk = 1024 * 1024;
    const left = try testing.allocator.alloc(u8, chunk);
    defer testing.allocator.free(left);
    const right = try testing.allocator.alloc(u8, chunk);
    defer testing.allocator.free(right);

    var offset: u64 = 0;
    while (offset < first.virtual_size) {
        const want: usize = @intCast(@min(@as(u64, chunk), first.virtual_size - offset));
        _ = try first_img.pread(io, left[0..want], offset);
        _ = try second_img.pread(io, right[0..want], offset);
        if (!std.mem.eql(u8, left[0..want], right[0..want])) {
            std.debug.print("images differ in the megabyte at offset {d}\n", .{offset});
            return error.TestUnexpectedResult;
        }
        offset += want;
    }
}
