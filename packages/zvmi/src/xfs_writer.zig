//! Bounded, deterministic native XFS v5 fresh-filesystem writer.
//!
//! This module is the write-side counterpart to `xfs.zig`'s reader. It drains
//! a `tree_cursor.Cursor` (the filesystem-neutral pull cursor a writer
//! consumes) plus separately-carried root-directory metadata, and emits a
//! *Linux/xfsprogs-valid* clean XFS v5 filesystem into a caller-provided byte
//! region -- not merely bytes this project's own reader happens to accept. The
//! output round-trips through `xfs.zig` and, in development, passes
//! `xfs_repair -n` (mounting requires an `xfs` kernel module the CI host lacks).
//!
//! Deliberately unreachable from `layout.FilesystemKind`, the public
//! CLI/config surface, and `filesystem_writer`'s dispatch: wiring this into the
//! product is a dependent change. Only `root.zig` re-exports it, so its tests
//! run.
//!
//! ## Geometry (fixed, classic, reader- and repair-compatible)
//!
//! Two allocation groups, 4096-byte blocks, 512-byte sectors, 512-byte inodes.
//! Every inode and every data block lives in AG0; AG1 holds only the internal
//! log (and free space) so the primary superblock has the redundant secondary
//! copy `mkfs.xfs`/`xfs_repair` expect. Feature set is the minimal v5 classic
//! one: FTYPE incompat, CRC/PROJID32/ATTR2/LAZYSBCOUNT in features2, no
//! finobt/rmapbt/reflink/sparse-inodes/nrext64/bigtime.
//!
//! ## Supported RootTree subset
//!
//! Directories (shortform and single-block "block" format with a real,
//! hash-sorted leaf index), regular files (a single contiguous EXTENTS
//! extent), symlinks (inline LOCAL and single-block remote), device nodes,
//! FIFOs, hardlinks (shared inode identity), POSIX mode/uid/gid/timestamps,
//! and shortform extended attributes. Anything a first correct pass cannot
//! represent safely -- multi-block leaf/node directories, btree-format files,
//! symlinks past `XFS_SYMLINK_MAXLEN`, out-of-line or oversized xattr forks --
//! is rejected *before any bytes are written*, never silently mangled.
const std = @import("std");
const tree_cursor = @import("tree_cursor.zig");

const Kind = tree_cursor.Kind;
const Cursor = tree_cursor.Cursor;

// ---------------------------------------------------------------------------
// Public option and error types
// ---------------------------------------------------------------------------

/// A whole-second POSIX time plus its sub-second part, used as the image-wide
/// fallback for any node whose cursor entry leaves a timestamp null (what a
/// reproducible build wants).
pub const Timestamp = struct {
    sec: i64 = 0,
    nsec: u32 = 0,
};

/// Root-directory metadata, carried separately from the entry stream exactly
/// as `tree_cursor.zig` documents: the root inode is not an entry a cursor
/// yields.
pub const RootMetadata = struct {
    /// Permission/sticky bits only; the directory type bit is implied.
    mode: u16 = 0o755,
    uid: u32 = 0,
    gid: u32 = 0,
    atime: ?i64 = null,
    mtime: ?i64 = null,
    ctime: ?i64 = null,
    crtime: ?i64 = null,
    atime_nsec: u32 = 0,
    mtime_nsec: u32 = 0,
    ctime_nsec: u32 = 0,
    crtime_nsec: u32 = 0,
    xattrs: []const tree_cursor.Xattr = &.{},
};

/// Format-time knobs: where the filesystem sits in the destination buffer, how
/// big it is, and the determinism inputs (UUID, label, fallback timestamp).
pub const FormatOptions = struct {
    /// Byte offset of the filesystem's own block 0 within the destination
    /// buffer (a partition start, typically). Must be sector-aligned.
    offset: u64 = 0,
    /// Bytes the filesystem may occupy. Must be at least `minimumSize` and is
    /// rounded down to a whole number of equally-sized allocation groups.
    length: u64,
    /// On-disk filesystem UUID; also every inode's and metadata block's owner
    /// UUID (no META_UUID feature, so the two are one and the same).
    uuid: [16]u8 = default_uuid,
    /// Volume label, at most 12 bytes; longer is rejected, not truncated.
    label: []const u8 = "",
    /// Fallback timestamp for any inode time a cursor entry leaves null.
    timestamp: Timestamp = .{},
};

pub const PopulateOptions = struct {
    format: FormatOptions,
    root: RootMetadata = .{},
};

/// A deterministic non-nil default UUID, so a caller that does not care still
/// gets reproducible output rather than zeros (which some tools treat as
/// "unset").
pub const default_uuid = [16]u8{
    0x2f, 0xb1, 0x9c, 0x00, 0x1e, 0x55, 0x4a, 0x11,
    0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

/// Every way `populate`/`format` can refuse. The rejection arm names the
/// concrete unsupported shape or feature so a caller (and a dependent
/// integration PR) can tell "your tree needs a structure this writer does not
/// emit yet" from "your buffer is the wrong size".
pub const WriteError = error{
    // Sizing and bounds.
    LengthTooSmall,
    BufferTooSmall,
    OffsetNotAligned,
    Overflow,
    // Feature/shape rejections (checked before any write).
    LabelTooLong,
    TooManyInodes,
    DirectoryTooLarge,
    FileTooLarge,
    TooManyExtents,
    SymlinkTooLong,
    EmptySymlink,
    XattrForkTooLarge,
    XattrValueTooLarge,
    XattrNameTooLong,
    UnsupportedXattrNamespace,
    NameTooLong,
    EmptyName,
    DuplicateName,
    PathHasNoParent,
    ParentIsNotADirectory,
    MissingParent,
    AbsolutePath,
    HardlinkTargetMissing,
    HardlinkToDirectory,
    MissingContent,
    ContentSizeMismatch,
    UnsupportedKind,
} || std.mem.Allocator.Error || Cursor.IteratorError || Cursor.ContentError;

// ---------------------------------------------------------------------------
// On-disk constants
// ---------------------------------------------------------------------------

const block_size: u32 = 4096;
const sector_size: u32 = 512;
const inode_size: u32 = 512;
const inodes_per_block: u32 = block_size / inode_size; // 8
const inopblog: u5 = 3; // log2(inodes_per_block)
const block_log: u8 = 12;
const sector_log: u8 = 9;
const inode_log: u8 = 9;
const inodes_per_chunk: u32 = 64;
const blocks_per_chunk: u32 = inodes_per_chunk / inodes_per_block; // 8
const literal_area: u32 = inode_size - 176; // 336 bytes after the v3 core

const ino_align: u32 = 4; // sb_inoalignmt, in blocks
const log_blocks: u32 = 16384; // 64 MiB internal log (mkfs's proven minimum)
const symlink_max_len: u32 = 1024;

const sb_magic: u32 = 0x5846_5342; // "XFSB"
const agf_magic: u32 = 0x5841_4746; // "XAGF"
const agi_magic: u32 = 0x5841_4749; // "XAGI"
const agfl_magic: u32 = 0x5841_464c; // "XAFL"
const bnobt_magic: u32 = 0x4142_3342; // "AB3B"
const cntbt_magic: u32 = 0x4142_3343; // "AB3C"
const inobt_magic: u32 = 0x4941_4233; // "IAB3"
const inode_magic: u16 = 0x494e; // "IN"
const dir3_block_magic: u32 = 0x5844_4233; // "XDB3"
const symlink_magic: u32 = 0x5853_4c4d; // "XSLM"
const log_magic: u32 = 0xFEED_BABE;

const version_num: u16 = 0xb4a5;
const features2: u32 = 0x0000_018a; // CRC | PROJID32 | ATTR2 | LAZYSBCOUNT
const features_incompat: u32 = 0x0000_0001; // FTYPE
const imax_pct: u8 = 25;

const fmt_dev: u8 = 0;
const fmt_local: u8 = 1;
const fmt_extents: u8 = 2;

const null_ino32: u32 = 0xffff_ffff;
const null_fsblock: u32 = 0xffff_ffff;
const null_agblock: u32 = 0xffff_ffff;

// Directory entry file types (XFS_DIR3_FT_*).
const ft_unknown: u8 = 0;
const ft_reg: u8 = 1;
const ft_dir: u8 = 2;
const ft_chrdev: u8 = 3;
const ft_blkdev: u8 = 4;
const ft_fifo: u8 = 5;
const ft_sock: u8 = 6;
const ft_symlink: u8 = 7;

// Shortform xattr entry flag bits (XFS_ATTR_*).
const attr_root_bit: u8 = 1 << 1; // trusted.*
const attr_secure_bit: u8 = 1 << 2; // security.*

// POSIX mode type bits.
const s_ififo: u16 = 0o010000;
const s_ifchr: u16 = 0o020000;
const s_ifdir: u16 = 0o040000;
const s_ifblk: u16 = 0o060000;
const s_ifreg: u16 = 0o100000;
const s_iflnk: u16 = 0o120000;

// Reserved inode indices within AG0's first chunk.
const root_ino: u64 = 64;
const rbm_ino: u64 = 65;
const rsum_ino: u64 = 66;
const first_user_ino: u64 = 67;

// The number of AGFL blocks mkfs pre-populates and repair expects.
const agfl_reserve: u32 = 4;

// ---------------------------------------------------------------------------
// CRC32C and endian helpers (same convention as the reader: Castagnoli,
// complemented, stored little-endian even though every other field is
// big-endian; the four CRC bytes count as zero while hashing).
// ---------------------------------------------------------------------------

const Crc32c = std.hash.crc.Crc(u32, .{
    .polynomial = 0x1edc6f41,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0,
});

fn computeCrc32c(buffer: []const u8, crc_offset: usize) u32 {
    var hash = Crc32c.init();
    hash.update(buffer[0..crc_offset]);
    hash.update(&[_]u8{ 0, 0, 0, 0 });
    hash.update(buffer[crc_offset + 4 ..]);
    return ~hash.final();
}

fn beU16(buf: []u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, buf[off..][0..2], v, .big);
}
fn beU32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .big);
}
fn beU64(buf: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], v, .big);
}
fn leU16(buf: []u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, buf[off..][0..2], v, .little);
}
fn leU32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .little);
}
fn writeCrc(buf: []u8, crc_offset: usize) void {
    leU32(buf, crc_offset, computeCrc32c(buf, crc_offset));
}

/// Encodes a v3 timestamp (`__be32 sec; __be32 nsec`). Seconds are a 32-bit
/// field without the bigtime feature, so a value outside the signed 32-bit
/// range wraps -- callers wanting the full range would enable bigtime, which
/// this classic writer deliberately does not.
fn writeTimestamp(buf: []u8, off: usize, sec: i64, nsec: u32) void {
    const secs32: u32 = @bitCast(@as(i32, @truncate(sec)));
    beU32(buf, off, secs32);
    beU32(buf, off + 4, nsec);
}

/// `rol32` used by `xfs_da_hashname`.
fn rol32(x: u32, n: u5) u32 {
    return std.math.rotl(u32, x, n);
}

/// The XFS directory name hash (`xfs_da_hashname`), verified against real
/// mkfs output ("." -> 0x2e, ".." -> 0x172e).
fn hashName(name: []const u8) u32 {
    var hash: u32 = 0;
    var i: usize = 0;
    const n = name.len;
    while (i + 4 <= n) : (i += 4) {
        hash = (@as(u32, name[i]) << 21) ^ (@as(u32, name[i + 1]) << 14) ^
            (@as(u32, name[i + 2]) << 7) ^ (@as(u32, name[i + 3])) ^ rol32(hash, 28);
    }
    const rem = n - i;
    return switch (rem) {
        3 => (@as(u32, name[i]) << 14) ^ (@as(u32, name[i + 1]) << 7) ^
            (@as(u32, name[i + 2])) ^ rol32(hash, 21),
        2 => (@as(u32, name[i]) << 7) ^ (@as(u32, name[i + 1])) ^ rol32(hash, 14),
        1 => (@as(u32, name[i])) ^ rol32(hash, 7),
        else => hash,
    };
}

/// Round `v` up to a multiple of `a` (a power of two), guarding overflow.
fn alignUp(v: u64, a: u64) WriteError!u64 {
    const sum = std.math.add(u64, v, a - 1) catch return error.Overflow;
    return sum & ~(a - 1);
}

fn ceilDiv(a: u64, b: u64) u64 {
    return (a + b - 1) / b;
}

/// The device-number encoding XFS actually stores on disk (`sysv_encode_dev`:
/// `minor | (major << 18)`), confirmed against mkfs output. Note the reader's
/// `new_decode_dev` differs; tests here verify the real on-disk bytes rather
/// than round-tripping the (major, minor) pair through that decode.
fn encodeDev(major: u32, minor: u32) u32 {
    return (minor & 0x3ffff) | (major << 18);
}

// ---------------------------------------------------------------------------
// The size of a directory entry's data-block form, and the shortform "offset"
// field (the cumulative data-block position xfs_repair validates).
// ---------------------------------------------------------------------------

/// `xfs_dir2_data_entsize`: inumber(8) + namelen(1) + name + ftype(1) +
/// tag(2), rounded up to 8.
fn dataEntSize(namelen: usize) u32 {
    return @intCast(alignUp8(8 + 1 + namelen + 1 + 2));
}

fn alignUp8(v: usize) usize {
    return (v + 7) & ~@as(usize, 7);
}

// The two synthetic leading entries "." and "..", each 16 bytes in a data
// block, so the first real entry begins at offset 96 (0x60).
const dir_data_hdr_len: u32 = 64;
const first_entry_offset: u32 = dir_data_hdr_len + 16 + 16; // 96

// ---------------------------------------------------------------------------
// Internal planning model
// ---------------------------------------------------------------------------

const OwnedXattr = struct {
    /// Name with the namespace prefix stripped.
    name: []u8,
    value: []u8,
    flags: u8,
};

const DirChild = struct {
    name: []const u8,
    ino: u64,
    ftype: u8,
};

const InodeNode = struct {
    ino: u64,
    /// Effective on-disk kind (a hardlink resolves to its target's kind).
    kind: Kind,
    mode_bits: u16, // permission/sticky bits only
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    atime: i64,
    mtime: i64,
    ctime: i64,
    crtime: i64,
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    crtime_nsec: u32,
    device: tree_cursor.DeviceNumbers,
    parent_ino: u64,

    // Fork payloads (owned in the planning arena).
    children: std.ArrayListUnmanaged(DirChild) = .empty,
    symlink_target: []u8 = &.{},
    file_content: []u8 = &.{},
    xattrs: []OwnedXattr = &.{},

    // Computed layout, filled during planning.
    di_format: u8 = fmt_extents,
    di_aformat: u8 = fmt_extents,
    forkoff: u8 = 0,
    dir_is_block: bool = false,
    data_start_block: u64 = 0,
    data_block_count: u64 = 0,
    nextents: u32 = 0,

    fn typeBit(self: *const InodeNode) u16 {
        return switch (self.kind) {
            .directory => s_ifdir,
            .file => s_ifreg,
            .symlink => s_iflnk,
            .block_device => s_ifblk,
            .char_device => s_ifchr,
            .fifo => s_ififo,
            .hardlink => unreachable,
        };
    }

    fn ftype(self: *const InodeNode) u8 {
        return switch (self.kind) {
            .directory => ft_dir,
            .file => ft_reg,
            .symlink => ft_symlink,
            .block_device => ft_blkdev,
            .char_device => ft_chrdev,
            .fifo => ft_fifo,
            .hardlink => unreachable,
        };
    }

    fn xattrForkBytes(self: *const InodeNode) u32 {
        if (self.xattrs.len == 0) return 0;
        var total: u32 = 4; // xfs_attr_sf_hdr
        for (self.xattrs) |x| total += @intCast(3 + x.name.len + x.value.len);
        return total;
    }
};

// ---------------------------------------------------------------------------
// Geometry computed for a concrete populate
// ---------------------------------------------------------------------------

const Geometry = struct {
    ag_blocks: u32,
    ag_block_log: u8,
    data_blocks: u64,
    inode_chunks: u32,
    inode_count: u64,
    used_inodes: u64,
    // AG0 free-space extent.
    ag0_free_start: u32,
    ag0_free_len: u32,
    // AG1 free-space extent.
    ag1_free_start: u32,
    ag1_free_len: u32,
    // `sb_logstart` as an agblklog-encoded filesystem block number (what the
    // superblock stores). For non-power-of-two `ag_blocks` this differs from
    // the physical location because XFS_FSB_TO_AGNO shifts by `ag_block_log`.
    log_start: u64,
    // Physical (linear) block where the log bytes are actually written: AG1
    // block 4. Equals XFS_FSB_TO_DADDR(log_start) in blocks.
    log_phys_block: u64,
};

const Plan = struct {
    arena: std.heap.ArenaAllocator,
    nodes: std.ArrayListUnmanaged(InodeNode),
    /// Index into `nodes` for the root directory (always 0).
    geom: Geometry,

    fn allocator(self: *Plan) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn deinit(self: *Plan) void {
        self.arena.deinit();
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Computes the smallest filesystem length (in bytes) that can hold the tree
/// the cursor yields under this writer's geometry. Resets and fully drains the
/// cursor. Rejects any tree shape the writer cannot represent, so a caller
/// gets the same up-front errors it would get from `populate`.
pub fn minimumSize(
    allocator: std.mem.Allocator,
    cursor: *Cursor,
    options: PopulateOptions,
) WriteError!u64 {
    var plan = try buildPlan(allocator, cursor, options);
    defer plan.deinit();
    return minimumLength(&plan.geom);
}

/// Formats and populates a clean XFS v5 filesystem for `cursor`'s tree into
/// `buffer[options.format.offset..]`. Resets and fully drains the cursor. On
/// any rejected shape or too-small buffer it returns an error having written
/// nothing meaningful (a caller must treat a non-`void` return as total
/// failure). A successful return means every planned byte was written; there
/// is no partial success.
pub fn populate(
    allocator: std.mem.Allocator,
    buffer: []u8,
    cursor: *Cursor,
    options: PopulateOptions,
) WriteError!void {
    if (options.format.offset % sector_size != 0) return error.OffsetNotAligned;

    var plan = try buildPlan(allocator, cursor, options);
    defer plan.deinit();

    const min_len = try minimumLength(&plan.geom);
    if (options.format.length < min_len) return error.LengthTooSmall;

    // Size the filesystem to the requested length, rounded down to whole AGs,
    // never below the minimum.
    const requested_blocks = options.format.length / block_size;
    var ag_blocks: u64 = requested_blocks / 2;
    if (ag_blocks < plan.geom.ag_blocks) ag_blocks = plan.geom.ag_blocks;
    try finalizeGeometry(&plan.geom, @intCast(ag_blocks));

    const fs_len = plan.geom.data_blocks * block_size;
    const end = std.math.add(u64, options.format.offset, fs_len) catch return error.Overflow;
    if (buffer.len < end) return error.BufferTooSmall;

    const region = buffer[@intCast(options.format.offset)..@intCast(end)];
    @memset(region, 0);
    try writeImage(region, &plan, options);
}

// ---------------------------------------------------------------------------
// Planning: drain the cursor, assign inode numbers, compute forks and layout.
// ---------------------------------------------------------------------------

fn buildPlan(
    allocator: std.mem.Allocator,
    cursor: *Cursor,
    options: PopulateOptions,
) WriteError!Plan {
    if (options.format.label.len > 12) return error.LabelTooLong;

    var plan = Plan{
        .arena = std.heap.ArenaAllocator.init(allocator),
        .nodes = .empty,
        .geom = undefined,
    };
    errdefer plan.deinit();
    const a = plan.allocator();

    // Root inode (index 0), realtime bitmap (1) and summary (2) reserved
    // inodes, all present and valid even though the tree never references
    // them, because xfs_repair checks they exist.
    try appendRoot(&plan, options.root);
    try appendReservedInode(&plan, rbm_ino);
    try appendReservedInode(&plan, rsum_ino);

    // Drain the cursor into a flat, path-sorted list first: a parent must be
    // planned before any child so directory membership resolves in one pass.
    var raw = std.ArrayListUnmanaged(RawEntry).empty;
    cursor.reset();
    while (try cursor.next()) |entry| {
        try raw.append(a, try captureEntry(a, entry));
    }
    std.sort.block(RawEntry, raw.items, {}, rawLess);

    // Map from path -> node index, for parent lookup and hardlink targets.
    var by_path = std.StringHashMapUnmanaged(usize).empty;
    try by_path.put(a, "", 0); // the root directory is the empty relative path

    var next_ino: u64 = first_user_ino;
    for (raw.items) |*e| {
        try planEntry(&plan, &by_path, e, &next_ino, options);
    }

    try computeForkLayout(&plan);
    try planGeometry(&plan);
    return plan;
}

const RawEntry = struct {
    path: []u8,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    device: tree_cursor.DeviceNumbers,
    hardlink_target: []u8,
    atime: ?i64,
    mtime: ?i64,
    ctime: ?i64,
    crtime: ?i64,
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    crtime_nsec: u32,
    content: ?Cursor.ContentReader,
    xattrs: []OwnedXattr,
};

/// Depth-first ordering by path so parents precede children deterministically.
fn rawLess(_: void, x: RawEntry, y: RawEntry) bool {
    return std.mem.lessThan(u8, x.path, y.path);
}

fn captureEntry(a: std.mem.Allocator, entry: Cursor.Entry) WriteError!RawEntry {
    const xattrs = try captureXattrs(a, entry.xattrs);
    return .{
        .path = try a.dupe(u8, entry.path),
        .kind = entry.kind,
        .mode = entry.mode,
        .uid = entry.uid,
        .gid = entry.gid,
        .size = entry.size,
        .device = entry.device,
        .hardlink_target = try a.dupe(u8, entry.hardlink_target),
        .atime = entry.atime,
        .mtime = entry.mtime,
        .ctime = entry.ctime,
        .crtime = entry.crtime,
        .atime_nsec = entry.atime_nsec,
        .mtime_nsec = entry.mtime_nsec,
        .ctime_nsec = entry.ctime_nsec,
        .crtime_nsec = entry.crtime_nsec,
        .content = entry.content,
        .xattrs = xattrs,
    };
}

fn captureXattrs(a: std.mem.Allocator, xattrs: []const tree_cursor.Xattr) WriteError![]OwnedXattr {
    if (xattrs.len == 0) return &.{};
    const out = try a.alloc(OwnedXattr, xattrs.len);
    for (xattrs, 0..) |x, i| {
        const parsed = try splitXattrNamespace(x.name);
        if (parsed.suffix.len > 255) return error.XattrNameTooLong;
        if (x.value.len > 255) return error.XattrValueTooLarge;
        out[i] = .{
            .name = try a.dupe(u8, parsed.suffix),
            .value = try a.dupe(u8, x.value),
            .flags = parsed.flags,
        };
    }
    return out;
}

const NamespaceSplit = struct { suffix: []const u8, flags: u8 };

fn splitXattrNamespace(name: []const u8) WriteError!NamespaceSplit {
    if (std.mem.startsWith(u8, name, "user.")) {
        return .{ .suffix = name["user.".len..], .flags = 0 };
    } else if (std.mem.startsWith(u8, name, "trusted.")) {
        return .{ .suffix = name["trusted.".len..], .flags = attr_root_bit };
    } else if (std.mem.startsWith(u8, name, "security.")) {
        return .{ .suffix = name["security.".len..], .flags = attr_secure_bit };
    }
    return error.UnsupportedXattrNamespace;
}

fn appendRoot(plan: *Plan, root: RootMetadata) WriteError!void {
    const a = plan.allocator();
    const ts = root; // for brevity
    const node = InodeNode{
        .ino = root_ino,
        .kind = .directory,
        .mode_bits = ts.mode,
        .uid = ts.uid,
        .gid = ts.gid,
        .nlink = 2, // updated as subdirectories are added
        .size = 0,
        .atime = ts.atime orelse 0,
        .mtime = ts.mtime orelse 0,
        .ctime = ts.ctime orelse 0,
        .crtime = ts.crtime orelse 0,
        .atime_nsec = ts.atime_nsec,
        .mtime_nsec = ts.mtime_nsec,
        .ctime_nsec = ts.ctime_nsec,
        .crtime_nsec = ts.crtime_nsec,
        .device = .{},
        .parent_ino = root_ino,
        .xattrs = try captureXattrs(a, ts.xattrs),
    };
    try plan.nodes.append(a, node);
}

fn appendReservedInode(plan: *Plan, ino: u64) WriteError!void {
    // The realtime bitmap/summary inodes: empty regular files with no links
    // reachable from the directory tree. xfs_repair only needs them present,
    // well-formed, and zero-sized.
    const node = InodeNode{
        .ino = ino,
        .kind = .file,
        .mode_bits = 0,
        .uid = 0,
        .gid = 0,
        .nlink = 1,
        .size = 0,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
        .crtime = 0,
        .atime_nsec = 0,
        .mtime_nsec = 0,
        .ctime_nsec = 0,
        .crtime_nsec = 0,
        .device = .{},
        .parent_ino = 0,
        .di_format = fmt_extents,
    };
    try plan.nodes.append(plan.allocator(), node);
}

fn planEntry(
    plan: *Plan,
    by_path: *std.StringHashMapUnmanaged(usize),
    e: *RawEntry,
    next_ino: *u64,
    options: PopulateOptions,
) WriteError!void {
    if (e.path.len == 0) return error.EmptyName;
    if (e.path[0] == '/') return error.AbsolutePath;

    const split = splitParent(e.path);
    const name = split.name;
    if (name.len == 0) return error.EmptyName;
    if (name.len > 255) return error.NameTooLong;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.EmptyName;

    const parent_idx = by_path.get(split.parent) orelse return error.MissingParent;
    const a = plan.allocator();

    // A hardlink adds a directory entry pointing at an already-planned inode
    // and bumps that inode's link count; it does not create a new inode.
    if (e.kind == .hardlink) {
        const target_idx = by_path.get(e.hardlink_target) orelse return error.HardlinkTargetMissing;
        const target = &plan.nodes.items[target_idx];
        if (target.kind == .directory) return error.HardlinkToDirectory;
        target.nlink = std.math.add(u32, target.nlink, 1) catch return error.Overflow;
        try addChild(plan, parent_idx, name, target.ino, target.ftype());
        return;
    }

    const ino = next_ino.*;
    next_ino.* += 1;

    var node = InodeNode{
        .ino = ino,
        .kind = e.kind,
        .mode_bits = e.mode,
        .uid = e.uid,
        .gid = e.gid,
        .nlink = 1,
        .size = e.size,
        .atime = e.atime orelse options.format.timestamp.sec,
        .mtime = e.mtime orelse options.format.timestamp.sec,
        .ctime = e.ctime orelse options.format.timestamp.sec,
        .crtime = e.crtime orelse options.format.timestamp.sec,
        .atime_nsec = if (e.atime == null) options.format.timestamp.nsec else e.atime_nsec,
        .mtime_nsec = if (e.mtime == null) options.format.timestamp.nsec else e.mtime_nsec,
        .ctime_nsec = if (e.ctime == null) options.format.timestamp.nsec else e.ctime_nsec,
        .crtime_nsec = if (e.crtime == null) options.format.timestamp.nsec else e.crtime_nsec,
        .device = e.device,
        .parent_ino = plan.nodes.items[parent_idx].ino,
        .xattrs = e.xattrs,
    };

    switch (e.kind) {
        .directory => node.nlink = 2, // "." plus the parent's entry; bumped by children
        .file => node.file_content = try readContent(a, e, e.size),
        .symlink => {
            if (e.size == 0) return error.EmptySymlink;
            if (e.size > symlink_max_len) return error.SymlinkTooLong;
            node.symlink_target = try readContent(a, e, e.size);
        },
        .block_device, .char_device, .fifo => {},
        .hardlink => unreachable,
    }

    const node_idx = plan.nodes.items.len;
    try plan.nodes.append(a, node);
    try by_path.put(a, e.path, node_idx);
    try addChild(plan, parent_idx, name, ino, plan.nodes.items[node_idx].ftype());

    if (e.kind == .directory) {
        // A new subdirectory adds one to the parent's link count (its "..").
        plan.nodes.items[parent_idx].nlink =
            std.math.add(u32, plan.nodes.items[parent_idx].nlink, 1) catch return error.Overflow;
    }
}

fn addChild(plan: *Plan, parent_idx: usize, name: []const u8, ino: u64, ftype: u8) WriteError!void {
    const parent = &plan.nodes.items[parent_idx];
    if (parent.kind != .directory) return error.ParentIsNotADirectory;
    for (parent.children.items) |c| {
        if (std.mem.eql(u8, c.name, name)) return error.DuplicateName;
    }
    try parent.children.append(plan.allocator(), .{ .name = name, .ino = ino, .ftype = ftype });
}

const ParentName = struct { parent: []const u8, name: []const u8 };

fn splitParent(path: []const u8) ParentName {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| {
        return .{ .parent = path[0..slash], .name = path[slash + 1 ..] };
    }
    return .{ .parent = "", .name = path };
}

fn readContent(a: std.mem.Allocator, e: *RawEntry, size: u64) WriteError![]u8 {
    if (size == 0) return &.{};
    const reader = e.content orelse return error.MissingContent;
    const buf = try a.alloc(u8, @intCast(size));
    var done: usize = 0;
    while (done < buf.len) {
        const got = try reader.readAt(buf[done..], done);
        if (got == 0) return error.ContentSizeMismatch;
        done += got;
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Fork layout: decide each inode's on-disk format and how many data blocks it
// needs, sorting directory children for deterministic output.
// ---------------------------------------------------------------------------

fn childLess(_: void, x: DirChild, y: DirChild) bool {
    return std.mem.lessThan(u8, x.name, y.name);
}

fn computeForkLayout(plan: *Plan) WriteError!void {
    for (plan.nodes.items) |*node| {
        std.sort.block(DirChild, node.children.items, {}, childLess);
        const attr_bytes = node.xattrForkBytes();

        switch (node.kind) {
            .directory => try layoutDirectory(node, attr_bytes),
            .file => try layoutFile(node, attr_bytes),
            .symlink => try layoutSymlink(node, attr_bytes),
            .block_device, .char_device, .fifo => try layoutDevice(node, attr_bytes),
            .hardlink => unreachable,
        }

        if (attr_bytes != 0) {
            node.di_aformat = fmt_local;
            // Data fork occupies [0, forkoff*8); the attr fork follows.
            const data_fork = try alignUp(dataForkBytes(node), 8);
            const forkoff_units = data_fork / 8;
            const need = data_fork + attr_bytes;
            if (need > literal_area or forkoff_units > 0xff) return error.XattrForkTooLarge;
            node.forkoff = @intCast(forkoff_units);
        }
    }
}

/// The number of literal-area bytes the *data* fork occupies for forkoff math.
fn dataForkBytes(node: *const InodeNode) u64 {
    return switch (node.di_format) {
        fmt_local => node.size, // shortform dir or inline symlink target
        fmt_extents => @as(u64, node.nextents) * 16,
        fmt_dev => 4,
        else => 0,
    };
}

fn layoutDirectory(node: *InodeNode, attr_bytes: u32) WriteError!void {
    const sf = shortformDirSize(node) catch return error.Overflow;
    const avail = availableDataFork(attr_bytes);
    if (sf <= avail) {
        node.di_format = fmt_local;
        node.dir_is_block = false;
        node.size = sf;
        return;
    }
    // Overflowed shortform: a single-block "block" format directory, if it
    // fits one directory block. Anything larger needs leaf/node format, which
    // the reader cannot read -- reject rather than emit unreadable bytes.
    try checkBlockDirFits(node);
    node.di_format = fmt_extents;
    node.dir_is_block = true;
    node.nextents = 1;
    node.data_block_count = 1;
    node.size = block_size;
}

/// `xfs_dir2_sf` on-disk size for the children in `node`.
fn shortformDirSize(node: *const InodeNode) !u32 {
    const big = dirNeedsBigInodes(node);
    const ino_bytes: u32 = if (big) 8 else 4;
    var total: u32 = 2 + ino_bytes; // count(1) + i8count(1) + parent(4|8)
    for (node.children.items) |c| {
        // namelen(1) + offset(2) + name + ftype(1) + inumber(4|8)
        total += @intCast(1 + 2 + c.name.len + 1 + ino_bytes);
    }
    return total;
}

fn dirNeedsBigInodes(node: *const InodeNode) bool {
    if (node.parent_ino > 0xffff_ffff) return true;
    for (node.children.items) |c| {
        if (c.ino > 0xffff_ffff) return true;
    }
    return false;
}

fn availableDataFork(attr_bytes: u32) u32 {
    if (attr_bytes == 0) return literal_area;
    // Leave room for the attr fork, 8-byte aligned split.
    const reserved = alignUp8(attr_bytes);
    if (reserved >= literal_area) return 0;
    return literal_area - @as(u32, @intCast(reserved));
}

fn checkBlockDirFits(node: *const InodeNode) WriteError!void {
    // Bytes used: header + "." + ".." + each child's data entry, plus the leaf
    // hash array (8 bytes per entry incl. dot/dotdot) and the 8-byte tail.
    var data_used: u64 = dir_data_hdr_len + 16 + 16;
    var leaf_count: u64 = 2;
    for (node.children.items) |c| {
        data_used += dataEntSize(c.name.len);
        leaf_count += 1;
    }
    const leaf_bytes = leaf_count * 8;
    const need = data_used + leaf_bytes + 8;
    if (need > block_size) return error.DirectoryTooLarge;
    // The gap between the data area and the leaf array is 8-aligned by
    // construction; a non-zero gap becomes one unused entry (>= 8 bytes).
}

fn layoutFile(node: *InodeNode, attr_bytes: u32) WriteError!void {
    node.di_format = fmt_extents;
    if (node.size == 0) {
        node.nextents = 0;
        node.data_block_count = 0;
        return;
    }
    const blocks = ceilDiv(node.size, block_size);
    // One contiguous extent. A file that would need more extents than the
    // literal area can hold (after the attr fork) is rejected rather than
    // promoted to btree format, which is out of scope for this pass.
    node.nextents = 1;
    node.data_block_count = blocks;
    const avail = availableDataFork(attr_bytes);
    if (16 > avail) return error.TooManyExtents;
    if (blocks > 0x1f_ffff_ffff) return error.FileTooLarge; // 43-bit extent count field
}

fn layoutSymlink(node: *InodeNode, attr_bytes: u32) WriteError!void {
    const avail = availableDataFork(attr_bytes);
    if (node.symlink_target.len <= avail) {
        node.di_format = fmt_local;
        node.data_block_count = 0;
        node.nextents = 0;
    } else {
        // Remote symlink: one block holds a 56-byte header plus the target.
        if (node.symlink_target.len + 56 > block_size) return error.SymlinkTooLong;
        node.di_format = fmt_extents;
        node.nextents = 1;
        node.data_block_count = 1;
        if (16 > avail) return error.XattrForkTooLarge;
    }
}

fn layoutDevice(node: *InodeNode, attr_bytes: u32) WriteError!void {
    node.di_format = fmt_dev;
    node.data_block_count = 0;
    node.nextents = 0;
    const avail = availableDataFork(attr_bytes);
    if (attr_bytes != 0 and 4 > avail) return error.XattrForkTooLarge;
}

// ---------------------------------------------------------------------------
// Geometry planning and minimum sizing.
// ---------------------------------------------------------------------------

fn planGeometry(plan: *Plan) WriteError!void {
    const inode_count = plan.nodes.items.len;
    // Inodes occupy a contiguous span [64, 64+inode_count); the chunk count is
    // ceil over 64. All chunks live in AG0.
    const chunks: u32 = @intCast(ceilDiv(inode_count, inodes_per_chunk));
    const highest_ino = root_ino + inode_count - 1;
    const chunk_span_inos = @as(u64, chunks) * inodes_per_chunk;
    if (highest_ino >= root_ino + chunk_span_inos) return error.TooManyInodes;

    var data_blocks: u64 = 0;
    for (plan.nodes.items) |node| {
        data_blocks = std.math.add(u64, data_blocks, node.data_block_count) catch return error.Overflow;
    }

    const inode_blocks = @as(u64, chunks) * blocks_per_chunk;

    // AG0 must hold: metadata(4) + AGFL reserve(4) + inode chunks + data +
    // at least one free block. AG1 must hold: metadata(4) + the log + AGFL
    // reserve(4) + at least one free block. Either way the fixed span before
    // free space is 8 + (inodes+data) or 8 + log.
    const ag0_fixed = 8 + inode_blocks + data_blocks;
    const ag1_fixed = 8 + log_blocks;
    const min_ag0 = ag0_fixed + 1;
    const min_ag1 = ag1_fixed + 1;
    const min_ag = @max(min_ag0, min_ag1);

    // Inode numbering assumes all inodes are in AG0, so AG0 (hence every AG)
    // must be large enough that agino stays within its AG. That is guaranteed
    // because inodes are the first thing after fixed metadata.
    if (min_ag > 0xffff_fffe) return error.TooManyInodes;

    plan.geom = .{
        .ag_blocks = @intCast(min_ag),
        .ag_block_log = 0,
        .data_blocks = 0,
        .inode_chunks = chunks,
        .inode_count = chunk_span_inos,
        .used_inodes = inode_count,
        .ag0_free_start = @intCast(8 + inode_blocks + data_blocks),
        .ag0_free_len = 0,
        .ag1_free_start = @intCast(8 + log_blocks),
        .ag1_free_len = 0,
        .log_start = 0,
        .log_phys_block = 0,
    };
    try finalizeGeometry(&plan.geom, plan.geom.ag_blocks);
}

/// Fills the AG-size-dependent geometry fields for a concrete `ag_blocks`.
fn finalizeGeometry(geom: *Geometry, ag_blocks: u32) WriteError!void {
    geom.ag_blocks = ag_blocks;
    geom.ag_block_log = bitWidth(ag_blocks);
    geom.data_blocks = @as(u64, ag_blocks) * 2;
    geom.ag0_free_len = ag_blocks - geom.ag0_free_start;
    geom.ag1_free_len = ag_blocks - geom.ag1_free_start;
    // The log lives physically at AG1 block 4 (linear block ag_blocks + 4).
    // `sb_logstart`, however, is an agblklog-encoded FSB: AGNO 1, AGBNO 4.
    // Encoding it (rather than storing the linear value) is what keeps
    // XFS_FSB_TO_AGNO(sb_logstart) == 1 for non-power-of-two `ag_blocks`, so
    // that xfs_repair's calc_mkfs does not believe the log sits in AG0 and
    // therefore expects the root inode at 64. XFS_FSB_TO_DADDR maps this back
    // to the same physical block, ag_blocks + 4.
    geom.log_phys_block = @as(u64, ag_blocks) + 4;
    geom.log_start = (@as(u64, 1) << @intCast(geom.ag_block_log)) + 4;
}

fn minimumLength(geom: *const Geometry) WriteError!u64 {
    return std.math.mul(u64, @as(u64, geom.ag_blocks) * 2, block_size) catch return error.Overflow;
}

/// Smallest `k` such that `2^k >= value`.
fn bitWidth(value: u32) u8 {
    if (value <= 1) return 0;
    return @intCast(32 - @clz(value - 1));
}

// ---------------------------------------------------------------------------
// Image writing
// ---------------------------------------------------------------------------

const WriteCtx = struct {
    region: []u8,
    plan: *Plan,
    options: PopulateOptions,

    fn geom(self: *const WriteCtx) *const Geometry {
        return &self.plan.geom;
    }

    fn blockSlice(self: *WriteCtx, fsblock: u64) []u8 {
        const off: usize = @intCast(fsblock * block_size);
        return self.region[off..][0..block_size];
    }

    fn sectorSlice(self: *WriteCtx, fsblock: u64, sector: u32) []u8 {
        const off: usize = @intCast(fsblock * block_size + sector * sector_size);
        return self.region[off..][0..sector_size];
    }
};

fn writeImage(region: []u8, plan: *Plan, options: PopulateOptions) WriteError!void {
    var ctx = WriteCtx{ .region = region, .plan = plan, .options = options };

    assignDataBlocks(&ctx);
    try writeSuperblocks(&ctx);
    try writeAgMetadata(&ctx);
    try writeInodeChunks(&ctx);
    writeLog(&ctx);
}

/// Assigns each inode's contiguous data-block run in AG0, immediately after the
/// inode table and in inode order, so the layout (and thus the whole image) is
/// deterministic. Must run before inode cores are written, since a core's
/// data-fork extent references the block number chosen here.
fn assignDataBlocks(ctx: *WriteCtx) void {
    const g = ctx.geom();
    const inode_blocks = @as(u64, g.inode_chunks) * blocks_per_chunk;
    var next: u64 = 8 + inode_blocks;
    for (ctx.plan.nodes.items) |*node| {
        if (node.data_block_count > 0) {
            node.data_start_block = next;
            next += node.data_block_count;
        }
    }
}

fn totalCounts(ctx: *WriteCtx) struct { icount: u64, ifree: u64, fdblocks: u64 } {
    const g = ctx.geom();
    const ifree = g.inode_count - g.used_inodes;
    const fdblocks = @as(u64, g.ag0_free_len) + @as(u64, g.ag1_free_len) + 2 * agfl_reserve;
    return .{ .icount = g.inode_count, .ifree = ifree, .fdblocks = fdblocks };
}

fn writeSuperblocks(ctx: *WriteCtx) WriteError!void {
    const g = ctx.geom();
    const counts = totalCounts(ctx);

    var agno: u32 = 0;
    while (agno < 2) : (agno += 1) {
        const sb = ctx.sectorSlice(@as(u64, agno) * g.ag_blocks, 0);
        beU32(sb, 0, sb_magic);
        beU32(sb, 4, block_size);
        beU64(sb, 8, g.data_blocks);
        beU64(sb, 16, 0); // rblocks
        beU64(sb, 24, 0); // rextents
        @memcpy(sb[32..48], &ctx.options.format.uuid);
        beU64(sb, 48, g.log_start);
        beU64(sb, 56, root_ino);
        beU64(sb, 64, rbm_ino);
        beU64(sb, 72, rsum_ino);
        beU32(sb, 80, 1); // rextsize
        beU32(sb, 84, g.ag_blocks);
        beU32(sb, 88, 2); // agcount
        beU32(sb, 92, 0); // rbmblocks
        beU32(sb, 96, log_blocks);
        beU16(sb, 100, version_num);
        beU16(sb, 102, @intCast(sector_size));
        beU16(sb, 104, @intCast(inode_size));
        beU16(sb, 106, @intCast(inodes_per_block));
        writeLabel(sb, ctx.options.format.label);
        sb[120] = block_log;
        sb[121] = sector_log;
        sb[122] = inode_log;
        sb[123] = @intCast(inopblog);
        sb[124] = g.ag_block_log;
        sb[125] = 0; // rextslog
        sb[126] = 0; // inprogress
        sb[127] = imax_pct;
        beU64(sb, 128, counts.icount);
        beU64(sb, 136, counts.ifree);
        beU64(sb, 144, counts.fdblocks);
        beU64(sb, 152, 0); // frextents
        beU64(sb, 160, 0); // uquotino
        beU64(sb, 168, 0); // gquotino
        beU16(sb, 176, 0); // qflags
        sb[178] = 0; // flags
        sb[179] = 0; // shared_vn
        beU32(sb, 180, ino_align);
        beU32(sb, 184, 0); // unit
        beU32(sb, 188, 0); // width
        sb[192] = 0; // dirblklog
        sb[193] = 0; // logsectlog
        beU16(sb, 194, 0); // logsectsize
        beU32(sb, 196, 1); // logsunit
        beU32(sb, 200, features2);
        beU32(sb, 204, features2); // bad_features2 mirrors features2
        beU32(sb, 208, 0); // features_compat
        beU32(sb, 212, 0); // features_ro_compat
        beU32(sb, 216, features_incompat);
        beU32(sb, 220, 0); // features_log_incompat
        // crc @224 written below
        beU32(sb, 228, 0); // spino_align
        beU64(sb, 232, 0); // pquotino
        beU64(sb, 240, 0); // lsn
        @memset(sb[248..264], 0); // meta_uuid (unused without META_UUID)
        writeCrc(sb, 224);
    }
}

fn writeLabel(sb: []u8, label: []const u8) void {
    @memset(sb[108..120], 0);
    @memcpy(sb[108..][0..label.len], label);
}

fn writeAgMetadata(ctx: *WriteCtx) WriteError!void {
    // AG0 carries the inode chunks and file/dir data; AG1 carries the log.
    try writeOneAgHeaders(ctx, 0);
    try writeOneAgHeaders(ctx, 1);
}

fn writeOneAgHeaders(ctx: *WriteCtx, agno: u32) WriteError!void {
    const g = ctx.geom();
    const ag_base = @as(u64, agno) * g.ag_blocks;

    const is_data_ag = agno == 0;
    const free_start: u32 = if (is_data_ag) g.ag0_free_start else g.ag1_free_start;
    const free_len: u32 = if (is_data_ag) g.ag0_free_len else g.ag1_free_len;

    // --- AGF (sector 1) ---
    const agf = ctx.sectorSlice(ag_base, 1);
    beU32(agf, 0, agf_magic);
    beU32(agf, 4, 1); // versionnum
    beU32(agf, 8, agno);
    beU32(agf, 12, g.ag_blocks);
    beU32(agf, 16, 1); // bno root at agbno 1
    beU32(agf, 20, 2); // cnt root at agbno 2
    beU32(agf, 24, 0); // rmap root
    beU32(agf, 28, 1); // bno level
    beU32(agf, 32, 1); // cnt level
    beU32(agf, 36, 0); // rmap level
    beU32(agf, 40, 1); // flfirst
    beU32(agf, 44, agfl_reserve); // fllast
    beU32(agf, 48, agfl_reserve); // flcount
    beU32(agf, 52, free_len); // freeblks
    beU32(agf, 56, free_len); // longest (single free extent)
    beU32(agf, 60, 0); // btreeblks
    @memcpy(agf[64..80], &ctx.options.format.uuid);
    beU32(agf, 80, 0); // rmap_blocks
    beU32(agf, 84, 0); // refcount_blocks
    beU32(agf, 88, 0); // refcount_root
    beU32(agf, 92, 0); // refcount_level
    beU64(agf, 208, 0); // lsn
    writeCrc(agf, 216);

    // --- AGI (sector 2) ---
    const agi = ctx.sectorSlice(ag_base, 2);
    beU32(agi, 0, agi_magic);
    beU32(agi, 4, 1);
    beU32(agi, 8, agno);
    beU32(agi, 12, g.ag_blocks);
    if (is_data_ag) {
        beU32(agi, 16, @intCast(g.inode_count)); // count
        beU32(agi, 20, 3); // root at agbno 3
        beU32(agi, 24, 1); // level
        beU32(agi, 28, @intCast(g.inode_count - g.used_inodes)); // freecount
        beU32(agi, 32, @intCast(newinoAgino(g))); // newino
    } else {
        beU32(agi, 16, 0);
        beU32(agi, 20, 3);
        beU32(agi, 24, 1);
        beU32(agi, 28, 0);
        beU32(agi, 32, null_ino32); // newino = null
    }
    beU32(agi, 36, null_ino32); // dirino
    var u: usize = 0;
    while (u < 64) : (u += 1) beU32(agi, 40 + u * 4, null_ino32); // unlinked buckets
    @memcpy(agi[296..312], &ctx.options.format.uuid);
    beU64(agi, 320, 0); // lsn
    beU32(agi, 328, 0); // free_root
    beU32(agi, 332, 0); // free_level
    writeCrc(agi, 312);

    // --- AGFL (sector 3) ---
    const agfl = ctx.sectorSlice(ag_base, 3);
    beU32(agfl, 0, agfl_magic);
    beU32(agfl, 4, agno); // seqno
    @memcpy(agfl[8..24], &ctx.options.format.uuid);
    beU64(agfl, 24, 0); // lsn
    // bno[] starts at 36. The four reserve blocks sit right after the btree
    // roots in AG0 (agbno 4..7), but in AG1 the log occupies agbno 4.. so they
    // sit right after the log instead -- exactly where mkfs.xfs places them.
    const agfl_base: u32 = if (is_data_ag) 4 else 4 + log_blocks;
    beU32(agfl, 36, null_agblock); // slot 0 unused (flfirst=1)
    var i: u32 = 0;
    while (i < agfl_reserve) : (i += 1) {
        beU32(agfl, 36 + (1 + i) * 4, agfl_base + i);
    }
    writeCrc(agfl, 32);

    // --- bnobt root (block 1) and cntbt root (block 2) ---
    try writeAllocBtree(ctx, ag_base + 1, bnobt_magic, agno, free_start, free_len);
    try writeAllocBtree(ctx, ag_base + 2, cntbt_magic, agno, free_start, free_len);

    // --- inobt root (block 3) ---
    try writeInobtRoot(ctx, ag_base + 3, agno, is_data_ag);
}

fn newinoAgino(g: *const Geometry) u64 {
    // Point newino at the last allocated chunk's first inode (agino), matching
    // mkfs's "most recent chunk" convention.
    const last_chunk = g.inode_chunks - 1;
    return root_ino + @as(u64, last_chunk) * inodes_per_chunk;
}

fn writeAllocBtree(
    ctx: *WriteCtx,
    fsblock: u64,
    magic: u32,
    agno: u32,
    start: u32,
    len: u32,
) WriteError!void {
    const blk = ctx.blockSlice(fsblock);
    writeShortBtreeHeader(blk, magic, fsblock, agno, 1, &ctx.options.format.uuid);
    // Single record: the one free extent (startblock, blockcount).
    beU32(blk, 56, start);
    beU32(blk, 60, len);
    writeCrc(blk, 52);
}

fn writeInobtRoot(ctx: *WriteCtx, fsblock: u64, agno: u32, is_data_ag: bool) WriteError!void {
    const g = ctx.geom();
    const blk = ctx.blockSlice(fsblock);
    if (!is_data_ag) {
        writeShortBtreeHeader(blk, inobt_magic, fsblock, agno, 0, &ctx.options.format.uuid);
        writeCrc(blk, 52);
        return;
    }
    writeShortBtreeHeader(blk, inobt_magic, fsblock, agno, g.inode_chunks, &ctx.options.format.uuid);
    // One record per chunk: startino, freecount, free bitmask (bit=1 => free).
    var chunk: u32 = 0;
    while (chunk < g.inode_chunks) : (chunk += 1) {
        const rec = blk[56 + chunk * 16 ..][0..16];
        const start_agino = root_ino + @as(u64, chunk) * inodes_per_chunk;
        const first_ino = root_ino + @as(u64, chunk) * inodes_per_chunk;
        // Which inodes in this chunk are used?
        var free_mask: u64 = 0;
        var free_count: u32 = 0;
        var i: u32 = 0;
        while (i < inodes_per_chunk) : (i += 1) {
            const ino = first_ino + i;
            const used = ino < root_ino + g.used_inodes;
            if (!used) {
                free_mask |= (@as(u64, 1) << @intCast(i));
                free_count += 1;
            }
        }
        beU32(rec, 0, @intCast(start_agino));
        beU32(rec, 4, free_count);
        beU64(rec, 8, free_mask);
    }
    writeCrc(blk, 52);
}

fn writeShortBtreeHeader(blk: []u8, magic: u32, fsblock: u64, agno: u32, numrecs: u32, uuid: *const [16]u8) void {
    beU32(blk, 0, magic);
    beU16(blk, 4, 0); // level (leaf root)
    beU16(blk, 6, @intCast(numrecs));
    beU32(blk, 8, null_fsblock); // leftsib
    beU32(blk, 12, null_fsblock); // rightsib
    beU64(blk, 16, fsblock * (block_size / sector_size)); // bb_blkno in 512B units
    beU64(blk, 24, 0); // lsn
    @memcpy(blk[32..48], uuid);
    beU32(blk, 48, agno); // bb_owner
    // crc @52 written by caller
}

fn writeInodeChunks(ctx: *WriteCtx) WriteError!void {
    const g = ctx.geom();
    // Every inode slot in every chunk must be a valid v3 inode; used slots get
    // real content, free slots a well-formed empty inode.
    var idx: u64 = 0;
    const total_slots = g.inode_count;
    while (idx < total_slots) : (idx += 1) {
        const ino = root_ino + idx;
        const inode_off = inodeByteOffset(g, ino);
        const inode = ctx.region[@intCast(inode_off)..][0..inode_size];
        if (idx < g.used_inodes) {
            try writeInodeCore(ctx, inode, &ctx.plan.nodes.items[@intCast(idx)]);
        } else {
            writeFreeInode(ctx, inode, ino);
        }
    }
}

/// Byte offset of an inode within AG0 (all inodes live there).
fn inodeByteOffset(g: *const Geometry, ino: u64) u64 {
    _ = g;
    const agino = ino; // AG0, so ino == agino
    const agbno = agino >> inopblog;
    const off_in_block = agino & (inodes_per_block - 1);
    return agbno * block_size + off_in_block * inode_size;
}

fn writeFreeInode(ctx: *WriteCtx, inode: []u8, ino: u64) void {
    @memset(inode, 0);
    beU16(inode, 0, inode_magic);
    beU16(inode, 2, 0); // mode 0
    inode[4] = 3; // version 3
    inode[5] = fmt_dev; // format 0 for an unused inode
    beU32(inode, 92, 0); // gen 0 for determinism
    beU32(inode, 96, null_ino32); // next_unlinked
    beU64(inode, 152, ino);
    @memcpy(inode[160..176], &ctx.options.format.uuid);
    writeCrc(inode, 100);
}

fn writeInodeCore(ctx: *WriteCtx, inode: []u8, node: *InodeNode) WriteError!void {
    @memset(inode, 0);
    beU16(inode, 0, inode_magic);
    beU16(inode, 2, node.typeBit() | (node.mode_bits & 0o7777));
    inode[4] = 3; // version
    inode[5] = node.di_format;
    beU16(inode, 6, 0); // di_onlink
    beU32(inode, 8, node.uid);
    beU32(inode, 12, node.gid);
    beU32(inode, 16, node.nlink);
    beU16(inode, 20, 0); // projid lo
    beU16(inode, 22, 0); // projid hi
    beU16(inode, 30, 0); // flushiter
    writeTimestamp(inode, 32, node.atime, node.atime_nsec);
    writeTimestamp(inode, 40, node.mtime, node.mtime_nsec);
    writeTimestamp(inode, 48, node.ctime, node.ctime_nsec);
    beU64(inode, 56, node.size);
    beU64(inode, 64, node.data_block_count); // di_nblocks (data fork only)
    beU32(inode, 72, 0); // extsize
    beU32(inode, 76, node.nextents);
    beU16(inode, 80, 0); // anextents (shortform attr fork uses none)
    inode[82] = node.forkoff;
    inode[83] = if (node.xattrs.len != 0) fmt_local else fmt_extents;
    beU16(inode, 90, 0); // di_flags
    beU32(inode, 92, 0); // di_gen deterministic
    beU32(inode, 96, null_ino32); // next_unlinked
    beU64(inode, 104, 0); // changecount
    beU64(inode, 112, 0); // lsn
    beU64(inode, 120, 0); // flags2
    beU32(inode, 128, 0); // cowextsize
    writeTimestamp(inode, 144, node.crtime, node.crtime_nsec);
    beU64(inode, 152, node.ino);
    @memcpy(inode[160..176], &ctx.options.format.uuid);

    // Data fork (literal area starts at 176).
    try writeDataFork(ctx, inode, node);
    // Attr fork (shortform), if any.
    if (node.xattrs.len != 0) writeAttrFork(inode, node);

    writeCrc(inode, 100);
}

fn writeDataFork(ctx: *WriteCtx, inode: []u8, node: *InodeNode) WriteError!void {
    const lit = inode[176..inode_size];
    switch (node.kind) {
        .directory => if (node.dir_is_block) {
            encodeExtent(lit[0..16], 0, node.data_start_block, 1, false);
            try writeBlockDirectory(ctx, node);
        } else {
            writeShortformDir(lit, node);
        },
        .file => if (node.nextents == 1) {
            encodeExtent(lit[0..16], 0, node.data_start_block, node.data_block_count, false);
            try writeFileData(ctx, node);
        },
        .symlink => if (node.di_format == fmt_local) {
            @memcpy(lit[0..node.symlink_target.len], node.symlink_target);
        } else {
            encodeExtent(lit[0..16], 0, node.data_start_block, 1, false);
            writeRemoteSymlink(ctx, node);
        },
        .block_device, .char_device => beU32(lit, 0, encodeDev(node.device.major, node.device.minor)),
        .fifo => beU32(lit, 0, 0),
        .hardlink => unreachable,
    }
}

/// Inverse of the reader's `decodeBmbtRec`.
fn encodeExtent(buf: []u8, logical: u64, start: u64, count: u64, unwritten: bool) void {
    const l0: u64 = (@as(u64, @intFromBool(unwritten)) << 63) | (logical << 9) | (start >> 43);
    const l1: u64 = ((start & ((@as(u64, 1) << 43) - 1)) << 21) | count;
    beU64(buf, 0, l0);
    beU64(buf, 8, l1);
}

fn writeShortformDir(lit: []u8, node: *InodeNode) void {
    const big = dirNeedsBigInodes(node);
    lit[0] = @intCast(node.children.items.len); // count
    lit[1] = if (big) @intCast(node.children.items.len) else 0; // i8count
    var pos: usize = 2;
    if (big) {
        beU64(lit, pos, node.parent_ino);
        pos += 8;
    } else {
        beU32(lit, pos, @intCast(node.parent_ino));
        pos += 4;
    }
    // The shortform "offset" field mirrors the data-block position each entry
    // would occupy; xfs_repair validates it even though the reader ignores it.
    var data_off: u32 = first_entry_offset;
    for (node.children.items) |c| {
        lit[pos] = @intCast(c.name.len);
        pos += 1;
        beU16(lit, pos, @intCast(data_off));
        pos += 2;
        @memcpy(lit[pos..][0..c.name.len], c.name);
        pos += c.name.len;
        lit[pos] = c.ftype;
        pos += 1;
        if (big) {
            beU64(lit, pos, c.ino);
            pos += 8;
        } else {
            beU32(lit, pos, @intCast(c.ino));
            pos += 4;
        }
        data_off += dataEntSize(c.name.len);
    }
}

fn writeAttrFork(inode: []u8, node: *InodeNode) void {
    const attr = inode[176 + @as(usize, node.forkoff) * 8 .. inode_size];
    var total: u16 = 4;
    for (node.xattrs) |x| total += @intCast(3 + x.name.len + x.value.len);
    beU16(attr, 0, total); // totsize
    attr[2] = @intCast(node.xattrs.len); // count
    attr[3] = 0; // pad
    var pos: usize = 4;
    for (node.xattrs) |x| {
        attr[pos] = @intCast(x.name.len);
        attr[pos + 1] = @intCast(x.value.len);
        attr[pos + 2] = x.flags;
        pos += 3;
        @memcpy(attr[pos..][0..x.name.len], x.name);
        pos += x.name.len;
        @memcpy(attr[pos..][0..x.value.len], x.value);
        pos += x.value.len;
    }
}

fn writeFileData(ctx: *WriteCtx, node: *InodeNode) WriteError!void {
    const base = node.data_start_block * block_size;
    @memcpy(ctx.region[@intCast(base)..][0..node.file_content.len], node.file_content);
    // Trailing bytes of the last block stay zero (already memset).
}

fn writeRemoteSymlink(ctx: *WriteCtx, node: *InodeNode) void {
    const blk = ctx.blockSlice(node.data_start_block);
    beU32(blk, 0, symlink_magic);
    beU32(blk, 4, 0); // sl_offset
    beU32(blk, 8, @intCast(node.symlink_target.len)); // sl_bytes
    @memcpy(blk[16..32], &ctx.options.format.uuid);
    beU64(blk, 32, node.ino); // sl_owner
    beU64(blk, 40, node.data_start_block * (block_size / sector_size)); // sl_blkno
    beU64(blk, 48, 0); // sl_lsn
    @memcpy(blk[56..][0..node.symlink_target.len], node.symlink_target);
    writeCrc(blk, 12);
}

// ---------------------------------------------------------------------------
// Block-format directory data block.
// ---------------------------------------------------------------------------

const LeafEntry = struct { hash: u32, address: u32 };

fn leafLess(_: void, x: LeafEntry, y: LeafEntry) bool {
    if (x.hash != y.hash) return x.hash < y.hash;
    return x.address < y.address;
}

fn writeBlockDirectory(ctx: *WriteCtx, node: *InodeNode) WriteError!void {
    const blk = ctx.blockSlice(node.data_start_block);
    const a = ctx.plan.allocator();

    const leaf_count: u32 = @intCast(2 + node.children.items.len);
    const leaf_start: u32 = block_size - 8 - leaf_count * 8;

    var leaves = try a.alloc(LeafEntry, leaf_count);

    // --- header ---
    beU32(blk, 0, dir3_block_magic);
    beU64(blk, 8, node.data_start_block * (block_size / sector_size)); // blkno
    beU64(blk, 16, 0); // lsn
    @memcpy(blk[24..40], &ctx.options.format.uuid);
    beU64(blk, 40, node.ino); // owner

    // --- data entries: "." , ".." , then sorted children ---
    var off: u32 = dir_data_hdr_len;
    writeDirDataEntry(blk, &off, node.ino, ".", ft_dir);
    leaves[0] = .{ .hash = hashName("."), .address = dir_data_hdr_len / 8 };
    const dotdot_off = off;
    writeDirDataEntry(blk, &off, node.parent_ino, "..", ft_dir);
    leaves[1] = .{ .hash = hashName(".."), .address = dotdot_off / 8 };

    for (node.children.items, 0..) |c, i| {
        const entry_off = off;
        writeDirDataEntry(blk, &off, c.ino, c.name, c.ftype);
        leaves[2 + i] = .{ .hash = hashName(c.name), .address = entry_off / 8 };
    }

    // --- unused free entry filling the gap up to the leaf array ---
    const gap = leaf_start - off;
    var best_off: u16 = 0;
    var best_len: u16 = 0;
    if (gap > 0) {
        beU16(blk, off, 0xffff); // freetag
        beU16(blk, off + 2, @intCast(gap)); // length
        beU16(blk, leaf_start - 2, @intCast(off)); // tag at end of unused entry
        best_off = @intCast(off);
        best_len = @intCast(gap);
    }
    beU16(blk, 48, best_off); // bestfree[0].offset
    beU16(blk, 50, best_len); // bestfree[0].length

    // --- leaf hash array (sorted by hash) ---
    std.sort.block(LeafEntry, leaves, {}, leafLess);
    var l: u32 = 0;
    while (l < leaf_count) : (l += 1) {
        beU32(blk, leaf_start + l * 8, leaves[l].hash);
        beU32(blk, leaf_start + l * 8 + 4, leaves[l].address);
    }

    // --- block tail: count, stale ---
    beU32(blk, block_size - 8, leaf_count);
    beU32(blk, block_size - 4, 0);

    writeCrc(blk, 4);
}

fn writeDirDataEntry(blk: []u8, off: *u32, ino: u64, name: []const u8, ftype: u8) void {
    const start = off.*;
    const size = dataEntSize(name.len);
    beU64(blk, start, ino);
    blk[start + 8] = @intCast(name.len);
    @memcpy(blk[start + 9 ..][0..name.len], name);
    blk[start + 9 + name.len] = ftype;
    beU16(blk, start + size - 2, @intCast(start)); // tag = this entry's offset
    off.* = start + size;
}

// ---------------------------------------------------------------------------
// Clean internal log (a single unmount record), replicated byte-for-byte from
// mkfs so xfs_repair sees a clean log needing no recovery.
// ---------------------------------------------------------------------------

fn writeLog(ctx: *WriteCtx) void {
    const g = ctx.geom();
    const base = g.log_phys_block * block_size;
    const header = ctx.region[@intCast(base)..][0..sector_size];

    beU32(header, 0, log_magic);
    beU32(header, 4, 1); // h_cycle
    beU32(header, 8, 2); // h_version
    beU32(header, 12, sector_size); // h_len
    beU64(header, 16, (@as(u64, 1) << 32)); // h_lsn = (cycle 1, block 0)
    beU64(header, 24, (@as(u64, 1) << 32)); // h_tail_lsn
    leU32(header, 32, 0); // h_crc (a clean log is not replayed, so left zero)
    beU32(header, 36, null_fsblock); // h_prev_block
    beU32(header, 40, 1); // h_num_logops
    beU32(header, 44, 0xb0c0d0d0); // h_cycle_data[0] = saved first word of data sector
    beU32(header, 300, 1); // h_fmt = XLOG_FMT_LINUX_LE
    @memcpy(header[304..320], &ctx.options.format.uuid);
    beU32(header, 320, 32768); // h_size

    // Unmount record data sector: first word cycle-stamped to the cycle number.
    const data = ctx.region[@intCast(base + sector_size)..][0..sector_size];
    beU32(data, 0, 1); // cycle stamp (original 0xb0c0d0d0 saved above)
    beU32(data, 4, 8); // oh_len
    data[8] = 0xaa; // oh_clientid = XFS_LOG
    data[9] = 0x20; // oh_flags = XLOG_UNMOUNT_TRANS
    leU16(data, 12, 0x556e); // unmount magic, little-endian per h_fmt
}

// ===========================================================================
// Tests
//
// These are pure-Zig: they build an in-memory cursor, populate a buffer, and
// reopen it with the merged XFS reader (`xfs.zig`). They never shell out to
// mkfs.xfs/xfs_repair -- that validation is a development step, documented in
// the commit, not a unit-test dependency.
// ===========================================================================

const testing = std.testing;
const xfs = @import("xfs.zig");
const Io = std.Io;

/// A minimal in-memory `Cursor` a test drives from a flat entry slice.
const FixtureEntry = struct {
    path: []const u8,
    kind: Kind,
    mode: u16 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    size: u64 = 0,
    content: []const u8 = "",
    xattrs: []const tree_cursor.Xattr = &.{},
    device: tree_cursor.DeviceNumbers = .{},
    hardlink_target: []const u8 = "",
    atime: ?i64 = null,
    mtime: ?i64 = null,
    ctime: ?i64 = null,
    crtime: ?i64 = null,
    atime_nsec: u32 = 0,
    mtime_nsec: u32 = 0,
    ctime_nsec: u32 = 0,
    crtime_nsec: u32 = 0,
};

const FixtureCursor = struct {
    entries: []FixtureEntry,
    index: usize = 0,

    fn readAt(ctx: *const anyopaque, buffer: []u8, offset: u64) Cursor.ContentError!usize {
        const e: *const FixtureEntry = @ptrCast(@alignCast(ctx));
        if (offset >= e.content.len) return 0;
        const n = @min(buffer.len, e.content.len - offset);
        @memcpy(buffer[0..n], e.content[@intCast(offset)..][0..n]);
        return n;
    }

    fn nextFn(ctx: *anyopaque) Cursor.IteratorError!?Cursor.Entry {
        const self: *FixtureCursor = @ptrCast(@alignCast(ctx));
        if (self.index >= self.entries.len) return null;
        const e = &self.entries[self.index];
        self.index += 1;
        return Cursor.Entry{
            .path = e.path,
            .kind = e.kind,
            .mode = e.mode,
            .uid = e.uid,
            .gid = e.gid,
            .size = e.size,
            .content = if (e.content.len > 0) .{ .ctx = e, .read_at_fn = readAt } else null,
            .xattrs = e.xattrs,
            .device = e.device,
            .hardlink_target = e.hardlink_target,
            .atime = e.atime,
            .mtime = e.mtime,
            .ctime = e.ctime,
            .crtime = e.crtime,
            .atime_nsec = e.atime_nsec,
            .mtime_nsec = e.mtime_nsec,
            .ctime_nsec = e.ctime_nsec,
            .crtime_nsec = e.crtime_nsec,
        };
    }

    fn resetFn(ctx: *anyopaque) void {
        const self: *FixtureCursor = @ptrCast(@alignCast(ctx));
        self.index = 0;
    }

    fn cursor(self: *FixtureCursor) Cursor {
        return .{ .ctx = self, .next_fn = nextFn, .reset_fn = resetFn };
    }
};

fn writeFixtureFile(path: []const u8, bytes: []const u8) !void {
    const io = std.testing.io;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

/// Mirrors the reader's `new_decode_dev`, so a device test can assert the
/// exact (major, minor) the reader will report from the real `sysv_encode_dev`
/// bytes this writer stores -- documenting, not hiding, that the two encodings
/// differ (see `encodeDev`).
fn readerDecodeDev(major: u32, minor: u32) tree_cursor.DeviceNumbers {
    const rdev = encodeDev(major, minor);
    return .{
        .major = (rdev >> 8) & 0xfff,
        .minor = (rdev & 0xff) | ((rdev >> 12) & 0xffff_ff00),
    };
}

const roundtrip_opts = PopulateOptions{
    .format = .{
        .length = 160 * 1024 * 1024,
        .uuid = xfs.test_fs_uuid,
        .label = "writertest",
        .timestamp = .{ .sec = 1_600_000_000, .nsec = 123456789 },
    },
    .root = .{ .mode = 0o755, .uid = 0, .gid = 0 },
};

test "populate emits a tree the merged reader reads back field-for-field" {
    const allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const big_bin = try a.alloc(u8, 5000);
    for (big_bin, 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xff);
    const long_target = try a.alloc(u8, 500); // forces a remote (out-of-line) symlink
    for (long_target, 0..) |*b, i| b.* = 'a' + @as(u8, @intCast(i % 26));

    const file_xattrs = [_]tree_cursor.Xattr{
        .{ .name = "user.color", .value = "blue" },
        .{ .name = "trusted.seal", .value = "xyz" },
    };

    var list = std.ArrayListUnmanaged(FixtureEntry).empty;
    try list.append(a, .{ .path = "file.txt", .kind = .file, .mode = 0o640, .uid = 1000, .gid = 1000, .size = 12, .content = "hello world\n", .mtime = 1_650_000_000 });
    try list.append(a, .{ .path = "empty.txt", .kind = .file, .mode = 0o600, .size = 0 });
    try list.append(a, .{ .path = "big.bin", .kind = .file, .mode = 0o644, .size = 5000, .content = big_bin });
    try list.append(a, .{ .path = "attrs.txt", .kind = .file, .mode = 0o644, .size = 3, .content = "abc", .xattrs = &file_xattrs });
    try list.append(a, .{ .path = "dir", .kind = .directory, .mode = 0o755 });
    try list.append(a, .{ .path = "dir/nested.txt", .kind = .file, .mode = 0o644, .size = 6, .content = "nested" });
    try list.append(a, .{ .path = "link", .kind = .symlink, .size = 8, .content = "file.txt" });
    try list.append(a, .{ .path = "longlink", .kind = .symlink, .size = 500, .content = long_target });
    try list.append(a, .{ .path = "cdev", .kind = .char_device, .mode = 0o600, .device = .{ .major = 1, .minor = 3 } });
    try list.append(a, .{ .path = "bdev", .kind = .block_device, .mode = 0o660, .device = .{ .major = 8, .minor = 0 } });
    try list.append(a, .{ .path = "pipe", .kind = .fifo, .mode = 0o644 });
    try list.append(a, .{ .path = "hard", .kind = .hardlink, .hardlink_target = "file.txt" });

    // A directory large enough to overflow shortform into single-block format.
    try list.append(a, .{ .path = "bigdir", .kind = .directory, .mode = 0o755 });
    var i: usize = 0;
    while (i < 30) : (i += 1) {
        const name = try std.fmt.allocPrint(a, "bigdir/entry_{d:0>3}", .{i});
        try list.append(a, .{ .path = name, .kind = .file, .mode = 0o644, .size = 0 });
    }

    var fc = FixtureCursor{ .entries = list.items };
    var cur = fc.cursor();

    const min = try minimumSize(allocator, &cur, roundtrip_opts);
    const buffer = try allocator.alloc(u8, roundtrip_opts.format.length);
    defer allocator.free(buffer);
    @memset(buffer, 0xcc); // poison, so the writer must overwrite everything it uses
    try testing.expect(roundtrip_opts.format.length >= min);
    try populate(allocator, buffer, &cur, roundtrip_opts);

    const path = "test-xfs-writer-roundtrip.img";
    try writeFixtureFile(path, buffer);
    defer Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    const io = std.testing.io;
    var reader = try xfs.Reader.openPath(allocator, io, path);
    defer reader.close(io);

    var tree = try xfs.scanReadable(&reader, io, allocator, .{ .available_length = roundtrip_opts.format.length });
    defer tree.deinit();

    // Identity.
    try testing.expectEqualSlices(u8, &xfs.test_fs_uuid, &tree.identity.uuid);
    try testing.expectEqual(@as(u32, block_size), tree.identity.block_size);
    try testing.expectEqual(@as(u16, inode_size), tree.identity.inode_size);
    try testing.expectEqual(@as(u32, features_incompat), tree.identity.features_incompat);
    try testing.expectEqualSlices(u8, "writertest\x00\x00", &tree.identity.label);

    // Root metadata.
    try testing.expectEqual(@as(u16, 0o755), tree.root.mode);

    // file.txt: content, mode, ownership, explicit mtime, fallback atime/nsec.
    const file_txt = findRt(&tree, "file.txt").?;
    try testing.expectEqual(xfs.Kind.file, file_txt.kind);
    try testing.expectEqual(@as(u16, 0o640), file_txt.mode);
    try testing.expectEqual(@as(u32, 1000), file_txt.uid);
    try testing.expectEqual(@as(u32, 1000), file_txt.gid);
    try testing.expectEqual(@as(i64, 1_650_000_000), file_txt.mtime);
    try testing.expectEqual(@as(i64, 1_600_000_000), file_txt.atime);
    try testing.expectEqual(@as(u32, 123456789), file_txt.atime_nsec);
    const file_txt_bytes = try readRt(allocator, file_txt);
    defer allocator.free(file_txt_bytes);
    try testing.expectEqualStrings("hello world\n", file_txt_bytes);

    // empty.txt.
    const empty_txt = findRt(&tree, "empty.txt").?;
    try testing.expectEqual(@as(u64, 0), empty_txt.size);

    // big.bin: a two-block EXTENTS file read back byte-for-byte.
    const big = findRt(&tree, "big.bin").?;
    try testing.expectEqual(@as(u64, 5000), big.size);
    const big_bytes = try readRt(allocator, big);
    defer allocator.free(big_bytes);
    try testing.expectEqualSlices(u8, big_bin, big_bytes);

    // attrs.txt: shortform xattr fork round-trips both namespaces.
    const attrs = findRt(&tree, "attrs.txt").?;
    try expectRtXattr(attrs, "user.color", "blue");
    try expectRtXattr(attrs, "trusted.seal", "xyz");

    // dir/nested.txt via a shortform subdirectory.
    const nested = findRt(&tree, "dir/nested.txt").?;
    const nested_bytes = try readRt(allocator, nested);
    defer allocator.free(nested_bytes);
    try testing.expectEqualStrings("nested", nested_bytes);

    // Inline (local) symlink.
    const link = findRt(&tree, "link").?;
    try testing.expectEqual(xfs.Kind.symlink, link.kind);
    const link_target = try readRt(allocator, link);
    defer allocator.free(link_target);
    try testing.expectEqualStrings("file.txt", link_target);

    // Remote (out-of-line) symlink.
    const longlink = findRt(&tree, "longlink").?;
    const longlink_target = try readRt(allocator, longlink);
    defer allocator.free(longlink_target);
    try testing.expectEqualSlices(u8, long_target, longlink_target);

    // Character and block devices: kind is exact; the reader's decode of the
    // real on-disk (sysv) rdev is what we assert against.
    const cdev = findRt(&tree, "cdev").?;
    try testing.expectEqual(xfs.Kind.char_device, cdev.kind);
    const cdev_expect = readerDecodeDev(1, 3);
    try testing.expectEqual(cdev_expect.major, cdev.device.major);
    try testing.expectEqual(cdev_expect.minor, cdev.device.minor);
    const bdev = findRt(&tree, "bdev").?;
    try testing.expectEqual(xfs.Kind.block_device, bdev.kind);

    // FIFO.
    const pipe = findRt(&tree, "pipe").?;
    try testing.expectEqual(xfs.Kind.fifo, pipe.kind);

    // Hardlink: same identity as file.txt, surfaced as `.hardlink`.
    const hard = findRt(&tree, "hard").?;
    try testing.expectEqual(xfs.Kind.hardlink, hard.kind);
    try testing.expectEqualStrings("file.txt", hard.hardlink_target);

    // Block-format directory: all 30 children present and readable.
    var seen: usize = 0;
    var j: usize = 0;
    while (j < 30) : (j += 1) {
        var namebuf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&namebuf, "bigdir/entry_{d:0>3}", .{j});
        if (findRt(&tree, name) != null) seen += 1;
    }
    try testing.expectEqual(@as(usize, 30), seen);
}

test "populate is byte-for-byte deterministic" {
    const allocator = testing.allocator;
    var entries = [_]FixtureEntry{
        .{ .path = "a.txt", .kind = .file, .mode = 0o644, .size = 5, .content = "alpha" },
        .{ .path = "d", .kind = .directory, .mode = 0o755 },
        .{ .path = "d/b.txt", .kind = .file, .mode = 0o644, .size = 4, .content = "beta" },
        .{ .path = "s", .kind = .symlink, .size = 5, .content = "a.txt" },
    };
    const opts = PopulateOptions{ .format = .{ .length = 160 * 1024 * 1024, .uuid = xfs.test_fs_uuid } };

    var fc1 = FixtureCursor{ .entries = &entries };
    var cur1 = fc1.cursor();
    const buf1 = try allocator.alloc(u8, opts.format.length);
    defer allocator.free(buf1);
    @memset(buf1, 0);
    try populate(allocator, buf1, &cur1, opts);

    var fc2 = FixtureCursor{ .entries = &entries };
    var cur2 = fc2.cursor();
    const buf2 = try allocator.alloc(u8, opts.format.length);
    defer allocator.free(buf2);
    @memset(buf2, 0xff);
    try populate(allocator, buf2, &cur2, opts);

    try testing.expect(std.mem.eql(u8, buf1, buf2));
}

fn expectReject(entries: []FixtureEntry, root: RootMetadata, length: u64, expected: WriteError) !void {
    var fc = FixtureCursor{ .entries = entries };
    var cur = fc.cursor();
    var empty: [0]u8 = .{};
    const res = populate(testing.allocator, &empty, &cur, .{
        .format = .{ .length = length, .uuid = xfs.test_fs_uuid },
        .root = root,
    });
    try testing.expectError(expected, res);
}

test "populate rejects unsupported shapes before writing" {
    const big_len = 160 * 1024 * 1024;

    {
        var e = [_]FixtureEntry{.{ .path = "only.txt", .kind = .file, .size = 1, .content = "x" }};
        try expectReject(&e, .{}, 1024, error.LengthTooSmall);
    }
    {
        var e = [_]FixtureEntry{
            .{ .path = "d", .kind = .directory, .mode = 0o755 },
            .{ .path = "h", .kind = .hardlink, .hardlink_target = "d" },
        };
        try expectReject(&e, .{}, big_len, error.HardlinkToDirectory);
    }
    {
        var e = [_]FixtureEntry{.{ .path = "h", .kind = .hardlink, .hardlink_target = "nope" }};
        try expectReject(&e, .{}, big_len, error.HardlinkTargetMissing);
    }
    {
        var e = [_]FixtureEntry{
            .{ .path = "dup", .kind = .file, .size = 1, .content = "x" },
            .{ .path = "dup", .kind = .file, .size = 1, .content = "y" },
        };
        try expectReject(&e, .{}, big_len, error.DuplicateName);
    }
    {
        var big: [2000]u8 = undefined;
        @memset(&big, 'a');
        var e = [_]FixtureEntry{.{ .path = "s", .kind = .symlink, .size = 2000, .content = &big }};
        try expectReject(&e, .{}, big_len, error.SymlinkTooLong);
    }
    {
        var e = [_]FixtureEntry{.{ .path = "s", .kind = .symlink, .size = 0 }};
        try expectReject(&e, .{}, big_len, error.EmptySymlink);
    }
    {
        const xa = [_]tree_cursor.Xattr{.{ .name = "bogus.x", .value = "v" }};
        var e = [_]FixtureEntry{.{ .path = "f", .kind = .file, .size = 1, .content = "x", .xattrs = &xa }};
        try expectReject(&e, .{}, big_len, error.UnsupportedXattrNamespace);
    }
    {
        var e = [_]FixtureEntry{.{ .path = "a/b/c", .kind = .file, .size = 1, .content = "x" }};
        try expectReject(&e, .{}, big_len, error.MissingParent);
    }
    {
        var e = [_]FixtureEntry{.{ .path = "/abs", .kind = .file, .size = 1, .content = "x" }};
        try expectReject(&e, .{}, big_len, error.AbsolutePath);
    }
    {
        var e = [_]FixtureEntry{.{ .path = "f", .kind = .file, .size = 1, .content = "x" }};
        var fc = FixtureCursor{ .entries = &e };
        var cur = fc.cursor();
        var empty: [0]u8 = .{};
        const res = populate(testing.allocator, &empty, &cur, .{
            .format = .{ .length = big_len, .uuid = xfs.test_fs_uuid, .label = "this-label-is-way-too-long" },
        });
        try testing.expectError(error.LabelTooLong, res);
    }
    {
        const xa = [_]tree_cursor.Xattr{.{ .name = "user.k", .value = &[_]u8{'v'} ** 300 }};
        var e = [_]FixtureEntry{.{ .path = "f", .kind = .file, .size = 1, .content = "x", .xattrs = &xa }};
        try expectReject(&e, .{}, big_len, error.XattrValueTooLarge);
    }
}

test "populate rejects an over-large single directory" {
    const allocator = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var list = std.ArrayListUnmanaged(FixtureEntry).empty;
    try list.append(a, .{ .path = "d", .kind = .directory, .mode = 0o755 });
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        const name = try std.fmt.allocPrint(a, "d/entry_number_{d:0>4}", .{i});
        try list.append(a, .{ .path = name, .kind = .file, .size = 0 });
    }
    try expectReject(list.items, .{}, 512 * 1024 * 1024, error.DirectoryTooLarge);
}

fn findRt(tree: *xfs.Tree, path: []const u8) ?xfs.Entry {
    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const entry = tree.entryAt(index);
        if (std.mem.eql(u8, entry.path, path)) return entry;
    }
    return null;
}

fn readRt(allocator: std.mem.Allocator, entry: xfs.Entry) ![]u8 {
    const bytes = try allocator.alloc(u8, @intCast(entry.size));
    errdefer allocator.free(bytes);
    const content = entry.content orelse return error.MissingContent;
    var done: usize = 0;
    while (done < bytes.len) {
        const got = try content.readAt(bytes[done..], done);
        if (got == 0) return error.UnexpectedEndOfStream;
        done += got;
    }
    return bytes;
}

fn expectRtXattr(entry: xfs.Entry, name: []const u8, value: []const u8) !void {
    for (entry.xattrs) |xattr| {
        if (!std.mem.eql(u8, xattr.name, name)) continue;
        try testing.expectEqualStrings(value, xattr.value);
        return;
    }
    return error.TestUnexpectedResult;
}
