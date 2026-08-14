//! XFS **read-only** reader for a bounded, explicitly-scoped subset of the
//! on-disk format.
//!
//! This is step 1 ("read before write") of the XFS support plan: a general
//! reader that feeds `root_tree` with an owned or borrowed tree of metadata,
//! the way `ext4.zig`'s `GeneralTree`/`scanReadable` and `squashfs.zig`'s
//! `Reader` already do for their filesystems. `root_tree` (`importXfs`/
//! `mountXfs`), `capture` (root discovery, `--source-root`, `--source-mount`)
//! and COSI's `/etc/os-release` extraction are all wired to this reader; only
//! writing to an XFS filesystem remains out of scope.
//!
//! Supported on-disk profile (anything outside this list is rejected with a
//! named error rather than silently skipped or misread):
//!  - XFS v5 (CRC-enabled) superblocks only. v1-v4 (pre-CRC) filesystems are
//!    refused outright.
//!  - The `FTYPE` incompat feature is required (every mainstream `mkfs.xfs`
//!    since 2016 sets it); `SPINODES`, `META_UUID`, `BIGTIME`, and `NREXT64`
//!    are understood and handled. `NEEDSREPAIR`, `EXCHRANGE`, `PARENT`,
//!    `METADIR`, `ZONED`, and `ZONE_GAPS` are refused by name, as is any
//!    other unrecognized incompat bit.
//!  - All four known ro-compat bits (`FINOBT`, `RMAPBT`, `REFLINK`,
//!    `INOBTCNT`) are accepted and ignored: they change free-space/rmap/
//!    refcount bookkeeping this reader never touches, not how file, directory,
//!    or extended-attribute data is stored.
//!  - Realtime volumes (a non-zero `sb_rblocks`, or an inode with
//!    `XFS_DIFLAG_REALTIME` set) are refused: this reader never looks at the
//!    separate realtime bitmap/summary inodes or the realtime data section.
//!  - Directories: shortform (embedded in the inode literal area) and
//!    single-block "block" format (one data block holding both entries and
//!    the trailing leaf/tail index) are supported. Multi-block data+leaf,
//!    node, and btree-format directories are refused by name -- a real,
//!    large directory (thousands of entries) will hit this refusal rather
//!    than being silently truncated or misread.
//!  - Regular file data: both `EXTENTS` (a flat array of bmap records in the
//!    inode literal area) and `BTREE` (a long-form bmap B+tree, walked
//!    recursively to arbitrary depth) formats are supported, so fragmented or
//!    large files are not arbitrarily excluded. Holes and "unwritten"
//!    (allocated-but-never-written) extents both read back as zeros.
//!  - Symlinks: both `LOCAL` (target embedded in the inode) and `EXTENTS`
//!    (up to `XFS_SYMLINK_MAPS` = 3 remote blocks, each with its own header
//!    and CRC) formats are supported.
//!  - Extended attributes: shortform only (`di_aformat == LOCAL`), which
//!    covers the common case of short `security.*`/`user.*` values that fit
//!    in the inode literal area. Leaf/node/btree (out-of-line) attribute
//!    forks are refused by name.
//!  - Device nodes (`FMT_DEV`), hardlink identity (via first-seen-path
//!    tracking), and POSIX metadata/timestamps (including the 64-bit
//!    `BIGTIME` encoding) are all supported.
//!
//! Known, deliberate limitations (documented rather than silently assumed
//! away):
//!  - This reader does **not** detect an unreplayed (dirty) XFS log. Unlike
//!    `ext4.zig`'s `SourceNeedsJournalRecovery` check, XFS log-dirty
//!    detection requires understanding the log record format, which is out
//!    of scope for this PR. A source that was not cleanly unmounted may be
//!    read with stale metadata and this reader will not notice.
//!  - ACL extended attributes are surfaced using their raw on-disk name
//!    (e.g. `trusted.SGI_ACL_FILE`) rather than the VFS-translated name a
//!    live mount would report (`system.posix_acl_access`); translating that
//!    is not implemented.
//!  - Reflink (shared/CoW) extents are read as ordinary extents: the shared
//!    physical blocks are simply read and copied like any other extent, so
//!    reflinked files still import correctly, just without the underlying
//!    sharing being preserved.
//!  - `readExtents`'s `FMT_BTREE` walk bounds recursion depth
//!    (`max_extent_depth`) and validates every child pointer against the
//!    filesystem's real block count, but it does not deduplicate repeated
//!    visits to the same physical block across sibling pointers. A
//!    deliberately adversarial bmap btree could reference the same child
//!    block from many parents to inflate the work one read does; this is a
//!    hardening gap for a hostile image, not a correctness bug against any
//!    real `mkfs.xfs`/`xfs_repair`-produced tree, which never does this.

const std = @import("std");
const Io = std.Io;
const limits_mod = @import("limits.zig");

const limit_defaults = limits_mod.ImportLimits{};

// ---------------------------------------------------------------------------
// On-disk constants
// ---------------------------------------------------------------------------

/// `sb_magicnum`, big-endian bytes "XFSB".
pub const magic: u32 = 0x5846_5342;
/// `di_magic`, big-endian bytes "IN".
const dinode_magic: u16 = 0x494e;
/// `XFS_DIR3_BLOCK_MAGIC`, big-endian bytes "XDB3": single-block directory.
const dir3_block_magic: u32 = 0x5844_4233;
/// `XFS_DIR3_DATA_MAGIC`, big-endian bytes "XDD3": multi-block directory
/// data block. Any directory data fork carrying this magic instead of
/// `dir3_block_magic` is a multi-block layout this reader refuses.
const dir3_data_magic: u32 = 0x5844_4433;
/// `XFS_SYMLINK_MAGIC`, big-endian bytes "XSLM".
const symlink_magic: u32 = 0x5853_4c4d;
/// `XFS_BMAP_CRC_MAGIC`, big-endian bytes "BMA3": long-form bmap btree block.
const bmap_btree_magic: u32 = 0x424d_4133;

const superblock_size: usize = 512;
const dinode_v3_core_size: usize = 176;
const dinode_crc_offset: usize = 100;
const dir3_data_header_size: usize = 64;
// struct xfs_dsymlink_hdr: sl_magic(be32,0) + sl_offset(be32,4) + sl_bytes(be32,8) +
// sl_crc(le32,12) + sl_uuid(16,16) + sl_owner(be64,32) + sl_blkno(be64,40) + sl_lsn(be64,48).
const symlink_header_size: usize = 56;
const symlink_owner_offset: usize = 32;
const bmbt_long_header_size: usize = 72;
const bmbt_rec_size: usize = 16;
/// `struct xfs_bmdr_block` (the inode-literal-area btree root header):
/// bb_level(be16,0) + bb_numrecs(be16,2) = 4 bytes.
const bmdr_header_size: usize = 4;
/// Both the inode-rooted root (`xfs_bmdr_block`) and the on-disk long-form
/// btree blocks (`xfs_btree_block`) store their key and pointer arrays as
/// fixed-capacity vectors sized for `maxrecs` -- the maximum number of
/// records that could ever fit in the available space -- not for the
/// `numrecs` actually populated. The pointer array therefore always starts
/// at `maxrecs * key_size` past the key array's start, never at
/// `numrecs * key_size`: getting this wrong reads pointers out of what is
/// actually still key bytes (or beyond the block) for any node that isn't
/// completely full. See `xfs_bmdr_ptr_addr`/`xfs_bmbt_ptr_addr` in
/// `xfs_bmap_btree.h`.
const bmbt_key_size: usize = 8;
const bmbt_ptr_size: usize = 8;

/// XFS_SB_VERSION_NUMBITS: the low 4 bits of `sb_versionnum` are the version.
const sb_version_num_mask: u16 = 0x000f;
const sb_version_5: u16 = 5;

/// `XFS_SB_FEAT_INCOMPAT_*` bits this reader understands or explicitly
/// refuses. Anything outside this set is unknown and therefore refused too.
const incompat_ftype: u32 = 1 << 0;
const incompat_spinodes: u32 = 1 << 1;
const incompat_meta_uuid: u32 = 1 << 2;
const incompat_bigtime: u32 = 1 << 3;
const incompat_needsrepair: u32 = 1 << 4;
const incompat_nrext64: u32 = 1 << 5;
const incompat_exchrange: u32 = 1 << 6;
const incompat_parent: u32 = 1 << 7;
const incompat_metadir: u32 = 1 << 8;
const incompat_zoned: u32 = 1 << 9;
const incompat_zone_gaps: u32 = 1 << 10;
const incompat_known_mask: u32 = incompat_ftype | incompat_spinodes | incompat_meta_uuid |
    incompat_bigtime | incompat_needsrepair | incompat_nrext64 | incompat_exchrange |
    incompat_parent | incompat_metadir | incompat_zoned | incompat_zone_gaps;

const ro_compat_finobt: u32 = 1 << 0;
const ro_compat_rmapbt: u32 = 1 << 1;
const ro_compat_reflink: u32 = 1 << 2;
const ro_compat_inobtcnt: u32 = 1 << 3;
const ro_compat_known_mask: u32 = ro_compat_finobt | ro_compat_rmapbt | ro_compat_reflink | ro_compat_inobtcnt;

/// `di_format`/`di_aformat` values (`enum xfs_dinode_fmt`).
const fmt_dev: u8 = 0;
const fmt_local: u8 = 1;
const fmt_extents: u8 = 2;
const fmt_btree: u8 = 3;

/// `di_flags` (`XFS_DIFLAG_*`) bits this reader needs to recognize.
const diflag_realtime: u16 = 1 << 0;

/// `di_flags2` (`XFS_DIFLAG2_*`) bits this reader needs to recognize.
const diflag2_bigtime: u64 = 1 << 3;
const diflag2_nrext64: u64 = 1 << 4;

/// `XFS_DIR3_FT_*`: directory entry file-type byte, standard Linux `DT_*`
/// numbering.
const dir_ft_unknown: u8 = 0;
const dir_ft_reg_file: u8 = 1;
const dir_ft_dir: u8 = 2;
const dir_ft_chrdev: u8 = 3;
const dir_ft_blkdev: u8 = 4;
const dir_ft_fifo: u8 = 5;
const dir_ft_sock: u8 = 6;
const dir_ft_symlink: u8 = 7;
const dir_ft_whiteout: u8 = 8;

/// `XFS_ATTR_*` shortform entry flag bits.
const attr_root_bit: u8 = 1 << 1;
const attr_secure_bit: u8 = 1 << 2;
const attr_parent_bit: u8 = 1 << 3;
const attr_incomplete_bit: u8 = 1 << 7;

/// POSIX file-type bits (`S_IFMT` and friends), used to decode `di_mode`.
const s_ifmt: u16 = 0o170000;
const s_ififo: u16 = 0o010000;
const s_ifchr: u16 = 0o020000;
const s_ifdir: u16 = 0o040000;
const s_ifblk: u16 = 0o060000;
const s_ifreg: u16 = 0o100000;
const s_iflnk: u16 = 0o120000;
const s_ifsock: u16 = 0o140000;

/// The bigtime epoch offset applied when decoding a 64-bit nanosecond
/// timestamp: `unix_seconds = (raw_ns / 1e9) - 2^31`.
const bigtime_epoch_offset: i64 = 2147483648;

// ---------------------------------------------------------------------------
// CRC32C (Castagnoli), XFS on-disk convention
// ---------------------------------------------------------------------------

/// Same polynomial/parameters as ext4's metadata_csum CRC32C -- both formats
/// use the ordinary Castagnoli CRC32C. What differs is how the final value is
/// stored: XFS complements it and always writes it little-endian, even though
/// every other XFS field is big-endian (see `xfs_end_cksum()` upstream).
const Crc32c = std.hash.crc.Crc(u32, .{
    .polynomial = 0x1edc6f41,
    .initial = 0xffffffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0,
});

/// Computes the on-disk CRC32C of `buffer`, treating the 4 bytes at
/// `crc_offset` as zero for the purpose of the computation (that is where the
/// stored checksum itself lives).
fn computeCrc32c(buffer: []const u8, crc_offset: usize) u32 {
    var hash = Crc32c.init();
    hash.update(buffer[0..crc_offset]);
    hash.update(&[_]u8{ 0, 0, 0, 0 });
    hash.update(buffer[crc_offset + 4 ..]);
    return ~hash.final();
}

/// Verifies a little-endian XFS CRC32C field embedded at `crc_offset` inside
/// `buffer`.
fn verifyCrc32c(buffer: []const u8, crc_offset: usize) bool {
    const stored = std.mem.readInt(u32, buffer[crc_offset..][0..4], .little);
    return stored == computeCrc32c(buffer, crc_offset);
}

// ---------------------------------------------------------------------------
// Superblock
// ---------------------------------------------------------------------------

pub const Superblock = struct {
    block_size: u32,
    data_blocks: u64,
    realtime_blocks: u64,
    uuid: [16]u8,
    meta_uuid: [16]u8,
    log_start: u64,
    root_ino: u64,
    rt_bitmap_ino: u64,
    rt_summary_ino: u64,
    ag_blocks: u32,
    ag_count: u32,
    log_blocks: u32,
    version_num: u16,
    sector_size: u16,
    inode_size: u16,
    inodes_per_block: u16,
    /// Exact on-disk 12-byte label field, including embedded/trailing NUL
    /// bytes.
    label: [12]u8,
    block_log: u8,
    sector_log: u8,
    inode_log: u8,
    inode_per_block_log: u8,
    ag_block_log: u8,
    quota_flags: u16,
    dir_block_log: u8,
    features_compat: u32,
    features_ro_compat: u32,
    features_incompat: u32,
    features_log_incompat: u32,

    /// Directory data-block size in bytes: `1 << (block_log + dir_block_log)`.
    /// `parseSuperblock` already rejects any combination whose sum would not
    /// fit safely in a `u32` shift amount, but the addition is redone here in
    /// a widened type (rather than trusting the original narrow `u8` fields
    /// not to overflow) so this method can never panic on its own.
    fn dirBlockSize(self: Superblock) u32 {
        const shift: u32 = @as(u32, self.block_log) + @as(u32, self.dir_block_log);
        return @as(u32, 1) << @intCast(shift);
    }

    /// Total AG-number+offset bits used inside an inode number.
    /// `parseSuperblock` already rejects any combination that would not fit
    /// in 63 bits, but see `dirBlockSize`'s comment above for why the sum is
    /// still computed in a widened type here rather than as `u8 + u8`.
    fn aginoBits(self: Superblock) u6 {
        const bits: u32 = @as(u32, self.ag_block_log) + @as(u32, self.inode_per_block_log);
        return @intCast(bits);
    }

    /// Blocks actually present in allocation group `agno`, accounting for the
    /// last (possibly short) AG.
    fn agBlockCount(self: Superblock, agno: u32) u64 {
        if (agno + 1 == self.ag_count) {
            return self.data_blocks - @as(u64, self.ag_count - 1) * self.ag_blocks;
        }
        return self.ag_blocks;
    }
};

pub const OpenError = error{
    BadMagic,
    UnsupportedSuperblockVersion,
    SuperblockChecksumMismatch,
    InvalidSuperblockGeometry,
    RealtimeVolumeUnsupported,
    SourceReadFailed,
    UnexpectedEndOfFile,
} || FeatureError || Io.File.OpenError || Io.File.ReadPositionalError || Io.File.StatError || std.mem.Allocator.Error;

fn maskLow(bits: u6) u64 {
    if (bits >= 64) return std.math.maxInt(u64);
    return (@as(u64, 1) << bits) - 1;
}

fn parseSuperblock(buf: *const [superblock_size]u8) OpenError!Superblock {
    if (std.mem.readInt(u32, buf[0..4], .big) != magic) return error.BadMagic;

    const version_num = std.mem.readInt(u16, buf[100..102], .big);
    if (version_num & sb_version_num_mask != sb_version_5) {
        return error.UnsupportedSuperblockVersion;
    }

    if (!verifyCrc32c(buf, 224)) return error.SuperblockChecksumMismatch;

    const features_compat = std.mem.readInt(u32, buf[208..212], .big);
    const features_ro_compat = std.mem.readInt(u32, buf[212..216], .big);
    const features_incompat = std.mem.readInt(u32, buf[216..220], .big);
    const features_log_incompat = std.mem.readInt(u32, buf[220..224], .big);
    try classifyFeatures(features_compat, features_ro_compat, features_incompat);

    const realtime_blocks = std.mem.readInt(u64, buf[16..24], .big);
    if (realtime_blocks != 0) return error.RealtimeVolumeUnsupported;

    const block_size = std.mem.readInt(u32, buf[4..8], .big);
    const ag_blocks = std.mem.readInt(u32, buf[84..88], .big);
    const ag_count = std.mem.readInt(u32, buf[88..92], .big);
    const data_blocks = std.mem.readInt(u64, buf[8..16], .big);
    const block_log = buf[120];
    const ag_block_log = buf[124];
    const inode_per_block_log = buf[123];
    const dir_block_log = buf[192];

    if (block_size == 0 or !std.math.isPowerOfTwo(block_size) or
        block_log >= 32 or (@as(u32, 1) << @intCast(block_log)) != block_size)
    {
        return error.InvalidSuperblockGeometry;
    }
    if (ag_count == 0 or ag_blocks == 0) return error.InvalidSuperblockGeometry;
    // The AG size is always a power of two number of blocks (mkfs.xfs
    // guarantees this so ino<->agbno math is a plain shift), and every AG
    // except the last is exactly `ag_blocks` blocks.
    if (ag_block_log >= 32 or (@as(u64, 1) << @intCast(ag_block_log)) < ag_blocks) {
        return error.InvalidSuperblockGeometry;
    }
    const expected_total = std.math.mul(u64, ag_count - 1, ag_blocks) catch
        return error.InvalidSuperblockGeometry;
    if (data_blocks <= expected_total) return error.InvalidSuperblockGeometry;
    const last_ag_blocks = data_blocks - expected_total;
    if (last_ag_blocks > ag_blocks) return error.InvalidSuperblockGeometry;
    // Both `ag_block_log`/`inode_per_block_log` (the agino bit width used by
    // `aginoBits`) and `block_log`/`dir_block_log` (the directory
    // block-size shift used by `dirBlockSize`) are raw on-disk `u8` fields
    // with no independent range limit; an adversarial or corrupt superblock
    // could set either byte anywhere up to 255. Widen both sums to `u32`
    // before comparing so a large `inopblog`/`dirblklog` value is rejected
    // by name here rather than overflowing a narrow (`u6`/`u8`) addition or
    // failing an `@intCast` panic the first time some other codepath shifts
    // by it.
    const agino_bits: u32 = @as(u32, ag_block_log) + @as(u32, inode_per_block_log);
    if (agino_bits > 63) return error.InvalidSuperblockGeometry;
    const dir_block_shift: u32 = @as(u32, block_log) + @as(u32, dir_block_log);
    if (dir_block_shift > 31) return error.InvalidSuperblockGeometry;

    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, buf[32..48]);
    var meta_uuid: [16]u8 = undefined;
    @memcpy(&meta_uuid, buf[248..264]);
    var label: [12]u8 = undefined;
    @memcpy(&label, buf[108..120]);

    return .{
        .block_size = block_size,
        .data_blocks = data_blocks,
        .realtime_blocks = realtime_blocks,
        .uuid = uuid,
        .meta_uuid = meta_uuid,
        .log_start = std.mem.readInt(u64, buf[48..56], .big),
        .root_ino = std.mem.readInt(u64, buf[56..64], .big),
        .rt_bitmap_ino = std.mem.readInt(u64, buf[64..72], .big),
        .rt_summary_ino = std.mem.readInt(u64, buf[72..80], .big),
        .ag_blocks = ag_blocks,
        .ag_count = ag_count,
        .log_blocks = std.mem.readInt(u32, buf[96..100], .big),
        .version_num = version_num,
        .sector_size = std.mem.readInt(u16, buf[102..104], .big),
        .inode_size = std.mem.readInt(u16, buf[104..106], .big),
        .inodes_per_block = std.mem.readInt(u16, buf[106..108], .big),
        .label = label,
        .block_log = block_log,
        .sector_log = buf[121],
        .inode_log = buf[122],
        .inode_per_block_log = inode_per_block_log,
        .ag_block_log = ag_block_log,
        .quota_flags = std.mem.readInt(u16, buf[176..178], .big),
        .dir_block_log = dir_block_log,
        .features_compat = features_compat,
        .features_ro_compat = features_ro_compat,
        .features_incompat = features_incompat,
        .features_log_incompat = features_log_incompat,
    };
}

/// Refusals that name the exact XFS feature responsible, mirroring
/// `ext4.classifyGeneralFeatures`'s one-named-error-per-bit approach.
pub const FeatureError = error{
    MissingFtypeFeature,
    SourceNeedsRepair,
    UnsupportedExchangeRangeFeature,
    UnsupportedParentPointerFeature,
    UnsupportedMetadataDirectoryFeature,
    UnsupportedZonedRtFeature,
    UnsupportedZoneGapsFeature,
    UnsupportedIncompatFeature,
    UnsupportedCompatFeature,
};

fn classifyFeatures(compat: u32, ro_compat: u32, incompat: u32) FeatureError!void {
    // No compat bits are defined upstream at all; a non-zero one is
    // unknown by construction.
    if (compat != 0) return error.UnsupportedCompatFeature;

    // Every known ro-compat bit only changes free-space/rmap/refcount
    // bookkeeping, which a read-only importer never touches, so all of them
    // are accepted; anything else is unknown.
    _ = ro_compat;

    const named = [_]struct { bit: u32, err: FeatureError }{
        .{ .bit = incompat_needsrepair, .err = error.SourceNeedsRepair },
        .{ .bit = incompat_exchrange, .err = error.UnsupportedExchangeRangeFeature },
        .{ .bit = incompat_parent, .err = error.UnsupportedParentPointerFeature },
        .{ .bit = incompat_metadir, .err = error.UnsupportedMetadataDirectoryFeature },
        .{ .bit = incompat_zoned, .err = error.UnsupportedZonedRtFeature },
        .{ .bit = incompat_zone_gaps, .err = error.UnsupportedZoneGapsFeature },
    };
    for (named) |entry| {
        if (incompat & entry.bit != 0) return entry.err;
    }
    if (incompat & incompat_ftype == 0) return error.MissingFtypeFeature;
    if (incompat & ~incompat_known_mask != 0) return error.UnsupportedIncompatFeature;
}

// ---------------------------------------------------------------------------
// Reader: superblock + raw block/inode addressing over an open file
// ---------------------------------------------------------------------------

pub const ReadError = error{ UnexpectedEndOfFile, InvalidAddress, SourceReadFailed } ||
    Io.File.ReadPositionalError || std.mem.Allocator.Error;

/// A read-only positional byte source used when XFS lives in a virtual disk
/// view (a partition on a raw disk image, or any format `Image` already
/// translates -- qcow2, VHD, VHDX) rather than directly in `file` at byte 0.
/// Mirrors `ext4.ReadOnlySource`'s shape exactly; callback errors are
/// deliberately collapsed to `error.SourceReadFailed`.
pub const ReadOnlySource = struct {
    ctx: *const anyopaque,
    read_at_fn: *const fn (ctx: *const anyopaque, io: Io, buffer: []u8, offset: u64) anyerror!usize,
};

fn readSourceAll(
    io: Io,
    file: Io.File,
    source: ?ReadOnlySource,
    buffer: []u8,
    offset: u64,
) (Io.File.ReadPositionalError || error{ SourceReadFailed, UnexpectedEndOfFile })!void {
    if (source) |read_source| {
        const got = read_source.read_at_fn(read_source.ctx, io, buffer, offset) catch
            return error.SourceReadFailed;
        if (got != buffer.len) return error.UnexpectedEndOfFile;
        return;
    }
    _ = try file.readPositionalAll(io, buffer, offset);
}

pub const Reader = struct {
    allocator: std.mem.Allocator,
    file: Io.File,
    read_only_source: ?ReadOnlySource = null,
    /// Byte offset of the filesystem's own block 0 within `file` (or within
    /// the byte source `read_only_source` addresses) -- zero for a
    /// standalone `.img` file, and a partition's start offset when the
    /// filesystem is embedded inside a larger disk image.
    offset: u64 = 0,
    /// Whether `close` should close `file`. Only `openPath` opens the file
    /// itself and so is the only path responsible for closing it again;
    /// `openFile` and `openReadOnlySource` take a file a caller already owns
    /// (an `Image`'s handle, typically), and closing it out from under the
    /// caller would be a use-after-free the moment the caller closes its own
    /// copy -- exactly like `ext4.Reader`, which never closes a caller-given
    /// file either.
    owns_file: bool = false,
    superblock: Superblock,

    pub fn openPath(allocator: std.mem.Allocator, io: Io, path: []const u8) OpenError!Reader {
        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        errdefer file.close(io);
        var reader = try openFile(allocator, io, file);
        reader.owns_file = true;
        return reader;
    }

    pub fn openFile(allocator: std.mem.Allocator, io: Io, file: Io.File) OpenError!Reader {
        return openInternal(allocator, io, file, null, 0);
    }

    /// Like `openFile`, but for a filesystem embedded at `offset` inside a
    /// larger raw file -- a partition of a disk image read directly through
    /// its host file, with no guest-visible address translation in between.
    /// Use `openReadOnlySource` instead when the container itself needs
    /// translating (qcow2, VHD, VHDX).
    pub fn openFileAt(allocator: std.mem.Allocator, io: Io, file: Io.File, offset: u64) OpenError!Reader {
        return openInternal(allocator, io, file, null, offset);
    }

    /// Opens XFS through a guest-visible read-only byte source at `offset`.
    /// `file` is retained only for API/layout compatibility and is never
    /// read while `source` is present.
    pub fn openReadOnlySource(
        allocator: std.mem.Allocator,
        io: Io,
        file: Io.File,
        source: ReadOnlySource,
        offset: u64,
    ) OpenError!Reader {
        return openInternal(allocator, io, file, source, offset);
    }

    fn openInternal(
        allocator: std.mem.Allocator,
        io: Io,
        file: Io.File,
        source: ?ReadOnlySource,
        offset: u64,
    ) OpenError!Reader {
        var buf: [superblock_size]u8 = undefined;
        try readSourceAll(io, file, source, &buf, offset);
        const superblock = try parseSuperblock(&buf);
        return .{
            .allocator = allocator,
            .file = file,
            .read_only_source = source,
            .offset = offset,
            .superblock = superblock,
        };
    }

    pub fn close(self: *Reader, io: Io) void {
        if (self.owns_file) self.file.close(io);
        self.* = undefined;
    }

    pub fn readAt(self: Reader, io: Io, buffer: []u8, offset: u64) ReadError!void {
        try readSourceAll(io, self.file, self.read_only_source, buffer, self.offset + offset);
    }

    /// Byte offset of fs-block `fsblock` within the volume.
    fn fsBlockOffset(self: Reader, fsblock: u64) ReadError!u64 {
        const sb = self.superblock;
        const ag_block_log: u6 = @intCast(sb.ag_block_log);
        const agno = fsblock >> ag_block_log;
        const agbno = fsblock & maskLow(ag_block_log);
        if (agno >= sb.ag_count or agbno >= sb.agBlockCount(@intCast(agno))) {
            return error.InvalidAddress;
        }
        return (agno * sb.ag_blocks + agbno) * sb.block_size;
    }

    /// Byte offset of inode `ino` within the volume.
    fn inodeOffset(self: Reader, ino: u64) ReadError!u64 {
        const sb = self.superblock;
        const agino_bits = sb.aginoBits();
        const inode_per_block_log: u6 = @intCast(sb.inode_per_block_log);
        const agino = ino & maskLow(agino_bits);
        const agno = ino >> agino_bits;
        const agbno = agino >> inode_per_block_log;
        const offset_in_block = agino & maskLow(inode_per_block_log);
        if (agno >= sb.ag_count or agbno >= sb.agBlockCount(@intCast(agno))) {
            return error.InvalidAddress;
        }
        const fsblock_byte = (agno * sb.ag_blocks + agbno) * sb.block_size;
        return fsblock_byte + offset_in_block * sb.inode_size;
    }

    fn readInodeRaw(self: Reader, io: Io, ino: u64, buffer: []u8) ReadError!void {
        std.debug.assert(buffer.len == self.superblock.inode_size);
        const offset = try self.inodeOffset(ino);
        try self.readAt(io, buffer, offset);
    }

    fn readFsBlock(self: Reader, io: Io, fsblock: u64, buffer: []u8) ReadError!void {
        std.debug.assert(buffer.len == self.superblock.block_size);
        const offset = try self.fsBlockOffset(fsblock);
        try self.readAt(io, buffer, offset);
    }

    fn readParsedInode(self: Reader, io: Io, ino: u64) (ReadError || InodeError || std.mem.Allocator.Error)!ParsedInode {
        const raw = try self.allocator.alloc(u8, self.superblock.inode_size);
        defer self.allocator.free(raw);
        try self.readInodeRaw(io, ino, raw);
        return parseInode(self.superblock, ino, raw, self.allocator);
    }

    /// Resolves a `/`-separated path (leading slashes and an empty path both
    /// mean the root) to an inode number by walking one directory listing
    /// per component, exactly as `ext4.Reader.lookupPath` does. This never
    /// scans the whole tree, so it stays cheap even against a filesystem too
    /// large or too limited (by `--max-nodes` and friends) for a full import.
    fn lookupPath(self: *Reader, io: Io, path: []const u8) LookupError!u64 {
        if (path.len == 0 or std.mem.eql(u8, path, "/")) return self.superblock.root_ino;

        var current: u64 = self.superblock.root_ino;
        var start: usize = 0;
        while (start < path.len) {
            while (start < path.len and path[start] == '/') : (start += 1) {}
            if (start >= path.len) break;
            var end = start;
            while (end < path.len and path[end] != '/') : (end += 1) {}
            current = try self.lookupChild(io, current, path[start..end]);
            start = end + 1;
        }
        return current;
    }

    fn lookupChild(self: *Reader, io: Io, dir_ino: u64, name: []const u8) LookupError!u64 {
        var dir_inode = try self.readParsedInode(io, dir_ino);
        defer dir_inode.deinit(self.allocator);
        if (dir_inode.kind != .directory) return error.NotDirectory;

        const children = try readDirectoryChildren(self, io, self.allocator, dir_inode);
        defer {
            for (children) |child| self.allocator.free(child.name);
            self.allocator.free(children);
        }
        for (children) |child| {
            if (std.mem.eql(u8, child.name, name)) return child.ino;
        }
        return error.NotFound;
    }

    pub const LookupError = ReadError || InodeError || DirectoryError || ExtentError ||
        std.mem.Allocator.Error || error{ NotFound, NotDirectory };

    pub const Stat = struct {
        ino: u64,
        kind: Kind,
        mode: u16,
        uid: u32,
        gid: u32,
        size: u64,
    };

    pub const StatError = LookupError;

    /// Looks up `path` and reports its kind and POSIX metadata without
    /// importing anything. Mirrors `ext4.Reader.statPath`, which callers
    /// probing "does this candidate filesystem look like a root" (an `/etc`
    /// directory) already rely on; this is what lets that probe treat XFS
    /// exactly like ext4 rather than as a special case.
    pub fn statPath(self: *Reader, io: Io, path: []const u8) StatError!Stat {
        const ino = try self.lookupPath(io, path);
        var inode = try self.readParsedInode(io, ino);
        defer inode.deinit(self.allocator);
        return .{
            .ino = inode.ino,
            .kind = inode.kind,
            .mode = inode.mode,
            .uid = inode.uid,
            .gid = inode.gid,
            .size = inode.size,
        };
    }

    pub const ReadFileError = LookupError || error{ NotFile, FileTooLarge };

    /// Reads a regular file's entire content by path without a full tree
    /// scan, for callers -- COSI's `/etc/os-release` extraction, chiefly --
    /// that need one file out of a filesystem this reader can open rather
    /// than everything in it. Mirrors `ext4.Reader.readFileAlloc`.
    pub fn readFileAlloc(self: *Reader, io: Io, allocator: std.mem.Allocator, path: []const u8) ReadFileError![]u8 {
        const ino = try self.lookupPath(io, path);
        var inode = try self.readParsedInode(io, ino);
        defer inode.deinit(self.allocator);
        if (inode.kind != .file) return error.NotFile;

        const size = std.math.cast(usize, inode.size) orelse return error.FileTooLarge;
        const buffer = try allocator.alloc(u8, size);
        errdefer allocator.free(buffer);
        if (size == 0) return buffer;

        const data_fork_bytes = try self.allocator.dupe(u8, inode.dataForkBytes());
        defer self.allocator.free(data_fork_bytes);
        var content = Content{
            .reader = self,
            .io = io,
            .ino = inode.ino,
            .size = inode.size,
            .data_format = inode.data_format,
            .data_extents = inode.data_extents,
            .data_fork_bytes = data_fork_bytes,
        };

        var done: usize = 0;
        while (done < size) {
            const got = try contentReadAt(&content, buffer[done..], done);
            if (got == 0) break;
            done += got;
        }
        return buffer[0..done];
    }
};

// ---------------------------------------------------------------------------
// Guest-visible types (self-contained: not coupled to ext4's types)
// ---------------------------------------------------------------------------

pub const Kind = enum {
    directory,
    file,
    symlink,
    hardlink,
    block_device,
    char_device,
    fifo,
    socket,
};

pub const DeviceNumbers = struct {
    major: u32 = 0,
    minor: u32 = 0,
};

pub const Xattr = struct {
    name: []const u8,
    value: []const u8,
};

pub const OwnedXattr = struct {
    name: []u8,
    value: []u8,
};

fn freeXattrs(allocator: std.mem.Allocator, xattrs: []OwnedXattr) void {
    for (xattrs) |xattr| {
        allocator.free(xattr.name);
        allocator.free(xattr.value);
    }
    allocator.free(xattrs);
}

/// Read-only view over one entry's file content, shaped like
/// `ext4.FileTreeView.ContentReader` (same method/error shape) so a future
/// `root_tree` adapter can wrap it trivially, without this module importing
/// `ext4.zig` or coupling to its types.
pub const ContentReader = struct {
    ctx: *const anyopaque,
    read_at_fn: *const fn (ctx: *const anyopaque, buffer: []u8, offset: u64) ContentError!usize,

    pub const ContentError = error{ ReadFailed, UnexpectedEndOfStream };

    pub fn readAt(self: ContentReader, buffer: []u8, offset: u64) ContentError!usize {
        return self.read_at_fn(self.ctx, buffer, offset);
    }
};

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

const Timestamp = struct {
    seconds: i64,
    nsec: u32,
};

fn decodeTimestamp(raw: *const [8]u8, bigtime: bool) Timestamp {
    if (bigtime) {
        const value = std.mem.readInt(u64, raw, .big);
        const secs_since_epoch: i64 = @intCast(value / 1_000_000_000);
        const nsec: u32 = @intCast(value % 1_000_000_000);
        return .{ .seconds = secs_since_epoch - bigtime_epoch_offset, .nsec = nsec };
    }
    const seconds = std.mem.readInt(i32, raw[0..4], .big);
    const nsec = std.mem.readInt(u32, raw[4..8], .big);
    return .{ .seconds = seconds, .nsec = nsec };
}

// ---------------------------------------------------------------------------
// Device number decode. XFS stores the 32-bit device number in the data fork
// using the IRIX/System V encoding: the major number occupies bits 18..31 and
// the minor number occupies bits 0..17. This matches xfsprogs' IRIX_DEV_MAJOR/
// IRIX_DEV_MINOR macros and the kernel's sysv_encode_dev(); it deliberately
// differs from ext4's new_decode_dev() layout used in ext4.zig.
// ---------------------------------------------------------------------------

fn decodeDeviceNumbers(rdev: u32) DeviceNumbers {
    return .{
        .major = (rdev >> 18) & 0x1ff,
        .minor = rdev & 0x3ffff,
    };
}

// ---------------------------------------------------------------------------
// Dinode
// ---------------------------------------------------------------------------

const ParsedInode = struct {
    ino: u64,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
    crtime: Timestamp,
    data_format: u8,
    attr_format: u8,
    data_extents: u64,
    attr_extents: u64,
    fork_off: u8,
    flags: u16,
    flags2: u64,
    /// The inode's literal area (data fork + optional attribute fork),
    /// exactly `inode_size - 176` bytes, copied out of the raw inode buffer
    /// so callers do not need to keep the raw buffer alive.
    literal_area: []u8,

    fn hasContent(self: ParsedInode) bool {
        return self.kind == .file or self.kind == .symlink;
    }

    fn dataForkBytes(self: ParsedInode) []const u8 {
        if (self.fork_off != 0) {
            return self.literal_area[0 .. @as(usize, self.fork_off) * 8];
        }
        return self.literal_area;
    }

    fn attrForkBytes(self: ParsedInode) []const u8 {
        if (self.fork_off == 0) return &.{};
        const off = @as(usize, self.fork_off) * 8;
        return self.literal_area[off..];
    }

    fn deinit(self: *ParsedInode, allocator: std.mem.Allocator) void {
        allocator.free(self.literal_area);
        self.* = undefined;
    }
};

pub const InodeError = error{
    BadDinodeMagic,
    UnsupportedInodeVersion,
    InodeChecksumMismatch,
    InodeIdentityMismatch,
    UnsupportedInodeMode,
    UnsupportedDataForkFormat,
    UnsupportedAttrForkFormat,
    RealtimeFileUnsupported,
    InvalidInodeLayout,
    InvalidForkOffset,
};

fn parseInode(sb: Superblock, ino: u64, raw: []const u8, allocator: std.mem.Allocator) (InodeError || std.mem.Allocator.Error)!ParsedInode {
    if (raw.len != sb.inode_size or raw.len < dinode_v3_core_size) return error.InvalidInodeLayout;
    if (std.mem.readInt(u16, raw[0..2], .big) != dinode_magic) return error.BadDinodeMagic;
    const version = raw[4];
    if (version != 3) return error.UnsupportedInodeVersion;
    if (!verifyCrc32c(raw, dinode_crc_offset)) return error.InodeChecksumMismatch;

    const stored_ino = std.mem.readInt(u64, raw[152..160], .big);
    if (stored_ino != ino) return error.InodeIdentityMismatch;
    if (!std.mem.eql(u8, raw[160..176], if (sb.features_incompat & incompat_meta_uuid != 0) &sb.meta_uuid else &sb.uuid)) {
        return error.InodeIdentityMismatch;
    }

    const mode = std.mem.readInt(u16, raw[2..4], .big);
    const kind: Kind = switch (mode & s_ifmt) {
        s_ifreg => .file,
        s_ifdir => .directory,
        s_iflnk => .symlink,
        s_ifblk => .block_device,
        s_ifchr => .char_device,
        s_ififo => .fifo,
        s_ifsock => .socket,
        else => return error.UnsupportedInodeMode,
    };

    const data_format = raw[5];
    const attr_format = raw[83];
    const flags2 = std.mem.readInt(u64, raw[120..128], .big);
    const bigtime = sb.features_incompat & incompat_bigtime != 0 and flags2 & diflag2_bigtime != 0;
    const nrext64 = sb.features_incompat & incompat_nrext64 != 0 and flags2 & diflag2_nrext64 != 0;
    const flags = std.mem.readInt(u16, raw[90..92], .big);
    if (flags & diflag_realtime != 0) return error.RealtimeFileUnsupported;

    var data_extents: u64 = undefined;
    var attr_extents: u64 = undefined;
    if (nrext64) {
        data_extents = std.mem.readInt(u64, raw[24..32], .big);
        attr_extents = std.mem.readInt(u32, raw[76..80], .big);
    } else {
        data_extents = std.mem.readInt(u32, raw[76..80], .big);
        attr_extents = std.mem.readInt(u16, raw[80..82], .big);
    }

    const fork_off = raw[82];
    // `di_forkoff` is stored in 8-byte units from the start of the literal
    // area; a corrupt or adversarial value past the literal area's real
    // length would otherwise make every later `dataForkBytes()`/
    // `attrForkBytes()` slice operation panic instead of returning a named
    // error, since Zig slice bounds are checked at the point of use, not
    // when the (out-of-range) length is merely stored.
    const literal_area_len = raw.len - dinode_v3_core_size;
    if (@as(usize, fork_off) * 8 > literal_area_len) return error.InvalidForkOffset;
    const literal_area = try allocator.dupe(u8, raw[dinode_v3_core_size..]);
    errdefer allocator.free(literal_area);

    return .{
        .ino = ino,
        .kind = kind,
        .mode = mode & 0o7777,
        .uid = std.mem.readInt(u32, raw[8..12], .big),
        .gid = std.mem.readInt(u32, raw[12..16], .big),
        .nlink = std.mem.readInt(u32, raw[16..20], .big),
        .size = std.mem.readInt(u64, raw[56..64], .big),
        .atime = decodeTimestamp(raw[32..40], bigtime),
        .mtime = decodeTimestamp(raw[40..48], bigtime),
        .ctime = decodeTimestamp(raw[48..56], bigtime),
        .crtime = decodeTimestamp(raw[144..152], bigtime),
        .data_format = data_format,
        .attr_format = attr_format,
        .data_extents = data_extents,
        .attr_extents = attr_extents,
        .fork_off = fork_off,
        .flags = flags,
        .flags2 = flags2,
        .literal_area = literal_area,
    };
}

// ---------------------------------------------------------------------------
// Bmap extents (data fork): direct array (EXTENTS) or long-form btree (BTREE)
// ---------------------------------------------------------------------------

pub const Extent = struct {
    logical_block: u64,
    start_block: u64,
    block_count: u64,
    /// An unwritten extent is allocated but never written, so the guest
    /// reads zeros from it -- preserving that is the difference between
    /// importing a sparse/prealloc'd file and importing garbage.
    unwritten: bool,
};

pub const ExtentError = error{
    UnsupportedExtentLayout,
    UnsupportedExtentDepth,
    InvalidExtent,
    BtreeBlockChecksumMismatch,
};

fn decodeBmbtRec(rec: *const [bmbt_rec_size]u8) Extent {
    const l0 = std.mem.readInt(u64, rec[0..8], .big);
    const l1 = std.mem.readInt(u64, rec[8..16], .big);
    const unwritten = (l0 >> 63) != 0;
    const startoff = (l0 >> 9) & ((@as(u64, 1) << 54) - 1);
    const startblock = ((l0 & 0x1ff) << 43) | (l1 >> 21);
    const blockcount = l1 & ((@as(u64, 1) << 21) - 1);
    return .{
        .logical_block = startoff,
        .start_block = startblock,
        .block_count = blockcount,
        .unwritten = unwritten,
    };
}

const max_extent_depth = 8;

/// Reads and validates every extent for a data fork, in ascending
/// logical-offset order with no overlaps. Both `FMT_EXTENTS` and `FMT_BTREE`
/// are supported; the tree is walked breadth-first over every child pointer
/// (full enumeration, not a keyed point lookup), which needs no key parsing
/// at all. Takes primitive fields rather than a `ParsedInode` so a cached
/// copy of just the literal-area bytes (as `Content` keeps) is enough to
/// resolve extents without re-reading the inode from disk on every call.
fn readExtents(
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    ino: u64,
    data_format: u8,
    data_extents: u64,
    data_fork_bytes: []const u8,
) (ExtentError || ReadError || std.mem.Allocator.Error)![]Extent {
    var extents = std.array_list.Managed(Extent).init(allocator);
    errdefer extents.deinit();

    switch (data_format) {
        fmt_extents => {
            // `data_fork_bytes` is sized to the whole data-fork region, which
            // may be larger than `data_extents * 16` when there is no
            // attribute fork (the fork simply gets the rest of the literal
            // area, whether or not every byte of it holds a real record).
            const needed = std.math.mul(usize, std.math.cast(usize, data_extents) orelse
                return error.UnsupportedExtentLayout, bmbt_rec_size) catch return error.UnsupportedExtentLayout;
            if (needed > data_fork_bytes.len) return error.UnsupportedExtentLayout;
            var index: usize = 0;
            while (index < data_extents) : (index += 1) {
                const rec = data_fork_bytes[index * bmbt_rec_size ..][0..bmbt_rec_size];
                try appendValidatedExtent(reader, &extents, decodeBmbtRec(rec));
            }
        },
        fmt_btree => {
            if (data_fork_bytes.len < bmdr_header_size) return error.UnsupportedExtentLayout;
            const level = std.mem.readInt(u16, data_fork_bytes[0..2], .big);
            const numrecs = std.mem.readInt(u16, data_fork_bytes[2..4], .big);
            if (level == 0 or level > max_extent_depth) return error.UnsupportedExtentDepth;
            const body = data_fork_bytes[bmdr_header_size..];
            // `xfs_bmdr_maxrecs(dblocklen, leaf=false)`: the root's key/ptr
            // arrays are sized for however many (key,ptr) pairs fit in the
            // whole available fork area, not for `numrecs`.
            const maxrecs = body.len / (bmbt_key_size + bmbt_ptr_size);
            if (@as(usize, numrecs) > maxrecs) return error.UnsupportedExtentLayout;
            // The pointer array starts after the full `maxrecs`-sized key
            // array (`xfs_bmdr_ptr_addr`), not after just the `numrecs`
            // populated key slots.
            const ptr_area = body[maxrecs * bmbt_key_size ..][0 .. maxrecs * bmbt_ptr_size];
            var index: usize = 0;
            while (index < numrecs) : (index += 1) {
                const child = std.mem.readInt(u64, ptr_area[index * bmbt_ptr_size ..][0..8], .big);
                try walkBtreeNode(reader, io, allocator, ino, child, level - 1, &extents);
            }
        },
        else => return error.UnsupportedExtentLayout,
    }

    const owned = try extents.toOwnedSlice();
    std.mem.sort(Extent, owned, {}, struct {
        fn lessThan(_: void, lhs: Extent, rhs: Extent) bool {
            return lhs.logical_block < rhs.logical_block;
        }
    }.lessThan);
    var index: usize = 1;
    while (index < owned.len) : (index += 1) {
        const prev = owned[index - 1];
        if (owned[index].logical_block < prev.logical_block + prev.block_count) {
            allocator.free(owned);
            return error.InvalidExtent;
        }
    }
    return owned;
}

fn appendValidatedExtent(reader: *Reader, extents: *std.array_list.Managed(Extent), extent: Extent) !void {
    if (extent.block_count == 0) return error.InvalidExtent;
    const end = std.math.add(u64, extent.start_block, extent.block_count) catch return error.InvalidExtent;
    if (end > reader.superblock.data_blocks) return error.InvalidExtent;
    try extents.append(extent);
}

/// Long-form (inode-rooted) bmap btree block header layout
/// (`struct xfs_btree_block` + `bb_u.l`, `XFS_BTREE_LBLOCK_CRC_LEN` = 72
/// bytes): magic(4) + level(2) + numrecs(2) + [leftsib(8) + rightsib(8) +
/// blkno(8) + lsn(8) + uuid(16) + owner(8) + crc(4, little-endian) + pad(4)].
/// `bb_owner` therefore sits at absolute byte 56 and `bb_crc` at absolute
/// byte 64 -- easy to get wrong since they are nested inside a union whose
/// short-form sibling has different field widths.
const bmbt_long_owner_offset: usize = 56;
const bmbt_long_crc_offset: usize = 64;

fn walkBtreeNode(
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    ino: u64,
    fsblock: u64,
    level: u16,
    extents: *std.array_list.Managed(Extent),
) (ExtentError || ReadError || std.mem.Allocator.Error)!void {
    const block = try allocator.alloc(u8, reader.superblock.block_size);
    defer allocator.free(block);
    try reader.readFsBlock(io, fsblock, block);

    if (std.mem.readInt(u32, block[0..4], .big) != bmap_btree_magic) return error.UnsupportedExtentLayout;
    if (!verifyCrc32c(block, bmbt_long_crc_offset)) return error.BtreeBlockChecksumMismatch;
    const owner = std.mem.readInt(u64, block[bmbt_long_owner_offset..][0..8], .big);
    if (owner != ino) return error.InvalidExtent;
    const block_level = std.mem.readInt(u16, block[4..6], .big);
    if (block_level != level) return error.UnsupportedExtentLayout;
    const numrecs = std.mem.readInt(u16, block[6..8], .big);
    const body = block[bmbt_long_header_size..];

    if (level == 0) {
        if (@as(usize, numrecs) * bmbt_rec_size > body.len) return error.UnsupportedExtentLayout;
        var index: usize = 0;
        while (index < numrecs) : (index += 1) {
            const rec = body[index * bmbt_rec_size ..][0..bmbt_rec_size];
            try appendValidatedExtent(reader, extents, decodeBmbtRec(rec));
        }
        return;
    }

    // Non-leaf long-form blocks size their key/ptr arrays for the maximum a
    // full block could ever hold (`xfs_bmbt_maxrecs`, based on the whole
    // block length); only the first `numrecs` pointers (after the full
    // `maxrecs`-sized key array, per `xfs_bmbt_ptr_addr`) are populated.
    const maxrecs = body.len / (bmbt_key_size + bmbt_ptr_size);
    if (@as(usize, numrecs) > maxrecs) return error.UnsupportedExtentLayout;
    const ptr_area = body[maxrecs * bmbt_key_size ..][0 .. maxrecs * bmbt_ptr_size];
    var index: usize = 0;
    while (index < numrecs) : (index += 1) {
        const child = std.mem.readInt(u64, ptr_area[index * bmbt_ptr_size ..][0..8], .big);
        try walkBtreeNode(reader, io, allocator, ino, child, level - 1, extents);
    }
}

fn findBlock(extents: []const Extent, logical_block: u64) ?struct { start: u64, unwritten: bool } {
    for (extents) |extent| {
        if (logical_block < extent.logical_block) continue;
        if (logical_block - extent.logical_block >= extent.block_count) continue;
        return .{ .start = extent.start_block + (logical_block - extent.logical_block), .unwritten = extent.unwritten };
    }
    return null;
}

// ---------------------------------------------------------------------------
// Regular file / symlink content reading
// ---------------------------------------------------------------------------

const Content = struct {
    reader: *Reader,
    io: Io,
    ino: u64,
    size: u64,
    data_format: u8,
    data_extents: u64,
    /// A copy of the data fork's bytes taken at scan time: for a regular
    /// file this is the raw extent array or btree-root bytes, and for a
    /// symlink (`data_format == fmt_local`, which a real regular file never
    /// uses) it is the fully resolved target string. Owning this up front
    /// means a read never has to re-fetch and re-verify the inode from disk.
    data_fork_bytes: []const u8,
};

fn contentReadAt(content: *const Content, buffer: []u8, offset: u64) !usize {
    if (offset >= content.size) return 0;
    const remaining = content.size - offset;
    const want: usize = @intCast(@min(@as(u64, buffer.len), remaining));
    if (want == 0) return 0;

    if (content.data_format == fmt_local) {
        const start: usize = @intCast(offset);
        @memcpy(buffer[0..want], content.data_fork_bytes[start .. start + want]);
        return want;
    }

    const reader = content.reader;
    const extents = try readExtents(reader, content.io, reader.allocator, content.ino, content.data_format, content.data_extents, content.data_fork_bytes);
    defer reader.allocator.free(extents);

    const block_size = reader.superblock.block_size;
    var done: usize = 0;
    while (done < want) {
        const logical_offset = offset + done;
        const logical_block = logical_offset / block_size;
        const within_block: usize = @intCast(logical_offset % block_size);
        const chunk = @min(want - done, @as(usize, block_size) - within_block);

        if (findBlock(extents, logical_block)) |mapping| {
            if (mapping.unwritten) {
                @memset(buffer[done .. done + chunk], 0);
            } else {
                try reader.readAt(content.io, buffer[done .. done + chunk], try reader.fsBlockOffset(mapping.start) + within_block);
            }
        } else {
            @memset(buffer[done .. done + chunk], 0);
        }
        done += chunk;
    }
    return done;
}

fn contentReadAtErased(ctx: *const anyopaque, buffer: []u8, offset: u64) ContentReader.ContentError!usize {
    const content: *const Content = @ptrCast(@alignCast(ctx));
    return contentReadAt(content, buffer, offset) catch error.ReadFailed;
}

// ---------------------------------------------------------------------------
// Symlinks
// ---------------------------------------------------------------------------

pub const SymlinkError = error{
    UnsupportedSymlinkFormat,
    SymlinkChecksumMismatch,
    SymlinkTargetTooLarge,
    InvalidSymlinkLayout,
};

const max_symlink_maps = 3;
const symlink_max_len = 1024;

fn readSymlinkTargetAlloc(reader: *Reader, io: Io, allocator: std.mem.Allocator, inode: ParsedInode) !([]u8) {
    if (inode.size > symlink_max_len) return error.SymlinkTargetTooLarge;
    const size: usize = @intCast(inode.size);

    if (inode.data_format == fmt_local) {
        const data = inode.dataForkBytes();
        if (data.len < size) return error.InvalidSymlinkLayout;
        return allocator.dupe(u8, data[0..size]);
    }
    if (inode.data_format != fmt_extents) return error.UnsupportedSymlinkFormat;

    const extents = try readExtents(reader, io, allocator, inode.ino, inode.data_format, inode.data_extents, inode.dataForkBytes());
    defer allocator.free(extents);
    if (extents.len == 0 or extents.len > max_symlink_maps) return error.UnsupportedSymlinkFormat;

    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    var written: usize = 0;
    const block_size = reader.superblock.block_size;
    const block = try allocator.alloc(u8, block_size);
    defer allocator.free(block);

    for (extents) |extent| {
        if (extent.unwritten or extent.block_count != 1) return error.UnsupportedSymlinkFormat;
        try reader.readFsBlock(io, extent.start_block, block);
        if (std.mem.readInt(u32, block[0..4], .big) != symlink_magic) return error.UnsupportedSymlinkFormat;
        if (!verifyCrc32c(block, 12)) return error.SymlinkChecksumMismatch;
        const owner = std.mem.readInt(u64, block[symlink_owner_offset..][0..8], .big);
        if (owner != inode.ino) return error.InvalidSymlinkLayout;
        const block_offset = std.mem.readInt(u32, block[4..8], .big);
        const chunk_bytes = std.mem.readInt(u32, block[8..12], .big);
        if (block_offset != written) return error.InvalidSymlinkLayout;
        if (@as(u64, block_offset) + chunk_bytes > size) return error.InvalidSymlinkLayout;
        const chunk_len: usize = @intCast(chunk_bytes);
        if (symlink_header_size + chunk_len > block.len) return error.InvalidSymlinkLayout;
        @memcpy(out[written..][0..chunk_len], block[symlink_header_size..][0..chunk_len]);
        written += chunk_len;
    }
    if (written != size) return error.InvalidSymlinkLayout;
    return out;
}

// ---------------------------------------------------------------------------
// Device nodes
// ---------------------------------------------------------------------------

fn readDeviceNumbers(inode: ParsedInode) !DeviceNumbers {
    if (inode.data_format != fmt_dev) return error.UnsupportedDataForkFormat;
    const data = inode.dataForkBytes();
    if (data.len < 4) return error.InvalidInodeLayout;
    const rdev = std.mem.readInt(u32, data[0..4], .big);
    return decodeDeviceNumbers(rdev);
}

// ---------------------------------------------------------------------------
// Directories: shortform + single-block "block" format
// ---------------------------------------------------------------------------

pub const DirectoryError = error{
    UnsupportedDirectoryFormat,
    DirectoryChecksumMismatch,
    InvalidDirectoryLayout,
    DirectoryEntryTooLong,
};

const DirChild = struct {
    name: []u8,
    ino: u64,
    dir_file_type: u8,
};

fn dirFtypeToKindHint(ftype: u8) ?Kind {
    return switch (ftype) {
        dir_ft_reg_file => .file,
        dir_ft_dir => .directory,
        dir_ft_chrdev => .char_device,
        dir_ft_blkdev => .block_device,
        dir_ft_fifo => .fifo,
        dir_ft_sock => .socket,
        dir_ft_symlink => .symlink,
        else => null,
    };
}

fn kindToDirFtype(kind: Kind) u8 {
    return switch (kind) {
        .directory => dir_ft_dir,
        .file, .hardlink => dir_ft_reg_file,
        .symlink => dir_ft_symlink,
        .block_device => dir_ft_blkdev,
        .char_device => dir_ft_chrdev,
        .fifo => dir_ft_fifo,
        .socket => dir_ft_sock,
    };
}

/// Reads every child of `inode` (a directory), rejecting anything outside
/// shortform/single-block "block" format by name.
fn readDirectoryChildren(
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    inode: ParsedInode,
) (DirectoryError || ReadError || ExtentError || std.mem.Allocator.Error)![]DirChild {
    if (inode.data_format == fmt_local) {
        return readShortformDirectory(allocator, inode.dataForkBytes());
    }
    if (inode.data_format != fmt_extents) return error.UnsupportedDirectoryFormat;

    const extents = try readExtents(reader, io, allocator, inode.ino, inode.data_format, inode.data_extents, inode.dataForkBytes());
    defer allocator.free(extents);
    const dir_block_size = reader.superblock.dirBlockSize();
    const fsb_per_dirblock = dir_block_size / reader.superblock.block_size;
    if (extents.len != 1 or extents[0].logical_block != 0 or
        extents[0].block_count != fsb_per_dirblock or extents[0].unwritten)
    {
        return error.UnsupportedDirectoryFormat;
    }

    const block = try allocator.alloc(u8, dir_block_size);
    defer allocator.free(block);
    var done: usize = 0;
    var fsb_index: u64 = 0;
    while (fsb_index < fsb_per_dirblock) : (fsb_index += 1) {
        try reader.readFsBlock(io, extents[0].start_block + fsb_index, block[done..][0..reader.superblock.block_size]);
        done += reader.superblock.block_size;
    }
    return readBlockFormatDirectory(allocator, block, inode.ino);
}

fn readShortformDirectory(allocator: std.mem.Allocator, data: []const u8) (DirectoryError || std.mem.Allocator.Error)![]DirChild {
    if (data.len < 2) return error.InvalidDirectoryLayout;
    const count = data[0];
    const i8count = data[1];
    const ino_bytes: usize = if (i8count != 0) 8 else 4;
    const header_size: usize = 2 + ino_bytes;
    if (data.len < header_size) return error.InvalidDirectoryLayout;

    var children = std.array_list.Managed(DirChild).init(allocator);
    errdefer {
        for (children.items) |child| allocator.free(child.name);
        children.deinit();
    }

    var cursor = header_size;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        if (cursor + 1 > data.len) return error.InvalidDirectoryLayout;
        const namelen = data[cursor];
        // namelen(1) + offset(2) + name(namelen) + ftype(1) + ino(4 or 8)
        const fixed_tail = 2 + 1 + ino_bytes;
        if (cursor + 1 + fixed_tail + namelen > data.len) return error.InvalidDirectoryLayout;
        const name_start = cursor + 1 + 2;
        const name = data[name_start..][0..namelen];
        const ftype = data[name_start + namelen];
        const ino_start = name_start + namelen + 1;
        const ino = if (ino_bytes == 8)
            std.mem.readInt(u64, data[ino_start..][0..8], .big)
        else
            @as(u64, std.mem.readInt(u32, data[ino_start..][0..4], .big));

        const owned_name = try allocator.dupe(u8, name);
        errdefer allocator.free(owned_name);
        try children.append(.{ .name = owned_name, .ino = ino, .dir_file_type = ftype });

        cursor = ino_start + ino_bytes;
    }
    // Unlike the single-block "block" format (which must exactly fill its
    // data area up to the leaf/tail index), a shortform fork simply gets
    // whatever bytes remain in the literal area after any attribute fork:
    // `dataForkBytes()` therefore routinely extends well past the last
    // real entry (or all the way to the end of the literal area, when
    // there is no attribute fork at all), and that trailing padding is not
    // part of the format to validate against.
    return children.toOwnedSlice();
}

fn readBlockFormatDirectory(allocator: std.mem.Allocator, block: []const u8, owner_ino: u64) (DirectoryError || std.mem.Allocator.Error)![]DirChild {
    if (block.len < dir3_data_header_size + 8) return error.InvalidDirectoryLayout;
    const magic_value = std.mem.readInt(u32, block[0..4], .big);
    if (magic_value == dir3_data_magic) return error.UnsupportedDirectoryFormat;
    if (magic_value != dir3_block_magic) return error.UnsupportedDirectoryFormat;
    if (!verifyCrc32c(block, 4)) return error.DirectoryChecksumMismatch;
    const owner = std.mem.readInt(u64, block[40..48], .big);
    if (owner != owner_ino) return error.InvalidDirectoryLayout;

    const tail = block[block.len - 8 ..];
    const leaf_count = std.mem.readInt(u32, tail[0..4], .big);
    const leaf_area_start = std.math.sub(usize, block.len - 8, @as(usize, leaf_count) * 8) catch
        return error.InvalidDirectoryLayout;
    if (leaf_area_start < dir3_data_header_size) return error.InvalidDirectoryLayout;

    var children = std.array_list.Managed(DirChild).init(allocator);
    errdefer {
        for (children.items) |child| allocator.free(child.name);
        children.deinit();
    }

    var cursor: usize = dir3_data_header_size;
    while (cursor < leaf_area_start) {
        if (cursor + 2 > leaf_area_start) return error.InvalidDirectoryLayout;
        const first_u16 = std.mem.readInt(u16, block[cursor..][0..2], .big);
        if (first_u16 == 0xffff) {
            // Unused entry: freetag(2) + length(2) + ... + tag(2), total
            // `length` bytes.
            if (cursor + 4 > leaf_area_start) return error.InvalidDirectoryLayout;
            const length = std.mem.readInt(u16, block[cursor + 2 ..][0..2], .big);
            if (length == 0 or length % 8 != 0 or cursor + length > leaf_area_start) {
                return error.InvalidDirectoryLayout;
            }
            cursor += length;
            continue;
        }

        // Real entry: inumber(8) + namelen(1) + name(namelen) + ftype(1) +
        // tag(2), rounded up to 8 bytes.
        if (cursor + 9 > leaf_area_start) return error.InvalidDirectoryLayout;
        const ino = std.mem.readInt(u64, block[cursor..][0..8], .big);
        const namelen = block[cursor + 8];
        const name_start = cursor + 9;
        if (name_start + @as(usize, namelen) + 1 > leaf_area_start) return error.InvalidDirectoryLayout;
        const name = block[name_start..][0..namelen];
        const ftype = block[name_start + namelen];
        const entry_len = std.mem.alignForward(usize, 8 + 1 + @as(usize, namelen) + 1 + 2, 8);
        if (cursor + entry_len > leaf_area_start) return error.InvalidDirectoryLayout;

        if (!(namelen == 1 and name[0] == '.') and
            !(namelen == 2 and name[0] == '.' and name[1] == '.'))
        {
            const owned_name = try allocator.dupe(u8, name);
            errdefer allocator.free(owned_name);
            try children.append(.{ .name = owned_name, .ino = ino, .dir_file_type = ftype });
        }
        cursor += entry_len;
    }
    if (cursor != leaf_area_start) return error.InvalidDirectoryLayout;
    return children.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Extended attributes: shortform only
// ---------------------------------------------------------------------------

pub const XattrError = error{
    UnsupportedXattrForkFormat,
    InvalidXattrLayout,
    UnsupportedXattrFlags,
};

fn xattrPrefix(flags: u8) []const u8 {
    if (flags & attr_secure_bit != 0) return "security.";
    if (flags & attr_root_bit != 0) return "trusted.";
    return "user.";
}

fn readXattrs(allocator: std.mem.Allocator, inode: ParsedInode) (XattrError || std.mem.Allocator.Error)![]OwnedXattr {
    if (inode.fork_off == 0) return &.{};
    if (inode.attr_format != fmt_local) return error.UnsupportedXattrForkFormat;

    const data = inode.attrForkBytes();
    if (data.len < 4) return error.InvalidXattrLayout;
    const totsize = std.mem.readInt(u16, data[0..2], .big);
    const count = data[2];
    if (totsize > data.len) return error.InvalidXattrLayout;

    var xattrs = std.array_list.Managed(OwnedXattr).init(allocator);
    errdefer {
        for (xattrs.items) |xattr| {
            allocator.free(xattr.name);
            allocator.free(xattr.value);
        }
        xattrs.deinit();
    }

    var cursor: usize = 4;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        if (cursor + 3 > totsize) return error.InvalidXattrLayout;
        const namelen = data[cursor];
        const valuelen = data[cursor + 1];
        const flags = data[cursor + 2];
        if (flags & (attr_parent_bit | attr_incomplete_bit) != 0) return error.UnsupportedXattrFlags;
        const name_start = cursor + 3;
        const value_start = name_start + namelen;
        const entry_end = value_start + valuelen;
        if (entry_end > totsize or entry_end > data.len) return error.InvalidXattrLayout;

        const prefix = xattrPrefix(flags);
        const name = try std.mem.concat(allocator, u8, &.{ prefix, data[name_start..value_start] });
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, data[value_start..entry_end]);
        errdefer allocator.free(value);
        try xattrs.append(.{ .name = name, .value = value });

        cursor = entry_end;
    }
    if (cursor != totsize) return error.InvalidXattrLayout;
    return xattrs.toOwnedSlice();
}

/// Rejects a duplicate xattr name (a real filesystem never re-emits the same
/// prefixed name twice on one inode; seeing one is corruption, not something
/// to silently coalesce) and enforces the configured per-node count/byte
/// limits, mirroring `ext4.zig`'s `appendInodeBodyXattrs` bookkeeping.
fn enforceXattrLimits(xattrs: []const OwnedXattr, options: ScanOptions) !void {
    limits_mod.observe(options.diagnostic, .xattrs_per_node, xattrs.len);
    if (xattrs.len > options.max_xattrs_per_node) {
        return limits_mod.exceeded(options.diagnostic, .xattrs_per_node, xattrs.len, options.max_xattrs_per_node);
    }
    var total_bytes: usize = 0;
    for (xattrs, 0..) |xattr, index| {
        total_bytes = std.math.add(usize, total_bytes, xattr.name.len + xattr.value.len) catch
            return error.XattrByteLimitExceeded;
        for (xattrs[index + 1 ..]) |other| {
            if (std.mem.eql(u8, xattr.name, other.name)) return error.DuplicateXattr;
        }
    }
    limits_mod.observe(options.diagnostic, .xattr_bytes_per_node, total_bytes);
    if (total_bytes > options.max_xattr_bytes_per_node) {
        return limits_mod.exceeded(options.diagnostic, .xattr_bytes_per_node, total_bytes, options.max_xattr_bytes_per_node);
    }
}

// ---------------------------------------------------------------------------
// Public scan API
// ---------------------------------------------------------------------------

pub const FilesystemIdentity = struct {
    uuid: [16]u8,
    /// Exact on-disk 12-byte label field, including embedded/trailing NUL
    /// bytes.
    label: [12]u8,
    block_size: u32,
    inode_size: u16,
    /// Bytes the filesystem itself occupies.
    filesystem_length: u64,
    features_compat: u32,
    features_ro_compat: u32,
    features_incompat: u32,
};

pub const Root = struct {
    mode: u16,
    uid: u32,
    gid: u32,
    atime: i64,
    mtime: i64,
    ctime: i64,
    crtime: i64,
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    crtime_nsec: u32,
    xattrs: []const Xattr,
};

pub const Entry = struct {
    /// Relative path with `/` separators and no leading `/`.
    path: []const u8,
    kind: Kind,
    /// Permission/sticky bits only; the file type comes from `kind`.
    mode: u16,
    uid: u32,
    gid: u32,
    /// Regular-file or symlink byte length; 0 for every other kind.
    size: u64,
    atime: i64,
    mtime: i64,
    ctime: i64,
    crtime: i64,
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    crtime_nsec: u32,
    /// Meaningful only for `.block_device` and `.char_device`.
    device: DeviceNumbers,
    /// Set only for `.hardlink`: the path of the first entry that shares the
    /// source inode.
    hardlink_target: []const u8,
    content: ?ContentReader,
    xattrs: []const Xattr,
};

const Node = struct {
    path: []u8,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    atime: i64,
    mtime: i64,
    ctime: i64,
    crtime: i64,
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    crtime_nsec: u32,
    device: DeviceNumbers,
    hardlink_target: []const u8,
    has_content: bool,
    content: Content,
    xattrs: []OwnedXattr,
    xattr_views: []Xattr,
};

pub const ScanOptions = struct {
    /// The bytes the source filesystem is allowed to occupy. A real
    /// partition or block device is routinely larger than the filesystem
    /// inside it.
    available_length: u64,
    max_nodes: usize = limit_defaults.max_nodes,
    max_path_bytes: usize = limit_defaults.max_path_bytes,
    max_component_bytes: usize = limit_defaults.max_component_bytes,
    max_file_bytes: u64 = limit_defaults.max_file_bytes,
    max_total_bytes: u64 = limit_defaults.max_total_bytes,
    max_xattrs_per_node: usize = limit_defaults.max_xattrs_per_node,
    max_xattr_bytes_per_node: usize = limit_defaults.max_xattr_bytes_per_node,
    max_scan_metadata_bytes: usize = limit_defaults.max_scan_metadata_bytes,
    /// Optional sink for the peak measurements and the first limit breach.
    diagnostic: ?*limits_mod.Diagnostic = null,
};

/// A general XFS source read out as an ordered tree, in the same shape as
/// `ext4.GeneralTree`/`fat32.Tree` but using this module's own types, per the
/// task's request for "a general tree shape preserving metadata rather than
/// coupling to ext4 types".
pub const Tree = struct {
    allocator: std.mem.Allocator,
    entries: []Node,
    identity: FilesystemIdentity,
    root: Root,
    root_xattrs_owned: []OwnedXattr,
    root_xattr_views: []Xattr,
    /// Guest-visible file bytes counted once per inode, so a hardlinked file
    /// is not billed twice.
    content_bytes: u64,

    pub fn deinit(self: *Tree) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.path);
            if (entry.kind != .hardlink) self.allocator.free(entry.content.data_fork_bytes);
            freeXattrs(self.allocator, entry.xattrs);
            self.allocator.free(entry.xattr_views);
        }
        self.allocator.free(self.entries);
        freeXattrs(self.allocator, self.root_xattrs_owned);
        self.allocator.free(self.root_xattr_views);
        self.* = undefined;
    }

    /// Excludes the implicit root directory.
    pub fn nodeCount(self: *const Tree) usize {
        return self.entries.len;
    }

    pub fn entryAt(self: *Tree, index: usize) Entry {
        const node = &self.entries[index];
        return .{
            .path = node.path,
            .kind = node.kind,
            .mode = node.mode,
            .uid = node.uid,
            .gid = node.gid,
            .size = node.size,
            .atime = node.atime,
            .mtime = node.mtime,
            .ctime = node.ctime,
            .crtime = node.crtime,
            .atime_nsec = node.atime_nsec,
            .mtime_nsec = node.mtime_nsec,
            .ctime_nsec = node.ctime_nsec,
            .crtime_nsec = node.crtime_nsec,
            .device = node.device,
            .hardlink_target = node.hardlink_target,
            .content = if (node.has_content) .{
                .ctx = &node.content,
                .read_at_fn = contentReadAtErased,
            } else null,
            .xattrs = node.xattr_views,
        };
    }
};

pub const ScanError = ReadError || InodeError || ExtentError || DirectoryError || XattrError ||
    SymlinkError || FeatureError || limits_mod.Error || error{
    RootIsNotADirectory,
    InvalidImportedPath,
    DuplicateDirectoryEntry,
    DuplicateXattr,
    DirectoryCycle,
    DirectoryFileTypeMismatch,
    InvalidInodeReference,
    InvalidFilesystemLength,
    FilesystemExceedsPartition,
    UnsupportedDataForkFormat,
    UnsupportedInodeMode,
};

pub fn scanReadable(reader: *Reader, io: Io, allocator: std.mem.Allocator, options: ScanOptions) ScanError!Tree {
    var scanner = try Scanner.init(reader, io, allocator, options);
    defer scanner.deinit();
    try scanner.scan();
    return scanner.finish();
}

const Scanner = struct {
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    options: ScanOptions,
    identity: FilesystemIdentity,
    entries: std.array_list.Managed(Node),
    /// Directory inodes already entered; a corrupt ".." pointer becomes a
    /// named error instead of an infinite walk.
    visited_directories: std.AutoHashMap(u64, void),
    /// First path seen for each multiply-linked inode.
    hardlinks: std.AutoHashMap(u64, []const u8),
    root: Root,
    root_xattrs_owned: []OwnedXattr,
    root_xattr_views: []Xattr,
    content_bytes: u64 = 0,
    node_count: usize = 0,

    fn init(reader: *Reader, io: Io, allocator: std.mem.Allocator, options: ScanOptions) !Scanner {
        const sb = reader.superblock;
        const filesystem_length = std.math.mul(u64, sb.data_blocks, sb.block_size) catch
            return error.InvalidFilesystemLength;
        if (filesystem_length > options.available_length) return error.FilesystemExceedsPartition;

        return .{
            .reader = reader,
            .io = io,
            .allocator = allocator,
            .options = options,
            .identity = .{
                .uuid = sb.uuid,
                .label = sb.label,
                .block_size = sb.block_size,
                .inode_size = sb.inode_size,
                .filesystem_length = filesystem_length,
                .features_compat = sb.features_compat,
                .features_ro_compat = sb.features_ro_compat,
                .features_incompat = sb.features_incompat,
            },
            .entries = .init(allocator),
            .visited_directories = .init(allocator),
            .hardlinks = .init(allocator),
            .root = undefined,
            .root_xattrs_owned = &.{},
            .root_xattr_views = &.{},
        };
    }

    fn deinit(self: *Scanner) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.path);
            if (entry.kind != .hardlink) self.allocator.free(entry.content.data_fork_bytes);
            freeXattrs(self.allocator, entry.xattrs);
            self.allocator.free(entry.xattr_views);
        }
        self.entries.deinit();
        self.visited_directories.deinit();
        self.hardlinks.deinit();
        freeXattrs(self.allocator, self.root_xattrs_owned);
        self.allocator.free(self.root_xattr_views);
        self.root_xattrs_owned = &.{};
        self.root_xattr_views = &.{};
    }

    fn finish(self: *Scanner) !Tree {
        const entries = try self.entries.toOwnedSlice();
        const owned_root_xattrs = self.root_xattrs_owned;
        const owned_root_views = self.root_xattr_views;
        self.root_xattrs_owned = &.{};
        self.root_xattr_views = &.{};
        return .{
            .allocator = self.allocator,
            .entries = entries,
            .identity = self.identity,
            .root = self.root,
            .root_xattrs_owned = owned_root_xattrs,
            .root_xattr_views = owned_root_views,
            .content_bytes = self.content_bytes,
        };
    }

    fn readInode(self: *Scanner, ino: u64) !ParsedInode {
        const raw = try self.allocator.alloc(u8, self.reader.superblock.inode_size);
        defer self.allocator.free(raw);
        try self.reader.readInodeRaw(self.io, ino, raw);
        return parseInode(self.reader.superblock, ino, raw, self.allocator);
    }

    fn scan(self: *Scanner) !void {
        var root = try self.readInode(self.reader.superblock.root_ino);
        defer root.deinit(self.allocator);
        if (root.kind != .directory) return error.RootIsNotADirectory;

        const xattrs = try readXattrs(self.allocator, root);
        errdefer freeXattrs(self.allocator, xattrs);
        try enforceXattrLimits(xattrs, self.options);
        const views = try self.allocator.alloc(Xattr, xattrs.len);
        for (xattrs, 0..) |xattr, index| views[index] = .{ .name = xattr.name, .value = xattr.value };
        self.root_xattrs_owned = xattrs;
        self.root_xattr_views = views;
        self.root = .{
            .mode = root.mode,
            .uid = root.uid,
            .gid = root.gid,
            .atime = root.atime.seconds,
            .mtime = root.mtime.seconds,
            .ctime = root.ctime.seconds,
            .crtime = root.crtime.seconds,
            .atime_nsec = root.atime.nsec,
            .mtime_nsec = root.mtime.nsec,
            .ctime_nsec = root.ctime.nsec,
            .crtime_nsec = root.crtime.nsec,
            .xattrs = views,
        };
        try self.visited_directories.put(self.reader.superblock.root_ino, {});
        try self.scanDirectory(root, "");
    }

    fn scanDirectory(self: *Scanner, directory: ParsedInode, path: []const u8) ScanError!void {
        const children = try readDirectoryChildren(self.reader, self.io, self.allocator, directory);
        defer {
            for (children) |child| self.allocator.free(child.name);
            self.allocator.free(children);
        }
        sortChildren(children);
        if (children.len > 1) {
            for (children[1..], children[0 .. children.len - 1]) |current, previous| {
                if (std.mem.eql(u8, current.name, previous.name)) return error.DuplicateDirectoryEntry;
            }
        }

        for (children) |child| {
            try validateComponent(child.name, self.options);
            const child_path = if (path.len == 0)
                try self.allocator.dupe(u8, child.name)
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ path, child.name });
            defer self.allocator.free(child_path);
            try self.scanChild(child, child_path);
        }
    }

    fn scanChild(self: *Scanner, child: DirChild, path: []const u8) ScanError!void {
        try validatePath(path, self.options);
        self.node_count += 1;
        limits_mod.observe(self.options.diagnostic, .nodes, self.node_count);
        if (self.node_count > self.options.max_nodes) {
            return limits_mod.exceeded(self.options.diagnostic, .nodes, self.node_count, self.options.max_nodes);
        }

        var inode = try self.readInode(child.ino);
        defer inode.deinit(self.allocator);
        if (child.dir_file_type != dir_ft_unknown and child.dir_file_type != kindToDirFtype(inode.kind)) {
            return error.DirectoryFileTypeMismatch;
        }

        if (inode.kind != .directory and inode.nlink > 1) {
            if (self.hardlinks.get(inode.ino)) |target| {
                try self.appendHardlink(path, inode, target);
                return;
            }
        }

        if (inode.kind == .directory) {
            if (self.visited_directories.contains(inode.ino)) return error.DirectoryCycle;
            try self.visited_directories.put(inode.ino, {});
        }

        limits_mod.observe(self.options.diagnostic, .file_bytes, inode.size);
        if (inode.size > self.options.max_file_bytes) {
            return limits_mod.exceeded(self.options.diagnostic, .file_bytes, inode.size, self.options.max_file_bytes);
        }
        if (inode.hasContent()) {
            self.content_bytes = std.math.add(u64, self.content_bytes, inode.size) catch
                return error.FilesystemExceedsPartition;
            limits_mod.observe(self.options.diagnostic, .total_bytes, self.content_bytes);
            if (self.content_bytes > self.options.max_total_bytes) {
                return limits_mod.exceeded(self.options.diagnostic, .total_bytes, self.content_bytes, self.options.max_total_bytes);
            }
        }

        var device: DeviceNumbers = .{};
        if (inode.kind == .block_device or inode.kind == .char_device) {
            device = try readDeviceNumbers(inode);
        }

        var symlink_target: []u8 = &.{};
        var symlink_target_owned = true;
        defer if (symlink_target_owned) self.allocator.free(symlink_target);
        if (inode.kind == .symlink) {
            symlink_target = try readSymlinkTargetAlloc(self.reader, self.io, self.allocator, inode);
        }

        // A regular file's `Content` keeps its own copy of the data-fork
        // bytes (the extent array or btree-root literal area) so a later
        // read never has to re-fetch and re-verify the inode from disk.
        var data_fork_bytes: []u8 = &.{};
        var data_fork_bytes_owned = true;
        defer if (data_fork_bytes_owned) self.allocator.free(data_fork_bytes);
        if (inode.kind == .file) {
            data_fork_bytes = try self.allocator.dupe(u8, inode.dataForkBytes());
        }

        const xattrs = try readXattrs(self.allocator, inode);
        var xattrs_owned = true;
        defer if (xattrs_owned) freeXattrs(self.allocator, xattrs);
        try enforceXattrLimits(xattrs, self.options);
        const owned_path = try self.allocator.dupe(u8, path);
        var node_owned = true;
        errdefer if (node_owned) self.allocator.free(owned_path);
        const views = try self.allocator.alloc(Xattr, xattrs.len);
        errdefer if (node_owned) self.allocator.free(views);
        for (xattrs, 0..) |xattr, index| views[index] = .{ .name = xattr.name, .value = xattr.value };

        const has_content = inode.hasContent();
        try self.entries.append(.{
            .path = owned_path,
            .kind = inode.kind,
            .mode = inode.mode,
            .uid = inode.uid,
            .gid = inode.gid,
            .size = if (has_content) inode.size else 0,
            .atime = inode.atime.seconds,
            .mtime = inode.mtime.seconds,
            .ctime = inode.ctime.seconds,
            .crtime = inode.crtime.seconds,
            .atime_nsec = inode.atime.nsec,
            .mtime_nsec = inode.mtime.nsec,
            .ctime_nsec = inode.ctime.nsec,
            .crtime_nsec = inode.crtime.nsec,
            .device = device,
            .hardlink_target = "",
            .has_content = has_content,
            .content = .{
                .reader = self.reader,
                .io = self.io,
                .ino = inode.ino,
                .size = inode.size,
                .data_format = if (inode.kind == .symlink) fmt_local else inode.data_format,
                .data_extents = inode.data_extents,
                .data_fork_bytes = if (inode.kind == .symlink) symlink_target else data_fork_bytes,
            },
            .xattrs = xattrs,
            .xattr_views = views,
        });
        xattrs_owned = false;
        node_owned = false;
        if (inode.kind == .symlink) symlink_target_owned = false;
        if (inode.kind == .file) data_fork_bytes_owned = false;

        if (inode.kind != .directory and inode.nlink > 1) {
            try self.hardlinks.put(inode.ino, self.entries.items[self.entries.items.len - 1].path);
        }
        if (inode.kind == .directory) try self.scanDirectory(inode, path);
    }

    fn appendHardlink(self: *Scanner, path: []const u8, inode: ParsedInode, target: []const u8) !void {
        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        try self.entries.append(.{
            .path = owned_path,
            .kind = .hardlink,
            .mode = inode.mode,
            .uid = inode.uid,
            .gid = inode.gid,
            .size = 0,
            .atime = inode.atime.seconds,
            .mtime = inode.mtime.seconds,
            .ctime = inode.ctime.seconds,
            .crtime = inode.crtime.seconds,
            .atime_nsec = inode.atime.nsec,
            .mtime_nsec = inode.mtime.nsec,
            .ctime_nsec = inode.ctime.nsec,
            .crtime_nsec = inode.crtime.nsec,
            .device = .{},
            .hardlink_target = target,
            .has_content = false,
            .content = undefined,
            .xattrs = &.{},
            .xattr_views = &.{},
        });
    }
};

fn sortChildren(children: []DirChild) void {
    std.mem.sort(DirChild, children, {}, struct {
        fn lessThan(_: void, lhs: DirChild, rhs: DirChild) bool {
            return std.mem.order(u8, lhs.name, rhs.name) == .lt;
        }
    }.lessThan);
}

fn validatePath(path: []const u8, options: ScanOptions) !void {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') return error.InvalidImportedPath;
    limits_mod.observe(options.diagnostic, .path_bytes, path.len);
    if (path.len > options.max_path_bytes) {
        return limits_mod.exceeded(options.diagnostic, .path_bytes, path.len, options.max_path_bytes);
    }
}

/// Rejects a directory-entry name that could never be a legal path
/// component (embedded NUL/`/`, or the reserved `.`/`..`) before it is ever
/// joined into a path, and separately enforces the configured per-component
/// length bound.
fn validateComponent(component: []const u8, options: ScanOptions) !void {
    if (component.len == 0 or
        std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..") or
        std.mem.indexOfScalar(u8, component, 0) != null or
        std.mem.indexOfScalar(u8, component, '/') != null)
    {
        return error.InvalidImportedPath;
    }
    limits_mod.observe(options.diagnostic, .component_bytes, component.len);
    if (component.len > options.max_component_bytes) {
        return limits_mod.exceeded(options.diagnostic, .component_bytes, component.len, options.max_component_bytes);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn writeFixture(path: []const u8, bytes: []const u8) !void {
    const io = std.testing.io;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

// ---------------------------------------------------------------------------
// Byte-buffer helpers shared by every fixture builder below.
// ---------------------------------------------------------------------------

fn beU16(buf: []u8, off: usize, v: u16) void {
    std.mem.writeInt(u16, buf[off..][0..2], v, .big);
}
fn beU32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .big);
}
fn beU64(buf: []u8, off: usize, v: u64) void {
    std.mem.writeInt(u64, buf[off..][0..8], v, .big);
}
fn leU32(buf: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], v, .little);
}
fn writeCrc(buf: []u8, crc_offset: usize) void {
    leU32(buf, crc_offset, computeCrc32c(buf, crc_offset));
}

/// Inverse of `decodeBmbtRec`, for building synthetic extent records.
fn encodeBmbtRec(buf: []u8, logical_block: u64, start_block: u64, block_count: u64, unwritten: bool) void {
    const l0: u64 = (@as(u64, @intFromBool(unwritten)) << 63) | (logical_block << 9) | (start_block >> 43);
    const l1: u64 = ((start_block & ((@as(u64, 1) << 43) - 1)) << 21) | block_count;
    beU64(buf, 0, l0);
    beU64(buf, 8, l1);
}

pub const test_fs_uuid = [16]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

// ---------------------------------------------------------------------------
// Superblock fixtures
// ---------------------------------------------------------------------------

const TestSuperblockOptions = struct {
    block_size: u32 = 512,
    sector_size: u16 = 512,
    inode_size: u16 = 512,
    ag_blocks: u32 = 32,
    ag_count: u32 = 2,
    data_blocks: u64 = 64,
    block_log: u8 = 9,
    ag_block_log: u8 = 5,
    inode_per_block_log: u8 = 0,
    dir_block_log: u8 = 0,
    root_ino: u64 = 2,
    realtime_blocks: u64 = 0,
    features_compat: u32 = 0,
    features_ro_compat: u32 = 0,
    features_incompat: u32 = incompat_ftype,
    version_num: u16 = sb_version_5,
    uuid: [16]u8 = test_fs_uuid,
    meta_uuid: [16]u8 = [_]u8{0} ** 16,
    label: [12]u8 = [_]u8{0} ** 12,
    corrupt_crc: bool = false,
};

fn buildTestSuperblock(o: TestSuperblockOptions) [superblock_size]u8 {
    var buf: [superblock_size]u8 = [_]u8{0} ** superblock_size;
    beU32(&buf, 0, magic);
    beU32(&buf, 4, o.block_size);
    beU64(&buf, 8, o.data_blocks);
    beU64(&buf, 16, o.realtime_blocks);
    @memcpy(buf[32..48], &o.uuid);
    beU64(&buf, 56, o.root_ino);
    beU32(&buf, 84, o.ag_blocks);
    beU32(&buf, 88, o.ag_count);
    beU16(&buf, 100, o.version_num);
    beU16(&buf, 102, o.sector_size);
    beU16(&buf, 104, o.inode_size);
    beU16(&buf, 106, 1);
    @memcpy(buf[108..120], &o.label);
    buf[120] = o.block_log;
    buf[121] = 9;
    buf[122] = 9;
    buf[123] = o.inode_per_block_log;
    buf[124] = o.ag_block_log;
    buf[192] = o.dir_block_log;
    beU32(&buf, 208, o.features_compat);
    beU32(&buf, 212, o.features_ro_compat);
    beU32(&buf, 216, o.features_incompat);
    beU32(&buf, 220, 0);
    @memcpy(buf[248..264], &o.meta_uuid);
    writeCrc(&buf, 224);
    if (o.corrupt_crc) buf[224] ^= 0xff;
    return buf;
}

test "parseSuperblock accepts a v5 superblock and exposes uuid/label" {
    var label = [_]u8{0} ** 12;
    @memcpy(label[0..9], "TESTLABEL");
    const buf = buildTestSuperblock(.{ .label = label });
    const sb = try parseSuperblock(&buf);
    try testing.expectEqual(@as(u32, 512), sb.block_size);
    try testing.expectEqual(@as(u64, 64), sb.data_blocks);
    try testing.expectEqualSlices(u8, &test_fs_uuid, &sb.uuid);
    try testing.expectEqualSlices(u8, &label, &sb.label);
    try testing.expectEqual(@as(u64, 2), sb.root_ino);
}

test "parseSuperblock rejects a bad magic" {
    var buf = buildTestSuperblock(.{});
    buf[0] = 0;
    try testing.expectError(error.BadMagic, parseSuperblock(&buf));
}

test "parseSuperblock rejects pre-CRC v1-v4 filesystems" {
    const buf = buildTestSuperblock(.{ .version_num = 4 });
    try testing.expectError(error.UnsupportedSuperblockVersion, parseSuperblock(&buf));
}

test "parseSuperblock rejects a corrupt checksum" {
    const buf = buildTestSuperblock(.{ .corrupt_crc = true });
    try testing.expectError(error.SuperblockChecksumMismatch, parseSuperblock(&buf));
}

test "parseSuperblock rejects a realtime volume" {
    const buf = buildTestSuperblock(.{ .realtime_blocks = 100 });
    try testing.expectError(error.RealtimeVolumeUnsupported, parseSuperblock(&buf));
}

test "parseSuperblock rejects each named unsupported incompat feature" {
    const cases = [_]struct { bit: u32, err: anyerror }{
        .{ .bit = incompat_needsrepair, .err = error.SourceNeedsRepair },
        .{ .bit = incompat_exchrange, .err = error.UnsupportedExchangeRangeFeature },
        .{ .bit = incompat_parent, .err = error.UnsupportedParentPointerFeature },
        .{ .bit = incompat_metadir, .err = error.UnsupportedMetadataDirectoryFeature },
        .{ .bit = incompat_zoned, .err = error.UnsupportedZonedRtFeature },
        .{ .bit = incompat_zone_gaps, .err = error.UnsupportedZoneGapsFeature },
    };
    for (cases) |case| {
        const buf = buildTestSuperblock(.{ .features_incompat = incompat_ftype | case.bit });
        try testing.expectError(case.err, parseSuperblock(&buf));
    }
}

test "parseSuperblock rejects a missing FTYPE feature" {
    const buf = buildTestSuperblock(.{ .features_incompat = 0 });
    try testing.expectError(error.MissingFtypeFeature, parseSuperblock(&buf));
}

test "parseSuperblock rejects an unknown incompat bit" {
    const buf = buildTestSuperblock(.{ .features_incompat = incompat_ftype | (1 << 31) });
    try testing.expectError(error.UnsupportedIncompatFeature, parseSuperblock(&buf));
}

test "parseSuperblock rejects a non-zero compat feature bit" {
    const buf = buildTestSuperblock(.{ .features_compat = 1 });
    try testing.expectError(error.UnsupportedCompatFeature, parseSuperblock(&buf));
}

test "parseSuperblock accepts every known ro-compat bit together" {
    const buf = buildTestSuperblock(.{ .features_ro_compat = ro_compat_known_mask });
    _ = try parseSuperblock(&buf);
}

test "parseSuperblock rejects an oversized inode_per_block_log without an arithmetic overflow" {
    // A raw 0xff `sb_inopblog` byte, added to a valid `ag_block_log`,
    // regression-tests that the agino-bit-width check widens both operands
    // before summing: a narrow `u6`/`u8` addition would panic on overflow
    // (31 + 255 doesn't fit in a `u8`) instead of returning this error.
    const buf = buildTestSuperblock(.{ .inode_per_block_log = 0xff });
    try testing.expectError(error.InvalidSuperblockGeometry, parseSuperblock(&buf));
}

test "parseSuperblock rejects an oversized dir_block_log without an arithmetic overflow" {
    // Same concern as above but for the directory block-size shift
    // (`block_log + dir_block_log`), which `dirBlockSize` later uses as a
    // `u32` shift amount.
    const buf = buildTestSuperblock(.{ .dir_block_log = 0xff });
    try testing.expectError(error.InvalidSuperblockGeometry, parseSuperblock(&buf));
}

test "parseSuperblock rejects an agino bit width one past the 63-bit boundary" {
    const buf = buildTestSuperblock(.{ .ag_block_log = 5, .inode_per_block_log = 59 });
    try testing.expectError(error.InvalidSuperblockGeometry, parseSuperblock(&buf));
}

test "parseSuperblock accepts an agino bit width exactly at the 63-bit boundary" {
    const buf = buildTestSuperblock(.{ .ag_block_log = 5, .inode_per_block_log = 58 });
    const sb = try parseSuperblock(&buf);
    try testing.expectEqual(@as(u6, 63), sb.aginoBits());
}

test "parseSuperblock rejects a directory block shift one past the 31-bit boundary" {
    const buf = buildTestSuperblock(.{ .block_log = 9, .dir_block_log = 23 });
    try testing.expectError(error.InvalidSuperblockGeometry, parseSuperblock(&buf));
}

test "parseSuperblock accepts a directory block shift exactly at the 31-bit boundary" {
    const buf = buildTestSuperblock(.{ .block_log = 9, .dir_block_log = 22 });
    const sb = try parseSuperblock(&buf);
    try testing.expectEqual(@as(u32, 1) << 31, sb.dirBlockSize());
}

// ---------------------------------------------------------------------------
// Inode fixtures
// ---------------------------------------------------------------------------

const TestInodeOptions = struct {
    ino: u64,
    mode: u16,
    uid: u32 = 0,
    gid: u32 = 0,
    nlink: u32 = 1,
    size: u64 = 0,
    data_format: u8 = fmt_extents,
    attr_format: u8 = fmt_local,
    nextents: u32 = 0,
    anextents: u16 = 0,
    forkoff: u8 = 0,
    flags: u16 = 0,
    flags2: u64 = 0,
    corrupt_ino: bool = false,
    corrupt_crc: bool = false,
};

/// Builds a full `inode_size`-byte v3 (CRC) dinode. `literal_prefix` is
/// copied to the start of the (zero-filled) literal area; callers only need
/// to supply the meaningful bytes, not pad to the full literal-area size.
fn buildTestInode(allocator: std.mem.Allocator, inode_size: u16, o: TestInodeOptions, literal_prefix: []const u8) ![]u8 {
    const buf = try allocator.alloc(u8, inode_size);
    @memset(buf, 0);
    beU16(buf, 0, dinode_magic);
    beU16(buf, 2, o.mode);
    buf[4] = 3;
    buf[5] = o.data_format;
    beU32(buf, 8, o.uid);
    beU32(buf, 12, o.gid);
    beU32(buf, 16, o.nlink);
    beU32(buf, 32, 1_700_000_000);
    beU32(buf, 40, 1_700_000_001);
    beU32(buf, 48, 1_700_000_002);
    beU64(buf, 56, o.size);
    beU32(buf, 76, o.nextents);
    beU16(buf, 80, o.anextents);
    buf[82] = o.forkoff;
    buf[83] = o.attr_format;
    beU16(buf, 90, o.flags);
    beU64(buf, 120, o.flags2);
    beU32(buf, 144, 1_700_000_003);
    beU64(buf, 152, if (o.corrupt_ino) o.ino + 1 else o.ino);
    @memcpy(buf[160..176], &test_fs_uuid);
    std.debug.assert(literal_prefix.len <= buf.len - dinode_v3_core_size);
    @memcpy(buf[dinode_v3_core_size..][0..literal_prefix.len], literal_prefix);
    writeCrc(buf, dinode_crc_offset);
    if (o.corrupt_crc) buf[dinode_crc_offset] ^= 0xff;
    return buf;
}

fn testSuperblock() !Superblock {
    return parseSuperblock(&buildTestSuperblock(.{}));
}

test "parseInode decodes core fields for a regular file" {
    const sb = try testSuperblock();
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 42,
        .mode = s_ifreg | 0o644,
        .uid = 1000,
        .gid = 1000,
        .nlink = 1,
        .size = 5,
        .data_format = fmt_local,
    }, "hello");
    defer testing.allocator.free(raw);
    var inode = try parseInode(sb, 42, raw, testing.allocator);
    defer inode.deinit(testing.allocator);
    try testing.expectEqual(Kind.file, inode.kind);
    try testing.expectEqual(@as(u16, 0o644), inode.mode);
    try testing.expectEqual(@as(u32, 1000), inode.uid);
    try testing.expectEqual(@as(u32, 1000), inode.gid);
    try testing.expectEqual(@as(u64, 5), inode.size);
    try testing.expectEqual(@as(i64, 1_700_000_000), inode.atime.seconds);
    try testing.expectEqualStrings("hello", inode.dataForkBytes()[0..5]);
}

test "parseInode rejects a stored inode number that does not match the request" {
    const sb = try testSuperblock();
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 42,
        .mode = s_ifreg | 0o644,
        .corrupt_ino = true,
    }, "");
    defer testing.allocator.free(raw);
    try testing.expectError(error.InodeIdentityMismatch, parseInode(sb, 42, raw, testing.allocator));
}

test "parseInode rejects a corrupt checksum" {
    const sb = try testSuperblock();
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 42,
        .mode = s_ifreg | 0o644,
        .corrupt_crc = true,
    }, "");
    defer testing.allocator.free(raw);
    try testing.expectError(error.InodeChecksumMismatch, parseInode(sb, 42, raw, testing.allocator));
}

test "parseInode rejects a fork offset past the end of the literal area without panicking" {
    const sb = try testSuperblock();
    // A malformed/adversarial `di_forkoff` describing a fork boundary
    // beyond the literal area must be rejected by name here, before any
    // later `dataForkBytes()`/`attrForkBytes()` call can slice past the
    // buffer's real length and panic.
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 42,
        .mode = s_ifreg | 0o644,
        .forkoff = 255,
    }, "");
    defer testing.allocator.free(raw);
    try testing.expectError(error.InvalidForkOffset, parseInode(sb, 42, raw, testing.allocator));
}

test "parseInode rejects a fork offset one 8-byte unit past the literal area boundary" {
    const sb = try testSuperblock();
    const literal_area_len = @as(usize, sb.inode_size) - dinode_v3_core_size;
    const one_past: u8 = @intCast(literal_area_len / 8 + 1);
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 42,
        .mode = s_ifreg | 0o644,
        .forkoff = one_past,
    }, "");
    defer testing.allocator.free(raw);
    try testing.expectError(error.InvalidForkOffset, parseInode(sb, 42, raw, testing.allocator));
}

test "parseInode accepts a fork offset that exactly fills the literal area" {
    const sb = try testSuperblock();
    const literal_area_len = @as(usize, sb.inode_size) - dinode_v3_core_size;
    const exact: u8 = @intCast(literal_area_len / 8);
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 42,
        .mode = s_ifreg | 0o644,
        .forkoff = exact,
    }, "");
    defer testing.allocator.free(raw);
    var inode = try parseInode(sb, 42, raw, testing.allocator);
    defer inode.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, literal_area_len), inode.dataForkBytes().len);
    try testing.expectEqual(@as(usize, 0), inode.attrForkBytes().len);
}

// ---------------------------------------------------------------------------
// Directory fixtures (shortform + single-block "block" format)
// ---------------------------------------------------------------------------

/// Builds a shortform (`xfs_dir2_sf_hdr` + `xfs_dir2_sf_entry`*) directory
/// fork using 4-byte inode numbers throughout (`i8count == 0`).
const ShortformDirBuilder = struct {
    buf: [512]u8 = undefined,
    len: usize = 6,
    count: u8 = 0,

    fn init(parent_ino: u32) ShortformDirBuilder {
        var self = ShortformDirBuilder{};
        self.buf[1] = 0;
        beU32(&self.buf, 2, parent_ino);
        return self;
    }

    fn append(self: *ShortformDirBuilder, name: []const u8, ino: u32, ftype: u8) void {
        self.buf[self.len] = @intCast(name.len);
        beU16(&self.buf, self.len + 1, 0);
        @memcpy(self.buf[self.len + 3 ..][0..name.len], name);
        self.buf[self.len + 3 + name.len] = ftype;
        beU32(&self.buf, self.len + 3 + name.len + 1, ino);
        self.len += 3 + name.len + 1 + 4;
        self.count += 1;
    }

    fn finish(self: *ShortformDirBuilder) []const u8 {
        self.buf[0] = self.count;
        return self.buf[0..self.len];
    }
};

/// Builds a single-block "block" format (`XDB3`) directory: header, real
/// entries, one trailing "unused" filler entry padding out to the leaf
/// array, and a zero-count leaf/tail area (no leaf entries are needed since
/// this reader linear-scans the data area directly).
const BlockFormatDirBuilder = struct {
    buf: [512]u8 = [_]u8{0} ** 512,
    len: usize = dir3_data_header_size,
    block_size: usize = 512,

    fn appendEntry(self: *BlockFormatDirBuilder, ino: u64, name: []const u8, ftype: u8) void {
        const entry_len = std.mem.alignForward(usize, 8 + 1 + name.len + 1 + 2, 8);
        beU64(&self.buf, self.len, ino);
        self.buf[self.len + 8] = @intCast(name.len);
        @memcpy(self.buf[self.len + 9 ..][0..name.len], name);
        self.buf[self.len + 9 + name.len] = ftype;
        self.len += entry_len;
    }

    fn finish(self: *BlockFormatDirBuilder, owner_ino: u64) []const u8 {
        const leaf_area_start = self.block_size - 8;
        const remaining = leaf_area_start - self.len;
        if (remaining > 0) {
            beU16(&self.buf, self.len, 0xffff);
            beU16(&self.buf, self.len + 2, @intCast(remaining));
            self.len += remaining;
        }
        beU32(&self.buf, self.block_size - 8, 0);
        beU32(&self.buf, self.block_size - 4, 0);
        beU32(&self.buf, 0, dir3_block_magic);
        beU64(&self.buf, 40, owner_ino);
        writeCrc(&self.buf, 4);
        return self.buf[0..self.block_size];
    }
};

test "readShortformDirectory decodes entries with 4-byte inode numbers" {
    var b = ShortformDirBuilder.init(2);
    b.append("abc", 5, dir_ft_reg_file);
    b.append("d", 6, dir_ft_dir);
    const data = b.finish();

    const children = try readShortformDirectory(testing.allocator, data);
    defer {
        for (children) |c| testing.allocator.free(c.name);
        testing.allocator.free(children);
    }
    try testing.expectEqual(@as(usize, 2), children.len);
    try testing.expectEqualStrings("abc", children[0].name);
    try testing.expectEqual(@as(u64, 5), children[0].ino);
    try testing.expectEqual(dir_ft_reg_file, children[0].dir_file_type);
    try testing.expectEqualStrings("d", children[1].name);
    try testing.expectEqual(@as(u64, 6), children[1].ino);
    try testing.expectEqual(dir_ft_dir, children[1].dir_file_type);
}

test "readBlockFormatDirectory decodes entries and skips dot/dotdot" {
    var b = BlockFormatDirBuilder{};
    b.appendEntry(40, ".", dir_ft_dir);
    b.appendEntry(2, "..", dir_ft_dir);
    b.appendEntry(41, "in_sub.txt", dir_ft_reg_file);
    b.appendEntry(6, "hardlinked2", dir_ft_reg_file);
    const block = b.finish(40);

    const children = try readBlockFormatDirectory(testing.allocator, block, 40);
    defer {
        for (children) |c| testing.allocator.free(c.name);
        testing.allocator.free(children);
    }
    try testing.expectEqual(@as(usize, 2), children.len);
    try testing.expectEqualStrings("in_sub.txt", children[0].name);
    try testing.expectEqual(@as(u64, 41), children[0].ino);
    try testing.expectEqualStrings("hardlinked2", children[1].name);
    try testing.expectEqual(@as(u64, 6), children[1].ino);
}

test "readBlockFormatDirectory rejects the multi-block XDD3 magic by name" {
    var b = BlockFormatDirBuilder{};
    b.appendEntry(2, "x", dir_ft_reg_file);
    const built = b.finish(40);
    var block: [512]u8 = undefined;
    @memcpy(&block, built);
    beU32(&block, 0, dir3_data_magic);
    try testing.expectError(error.UnsupportedDirectoryFormat, readBlockFormatDirectory(testing.allocator, &block, 40));
}

test "readBlockFormatDirectory rejects a checksum mismatch" {
    var b = BlockFormatDirBuilder{};
    b.appendEntry(2, "x", dir_ft_reg_file);
    const built = b.finish(40);
    var block: [512]u8 = undefined;
    @memcpy(&block, built);
    block[300] ^= 0xff;
    try testing.expectError(error.DirectoryChecksumMismatch, readBlockFormatDirectory(testing.allocator, &block, 40));
}

// ---------------------------------------------------------------------------
// Extent fixtures (flat EXTENTS array; BTREE is covered by the full
// integration test below, since it needs real block reads via `Reader`).
// ---------------------------------------------------------------------------

test "readExtents decodes a flat EXTENTS record" {
    const sb = try testSuperblock();
    var reader: Reader = .{ .allocator = testing.allocator, .file = undefined, .superblock = sb };
    var rec: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&rec, 0, 10, 2, false);

    const extents = try readExtents(&reader, std.testing.io, testing.allocator, 99, fmt_extents, 1, &rec);
    defer testing.allocator.free(extents);
    try testing.expectEqual(@as(usize, 1), extents.len);
    try testing.expectEqual(@as(u64, 0), extents[0].logical_block);
    try testing.expectEqual(@as(u64, 10), extents[0].start_block);
    try testing.expectEqual(@as(u64, 2), extents[0].block_count);
    try testing.expect(!extents[0].unwritten);
}

test "readExtents rejects overlapping extent records" {
    const sb = try testSuperblock();
    var reader: Reader = .{ .allocator = testing.allocator, .file = undefined, .superblock = sb };
    var recs: [2 * bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(recs[0..bmbt_rec_size], 0, 10, 2, false);
    encodeBmbtRec(recs[bmbt_rec_size..][0..bmbt_rec_size], 1, 20, 2, false);

    try testing.expectError(
        error.InvalidExtent,
        readExtents(&reader, std.testing.io, testing.allocator, 99, fmt_extents, 2, &recs),
    );
}

// ---------------------------------------------------------------------------
// Symlink fixtures (LOCAL only here; remote EXTENTS needs a real block read
// and is covered by the full integration test below).
// ---------------------------------------------------------------------------

test "readSymlinkTargetAlloc decodes an inline LOCAL target" {
    const sb = try testSuperblock();
    const target = "file.txt";
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 4,
        .mode = s_iflnk | 0o777,
        .data_format = fmt_local,
        .size = target.len,
    }, target);
    defer testing.allocator.free(raw);
    var inode = try parseInode(sb, 4, raw, testing.allocator);
    defer inode.deinit(testing.allocator);

    var dummy_reader: Reader = undefined;
    const out = try readSymlinkTargetAlloc(&dummy_reader, std.testing.io, testing.allocator, inode);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(target, out);
}

test "readSymlinkTargetAlloc rejects an oversized target" {
    const sb = try testSuperblock();
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 4,
        .mode = s_iflnk | 0o777,
        .data_format = fmt_local,
        .size = symlink_max_len + 1,
    }, "");
    defer testing.allocator.free(raw);
    var inode = try parseInode(sb, 4, raw, testing.allocator);
    defer inode.deinit(testing.allocator);

    var dummy_reader: Reader = undefined;
    try testing.expectError(
        error.SymlinkTargetTooLarge,
        readSymlinkTargetAlloc(&dummy_reader, std.testing.io, testing.allocator, inode),
    );
}

// ---------------------------------------------------------------------------
// Device numbers
// ---------------------------------------------------------------------------

test "decodeDeviceNumbers matches the XFS sysv/IRIX major/minor packing" {
    // sysv_encode_dev(major=1, minor=3) = (1 << 18) | 3 = 0x40003
    const dev = decodeDeviceNumbers(0x40003);
    try testing.expectEqual(@as(u32, 1), dev.major);
    try testing.expectEqual(@as(u32, 3), dev.minor);

    // sysv_encode_dev(major=8, minor=0) = 8 << 18 = 0x200000
    const dev2 = decodeDeviceNumbers(0x200000);
    try testing.expectEqual(@as(u32, 8), dev2.major);
    try testing.expectEqual(@as(u32, 0), dev2.minor);

    // A minor above 0xff must round-trip; this case distinguishes the sysv
    // encoding from ext4's new_decode_dev(): sysv_encode_dev(4, 300) =
    // (4 << 18) | 300 = 0x10012c.
    const dev3 = decodeDeviceNumbers(0x10012c);
    try testing.expectEqual(@as(u32, 4), dev3.major);
    try testing.expectEqual(@as(u32, 300), dev3.minor);
}

// ---------------------------------------------------------------------------
// Extended attribute fixtures (shortform only)
// ---------------------------------------------------------------------------

const ShortformXattrBuilder = struct {
    buf: [512]u8 = undefined,
    len: usize = 4,
    count: u8 = 0,

    fn append(self: *ShortformXattrBuilder, name: []const u8, value: []const u8, flags: u8) void {
        self.buf[self.len] = @intCast(name.len);
        self.buf[self.len + 1] = @intCast(value.len);
        self.buf[self.len + 2] = flags;
        @memcpy(self.buf[self.len + 3 ..][0..name.len], name);
        @memcpy(self.buf[self.len + 3 + name.len ..][0..value.len], value);
        self.len += 3 + name.len + value.len;
        self.count += 1;
    }

    fn finish(self: *ShortformXattrBuilder) []const u8 {
        beU16(&self.buf, 0, @intCast(self.len));
        self.buf[2] = self.count;
        self.buf[3] = 0;
        return self.buf[0..self.len];
    }
};

/// Builds a regular-file inode whose attribute fork (`forkoff == 1`, so the
/// data fork is the first 8 bytes of the literal area) holds `xattr_data`.
fn buildXattrTestInode(allocator: std.mem.Allocator, sb: Superblock, xattr_data: []const u8) !struct { raw: []u8, inode: ParsedInode } {
    var literal: [336]u8 = [_]u8{0} ** 336;
    @memcpy(literal[8..][0..xattr_data.len], xattr_data);
    const raw = try buildTestInode(allocator, sb.inode_size, .{
        .ino = 7,
        .mode = s_ifreg | 0o644,
        .data_format = fmt_extents,
        .attr_format = fmt_local,
        .forkoff = 1,
    }, &literal);
    errdefer allocator.free(raw);
    const inode = try parseInode(sb, 7, raw, allocator);
    return .{ .raw = raw, .inode = inode };
}

test "readXattrs decodes shortform entries with prefix flags" {
    const sb = try testSuperblock();
    var xb = ShortformXattrBuilder{};
    xb.append("foo", "bar", 0);
    xb.append("baz", "qux", attr_root_bit);
    const built = try buildXattrTestInode(testing.allocator, sb, xb.finish());
    defer testing.allocator.free(built.raw);
    var inode = built.inode;
    defer inode.deinit(testing.allocator);

    const xattrs = try readXattrs(testing.allocator, inode);
    defer {
        for (xattrs) |x| {
            testing.allocator.free(x.name);
            testing.allocator.free(x.value);
        }
        testing.allocator.free(xattrs);
    }
    try testing.expectEqual(@as(usize, 2), xattrs.len);
    try testing.expectEqualStrings("user.foo", xattrs[0].name);
    try testing.expectEqualStrings("bar", xattrs[0].value);
    try testing.expectEqualStrings("trusted.baz", xattrs[1].name);
    try testing.expectEqualStrings("qux", xattrs[1].value);
}

test "readXattrs rejects the PARENT and INCOMPLETE flag bits" {
    const sb = try testSuperblock();
    for ([_]u8{ attr_parent_bit, attr_incomplete_bit }) |bit| {
        var xb = ShortformXattrBuilder{};
        xb.append("foo", "bar", bit);
        const built = try buildXattrTestInode(testing.allocator, sb, xb.finish());
        defer testing.allocator.free(built.raw);
        var inode = built.inode;
        defer inode.deinit(testing.allocator);
        try testing.expectError(error.UnsupportedXattrFlags, readXattrs(testing.allocator, inode));
    }
}

test "readXattrs rejects an out-of-line (non-LOCAL) attribute fork format" {
    const sb = try testSuperblock();
    const raw = try buildTestInode(testing.allocator, sb.inode_size, .{
        .ino = 7,
        .mode = s_ifreg | 0o644,
        .forkoff = 1,
        .attr_format = fmt_extents,
    }, &[_]u8{0} ** 336);
    defer testing.allocator.free(raw);
    var inode = try parseInode(sb, 7, raw, testing.allocator);
    defer inode.deinit(testing.allocator);
    try testing.expectError(error.UnsupportedXattrForkFormat, readXattrs(testing.allocator, inode));
}

// ---------------------------------------------------------------------------
// Full integration test: a hand-built on-disk image exercised through
// `Reader.openPath` + `scanReadable`, the same way `squashfs.zig`'s and
// `ext4.zig`'s own fixture-file tests do.
// ---------------------------------------------------------------------------

fn buildVolume(allocator: std.mem.Allocator, total_blocks: u64, block_size: u32) ![]u8 {
    const buf = try allocator.alloc(u8, @as(usize, @intCast(total_blocks)) * block_size);
    @memset(buf, 0);
    return buf;
}

fn putBlock(volume: []u8, block_size: u32, block_no: u64, bytes: []const u8) void {
    const off = @as(usize, @intCast(block_no)) * block_size;
    @memcpy(volume[off..][0..bytes.len], bytes);
}

fn findEntry(tree: *Tree, path: []const u8) ?Entry {
    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const entry = tree.entryAt(index);
        if (std.mem.eql(u8, entry.path, path)) return entry;
    }
    return null;
}

fn readEntryAlloc(allocator: std.mem.Allocator, entry: Entry) ![]u8 {
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

fn expectXattr(entry: Entry, name: []const u8, value: []const u8) !void {
    for (entry.xattrs) |xattr| {
        if (!std.mem.eql(u8, xattr.name, name)) continue;
        try testing.expectEqualStrings(value, xattr.value);
        return;
    }
    std.debug.print("missing xattr {s} on {s}\n", .{ name, entry.path });
    return error.TestUnexpectedResult;
}

const integration_fixture_path = "test-xfs-general.img";
/// Exposed (rather than kept private) so `root_tree.zig` and
/// `preserved_image.zig` can build focused XFS-backed tests against a real,
/// hand-built XFS volume without requiring `mkfs.xfs` in the test
/// environment.
pub const integration_block_size: u32 = 512;
pub const integration_ag_blocks: u32 = 32;
pub const integration_ag_count: u32 = 2;
pub const integration_data_blocks: u64 = integration_ag_blocks * integration_ag_count;

pub const file_txt_content = "hello from file.txt, read back through a single EXTENTS record\n";
pub const hardlinked_content = "shared content, visible under two names via one inode\n";
const attrs_txt_content = "attrs.txt content, alongside a populated shortform xattr fork\n";
pub const in_sub_txt_content = "in_sub.txt content: this block is real, the next is a hole\n";
pub const rlink_target = "0123456789" ** 20; // 200 bytes: exercises the *remote* EXTENTS symlink path.
pub const big_bin_block0 = [_]u8{'A'} ** integration_block_size;
pub const big_bin_block1 = [_]u8{'B'} ** integration_block_size;
pub const in_sub_txt_size: u64 = integration_block_size + 100;
/// `unwritten.bin`'s single extent is marked unwritten (allocated, never
/// written) rather than left as a hole, so a consumer can tell the two
/// apart in the fixture even though both read back as zeros.
pub const unwritten_bin_size: u64 = integration_block_size;

/// Builds the full synthetic volume described in this module's test plan:
/// two allocation groups, a shortform root directory, a nested single-block
/// "block" format directory, EXTENTS and BTREE regular files (the latter
/// with a genuine hole), an EXTENTS file whose sole extent is unwritten
/// (allocated but never written, distinct from a hole -- no extent record
/// at all), LOCAL and remote-EXTENTS symlinks, a hardlinked inode reached
/// under two names, a character device, and a shortform xattr fork --
/// geometry chosen so `inode_per_block_log == 0` and
/// `ag_block_log == log2(ag_blocks)` make every inode number equal to the
/// raw fs-block number it lives in, regardless of which AG it falls in.
///
/// Public so other modules' tests (`root_tree.zig`, `preserved_image.zig`)
/// can reuse this exact fixture instead of hand-building their own synthetic
/// XFS bytes or depending on `mkfs.xfs` being present.
pub fn buildIntegrationVolume(allocator: std.mem.Allocator) ![]u8 {
    const volume = try buildVolume(allocator, integration_data_blocks, integration_block_size);
    errdefer allocator.free(volume);

    const sb = buildTestSuperblock(.{
        .block_size = integration_block_size,
        .sector_size = integration_block_size,
        .inode_size = integration_block_size,
        .ag_blocks = integration_ag_blocks,
        .ag_count = integration_ag_count,
        .data_blocks = integration_data_blocks,
        .root_ino = 2,
    });
    putBlock(volume, integration_block_size, 0, &sb);

    // --- root (ino 2, AG0): shortform directory -----------------------
    var root_dir = ShortformDirBuilder.init(2);
    root_dir.append("file.txt", 3, dir_ft_reg_file);
    root_dir.append("link", 4, dir_ft_symlink);
    root_dir.append("dev", 5, dir_ft_chrdev);
    root_dir.append("hardlinked", 6, dir_ft_reg_file);
    root_dir.append("attrs.txt", 7, dir_ft_reg_file);
    root_dir.append("sub", 40, dir_ft_dir);
    root_dir.append("big.bin", 50, dir_ft_reg_file);
    root_dir.append("rlink", 51, dir_ft_symlink);
    root_dir.append("unwritten.bin", 8, dir_ft_reg_file);
    const root_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 2,
        .mode = s_ifdir | 0o755,
        .nlink = 3,
        .data_format = fmt_local,
    }, root_dir.finish());
    defer allocator.free(root_inode);
    putBlock(volume, integration_block_size, 2, root_inode);

    // --- file.txt (ino 3, AG0): EXTENTS regular file, content at block 20
    var file_txt_extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&file_txt_extent, 0, 20, 1, false);
    const file_txt_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 3,
        .mode = s_ifreg | 0o644,
        .size = file_txt_content.len,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &file_txt_extent);
    defer allocator.free(file_txt_inode);
    putBlock(volume, integration_block_size, 3, file_txt_inode);
    putBlock(volume, integration_block_size, 20, file_txt_content);

    // --- link (ino 4, AG0): LOCAL symlink -> "file.txt" ----------------
    const link_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 4,
        .mode = s_iflnk | 0o777,
        .size = "file.txt".len,
        .data_format = fmt_local,
    }, "file.txt");
    defer allocator.free(link_inode);
    putBlock(volume, integration_block_size, 4, link_inode);

    // --- dev (ino 5, AG0): char device, major 1 minor 3 ----------------
    // On disk XFS stores the device number sysv-encoded: (major << 18) | minor.
    var dev_data: [4]u8 = undefined;
    beU32(&dev_data, 0, 0x40003);
    const dev_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 5,
        .mode = s_ifchr | 0o644,
        .data_format = fmt_dev,
    }, &dev_data);
    defer allocator.free(dev_inode);
    putBlock(volume, integration_block_size, 5, dev_inode);

    // --- hardlinked (ino 6, AG0): EXTENTS regular file, nlink 2 --------
    var hardlinked_extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&hardlinked_extent, 0, 21, 1, false);
    const hardlinked_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 6,
        .mode = s_ifreg | 0o640,
        .nlink = 2,
        .size = hardlinked_content.len,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &hardlinked_extent);
    defer allocator.free(hardlinked_inode);
    putBlock(volume, integration_block_size, 6, hardlinked_inode);
    putBlock(volume, integration_block_size, 21, hardlinked_content);

    // --- attrs.txt (ino 7, AG0): EXTENTS regular file + shortform xattrs
    var xb = ShortformXattrBuilder{};
    xb.append("foo", "bar", 0);
    xb.append("baz", "qux", attr_root_bit);
    var attrs_literal: [integration_block_size - dinode_v3_core_size]u8 = [_]u8{0} ** (integration_block_size - dinode_v3_core_size);
    encodeBmbtRec(attrs_literal[0..bmbt_rec_size], 0, 22, 1, false);
    const xattr_bytes = xb.finish();
    @memcpy(attrs_literal[16..][0..xattr_bytes.len], xattr_bytes);
    const attrs_txt_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 7,
        .mode = s_ifreg | 0o644,
        .size = attrs_txt_content.len,
        .data_format = fmt_extents,
        .attr_format = fmt_local,
        .forkoff = 2,
        .nextents = 1,
    }, &attrs_literal);
    defer allocator.free(attrs_txt_inode);
    putBlock(volume, integration_block_size, 7, attrs_txt_inode);
    putBlock(volume, integration_block_size, 22, attrs_txt_content);

    // --- unwritten.bin (ino 8, AG0): EXTENTS regular file whose sole
    // extent is unwritten -- allocated but never written. Block 23 (the
    // extent's target) is filled with a non-zero marker rather than left
    // zeroed, so a read that returned it verbatim instead of zero-filling
    // would be caught rather than accidentally matching anyway.
    var unwritten_extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&unwritten_extent, 0, 23, 1, true);
    const unwritten_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 8,
        .mode = s_ifreg | 0o644,
        .size = unwritten_bin_size,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &unwritten_extent);
    defer allocator.free(unwritten_inode);
    putBlock(volume, integration_block_size, 8, unwritten_inode);
    const unwritten_marker = [_]u8{0xEE} ** integration_block_size;
    putBlock(volume, integration_block_size, 23, &unwritten_marker);

    // --- sub (ino 40, AG1): EXTENTS single-block "block" format dir ---
    var sub_dir = BlockFormatDirBuilder{};
    sub_dir.appendEntry(40, ".", dir_ft_dir);
    sub_dir.appendEntry(2, "..", dir_ft_dir);
    sub_dir.appendEntry(6, "hardlinked2", dir_ft_reg_file);
    sub_dir.appendEntry(41, "in_sub.txt", dir_ft_reg_file);
    const sub_dir_block = sub_dir.finish(40);
    putBlock(volume, integration_block_size, 42, sub_dir_block);
    var sub_extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&sub_extent, 0, 42, 1, false);
    const sub_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 40,
        .mode = s_ifdir | 0o755,
        .nlink = 2,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &sub_extent);
    defer allocator.free(sub_inode);
    putBlock(volume, integration_block_size, 40, sub_inode);

    // --- in_sub.txt (ino 41, AG1): EXTENTS with a genuine hole ---------
    // Logical block 0 has a real extent (block 43); logical block 1 is a
    // hole (no extent record at all), read back as zeros.
    var in_sub_extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&in_sub_extent, 0, 43, 1, false);
    const in_sub_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 41,
        .mode = s_ifreg | 0o644,
        .size = in_sub_txt_size,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &in_sub_extent);
    defer allocator.free(in_sub_inode);
    putBlock(volume, integration_block_size, 41, in_sub_inode);
    putBlock(volume, integration_block_size, 43, in_sub_txt_content);

    // --- big.bin (ino 50, AG1): FMT_BTREE, 2 extents via a leaf block --
    // The inode-rooted bmdr block sizes its key/ptr arrays for `maxrecs`
    // (however many (key,ptr) pairs fit in the whole literal area), not for
    // `numrecs` -- deliberately using numrecs=1 << maxrecs here (a
    // non-full root) regression-tests that the pointer is read from the
    // maxrecs-based offset (`xfs_bmdr_ptr_addr`), not from `numrecs * 8`.
    const big_bin_literal_area_len = integration_block_size - dinode_v3_core_size;
    const big_bin_root_maxrecs = (big_bin_literal_area_len - bmdr_header_size) / (bmbt_key_size + bmbt_ptr_size);
    const big_bin_root_ptr_offset = bmdr_header_size + big_bin_root_maxrecs * bmbt_key_size;
    var big_bin_root: [big_bin_root_ptr_offset + 8]u8 = [_]u8{0} ** (big_bin_root_ptr_offset + 8);
    beU16(&big_bin_root, 0, 1); // level: 1 above the leaf
    beU16(&big_bin_root, 2, 1); // numrecs
    beU64(&big_bin_root, big_bin_root_ptr_offset, 53); // ptr: child fsblock
    const big_bin_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 50,
        .mode = s_ifreg | 0o644,
        .size = 2 * integration_block_size,
        .data_format = fmt_btree,
        .nextents = 2,
    }, &big_bin_root);
    defer allocator.free(big_bin_inode);
    putBlock(volume, integration_block_size, 50, big_bin_inode);

    var leaf: [integration_block_size]u8 = [_]u8{0} ** integration_block_size;
    beU32(&leaf, 0, bmap_btree_magic);
    beU16(&leaf, 4, 0); // level 0 (leaf)
    beU16(&leaf, 6, 2); // numrecs
    beU64(&leaf, 56, 50); // bb_owner == ino
    encodeBmbtRec(leaf[bmbt_long_header_size..][0..bmbt_rec_size], 0, 54, 1, false);
    encodeBmbtRec(leaf[bmbt_long_header_size + bmbt_rec_size ..][0..bmbt_rec_size], 1, 55, 1, false);
    writeCrc(&leaf, bmbt_long_crc_offset);
    putBlock(volume, integration_block_size, 53, &leaf);
    putBlock(volume, integration_block_size, 54, &big_bin_block0);
    putBlock(volume, integration_block_size, 55, &big_bin_block1);

    // --- rlink (ino 51, AG1): remote EXTENTS symlink -------------------
    var rlink_extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&rlink_extent, 0, 52, 1, false);
    const rlink_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 51,
        .mode = s_iflnk | 0o777,
        .size = rlink_target.len,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &rlink_extent);
    defer allocator.free(rlink_inode);
    putBlock(volume, integration_block_size, 51, rlink_inode);

    var symlink_block: [integration_block_size]u8 = [_]u8{0} ** integration_block_size;
    beU32(&symlink_block, 0, symlink_magic);
    beU32(&symlink_block, 4, 0); // sl_offset
    beU32(&symlink_block, 8, rlink_target.len); // sl_bytes
    @memcpy(symlink_block[16..32], &test_fs_uuid);
    beU64(&symlink_block, symlink_owner_offset, 51); // sl_owner == ino
    beU64(&symlink_block, 40, 52); // sl_blkno
    @memcpy(symlink_block[symlink_header_size..][0..rlink_target.len], rlink_target);
    writeCrc(&symlink_block, 12);
    putBlock(volume, integration_block_size, 52, &symlink_block);

    return volume;
}

pub const socket_ag_blocks: u32 = 32;
pub const socket_ag_count: u32 = 1;
pub const socket_data_blocks: u64 = socket_ag_blocks * socket_ag_count;

/// A second, much smaller synthetic volume containing only a root directory
/// and a single socket-mode inode. Unlike ext4.zig -- whose own scan rejects
/// a socket inode before a `GeneralTree` can ever represent one -- this
/// reader classifies `.socket` like any other kind, deferring the "refuse
/// it" decision to a consumer such as `root_tree.zig`. This fixture exists
/// to exercise exactly that consumer-side rejection.
pub fn buildSocketVolume(allocator: std.mem.Allocator) ![]u8 {
    const volume = try buildVolume(allocator, socket_data_blocks, integration_block_size);
    errdefer allocator.free(volume);

    const sb = buildTestSuperblock(.{
        .block_size = integration_block_size,
        .sector_size = integration_block_size,
        .inode_size = integration_block_size,
        .ag_blocks = socket_ag_blocks,
        .ag_count = socket_ag_count,
        .data_blocks = socket_data_blocks,
        .root_ino = 2,
    });
    putBlock(volume, integration_block_size, 0, &sb);

    var root_dir = ShortformDirBuilder.init(2);
    root_dir.append("sock", 3, dir_ft_sock);
    const root_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 2,
        .mode = s_ifdir | 0o755,
        .nlink = 2,
        .data_format = fmt_local,
    }, root_dir.finish());
    defer allocator.free(root_inode);
    putBlock(volume, integration_block_size, 2, root_inode);

    const sock_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 3,
        .mode = s_ifsock | 0o755,
    }, "");
    defer allocator.free(sock_inode);
    putBlock(volume, integration_block_size, 3, sock_inode);

    return volume;
}

pub const etc_os_release_ag_blocks: u32 = 16;
pub const etc_os_release_ag_count: u32 = 1;
pub const etc_os_release_data_blocks: u64 = etc_os_release_ag_blocks * etc_os_release_ag_count;
/// Volume label baked into `buildEtcOsReleaseVolume`, exposed so a caller
/// asserting an XFS source's identity survived a capture/mount has a known
/// value to check against, the way `test_fs_uuid` already lets it check the
/// UUID.
pub const etc_os_release_label: [12]u8 = .{ 'c', 'a', 'p', 'r', 'o', 'o', 't', 0, 0, 0, 0, 0 };

/// A third, minimal synthetic volume: just a root directory holding `/etc`,
/// which in turn holds `/etc/os-release` with the given `content`. Exposed
/// (like `buildIntegrationVolume` and `buildSocketVolume`) so `capture.zig`'s
/// root-discovery tests and `cosi.zig`'s `/etc/os-release` extraction tests
/// can each prove their XFS path against a genuine `/etc` without either
/// needing `mkfs.xfs` or hand-rolling their own on-disk bytes.
pub fn buildEtcOsReleaseVolume(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    std.debug.assert(content.len <= integration_block_size);
    const volume = try buildVolume(allocator, etc_os_release_data_blocks, integration_block_size);
    errdefer allocator.free(volume);

    const sb = buildTestSuperblock(.{
        .block_size = integration_block_size,
        .sector_size = integration_block_size,
        .inode_size = integration_block_size,
        .ag_blocks = etc_os_release_ag_blocks,
        .ag_count = etc_os_release_ag_count,
        .data_blocks = etc_os_release_data_blocks,
        .root_ino = 2,
        .label = etc_os_release_label,
    });
    putBlock(volume, integration_block_size, 0, &sb);

    // root (ino 2): shortform directory -> etc
    var root_dir = ShortformDirBuilder.init(2);
    root_dir.append("etc", 3, dir_ft_dir);
    const root_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 2,
        .mode = s_ifdir | 0o755,
        .nlink = 3,
        .data_format = fmt_local,
    }, root_dir.finish());
    defer allocator.free(root_inode);
    putBlock(volume, integration_block_size, 2, root_inode);

    // etc (ino 3): shortform directory -> os-release
    var etc_dir = ShortformDirBuilder.init(2);
    etc_dir.append("os-release", 4, dir_ft_reg_file);
    const etc_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 3,
        .mode = s_ifdir | 0o755,
        .nlink = 2,
        .data_format = fmt_local,
    }, etc_dir.finish());
    defer allocator.free(etc_inode);
    putBlock(volume, integration_block_size, 3, etc_inode);

    // os-release (ino 4): EXTENTS regular file, content at block 10
    var extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&extent, 0, 10, 1, false);
    const os_release_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 4,
        .mode = s_ifreg | 0o644,
        .size = content.len,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &extent);
    defer allocator.free(os_release_inode);
    putBlock(volume, integration_block_size, 4, os_release_inode);
    putBlock(volume, integration_block_size, 10, content);

    return volume;
}

test "the reader scans a hand-built XFS v5 filesystem across two allocation groups" {
    const allocator = testing.allocator;
    const volume = try buildIntegrationVolume(allocator);
    defer allocator.free(volume);
    try writeFixture(integration_fixture_path, volume);
    defer Io.Dir.cwd().deleteFile(std.testing.io, integration_fixture_path) catch {};

    const io = std.testing.io;
    var reader = try Reader.openPath(allocator, io, integration_fixture_path);
    defer reader.close(io);

    try testing.expectEqualSlices(u8, &test_fs_uuid, &reader.superblock.uuid);
    try testing.expectEqual(@as(u32, 2), reader.superblock.ag_count);

    var tree = try scanReadable(&reader, io, allocator, .{
        .available_length = integration_data_blocks * integration_block_size,
    });
    defer tree.deinit();

    try testing.expectEqualSlices(u8, &test_fs_uuid, &tree.identity.uuid);
    try testing.expectEqual(
        integration_data_blocks * integration_block_size,
        tree.identity.filesystem_length,
    );

    // file.txt: flat EXTENTS content.
    const file_txt = findEntry(&tree, "file.txt").?;
    try testing.expectEqual(Kind.file, file_txt.kind);
    try testing.expectEqual(@as(u16, 0o644), file_txt.mode);
    const file_txt_bytes = try readEntryAlloc(allocator, file_txt);
    defer allocator.free(file_txt_bytes);
    try testing.expectEqualStrings(file_txt_content, file_txt_bytes);

    // link: inline LOCAL symlink.
    const link = findEntry(&tree, "link").?;
    try testing.expectEqual(Kind.symlink, link.kind);
    const link_target = try readEntryAlloc(allocator, link);
    defer allocator.free(link_target);
    try testing.expectEqualStrings("file.txt", link_target);

    // dev: character device, major/minor decoded.
    const dev = findEntry(&tree, "dev").?;
    try testing.expectEqual(Kind.char_device, dev.kind);
    try testing.expectEqual(@as(u32, 1), dev.device.major);
    try testing.expectEqual(@as(u32, 3), dev.device.minor);

    // hardlinked / sub/hardlinked2: same inode, two names, one physical
    // content read, second visit surfaces as `.hardlink`.
    const hardlinked = findEntry(&tree, "hardlinked").?;
    try testing.expectEqual(Kind.file, hardlinked.kind);
    const hardlinked_bytes = try readEntryAlloc(allocator, hardlinked);
    defer allocator.free(hardlinked_bytes);
    try testing.expectEqualStrings(hardlinked_content, hardlinked_bytes);

    const alias = findEntry(&tree, "sub/hardlinked2").?;
    try testing.expectEqual(Kind.hardlink, alias.kind);
    try testing.expectEqualStrings("hardlinked", alias.hardlink_target);
    try testing.expectEqual(@as(?ContentReader, null), alias.content);

    // attrs.txt: EXTENTS content plus a populated shortform xattr fork.
    const attrs_txt = findEntry(&tree, "attrs.txt").?;
    const attrs_txt_bytes = try readEntryAlloc(allocator, attrs_txt);
    defer allocator.free(attrs_txt_bytes);
    try testing.expectEqualStrings(attrs_txt_content, attrs_txt_bytes);
    try expectXattr(attrs_txt, "user.foo", "bar");
    try expectXattr(attrs_txt, "trusted.baz", "qux");

    // sub: nested single-block "block" format directory (proves AG1
    // addressing works: ino 40 lives in the second allocation group).
    try testing.expectEqual(Kind.directory, findEntry(&tree, "sub").?.kind);

    // sub/in_sub.txt: one real extent followed by a hole.
    const in_sub = findEntry(&tree, "sub/in_sub.txt").?;
    const in_sub_bytes = try readEntryAlloc(allocator, in_sub);
    defer allocator.free(in_sub_bytes);
    try testing.expectEqualStrings(in_sub_txt_content, in_sub_bytes[0..in_sub_txt_content.len]);
    for (in_sub_bytes[integration_block_size..]) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }

    // big.bin: FMT_BTREE, single leaf level, two extents.
    const big_bin = findEntry(&tree, "big.bin").?;
    const big_bin_bytes = try readEntryAlloc(allocator, big_bin);
    defer allocator.free(big_bin_bytes);
    try testing.expectEqualSlices(u8, &big_bin_block0, big_bin_bytes[0..integration_block_size]);
    try testing.expectEqualSlices(u8, &big_bin_block1, big_bin_bytes[integration_block_size..]);

    // rlink: remote EXTENTS symlink (header + CRC + owner all validated).
    const rlink = findEntry(&tree, "rlink").?;
    try testing.expectEqual(Kind.symlink, rlink.kind);
    const rlink_bytes = try readEntryAlloc(allocator, rlink);
    defer allocator.free(rlink_bytes);
    try testing.expectEqualStrings(rlink_target, rlink_bytes);

    // unwritten.bin: sole extent is unwritten (allocated, never written),
    // distinct from in_sub.txt's genuine hole (no extent record at all).
    // Both read back as zeros, but only this one has a real, non-zero block
    // sitting behind the mapping -- proving the zero-fill comes from the
    // unwritten flag and not from the backing block happening to be zero.
    const unwritten_bin = findEntry(&tree, "unwritten.bin").?;
    try testing.expectEqual(Kind.file, unwritten_bin.kind);
    const unwritten_bin_bytes = try readEntryAlloc(allocator, unwritten_bin);
    defer allocator.free(unwritten_bin_bytes);
    for (unwritten_bin_bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);

    // The hardlinked inode's bytes are billed once, not once per name.
    try testing.expectEqual(
        @as(u64, file_txt_content.len + "file.txt".len + hardlinked_content.len +
            attrs_txt_content.len + in_sub_txt_size + 2 * integration_block_size + rlink_target.len +
            unwritten_bin_size),
        tree.content_bytes,
    );
}

test "scan rejects a duplicate directory entry name" {
    const allocator = testing.allocator;
    const volume = try buildVolume(allocator, integration_data_blocks, integration_block_size);
    defer allocator.free(volume);

    const sb = buildTestSuperblock(.{
        .block_size = integration_block_size,
        .sector_size = integration_block_size,
        .inode_size = integration_block_size,
        .ag_blocks = integration_ag_blocks,
        .ag_count = integration_ag_count,
        .data_blocks = integration_data_blocks,
        .root_ino = 2,
    });
    putBlock(volume, integration_block_size, 0, &sb);

    var root_dir = ShortformDirBuilder.init(2);
    root_dir.append("dup", 3, dir_ft_reg_file);
    root_dir.append("dup", 4, dir_ft_reg_file);
    const root_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 2,
        .mode = s_ifdir | 0o755,
        .nlink = 2,
        .data_format = fmt_local,
    }, root_dir.finish());
    defer allocator.free(root_inode);
    putBlock(volume, integration_block_size, 2, root_inode);

    const path = "test-xfs-dup-entry.img";
    try writeFixture(path, volume);
    defer Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    const io = std.testing.io;
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try testing.expectError(error.DuplicateDirectoryEntry, scanReadable(&reader, io, allocator, .{
        .available_length = integration_data_blocks * integration_block_size,
    }));
}

test "scan rejects a directory entry whose ftype disagrees with the real inode kind" {
    const allocator = testing.allocator;
    const volume = try buildVolume(allocator, integration_data_blocks, integration_block_size);
    defer allocator.free(volume);

    const sb = buildTestSuperblock(.{
        .block_size = integration_block_size,
        .sector_size = integration_block_size,
        .inode_size = integration_block_size,
        .ag_blocks = integration_ag_blocks,
        .ag_count = integration_ag_count,
        .data_blocks = integration_data_blocks,
        .root_ino = 2,
    });
    putBlock(volume, integration_block_size, 0, &sb);

    var root_dir = ShortformDirBuilder.init(2);
    // The directory entry claims ino 3 is a directory, but ino 3 is really
    // a regular file: the reader must catch this even though it only
    // discovers the mismatch after reading the real inode.
    root_dir.append("badtype", 3, dir_ft_dir);
    const root_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 2,
        .mode = s_ifdir | 0o755,
        .nlink = 2,
        .data_format = fmt_local,
    }, root_dir.finish());
    defer allocator.free(root_inode);
    putBlock(volume, integration_block_size, 2, root_inode);

    var extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&extent, 0, 20, 1, false);
    const regular_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 3,
        .mode = s_ifreg | 0o644,
        .size = 4,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &extent);
    defer allocator.free(regular_inode);
    putBlock(volume, integration_block_size, 3, regular_inode);
    putBlock(volume, integration_block_size, 20, "data");

    const path = "test-xfs-ftype-mismatch.img";
    try writeFixture(path, volume);
    defer Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    const io = std.testing.io;
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try testing.expectError(error.DirectoryFileTypeMismatch, scanReadable(&reader, io, allocator, .{
        .available_length = integration_data_blocks * integration_block_size,
    }));
}

test "scan rejects a directory cycle" {
    const allocator = testing.allocator;
    const volume = try buildVolume(allocator, integration_data_blocks, integration_block_size);
    defer allocator.free(volume);

    const sb = buildTestSuperblock(.{
        .block_size = integration_block_size,
        .sector_size = integration_block_size,
        .inode_size = integration_block_size,
        .ag_blocks = integration_ag_blocks,
        .ag_count = integration_ag_count,
        .data_blocks = integration_data_blocks,
        .root_ino = 2,
    });
    putBlock(volume, integration_block_size, 0, &sb);

    var root_dir = ShortformDirBuilder.init(2);
    root_dir.append("loop", 8, dir_ft_dir);
    const root_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 2,
        .mode = s_ifdir | 0o755,
        .nlink = 3,
        .data_format = fmt_local,
    }, root_dir.finish());
    defer allocator.free(root_inode);
    putBlock(volume, integration_block_size, 2, root_inode);

    // "loop" (ino 8) is a real single-block "block" format directory whose
    // own entries point straight back at the already-visited root ino.
    var loop_dir = BlockFormatDirBuilder{};
    loop_dir.appendEntry(8, ".", dir_ft_dir);
    loop_dir.appendEntry(2, "..", dir_ft_dir);
    loop_dir.appendEntry(2, "back", dir_ft_dir);
    const loop_dir_block = loop_dir.finish(8);
    putBlock(volume, integration_block_size, 9, loop_dir_block);
    var loop_extent: [bmbt_rec_size]u8 = undefined;
    encodeBmbtRec(&loop_extent, 0, 9, 1, false);
    const loop_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 8,
        .mode = s_ifdir | 0o755,
        .nlink = 2,
        .data_format = fmt_extents,
        .nextents = 1,
    }, &loop_extent);
    defer allocator.free(loop_inode);
    putBlock(volume, integration_block_size, 8, loop_inode);

    const path = "test-xfs-directory-cycle.img";
    try writeFixture(path, volume);
    defer Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    const io = std.testing.io;
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try testing.expectError(error.DirectoryCycle, scanReadable(&reader, io, allocator, .{
        .available_length = integration_data_blocks * integration_block_size,
    }));
}

test "readExtents walks a non-full, three-level BTREE chain using maxrecs-based pointer offsets" {
    // Regression for a bug where both the inode-rooted bmdr root and the
    // on-disk long-form btree "node" level addressed their pointer arrays
    // right after `numrecs` keys instead of after the full `maxrecs`-sized
    // key array (`xfs_bmdr_ptr_addr`/`xfs_bmbt_ptr_addr`). Every level here
    // is deliberately non-full (numrecs == 1, well under each level's real
    // maxrecs) so a numrecs-based offset would read the pointer from bytes
    // that are still (zeroed) key/padding space, not the byte-4 image below.
    const allocator = testing.allocator;
    const volume = try buildVolume(allocator, integration_data_blocks, integration_block_size);
    defer allocator.free(volume);

    const sb = buildTestSuperblock(.{
        .block_size = integration_block_size,
        .sector_size = integration_block_size,
        .inode_size = integration_block_size,
        .ag_blocks = integration_ag_blocks,
        .ag_count = integration_ag_count,
        .data_blocks = integration_data_blocks,
        .root_ino = 2,
    });
    putBlock(volume, integration_block_size, 0, &sb);

    var root_dir = ShortformDirBuilder.init(2);
    root_dir.append("big.bin", 3, dir_ft_reg_file);
    const root_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 2,
        .mode = s_ifdir | 0o755,
        .nlink = 2,
        .data_format = fmt_local,
    }, root_dir.finish());
    defer allocator.free(root_inode);
    putBlock(volume, integration_block_size, 2, root_inode);

    // Level 2: the inode-rooted bmdr root. Its key/ptr arrays are sized for
    // `maxrecs` (however many (key,ptr) pairs fit in the whole literal
    // area), not `numrecs` -- so the single real pointer must sit at the
    // maxrecs-based offset, with only zeroed key/padding bytes before it.
    const literal_area_len = integration_block_size - dinode_v3_core_size;
    const root_maxrecs = (literal_area_len - bmdr_header_size) / (bmbt_key_size + bmbt_ptr_size);
    const root_ptr_offset = bmdr_header_size + root_maxrecs * bmbt_key_size;
    var root_literal: [root_ptr_offset + 8]u8 = [_]u8{0} ** (root_ptr_offset + 8);
    beU16(&root_literal, 0, 2); // level: 2 (root -> internal node -> leaf)
    beU16(&root_literal, 2, 1); // numrecs: 1, far below root_maxrecs
    beU64(&root_literal, root_ptr_offset, 10); // ptr: internal node at fsblock 10
    const big_bin_inode = try buildTestInode(allocator, integration_block_size, .{
        .ino = 3,
        .mode = s_ifreg | 0o644,
        .size = 2 * integration_block_size,
        .data_format = fmt_btree,
        .nextents = 2,
    }, &root_literal);
    defer allocator.free(big_bin_inode);
    putBlock(volume, integration_block_size, 3, big_bin_inode);

    // Level 1: an on-disk long-form "node" block (not the root). Its key/ptr
    // arrays are likewise sized for the block's own maxrecs, computed from
    // the whole block length, not from this block's numrecs=1.
    const node_body_len = integration_block_size - bmbt_long_header_size;
    const node_maxrecs = node_body_len / (bmbt_key_size + bmbt_ptr_size);
    const node_ptr_offset = bmbt_long_header_size + node_maxrecs * bmbt_key_size;
    var node: [integration_block_size]u8 = [_]u8{0} ** integration_block_size;
    beU32(&node, 0, bmap_btree_magic);
    beU16(&node, 4, 1); // level 1 (internal node, one above the leaf)
    beU16(&node, 6, 1); // numrecs: 1, far below node_maxrecs
    beU64(&node, bmbt_long_owner_offset, 3); // bb_owner == ino
    beU64(&node, node_ptr_offset, 11); // ptr: leaf block at fsblock 11
    writeCrc(&node, bmbt_long_crc_offset);
    putBlock(volume, integration_block_size, 10, &node);

    // Level 0: the leaf, holding the two real extent records.
    var leaf: [integration_block_size]u8 = [_]u8{0} ** integration_block_size;
    beU32(&leaf, 0, bmap_btree_magic);
    beU16(&leaf, 4, 0); // level 0 (leaf)
    beU16(&leaf, 6, 2); // numrecs
    beU64(&leaf, bmbt_long_owner_offset, 3); // bb_owner == ino
    encodeBmbtRec(leaf[bmbt_long_header_size..][0..bmbt_rec_size], 0, 20, 1, false);
    encodeBmbtRec(leaf[bmbt_long_header_size + bmbt_rec_size ..][0..bmbt_rec_size], 1, 21, 1, false);
    writeCrc(&leaf, bmbt_long_crc_offset);
    putBlock(volume, integration_block_size, 11, &leaf);

    const block0 = [_]u8{'A'} ** integration_block_size;
    const block1 = [_]u8{'B'} ** integration_block_size;
    putBlock(volume, integration_block_size, 20, &block0);
    putBlock(volume, integration_block_size, 21, &block1);

    const path = "test-xfs-btree-non-full-multilevel.img";
    try writeFixture(path, volume);
    defer Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    const io = std.testing.io;
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    var tree = try scanReadable(&reader, io, allocator, .{
        .available_length = integration_data_blocks * integration_block_size,
    });
    defer tree.deinit();

    const big_bin = findEntry(&tree, "big.bin").?;
    const big_bin_bytes = try readEntryAlloc(allocator, big_bin);
    defer allocator.free(big_bin_bytes);
    try testing.expectEqualSlices(u8, &block0, big_bin_bytes[0..integration_block_size]);
    try testing.expectEqualSlices(u8, &block1, big_bin_bytes[integration_block_size..]);
}

test "readExtents rejects a BTREE root whose numrecs exceeds its maxrecs capacity" {
    const allocator = testing.allocator;
    const sb = try testSuperblock();
    var reader: Reader = .{ .allocator = allocator, .file = undefined, .superblock = sb };
    const literal_area_len = integration_block_size - dinode_v3_core_size;
    const root_maxrecs = (literal_area_len - bmdr_header_size) / (bmbt_key_size + bmbt_ptr_size);
    var root_literal: [literal_area_len]u8 = [_]u8{0} ** literal_area_len;
    beU16(&root_literal, 0, 1); // level
    beU16(&root_literal, 2, @intCast(root_maxrecs + 1)); // numrecs > maxrecs: must be rejected
    try testing.expectError(error.UnsupportedExtentLayout, readExtents(
        &reader,
        std.testing.io,
        allocator,
        3,
        fmt_btree,
        1,
        &root_literal,
    ));
}

test "Reader.statPath finds /etc without a full tree scan" {
    const allocator = testing.allocator;
    const os_release = "NAME=zvmi\nID=zvmi\n";
    const volume = try buildEtcOsReleaseVolume(allocator, os_release);
    defer allocator.free(volume);

    const path = "test-xfs-stat-path.img";
    try writeFixture(path, volume);
    defer Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    const io = std.testing.io;
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    const root_stat = try reader.statPath(io, "/");
    try testing.expectEqual(Kind.directory, root_stat.kind);

    const etc_stat = try reader.statPath(io, "/etc");
    try testing.expectEqual(Kind.directory, etc_stat.kind);

    const os_release_stat = try reader.statPath(io, "etc/os-release");
    try testing.expectEqual(Kind.file, os_release_stat.kind);
    try testing.expectEqual(@as(u64, os_release.len), os_release_stat.size);

    try testing.expectError(error.NotFound, reader.statPath(io, "/etc/missing"));
    try testing.expectError(error.NotFound, reader.statPath(io, "/missing"));
    try testing.expectError(error.NotDirectory, reader.statPath(io, "/etc/os-release/nope"));
}

test "Reader.readFileAlloc reads /etc/os-release without a full tree scan" {
    const allocator = testing.allocator;
    const os_release = "NAME=zvmi\nID=zvmi\nVERSION_ID=1\n";
    const volume = try buildEtcOsReleaseVolume(allocator, os_release);
    defer allocator.free(volume);

    const path = "test-xfs-read-file-alloc.img";
    try writeFixture(path, volume);
    defer Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    const io = std.testing.io;
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    const bytes = try reader.readFileAlloc(io, allocator, "etc/os-release");
    defer allocator.free(bytes);
    try testing.expectEqualStrings(os_release, bytes);

    try testing.expectError(error.NotFile, reader.readFileAlloc(io, allocator, "/etc"));
    try testing.expectError(error.NotFound, reader.readFileAlloc(io, allocator, "/etc/missing"));
}
