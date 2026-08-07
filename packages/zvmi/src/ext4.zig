//! Native ext4 writer + readback helper for image building.
//!
//! Feature flags intentionally stay within a conservative, fsck-friendly
//! subset:
//!   - `feature_compat = EXT_ATTR | DIR_INDEX`, plus `HAS_JOURNAL` when a
//!     journal is asked for: external xattr blocks are supported, and
//!     directories that outgrow a single leaf block are written with ext4
//!     htree indexes, including interior index nodes when a single root index
//!     block is no longer enough. `RESIZE_INODE` and the quota bits remain
//!     permanently unset.
//!
//!     The journal is opt-in and off by default. Nothing needs one while the
//!     image is being built -- the filesystem is created offline and written
//!     atomically, so there is no partially applied metadata update for a log
//!     to protect. That stops being the whole story the moment the image
//!     becomes a running machine's mutable root filesystem: from first boot
//!     onward an unclean shutdown leaves a journal-less volume with no
//!     recovery log, so the next boot faces a full `fsck` rather than a fast
//!     replay. `PopulateOptions.journal` therefore allocates the reserved
//!     journal inode (8) with a JBD2 superblock sized on `mke2fs`'s own
//!     ladder. It stays off by default because every existing build path
//!     produces purpose-built images that chose journal-less output
//!     deliberately, and because a journalled image is a different profile:
//!     `scanWriterCompatible` refuses it, so only the general importer can
//!     read one back.
//!   - `feature_incompat = FILETYPE | EXTENTS`: directory entries carry the
//!     ext4 file-type byte, and regular-file / directory payloads are mapped
//!     with extents.
//!   - `feature_ro_compat = SPARSE_SUPER | METADATA_CSUM | EXTRA_ISIZE` (plus
//!     `LARGE_FILE` only when a file exceeds 2 GiB): sparse backup
//!     superblocks/group-descriptor tables are written for groups selected by
//!     ext4's classic sparse-super rule, and metadata-bearing structures are
//!     checksummed with crc32c.
//!   - 256-byte inodes, as `mke2fs` has written by default since 2008. The
//!     classic 128-byte inode stops at `i_osd2`, which leaves nowhere for
//!     `i_extra_isize` and therefore no creation time and -- the part that
//!     silently corrupts data rather than merely losing it -- no epoch bits.
//!     Without those the seconds field is a bare signed 32-bit count that
//!     wraps in 2038, so a 2049 timestamp reads back as 1913. 128-byte inodes
//!     are still read, resized and edited; they are just never written.
//!
//! Deliberate phase-2 non-goals: no journal replay or log writing (a journal
//! this writer creates is always empty, so there is nothing to replay) and no
//! quota files. Extents stay inline for small files, but larger fragmented
//! files now spill into standard ext4 extent/index blocks with recursive
//! readback support. With 4 KiB blocks this writer supports extent-tree depths
//! up to 4, which is enough to cover the filesystem's 32-bit logical-block
//! space. Resizing is supported as an offline, in-place grow operation that
//! rewrites the superblock/GDTs and initializes new block groups without
//! enabling ext4's separate `RESIZE_INODE` online-resize scaffolding.

const std = @import("std");
const limits_mod = @import("limits.zig");
const Io = std.Io;

/// The scan shares the importer's limit defaults so a source that scans is a
/// source that imports.
const limit_defaults = limits_mod.ImportLimits{};

pub const default_block_size: u32 = 4096;
pub const default_blocks_per_group: u32 = 32 * 1024;
pub const root_inode: u32 = 2;
/// `EXT4_JOURNAL_INO`. It sits inside the 1..10 reserved range, so allocating
/// it costs no inode the tree could otherwise have used.
pub const journal_inode: u32 = 8;
pub const first_non_reserved_inode: u32 = 11;

/// The inode size this writer emits. `mke2fs` has defaulted to 256 since
/// e2fsprogs 1.41 (2008). The classic 128-byte inode ends at `i_osd2` and so
/// has nowhere to put `i_extra_isize`, which is what carries creation time,
/// nanosecond resolution, and -- the reason this matters most -- the two
/// epoch bits without which no timestamp past 2038 can be represented.
///
/// This is a constant rather than a parameter on purpose, and the trade is
/// recorded in `doc/image-building.md` beside the strict-profile discussion:
/// a writer that could also emit 128-byte inodes would make the range of
/// representable timestamps a property of the source it was handed rather
/// than of the writer, which is what `root_tree.validateExt4Time` relies on
/// not being true. An image an older zvmi wrote with 128-byte inodes is
/// therefore read under `ext4_general_v1` and migrates by being rebuilt once.
const writer_inode_size: u16 = 256;
/// The classic ext2 inode. Still read, never written.
const min_supported_reader_inode_size: u16 = 128;
const max_supported_reader_inode_size: u16 = 256;
/// `i_extra_isize`: how many bytes past the classic 128 this writer fills in.
/// 32 reaches the end of `i_projid`, which is what `mke2fs` also writes.
const writer_extra_isize: u16 = 32;
const group_desc_size: u16 = 32;
const max_inline_extents: usize = 4;
const max_supported_extent_depth: u16 = 4;
const superblock_size: usize = 1024;
const superblock_offset: u64 = 1024;
const dir_entry_alignment: usize = 4;
const sectors_per_block: u32 = default_block_size / 512;
const extent_header_size: usize = 12;
const extent_entry_size: usize = 12;
const extent_tail_size: usize = 4;

const super_magic: u16 = 0xEF53;
const state_clean: u16 = 0x0001;
const errors_continue: u16 = 0x0001;
const creator_os_linux: u32 = 0;
const rev_dynamic: u32 = 1;

const feature_compat_dir_prealloc: u32 = 0x0001;
const feature_compat_imagic_inodes: u32 = 0x0002;
const feature_compat_has_journal: u32 = 0x0004;
const feature_compat_ext_attr: u32 = 0x0008;
const feature_compat_resize_inode: u32 = 0x0010;
const feature_compat_dir_index: u32 = 0x0020;
const feature_compat_sparse_super2: u32 = 0x0200;
const feature_compat_fast_commit: u32 = 0x0400;
const feature_compat_stable_inodes: u32 = 0x0800;
const feature_compat_orphan_file: u32 = 0x1000;
const feature_incompat_compression: u32 = 0x0001;
const feature_incompat_filetype: u32 = 0x0002;
const feature_incompat_recover: u32 = 0x0004;
const feature_incompat_journal_dev: u32 = 0x0008;
const feature_incompat_meta_bg: u32 = 0x0010;
const feature_incompat_extents: u32 = 0x0040;
const feature_incompat_64bit: u32 = 0x0080;
const feature_incompat_mmp: u32 = 0x0100;
const feature_incompat_flex_bg: u32 = 0x0200;
const feature_incompat_ea_inode: u32 = 0x0400;
const feature_incompat_dirdata: u32 = 0x1000;
const feature_incompat_csum_seed: u32 = 0x2000;
const feature_incompat_largedir: u32 = 0x4000;
const feature_incompat_inline_data: u32 = 0x8000;
const feature_incompat_encrypt: u32 = 0x0001_0000;
const feature_incompat_casefold: u32 = 0x0002_0000;
const feature_ro_compat_sparse_super: u32 = 0x0001;
const feature_ro_compat_large_file: u32 = 0x0002;
const feature_ro_compat_btree_dir: u32 = 0x0004;
const feature_ro_compat_huge_file: u32 = 0x0008;
const feature_ro_compat_gdt_csum: u32 = 0x0010;
const feature_ro_compat_dir_nlink: u32 = 0x0020;
const feature_ro_compat_extra_isize: u32 = 0x0040;
const feature_ro_compat_has_snapshot: u32 = 0x0080;
const feature_ro_compat_quota: u32 = 0x0100;
const feature_ro_compat_bigalloc: u32 = 0x0200;
const feature_ro_compat_metadata_csum: u32 = 0x0400;
const feature_ro_compat_replica: u32 = 0x0800;
const feature_ro_compat_readonly: u32 = 0x1000;
const feature_ro_compat_project: u32 = 0x2000;
const feature_ro_compat_shared_blocks: u32 = 0x4000;
const feature_ro_compat_verity: u32 = 0x8000;
const feature_ro_compat_orphan_present: u32 = 0x0001_0000;
const writer_feature_compat: u32 = feature_compat_ext_attr | feature_compat_dir_index;
const writer_feature_incompat: u32 = feature_incompat_filetype | feature_incompat_extents;
/// Always set by this writer. `EXTRA_ISIZE` asserts that every inode has at
/// least `s_min_extra_isize` bytes past the classic 128 already filled in,
/// which is exactly what `writeInodes` guarantees.
const writer_feature_ro_compat_base: u32 = feature_ro_compat_sparse_super | feature_ro_compat_metadata_csum | feature_ro_compat_extra_isize;
/// Allowed on a filesystem this module reads back, but conditional on its
/// contents rather than always present.
const writer_feature_ro_compat_optional: u32 = feature_ro_compat_large_file;
const reader_feature_compat: u32 = writer_feature_compat | feature_compat_has_journal | feature_compat_resize_inode | feature_compat_orphan_file;
const reader_feature_incompat: u32 = writer_feature_incompat | feature_incompat_64bit | feature_incompat_flex_bg | feature_incompat_csum_seed;
const reader_feature_ro_compat: u32 = writer_feature_ro_compat_base | feature_ro_compat_large_file | feature_ro_compat_huge_file | feature_ro_compat_dir_nlink | feature_ro_compat_extra_isize;

/// Every inode size between the classic 128 and the 256 this writer emits,
/// as a power of two. Images written by an older zvmi -- and by `mke2fs -I
/// 128` -- still have to be readable, resizable and editable.
fn supportedInodeSize(value: u16) bool {
    return value >= min_supported_reader_inode_size and
        value <= max_supported_reader_inode_size and
        std.math.isPowerOfTwo(value);
}

const inode_flag_encrypt: u32 = 0x0000_0800;
const inode_flag_index: u32 = 0x0000_1000;
const inode_flag_extents: u32 = 0x0008_0000;
const inode_flag_verity: u32 = 0x0010_0000;
const inode_flag_ea_inode: u32 = 0x0020_0000;
const inode_flag_inline_data: u32 = 0x1000_0000;

const mode_fifo: u16 = 0o010000;
const mode_char_device: u16 = 0o020000;
const mode_dir: u16 = 0o040000;
const mode_block_device: u16 = 0o060000;
const mode_reg: u16 = 0o100000;
const mode_symlink: u16 = 0o120000;
const mode_socket: u16 = 0o140000;

const dir_ft_unknown: u8 = 0;
const dir_ft_reg: u8 = 1;
const dir_ft_dir: u8 = 2;
const dir_ft_char_device: u8 = 3;
const dir_ft_block_device: u8 = 4;
const dir_ft_fifo: u8 = 5;
const dir_ft_socket: u8 = 6;
const dir_ft_symlink: u8 = 7;
const dir_ft_checksum: u8 = 0xDE;

const extent_magic: u16 = 0xF30A;
const ext4_xattr_magic: u32 = 0xEA02_0000;

// JBD2 on-disk constants. The journal superblock is big-endian throughout,
// unlike every other structure this module writes.
const jbd2_magic: u32 = 0xC03B_3998;
const jbd2_superblock_v2: u32 = 4;
/// `JBD2_MIN_JOURNAL_BLOCKS`, and `mke2fs`'s own floor for an explicit size.
const jbd2_min_journal_blocks: u32 = 1024;
/// `mke2fs`'s own ceiling for an explicit `-J size=`.
const jbd2_max_journal_blocks: u32 = 10_240_000;
/// A filesystem smaller than this has nowhere sensible to put the 1024-block
/// JBD2 minimum, which is why `mke2fs` refuses one too.
const min_journalled_filesystem_blocks: u32 = 2048;
/// `mke2fs` writes the journal inode with these bits and nothing else.
const journal_inode_mode: u16 = 0o600;
/// `EXT3_JNL_BACKUP_BLOCKS`: `s_jnl_blocks` holds the journal inode's
/// `i_block` array plus its size, so `e2fsck` can find the log even if the
/// inode itself is unreadable.
const jnl_backup_type_blocks: u8 = 1;
const dx_hash_half_md4: u8 = 0x1;
const super_checksum_type_crc32c: u8 = 0x1;
const xattr_name_user: u8 = 1;
const xattr_name_posix_acl_access: u8 = 2;
const xattr_name_posix_acl_default: u8 = 3;
const xattr_name_trusted: u8 = 4;
const xattr_name_security: u8 = 6;
const xattr_name_system: u8 = 7;

pub const Kind = enum(u8) {
    directory,
    file,
    symlink,
    /// A second name for a `file` entry's inode, named by `hardlink_target`.
    hardlink,
    block_device,
    char_device,
    fifo,
};

/// Whether the written filesystem carries a JBD2 journal, and how large.
///
/// `enabled` is false by default and that default is load-bearing: every
/// caller that predates this option builds an image whose filesystem is
/// written once, offline and atomically, and flipping the default would
/// change the bytes of all of them. Turn it on for an image that becomes a
/// running machine's mutable root filesystem, where an unclean shutdown
/// otherwise leaves no recovery log behind.
pub const JournalOptions = struct {
    enabled: bool = false,
    /// Journal size in bytes, which must be a whole number of blocks. Null
    /// selects `defaultJournalBlocks`, which is `mke2fs`'s own ladder. An
    /// explicit size is accepted between 1024 and 10,240,000 blocks and up to
    /// half the filesystem, matching `mke2fs -J size=`.
    size_bytes: ?u64 = null,
};

/// `mke2fs`'s default journal size in filesystem blocks, reproducing
/// e2fsprogs 1.47's `ext2fs_default_journal_size` ladder exactly. Null means
/// the filesystem is too small to carry a journal at all.
///
/// With 4 KiB blocks that is 4 MiB below 128 MiB, 16 MiB below 1 GiB, 32 MiB
/// below 2 GiB, 64 MiB below 16 GiB, and so on up to 1 GiB of journal.
pub fn defaultJournalBlocks(total_blocks: u32) ?u32 {
    if (total_blocks < min_journalled_filesystem_blocks) return null;
    if (total_blocks < 32 * 1024) return 1024;
    if (total_blocks < 256 * 1024) return 4096;
    if (total_blocks < 512 * 1024) return 8192;
    if (total_blocks < 4096 * 1024) return 16384;
    if (total_blocks < 8192 * 1024) return 32768;
    if (total_blocks < 16384 * 1024) return 65536;
    if (total_blocks < 32768 * 1024) return 131072;
    return 262144;
}

pub const PopulateOptions = struct {
    /// Byte offset within `file` where the filesystem starts.
    offset: u64 = 0,
    /// Total filesystem size, in bytes. Must be a multiple of `block_size`.
    length: u64,
    /// Only 4096-byte blocks are currently supported.
    block_size: u32 = default_block_size,
    /// Optional volume label, truncated at 16 bytes.
    label: []const u8 = "",
    /// Extended attributes applied to the implicit root inode.
    root_xattrs: []const Xattr = &.{},
    /// Permission bits of the implicit root inode. Defaulted rather than
    /// derived, because the tree interface has no entry for the root.
    root_mode: u16 = 0o755,
    root_uid: u32 = 0,
    root_gid: u32 = 0,
    /// Root inode times. Null falls back to `timestamp`, which is what every
    /// reproducible caller wants; a general import supplies the source's own.
    root_atime: ?i64 = null,
    root_mtime: ?i64 = null,
    root_ctime: ?i64 = null,
    root_atime_nsec: u32 = 0,
    root_mtime_nsec: u32 = 0,
    root_ctime_nsec: u32 = 0,
    root_crtime: ?i64 = null,
    root_crtime_nsec: u32 = 0,
    /// If omitted, a zero UUID is written.
    uuid: ?[16]u8 = null,
    /// POSIX seconds timestamp written to the superblock/inodes.
    timestamp: u32 = 0,
    /// Journal creation policy. Off by default; see `JournalOptions`.
    journal: JournalOptions = .{},
};

pub const ResizeOptions = struct {
    offset: u64 = 0,
    length: u64,
};

pub const FilesystemInfo = struct {
    block_count: u32,
    free_block_count: u32,
    inode_count: u32,
    free_inode_count: u32,
    group_count: u32,
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    /// Blocks occupied by the journal, or 0 when the filesystem has none.
    journal_block_count: u32 = 0,
};

pub const Stat = struct {
    inode: u32,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
};

pub const Extent = struct {
    logical_block: u32,
    start_block: u64,
    block_count: u16,
};

pub const DirEntry = struct {
    inode: u32,
    kind: Kind,
    name: []u8,
};

pub fn freeDirEntries(allocator: std.mem.Allocator, entries: []DirEntry) void {
    for (entries) |entry| allocator.free(entry.name);
    allocator.free(entries);
}

pub const Xattr = struct {
    name: []const u8,
    value: []const u8,
};

pub const OwnedXattr = struct {
    name: []u8,
    value: []u8,
};

pub fn freeXattrs(allocator: std.mem.Allocator, xattrs: []OwnedXattr) void {
    for (xattrs) |xattr| {
        allocator.free(xattr.name);
        allocator.free(xattr.value);
    }
    allocator.free(xattrs);
}

/// Small, self-contained tree-population interface for future ingestion
/// modules to adapt to. `populate()` resets the view once, consumes every
/// yielded entry, sorts them by path depth/name, and then writes the full
/// filesystem image in one pass. The root directory is implicit; entries must
/// use relative paths like `boot/kernel` rather than `/boot/kernel`.
pub const FileTreeView = struct {
    ctx: *anyopaque,
    next_fn: *const fn (ctx: *anyopaque) IteratorError!?Entry,
    reset_fn: *const fn (ctx: *anyopaque) void,

    pub const IteratorError = error{EnumerationFailed};
    pub const ContentError = error{ ReadFailed, UnexpectedEndOfStream };

    pub const ContentReader = struct {
        ctx: *const anyopaque,
        read_at_fn: *const fn (ctx: *const anyopaque, buffer: []u8, offset: u64) ContentError!usize,

        pub fn readAt(self: ContentReader, buffer: []u8, offset: u64) ContentError!usize {
            return self.read_at_fn(self.ctx, buffer, offset);
        }
    };

    pub const Entry = struct {
        /// Relative UTF-8/byte path using `/` separators, without a leading `/`.
        path: []const u8,
        kind: Kind,
        /// Unix permission/sticky bits only; the file type comes from `kind`.
        mode: u16,
        uid: u32,
        gid: u32,
        /// Regular-file byte length, symlink-target byte length, or 0 for dirs.
        size: u64,
        /// Required for non-empty regular files and symlinks.
        content: ?ContentReader = null,
        /// Optional extended attributes such as `user.*` or `security.*`.
        xattrs: []const Xattr = &.{},
        /// Device numbers, for `block_device` and `char_device` only.
        device: DeviceNumbers = .{},
        /// The already-emitted path whose inode a `hardlink` shares. Copying
        /// the bytes instead would silently break every consumer that relies
        /// on shared identity, from package managers to `rsync -H`.
        hardlink_target: []const u8 = "",
        /// POSIX seconds. Null means "use the image-wide timestamp", which is
        /// what a reproducible build wants; an imported filesystem carrying
        /// real per-file times supplies them so they survive the round trip.
        atime: ?i64 = null,
        mtime: ?i64 = null,
        ctime: ?i64 = null,
        /// Sub-second parts of the three times above, 0..999999999. A source
        /// that stored whole seconds -- or a caller that does not care --
        /// leaves these zero, which is what the writer emitted for every
        /// inode before they existed.
        atime_nsec: u32 = 0,
        mtime_nsec: u32 = 0,
        ctime_nsec: u32 = 0,
        /// The inode's creation time. Null means the source had none to give
        /// -- a 128-byte inode has nowhere to store one -- and the writer
        /// falls back to the image-wide timestamp, which is the honest answer
        /// for a node this build is genuinely creating.
        crtime: ?i64 = null,
        crtime_nsec: u32 = 0,
    };

    pub fn reset(self: *FileTreeView) void {
        self.reset_fn(self.ctx);
    }

    pub fn next(self: *FileTreeView) IteratorError!?Entry {
        return self.next_fn(self.ctx);
    }
};

pub const PopulateError = std.mem.Allocator.Error || Io.File.ReadPositionalError ||
    Io.File.WritePositionalError || Io.File.SetLengthError || Io.File.StatError ||
    FileTreeView.IteratorError || FileTreeView.ContentError || error{
    UnsupportedBlockSize,
    InvalidRange,
    LabelTooLong,
    InvalidPath,
    RootEntryForbidden,
    DuplicatePath,
    MissingParentDirectory,
    ParentNotDirectory,
    MissingContentReader,
    UnexpectedContentLength,
    InvalidDirectorySize,
    MissingHardlinkTarget,
    UnsupportedHardlinkTarget,
    TooManyHardlinks,
    InvalidDeviceEntry,
    TimestampOutOfRange,
    NotEnoughSpace,
    TooManyExtents,
    TooManyInodes,
    FilesystemTooLarge,
    InvalidXattr,
    XattrTooLarge,
    FilesystemTooSmallForJournal,
    JournalSizeTooSmall,
    JournalSizeTooLarge,
    UnalignedJournalSize,
    /// `minimumPopulateLength` kept revising its own answer without settling
    /// on one. Named rather than papered over with a larger guess: the two
    /// things it revises for both converge, so failing to converge means one
    /// of them no longer behaves the way the solver assumes.
    MinimumSizeUnconverged,
};

pub const OpenError = std.mem.Allocator.Error || Io.File.ReadPositionalError || error{
    BadMagic,
    UnsupportedBlockSize,
    UnsupportedDescriptorSize,
    UnsupportedFeatures,
    UnsupportedInodeSize,
    UnsupportedRevision,
    SourceReadFailed,
    UnexpectedEndOfFile,
};

pub const ReadError = std.mem.Allocator.Error || Io.File.ReadPositionalError || error{
    NotFound,
    NotDirectory,
    NotFile,
    NotSymlink,
    BadDirectoryEntry,
    UnsupportedExtentDepth,
    UnsupportedInodeLayout,
    FileTooLarge,
    XattrNotFound,
    SourceReadFailed,
    UnexpectedEndOfFile,
};

pub const ResizeError = PopulateError || OpenError || Io.File.ReadPositionalError || Io.File.WritePositionalError ||
    Io.File.SetLengthError || Io.File.StatError || std.mem.Allocator.Error || error{
    InvalidRange,
    ShrinkNotSupported,
    UnsupportedResizeLayout,
    ResizeInodeNotSupported,
    FilesystemTooLarge,
};

const OwnedEntry = struct {
    path: []u8,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    content: ?FileTreeView.ContentReader,
    xattrs: []OwnedXattr,
    device: DeviceNumbers = .{},
    hardlink_target: []u8 = &.{},
    times: InodeTimes = .{},
};

/// The three times an inode written by this module can carry. On a 256-byte
/// inode each one gets a matching `i_*_extra` word, whose low two bits push
/// the signed 32-bit seconds field forward by whole 2^32-second epochs. That
/// covers 1901-12-13 through 2446-05-10; anything outside it is refused
/// rather than wrapped into a plausible-looking wrong date.
const InodeTimes = struct {
    atime: ?i64 = null,
    mtime: ?i64 = null,
    ctime: ?i64 = null,
    /// The upper 30 bits of each `i_*_extra` word. Zero is both the default
    /// and what every inode this writer emitted before carried, so a caller
    /// that supplies nothing gets byte-identical output.
    atime_nsec: u32 = 0,
    mtime_nsec: u32 = 0,
    ctime_nsec: u32 = 0,
    /// Null means the source had no creation time to preserve, and the
    /// image-wide timestamp is used instead.
    crtime: ?i64 = null,
    crtime_nsec: u32 = 0,

    fn from(entry: FileTreeView.Entry) PopulateError!InodeTimes {
        return .{
            .atime = try checkedTime(entry.atime),
            .mtime = try checkedTime(entry.mtime),
            .ctime = try checkedTime(entry.ctime),
            .atime_nsec = try checkedNanoseconds(entry.atime_nsec),
            .mtime_nsec = try checkedNanoseconds(entry.mtime_nsec),
            .ctime_nsec = try checkedNanoseconds(entry.ctime_nsec),
            .crtime = try checkedTime(entry.crtime),
            .crtime_nsec = try checkedNanoseconds(entry.crtime_nsec),
        };
    }

    fn resolve(self: InodeTimes, fallback: u32) struct { i64, i64, i64 } {
        const default: i64 = fallback;
        return .{
            self.atime orelse default,
            self.ctime orelse default,
            self.mtime orelse default,
        };
    }
};

/// Rejects a timestamp at tree-walk time rather than at inode-write time, so
/// the failure names the entry that carries it.
fn checkedTime(value: ?i64) PopulateError!?i64 {
    const seconds = value orelse return null;
    _ = try encodeInodeTime(seconds);
    return seconds;
}

/// The `i_*_extra` words carry the sub-second part in 30 bits, so a value of
/// a billion or more is not merely out of range -- it would silently overlap
/// the two epoch bits below it and move the timestamp by 136 years.
fn checkedNanoseconds(value: u32) PopulateError!u32 {
    if (value >= 1_000_000_000) return error.TimestampOutOfRange;
    return value;
}

/// Packs an epoch count and a sub-second part into an `i_*_extra` word, which
/// is the two low bits and the thirty above them.
fn encodeInodeExtra(epoch: u32, nanoseconds: u32) u32 {
    return (epoch & 0x3) | (nanoseconds << 2);
}

const EncodedTime = struct {
    /// `i_atime` and friends: the low 32 bits, read back as signed.
    seconds: u32,
    /// The low two bits of the matching `i_*_extra` word.
    epoch: u32,
};

/// 1901-12-13T20:45:52Z: epoch 0 with the seconds field at its most negative.
pub const min_representable_time: i64 = std.math.minInt(i32);
/// 2446-05-10T22:38:55Z: epoch 3 with the seconds field at its most positive.
pub const max_representable_time: i64 = std.math.maxInt(i32) + (3 << 32);

/// The inverse of `decodeInodeTime`. ext4 stores the seconds truncated to 32
/// bits and the discarded high part as an epoch count, so the two together
/// reach 2^34 seconds from 1901 rather than stopping dead in 2038.
fn encodeInodeTime(value: i64) PopulateError!EncodedTime {
    if (value < min_representable_time or value > max_representable_time) {
        return error.TimestampOutOfRange;
    }
    const low: i32 = @truncate(value);
    const epoch = @divExact(value - @as(i64, low), 1 << 32);
    return .{ .seconds = @bitCast(low), .epoch = @intCast(epoch) };
}

const Node = struct {
    path: []const u8,
    name: []const u8,
    parent_path: []const u8,
    parent_index: usize,
    inode: u32,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    declared_size: u64,
    content: ?FileTreeView.ContentReader,
    xattrs: []OwnedXattr,
    times: InodeTimes = .{},
    dir_bytes: ?[]u8 = null,
    xattr_block_bytes: ?[]u8 = null,
    size_on_disk: u64 = 0,
    data_block_count: u32 = 0,
    extents: []Extent = &.{},
    extent_root: [60]u8 = [_]u8{0} ** 60,
    extent_tree_blocks: []ExtentTreeBlock = &.{},
    xattr_block: ?u64 = null,
    link_count: u16 = 1,
    device: DeviceNumbers = .{},
    hardlink_target: []const u8 = "",
    /// False for a `hardlink`, which reuses the inode its target owns and so
    /// must be skipped everywhere an inode is allocated, counted or written.
    owns_inode: bool = true,
    uses_fast_symlink: bool = false,
    uses_hashed_directory: bool = false,
    hashed_directory_index_block_count: u32 = 0,
};

const ExtentHeader = struct {
    entries: u16,
    max: u16,
    depth: u16,
    generation: u32,
};

const ExtentIndex = struct {
    logical_block: u32,
    leaf_block: u64,
};

const ExtentTreeBlock = struct {
    block_number: u64,
    bytes: [default_block_size]u8 = [_]u8{0} ** default_block_size,
};

const ExtentNodeRef = struct {
    logical_block: u32,
    block_number: u64,
};

const Layout = struct {
    total_blocks: u32,
    group_count: u32,
    gdt_blocks: u32,
    inodes_per_group: u32,
    inode_table_blocks: u32,
    groups: []GroupLayout,
};

const GroupLayout = struct {
    index: u32,
    start_block: u64,
    block_count: u32,
    has_super_copy: bool,
    block_bitmap_block: u32,
    inode_bitmap_block: u32,
    inode_table_block: u32,
    data_start_block: u64,
    reserved_block_count: u32,
    data_capacity: u32,
    used_data_blocks: u32 = 0,
    used_inode_count: u32 = 0,
    used_dir_count: u32 = 0,
};

const WriterPlan = struct {
    entries: []OwnedEntry,
    nodes: []Node,
    /// Zero or one element. The journal is deliberately not part of `nodes`:
    /// it owns a reserved inode and has no directory entry anywhere, so
    /// letting it into that array would make it a child of the root, count it
    /// as a link, and hand it a name it must never have.
    journal: []Node,
    feature_compat: u32,
    feature_ro_compat: u32,
    data_blocks_needed: u32,
    /// Nodes that own an inode, which is fewer than `nodes.len` whenever the
    /// tree contains hardlinks.
    inode_count: usize,

    fn journalBlockCount(self: *const WriterPlan) u32 {
        if (self.journal.len == 0) return 0;
        return self.journal[0].data_block_count;
    }

    fn deinit(self: *WriterPlan, allocator: std.mem.Allocator) void {
        for (self.nodes) |node| {
            if (node.dir_bytes) |bytes| allocator.free(bytes);
            if (node.xattr_block_bytes) |bytes| allocator.free(bytes);
            if (node.extents.len > 0) allocator.free(node.extents);
            if (node.extent_tree_blocks.len > 0) allocator.free(node.extent_tree_blocks);
            for (node.xattrs) |xattr| {
                allocator.free(xattr.name);
                allocator.free(xattr.value);
            }
            allocator.free(node.xattrs);
        }
        allocator.free(self.nodes);
        for (self.journal) |node| {
            if (node.extents.len > 0) allocator.free(node.extents);
            if (node.extent_tree_blocks.len > 0) allocator.free(node.extent_tree_blocks);
        }
        allocator.free(self.journal);
        for (self.entries) |entry| {
            allocator.free(entry.path);
            if (entry.hardlink_target.len > 0) allocator.free(entry.hardlink_target);
        }
        allocator.free(self.entries);
        self.* = undefined;
    }
};

const PreparedPopulate = struct {
    writer: WriterPlan,
    layout: Layout,

    fn deinit(self: *PreparedPopulate, allocator: std.mem.Allocator) void {
        self.writer.deinit(allocator);
        allocator.free(self.layout.groups);
        self.* = undefined;
    }

    fn filesystemInfo(self: *const PreparedPopulate) FilesystemInfo {
        return .{
            .block_count = self.layout.total_blocks,
            .free_block_count = countFreeBlocks(self.layout.groups),
            .inode_count = self.layout.group_count * self.layout.inodes_per_group,
            .free_inode_count = countFreeInodes(
                self.layout.groups,
                self.layout.inodes_per_group,
            ),
            .group_count = self.layout.group_count,
            .feature_compat = self.writer.feature_compat,
            .feature_incompat = writer_feature_incompat,
            .feature_ro_compat = self.writer.feature_ro_compat,
            .journal_block_count = self.writer.journalBlockCount(),
        };
    }
};

/// Validates and plans the exact ext4 population operation without creating
/// or modifying a file.
pub fn preflightPopulate(
    allocator: std.mem.Allocator,
    tree: *FileTreeView,
    options: PopulateOptions,
) PopulateError!FilesystemInfo {
    var prepared = try preparePopulate(allocator, tree, options);
    defer prepared.deinit(allocator);
    return prepared.filesystemInfo();
}

/// What `minimumPopulateLength` arrived at, and where every block of it went.
/// Broken out rather than reduced to one number because a caller that has to
/// explain to an operator why a 6 GiB tree needs an 8 GiB filesystem needs
/// the parts, and because the parts are what makes the answer checkable
/// against `mke2fs`.
///
/// `content_blocks + extent_tree_blocks + journal_blocks + metadata_blocks +
/// free_blocks == total_blocks`, exactly.
pub const MinimumSize = struct {
    /// The smallest `PopulateOptions.length` for which `populate` of this
    /// tree succeeds, or the smallest such length at or above the floor the
    /// caller asked for. Always a whole number of blocks.
    length: u64,
    total_blocks: u32,
    /// File, directory and slow-symlink content, plus one block for each
    /// inode that carries extended attributes.
    content_blocks: u32,
    /// Extent-tree index blocks, which only a file too large to describe
    /// with four inline extents needs.
    extent_tree_blocks: u32,
    /// The journal, or 0 when the filesystem has none.
    journal_blocks: u32,
    /// Superblock copies, group descriptor tables, block and inode bitmaps,
    /// and inode tables.
    metadata_blocks: u32,
    /// What is still free at this size. Rarely zero: a filesystem is a whole
    /// number of block groups, and the last one is not usually exactly full.
    free_blocks: u32,
    inode_count: u32,
    group_count: u32,
};

/// How many times the solver may revise its own answer before giving up.
/// Each revision is prompted by something it cannot know in advance -- which
/// rung of the journal ladder the size lands on, and how many extent-tree
/// blocks the allocator turns out to need -- and both converge in a handful
/// of rounds. The bound is here so that anything neither of them covers
/// fails by name instead of spinning.
const max_minimum_size_rounds: u32 = 64;

/// The smallest filesystem `populate` would accept for `tree`.
///
/// `PopulateOptions.length` is an input everywhere else: `build-image` takes
/// it from the operator, and a preserved-image rebuild inherits it from the
/// partition it overwrites in place. Neither derives it from the content,
/// which is what capturing an installed system into a right-sized image
/// needs.
///
/// `options.length` is ignored; every other field is honoured, because the
/// label, the root xattrs and above all the journal policy all change the
/// answer.
///
/// The result is the true minimum, with no headroom. That is right for a
/// read-only image and wrong for a filesystem a machine will go on writing
/// to, but how much headroom a running system wants is policy, and this is
/// not the layer that holds it. `minimumPopulateLengthAtLeast` is how a
/// caller that has a headroom policy applies it.
pub fn minimumPopulateLength(
    allocator: std.mem.Allocator,
    tree: *FileTreeView,
    options: PopulateOptions,
) PopulateError!MinimumSize {
    return minimumPopulateLengthAtLeast(allocator, tree, options, 0);
}

/// The smallest filesystem `populate` would accept for `tree` that is also
/// no smaller than `floor` bytes.
///
/// Adding headroom is not as simple as adding it to `minimumPopulateLength`,
/// because "does this length work" is not monotone in the length. A
/// filesystem is a whole number of block groups, and `buildLayout` refuses
/// any group whose own metadata is not smaller than the blocks it spans, so
/// the first few megabytes past a group boundary buy a group header the
/// filesystem cannot pay for. A tree whose minimum lands just under a
/// boundary can therefore be refused at minimum + 1 MiB and accepted again
/// at minimum + 8 MiB. This walks past that hole rather than leaving the
/// caller to discover it as a `NotEnoughSpace` from `populate`.
pub fn minimumPopulateLengthAtLeast(
    allocator: std.mem.Allocator,
    tree: *FileTreeView,
    options: PopulateOptions,
    floor: u64,
) PopulateError!MinimumSize {
    if (options.block_size != default_block_size) return error.UnsupportedBlockSize;
    if (options.label.len > 16) return error.LabelTooLong;
    const floor_blocks = std.math.cast(u32, divCeil(floor, @as(u64, options.block_size))) orelse
        return error.FilesystemTooLarge;

    // The tree is walked exactly once, here. Every candidate geometry below
    // reuses this plan: re-walking a root filesystem's worth of nodes for
    // each probe is the one cost this function cannot afford.
    var plan = try buildPlan(allocator, tree, options, 0);
    defer plan.deinit(allocator);
    const content_blocks = plan.data_blocks_needed;
    // `buildLayout` refuses an unrepresentable inode count with the same
    // error it uses for "this geometry has too few groups". Only the latter
    // grows away with size, so the former is ruled out up front rather than
    // left to look like a filesystem that is merely too small.
    _ = std.math.cast(u32, plan.inode_count - 1) orelse return error.TooManyInodes;

    // An explicit journal size is fixed, and bounded up front by exactly the
    // checks `populate` applies. The ladder default is not: it is keyed on
    // the filesystem size, which is the thing being solved for, so it is
    // resolved again on each round below.
    const fixed_journal: ?u32 = if (!options.journal.enabled)
        0
    else if (options.journal.size_bytes != null)
        try resolveJournalBlocks(options, std.math.maxInt(u32))
    else
        null;
    // `resolveJournalBlocks` refuses a journal larger than half the
    // filesystem, and the ladder has nothing to offer below its own floor.
    // Both are lower bounds on the answer rather than reasons to fail.
    const total_floor: u32 = @max(floor_blocks, if (fixed_journal) |blocks|
        (if (blocks == 0) 1 else std.math.mul(u32, blocks, 2) catch return error.JournalSizeTooLarge)
    else
        min_journalled_filesystem_blocks);

    var journal_blocks: u32 = fixed_journal orelse 0;
    var extent_tree_allowance: u32 = 0;
    // A confirmed answer that a later, tighter round may yet improve on.
    var best: ?MinimumSize = null;
    var round: u32 = 0;
    while (round < max_minimum_size_rounds) : (round += 1) {
        const needed = sumBlockCounts(content_blocks, journal_blocks, extent_tree_allowance) orelse
            return error.FilesystemTooLarge;
        const total = try solveTotalBlocks(allocator, plan.inode_count, needed, total_floor);

        // The journal ladder is keyed on the size it is helping to choose,
        // so the rounds walk it upwards: a larger journal forces a larger
        // filesystem, which can only select the same rung or a higher one.
        // The fixed point that reaches is the smallest feasible size, not
        // merely a feasible one -- any size that satisfies the ladder is at
        // least as large as every round's answer, by induction on the rounds.
        if (fixed_journal == null) {
            const laddered = defaultJournalBlocks(total) orelse
                return error.FilesystemTooSmallForJournal;
            if (laddered != journal_blocks) {
                journal_blocks = laddered;
                continue;
            }
        }

        const layout = layOutTrial(allocator, &plan, needed, total, journal_blocks) catch |err| switch (err) {
            // The allowance was too small for the extent-tree blocks the
            // allocator actually needed. That is the one cost the search
            // cannot see in advance, so it is fed back in and retried --
            // unless a larger allowance has already produced a confirmed
            // answer, which is then the smallest one there is.
            error.NotEnoughSpace, error.TooManyInodes => {
                if (best) |confirmed| return confirmed;
                extent_tree_allowance = try raiseExtentTreeAllowance(&plan, extent_tree_allowance);
                continue;
            },
            else => return err,
        };
        defer allocator.free(layout.groups);

        const extent_tree_blocks = try countExtentTreeBlocks(&plan);
        if (extent_tree_blocks > extent_tree_allowance) {
            extent_tree_allowance = extent_tree_blocks;
            continue;
        }

        var metadata_blocks: u32 = 0;
        for (layout.groups) |group| metadata_blocks += group.reserved_block_count;
        const result: MinimumSize = .{
            .length = @as(u64, total) * options.block_size,
            .total_blocks = total,
            .content_blocks = content_blocks,
            .extent_tree_blocks = extent_tree_blocks,
            .journal_blocks = journal_blocks,
            .metadata_blocks = metadata_blocks,
            .free_blocks = countFreeBlocks(layout.groups),
            .inode_count = layout.group_count * layout.inodes_per_group,
            .group_count = layout.group_count,
        };
        // The allowance overshot what the allocator used, so this answer
        // works but may not be the smallest one that does. Keep it, and try
        // again with what was actually used; each such round lowers the
        // allowance strictly, so this terminates.
        if (extent_tree_blocks < extent_tree_allowance) {
            best = result;
            extent_tree_allowance = extent_tree_blocks;
            continue;
        }
        return result;
    }
    if (best) |confirmed| return confirmed;
    return error.MinimumSizeUnconverged;
}

fn sumBlockCounts(a: u32, b: u32, c: u32) ?u32 {
    const total = @as(u64, a) + @as(u64, b) + @as(u64, c);
    return std.math.cast(u32, total);
}

/// Lays `plan` out against one candidate geometry, running the real
/// allocator rather than a model of it, so that the extent-tree blocks the
/// answer has to include are counted by the same code that will go on to
/// allocate them.
fn layOutTrial(
    allocator: std.mem.Allocator,
    plan: *WriterPlan,
    needed_blocks: u32,
    total_blocks: u32,
    journal_blocks: u32,
) PopulateError!Layout {
    releaseNodeAllocations(allocator, plan.nodes);
    releaseNodeAllocations(allocator, plan.journal);
    allocator.free(plan.journal);
    plan.journal = &.{};
    plan.journal = try buildJournalNode(allocator, journal_blocks);
    plan.data_blocks_needed = needed_blocks;

    const layout = try buildLayout(allocator, total_blocks, plan.inode_count, needed_blocks);
    errdefer allocator.free(layout.groups);
    assignInodesToGroups(plan.nodes, layout.groups, layout.inodes_per_group);
    var block_allocator = BlockAllocator{ .groups = layout.groups };
    try allocateNodeBlocks(allocator, plan.nodes, &block_allocator);
    try allocateNodeBlocks(allocator, plan.journal, &block_allocator);
    return layout;
}

/// Undoes `allocateNodeBlocks` so the same nodes can be laid out again
/// against a different geometry. Solving for the minimum size means trying
/// several of them, and rebuilding the plan for each would mean walking the
/// tree again.
fn releaseNodeAllocations(allocator: std.mem.Allocator, nodes: []Node) void {
    for (nodes) |*node| {
        if (node.extents.len > 0) allocator.free(node.extents);
        node.extents = &.{};
        if (node.extent_tree_blocks.len > 0) allocator.free(node.extent_tree_blocks);
        node.extent_tree_blocks = &.{};
        node.xattr_block = null;
    }
}

fn countExtentTreeBlocks(plan: *const WriterPlan) PopulateError!u32 {
    var total: u64 = 0;
    for (plan.nodes) |node| total += node.extent_tree_blocks.len;
    for (plan.journal) |node| total += node.extent_tree_blocks.len;
    return std.math.cast(u32, total) orelse error.TooManyExtents;
}

/// Raises the extent-tree allowance after a trial ran out of space part-way
/// through allocating. The partial allocation already accounts for most of
/// what was missing, so the next round normally lands; the `+ 1` is what
/// guarantees the search makes progress at all.
fn raiseExtentTreeAllowance(plan: *const WriterPlan, current: u32) PopulateError!u32 {
    const observed = try countExtentTreeBlocks(plan);
    return std.math.add(u32, @max(observed, current), 1) catch error.FilesystemTooLarge;
}

/// The smallest `total_blocks` that is at least `floor_blocks` and whose
/// layout has room for `needed_blocks`.
///
/// Candidate geometries are probed with `buildLayout` rather than by
/// recomputing what a block group costs. That arithmetic has exactly one
/// definition in this file, and a second copy of it would be free to drift.
fn solveTotalBlocks(
    allocator: std.mem.Allocator,
    inode_count: usize,
    needed_blocks: u32,
    floor_blocks: u32,
) PopulateError!u32 {
    // Whole block groups are searched first, because "do G groups fit" is
    // monotone in G and so safe to bisect: a group brings its own blocks,
    // and it lowers `inodes_per_group`, which shrinks the inode table in
    // every other group too. Size *within* the winning group is not
    // monotone -- a runt last group can cost more in metadata than it
    // contributes -- so it is solved directly afterwards instead.
    const max_groups = blocksToGroups(std.math.maxInt(u32), default_blocks_per_group);
    var low: u32 = 1;
    var high: u32 = 1;
    while (!try groupCountFits(allocator, inode_count, needed_blocks, high)) {
        if (high >= max_groups) return error.FilesystemTooLarge;
        low = high + 1;
        high = if (high > max_groups / 2) max_groups else high * 2;
    }
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (try groupCountFits(allocator, inode_count, needed_blocks, mid)) {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    // A total of at least `floor_blocks` spans at least as many groups as
    // `floor_blocks` does, and the search above says it spans at least
    // `low`. Both are lower bounds on the same quantity, so the group count
    // is the larger of them, and the size inside that group is what
    // `trimToLastGroup` then resolves.
    const floor_groups = @max(@as(u32, 1), blocksToGroups(floor_blocks, default_blocks_per_group));
    return trimToLastGroup(allocator, inode_count, needed_blocks, @max(low, floor_groups), floor_blocks);
}

fn groupCountFits(
    allocator: std.mem.Allocator,
    inode_count: usize,
    needed_blocks: u32,
    group_count: u32,
) PopulateError!bool {
    const layout = buildLayout(
        allocator,
        blocksForGroupCount(group_count),
        inode_count,
        needed_blocks,
    ) catch |err| switch (err) {
        // Both mean "this geometry is too small", which is exactly what the
        // search exists to walk past. Every other failure is real.
        error.NotEnoughSpace, error.TooManyInodes => return false,
        else => |other| return other,
    };
    allocator.free(layout.groups);
    return true;
}

fn blocksForGroupCount(group_count: u32) u32 {
    return std.math.mul(u32, group_count, default_blocks_per_group) catch std.math.maxInt(u32);
}

/// Shrinks the winning geometry back into its last block group. A filesystem
/// of whole groups almost always has capacity to spare, and every block of
/// that spare capacity is a block the last group does not have to contain.
///
/// Shrinking cannot change what any group costs -- the group count, and with
/// it `inodes_per_group`, stays the same -- so the answer is computed rather
/// than searched, and then confirmed against `buildLayout` once.
///
/// `floor_blocks` is the caller's own lower bound. It is applied here rather
/// than by the caller because a size below the last group's own metadata is
/// refused outright, and clamping a floor up to the first size the layout
/// accepts is exactly the hole this function already knows how to step over.
fn trimToLastGroup(
    allocator: std.mem.Allocator,
    inode_count: usize,
    needed_blocks: u32,
    group_count: u32,
    floor_blocks: u32,
) PopulateError!u32 {
    const full_blocks = blocksForGroupCount(group_count);
    const layout = try buildLayout(allocator, full_blocks, inode_count, needed_blocks);
    const spare = countFreeBlocks(layout.groups) - needed_blocks;
    const last = layout.groups[layout.groups.len - 1];
    const last_capacity = last.data_capacity;
    // A group whose blocks do not outnumber its own metadata is refused
    // outright, so the last one cannot be shrunk past that point.
    const last_floor = last.start_block + last.reserved_block_count + 1;
    allocator.free(layout.groups);

    const trimmed = full_blocks - @min(spare, last_capacity);
    const total = std.math.cast(u32, @max(@max(@as(u64, trimmed), last_floor), floor_blocks)) orelse
        return error.FilesystemTooLarge;
    // The trimmed geometry is derived rather than searched, so it is
    // confirmed against the one definition of what a block group costs
    // before it is handed back as an answer.
    const confirmed = try buildLayout(allocator, total, inode_count, needed_blocks);
    allocator.free(confirmed.groups);
    return total;
}

/// Formats a fresh ext4 filesystem inside `file[options.offset .. options.offset + options.length)`,
/// writes the supplied tree, and returns the resulting geometry/feature bits.
pub fn populate(
    io: Io,
    file: Io.File,
    allocator: std.mem.Allocator,
    tree: *FileTreeView,
    options: PopulateOptions,
) PopulateError!FilesystemInfo {
    var prepared = try preparePopulate(allocator, tree, options);
    defer prepared.deinit(allocator);

    const stat = try file.stat(io);
    const range_end = options.offset + options.length;
    if (stat.size < range_end) {
        // `stat.size` reads back as 0 for a block-device special file (real
        // hardware, e.g. formatting a resource disk directly rather than a
        // disk-image regular file -- see azagent/resource_disk.zig), so
        // this branch is always taken there even though the device already
        // has a fixed, sufficient size. `setLength` on such a file fails
        // with `NonResizable` rather than actually resizing anything;
        // that's expected in this case, so it's tolerated rather than
        // propagated. A regular file that's genuinely too small to hold
        // the requested range fails for a different reason (`FileTooBig`,
        // `NoSpaceLeft`, etc., surfaced normally by the writes below).
        file.setLength(io, range_end) catch |err| switch (err) {
            error.NonResizable => {},
            else => return err,
        };
    }

    try writeNodeData(io, file, prepared.writer.nodes, options);
    try writeJournalData(io, file, prepared.writer.journal, options);
    try zeroUnusedInodeTableBlocks(io, file, prepared.layout, options.offset);
    try writeBitmaps(io, file, prepared.layout, options.offset);
    try writeInodes(io, file, prepared.writer.nodes, prepared.layout, options);
    try writeInodes(io, file, prepared.writer.journal, prepared.layout, options);
    try writeGroupDescriptorTables(
        io,
        file,
        prepared.layout,
        options.offset,
        options.uuid orelse [_]u8{0} ** 16,
    );
    try writeSuperblocks(io, file, prepared.layout, prepared.writer, options);

    return prepared.filesystemInfo();
}

fn preparePopulate(
    allocator: std.mem.Allocator,
    tree: *FileTreeView,
    options: PopulateOptions,
) PopulateError!PreparedPopulate {
    if (options.block_size != default_block_size) return error.UnsupportedBlockSize;
    if (options.length == 0 or options.length % options.block_size != 0) {
        return error.InvalidRange;
    }
    _ = std.math.add(u64, options.offset, options.length) catch
        return error.InvalidRange;
    if (options.label.len > 16) return error.LabelTooLong;

    const total_blocks64 = options.length / options.block_size;
    const total_blocks = std.math.cast(u32, total_blocks64) orelse
        return error.FilesystemTooLarge;

    var writer = try buildPlan(allocator, tree, options, try resolveJournalBlocks(options, total_blocks));
    errdefer writer.deinit(allocator);
    const layout = try buildLayout(
        allocator,
        total_blocks,
        writer.inode_count,
        writer.data_blocks_needed,
    );
    errdefer allocator.free(layout.groups);

    assignInodesToGroups(writer.nodes, layout.groups, layout.inodes_per_group);
    if (writer.data_blocks_needed > countFreeBlocks(layout.groups)) {
        return error.NotEnoughSpace;
    }
    // The tree is allocated first so that turning the journal on moves no
    // file: an image built with and without a journal places every node's
    // data in exactly the same blocks, which makes the two directly
    // comparable.
    var block_allocator = BlockAllocator{ .groups = layout.groups };
    try allocateNodeBlocks(allocator, writer.nodes, &block_allocator);
    try allocateNodeBlocks(allocator, writer.journal, &block_allocator);
    return .{ .writer = writer, .layout = layout };
}

/// Resolves the requested journal size into whole filesystem blocks, applying
/// the same bounds `mke2fs` does. Zero means "no journal".
fn resolveJournalBlocks(options: PopulateOptions, total_blocks: u32) PopulateError!u32 {
    if (!options.journal.enabled) return 0;

    const blocks = if (options.journal.size_bytes) |size_bytes| blk: {
        if (size_bytes == 0 or size_bytes % options.block_size != 0) {
            return error.UnalignedJournalSize;
        }
        const in_blocks = std.math.cast(u32, size_bytes / options.block_size) orelse
            return error.JournalSizeTooLarge;
        if (in_blocks < jbd2_min_journal_blocks) return error.JournalSizeTooSmall;
        if (in_blocks > jbd2_max_journal_blocks) return error.JournalSizeTooLarge;
        break :blk in_blocks;
    } else defaultJournalBlocks(total_blocks) orelse
        return error.FilesystemTooSmallForJournal;

    // `mke2fs` refuses a journal larger than half the filesystem, and so does
    // this: past that point the log is no longer overhead, it is the image.
    if (blocks > total_blocks / 2) return error.JournalSizeTooLarge;
    return blocks;
}

/// The journal's stand-in node. It carries a reserved inode and no name, so
/// it travels beside the tree rather than inside it.
fn buildJournalNode(allocator: std.mem.Allocator, block_count: u32) PopulateError![]Node {
    if (block_count == 0) return allocator.alloc(Node, 0);
    const journal = try allocator.alloc(Node, 1);
    errdefer allocator.free(journal);
    const size_bytes = @as(u64, block_count) * default_block_size;
    journal[0] = .{
        .path = "",
        .name = "",
        .parent_path = "",
        .parent_index = 0,
        .inode = journal_inode,
        .kind = .file,
        .mode = journal_inode_mode,
        .uid = 0,
        .gid = 0,
        .declared_size = size_bytes,
        .content = null,
        .xattrs = &.{},
        .size_on_disk = size_bytes,
        .data_block_count = block_count,
    };
    return journal;
}

/// Grow an ext4 filesystem in place by extending the final block group or
/// appending new groups; this deliberately does not emulate online
/// `resize_inode` journaling/reservation machinery.
pub fn resize(io: Io, file: Io.File, allocator: std.mem.Allocator, options: ResizeOptions) ResizeError!FilesystemInfo {
    if (options.length == 0 or options.length % default_block_size != 0) return error.InvalidRange;

    var sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sb, options.offset + superblock_offset);
    if (readInt(u16, sb[0x38..0x3A]) != super_magic) return error.BadMagic;
    if (readInt(u32, sb[0x4C..0x50]) != rev_dynamic) return error.UnsupportedRevision;
    if ((@as(u32, 1024) << @intCast(readInt(u32, sb[0x18..0x1C]))) != default_block_size) return error.UnsupportedBlockSize;

    const compat = readInt(u32, sb[0x5C..0x60]);
    const incompat = readInt(u32, sb[0x60..0x64]);
    const ro_compat = readInt(u32, sb[0x64..0x68]);
    // `RESIZE_INODE` reserves GDT blocks inside every group carrying a
    // superblock copy, and inode 7 maps them. This path neither reads that
    // inode nor preserves those reservations while it rebuilds the block
    // bitmaps, so it refuses by name instead of quietly handing back a
    // filesystem whose reserved growth room it has just handed to files.
    if (compat & feature_compat_resize_inode != 0) return error.ResizeInodeNotSupported;
    if (compat & ~(writer_feature_compat | feature_compat_has_journal) != 0) return error.UnsupportedFeatures;
    // A journal needs nothing special here. Its inode and its blocks live
    // entirely inside the old range, growing appends groups beyond them, and
    // the bitmap rebuild below only relies on this writer's invariant that
    // every group's used data blocks form a prefix of its data area -- which
    // holds for the journal exactly as it does for a file.
    if (incompat != writer_feature_incompat) return error.UnsupportedFeatures;
    if (ro_compat & ~(writer_feature_ro_compat_base | writer_feature_ro_compat_optional) != 0) return error.UnsupportedFeatures;

    // `s_jnl_blocks` is a backup of the journal inode that this path leaves
    // exactly as it found it, which is only correct while the journal itself
    // is untouched. Any other backup type means the filesystem was not
    // written here, so its layout assumptions are not this writer's either.
    const has_journal = compat & feature_compat_has_journal != 0;
    if (has_journal and readInt(u8, sb[0xFD..0xFE]) != jnl_backup_type_blocks) {
        return error.UnsupportedResizeLayout;
    }
    const journal_block_count: u32 = if (has_journal) blocksForBytes(
        (@as(u64, readInt(u32, sb[0x148..0x14C])) << 32) | readInt(u32, sb[0x14C..0x150]),
        default_block_size,
    ) else 0;

    const old_total_blocks = readInt(u32, sb[0x04..0x08]);
    const new_total_blocks = std.math.cast(u32, options.length / default_block_size) orelse return error.FilesystemTooLarge;
    if (new_total_blocks < old_total_blocks) return error.ShrinkNotSupported;
    if (new_total_blocks == old_total_blocks) {
        return .{
            .block_count = old_total_blocks,
            .free_block_count = readInt(u32, sb[0x0C..0x10]),
            .inode_count = readInt(u32, sb[0x00..0x04]),
            .free_inode_count = readInt(u32, sb[0x10..0x14]),
            .group_count = blocksToGroups(old_total_blocks, readInt(u32, sb[0x20..0x24])),
            .feature_compat = compat,
            .feature_incompat = incompat,
            .feature_ro_compat = ro_compat,
            .journal_block_count = journal_block_count,
        };
    }

    const desc_size = blk: {
        const raw = readInt(u16, sb[0xFE..0x100]);
        break :blk if (raw == 0) @as(u16, 32) else raw;
    };
    if (desc_size != group_desc_size) return error.UnsupportedDescriptorSize;

    const blocks_per_group = readInt(u32, sb[0x20..0x24]);
    const inodes_per_group = readInt(u32, sb[0x28..0x2C]);
    const inode_size_on_disk = readInt(u16, sb[0x58..0x5A]);
    if (blocks_per_group != default_blocks_per_group or !supportedInodeSize(inode_size_on_disk)) return error.UnsupportedResizeLayout;

    const old_group_count = blocksToGroups(old_total_blocks, blocks_per_group);
    const new_group_count = blocksToGroups(new_total_blocks, blocks_per_group);
    const old_gdt_blocks = blocksForBytes(@as(u64, old_group_count) * group_desc_size, default_block_size);
    const required_new_gdt_blocks = blocksForBytes(@as(u64, new_group_count) * group_desc_size, default_block_size);
    if (required_new_gdt_blocks > old_gdt_blocks) return error.UnsupportedResizeLayout;
    const inode_table_blocks = divCeil(@as(u32, inodes_per_group) * inode_size_on_disk, default_block_size);

    const old_layout = try buildFixedLayout(allocator, old_total_blocks, blocks_per_group, inodes_per_group, inode_table_blocks, old_gdt_blocks);
    defer allocator.free(old_layout.groups);
    var new_layout = try buildFixedLayout(allocator, new_total_blocks, blocks_per_group, inodes_per_group, inode_table_blocks, old_gdt_blocks);
    defer allocator.free(new_layout.groups);

    const gdt_bytes = @as(usize, old_group_count) * group_desc_size;
    const gdt_storage_bytes = @as(usize, old_gdt_blocks) * default_block_size;
    const old_gdt = try allocator.alloc(u8, gdt_storage_bytes);
    defer allocator.free(old_gdt);
    @memset(old_gdt, 0);
    _ = try file.readPositionalAll(io, old_gdt, options.offset + default_block_size);
    _ = gdt_bytes;

    for (old_layout.groups, 0..) |old_group, index| {
        const base = index * group_desc_size;
        const free_blocks = readInt(u16, old_gdt[base + 12 .. base + 14]);
        const free_inodes = readInt(u16, old_gdt[base + 14 .. base + 16]);
        const used_dirs = readInt(u16, old_gdt[base + 16 .. base + 18]);
        new_layout.groups[index].used_data_blocks = old_group.data_capacity - free_blocks;
        new_layout.groups[index].used_inode_count = inodes_per_group - free_inodes;
        new_layout.groups[index].used_dir_count = used_dirs;
    }

    const stat = try file.stat(io);
    if (stat.size < options.offset + options.length) try file.setLength(io, options.offset + options.length);

    if (new_group_count > old_group_count) {
        var group_index = old_group_count;
        while (group_index < new_group_count) : (group_index += 1) {
            var zero_block: [default_block_size]u8 = [_]u8{0} ** default_block_size;
            var block: u32 = 0;
            while (block < inode_table_blocks) : (block += 1) {
                try file.writePositionalAll(io, &zero_block, options.offset + (@as(u64, new_layout.groups[group_index].inode_table_block) + block) * default_block_size);
            }
        }
    }

    try writeBitmaps(io, file, new_layout, options.offset);

    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, sb[0x68..0x78]);
    try writeGroupDescriptorTables(io, file, new_layout, options.offset, uuid);

    writeInt(u32, sb[0x00..0x04], new_group_count * inodes_per_group);
    writeInt(u32, sb[0x04..0x08], new_total_blocks);
    writeInt(u32, sb[0x0C..0x10], countFreeBlocks(new_layout.groups));
    writeInt(u32, sb[0x10..0x14], countFreeInodes(new_layout.groups, inodes_per_group));
    writeInt(u32, sb[0x20..0x24], blocks_per_group);
    writeInt(u32, sb[0x24..0x28], blocks_per_group);
    writeInt(u32, sb[0x28..0x2C], inodes_per_group);
    writeInt(u16, sb[0x5A..0x5C], 0);
    setSuperblockChecksum(&sb);
    try file.writePositionalAll(io, &sb, options.offset + superblock_offset);
    for (new_layout.groups) |group| {
        if (group.index == 0 or !group.has_super_copy) continue;
        writeInt(u16, sb[0x5A..0x5C], @intCast(group.index));
        setSuperblockChecksum(&sb);
        try file.writePositionalAll(io, &sb, options.offset + group.start_block * default_block_size);
    }

    return .{
        .block_count = new_total_blocks,
        .free_block_count = countFreeBlocks(new_layout.groups),
        .inode_count = new_group_count * inodes_per_group,
        .free_inode_count = countFreeInodes(new_layout.groups, inodes_per_group),
        .group_count = new_group_count,
        .feature_compat = compat,
        .feature_incompat = incompat,
        .feature_ro_compat = ro_compat,
        .journal_block_count = journal_block_count,
    };
}

pub const OpenOptions = struct {
    offset: u64 = 0,
};

fn readSourceAll(
    io: Io,
    file: Io.File,
    source: ?ReadOnlySource,
    buffer: []u8,
    offset: u64,
) (Io.File.ReadPositionalError || error{ SourceReadFailed, UnexpectedEndOfFile })!void {
    var done: usize = 0;
    while (done < buffer.len) {
        const count = if (source) |read_source|
            read_source.read_at_fn(read_source.ctx, io, buffer[done..], offset + done) catch
                return error.SourceReadFailed
        else
            try file.readPositionalAll(io, buffer[done..], offset + done);
        if (count == 0 or count > buffer.len - done) return error.UnexpectedEndOfFile;
        done += count;
    }
}

/// A read-only positional byte source used when ext4 lives in a virtual disk
/// view (for example, a qcow2 backing chain) rather than directly in `file`.
/// Callback errors are deliberately collapsed to `error.SourceReadFailed`.
pub const ReadOnlySource = struct {
    ctx: *const anyopaque,
    read_at_fn: *const fn (
        ctx: *const anyopaque,
        io: Io,
        buffer: []u8,
        offset: u64,
    ) anyerror!usize,
};

pub const Reader = struct {
    file: Io.File,
    read_only_source: ?ReadOnlySource,
    allocator: std.mem.Allocator,
    offset: u64,
    uuid: [16]u8,
    label: [16]u8,
    block_size: u32,
    total_blocks: u32,
    total_inodes: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_size: u16,
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    groups: []ReaderGroup,

    pub fn open(io: Io, file: Io.File, allocator: std.mem.Allocator, options: OpenOptions) OpenError!Reader {
        return openInternal(io, file, null, allocator, options);
    }

    /// Opens ext4 through a guest-visible read-only byte source. `file` is
    /// retained only for API/layout compatibility and is never read while the
    /// supplied source is present.
    pub fn openReadOnlySource(
        io: Io,
        file: Io.File,
        source: ReadOnlySource,
        allocator: std.mem.Allocator,
        options: OpenOptions,
    ) OpenError!Reader {
        return openInternal(io, file, source, allocator, options);
    }

    fn openInternal(
        io: Io,
        file: Io.File,
        source: ?ReadOnlySource,
        allocator: std.mem.Allocator,
        options: OpenOptions,
    ) OpenError!Reader {
        var sb: [superblock_size]u8 = undefined;
        try readSourceAll(io, file, source, &sb, options.offset + superblock_offset);
        if (readInt(u16, sb[0x38..0x3A]) != super_magic) return error.BadMagic;
        if (readInt(u32, sb[0x4C..0x50]) != rev_dynamic) return error.UnsupportedRevision;

        const log_block_size = readInt(u32, sb[0x18..0x1C]);
        if (log_block_size > 2) return error.UnsupportedBlockSize;
        const block_size = @as(u32, 1024) << @intCast(log_block_size);
        if (block_size != default_block_size) return error.UnsupportedBlockSize;

        const incompat = readInt(u32, sb[0x60..0x64]);
        const ro_compat = readInt(u32, sb[0x64..0x68]);
        const compat = readInt(u32, sb[0x5C..0x60]);
        if (compat & ~reader_feature_compat != 0) return error.UnsupportedFeatures;
        if (incompat & ~reader_feature_incompat != 0) return error.UnsupportedFeatures;
        if (ro_compat & ~reader_feature_ro_compat != 0) return error.UnsupportedFeatures;

        var uuid: [16]u8 = undefined;
        @memcpy(&uuid, sb[0x68..0x78]);
        const label = sb[0x78..0x88].*;

        const desc_size = blk: {
            const raw = readInt(u16, sb[0xFE..0x100]);
            break :blk if (raw == 0) @as(u16, 32) else raw;
        };
        if (desc_size != group_desc_size and desc_size != 64) return error.UnsupportedDescriptorSize;

        const total_blocks = readInt(u32, sb[0x04..0x08]);
        const total_inodes = readInt(u32, sb[0x00..0x04]);
        const blocks_per_group = readInt(u32, sb[0x20..0x24]);
        const inodes_per_group = readInt(u32, sb[0x28..0x2C]);
        const inode_size_on_disk = readInt(u16, sb[0x58..0x5A]);
        if (!supportedInodeSize(inode_size_on_disk)) return error.UnsupportedInodeSize;
        if (total_blocks == 0 or blocks_per_group == 0 or inodes_per_group == 0) {
            return error.UnsupportedFeatures;
        }
        const group_count = blocksToGroups(total_blocks, blocks_per_group);

        const groups = try allocator.alloc(ReaderGroup, group_count);
        errdefer allocator.free(groups);

        const gdt_bytes = @as(usize, group_count) * desc_size;
        const gdt_storage_bytes = @as(usize, blocksForBytes(gdt_bytes, block_size)) * block_size;
        const gdt = try allocator.alloc(u8, gdt_storage_bytes);
        defer allocator.free(gdt);
        @memset(gdt, 0);
        try readSourceAll(io, file, source, gdt, options.offset + @as(u64, block_size));
        var group_index: u32 = 0;
        while (group_index < group_count) : (group_index += 1) {
            const base = @as(usize, group_index) * desc_size;
            groups[group_index] = .{
                .block_bitmap_block = readInt(u32, gdt[base + 0 .. base + 4]),
                .inode_bitmap_block = readInt(u32, gdt[base + 4 .. base + 8]),
                .inode_table_block = readInt(u32, gdt[base + 8 .. base + 12]),
                .free_block_count = readInt(u16, gdt[base + 12 .. base + 14]),
                .free_inode_count = readInt(u16, gdt[base + 14 .. base + 16]),
                .used_directory_count = readInt(u16, gdt[base + 16 .. base + 18]),
                .block_bitmap_checksum = readInt(u16, gdt[base + 0x18 .. base + 0x1A]),
                .inode_bitmap_checksum = readInt(u16, gdt[base + 0x1A .. base + 0x1C]),
                .descriptor_checksum = readInt(u16, gdt[base + 0x1E .. base + 0x20]),
            };
        }

        return .{
            .file = file,
            .read_only_source = source,
            .allocator = allocator,
            .offset = options.offset,
            .uuid = uuid,
            .label = label,
            .block_size = block_size,
            .total_blocks = total_blocks,
            .total_inodes = total_inodes,
            .blocks_per_group = blocks_per_group,
            .inodes_per_group = inodes_per_group,
            .inode_size = inode_size_on_disk,
            .feature_compat = compat,
            .feature_incompat = incompat,
            .feature_ro_compat = ro_compat,
            .groups = groups,
        };
    }

    pub fn deinit(self: *Reader) void {
        self.allocator.free(self.groups);
        self.* = undefined;
    }

    pub fn statPath(self: Reader, io: Io, path: []const u8) ReadError!Stat {
        const inode_number = try self.lookupPath(io, path);
        const inode = try self.readInode(io, inode_number);
        return inode.stat();
    }

    pub fn listDir(self: Reader, io: Io, allocator: std.mem.Allocator, path: []const u8) ReadError![]DirEntry {
        const inode_number = try self.lookupPath(io, path);
        const inode = try self.readInode(io, inode_number);
        return self.listDirByInode(io, allocator, inode);
    }

    fn listDirByInode(self: Reader, io: Io, allocator: std.mem.Allocator, inode: ParsedInode) ReadError![]DirEntry {
        if (inode.kind != .directory) return error.NotDirectory;

        const data = try self.readInodeDataAlloc(io, allocator, inode);
        defer allocator.free(data);

        var entries = std.array_list.Managed(DirEntry).init(allocator);
        errdefer {
            for (entries.items) |entry| allocator.free(entry.name);
            entries.deinit();
        }

        var offset: usize = 0;
        while (offset + 8 <= data.len) {
            const child_inode = readInt(u32, data[offset .. offset + 4]);
            const rec_len = readInt(u16, data[offset + 4 .. offset + 6]);
            const name_len = data[offset + 6];
            const file_type = data[offset + 7];
            if (rec_len < 8 or offset + rec_len > data.len) return error.BadDirectoryEntry;
            if (name_len > rec_len - 8) return error.BadDirectoryEntry;
            const name = data[offset + 8 .. offset + 8 + name_len];
            if (child_inode != 0 and !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                try entries.append(.{
                    .inode = child_inode,
                    .kind = dirFileTypeToKind(file_type),
                    .name = try allocator.dupe(u8, name),
                });
            }
            offset += rec_len;
        }
        return entries.toOwnedSlice();
    }

    pub fn readFileAlloc(self: Reader, io: Io, allocator: std.mem.Allocator, path: []const u8) ReadError![]u8 {
        const inode_number = try self.lookupPath(io, path);
        const inode = try self.readInode(io, inode_number);
        if (inode.kind != .file) return error.NotFile;
        return self.readInodeDataAlloc(io, allocator, inode);
    }

    pub fn readLinkAlloc(self: Reader, io: Io, allocator: std.mem.Allocator, path: []const u8) ReadError![]u8 {
        const inode_number = try self.lookupPath(io, path);
        const inode = try self.readInode(io, inode_number);
        if (inode.kind != .symlink) return error.NotSymlink;
        return self.readInodeDataAlloc(io, allocator, inode);
    }

    pub fn preadPath(self: Reader, io: Io, path: []const u8, buffer: []u8, offset: u64) ReadError!usize {
        const inode_number = try self.lookupPath(io, path);
        const inode = try self.readInode(io, inode_number);
        if (inode.kind != .file) return error.NotFile;
        return self.preadInode(io, inode, buffer, offset);
    }

    pub fn readExtents(self: Reader, io: Io, allocator: std.mem.Allocator, path: []const u8) ReadError![]Extent {
        const inode_number = try self.lookupPath(io, path);
        const inode = try self.readInode(io, inode_number);
        if (inode.kind != .file and inode.kind != .directory and inode.kind != .symlink) return error.UnsupportedInodeLayout;
        if (inode.kind == .symlink and inode.isFastSymlink()) {
            return allocator.alloc(Extent, 0);
        }
        return self.readInodeExtentsAlloc(io, allocator, inode);
    }

    pub fn readXattrsAlloc(self: Reader, io: Io, allocator: std.mem.Allocator, path: []const u8) ReadError![]OwnedXattr {
        const inode_number = try self.lookupPath(io, path);
        const inode = try self.readInode(io, inode_number);
        return self.readInodeXattrsAlloc(io, allocator, inode);
    }

    pub fn readXattrAlloc(self: Reader, io: Io, allocator: std.mem.Allocator, path: []const u8, name: []const u8) ReadError![]u8 {
        const xattrs = try self.readXattrsAlloc(io, allocator, path);
        defer freeXattrs(allocator, xattrs);
        for (xattrs) |xattr| {
            if (std.mem.eql(u8, xattr.name, name)) return allocator.dupe(u8, xattr.value);
        }
        return error.XattrNotFound;
    }

    fn lookupPath(self: Reader, io: Io, path: []const u8) ReadError!u32 {
        if (path.len == 0 or std.mem.eql(u8, path, "/")) return root_inode;

        var current_inode = root_inode;
        var start: usize = 0;
        while (start < path.len) {
            while (start < path.len and path[start] == '/') : (start += 1) {}
            if (start >= path.len) break;
            var end = start;
            while (end < path.len and path[end] != '/') : (end += 1) {}
            const component = path[start..end];
            current_inode = try self.lookupChild(io, current_inode, component);
            start = end + 1;
        }
        return current_inode;
    }

    fn lookupChild(self: Reader, io: Io, dir_inode_number: u32, name: []const u8) ReadError!u32 {
        const inode = try self.readInode(io, dir_inode_number);
        if (inode.kind != .directory) return error.NotDirectory;

        // ext4 htree index blocks deliberately masquerade as unused directory
        // entries, so a linear scan remains correct for both indexed and
        // non-indexed directories.
        const data = try self.readInodeDataAlloc(io, self.allocator, inode);
        defer self.allocator.free(data);

        var offset: usize = 0;
        while (offset + 8 <= data.len) {
            const child_inode = readInt(u32, data[offset .. offset + 4]);
            const rec_len = readInt(u16, data[offset + 4 .. offset + 6]);
            const name_len = data[offset + 6];
            if (rec_len < 8 or offset + rec_len > data.len) return error.BadDirectoryEntry;
            if (name_len > rec_len - 8) return error.BadDirectoryEntry;
            if (child_inode != 0 and std.mem.eql(u8, data[offset + 8 .. offset + 8 + name_len], name)) {
                return child_inode;
            }
            offset += rec_len;
        }
        return error.NotFound;
    }

    fn preadInode(self: Reader, io: Io, inode: ParsedInode, buffer: []u8, offset: u64) ReadError!usize {
        if (offset >= inode.size) return 0;
        const max_len = std.math.cast(usize, inode.size - offset) orelse return error.FileTooLarge;
        const want = @min(buffer.len, max_len);

        if (inode.kind == .symlink and inode.isFastSymlink()) {
            const src = inode.block_bytes[0..@intCast(inode.size)];
            const src_offset: usize = @intCast(offset);
            std.mem.copyForwards(u8, buffer[0..want], src[src_offset .. src_offset + want]);
            return want;
        }

        const extents = try self.readInodeExtentsAlloc(io, self.allocator, inode);
        defer self.allocator.free(extents);
        var done: usize = 0;
        var remaining = want;
        var logical_offset = offset;
        while (remaining > 0) {
            const logical_block: u32 = @intCast(logical_offset / self.block_size);
            const within_block: usize = @intCast(logical_offset % self.block_size);
            const physical_block = findPhysicalBlock(extents, logical_block) orelse return error.UnsupportedInodeLayout;
            const chunk = @min(remaining, @as(usize, self.block_size) - within_block);
            try self.readAll(io, buffer[done .. done + chunk], self.blockOffset(physical_block) + within_block);
            done += chunk;
            remaining -= chunk;
            logical_offset += chunk;
        }
        return done;
    }

    fn readInodeDataAlloc(self: Reader, io: Io, allocator: std.mem.Allocator, inode: ParsedInode) ReadError![]u8 {
        const size = std.math.cast(usize, inode.size) orelse return error.FileTooLarge;
        const data = try allocator.alloc(u8, size);
        errdefer allocator.free(data);
        if (size == 0) return data;

        if (inode.kind == .symlink and inode.isFastSymlink()) {
            std.mem.copyForwards(u8, data, inode.block_bytes[0..size]);
            return data;
        }

        const extents = try self.readInodeExtentsAlloc(io, allocator, inode);
        defer allocator.free(extents);
        var offset: usize = 0;
        while (offset < data.len) {
            offset += try self.preadInodeWithExtents(io, inode, extents, data[offset..], offset);
        }
        return data;
    }

    fn readInodeXattrsAlloc(self: Reader, io: Io, allocator: std.mem.Allocator, inode: ParsedInode) ReadError![]OwnedXattr {
        if (inode.file_acl_block == 0) return allocator.alloc(OwnedXattr, 0);

        const block = try allocator.alloc(u8, self.block_size);
        defer allocator.free(block);
        try self.readAll(io, block, self.blockOffset(inode.file_acl_block));
        if (readInt(u32, block[0..4]) != ext4_xattr_magic) return error.UnsupportedInodeLayout;

        var xattrs = std.array_list.Managed(OwnedXattr).init(allocator);
        errdefer {
            for (xattrs.items) |xattr| {
                allocator.free(xattr.name);
                allocator.free(xattr.value);
            }
            xattrs.deinit();
        }

        var cursor: usize = 32;
        while (cursor + 4 <= block.len) {
            if (readInt(u32, block[cursor .. cursor + 4]) == 0) break;
            const name_len = block[cursor];
            const name_index = block[cursor + 1];
            const value_off = readInt(u16, block[cursor + 2 .. cursor + 4]);
            const value_size = readInt(u32, block[cursor + 8 .. cursor + 12]);
            const entry_len = alignUpU16(@as(u16, @intCast(16 + name_len)), 4);
            const value_end = std.math.add(u64, value_off, value_size) catch
                return error.UnsupportedInodeLayout;
            if (cursor + entry_len > block.len or value_end > block.len) return error.UnsupportedInodeLayout;
            if (cursor + 16 + name_len > block.len) return error.UnsupportedInodeLayout;
            const short_name = block[cursor + 16 .. cursor + 16 + name_len];
            try xattrs.append(.{
                .name = try joinXattrName(allocator, name_index, short_name),
                .value = try allocator.dupe(u8, block[value_off..@intCast(value_end)]),
            });
            cursor += entry_len;
        }
        return xattrs.toOwnedSlice();
    }

    fn readInode(self: Reader, io: Io, inode_number: u32) ReadError!ParsedInode {
        if (inode_number == 0 or inode_number > self.total_inodes) return error.NotFound;
        const group_index = (inode_number - 1) / self.inodes_per_group;
        const index_in_group = (inode_number - 1) % self.inodes_per_group;
        const group = self.groups[group_index];
        const inode_offset = self.blockOffset(group.inode_table_block) + @as(u64, index_in_group) * self.inode_size;

        var buf: [max_supported_reader_inode_size]u8 = [_]u8{0} ** max_supported_reader_inode_size;
        try self.readAll(io, buf[0..self.inode_size], inode_offset);
        return ParsedInode.fromBytes(inode_number, buf[0..self.inode_size]);
    }

    fn blockOffset(self: Reader, block_number: u64) u64 {
        return self.offset + block_number * self.block_size;
    }

    fn readAll(self: Reader, io: Io, buffer: []u8, offset: u64) ReadError!void {
        readSourceAll(io, self.file, self.read_only_source, buffer, offset) catch |err| switch (err) {
            error.SourceReadFailed => return error.SourceReadFailed,
            error.UnexpectedEndOfFile => return error.UnexpectedEndOfFile,
            else => return err,
        };
    }

    fn readInodeExtentsAlloc(self: Reader, io: Io, allocator: std.mem.Allocator, inode: ParsedInode) ReadError![]Extent {
        if ((inode.flags & inode_flag_extents) == 0) return error.UnsupportedInodeLayout;

        var extents = std.array_list.Managed(Extent).init(allocator);
        errdefer extents.deinit();
        try self.appendExtentTreeEntries(io, &extents, inode.block_bytes[0..], max_inline_extents, null);
        return extents.toOwnedSlice();
    }

    fn appendExtentTreeEntries(
        self: Reader,
        io: Io,
        extents: *std.array_list.Managed(Extent),
        node_bytes: []const u8,
        node_capacity: usize,
        expected_depth: ?u16,
    ) ReadError!void {
        const header = try parseExtentHeader(node_bytes[0..extent_header_size]);
        if (expected_depth) |depth| {
            if (header.depth != depth) return error.UnsupportedInodeLayout;
        }
        if (header.depth > max_supported_extent_depth) return error.UnsupportedExtentDepth;
        if (header.entries > header.max or header.max > node_capacity) return error.UnsupportedInodeLayout;

        var entry_index: usize = 0;
        if (header.depth == 0) {
            while (entry_index < header.entries) : (entry_index += 1) {
                const base = extent_header_size + entry_index * extent_entry_size;
                try extents.append(decodeExtent(node_bytes[base .. base + extent_entry_size]));
            }
            return;
        }

        var child_block: [default_block_size]u8 = undefined;
        while (entry_index < header.entries) : (entry_index += 1) {
            const base = extent_header_size + entry_index * extent_entry_size;
            const child = decodeExtentIndex(node_bytes[base .. base + extent_entry_size]);
            try self.readAll(io, &child_block, self.blockOffset(child.leaf_block));
            try self.appendExtentTreeEntries(
                io,
                extents,
                child_block[0..],
                extentEntriesPerBlock(self.block_size),
                header.depth - 1,
            );
        }
    }

    fn preadInodeWithExtents(
        self: Reader,
        io: Io,
        inode: ParsedInode,
        extents: []const Extent,
        buffer: []u8,
        offset: u64,
    ) ReadError!usize {
        if (offset >= inode.size) return 0;
        const max_len = std.math.cast(usize, inode.size - offset) orelse return error.FileTooLarge;
        const want = @min(buffer.len, max_len);

        var done: usize = 0;
        var remaining = want;
        var logical_offset = offset;
        while (remaining > 0) {
            const logical_block: u32 = @intCast(logical_offset / self.block_size);
            const within_block: usize = @intCast(logical_offset % self.block_size);
            const physical_block = findPhysicalBlock(extents, logical_block) orelse return error.UnsupportedInodeLayout;
            const chunk = @min(remaining, @as(usize, self.block_size) - within_block);
            try self.readAll(io, buffer[done .. done + chunk], self.blockOffset(physical_block) + within_block);
            done += chunk;
            remaining -= chunk;
            logical_offset += chunk;
        }
        return done;
    }
};

pub fn open(io: Io, file: Io.File, allocator: std.mem.Allocator, options: OpenOptions) OpenError!Reader {
    return Reader.open(io, file, allocator, options);
}

pub fn openReadOnlySource(
    io: Io,
    file: Io.File,
    source: ReadOnlySource,
    allocator: std.mem.Allocator,
    options: OpenOptions,
) OpenError!Reader {
    return Reader.openReadOnlySource(io, file, source, allocator, options);
}

pub const EditOptions = struct {
    offset: u64 = 0,
};

pub const EditError = ReadError || OpenError || Io.File.WritePositionalError || std.mem.Allocator.Error || error{
    NotEnoughSpace,
    TooManyExtents,
    RootPathForbidden,
    IsDirectory,
    UnsupportedEditLayout,
};

/// Live per-group free-space bookkeeping used by `Editor`. Unlike the
/// populate-time `GroupLayout` (which is only ever derived from a
/// from-scratch allocation plan), this mirrors the *actual* on-disk bitmap
/// bytes so blocks/inodes freed by earlier edits in the same session can be
/// reused, and so freeing never has to touch bits outside the group's real
/// data/inode region.
const EditGroupState = struct {
    start_block: u64,
    block_count: u32,
    data_capacity: u32,
    used_data_blocks: u32,
    used_inode_count: u32,
    used_dir_count: u32,
    block_bitmap_block: u32,
    inode_bitmap_block: u32,
    /// `bg_itable_unused`, preserved byte-for-byte from the original image.
    /// This counts inode-table slots at the *tail* of the group that have
    /// never been written at all (letting e2fsck skip scanning them) --
    /// it is only ever correct to compute fresh from
    /// `inodes_per_group - used_inode_count` when usage is guaranteed
    /// contiguous from index 0, which is only true for a brand-new
    /// populate()/resize() layout. Editor only ever deletes/overwrites
    /// existing entries (never allocates a new inode), so this count can
    /// never legitimately change during an edit session and must be
    /// carried through unmodified -- recomputing it from the live
    /// (post-deletion, holey) used_inode_count would make e2fsck treat
    /// still-valid inodes in the middle of the range as uninitialized.
    itable_unused: u16,
};

fn bitTest(bitmap: []const u8, index: u32) bool {
    return (bitmap[index / 8] & (@as(u8, 1) << @intCast(index % 8))) != 0;
}

fn bitClear(bitmap: []u8, index: u32) void {
    bitmap[index / 8] &= ~(@as(u8, 1) << @intCast(index % 8));
}

fn inodeBlockSectors(data_block_count: u32, has_external_xattr_block: bool) u32 {
    var block_count = data_block_count;
    if (has_external_xattr_block) block_count += 1;
    return block_count * sectors_per_block;
}

/// Targeted, in-place editor for images produced by this module's own
/// `populate()`/`resize()`. Supports deleting or overwriting *existing*
/// paths only -- creating a brand-new path that doesn't already exist is
/// out of scope (see issue #109). Deliberately restricted to the exact
/// on-disk shape this writer always emits (32-byte group descriptors,
/// 128-byte inodes, 4096-byte blocks): `open()` rejects anything else with
/// `error.UnsupportedEditLayout` rather than risk silently mis-editing a
/// layout it doesn't fully understand.
pub const Editor = struct {
    reader: Reader,
    allocator: std.mem.Allocator,
    groups: []EditGroupState,
    block_bitmaps: [][]u8,
    inode_bitmaps: [][]u8,
    group_dirty: []bool,
    sb: [superblock_size]u8,
    sb_dirty: bool,

    pub fn open(io: Io, file: Io.File, allocator: std.mem.Allocator, options: EditOptions) EditError!Editor {
        var reader = try Reader.open(io, file, allocator, .{ .offset = options.offset });
        errdefer reader.deinit();

        if (!supportedInodeSize(reader.inode_size)) return error.UnsupportedEditLayout;
        if (reader.blocks_per_group != default_blocks_per_group) return error.UnsupportedEditLayout;
        if (reader.feature_compat & ~writer_feature_compat != 0) return error.UnsupportedEditLayout;
        if (reader.feature_incompat != writer_feature_incompat) return error.UnsupportedEditLayout;
        if (reader.feature_ro_compat & ~(writer_feature_ro_compat_base | writer_feature_ro_compat_optional) != 0) return error.UnsupportedEditLayout;

        var sb: [superblock_size]u8 = undefined;
        _ = try file.readPositionalAll(io, &sb, options.offset + superblock_offset);
        const desc_size = blk: {
            const raw = readInt(u16, sb[0xFE..0x100]);
            break :blk if (raw == 0) @as(u16, 32) else raw;
        };
        if (desc_size != group_desc_size) return error.UnsupportedEditLayout;

        const group_count = reader.groups.len;
        const gdt_blocks = @max(@as(u32, 1), blocksForBytes(@as(u64, group_count) * group_desc_size, reader.block_size));
        const gdt_storage_bytes = @as(usize, gdt_blocks) * reader.block_size;
        const gdt = try allocator.alloc(u8, gdt_storage_bytes);
        defer allocator.free(gdt);
        @memset(gdt, 0);
        _ = try file.readPositionalAll(io, gdt, options.offset + @as(u64, reader.block_size));

        const groups = try allocator.alloc(EditGroupState, group_count);
        errdefer allocator.free(groups);
        const block_bitmaps = try allocator.alloc([]u8, group_count);
        errdefer allocator.free(block_bitmaps);
        const inode_bitmaps = try allocator.alloc([]u8, group_count);
        errdefer allocator.free(inode_bitmaps);
        const group_dirty = try allocator.alloc(bool, group_count);
        errdefer allocator.free(group_dirty);
        @memset(group_dirty, false);

        var loaded: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < loaded) : (i += 1) {
                allocator.free(block_bitmaps[i]);
                allocator.free(inode_bitmaps[i]);
            }
        }

        var group_index: usize = 0;
        while (group_index < group_count) : (group_index += 1) {
            const start_block = @as(u64, group_index) * reader.blocks_per_group;
            const block_count: u32 = @intCast(@min(@as(u64, reader.blocks_per_group), reader.total_blocks - start_block));
            const has_super_copy = group_index == 0 or isSparseSuperGroup(@intCast(group_index));
            const super_gdt_blocks: u32 = if (has_super_copy) 1 + gdt_blocks else 0;
            const reserved_block_count = super_gdt_blocks + 2 + divCeil(reader.inodes_per_group * @as(u32, reader.inode_size), reader.block_size);
            if (reserved_block_count >= block_count) return error.UnsupportedEditLayout;

            const rgroup = reader.groups[group_index];
            if (rgroup.block_bitmap_block != @as(u32, @intCast(start_block + super_gdt_blocks)) or
                rgroup.inode_bitmap_block != @as(u32, @intCast(start_block + super_gdt_blocks + 1)) or
                rgroup.inode_table_block != @as(u32, @intCast(start_block + super_gdt_blocks + 2)))
            {
                return error.UnsupportedEditLayout;
            }

            const desc_base = group_index * group_desc_size;
            const free_blocks = readInt(u16, gdt[desc_base + 12 .. desc_base + 14]);
            const free_inodes = readInt(u16, gdt[desc_base + 14 .. desc_base + 16]);
            const used_dirs = readInt(u16, gdt[desc_base + 16 .. desc_base + 18]);
            const itable_unused = readInt(u16, gdt[desc_base + 0x1C .. desc_base + 0x1E]);
            const data_capacity = block_count - reserved_block_count;

            block_bitmaps[group_index] = try allocator.alloc(u8, reader.block_size);
            _ = try file.readPositionalAll(io, block_bitmaps[group_index], reader.blockOffset(rgroup.block_bitmap_block));
            inode_bitmaps[group_index] = try allocator.alloc(u8, reader.block_size);
            _ = try file.readPositionalAll(io, inode_bitmaps[group_index], reader.blockOffset(rgroup.inode_bitmap_block));
            loaded += 1;

            groups[group_index] = .{
                .start_block = start_block,
                .block_count = block_count,
                .data_capacity = data_capacity,
                .used_data_blocks = data_capacity - free_blocks,
                .used_inode_count = reader.inodes_per_group - free_inodes,
                .used_dir_count = used_dirs,
                .block_bitmap_block = rgroup.block_bitmap_block,
                .inode_bitmap_block = rgroup.inode_bitmap_block,
                .itable_unused = itable_unused,
            };
        }

        return .{
            .reader = reader,
            .allocator = allocator,
            .groups = groups,
            .block_bitmaps = block_bitmaps,
            .inode_bitmaps = inode_bitmaps,
            .group_dirty = group_dirty,
            .sb = sb,
            .sb_dirty = false,
        };
    }

    /// Frees in-memory state without writing anything back. Call `flush()`
    /// first if pending edits should be persisted.
    pub fn deinit(self: *Editor) void {
        for (self.block_bitmaps) |bitmap| self.allocator.free(bitmap);
        for (self.inode_bitmaps) |bitmap| self.allocator.free(bitmap);
        self.allocator.free(self.block_bitmaps);
        self.allocator.free(self.inode_bitmaps);
        self.allocator.free(self.groups);
        self.allocator.free(self.group_dirty);
        self.reader.deinit();
        self.* = undefined;
    }

    /// Writes every group whose bitmaps/descriptor changed since `open()`,
    /// plus the superblock's global free-space counters, to the primary
    /// superblock and every sparse-super backup copy -- mirroring the
    /// existing `resize()` write pattern.
    pub fn flush(self: *Editor, io: Io) EditError!void {
        var any_group_dirty = false;
        for (self.group_dirty) |dirty| {
            if (dirty) any_group_dirty = true;
        }
        if (!any_group_dirty and !self.sb_dirty) return;

        if (any_group_dirty) {
            const group_count = self.groups.len;
            const gdt_blocks = @max(@as(u32, 1), blocksForBytes(@as(u64, group_count) * group_desc_size, self.reader.block_size));
            const gdt_storage_bytes = @as(usize, gdt_blocks) * self.reader.block_size;
            const gdt = try self.allocator.alloc(u8, gdt_storage_bytes);
            defer self.allocator.free(gdt);
            @memset(gdt, 0);
            _ = try self.reader.file.readPositionalAll(io, gdt, self.reader.offset + @as(u64, self.reader.block_size));

            for (self.groups, 0..) |group, index| {
                if (!self.group_dirty[index]) continue;
                try self.reader.file.writePositionalAll(io, self.block_bitmaps[index], self.reader.blockOffset(group.block_bitmap_block));
                try self.reader.file.writePositionalAll(io, self.inode_bitmaps[index], self.reader.blockOffset(group.inode_bitmap_block));

                const desc_base = index * group_desc_size;
                const desc = gdt[desc_base .. desc_base + group_desc_size];
                writeInt(u16, desc[12..14], @intCast(group.data_capacity - group.used_data_blocks));
                writeInt(u16, desc[14..16], @intCast(self.reader.inodes_per_group - group.used_inode_count));
                writeInt(u16, desc[16..18], @intCast(group.used_dir_count));
                writeInt(u16, desc[0x18..0x1A], @truncate(bitmapChecksum(self.reader.uuid, self.block_bitmaps[index], default_blocks_per_group / 8)));
                writeInt(u16, desc[0x1A..0x1C], @truncate(bitmapChecksum(self.reader.uuid, self.inode_bitmaps[index], self.reader.inodes_per_group / 8)));
                // Deliberately *not* recomputed from used_inode_count -- see
                // EditGroupState.itable_unused's doc comment.
                writeInt(u16, desc[0x1C..0x1E], group.itable_unused);
                writeInt(u16, desc[0x1E..0x20], 0);
                var group_le = std.mem.nativeToLittle(u32, @as(u32, @intCast(index)));
                writeInt(u16, desc[0x1E..0x20], @truncate(ext4Crc32c(&.{
                    &self.reader.uuid,
                    std.mem.asBytes(&group_le),
                    desc,
                })));
            }

            try self.reader.file.writePositionalAll(io, gdt, self.reader.offset + @as(u64, self.reader.block_size));
            for (self.groups, 0..) |group, index| {
                if (index == 0 or !isSparseSuperGroup(@intCast(index))) continue;
                try self.reader.file.writePositionalAll(io, gdt, self.reader.offset + (group.start_block + 1) * self.reader.block_size);
            }
        }

        var free_blocks: u32 = 0;
        var free_inodes: u32 = 0;
        for (self.groups) |group| {
            free_blocks += group.data_capacity - group.used_data_blocks;
            free_inodes += self.reader.inodes_per_group - group.used_inode_count;
        }
        writeInt(u32, self.sb[0x0C..0x10], free_blocks);
        writeInt(u32, self.sb[0x10..0x14], free_inodes);
        writeInt(u16, self.sb[0x5A..0x5C], 0);
        setSuperblockChecksum(&self.sb);
        try self.reader.file.writePositionalAll(io, &self.sb, self.reader.offset + superblock_offset);
        for (self.groups, 0..) |group, index| {
            if (index == 0 or !isSparseSuperGroup(@intCast(index))) continue;
            writeInt(u16, self.sb[0x5A..0x5C], @intCast(index));
            setSuperblockChecksum(&self.sb);
            try self.reader.file.writePositionalAll(io, &self.sb, self.reader.offset + group.start_block * self.reader.block_size);
        }

        self.sb_dirty = false;
        @memset(self.group_dirty, false);
    }

    /// Flushes pending edits (if any) and frees in-memory state.
    pub fn close(self: *Editor, io: Io) EditError!void {
        try self.flush(io);
        self.deinit();
    }

    /// Marks one physical data block free in its group's live bitmap, if it
    /// was actually marked used. Safe to call more than once for the same
    /// block (a double-free is a silent no-op rather than an error, since
    /// callers may legitimately re-encounter a block while walking an
    /// extent tree that happens to alias metadata, e.g. a reused xattr
    /// block referenced from more than one place is not something this
    /// writer ever produces, but this keeps the mutator defensive).
    fn freeBlock(self: *Editor, physical_block: u64) void {
        const group_index: usize = @intCast(physical_block / self.reader.blocks_per_group);
        const group = &self.groups[group_index];
        const bit_index: u32 = @intCast(physical_block - group.start_block);
        const bitmap = self.block_bitmaps[group_index];
        if (bitTest(bitmap, bit_index)) {
            bitClear(bitmap, bit_index);
            group.used_data_blocks -= 1;
            self.group_dirty[group_index] = true;
            self.sb_dirty = true;
        }
    }

    /// Allocates `block_count` data blocks, greedily preferring contiguous
    /// runs within a group to minimize the resulting extent count (mirrors
    /// the populate-time `BlockAllocator`, but scans a live bitmap with
    /// holes instead of bump-allocating from an empty group). On
    /// `error.NotEnoughSpace`, any blocks already claimed by this call are
    /// rolled back before returning.
    fn allocateExtents(self: *Editor, allocator: std.mem.Allocator, block_count: u32) EditError![]Extent {
        var extents = std.array_list.Managed(Extent).init(allocator);
        errdefer extents.deinit();
        var remaining = block_count;
        var logical: u32 = 0;

        for (self.groups, 0..) |*group, group_index| {
            if (remaining == 0) break;
            if (group.used_data_blocks >= group.data_capacity) continue;

            const bitmap = self.block_bitmaps[group_index];
            var bit_index: u32 = 0;
            while (bit_index < group.block_count and remaining > 0) {
                if (bitTest(bitmap, bit_index)) {
                    bit_index += 1;
                    continue;
                }
                const run_start = bit_index;
                var run_len: u32 = 0;
                while (bit_index < group.block_count and run_len < remaining and !bitTest(bitmap, bit_index)) : (bit_index += 1) {
                    run_len += 1;
                }
                var i = run_start;
                while (i < run_start + run_len) : (i += 1) setBitmapBit(bitmap, i);
                group.used_data_blocks += run_len;
                self.group_dirty[group_index] = true;
                self.sb_dirty = true;
                try extents.append(.{
                    .logical_block = logical,
                    .start_block = group.start_block + run_start,
                    .block_count = @intCast(run_len),
                });
                logical += run_len;
                remaining -= run_len;
            }
        }

        if (remaining > 0) {
            for (extents.items) |extent| {
                var n: u16 = 0;
                while (n < extent.block_count) : (n += 1) self.freeBlock(extent.start_block + n);
            }
            extents.deinit();
            return error.NotEnoughSpace;
        }
        return extents.toOwnedSlice();
    }

    /// Marks one inode free in its group's live inode bitmap, if it was
    /// actually marked used, and decrements the group's directory count too
    /// when `is_dir` is set.
    fn freeInodeBit(self: *Editor, inode_number: u32, is_dir: bool) void {
        const group_index: usize = (inode_number - 1) / self.reader.inodes_per_group;
        const index_in_group: u32 = @intCast((inode_number - 1) % self.reader.inodes_per_group);
        const group = &self.groups[group_index];
        const bitmap = self.inode_bitmaps[group_index];
        if (bitTest(bitmap, index_in_group)) {
            bitClear(bitmap, index_in_group);
            group.used_inode_count -= 1;
            if (is_dir and group.used_dir_count > 0) group.used_dir_count -= 1;
            self.group_dirty[group_index] = true;
            self.sb_dirty = true;
        }
    }

    /// Recursively walks an extent tree exactly like the Reader's
    /// `appendExtentTreeEntries`, but collects both the leaf extents' data
    /// blocks *and* every interior/index node's own physical block number,
    /// since deleting or truncating an inode must free the extent-tree
    /// metadata blocks too, not just the data they describe.
    fn collectExtentTreeBlocks(
        self: *Editor,
        io: Io,
        node_bytes: []const u8,
        node_capacity: usize,
        expected_depth: ?u16,
        leaf_extents: *std.array_list.Managed(Extent),
        index_blocks: *std.array_list.Managed(u64),
    ) EditError!void {
        const header = try parseExtentHeader(node_bytes[0..extent_header_size]);
        if (expected_depth) |depth| {
            if (header.depth != depth) return error.UnsupportedInodeLayout;
        }
        if (header.depth > max_supported_extent_depth) return error.UnsupportedExtentDepth;
        if (header.entries > header.max or header.max > node_capacity) return error.UnsupportedInodeLayout;

        var entry_index: usize = 0;
        if (header.depth == 0) {
            while (entry_index < header.entries) : (entry_index += 1) {
                const base = extent_header_size + entry_index * extent_entry_size;
                try leaf_extents.append(decodeExtent(node_bytes[base .. base + extent_entry_size]));
            }
            return;
        }

        var child_block: [default_block_size]u8 = undefined;
        while (entry_index < header.entries) : (entry_index += 1) {
            const base = extent_header_size + entry_index * extent_entry_size;
            const child = decodeExtentIndex(node_bytes[base .. base + extent_entry_size]);
            try index_blocks.append(child.leaf_block);
            _ = try self.reader.file.readPositionalAll(io, &child_block, self.reader.blockOffset(child.leaf_block));
            try self.collectExtentTreeBlocks(
                io,
                child_block[0..],
                extentEntriesPerBlock(self.reader.block_size),
                header.depth - 1,
                leaf_extents,
                index_blocks,
            );
        }
    }

    /// Frees every block backing an inode's content: all extent-tree leaf
    /// (data) blocks, all interior/index extent-tree blocks, and (when
    /// `free_xattr` is set) the external xattr block. Fast symlinks store
    /// their target inline in `i_block` and own no separate blocks at all,
    /// so they are a deliberate no-op here.
    fn freeInodeAllocations(self: *Editor, io: Io, inode: ParsedInode, free_xattr: bool) EditError!void {
        if (inode.kind == .symlink and inode.isFastSymlink()) {
            if (free_xattr and inode.file_acl_block != 0) self.freeBlock(inode.file_acl_block);
            return;
        }
        if ((inode.flags & inode_flag_extents) == 0) return error.UnsupportedInodeLayout;

        var leaf_extents = std.array_list.Managed(Extent).init(self.allocator);
        defer leaf_extents.deinit();
        var index_blocks = std.array_list.Managed(u64).init(self.allocator);
        defer index_blocks.deinit();
        try self.collectExtentTreeBlocks(io, inode.block_bytes[0..], max_inline_extents, null, &leaf_extents, &index_blocks);

        for (leaf_extents.items) |extent| {
            var n: u16 = 0;
            while (n < extent.block_count) : (n += 1) self.freeBlock(extent.start_block + n);
        }
        for (index_blocks.items) |block_number| self.freeBlock(block_number);
        if (free_xattr and inode.file_acl_block != 0) self.freeBlock(inode.file_acl_block);
    }

    /// Scans a directory's data block-by-block (never the flattened,
    /// whole-directory buffer `listDirByInode` uses) to find exactly which
    /// physical block holds a named entry, since directory-leaf checksums
    /// are computed per block and only that one block needs to be rewritten
    /// to splice an entry out.
    fn findDirEntry(self: *Editor, io: Io, dir_inode: ParsedInode, name: []const u8) EditError!FoundDirEntry {
        const extents = try self.reader.readInodeExtentsAlloc(io, self.allocator, dir_inode);
        defer self.allocator.free(extents);

        for (extents) |extent| {
            var block_in_extent: u16 = 0;
            while (block_in_extent < extent.block_count) : (block_in_extent += 1) {
                const physical_block = extent.start_block + block_in_extent;
                var block: [default_block_size]u8 = undefined;
                _ = try self.reader.file.readPositionalAll(io, &block, self.reader.blockOffset(physical_block));

                var offset: usize = 0;
                var prev_offset: ?usize = null;
                while (offset + 8 <= block.len) {
                    const child_inode = readInt(u32, block[offset .. offset + 4]);
                    const rec_len = readInt(u16, block[offset + 4 .. offset + 6]);
                    const name_len = block[offset + 6];
                    if (rec_len < 8 or offset + rec_len > block.len) return error.BadDirectoryEntry;
                    if (name_len > rec_len - 8) return error.BadDirectoryEntry;
                    if (child_inode != 0 and name_len == name.len and std.mem.eql(u8, block[offset + 8 .. offset + 8 + name_len], name)) {
                        return .{
                            .physical_block = physical_block,
                            .block = block,
                            .entry_offset = offset,
                            .prev_offset = prev_offset,
                            .inode = child_inode,
                        };
                    }
                    prev_offset = offset;
                    offset += rec_len;
                }
            }
        }
        return error.NotFound;
    }

    /// Splices a directory entry out of its containing block: merges its
    /// `rec_len` into the immediately preceding entry in the same block
    /// (the standard ext4 `ext4_delete_entry()` technique -- no data
    /// movement needed, since `rec_len` simply grows to span the freed
    /// space), or if it was the first entry in the block, just zeroes its
    /// inode field (already tolerated everywhere this codebase scans
    /// directory entries, exactly like htree index blocks that
    /// "masquerade as unused directory entries"). Recomputes and writes
    /// back only that one block.
    fn spliceDirEntry(self: *Editor, io: Io, found: FoundDirEntry, dir_inode_number: u32) EditError!void {
        var block = found.block;
        const rec_len = readInt(u16, block[found.entry_offset + 4 .. found.entry_offset + 6]);
        if (found.prev_offset) |prev_off| {
            const prev_rec_len = readInt(u16, block[prev_off + 4 .. prev_off + 6]);
            writeInt(u16, block[prev_off + 4 .. prev_off + 6], prev_rec_len + rec_len);
        } else {
            writeInt(u32, block[found.entry_offset .. found.entry_offset + 4], 0);
        }
        setDirectoryLeafChecksum(&block, self.reader.uuid, dir_inode_number, 0);
        try self.reader.file.writePositionalAll(io, &block, self.reader.blockOffset(found.physical_block));
    }

    /// Removes `name`'s directory entry from `parent_inode_number`'s data.
    fn removeDirEntryFromParent(self: *Editor, io: Io, parent_inode_number: u32, name: []const u8) EditError!void {
        const parent_inode = try self.reader.readInode(io, parent_inode_number);
        if (parent_inode.kind != .directory) return error.NotDirectory;
        const found = try self.findDirEntry(io, parent_inode, name);
        try self.spliceDirEntry(io, found, parent_inode_number);
    }

    fn inodeLocation(self: Editor, inode_number: u32) u64 {
        const group_index = (inode_number - 1) / self.reader.inodes_per_group;
        const index_in_group = (inode_number - 1) % self.reader.inodes_per_group;
        const rgroup = self.reader.groups[group_index];
        return self.reader.blockOffset(rgroup.inode_table_block) + @as(u64, index_in_group) * self.reader.inode_size;
    }

    /// The image's own inode size decides how much of the storage is live.
    /// Reading or writing a fixed 128 bytes would leave the extra region of
    /// a 256-byte inode stale, and hashing the whole array would checksum
    /// bytes that are not part of the inode.
    const RawInode = struct {
        storage: [max_supported_reader_inode_size]u8,
        len: u16,

        fn bytes(self: *RawInode) []u8 {
            return self.storage[0..self.len];
        }
    };

    fn readInodeRaw(self: Editor, io: Io, inode_number: u32) EditError!RawInode {
        var raw: RawInode = .{ .storage = undefined, .len = self.reader.inode_size };
        _ = try self.reader.file.readPositionalAll(io, raw.bytes(), self.inodeLocation(inode_number));
        return raw;
    }

    fn writeInodeRaw(self: Editor, io: Io, inode_number: u32, raw: *RawInode) EditError!void {
        try self.reader.file.writePositionalAll(io, raw.bytes(), self.inodeLocation(inode_number));
    }

    /// Decrements a regular file's or symlink's `i_links_count`. This
    /// writer never creates hardlinked regular files (`FileTreeView` has no
    /// hardlink concept), so in practice `link_count` is always 1 and this
    /// always frees the inode -- but decrementing rather than
    /// force-freeing handles a hand-crafted or externally-hardlinked image
    /// correctly too, only retiring the inode once its last reference is
    /// gone.
    fn decrementLinkCountAndMaybeFree(self: *Editor, io: Io, inode_number: u32, kind: Kind) EditError!void {
        var raw = try self.readInodeRaw(io, inode_number);
        const buf = raw.bytes();
        const link_count = readInt(u16, buf[26..28]);
        if (link_count == 0) return;
        if (link_count == 1) {
            const parsed = try ParsedInode.fromBytes(inode_number, buf);
            try self.freeInodeAllocations(io, parsed, true);
            @memset(buf, 0);
            try self.writeInodeRaw(io, inode_number, &raw);
            self.freeInodeBit(inode_number, kind == .directory);
        } else {
            writeInt(u16, buf[26..28], link_count - 1);
            setInodeChecksum(buf, self.reader.uuid, inode_number);
            try self.writeInodeRaw(io, inode_number, &raw);
        }
    }

    /// Directories can never be hardlinked in POSIX/ext4 -- any link count
    /// above 1 is purely structural (its own "." plus one per subdirectory
    /// child's ".."), never a "real" extra reference -- so a directory
    /// being fully removed is always safe to force-retire outright, unlike
    /// the decrement-and-maybe-free handling regular files need.
    fn forceRetireDirectory(self: *Editor, io: Io, inode_number: u32) EditError!void {
        var raw = try self.readInodeRaw(io, inode_number);
        const parsed = try ParsedInode.fromBytes(inode_number, raw.bytes());
        try self.freeInodeAllocations(io, parsed, true);
        @memset(raw.bytes(), 0);
        try self.writeInodeRaw(io, inode_number, &raw);
        self.freeInodeBit(inode_number, true);
    }

    fn decrementParentLinkCount(self: *Editor, io: Io, parent_inode_number: u32) EditError!void {
        var raw = try self.readInodeRaw(io, parent_inode_number);
        const buf = raw.bytes();
        const link_count = readInt(u16, buf[26..28]);
        if (link_count > 0) {
            writeInt(u16, buf[26..28], link_count - 1);
            setInodeChecksum(buf, self.reader.uuid, parent_inode_number);
            try self.writeInodeRaw(io, parent_inode_number, &raw);
        }
    }

    /// Recursively retires an inode and everything beneath it (for
    /// directories), freeing every block and inode along the way, but
    /// without touching any directory entries -- the caller is responsible
    /// for splicing the top-level entry out of its parent, since every
    /// entry *within* a subtree being fully destroyed is irrelevant (the
    /// whole subtree's blocks/inodes are being freed regardless of their
    /// logical occupancy).
    fn retireRecursively(self: *Editor, io: Io, inode_number: u32) EditError!void {
        const inode = try self.reader.readInode(io, inode_number);
        if (inode.kind == .directory) {
            const children = try self.reader.listDirByInode(io, self.allocator, inode);
            defer freeDirEntries(self.allocator, children);
            for (children) |entry| try self.retireRecursively(io, entry.inode);
            try self.forceRetireDirectory(io, inode_number);
        } else {
            try self.decrementLinkCountAndMaybeFree(io, inode_number, inode.kind);
        }
    }

    /// Deletes an existing regular file or symlink at `path`. Use
    /// `deleteTree` for directories.
    pub fn deleteFile(self: *Editor, io: Io, path: []const u8) EditError!void {
        const split = try splitParentAndName(path);
        const parent_inode_number = try self.reader.lookupPath(io, split.parent);
        const child_inode_number = try self.reader.lookupChild(io, parent_inode_number, split.name);
        const child_inode = try self.reader.readInode(io, child_inode_number);
        if (child_inode.kind == .directory) return error.IsDirectory;
        try self.decrementLinkCountAndMaybeFree(io, child_inode_number, child_inode.kind);
        try self.removeDirEntryFromParent(io, parent_inode_number, split.name);
    }

    /// Recursively deletes an existing path -- a single file/symlink, or a
    /// directory and everything beneath it. Creating a brand-new path that
    /// doesn't already exist remains out of scope; only deleting or
    /// overwriting existing entries is supported.
    pub fn deleteTree(self: *Editor, io: Io, path: []const u8) EditError!void {
        const split = try splitParentAndName(path);
        const parent_inode_number = try self.reader.lookupPath(io, split.parent);
        const child_inode_number = try self.reader.lookupChild(io, parent_inode_number, split.name);
        const child_inode = try self.reader.readInode(io, child_inode_number);
        try self.retireRecursively(io, child_inode_number);
        try self.removeDirEntryFromParent(io, parent_inode_number, split.name);
        if (child_inode.kind == .directory) try self.decrementParentLinkCount(io, parent_inode_number);
    }

    /// Overwrites the content of an existing regular file. Extended
    /// attributes are preserved (only the data content is replaced); this
    /// is not a general truncate/rewrite -- it always replaces the whole
    /// file. Fragmentation is bounded: the new content is allocated as
    /// contiguous runs greedily, and if that still needs more than
    /// `max_inline_extents` (4) extents, the allocation is rolled back and
    /// `error.TooManyExtents` is returned rather than building a deeper
    /// extent tree (a deliberate v1 scope limit -- see issue #109). The new
    /// content is always written to freshly allocated blocks *before* the
    /// old content is freed (needing up to `new_block_count` blocks of
    /// headroom beyond the old file's own size), so a failed overwrite
    /// never leaves the original file half-freed with nothing valid in its
    /// place.
    pub fn writeFile(self: *Editor, io: Io, path: []const u8, content: []const u8) EditError!void {
        const split = try splitParentAndName(path);
        const parent_inode_number = try self.reader.lookupPath(io, split.parent);
        const child_inode_number = try self.reader.lookupChild(io, parent_inode_number, split.name);
        const child_inode = try self.reader.readInode(io, child_inode_number);
        if (child_inode.kind != .file) return error.NotFile;

        const block_size = self.reader.block_size;
        const new_block_count: u32 = if (content.len == 0) 0 else @intCast(divCeil(@as(u64, content.len), block_size));

        var new_extents: []Extent = &.{};
        if (new_block_count > 0) new_extents = try self.allocateExtents(self.allocator, new_block_count);
        defer if (new_block_count > 0) self.allocator.free(new_extents);

        if (new_extents.len > max_inline_extents) {
            for (new_extents) |extent| {
                var n: u16 = 0;
                while (n < extent.block_count) : (n += 1) self.freeBlock(extent.start_block + n);
            }
            return error.TooManyExtents;
        }

        // Only now that the new content's space is fully secured, release
        // the file's old content.
        try self.freeInodeAllocations(io, child_inode, false);

        var scratch: [default_block_size]u8 = undefined;
        var written: u64 = 0;
        for (new_extents) |extent| {
            var block_in_extent: u16 = 0;
            while (block_in_extent < extent.block_count) : (block_in_extent += 1) {
                @memset(&scratch, 0);
                const remaining = content.len - written;
                const want: usize = @intCast(@min(@as(u64, block_size), remaining));
                if (want > 0) @memcpy(scratch[0..want], content[written .. written + want]);
                const physical_block = extent.start_block + block_in_extent;
                try self.reader.file.writePositionalAll(io, &scratch, self.reader.blockOffset(physical_block));
                written += want;
            }
        }

        var raw = try self.readInodeRaw(io, child_inode_number);
        const buf = raw.bytes();
        writeInt(u32, buf[4..8], @truncate(content.len));
        writeInt(u32, buf[108..112], @as(u32, @truncate(@as(u64, content.len) >> 32)));
        writeInt(u32, buf[28..32], inodeBlockSectors(new_block_count, child_inode.file_acl_block != 0));
        var extent_root: [60]u8 = [_]u8{0} ** 60;
        encodeExtentLeafNode(extent_root[0..], max_inline_extents, new_extents);
        @memcpy(buf[40..100], &extent_root);
        writeInt(u32, buf[32..36], readInt(u32, buf[32..36]) | inode_flag_extents);
        setInodeChecksum(buf, self.reader.uuid, child_inode_number);
        try self.writeInodeRaw(io, child_inode_number, &raw);

        // Match populate()'s own convention of setting the large-file
        // ro_compat bit once any file exceeds 2 GiB, for consistency with
        // images this writer creates from scratch.
        if (content.len >= 2 * 1024 * 1024 * 1024) {
            const ro_compat = readInt(u32, self.sb[0x64..0x68]);
            if (ro_compat & feature_ro_compat_large_file == 0) {
                writeInt(u32, self.sb[0x64..0x68], ro_compat | feature_ro_compat_large_file);
                self.sb_dirty = true;
            }
        }
    }
};

const FoundDirEntry = struct {
    physical_block: u64,
    block: [default_block_size]u8,
    entry_offset: usize,
    prev_offset: ?usize,
    inode: u32,
};

/// Splits a path into its parent directory and final component, matching
/// `Reader.lookupPath`'s own root/trailing-slash tolerance. Returns
/// `error.RootPathForbidden` for `""`/`"/"`, since delete/overwrite always
/// need an existing named entry to act on.
fn splitParentAndName(path: []const u8) EditError!struct { parent: []const u8, name: []const u8 } {
    var trimmed = path;
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') trimmed = trimmed[0 .. trimmed.len - 1];
    if (trimmed.len == 0) return error.RootPathForbidden;
    if (std.mem.lastIndexOfScalar(u8, trimmed, '/')) |index| {
        return .{ .parent = trimmed[0..index], .name = trimmed[index + 1 ..] };
    }
    return .{ .parent = "", .name = trimmed };
}

const ReaderGroup = struct {
    block_bitmap_block: u32,
    inode_bitmap_block: u32,
    inode_table_block: u32,
    free_block_count: u16,
    free_inode_count: u16,
    used_directory_count: u16,
    block_bitmap_checksum: u16,
    inode_bitmap_checksum: u16,
    descriptor_checksum: u16,
};

const ParsedInode = struct {
    inode: u32,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    atime: u32,
    ctime: u32,
    mtime: u32,
    deletion_time: u32,
    sector_count: u32,
    generation: u32,
    flags: u32,
    file_acl_block: u32,
    link_count: u16,
    block_bytes: [60]u8,

    fn fromBytes(inode_number: u32, buf: []const u8) ReadError!ParsedInode {
        const full_mode = readInt(u16, buf[0..2]);
        const kind = modeToKind(full_mode) orelse return error.UnsupportedInodeLayout;
        var block_bytes: [60]u8 = undefined;
        @memcpy(&block_bytes, buf[40..100]);
        return .{
            .inode = inode_number,
            .kind = kind,
            .mode = full_mode & 0x0FFF,
            .uid = readInt(u16, buf[2..4]) | (@as(u32, readInt(u16, buf[120..122])) << 16),
            .gid = readInt(u16, buf[24..26]) | (@as(u32, readInt(u16, buf[122..124])) << 16),
            .size = readInt(u32, buf[4..8]) | (@as(u64, readInt(u32, buf[108..112])) << 32),
            .atime = readInt(u32, buf[8..12]),
            .ctime = readInt(u32, buf[12..16]),
            .mtime = readInt(u32, buf[16..20]),
            .deletion_time = readInt(u32, buf[20..24]),
            .sector_count = readInt(u32, buf[28..32]),
            .generation = readInt(u32, buf[100..104]),
            .flags = readInt(u32, buf[32..36]),
            .file_acl_block = readInt(u32, buf[104..108]),
            .link_count = readInt(u16, buf[26..28]),
            .block_bytes = block_bytes,
        };
    }

    fn stat(self: ParsedInode) Stat {
        return .{
            .inode = self.inode,
            .kind = self.kind,
            .mode = self.mode,
            .uid = self.uid,
            .gid = self.gid,
            .size = self.size,
        };
    }

    fn isFastSymlink(self: ParsedInode) bool {
        // Must match the writer's fast-symlink eligibility check exactly
        // (see the `.symlink =>` case in buildPlan's node-sizing loop) --
        // real ext4 requires `strlen < 60` for inline storage (see issue #74).
        return self.kind == .symlink and self.size < 60 and (self.flags & inode_flag_extents) == 0;
    }
};

/// The only ext4 source profile accepted by the rootless rebuild importer.
/// It is intentionally the exact feature/layout subset emitted by this
/// module's writer, not a promise to ingest general ext4 filesystems.
pub const StrictProfile = enum {
    zvmi_ext4_v1,
};

pub const StrictFilesystemIdentity = struct {
    profile: StrictProfile = .zvmi_ext4_v1,
    uuid: [16]u8,
    /// Exact on-disk 16-byte volume-name field, including embedded/trailing
    /// NUL bytes.
    label: [16]u8,
    block_size: u32,
    filesystem_length: u64,
    global_timestamp: u32,
};

pub const StrictScanOptions = struct {
    /// The selected partition must be exactly this long. Padding or trailers
    /// after the ext4 block range are rejected.
    expected_length: u64,
    max_nodes: usize = limit_defaults.max_nodes,
    max_path_bytes: usize = limit_defaults.max_path_bytes,
    max_component_bytes: usize = limit_defaults.max_component_bytes,
    max_file_bytes: u64 = limit_defaults.max_file_bytes,
    max_total_bytes: u64 = limit_defaults.max_total_bytes,
    max_xattrs_per_node: usize = limit_defaults.max_xattrs_per_node,
    max_xattr_bytes_per_node: usize = limit_defaults.max_xattr_bytes_per_node,
    max_scan_metadata_bytes: usize = limit_defaults.max_scan_metadata_bytes,
    /// Optional sink for the peak measurements and the first limit breach.
    /// The scanner is torn down before `scanWriterCompatible` returns, so a
    /// failure can only report through a sink the caller still owns.
    diagnostic: ?*limits_mod.Diagnostic = null,
};

const StrictContent = struct {
    reader: *Reader,
    io: Io,
    inode: ParsedInode,
};

const StrictEntry = struct {
    path: []u8,
    inode: ParsedInode,
    xattrs: []OwnedXattr,
    xattr_views: []Xattr,
    content: StrictContent,
};

/// An exhaustively validated, deterministic tree view. Paths/xattrs are
/// owned, while file bytes remain in the read-only source until a caller
/// imports the view into its own spool.
pub const StrictTree = struct {
    allocator: std.mem.Allocator,
    entries: []StrictEntry,
    identity: StrictFilesystemIdentity,
    /// Guest-visible file bytes. An importer spools a full copy of exactly
    /// this many bytes, so it is also the scratch space an import needs.
    content_bytes: u64,
    iteration_index: usize = 0,
    view: FileTreeView = undefined,

    pub fn deinit(self: *StrictTree) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.path);
            freeXattrs(self.allocator, entry.xattrs);
            self.allocator.free(entry.xattr_views);
        }
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn nodeCount(self: *const StrictTree) usize {
        return self.entries.len;
    }

    pub fn fileTreeView(self: *StrictTree) *FileTreeView {
        self.iteration_index = 0;
        self.view = .{
            .ctx = self,
            .next_fn = strictTreeNext,
            .reset_fn = strictTreeReset,
        };
        return &self.view;
    }
};

fn strictTreeReset(ctx: *anyopaque) void {
    const tree: *StrictTree = @ptrCast(@alignCast(ctx));
    tree.iteration_index = 0;
}

fn strictTreeNext(ctx: *anyopaque) FileTreeView.IteratorError!?FileTreeView.Entry {
    const tree: *StrictTree = @ptrCast(@alignCast(ctx));
    if (tree.iteration_index == tree.entries.len) return null;
    const entry = &tree.entries[tree.iteration_index];
    tree.iteration_index += 1;
    return .{
        .path = entry.path,
        .kind = entry.inode.kind,
        .mode = entry.inode.mode,
        .uid = entry.inode.uid,
        .gid = entry.inode.gid,
        .size = if (entry.inode.kind == .directory) 0 else entry.inode.size,
        .content = if (entry.inode.kind == .directory) null else .{
            .ctx = &entry.content,
            .read_at_fn = strictContentReadAt,
        },
        .xattrs = entry.xattr_views,
    };
}

fn strictContentReadAt(
    ctx: *const anyopaque,
    buffer: []u8,
    offset: u64,
) FileTreeView.ContentError!usize {
    const content: *const StrictContent = @ptrCast(@alignCast(ctx));
    return content.reader.preadInode(content.io, content.inode, buffer, offset) catch
        return error.ReadFailed;
}

/// Validates every allocated inode/block and returns a deterministic view of
/// the guest-visible tree. No files are created and the source is never
/// opened for writing.
pub fn scanWriterCompatible(
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    options: StrictScanOptions,
) !StrictTree {
    var scanner = try StrictScanner.init(reader, io, allocator, options);
    defer scanner.deinit();
    try scanner.scan();
    const entries = try scanner.entries.toOwnedSlice();
    return .{
        .allocator = allocator,
        .entries = entries,
        .identity = scanner.identity,
        .content_bytes = scanner.total_content_bytes,
    };
}

const StrictChild = struct {
    inode: u32,
    kind: Kind,
    name: []u8,
};

const StrictExtentResult = struct {
    extents: []Extent,
    index_block_count: u32,
};

const StrictScanner = struct {
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    options: StrictScanOptions,
    identity: StrictFilesystemIdentity,
    entries: std.array_list.Managed(StrictEntry),
    visited_inodes: []u8,
    allocated_inodes: []u8,
    owned_blocks: []u8,
    allocated_blocks: []u8,
    directories_per_group: []u32,
    total_content_bytes: u64 = 0,
    visited_inode_count: usize = 0,
    super_free_blocks: u32,
    super_free_inodes: u32,

    fn init(
        reader: *Reader,
        io: Io,
        allocator: std.mem.Allocator,
        options: StrictScanOptions,
    ) !StrictScanner {
        const identity_and_counts = try validateStrictSuperblock(reader, io, options.expected_length);
        const inode_bitmap_len = bitmapByteLength(reader.total_inodes);
        const block_bitmap_len = bitmapByteLength(reader.total_blocks);
        const bitmap_bytes = std.math.mul(
            usize,
            std.math.add(usize, inode_bitmap_len, block_bitmap_len) catch
                return error.ScanMetadataLimitExceeded,
            2,
        ) catch return error.ScanMetadataLimitExceeded;
        const directory_count_bytes = std.math.mul(usize, reader.groups.len, @sizeOf(u32)) catch
            return error.ScanMetadataLimitExceeded;
        const scan_metadata_bytes = std.math.add(
            usize,
            bitmap_bytes,
            directory_count_bytes,
        ) catch return error.ScanMetadataLimitExceeded;
        limits_mod.observe(options.diagnostic, .scan_metadata_bytes, scan_metadata_bytes);
        if (scan_metadata_bytes > options.max_scan_metadata_bytes) {
            return limits_mod.exceeded(
                options.diagnostic,
                .scan_metadata_bytes,
                scan_metadata_bytes,
                options.max_scan_metadata_bytes,
            );
        }
        const visited = try allocator.alloc(u8, inode_bitmap_len);
        errdefer allocator.free(visited);
        const allocated_inodes = try allocator.alloc(u8, inode_bitmap_len);
        errdefer allocator.free(allocated_inodes);
        const owned_blocks = try allocator.alloc(u8, block_bitmap_len);
        errdefer allocator.free(owned_blocks);
        const allocated_blocks = try allocator.alloc(u8, block_bitmap_len);
        errdefer allocator.free(allocated_blocks);
        const directories = try allocator.alloc(u32, reader.groups.len);
        errdefer allocator.free(directories);
        @memset(visited, 0);
        @memset(allocated_inodes, 0);
        @memset(owned_blocks, 0);
        @memset(allocated_blocks, 0);
        @memset(directories, 0);
        return .{
            .reader = reader,
            .io = io,
            .allocator = allocator,
            .options = options,
            .identity = identity_and_counts.identity,
            .entries = .init(allocator),
            .visited_inodes = visited,
            .allocated_inodes = allocated_inodes,
            .owned_blocks = owned_blocks,
            .allocated_blocks = allocated_blocks,
            .directories_per_group = directories,
            .super_free_blocks = identity_and_counts.free_blocks,
            .super_free_inodes = identity_and_counts.free_inodes,
        };
    }

    fn deinit(self: *StrictScanner) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.path);
            freeXattrs(self.allocator, entry.xattrs);
            self.allocator.free(entry.xattr_views);
        }
        self.entries.deinit();
        self.allocator.free(self.visited_inodes);
        self.allocator.free(self.allocated_inodes);
        self.allocator.free(self.owned_blocks);
        self.allocator.free(self.allocated_blocks);
        self.allocator.free(self.directories_per_group);
    }

    fn scan(self: *StrictScanner) !void {
        try self.loadAndValidateBitmaps();
        try self.scanNode(root_inode, root_inode, "", .directory, true);

        var inode_number: u32 = 1;
        while (inode_number <= self.reader.total_inodes) : (inode_number += 1) {
            const expected = inode_number <= first_non_reserved_inode - 1 or
                bitmapIsSet(self.visited_inodes, inode_number - 1);
            if (bitmapIsSet(self.allocated_inodes, inode_number - 1) != expected) {
                return error.UnsupportedAllocatedInode;
            }
        }

        var block_number: u32 = 0;
        while (block_number < self.reader.total_blocks) : (block_number += 1) {
            if (bitmapIsSet(self.allocated_blocks, block_number) !=
                bitmapIsSet(self.owned_blocks, block_number))
            {
                return error.UnsupportedAllocatedBlock;
            }
        }

        for (self.reader.groups, 0..) |group, index| {
            if (group.used_directory_count != self.directories_per_group[index]) {
                return error.InvalidDirectoryCount;
            }
        }
    }

    fn loadAndValidateBitmaps(self: *StrictScanner) !void {
        const group_count: u32 = @intCast(self.reader.groups.len);
        const gdt_bytes = @as(usize, group_count) * group_desc_size;
        const gdt_storage_bytes = @as(usize, blocksForBytes(gdt_bytes, self.reader.block_size)) *
            self.reader.block_size;
        const gdt = try self.allocator.alloc(u8, gdt_storage_bytes);
        defer self.allocator.free(gdt);
        try self.reader.readAll(self.io, gdt, self.reader.offset + self.reader.block_size);
        var primary_superblock: [superblock_size]u8 = undefined;
        try self.reader.readAll(
            self.io,
            &primary_superblock,
            self.reader.offset + superblock_offset,
        );

        const gdt_blocks = @max(@as(u32, 1), blocksForBytes(
            @as(u64, group_count) * group_desc_size,
            self.reader.block_size,
        ));
        const inode_table_blocks = divCeil(
            self.reader.inodes_per_group * @as(u32, self.reader.inode_size),
            self.reader.block_size,
        );
        var total_free_blocks: u32 = 0;
        var total_free_inodes: u32 = 0;

        for (self.reader.groups, 0..) |group, index| {
            const group_index: u32 = @intCast(index);
            const start_block = @as(u64, group_index) * self.reader.blocks_per_group;
            const block_count = @min(
                self.reader.blocks_per_group,
                self.reader.total_blocks - @as(u32, @intCast(start_block)),
            );
            const has_super_copy = group_index == 0 or isSparseSuperGroup(group_index);
            const super_gdt_blocks: u32 = if (has_super_copy) 1 + gdt_blocks else 0;
            const reserved_block_count = super_gdt_blocks + 2 + inode_table_blocks;
            if (reserved_block_count >= block_count or
                group.block_bitmap_block != start_block + super_gdt_blocks or
                group.inode_bitmap_block != start_block + super_gdt_blocks + 1 or
                group.inode_table_block != start_block + super_gdt_blocks + 2)
            {
                return error.UnsupportedGroupLayout;
            }
            if (group_index != 0 and has_super_copy) {
                var backup_superblock: [superblock_size]u8 = undefined;
                try self.reader.readAll(
                    self.io,
                    &backup_superblock,
                    self.reader.blockOffset(start_block),
                );
                var expected_superblock = primary_superblock;
                writeInt(u16, expected_superblock[0x5A..0x5C], @intCast(group_index));
                setSuperblockChecksum(&expected_superblock);
                if (!std.mem.eql(u8, &backup_superblock, &expected_superblock)) {
                    return error.InvalidBackupSuperblock;
                }

                const backup_gdt = try self.allocator.alloc(u8, gdt_storage_bytes);
                defer self.allocator.free(backup_gdt);
                try self.reader.readAll(
                    self.io,
                    backup_gdt,
                    self.reader.blockOffset(start_block + 1),
                );
                if (!std.mem.eql(u8, backup_gdt, gdt)) {
                    return error.InvalidBackupGroupDescriptors;
                }
            }

            const desc_base = index * group_desc_size;
            var descriptor: [group_desc_size]u8 = undefined;
            @memcpy(&descriptor, gdt[desc_base .. desc_base + group_desc_size]);
            const stored_descriptor_checksum = readInt(u16, descriptor[0x1E..0x20]);
            writeInt(u16, descriptor[0x1E..0x20], 0);
            var group_le = std.mem.nativeToLittle(u32, group_index);
            const expected_descriptor_checksum: u16 = @truncate(ext4Crc32c(&.{
                &self.reader.uuid,
                std.mem.asBytes(&group_le),
                &descriptor,
            }));
            if (stored_descriptor_checksum != expected_descriptor_checksum or
                stored_descriptor_checksum != group.descriptor_checksum)
            {
                return error.BadGroupDescriptorChecksum;
            }

            var block_bitmap: [default_block_size]u8 = undefined;
            var inode_bitmap: [default_block_size]u8 = undefined;
            try self.reader.readAll(
                self.io,
                &block_bitmap,
                self.reader.blockOffset(group.block_bitmap_block),
            );
            try self.reader.readAll(
                self.io,
                &inode_bitmap,
                self.reader.blockOffset(group.inode_bitmap_block),
            );
            if (@as(u16, @truncate(bitmapChecksum(
                self.reader.uuid,
                &block_bitmap,
                default_blocks_per_group / 8,
            ))) != group.block_bitmap_checksum or
                @as(u16, @truncate(bitmapChecksum(
                    self.reader.uuid,
                    &inode_bitmap,
                    self.reader.inodes_per_group / 8,
                ))) != group.inode_bitmap_checksum)
            {
                return error.BadBitmapChecksum;
            }

            var allocated_in_group: u32 = 0;
            var bit: u32 = 0;
            while (bit < block_count) : (bit += 1) {
                if (!bitmapIsSet(&block_bitmap, bit)) continue;
                allocated_in_group += 1;
                bitmapSet(self.allocated_blocks, @as(u32, @intCast(start_block)) + bit);
            }
            while (bit < default_block_size * 8) : (bit += 1) {
                if (!bitmapIsSet(&block_bitmap, bit)) return error.InvalidBlockBitmapTail;
            }
            if (group.free_block_count != block_count - allocated_in_group) {
                return error.InvalidFreeBlockCount;
            }
            total_free_blocks += group.free_block_count;

            var allocated_inode_count: u32 = 0;
            bit = 0;
            while (bit < self.reader.inodes_per_group) : (bit += 1) {
                if (!bitmapIsSet(&inode_bitmap, bit)) continue;
                allocated_inode_count += 1;
                bitmapSet(
                    self.allocated_inodes,
                    group_index * self.reader.inodes_per_group + bit,
                );
            }
            while (bit < default_block_size * 8) : (bit += 1) {
                if (!bitmapIsSet(&inode_bitmap, bit)) return error.InvalidInodeBitmapTail;
            }
            if (group.free_inode_count != self.reader.inodes_per_group - allocated_inode_count) {
                return error.InvalidFreeInodeCount;
            }
            total_free_inodes += group.free_inode_count;

            bit = 0;
            while (bit < reserved_block_count) : (bit += 1) {
                try self.markOwnedBlock(@as(u32, @intCast(start_block)) + bit);
            }
        }
        if (total_free_blocks != self.super_free_blocks or
            total_free_inodes != self.super_free_inodes)
        {
            return error.InvalidSuperblockFreeCount;
        }
    }

    fn scanNode(
        self: *StrictScanner,
        inode_number: u32,
        parent_inode_number: u32,
        path: []const u8,
        expected_kind: Kind,
        is_root: bool,
    ) !void {
        if (inode_number == 0 or inode_number > self.reader.total_inodes) {
            return error.InvalidDirectoryInode;
        }
        if (bitmapIsSet(self.visited_inodes, inode_number - 1)) return error.InodeAlias;
        bitmapSet(self.visited_inodes, inode_number - 1);
        self.visited_inode_count += 1;
        if (!bitmapIsSet(self.allocated_inodes, inode_number - 1)) {
            return error.DirectoryReferencesFreeInode;
        }
        const visible_count = self.visited_inode_count - 1;
        limits_mod.observe(self.options.diagnostic, .nodes, visible_count);
        if (visible_count > self.options.max_nodes) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .nodes,
                visible_count,
                self.options.max_nodes,
            );
        }

        const inode = try self.reader.readInode(self.io, inode_number);
        if (inode.kind != expected_kind) return error.DirectoryFileTypeMismatch;
        try self.validateInodeRaw(inode);
        if (inode.atime != self.identity.global_timestamp or
            inode.mtime != self.identity.global_timestamp or
            inode.ctime != self.identity.global_timestamp)
        {
            return error.DivergentInodeTimestamp;
        }
        if (inode.deletion_time != 0 or inode.generation != 0) {
            return error.UnsupportedInodeMetadata;
        }
        limits_mod.observe(self.options.diagnostic, .file_bytes, inode.size);
        if (inode.size > self.options.max_file_bytes) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .file_bytes,
                inode.size,
                self.options.max_file_bytes,
            );
        }
        if (!is_root) try validateStrictPath(path, self.options);

        const fast_symlink = inode.kind == .symlink and inode.size < 60;
        const allowed_flags: u32 = switch (inode.kind) {
            .directory => inode_flag_extents | inode_flag_index,
            .file => inode_flag_extents,
            .symlink => if (fast_symlink) 0 else inode_flag_extents,
            // `modeToKind` never yields these, so the strict reader cannot
            // reach them; the general importer is the path that handles them.
            .hardlink, .block_device, .char_device, .fifo => return error.UnsupportedInodeType,
        };
        if (inode.flags & ~allowed_flags != 0 or
            (inode.flags & inode_flag_extents != 0) != !fast_symlink or
            (inode.kind != .directory and inode.flags & inode_flag_index != 0))
        {
            return error.UnsupportedInodeFlags;
        }

        var data_block_count: u32 = 0;
        var index_block_count: u32 = 0;
        if (fast_symlink) {
            for (inode.block_bytes[@intCast(inode.size)..]) |byte| {
                if (byte != 0) return error.UnsupportedFastSymlinkLayout;
            }
        } else {
            const extent_result = try self.strictExtents(inode);
            defer self.allocator.free(extent_result.extents);
            data_block_count = blocksForBytes(inode.size, self.reader.block_size);
            index_block_count = extent_result.index_block_count;
            try self.validateAndOwnDataExtents(extent_result.extents, data_block_count);
        }

        const xattrs = try self.strictXattrs(inode);
        var xattrs_owned = true;
        defer if (xattrs_owned) freeXattrs(self.allocator, xattrs);
        const xattr_block_count: u32 = if (inode.file_acl_block == 0) 0 else 1;
        const expected_sectors = std.math.mul(
            u32,
            data_block_count + index_block_count + xattr_block_count,
            sectors_per_block,
        ) catch return error.UnsupportedInodeLayout;
        if (inode.sector_count != expected_sectors) return error.UnsupportedInodeBlockCount;

        if (is_root) {
            if (inode.kind != .directory or inode.mode != 0o755 or inode.uid != 0 or
                inode.gid != 0 or xattrs.len != 0)
            {
                return error.NoncanonicalRootMetadata;
            }
        } else {
            self.total_content_bytes = std.math.add(
                u64,
                self.total_content_bytes,
                if (inode.kind == .directory) 0 else inode.size,
            ) catch return error.TotalContentLimitExceeded;
            limits_mod.observe(self.options.diagnostic, .total_bytes, self.total_content_bytes);
            if (self.total_content_bytes > self.options.max_total_bytes) {
                return limits_mod.exceeded(
                    self.options.diagnostic,
                    .total_bytes,
                    self.total_content_bytes,
                    self.options.max_total_bytes,
                );
            }
            try self.appendEntry(path, inode, xattrs);
            xattrs_owned = false;
        }

        if (inode.kind != .directory) {
            if (inode.link_count != 1) return error.UnsupportedHardlink;
            return;
        }
        if (inode.size == 0 or inode.size % self.reader.block_size != 0) {
            return error.UnsupportedDirectoryLayout;
        }
        const group_index = (inode.inode - 1) / self.reader.inodes_per_group;
        self.directories_per_group[group_index] += 1;

        const children = try self.readStrictDirectory(inode, parent_inode_number);
        defer freeStrictChildren(self.allocator, children);
        var subdirectory_count: u32 = 0;
        for (children) |child| {
            if (child.kind == .directory) subdirectory_count += 1;
        }
        if (inode.link_count != 2 + subdirectory_count) return error.InvalidDirectoryLinkCount;

        for (children) |child| {
            const child_path = if (path.len == 0)
                try self.allocator.dupe(u8, child.name)
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ path, child.name });
            defer self.allocator.free(child_path);
            try self.scanNode(child.inode, inode.inode, child_path, child.kind, false);
        }
    }

    fn validateInodeRaw(self: *StrictScanner, inode: ParsedInode) !void {
        var storage: [max_supported_reader_inode_size]u8 = undefined;
        const raw = storage[0..self.reader.inode_size];
        const group_index = (inode.inode - 1) / self.reader.inodes_per_group;
        const index_in_group = (inode.inode - 1) % self.reader.inodes_per_group;
        const group = self.reader.groups[group_index];
        const inode_offset = self.reader.blockOffset(group.inode_table_block) +
            @as(u64, index_in_group) * self.reader.inode_size;
        try self.reader.readAll(self.io, raw, inode_offset);
        // Both halves of the checksum have to be compared, or a corrupt
        // high half on a 256-byte inode reads as intact.
        const wide = raw.len >= 132 and readInt(u16, raw[128..130]) >= 4;
        const stored_checksum = readInt(u16, raw[124..126]) |
            (@as(u32, if (wide) readInt(u16, raw[130..132]) else 0) << 16);
        var checked_storage: [max_supported_reader_inode_size]u8 = undefined;
        const checked = checked_storage[0..raw.len];
        @memcpy(checked, raw);
        setInodeChecksum(checked, self.reader.uuid, inode.inode);
        const computed = readInt(u16, checked[124..126]) |
            (@as(u32, if (wide) readInt(u16, checked[130..132]) else 0) << 16);
        if (stored_checksum != computed) return error.BadInodeChecksum;
        if (!allZero(raw[112..120]) or !allZero(raw[126..128])) {
            return error.UnsupportedInodeMetadata;
        }
        if (raw.len > min_supported_reader_inode_size) {
            // Every byte of the extra region has exactly one value this
            // writer can have produced, so all of it is checked. The epoch
            // words matter most: `ParsedInode` reads the seconds fields as
            // bare 32-bit values and the strict tree re-derives every time
            // from `global_timestamp`, so an epoch this scan let through
            // unexamined would be dropped on rebuild and move the timestamp
            // by 136 years -- the precise failure 256-byte inodes exist to
            // prevent.
            const expected = encodeInodeTime(self.identity.global_timestamp) catch
                return error.UnsupportedInodeMetadata;
            if (readInt(u16, raw[128..130]) != writer_extra_isize or
                readInt(u32, raw[132..136]) != expected.epoch or
                readInt(u32, raw[136..140]) != expected.epoch or
                readInt(u32, raw[140..144]) != expected.epoch or
                readInt(u32, raw[144..148]) != expected.seconds or
                readInt(u32, raw[148..152]) != expected.epoch or
                // `i_version_hi` and `i_projid`, which this writer leaves zero.
                !allZero(raw[152..160]) or
                !allZero(raw[160..raw.len]))
            {
                return error.UnsupportedInodeMetadata;
            }
        }
    }

    fn strictExtents(self: *StrictScanner, inode: ParsedInode) !StrictExtentResult {
        var extents = std.array_list.Managed(Extent).init(self.allocator);
        errdefer extents.deinit();
        var index_block_count: u32 = 0;
        try self.appendStrictExtentNode(
            inode,
            inode.block_bytes[0..],
            max_inline_extents,
            null,
            false,
            &extents,
            &index_block_count,
        );
        return .{
            .extents = try extents.toOwnedSlice(),
            .index_block_count = index_block_count,
        };
    }

    fn appendStrictExtentNode(
        self: *StrictScanner,
        inode: ParsedInode,
        node_bytes: []const u8,
        capacity: usize,
        expected_depth: ?u16,
        external: bool,
        extents: *std.array_list.Managed(Extent),
        index_block_count: *u32,
    ) !void {
        const header = try parseExtentHeader(node_bytes[0..extent_header_size]);
        if (header.max != capacity or header.entries > header.max or
            header.depth > max_supported_extent_depth or header.generation != 0)
        {
            return error.UnsupportedExtentLayout;
        }
        if (expected_depth) |depth| {
            if (header.depth != depth) return error.UnsupportedExtentLayout;
        }
        if (header.depth > 0 and header.entries == 0) return error.UnsupportedExtentLayout;

        if (external) {
            const tail_offset = extentTailOffset(header.max);
            if (tail_offset + extent_tail_size > node_bytes.len) return error.UnsupportedExtentLayout;
            const stored_checksum = readInt(u32, node_bytes[tail_offset .. tail_offset + 4]);
            const checked = try self.allocator.dupe(u8, node_bytes);
            defer self.allocator.free(checked);
            setExtentBlockChecksum(checked, self.reader.uuid, inode.inode, inode.generation);
            if (stored_checksum != readInt(u32, checked[tail_offset .. tail_offset + 4])) {
                return error.BadExtentChecksum;
            }
        }
        const unused_start = extent_header_size + @as(usize, header.entries) * extent_entry_size;
        const unused_end = if (external)
            extentTailOffset(header.max)
        else
            extent_header_size + capacity * extent_entry_size;
        if (!allZero(node_bytes[unused_start..unused_end])) {
            return error.UnsupportedExtentLayout;
        }

        if (header.depth == 0) {
            var index: usize = 0;
            while (index < header.entries) : (index += 1) {
                const base = extent_header_size + index * extent_entry_size;
                const raw_count = readInt(u16, node_bytes[base + 4 .. base + 6]);
                if (raw_count == 0 or raw_count > 0x8000) return error.UnsupportedExtent;
                const extent = decodeExtent(node_bytes[base .. base + extent_entry_size]);
                if (extents.items.len > 0) {
                    const previous = extents.items[extents.items.len - 1];
                    const previous_end = std.math.add(
                        u32,
                        previous.logical_block,
                        previous.block_count,
                    ) catch return error.UnsupportedExtent;
                    if (extent.logical_block < previous_end) return error.UnsupportedExtent;
                }
                try extents.append(extent);
            }
            return;
        }

        var previous_key: ?u32 = null;
        var index: usize = 0;
        while (index < header.entries) : (index += 1) {
            const base = extent_header_size + index * extent_entry_size;
            const child = decodeExtentIndex(node_bytes[base .. base + extent_entry_size]);
            if (!allZero(node_bytes[base + 10 .. base + 12]) or
                (previous_key != null and child.logical_block <= previous_key.?))
            {
                return error.UnsupportedExtentLayout;
            }
            previous_key = child.logical_block;
            const child_block = std.math.cast(u32, child.leaf_block) orelse
                return error.UnsupportedExtent;
            try self.markOwnedBlock(child_block);
            index_block_count.* = std.math.add(u32, index_block_count.*, 1) catch
                return error.UnsupportedExtentLayout;
            var block: [default_block_size]u8 = undefined;
            try self.reader.readAll(self.io, &block, self.reader.blockOffset(child.leaf_block));
            const before = extents.items.len;
            try self.appendStrictExtentNode(
                inode,
                &block,
                extentEntriesPerBlock(self.reader.block_size),
                header.depth - 1,
                true,
                extents,
                index_block_count,
            );
            if (extents.items.len == before or
                extents.items[before].logical_block != child.logical_block)
            {
                return error.UnsupportedExtentLayout;
            }
        }
    }

    fn validateAndOwnDataExtents(
        self: *StrictScanner,
        extents: []const Extent,
        expected_blocks: u32,
    ) !void {
        var logical: u32 = 0;
        for (extents) |extent| {
            if (extent.logical_block != logical) return error.SparseFileUnsupported;
            const end = std.math.add(u64, extent.start_block, extent.block_count) catch
                return error.UnsupportedExtent;
            if (extent.start_block == 0 or end > self.reader.total_blocks) {
                return error.UnsupportedExtent;
            }
            var block: u16 = 0;
            while (block < extent.block_count) : (block += 1) {
                try self.markOwnedBlock(@intCast(extent.start_block + block));
            }
            logical = std.math.add(u32, logical, extent.block_count) catch
                return error.UnsupportedExtent;
        }
        if (logical != expected_blocks) return error.SparseFileUnsupported;
    }

    fn strictXattrs(self: *StrictScanner, inode: ParsedInode) ![]OwnedXattr {
        if (inode.file_acl_block == 0) return self.allocator.alloc(OwnedXattr, 0);
        try self.markOwnedBlock(inode.file_acl_block);
        var raw: [default_block_size]u8 = undefined;
        try self.reader.readAll(
            self.io,
            &raw,
            self.reader.blockOffset(inode.file_acl_block),
        );
        const xattrs = try self.reader.readInodeXattrsAlloc(self.io, self.allocator, inode);
        errdefer freeXattrs(self.allocator, xattrs);
        limits_mod.observe(self.options.diagnostic, .xattrs_per_node, xattrs.len);
        if (xattrs.len > self.options.max_xattrs_per_node) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .xattrs_per_node,
                xattrs.len,
                self.options.max_xattrs_per_node,
            );
        }
        var total_bytes: usize = 0;
        for (xattrs, 0..) |xattr, index| {
            _ = try splitXattrName(xattr.name);
            total_bytes = std.math.add(
                usize,
                total_bytes,
                xattr.name.len + xattr.value.len,
            ) catch return error.XattrByteLimitExceeded;
            for (xattrs[index + 1 ..]) |other| {
                if (std.mem.eql(u8, xattr.name, other.name)) return error.DuplicateXattr;
            }
        }
        limits_mod.observe(self.options.diagnostic, .xattr_bytes_per_node, total_bytes);
        if (total_bytes > self.options.max_xattr_bytes_per_node) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .xattr_bytes_per_node,
                total_bytes,
                self.options.max_xattr_bytes_per_node,
            );
        }
        const canonical = try buildXattrBlock(self.allocator, xattrs, self.reader.block_size);
        defer self.allocator.free(canonical);
        setXattrBlockChecksum(canonical, self.reader.uuid, inode.file_acl_block);
        if (!std.mem.eql(u8, &raw, canonical)) return error.UnsupportedXattrLayout;
        return xattrs;
    }

    fn appendEntry(
        self: *StrictScanner,
        path: []const u8,
        inode: ParsedInode,
        xattrs: []OwnedXattr,
    ) !void {
        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        const views = try self.allocator.alloc(Xattr, xattrs.len);
        errdefer self.allocator.free(views);
        for (xattrs, 0..) |xattr, index| {
            views[index] = .{ .name = xattr.name, .value = xattr.value };
        }
        try self.entries.append(.{
            .path = owned_path,
            .inode = inode,
            .xattrs = xattrs,
            .xattr_views = views,
            .content = .{
                .reader = self.reader,
                .io = self.io,
                .inode = inode,
            },
        });
    }

    fn readStrictDirectory(
        self: *StrictScanner,
        inode: ParsedInode,
        expected_parent: u32,
    ) ![]StrictChild {
        var children = std.array_list.Managed(StrictChild).init(self.allocator);
        errdefer {
            for (children.items) |child| self.allocator.free(child.name);
            children.deinit();
        }
        var dot_count: u8 = 0;
        var dotdot_count: u8 = 0;
        var block: [default_block_size]u8 = undefined;
        const directory_block_count = inode.size / self.reader.block_size;
        var logical_block: u32 = 0;
        while (logical_block < directory_block_count) : (logical_block += 1) {
            const got = try self.reader.preadInode(
                self.io,
                inode,
                &block,
                @as(u64, logical_block) * self.reader.block_size,
            );
            if (got != block.len) return error.UnexpectedEndOfFile;
            try self.validateDirectoryBlock(
                inode,
                &block,
                logical_block,
            );
            var offset: usize = 0;
            while (offset < block.len) {
                if (offset + 8 > block.len) return error.BadDirectoryEntry;
                const child_inode = readInt(u32, block[offset .. offset + 4]);
                const rec_len = readInt(u16, block[offset + 4 .. offset + 6]);
                const name_len = block[offset + 6];
                const file_type = block[offset + 7];
                if (rec_len < 8 or rec_len % dir_entry_alignment != 0 or
                    offset + rec_len > block.len or name_len > rec_len - 8)
                {
                    return error.BadDirectoryEntry;
                }
                const name = block[offset + 8 .. offset + 8 + name_len];
                if (child_inode != 0) {
                    const kind: Kind = switch (file_type) {
                        dir_ft_reg => .file,
                        dir_ft_dir => .directory,
                        dir_ft_symlink => .symlink,
                        else => return error.UnsupportedDirectoryFileType,
                    };
                    if (std.mem.eql(u8, name, ".")) {
                        if (kind != .directory or child_inode != inode.inode) {
                            return error.InvalidDotEntry;
                        }
                        dot_count += 1;
                    } else if (std.mem.eql(u8, name, "..")) {
                        if (kind != .directory or child_inode != expected_parent) {
                            return error.InvalidDotDotEntry;
                        }
                        dotdot_count += 1;
                    } else {
                        try validateStrictComponent(name, self.options);
                        try children.append(.{
                            .inode = child_inode,
                            .kind = kind,
                            .name = try self.allocator.dupe(u8, name),
                        });
                    }
                }
                offset += rec_len;
            }
        }
        if (dot_count != 1 or dotdot_count != 1) return error.InvalidDirectoryDots;
        sortStrictChildren(children.items);
        if (children.items.len > 1) {
            for (children.items[1..], children.items[0 .. children.items.len - 1]) |current, previous| {
                if (std.mem.eql(u8, current.name, previous.name)) {
                    return error.DuplicateDirectoryEntry;
                }
            }
        }
        try self.validateCanonicalDirectory(inode, expected_parent, children.items);
        return children.toOwnedSlice();
    }

    fn validateCanonicalDirectory(
        self: *StrictScanner,
        inode: ParsedInode,
        parent_inode: u32,
        children: []const StrictChild,
    ) !void {
        var linear_specs = std.array_list.Managed(DirEntrySpec).init(self.allocator);
        defer linear_specs.deinit();
        try linear_specs.append(.{ .inode = inode.inode, .kind = .directory, .name = "." });
        try linear_specs.append(.{ .inode = parent_inode, .kind = .directory, .name = ".." });

        const child_specs = try self.allocator.alloc(DirEntrySpec, children.len);
        defer self.allocator.free(child_specs);
        for (children, 0..) |child, index| {
            child_specs[index] = .{
                .inode = child.inode,
                .kind = child.kind,
                .name = child.name,
            };
            try linear_specs.append(child_specs[index]);
        }

        const linear = try buildLinearDirectoryBytes(
            self.allocator,
            linear_specs.items,
            self.reader.block_size,
        );
        const expected_indexed = linear.len > self.reader.block_size and children.len != 0;
        if ((inode.flags & inode_flag_index != 0) != expected_indexed) {
            self.allocator.free(linear);
            return error.UnsupportedDirectoryLayout;
        }

        var index_block_count: u32 = 0;
        const canonical = if (expected_indexed) canonical: {
            self.allocator.free(linear);
            const indexed = try buildIndexedDirectoryBytes(
                self.allocator,
                inode.inode,
                parent_inode,
                child_specs,
                self.reader.block_size,
            );
            index_block_count = indexed.index_block_count;
            break :canonical indexed.bytes;
        } else linear;
        defer self.allocator.free(canonical);
        if (canonical.len != inode.size) return error.UnsupportedDirectoryLayout;

        var block_index: usize = 0;
        while (block_index < canonical.len / self.reader.block_size) : (block_index += 1) {
            const block = canonical[block_index * self.reader.block_size .. (block_index + 1) * self.reader.block_size];
            if (expected_indexed and block_index < index_block_count) {
                const count_offset: usize = if (block_index == 0) 32 else 8;
                const limit = readInt(u16, block[count_offset .. count_offset + 2]);
                const count = readInt(u16, block[count_offset + 2 .. count_offset + 4]);
                setDxChecksum(
                    block,
                    count_offset,
                    count,
                    limit,
                    self.reader.uuid,
                    inode.inode,
                    inode.generation,
                );
            } else {
                setDirectoryLeafChecksum(
                    block,
                    self.reader.uuid,
                    inode.inode,
                    inode.generation,
                );
            }

            var actual: [default_block_size]u8 = undefined;
            const got = try self.reader.preadInode(
                self.io,
                inode,
                &actual,
                @as(u64, block_index) * self.reader.block_size,
            );
            if (got != actual.len) return error.UnexpectedEndOfFile;
            if (!std.mem.eql(u8, block, &actual)) {
                return error.UnsupportedDirectoryLayout;
            }
        }
    }

    fn validateDirectoryBlock(
        self: *StrictScanner,
        inode: ParsedInode,
        block: []const u8,
        logical_block: u32,
    ) !void {
        const tail = block[block.len - 12 ..];
        const is_leaf = readInt(u32, tail[0..4]) == 0 and
            readInt(u16, tail[4..6]) == 12 and
            tail[6] == 0 and tail[7] == dir_ft_checksum;
        if (is_leaf) {
            const stored = readInt(u32, tail[8..12]);
            const checked = try self.allocator.dupe(u8, block);
            defer self.allocator.free(checked);
            setDirectoryLeafChecksum(
                checked,
                self.reader.uuid,
                inode.inode,
                inode.generation,
            );
            if (stored != readInt(u32, checked[checked.len - 4 ..])) {
                return error.BadDirectoryChecksum;
            }
            return;
        }
        if (inode.flags & inode_flag_index == 0) return error.UnsupportedDirectoryLayout;

        const count_offset: usize = if (logical_block == 0) 32 else 8;
        const expected_limit = if (logical_block == 0)
            dxRootLimit(self.reader.block_size)
        else
            dxNodeLimit(self.reader.block_size);
        if (logical_block == 0 and
            (block[28] != dx_hash_half_md4 or block[29] != 8 or
                block[30] > max_supported_extent_depth or block[31] != 0))
        {
            return error.UnsupportedDirectoryLayout;
        }
        const limit = readInt(u16, block[count_offset .. count_offset + 2]);
        const count = readInt(u16, block[count_offset + 2 .. count_offset + 4]);
        if (limit != expected_limit or count == 0 or count > limit) {
            return error.UnsupportedDirectoryLayout;
        }
        const tail_offset = count_offset + @as(usize, limit) * 8;
        const used_end = count_offset + @as(usize, count) * 8;
        if (tail_offset + 8 > block.len or
            !allZero(block[used_end..tail_offset]) or
            !allZero(block[tail_offset .. tail_offset + 4]))
        {
            return error.UnsupportedDirectoryLayout;
        }
        const stored = readInt(u32, block[tail_offset + 4 .. tail_offset + 8]);
        const checked = try self.allocator.dupe(u8, block);
        defer self.allocator.free(checked);
        setDxChecksum(
            checked,
            count_offset,
            count,
            limit,
            self.reader.uuid,
            inode.inode,
            inode.generation,
        );
        if (stored != readInt(u32, checked[tail_offset + 4 .. tail_offset + 8])) {
            return error.BadDirectoryChecksum;
        }
    }

    fn markOwnedBlock(self: *StrictScanner, block: u32) !void {
        if (block >= self.reader.total_blocks) return error.BlockOutsideFilesystem;
        if (bitmapIsSet(self.owned_blocks, block)) return error.OverlappingBlockOwnership;
        bitmapSet(self.owned_blocks, block);
    }
};

fn validateStrictSuperblock(
    reader: *Reader,
    io: Io,
    expected_length: u64,
) !struct {
    identity: StrictFilesystemIdentity,
    free_blocks: u32,
    free_inodes: u32,
} {
    var sb: [superblock_size]u8 = undefined;
    try reader.readAll(io, &sb, reader.offset + superblock_offset);
    const filesystem_length = std.math.mul(
        u64,
        reader.total_blocks,
        reader.block_size,
    ) catch return error.InvalidFilesystemLength;
    if (filesystem_length != expected_length) return error.FilesystemLengthMismatch;

    const stored_checksum = readInt(u32, sb[0x3FC..0x400]);
    var checked = sb;
    setSuperblockChecksum(&checked);
    if (stored_checksum != readInt(u32, checked[0x3FC..0x400])) {
        return error.BadSuperblockChecksum;
    }

    const timestamp = readInt(u32, sb[0x2C..0x30]);
    if (timestamp != readInt(u32, sb[0x30..0x34]) or
        timestamp != readInt(u32, sb[0x40..0x44]) or
        timestamp != readInt(u32, sb[0x108..0x10C]))
    {
        return error.DivergentSuperblockTimestamp;
    }
    if (reader.feature_compat != writer_feature_compat or
        reader.feature_incompat != writer_feature_incompat or
        reader.feature_ro_compat & ~(writer_feature_ro_compat_base | writer_feature_ro_compat_optional) != 0 or
        reader.feature_ro_compat & writer_feature_ro_compat_base != writer_feature_ro_compat_base or
        reader.block_size != default_block_size or
        reader.blocks_per_group != default_blocks_per_group or
        // Exactly the writer's own size, not merely one it can read. This
        // profile's whole claim is that a rebuild reproduces the source byte
        // for byte, and an image an older zvmi wrote with 128-byte inodes
        // would come back out with 256-byte ones. It belongs in the general
        // profile, which reports `source_reproducible = false` honestly.
        reader.inode_size != writer_inode_size or
        reader.total_blocks == 0 or
        reader.inodes_per_group == 0 or
        reader.inodes_per_group > default_block_size * 8 or
        reader.inodes_per_group % (default_block_size / writer_inode_size) != 0 or
        reader.total_inodes != reader.groups.len * reader.inodes_per_group or
        readInt(u32, sb[0x08..0x0C]) != 0 or
        readInt(u32, sb[0x14..0x18]) != 0 or
        readInt(u32, sb[0x18..0x1C]) != 2 or
        readInt(u32, sb[0x1C..0x20]) != 2 or
        readInt(u32, sb[0x24..0x28]) != default_blocks_per_group or
        readInt(u16, sb[0x3A..0x3C]) != state_clean or
        readInt(u16, sb[0x3C..0x3E]) != errors_continue or
        readInt(u32, sb[0x48..0x4C]) != creator_os_linux or
        readInt(u32, sb[0x54..0x58]) != first_non_reserved_inode or
        readInt(u16, sb[0x5A..0x5C]) != 0 or
        readInt(u8, sb[0xFC..0xFD]) != dx_hash_half_md4 or
        readInt(u16, sb[0xFE..0x100]) != group_desc_size or
        readInt(u8, sb[0x175..0x176]) != super_checksum_type_crc32c)
    {
        return error.UnsupportedWriterProfile;
    }

    return .{
        .identity = .{
            .uuid = reader.uuid,
            .label = reader.label,
            .block_size = reader.block_size,
            .filesystem_length = filesystem_length,
            .global_timestamp = timestamp,
        },
        .free_blocks = readInt(u32, sb[0x0C..0x10]),
        .free_inodes = readInt(u32, sb[0x10..0x14]),
    };
}

/// A path this profile can never represent is rejected as invalid, while a
/// path that is merely longer than the configured limit reports the limit, so
/// an operator can tell "impossible" from "raise this flag" apart.
fn validateStrictPath(path: []const u8, options: StrictScanOptions) !void {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') {
        return error.InvalidImportedPath;
    }
    limits_mod.observe(options.diagnostic, .path_bytes, path.len);
    if (path.len > options.max_path_bytes) {
        return limits_mod.exceeded(
            options.diagnostic,
            .path_bytes,
            path.len,
            options.max_path_bytes,
        );
    }
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| try validateStrictComponent(component, options);
}

fn validateStrictComponent(component: []const u8, options: StrictScanOptions) !void {
    if (component.len == 0 or
        // 255 bytes is the ext4 directory-entry name field itself, which no
        // flag can widen.
        component.len > 255 or std.mem.eql(u8, component, ".") or
        std.mem.eql(u8, component, "..") or
        std.mem.indexOfScalar(u8, component, 0) != null or
        std.mem.indexOfScalar(u8, component, '/') != null)
    {
        return error.InvalidImportedPath;
    }
    limits_mod.observe(options.diagnostic, .component_bytes, component.len);
    if (component.len > options.max_component_bytes) {
        return limits_mod.exceeded(
            options.diagnostic,
            .component_bytes,
            component.len,
            options.max_component_bytes,
        );
    }
}

// ---------------------------------------------------------------------------
// General import
//
// `scanWriterCompatible` above revalidates this module's own output down to
// the last unused byte, which is what lets a rebuild promise a byte-for-byte
// reproducible result. A stock distro root filesystem can never satisfy that
// contract: `mke2fs` defaults produce 256-byte inodes, a journal, `64bit`,
// `flex_bg` and `metadata_csum_seed`, and its allocator has no reason to
// agree with ours about where anything lives.
//
// The general importer below therefore validates a different, weaker thing:
// that every guest-visible name, byte, and metadata field can be read out
// unambiguously. It makes no claim about the source's own layout and it never
// reconstructs it. What it does guarantee is that nothing guest-visible is
// dropped silently -- anything it cannot represent is a named refusal, not a
// partial import.
// ---------------------------------------------------------------------------

/// Which import path produced a tree, and therefore what a rebuild from it
/// may promise. Reported so an operator is never left guessing whether a
/// given output is reproducible.
pub const SourceProfile = enum {
    /// `scanWriterCompatible`: this module's own writer profile, revalidated
    /// exhaustively. Rebuilding is byte-for-byte reproducible.
    zvmi_ext4_v1,
    /// `scanReadable`: any ext4 the general reader accepts. Content and
    /// metadata are preserved; the source's own byte layout is not, so a
    /// rebuild is deterministic given the imported tree but is not a
    /// reproduction of the source image.
    ext4_general_v1,

    /// True only when re-running the import against the produced image would
    /// yield the identical source bytes.
    pub fn isByteReproducible(self: SourceProfile) bool {
        return switch (self) {
            .zvmi_ext4_v1 => true,
            .ext4_general_v1 => false,
        };
    }

    pub fn label(self: SourceProfile) []const u8 {
        return switch (self) {
            .zvmi_ext4_v1 => "zvmi_ext4_v1",
            .ext4_general_v1 => "ext4_general_v1",
        };
    }
};

/// Every guest-visible node type a general ext4 source can hold. `hardlink`
/// is not an on-disk inode type: it is how a second or later directory entry
/// pointing at an already-imported inode is represented, so the importer
/// neither duplicates the content nor loses the fact that the two names share
/// storage.
pub const GeneralKind = enum {
    directory,
    file,
    symlink,
    hardlink,
    block_device,
    char_device,
    fifo,
};

pub const DeviceNumbers = struct {
    major: u32 = 0,
    minor: u32 = 0,
};

/// Refusals that name the exact ext4 feature responsible. A partial import is
/// worse than no import: every one of these features changes how guest-visible
/// data is stored, so importing "everything else" would silently produce a
/// filesystem missing real content.
pub const GeneralFeatureError = error{
    UnsupportedBigallocFeature,
    UnsupportedInlineDataFeature,
    UnsupportedCasefoldFeature,
    UnsupportedEncryptFeature,
    UnsupportedVerityFeature,
    UnsupportedMmpFeature,
    UnsupportedFastCommitFeature,
    UnsupportedQuotaFeature,
    UnsupportedProjectFeature,
    UnsupportedCompressionFeature,
    UnsupportedMetaBlockGroupFeature,
    UnsupportedExternalJournalFeature,
    UnsupportedXattrInodeFeature,
    UnsupportedLargeDirFeature,
    UnsupportedDirdataFeature,
    UnsupportedSnapshotFeature,
    UnsupportedReplicaFeature,
    UnsupportedSharedBlocksFeature,
    UnsupportedSparseSuper2Feature,
    UnsupportedLegacyGroupChecksumFeature,
    UnsupportedBtreeDirectoryFeature,
    UnsupportedImagicInodeFeature,
    UnsupportedDirectoryPreallocFeature,
    UnsupportedStableInodesFeature,
    MissingExtentsFeature,
    MissingFiletypeFeature,
    /// The source was not cleanly unmounted. Journal contents are
    /// deliberately never replayed, so an import would silently miss whatever
    /// the log still holds.
    SourceNeedsJournalRecovery,
    /// Inodes are queued for deletion or truncation. Their on-disk state is
    /// the pre-truncation state, which is not what the guest would see.
    SourceHasOrphanInodes,
    UnsupportedFilesystemFeature,
};

/// Rejects any feature outside the general importer's first-pass scope, by
/// name. Bits the reader already understands pass through untouched.
pub fn classifyGeneralFeatures(
    compat: u32,
    incompat: u32,
    ro_compat: u32,
) GeneralFeatureError!void {
    const compat_named = [_]struct { bit: u32, err: GeneralFeatureError }{
        .{ .bit = feature_compat_fast_commit, .err = error.UnsupportedFastCommitFeature },
        .{ .bit = feature_compat_sparse_super2, .err = error.UnsupportedSparseSuper2Feature },
        .{ .bit = feature_compat_imagic_inodes, .err = error.UnsupportedImagicInodeFeature },
        .{ .bit = feature_compat_dir_prealloc, .err = error.UnsupportedDirectoryPreallocFeature },
        .{ .bit = feature_compat_stable_inodes, .err = error.UnsupportedStableInodesFeature },
    };
    for (compat_named) |named| {
        if (compat & named.bit != 0) return named.err;
    }
    const incompat_named = [_]struct { bit: u32, err: GeneralFeatureError }{
        .{ .bit = feature_incompat_inline_data, .err = error.UnsupportedInlineDataFeature },
        .{ .bit = feature_incompat_encrypt, .err = error.UnsupportedEncryptFeature },
        .{ .bit = feature_incompat_casefold, .err = error.UnsupportedCasefoldFeature },
        .{ .bit = feature_incompat_mmp, .err = error.UnsupportedMmpFeature },
        .{ .bit = feature_incompat_compression, .err = error.UnsupportedCompressionFeature },
        .{ .bit = feature_incompat_meta_bg, .err = error.UnsupportedMetaBlockGroupFeature },
        .{ .bit = feature_incompat_journal_dev, .err = error.UnsupportedExternalJournalFeature },
        .{ .bit = feature_incompat_ea_inode, .err = error.UnsupportedXattrInodeFeature },
        .{ .bit = feature_incompat_largedir, .err = error.UnsupportedLargeDirFeature },
        .{ .bit = feature_incompat_dirdata, .err = error.UnsupportedDirdataFeature },
        .{ .bit = feature_incompat_recover, .err = error.SourceNeedsJournalRecovery },
    };
    for (incompat_named) |named| {
        if (incompat & named.bit != 0) return named.err;
    }
    const ro_compat_named = [_]struct { bit: u32, err: GeneralFeatureError }{
        .{ .bit = feature_ro_compat_bigalloc, .err = error.UnsupportedBigallocFeature },
        .{ .bit = feature_ro_compat_verity, .err = error.UnsupportedVerityFeature },
        .{ .bit = feature_ro_compat_quota, .err = error.UnsupportedQuotaFeature },
        .{ .bit = feature_ro_compat_project, .err = error.UnsupportedProjectFeature },
        .{ .bit = feature_ro_compat_has_snapshot, .err = error.UnsupportedSnapshotFeature },
        .{ .bit = feature_ro_compat_replica, .err = error.UnsupportedReplicaFeature },
        .{ .bit = feature_ro_compat_shared_blocks, .err = error.UnsupportedSharedBlocksFeature },
        .{ .bit = feature_ro_compat_gdt_csum, .err = error.UnsupportedLegacyGroupChecksumFeature },
        .{ .bit = feature_ro_compat_btree_dir, .err = error.UnsupportedBtreeDirectoryFeature },
        .{ .bit = feature_ro_compat_orphan_present, .err = error.SourceHasOrphanInodes },
    };
    for (ro_compat_named) |named| {
        if (ro_compat & named.bit != 0) return named.err;
    }

    // ext2/ext3 block-mapped inodes and type-less directory entries are both
    // readable in principle, but neither is what a general importer is for:
    // any filesystem worth right-sizing today is ext4.
    if (incompat & feature_incompat_extents == 0) return error.MissingExtentsFeature;
    if (incompat & feature_incompat_filetype == 0) return error.MissingFiletypeFeature;

    // Anything still unaccounted for is genuinely unknown to this build, and
    // an unknown feature may well change how file data is stored.
    if (compat & ~reader_feature_compat != 0 or
        incompat & ~reader_feature_incompat != 0 or
        ro_compat & ~reader_feature_ro_compat != 0)
    {
        return error.UnsupportedFilesystemFeature;
    }
}

pub const GeneralOpenError = OpenError || GeneralFeatureError;

/// Opens a source for general import. `Reader.open` collapses every feature
/// it does not implement into `UnsupportedFeatures`; this classifies the
/// superblock first so a refusal names the feature that caused it.
pub fn openGeneral(
    io: Io,
    file: Io.File,
    allocator: std.mem.Allocator,
    options: OpenOptions,
) GeneralOpenError!Reader {
    try classifySuperblockForGeneralImport(io, file, null, options.offset);
    return Reader.open(io, file, allocator, options);
}

pub fn openGeneralReadOnlySource(
    io: Io,
    file: Io.File,
    source: ReadOnlySource,
    allocator: std.mem.Allocator,
    options: OpenOptions,
) GeneralOpenError!Reader {
    try classifySuperblockForGeneralImport(io, file, source, options.offset);
    return Reader.openReadOnlySource(io, file, source, allocator, options);
}

fn classifySuperblockForGeneralImport(
    io: Io,
    file: Io.File,
    source: ?ReadOnlySource,
    offset: u64,
) GeneralOpenError!void {
    var sb: [superblock_size]u8 = undefined;
    try readSourceAll(io, file, source, &sb, offset + superblock_offset);
    if (readInt(u16, sb[0x38..0x3A]) != super_magic) return error.BadMagic;
    try classifyGeneralFeatures(
        readInt(u32, sb[0x5C..0x60]),
        readInt(u32, sb[0x60..0x64]),
        readInt(u32, sb[0x64..0x68]),
    );
}

pub const GeneralScanOptions = struct {
    /// The bytes the source filesystem is allowed to occupy. Unlike the
    /// strict scan this is an upper bound rather than an equality: a real
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
    /// The scanner is torn down before `scanReadable` returns, so a failure
    /// can only report through a sink the caller still owns.
    diagnostic: ?*limits_mod.Diagnostic = null,
};

pub const GeneralFilesystemIdentity = struct {
    profile: SourceProfile = .ext4_general_v1,
    uuid: [16]u8,
    /// Exact on-disk 16-byte volume-name field, including embedded/trailing
    /// NUL bytes.
    label: [16]u8,
    block_size: u32,
    /// Bytes the filesystem itself occupies, which may be less than the
    /// partition or device holding it.
    filesystem_length: u64,
    inode_size: u16,
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    /// Reported because a journal-less rebuild of a journalled source is a
    /// deliberate change of behaviour the operator should know about.
    has_journal: bool,
};

/// Metadata of the source's own root directory. The tree formats below all
/// model the root implicitly, so it travels beside the entries rather than
/// as one of them.
pub const GeneralRoot = struct {
    mode: u16,
    uid: u32,
    gid: u32,
    atime: i64,
    mtime: i64,
    ctime: i64,
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    crtime: ?i64,
    crtime_nsec: u32,
    xattrs: []const Xattr,
};

pub const GeneralEntry = struct {
    /// Relative path with `/` separators and no leading `/`.
    path: []const u8,
    kind: GeneralKind,
    /// Permission/sticky bits only; the file type comes from `kind`.
    mode: u16,
    uid: u32,
    gid: u32,
    /// Regular-file or symlink byte length; 0 for every other kind.
    size: u64,
    atime: i64,
    mtime: i64,
    ctime: i64,
    /// Sub-second parts of the three times above. A source whose inodes are
    /// too narrow to store them, or which simply stored whole seconds,
    /// reports zero.
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    /// The inode's creation time, or null when the source could not store one
    /// -- a 128-byte inode has no extra region, and a wider one may not
    /// declare an `i_extra_isize` that reaches this far.
    crtime: ?i64,
    crtime_nsec: u32,
    /// Meaningful only for `.block_device` and `.char_device`.
    device: DeviceNumbers,
    /// Set only for `.hardlink`: the path of the first entry that shares the
    /// source inode. Always earlier in iteration order than the link itself.
    hardlink_target: []const u8,
    content: ?FileTreeView.ContentReader,
    xattrs: []const Xattr,
};

const GeneralContent = struct {
    reader: *Reader,
    io: Io,
    inode_number: u32,
    size: u64,
    flags: u32,
    block_bytes: [60]u8,
};

const GeneralNode = struct {
    path: []u8,
    kind: GeneralKind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    atime: i64,
    mtime: i64,
    ctime: i64,
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    crtime: ?i64,
    crtime_nsec: u32,
    device: DeviceNumbers,
    /// Borrowed from the earlier node that owns this inode's content.
    hardlink_target: []const u8,
    has_content: bool,
    content: GeneralContent,
    xattrs: []OwnedXattr,
    xattr_views: []Xattr,
};

/// A general ext4 source read out as an ordered tree. Paths, xattrs, and
/// metadata are owned; file bytes stay in the read-only source until an
/// importer spools them.
pub const GeneralTree = struct {
    allocator: std.mem.Allocator,
    entries: []GeneralNode,
    identity: GeneralFilesystemIdentity,
    root: GeneralRoot,
    root_xattrs_owned: []OwnedXattr,
    root_xattr_views: []Xattr,
    /// Guest-visible file bytes counted once per inode, so a hardlinked file
    /// is not billed twice. This is the scratch space an import needs.
    content_bytes: u64,
    view: FileTreeView = .{
        .ctx = undefined,
        .next_fn = generalViewNext,
        .reset_fn = generalViewReset,
    },
    iteration_index: usize = 0,

    pub fn deinit(self: *GeneralTree) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.path);
            freeXattrs(self.allocator, entry.xattrs);
            self.allocator.free(entry.xattr_views);
        }
        self.allocator.free(self.entries);
        freeXattrs(self.allocator, self.root_xattrs_owned);
        self.allocator.free(self.root_xattr_views);
        self.* = undefined;
    }

    /// Excludes the implicit root directory, matching `StrictTree`.
    pub fn nodeCount(self: *const GeneralTree) usize {
        return self.entries.len;
    }

    pub fn entryAt(self: *GeneralTree, index: usize) GeneralEntry {
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
            .atime_nsec = node.atime_nsec,
            .mtime_nsec = node.mtime_nsec,
            .ctime_nsec = node.ctime_nsec,
            .crtime = node.crtime,
            .crtime_nsec = node.crtime_nsec,
            .device = node.device,
            .hardlink_target = node.hardlink_target,
            .content = if (node.has_content) .{
                .ctx = &node.content,
                .read_at_fn = generalContentReadAt,
            } else null,
            .xattrs = node.xattr_views,
        };
    }

    /// A `FileTreeView` over the same entries, for callers that only need the
    /// shape a writer consumes. It deliberately drops the per-node
    /// timestamps: `FileTreeView` has nowhere to carry them, so anything that
    /// must preserve them has to consume `entryAt` directly.
    pub fn fileTreeView(self: *GeneralTree) *FileTreeView {
        self.iteration_index = 0;
        self.view = .{
            .ctx = self,
            .next_fn = generalViewNext,
            .reset_fn = generalViewReset,
        };
        return &self.view;
    }

    fn generalViewReset(ctx: *anyopaque) void {
        const self: *GeneralTree = @ptrCast(@alignCast(ctx));
        self.iteration_index = 0;
    }

    fn generalViewNext(ctx: *anyopaque) FileTreeView.IteratorError!?FileTreeView.Entry {
        const self: *GeneralTree = @ptrCast(@alignCast(ctx));
        if (self.iteration_index >= self.entries.len) return null;
        const entry = self.entryAt(self.iteration_index);
        self.iteration_index += 1;
        return .{
            .path = entry.path,
            .kind = switch (entry.kind) {
                .directory => .directory,
                .file => .file,
                .symlink => .symlink,
                .hardlink => .hardlink,
                .block_device => .block_device,
                .char_device => .char_device,
                .fifo => .fifo,
            },
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = entry.content,
            .xattrs = entry.xattrs,
            .device = entry.device,
            .hardlink_target = entry.hardlink_target,
        };
    }
};

fn generalContentReadAt(
    ctx: *const anyopaque,
    buffer: []u8,
    offset: u64,
) FileTreeView.ContentError!usize {
    const content: *const GeneralContent = @ptrCast(@alignCast(ctx));
    return readGeneralContent(content, buffer, offset) catch return error.ReadFailed;
}

/// Imports any ext4 filesystem the general reader accepts. Nothing is
/// written and the source is never opened for writing.
/// Spelled out rather than inferred because the scanner recurses through
/// directories, and Zig cannot infer an error set that depends on itself.
pub const GeneralScanError = ReadError || GeneralFeatureError || limits_mod.Error || error{
    SourceNotCleanlyUnmounted,
    InvalidFilesystemLength,
    UnsupportedSocketInode,
    UnsupportedInodeType,
    UnsupportedInodeCount,
    UnsupportedFirstInode,
    UnsupportedBlockMappedInode,
    UnsupportedXattrLayout,
    UnsupportedXattrName,
    UnsupportedDirectoryLayout,
    UnsupportedExtent,
    UnsupportedExtentLayout,
    DeletedInodeReferenced,
    DirectoryCycle,
    DirectoryFileTypeMismatch,
    DuplicateDirectoryEntry,
    DuplicateXattr,
    FilesystemTooLargeToImport,
    FilesystemExceedsPartition,
    RootIsNotADirectory,
    InvalidImportedPath,
    InvalidInodeReference,
};

pub fn scanReadable(
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    options: GeneralScanOptions,
) GeneralScanError!GeneralTree {
    var scanner = try GeneralScanner.init(reader, io, allocator, options);
    defer scanner.deinit();
    try scanner.scan();
    return scanner.finish();
}

const GeneralChild = struct {
    inode: u32,
    dir_file_type: u8,
    name: []u8,
};

const GeneralExtent = struct {
    logical_block: u32,
    start_block: u64,
    block_count: u32,
    /// An uninitialized extent is allocated but has never been written, so
    /// the guest reads zeros from it. Preserving that distinction is what
    /// keeps a `fallocate`d region from importing as garbage.
    initialized: bool,
};

const GeneralInode = struct {
    inode: u32,
    kind: GeneralKind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    atime: i64,
    mtime: i64,
    ctime: i64,
    atime_nsec: u32,
    mtime_nsec: u32,
    ctime_nsec: u32,
    crtime: ?i64,
    crtime_nsec: u32,
    link_count: u16,
    flags: u32,
    file_acl_block: u32,
    device: DeviceNumbers,
    block_bytes: [60]u8,

    fn isFastSymlink(self: GeneralInode) bool {
        return self.kind == .symlink and self.size < 60 and
            (self.flags & inode_flag_extents) == 0;
    }

    fn hasContent(self: GeneralInode) bool {
        return self.kind == .file or self.kind == .symlink;
    }
};

const GeneralScanner = struct {
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    options: GeneralScanOptions,
    identity: GeneralFilesystemIdentity,
    entries: std.array_list.Managed(GeneralNode),
    /// Directory inodes already entered, which is what turns a corrupt
    /// parent pointer from an infinite walk into a named error.
    visited_directories: []u8,
    /// First path seen for each multiply-linked inode. Later names for the
    /// same inode become `.hardlink` entries pointing at it.
    hardlinks: std.AutoHashMap(u32, []const u8),
    root: GeneralRoot,
    root_xattrs_owned: []OwnedXattr,
    root_xattr_views: []Xattr,
    content_bytes: u64 = 0,
    node_count: usize = 0,

    fn init(
        reader: *Reader,
        io: Io,
        allocator: std.mem.Allocator,
        options: GeneralScanOptions,
    ) !GeneralScanner {
        const identity = try validateGeneralSuperblock(reader, io, options);
        const directory_bitmap_len = bitmapByteLength(reader.total_inodes);
        limits_mod.observe(options.diagnostic, .scan_metadata_bytes, directory_bitmap_len);
        if (directory_bitmap_len > options.max_scan_metadata_bytes) {
            return limits_mod.exceeded(
                options.diagnostic,
                .scan_metadata_bytes,
                directory_bitmap_len,
                options.max_scan_metadata_bytes,
            );
        }
        const visited = try allocator.alloc(u8, directory_bitmap_len);
        errdefer allocator.free(visited);
        @memset(visited, 0);
        return .{
            .reader = reader,
            .io = io,
            .allocator = allocator,
            .options = options,
            .identity = identity,
            .entries = .init(allocator),
            .visited_directories = visited,
            .hardlinks = .init(allocator),
            .root = undefined,
            .root_xattrs_owned = &.{},
            .root_xattr_views = &.{},
        };
    }

    fn deinit(self: *GeneralScanner) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.path);
            freeXattrs(self.allocator, entry.xattrs);
            self.allocator.free(entry.xattr_views);
        }
        self.entries.deinit();
        self.allocator.free(self.visited_directories);
        self.hardlinks.deinit();
        freeXattrs(self.allocator, self.root_xattrs_owned);
        self.allocator.free(self.root_xattr_views);
        self.root_xattrs_owned = &.{};
        self.root_xattr_views = &.{};
    }

    fn finish(self: *GeneralScanner) !GeneralTree {
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

    fn scan(self: *GeneralScanner) !void {
        var raw: [max_supported_reader_inode_size]u8 = undefined;
        const root = try self.readGeneralInode(root_inode, &raw);
        if (root.kind != .directory) return error.RootIsNotADirectory;
        const xattrs = try self.readNodeXattrs(root, &raw);
        errdefer freeXattrs(self.allocator, xattrs);
        const views = try self.allocator.alloc(Xattr, xattrs.len);
        for (xattrs, 0..) |xattr, index| {
            views[index] = .{ .name = xattr.name, .value = xattr.value };
        }
        self.root_xattrs_owned = xattrs;
        self.root_xattr_views = views;
        self.root = .{
            .mode = root.mode,
            .uid = root.uid,
            .gid = root.gid,
            .atime = root.atime,
            .mtime = root.mtime,
            .ctime = root.ctime,
            .atime_nsec = root.atime_nsec,
            .mtime_nsec = root.mtime_nsec,
            .ctime_nsec = root.ctime_nsec,
            .crtime = root.crtime,
            .crtime_nsec = root.crtime_nsec,
            .xattrs = views,
        };
        bitmapSet(self.visited_directories, root_inode - 1);
        try self.scanDirectory(root, "");
    }

    fn scanDirectory(self: *GeneralScanner, directory: GeneralInode, path: []const u8) GeneralScanError!void {
        const children = try self.readDirectory(directory);
        defer {
            for (children) |child| self.allocator.free(child.name);
            self.allocator.free(children);
        }
        sortGeneralChildren(children);
        if (children.len > 1) {
            for (children[1..], children[0 .. children.len - 1]) |current, previous| {
                if (std.mem.eql(u8, current.name, previous.name)) {
                    return error.DuplicateDirectoryEntry;
                }
            }
        }

        for (children) |child| {
            const child_path = if (path.len == 0)
                try self.allocator.dupe(u8, child.name)
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ path, child.name });
            defer self.allocator.free(child_path);
            try self.scanChild(child, child_path);
        }
    }

    fn scanChild(self: *GeneralScanner, child: GeneralChild, path: []const u8) GeneralScanError!void {
        try validateGeneralPath(path, self.options);
        self.node_count += 1;
        limits_mod.observe(self.options.diagnostic, .nodes, self.node_count);
        if (self.node_count > self.options.max_nodes) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .nodes,
                self.node_count,
                self.options.max_nodes,
            );
        }

        var raw: [max_supported_reader_inode_size]u8 = undefined;
        const inode = try self.readGeneralInode(child.inode, &raw);
        if (child.dir_file_type != dir_ft_unknown and
            child.dir_file_type != generalKindToDirFileType(inode.kind))
        {
            return error.DirectoryFileTypeMismatch;
        }

        // A second name for an already-imported inode is a hardlink. It must
        // not re-import the content, and it must not be walked again.
        if (inode.kind != .directory and inode.link_count > 1) {
            if (self.hardlinks.get(inode.inode)) |target| {
                try self.appendHardlink(path, inode, target);
                return;
            }
        }

        if (inode.kind == .directory) {
            if (bitmapIsSet(self.visited_directories, inode.inode - 1)) {
                return error.DirectoryCycle;
            }
            bitmapSet(self.visited_directories, inode.inode - 1);
        }

        limits_mod.observe(self.options.diagnostic, .file_bytes, inode.size);
        if (inode.size > self.options.max_file_bytes) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .file_bytes,
                inode.size,
                self.options.max_file_bytes,
            );
        }
        if (inode.hasContent()) {
            self.content_bytes = std.math.add(u64, self.content_bytes, inode.size) catch
                return error.TotalContentLimitExceeded;
            limits_mod.observe(self.options.diagnostic, .total_bytes, self.content_bytes);
            if (self.content_bytes > self.options.max_total_bytes) {
                return limits_mod.exceeded(
                    self.options.diagnostic,
                    .total_bytes,
                    self.content_bytes,
                    self.options.max_total_bytes,
                );
            }
        }

        const xattrs = try self.readNodeXattrs(inode, &raw);
        var xattrs_owned = true;
        defer if (xattrs_owned) freeXattrs(self.allocator, xattrs);
        const owned_path = try self.allocator.dupe(u8, path);
        // Ownership moves into `entries` on a successful append, and the tree
        // frees it from there; recursing into a subdirectory can still fail
        // afterwards, so the guard has to be cancelled rather than scoped.
        var node_owned = true;
        errdefer if (node_owned) self.allocator.free(owned_path);
        const views = try self.allocator.alloc(Xattr, xattrs.len);
        errdefer if (node_owned) self.allocator.free(views);
        for (xattrs, 0..) |xattr, index| {
            views[index] = .{ .name = xattr.name, .value = xattr.value };
        }
        try self.entries.append(.{
            .path = owned_path,
            .kind = inode.kind,
            .mode = inode.mode,
            .uid = inode.uid,
            .gid = inode.gid,
            .size = if (inode.hasContent()) inode.size else 0,
            .atime = inode.atime,
            .mtime = inode.mtime,
            .ctime = inode.ctime,
            .atime_nsec = inode.atime_nsec,
            .mtime_nsec = inode.mtime_nsec,
            .ctime_nsec = inode.ctime_nsec,
            .crtime = inode.crtime,
            .crtime_nsec = inode.crtime_nsec,
            .device = inode.device,
            .hardlink_target = "",
            .has_content = inode.hasContent(),
            .content = .{
                .reader = self.reader,
                .io = self.io,
                .inode_number = inode.inode,
                .size = inode.size,
                .flags = inode.flags,
                .block_bytes = inode.block_bytes,
            },
            .xattrs = xattrs,
            .xattr_views = views,
        });
        xattrs_owned = false;
        node_owned = false;

        if (inode.kind != .directory and inode.link_count > 1) {
            // The stored path belongs to the entry that now owns the content;
            // it outlives the scan because the tree owns it too.
            try self.hardlinks.put(inode.inode, self.entries.items[self.entries.items.len - 1].path);
        }
        if (inode.kind == .directory) try self.scanDirectory(inode, path);
    }

    fn appendHardlink(
        self: *GeneralScanner,
        path: []const u8,
        inode: GeneralInode,
        target: []const u8,
    ) !void {
        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        try self.entries.append(.{
            .path = owned_path,
            .kind = .hardlink,
            .mode = inode.mode,
            .uid = inode.uid,
            .gid = inode.gid,
            .size = 0,
            .atime = inode.atime,
            .mtime = inode.mtime,
            .ctime = inode.ctime,
            .atime_nsec = inode.atime_nsec,
            .mtime_nsec = inode.mtime_nsec,
            .ctime_nsec = inode.ctime_nsec,
            .crtime = inode.crtime,
            .crtime_nsec = inode.crtime_nsec,
            .device = .{},
            .hardlink_target = target,
            .has_content = false,
            .content = undefined,
            .xattrs = &.{},
            .xattr_views = &.{},
        });
    }

    fn readGeneralInode(
        self: *GeneralScanner,
        inode_number: u32,
        raw: *[max_supported_reader_inode_size]u8,
    ) !GeneralInode {
        if (inode_number == 0 or inode_number > self.reader.total_inodes) {
            return error.InvalidInodeReference;
        }
        @memset(raw, 0);
        const group_index = (inode_number - 1) / self.reader.inodes_per_group;
        const index_in_group = (inode_number - 1) % self.reader.inodes_per_group;
        const group = self.reader.groups[group_index];
        const offset = self.reader.blockOffset(group.inode_table_block) +
            @as(u64, index_in_group) * self.reader.inode_size;
        try self.reader.readAll(self.io, raw[0..self.reader.inode_size], offset);
        return parseGeneralInode(inode_number, raw[0..self.reader.inode_size]);
    }

    fn readNodeXattrs(
        self: *GeneralScanner,
        inode: GeneralInode,
        raw: *const [max_supported_reader_inode_size]u8,
    ) ![]OwnedXattr {
        var xattrs = std.array_list.Managed(OwnedXattr).init(self.allocator);
        errdefer {
            for (xattrs.items) |xattr| {
                self.allocator.free(xattr.name);
                self.allocator.free(xattr.value);
            }
            xattrs.deinit();
        }

        // A 256-byte inode carries small attributes in the space past
        // `i_extra_isize`. SELinux labels and POSIX ACLs land there first and
        // only spill into a block when they no longer fit, so an importer
        // that reads only the block silently drops most real-world labels.
        try appendInodeBodyXattrs(
            self.allocator,
            raw[0..self.reader.inode_size],
            &xattrs,
        );
        if (inode.file_acl_block != 0) {
            const block = try self.allocator.alloc(u8, self.reader.block_size);
            defer self.allocator.free(block);
            try self.reader.readAll(
                self.io,
                block,
                self.reader.blockOffset(inode.file_acl_block),
            );
            if (readInt(u32, block[0..4]) != ext4_xattr_magic) {
                return error.UnsupportedXattrLayout;
            }
            try appendXattrEntries(self.allocator, block, 32, 0, &xattrs);
        }

        limits_mod.observe(self.options.diagnostic, .xattrs_per_node, xattrs.items.len);
        if (xattrs.items.len > self.options.max_xattrs_per_node) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .xattrs_per_node,
                xattrs.items.len,
                self.options.max_xattrs_per_node,
            );
        }
        var total_bytes: usize = 0;
        for (xattrs.items, 0..) |xattr, index| {
            // Checked here so an attribute the writer could never re-emit
            // fails at import time with a name, not later inside a build.
            _ = splitXattrName(xattr.name) catch return error.UnsupportedXattrName;
            total_bytes = std.math.add(
                usize,
                total_bytes,
                xattr.name.len + xattr.value.len,
            ) catch return error.XattrByteLimitExceeded;
            for (xattrs.items[index + 1 ..]) |other| {
                if (std.mem.eql(u8, xattr.name, other.name)) return error.DuplicateXattr;
            }
        }
        limits_mod.observe(self.options.diagnostic, .xattr_bytes_per_node, total_bytes);
        if (total_bytes > self.options.max_xattr_bytes_per_node) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .xattr_bytes_per_node,
                total_bytes,
                self.options.max_xattr_bytes_per_node,
            );
        }
        return xattrs.toOwnedSlice();
    }

    fn readDirectory(self: *GeneralScanner, inode: GeneralInode) ![]GeneralChild {
        if (inode.size == 0 or inode.size % self.reader.block_size != 0) {
            return error.UnsupportedDirectoryLayout;
        }
        const size = std.math.cast(usize, inode.size) orelse return error.UnsupportedDirectoryLayout;
        limits_mod.observe(self.options.diagnostic, .scan_metadata_bytes, size);
        if (size > self.options.max_scan_metadata_bytes) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .scan_metadata_bytes,
                size,
                self.options.max_scan_metadata_bytes,
            );
        }
        const data = try self.allocator.alloc(u8, size);
        defer self.allocator.free(data);
        const content = GeneralContent{
            .reader = self.reader,
            .io = self.io,
            .inode_number = inode.inode,
            .size = inode.size,
            .flags = inode.flags,
            .block_bytes = inode.block_bytes,
        };
        var done: usize = 0;
        while (done < data.len) {
            const got = try readGeneralContent(&content, data[done..], done);
            if (got == 0) return error.UnexpectedEndOfFile;
            done += got;
        }

        var children = std.array_list.Managed(GeneralChild).init(self.allocator);
        errdefer {
            for (children.items) |child| self.allocator.free(child.name);
            children.deinit();
        }
        var block_start: usize = 0;
        while (block_start < data.len) : (block_start += self.reader.block_size) {
            const block = data[block_start..][0..self.reader.block_size];
            var offset: usize = 0;
            while (offset + 8 <= block.len) {
                const child_inode = readInt(u32, block[offset .. offset + 4]);
                const rec_len = readInt(u16, block[offset + 4 .. offset + 6]);
                const name_len = block[offset + 6];
                const file_type = block[offset + 7];
                if (rec_len < 8 or rec_len % dir_entry_alignment != 0 or
                    offset + rec_len > block.len or name_len > rec_len - 8)
                {
                    return error.BadDirectoryEntry;
                }
                const name = block[offset + 8 .. offset + 8 + name_len];
                // An htree index block and a leaf's checksum tail both
                // masquerade as an unused entry, so skipping inode 0 covers
                // both without needing to parse the index at all.
                if (child_inode != 0 and file_type != dir_ft_checksum and
                    !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, ".."))
                {
                    try validateGeneralComponent(name, self.options);
                    const owned_name = try self.allocator.dupe(u8, name);
                    errdefer self.allocator.free(owned_name);
                    try children.append(.{
                        .inode = child_inode,
                        .dir_file_type = file_type,
                        .name = owned_name,
                    });
                }
                offset += rec_len;
            }
        }
        return children.toOwnedSlice();
    }
};

fn validateGeneralSuperblock(
    reader: *Reader,
    io: Io,
    options: GeneralScanOptions,
) !GeneralFilesystemIdentity {
    var sb: [superblock_size]u8 = undefined;
    try reader.readAll(io, &sb, reader.offset + superblock_offset);
    try classifyGeneralFeatures(
        reader.feature_compat,
        reader.feature_incompat,
        reader.feature_ro_compat,
    );

    // A source that was not cleanly unmounted has state the journal still
    // holds, and this importer deliberately never replays a journal.
    if (readInt(u16, sb[0x3A..0x3C]) & state_clean == 0) {
        return error.SourceNotCleanlyUnmounted;
    }
    if (readInt(u32, sb[0xE8..0xEC]) != 0) return error.SourceHasOrphanInodes;

    // `s_blocks_count_hi` is the only place a 64-bit filesystem records the
    // blocks this build cannot address, so it is checked rather than
    // truncated.
    if (reader.feature_incompat & feature_incompat_64bit != 0 and
        readInt(u32, sb[0x150..0x154]) != 0)
    {
        return error.FilesystemTooLargeToImport;
    }
    if (readInt(u32, sb[0x54..0x58]) < first_non_reserved_inode) {
        return error.UnsupportedFirstInode;
    }

    const filesystem_length = std.math.mul(
        u64,
        reader.total_blocks,
        reader.block_size,
    ) catch return error.InvalidFilesystemLength;
    if (filesystem_length > options.available_length) {
        return error.FilesystemExceedsPartition;
    }
    if (reader.total_inodes == 0 or
        @as(u64, reader.total_inodes) > @as(u64, reader.groups.len) * reader.inodes_per_group)
    {
        return error.UnsupportedInodeCount;
    }
    try validateGeneralGroupDescriptors(reader, io);

    return .{
        .uuid = reader.uuid,
        .label = reader.label,
        .block_size = reader.block_size,
        .filesystem_length = filesystem_length,
        .inode_size = reader.inode_size,
        .feature_compat = reader.feature_compat,
        .feature_incompat = reader.feature_incompat,
        .feature_ro_compat = reader.feature_ro_compat,
        .has_journal = reader.feature_compat & feature_compat_has_journal != 0,
    };
}

/// A 64-bit filesystem widens every group-descriptor block pointer with a
/// high half this build ignores. Ignoring a non-zero high half would read the
/// wrong block and call the result a filesystem, so it is refused instead.
fn validateGeneralGroupDescriptors(reader: *Reader, io: Io) !void {
    const desc_size: usize = if (reader.feature_incompat & feature_incompat_64bit != 0) 64 else 32;
    if (desc_size == 32) return;
    const gdt_bytes = reader.groups.len * desc_size;
    const gdt_storage_bytes = @as(usize, blocksForBytes(gdt_bytes, reader.block_size)) *
        reader.block_size;
    const gdt = try reader.allocator.alloc(u8, gdt_storage_bytes);
    defer reader.allocator.free(gdt);
    try reader.readAll(io, gdt, reader.offset + reader.block_size);
    var index: usize = 0;
    while (index < reader.groups.len) : (index += 1) {
        const base = index * desc_size;
        if (readInt(u32, gdt[base + 0x20 .. base + 0x24]) != 0 or
            readInt(u32, gdt[base + 0x24 .. base + 0x28]) != 0 or
            readInt(u32, gdt[base + 0x28 .. base + 0x2C]) != 0)
        {
            return error.FilesystemTooLargeToImport;
        }
    }
}

fn parseGeneralInode(inode_number: u32, buf: []const u8) !GeneralInode {
    const full_mode = readInt(u16, buf[0..2]);
    const kind = generalModeToKind(full_mode) orelse return switch (full_mode & 0xF000) {
        mode_socket => error.UnsupportedSocketInode,
        else => error.UnsupportedInodeType,
    };
    if (readInt(u32, buf[20..24]) != 0) return error.DeletedInodeReferenced;
    const flags = readInt(u32, buf[32..36]);
    // Every one of these changes where the guest's bytes actually live, so an
    // importer that ignored them would produce plausible-looking wrong data.
    if (flags & inode_flag_inline_data != 0) return error.UnsupportedInlineDataFeature;
    if (flags & inode_flag_encrypt != 0) return error.UnsupportedEncryptFeature;
    if (flags & inode_flag_verity != 0) return error.UnsupportedVerityFeature;
    if (flags & inode_flag_ea_inode != 0) return error.UnsupportedXattrInodeFeature;

    var block_bytes: [60]u8 = undefined;
    @memcpy(&block_bytes, buf[40..100]);
    const size = readInt(u32, buf[4..8]) | (@as(u64, readInt(u32, buf[108..112])) << 32);
    // `i_extra_isize` counts the bytes past the classic 128-byte inode that
    // are actually present, so each `*_extra` field has to be covered
    // individually rather than assumed from the inode size alone.
    const extra_isize: usize = if (buf.len >= 130) readInt(u16, buf[128..130]) else 0;
    const ctime_extra: u32 = if (buf.len >= 136 and extra_isize >= 8)
        readInt(u32, buf[132..136])
    else
        0;
    const mtime_extra: u32 = if (buf.len >= 140 and extra_isize >= 12)
        readInt(u32, buf[136..140])
    else
        0;
    const atime_extra: u32 = if (buf.len >= 144 and extra_isize >= 16)
        readInt(u32, buf[140..144])
    else
        0;
    // `i_crtime` needs `i_extra_isize` to cover 128..148 and its own extra
    // word another four bytes past that. A source that declares less has no
    // creation time to give rather than one that happens to read as zero,
    // and the two have to stay distinguishable: 1970-01-01 is a creation
    // time a real file can have.
    const crtime: ?i64 = if (buf.len >= 152 and extra_isize >= 24)
        decodeInodeTime(readInt(u32, buf[144..148]), readInt(u32, buf[148..152]))
    else
        null;
    const crtime_extra: u32 = if (buf.len >= 152 and extra_isize >= 24)
        readInt(u32, buf[148..152])
    else
        0;
    return .{
        .inode = inode_number,
        .kind = kind,
        .mode = full_mode & 0x0FFF,
        .uid = readInt(u16, buf[2..4]) | (@as(u32, readInt(u16, buf[120..122])) << 16),
        .gid = readInt(u16, buf[24..26]) | (@as(u32, readInt(u16, buf[122..124])) << 16),
        .size = if (kind == .file or kind == .symlink or kind == .directory) size else 0,
        .atime = decodeInodeTime(readInt(u32, buf[8..12]), atime_extra),
        .ctime = decodeInodeTime(readInt(u32, buf[12..16]), ctime_extra),
        .mtime = decodeInodeTime(readInt(u32, buf[16..20]), mtime_extra),
        .atime_nsec = decodeInodeNanoseconds(atime_extra),
        .ctime_nsec = decodeInodeNanoseconds(ctime_extra),
        .mtime_nsec = decodeInodeNanoseconds(mtime_extra),
        .crtime = crtime,
        .crtime_nsec = decodeInodeNanoseconds(crtime_extra),
        .link_count = readInt(u16, buf[26..28]),
        .flags = flags,
        .file_acl_block = readInt(u32, buf[104..108]),
        .device = decodeDeviceNumbers(kind, block_bytes),
        .block_bytes = block_bytes,
    };
}

/// ext4 keeps seconds in a signed 32-bit field and, on inodes large enough to
/// hold it, two extra high bits in the matching `*_extra` field. Dropping the
/// extra bits would silently move post-2038 timestamps back by 136 years.
/// The sub-second part of an `i_*_extra` word: everything above the two
/// epoch bits. A source that wrote a value of a billion or more is corrupt
/// rather than merely unusual, and reporting zero for it keeps a rebuild from
/// propagating a number ext4 itself could not have meant.
fn decodeInodeNanoseconds(extra: u32) u32 {
    const nanoseconds = extra >> 2;
    return if (nanoseconds >= 1_000_000_000) 0 else nanoseconds;
}

fn decodeInodeTime(seconds: u32, extra: u32) i64 {
    var value: i64 = @as(i32, @bitCast(seconds));
    const epoch = extra & 0x3;
    if (epoch != 0) value += @as(i64, epoch) << 32;
    return value;
}

/// Device numbers live in `i_block`: the Linux-native encoding in the second
/// word when either half needs more than 8 bits, and the legacy 16-bit form
/// in the first word otherwise.
fn decodeDeviceNumbers(kind: GeneralKind, block_bytes: [60]u8) DeviceNumbers {
    if (kind != .block_device and kind != .char_device) return .{};
    const legacy = readInt(u32, block_bytes[0..4]);
    if (legacy != 0) {
        return .{ .major = (legacy >> 8) & 0xFF, .minor = legacy & 0xFF };
    }
    const modern = readInt(u32, block_bytes[4..8]);
    return .{
        .major = (modern >> 8) & 0xFFF,
        .minor = (modern & 0xFF) | ((modern >> 12) & 0xFFF00),
    };
}

fn generalModeToKind(mode: u16) ?GeneralKind {
    return switch (mode & 0xF000) {
        mode_dir => .directory,
        mode_reg => .file,
        mode_symlink => .symlink,
        mode_block_device => .block_device,
        mode_char_device => .char_device,
        mode_fifo => .fifo,
        else => null,
    };
}

fn generalKindToDirFileType(kind: GeneralKind) u8 {
    return switch (kind) {
        .directory => dir_ft_dir,
        .file, .hardlink => dir_ft_reg,
        .symlink => dir_ft_symlink,
        .block_device => dir_ft_block_device,
        .char_device => dir_ft_char_device,
        .fifo => dir_ft_fifo,
    };
}

fn generalChildLess(lhs: GeneralChild, rhs: GeneralChild) bool {
    return std.mem.order(u8, lhs.name, rhs.name) == .lt;
}

/// Directory order on a real filesystem is an artifact of its hash and
/// allocator. Sorting by name makes the imported tree depend only on what the
/// source contains, not on how it happened to be laid out.
fn sortGeneralChildren(children: []GeneralChild) void {
    std.mem.sort(GeneralChild, children, {}, struct {
        fn lessThan(_: void, lhs: GeneralChild, rhs: GeneralChild) bool {
            return generalChildLess(lhs, rhs);
        }
    }.lessThan);
}

fn validateGeneralPath(path: []const u8, options: GeneralScanOptions) !void {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') {
        return error.InvalidImportedPath;
    }
    limits_mod.observe(options.diagnostic, .path_bytes, path.len);
    if (path.len > options.max_path_bytes) {
        return limits_mod.exceeded(
            options.diagnostic,
            .path_bytes,
            path.len,
            options.max_path_bytes,
        );
    }
}

fn validateGeneralComponent(component: []const u8, options: GeneralScanOptions) !void {
    if (component.len == 0 or component.len > 255 or
        std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..") or
        std.mem.indexOfScalar(u8, component, 0) != null or
        std.mem.indexOfScalar(u8, component, '/') != null)
    {
        return error.InvalidImportedPath;
    }
    limits_mod.observe(options.diagnostic, .component_bytes, component.len);
    if (component.len > options.max_component_bytes) {
        return limits_mod.exceeded(
            options.diagnostic,
            .component_bytes,
            component.len,
            options.max_component_bytes,
        );
    }
}

fn appendInodeBodyXattrs(
    allocator: std.mem.Allocator,
    inode_bytes: []const u8,
    out: *std.array_list.Managed(OwnedXattr),
) !void {
    if (inode_bytes.len <= 128 + 2) return;
    const extra_isize = readInt(u16, inode_bytes[128..130]);
    const header_start = 128 + @as(usize, extra_isize);
    if (extra_isize < 4 or header_start + 4 > inode_bytes.len) return;
    if (readInt(u32, inode_bytes[header_start .. header_start + 4]) != ext4_xattr_magic) return;
    const entries_start = header_start + 4;
    try appendXattrEntries(allocator, inode_bytes, entries_start, entries_start, out);
}

/// Walks one ext4 attribute list. Entry offsets are block-relative in an
/// external block and entry-area-relative inside an inode, which is the only
/// difference between the two encodings.
fn appendXattrEntries(
    allocator: std.mem.Allocator,
    region: []const u8,
    entries_offset: usize,
    value_base: usize,
    out: *std.array_list.Managed(OwnedXattr),
) !void {
    var cursor = entries_offset;
    while (true) {
        if (cursor + 4 > region.len) return error.UnsupportedXattrLayout;
        if (readInt(u32, region[cursor .. cursor + 4]) == 0) return;
        if (cursor + 16 > region.len) return error.UnsupportedXattrLayout;
        const name_len = region[cursor];
        const name_index = region[cursor + 1];
        const value_offset = readInt(u16, region[cursor + 2 .. cursor + 4]);
        const value_inode = readInt(u32, region[cursor + 4 .. cursor + 8]);
        const value_size = readInt(u32, region[cursor + 8 .. cursor + 12]);
        if (value_inode != 0) return error.UnsupportedXattrInodeFeature;
        const entry_len = alignUpUsize(16 + @as(usize, name_len), 4);
        if (cursor + entry_len > region.len) return error.UnsupportedXattrLayout;
        const value_start = std.math.add(usize, value_base, value_offset) catch
            return error.UnsupportedXattrLayout;
        const value_end = std.math.add(usize, value_start, value_size) catch
            return error.UnsupportedXattrLayout;
        if (value_end > region.len) return error.UnsupportedXattrLayout;
        const short_name = region[cursor + 16 .. cursor + 16 + name_len];
        const name = try joinXattrName(allocator, name_index, short_name);
        errdefer allocator.free(name);
        if (name.len == 0) return error.UnsupportedXattrLayout;
        const value = try allocator.dupe(u8, region[value_start..value_end]);
        errdefer allocator.free(value);
        try out.append(.{ .name = name, .value = value });
        cursor += entry_len;
    }
}

fn readGeneralContent(
    content: *const GeneralContent,
    buffer: []u8,
    offset: u64,
) !usize {
    if (offset >= content.size) return 0;
    const remaining = std.math.cast(usize, content.size - offset) orelse
        return error.FileTooLarge;
    const want = @min(buffer.len, remaining);
    if (want == 0) return 0;

    const reader = content.reader;
    if (content.flags & inode_flag_extents == 0) {
        // The only inode without an extent tree this importer accepts is a
        // fast symlink, whose target sits in `i_block` itself.
        if (content.size >= 60) return error.UnsupportedBlockMappedInode;
        const start: usize = @intCast(offset);
        @memcpy(buffer[0..want], content.block_bytes[start .. start + want]);
        return want;
    }

    const extents = try readGeneralExtents(
        reader,
        content.io,
        reader.allocator,
        content.block_bytes[0..],
        content.inode_number,
    );
    defer reader.allocator.free(extents);

    var done: usize = 0;
    while (done < want) {
        const logical_offset = offset + done;
        const logical_block: u32 = std.math.cast(u32, logical_offset / reader.block_size) orelse
            return error.FileTooLarge;
        const within_block: usize = @intCast(logical_offset % reader.block_size);
        const chunk = @min(want - done, @as(usize, reader.block_size) - within_block);
        const mapping = findGeneralBlock(extents, logical_block);
        if (mapping) |physical| {
            try reader.readAll(
                content.io,
                buffer[done .. done + chunk],
                reader.blockOffset(physical) + within_block,
            );
        } else {
            // A hole, or an allocated-but-never-written extent. Both read as
            // zeros on a live filesystem, and preserving that is the
            // difference between importing a sparse file and importing junk.
            @memset(buffer[done .. done + chunk], 0);
        }
        done += chunk;
    }
    return done;
}

fn findGeneralBlock(extents: []const GeneralExtent, logical_block: u32) ?u64 {
    for (extents) |extent| {
        if (logical_block < extent.logical_block) continue;
        if (logical_block - extent.logical_block >= extent.block_count) continue;
        if (!extent.initialized) return null;
        return extent.start_block + (logical_block - extent.logical_block);
    }
    return null;
}

fn readGeneralExtents(
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    root_bytes: []const u8,
    inode_number: u32,
) ![]GeneralExtent {
    var extents = std.array_list.Managed(GeneralExtent).init(allocator);
    errdefer extents.deinit();
    try appendGeneralExtentNode(
        reader,
        io,
        allocator,
        root_bytes,
        max_inline_extents,
        null,
        inode_number,
        &extents,
    );
    return extents.toOwnedSlice();
}

fn appendGeneralExtentNode(
    reader: *Reader,
    io: Io,
    allocator: std.mem.Allocator,
    node_bytes: []const u8,
    capacity: usize,
    expected_depth: ?u16,
    inode_number: u32,
    extents: *std.array_list.Managed(GeneralExtent),
) !void {
    const header = try parseExtentHeader(node_bytes[0..extent_header_size]);
    if (expected_depth) |depth| {
        if (header.depth != depth) return error.UnsupportedExtentLayout;
    }
    if (header.depth > max_supported_extent_depth) return error.UnsupportedExtentDepth;
    if (header.entries > header.max or header.max > capacity) {
        return error.UnsupportedExtentLayout;
    }

    if (header.depth == 0) {
        var index: usize = 0;
        while (index < header.entries) : (index += 1) {
            const base = extent_header_size + index * extent_entry_size;
            const raw_count = readInt(u16, node_bytes[base + 4 .. base + 6]);
            const initialized = raw_count <= 32768;
            const block_count: u32 = if (initialized) raw_count else raw_count - 32768;
            if (block_count == 0) return error.UnsupportedExtent;
            const decoded = decodeExtent(node_bytes[base .. base + extent_entry_size]);
            const end = std.math.add(u64, decoded.start_block, block_count) catch
                return error.UnsupportedExtent;
            if (initialized and (decoded.start_block == 0 or end > reader.total_blocks)) {
                return error.UnsupportedExtent;
            }
            try extents.append(.{
                .logical_block = decoded.logical_block,
                .start_block = decoded.start_block,
                .block_count = block_count,
                .initialized = initialized,
            });
        }
        return;
    }

    const child_block = try allocator.alloc(u8, reader.block_size);
    defer allocator.free(child_block);
    var index: usize = 0;
    while (index < header.entries) : (index += 1) {
        const base = extent_header_size + index * extent_entry_size;
        const child = decodeExtentIndex(node_bytes[base .. base + extent_entry_size]);
        if (child.leaf_block == 0 or child.leaf_block >= reader.total_blocks) {
            return error.UnsupportedExtent;
        }
        try reader.readAll(io, child_block, reader.blockOffset(child.leaf_block));
        try appendGeneralExtentNode(
            reader,
            io,
            allocator,
            child_block,
            extentEntriesPerBlock(reader.block_size),
            header.depth - 1,
            inode_number,
            extents,
        );
    }
}

fn bitmapByteLength(bit_count: u32) usize {
    return (@as(usize, bit_count) + 7) / 8;
}

fn bitmapIsSet(bitmap: []const u8, index: u32) bool {
    return bitmap[index / 8] & (@as(u8, 1) << @intCast(index % 8)) != 0;
}

fn bitmapSet(bitmap: []u8, index: u32) void {
    bitmap[index / 8] |= @as(u8, 1) << @intCast(index % 8);
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

fn strictChildLess(lhs: StrictChild, rhs: StrictChild) bool {
    return std.mem.order(u8, lhs.name, rhs.name) == .lt;
}

fn sortStrictChildren(children: []StrictChild) void {
    var index: usize = 1;
    while (index < children.len) : (index += 1) {
        var cursor = index;
        while (cursor > 0 and strictChildLess(children[cursor], children[cursor - 1])) : (cursor -= 1) {
            std.mem.swap(StrictChild, &children[cursor], &children[cursor - 1]);
        }
    }
}

fn freeStrictChildren(allocator: std.mem.Allocator, children: []StrictChild) void {
    for (children) |child| allocator.free(child.name);
    allocator.free(children);
}

fn buildPlan(
    allocator: std.mem.Allocator,
    tree: *FileTreeView,
    options: PopulateOptions,
    journal_blocks: u32,
) PopulateError!WriterPlan {
    var entries_list = std.array_list.Managed(OwnedEntry).init(allocator);
    errdefer {
        for (entries_list.items) |entry| {
            allocator.free(entry.path);
            if (entry.hardlink_target.len > 0) allocator.free(entry.hardlink_target);
            freeOwnedXattrSlice(allocator, entry.xattrs);
        }
        entries_list.deinit();
    }

    tree.reset();
    while (try tree.next()) |entry| {
        try validateTreeEntry(entry);
        const owned_xattrs = try dupXattrs(allocator, entry.xattrs);
        errdefer freeOwnedXattrSlice(allocator, owned_xattrs);
        // Each allocation is tracked on its own because a later field in the
        // same entry can still fail -- a timestamp no inode can represent,
        // say -- and the list's cleanup only reaches entries that made it in.
        const owned_path = try allocator.dupe(u8, entry.path);
        errdefer allocator.free(owned_path);
        const owned_hardlink_target = try allocator.dupe(u8, entry.hardlink_target);
        errdefer if (owned_hardlink_target.len > 0) allocator.free(owned_hardlink_target);
        const times = try InodeTimes.from(entry);
        try entries_list.append(.{
            .path = owned_path,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = entry.content,
            .xattrs = owned_xattrs,
            .device = entry.device,
            .hardlink_target = owned_hardlink_target,
            .times = times,
        });
    }

    sortOwnedEntries(entries_list.items);
    if (hasDuplicatePaths(entries_list.items)) return error.DuplicatePath;

    const node_count = entries_list.items.len + 1;
    const nodes = try allocator.alloc(Node, node_count);
    errdefer allocator.free(nodes);
    const root_xattrs = try dupXattrs(allocator, options.root_xattrs);
    errdefer freeOwnedXattrSlice(allocator, root_xattrs);

    nodes[0] = .{
        .path = "",
        .name = "",
        .parent_path = "",
        .parent_index = 0,
        .inode = root_inode,
        .kind = .directory,
        .mode = options.root_mode,
        .uid = options.root_uid,
        .gid = options.root_gid,
        .declared_size = 0,
        .content = null,
        .xattrs = root_xattrs,
        .times = .{
            .atime = try checkedTime(options.root_atime),
            .mtime = try checkedTime(options.root_mtime),
            .ctime = try checkedTime(options.root_ctime),
            .atime_nsec = try checkedNanoseconds(options.root_atime_nsec),
            .mtime_nsec = try checkedNanoseconds(options.root_mtime_nsec),
            .ctime_nsec = try checkedNanoseconds(options.root_ctime_nsec),
            .crtime = try checkedTime(options.root_crtime),
            .crtime_nsec = try checkedNanoseconds(options.root_crtime_nsec),
        },
    };

    var next_inode = first_non_reserved_inode;
    var inode_count: usize = 1;
    for (entries_list.items, 0..) |*entry, index| {
        const parent_path = pathParent(entry.path);
        const parent_index = findNodeIndexByPath(nodes[0 .. index + 1], parent_path) orelse return error.MissingParentDirectory;
        if (nodes[parent_index].kind != .directory) return error.ParentNotDirectory;
        const owns_inode = entry.kind != .hardlink;
        nodes[index + 1] = .{
            .path = entry.path,
            .name = pathBase(entry.path),
            .parent_path = parent_path,
            .parent_index = parent_index,
            // A hardlink's inode number is only known once its target has one,
            // and the target may sort after it, so it is filled in below.
            .inode = if (owns_inode) next_inode else 0,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .declared_size = entry.size,
            .content = entry.content,
            .xattrs = entry.xattrs,
            .device = entry.device,
            .hardlink_target = entry.hardlink_target,
            .times = entry.times,
            .owns_inode = owns_inode,
        };
        entry.xattrs = &.{};
        if (owns_inode) {
            next_inode += 1;
            inode_count += 1;
        }
    }

    for (nodes) |*node| {
        if (node.owns_inode) continue;
        const target_index = findNodeIndexByPath(nodes, node.hardlink_target) orelse
            return error.MissingHardlinkTarget;
        // Only a regular file may be shared. Linking a directory would create
        // a cycle no `fsck` accepts, and every other kind carries its whole
        // state in the inode, so a second copy of it loses nothing.
        if (nodes[target_index].kind != .file) return error.UnsupportedHardlinkTarget;
        node.inode = nodes[target_index].inode;
        nodes[target_index].link_count = std.math.add(u16, nodes[target_index].link_count, 1) catch
            return error.TooManyHardlinks;
    }

    try buildDirectoryPayloads(allocator, nodes, options.block_size);

    var data_blocks_needed: u32 = 0;
    var feature_ro_compat: u32 = writer_feature_ro_compat_base;
    for (nodes) |*node| {
        switch (node.kind) {
            .directory => {
                node.size_on_disk = node.dir_bytes.?.len;
                node.data_block_count = @intCast(node.size_on_disk / options.block_size);
                data_blocks_needed += node.data_block_count;
                node.link_count = countDirectoryLinks(nodes, node.inode);
            },
            .file => {
                node.size_on_disk = node.declared_size;
                node.data_block_count = blocksForBytes(node.size_on_disk, options.block_size);
                data_blocks_needed += node.data_block_count;
                if (node.size_on_disk > std.math.maxInt(i32)) feature_ro_compat |= feature_ro_compat_large_file;
            },
            .symlink => {
                node.size_on_disk = node.declared_size;
                // A "fast" symlink stores its target inline in the inode's
                // 60-byte i_block region (bytes 40..100), relying on the
                // zero-initialized buffer to provide an implicit NUL
                // terminator for the target string. The real ext4 on-disk
                // limit is therefore `strlen <= 59`, not `<= 60`: the kernel
                // computes `disk_link.len = strlen(target) + 1` (including
                // the NUL) and requires `disk_link.len <= 60`. A target of
                // exactly 60 characters would fill the entire i_block region
                // with no room for a NUL terminator, which the kernel
                // correctly rejects on read as "invalid fast symlink length
                // 60" (confirmed via real QEMU boot testing against a real
                // Azure Linux image, see issue #74 -- a real distro symlink
                // of exactly 60 characters triggered this in practice).
                node.uses_fast_symlink = node.declared_size < 60;
                node.data_block_count = if (node.uses_fast_symlink) 0 else blocksForBytes(node.size_on_disk, options.block_size);
                data_blocks_needed += node.data_block_count;
            },
            // A device or FIFO is entirely described by its inode, and a
            // hardlink has no inode of its own at all.
            .block_device, .char_device, .fifo, .hardlink => {},
        }
        if (!node.owns_inode) continue;
        if (node.xattrs.len > 0) {
            node.xattr_block_bytes = try buildXattrBlock(allocator, node.xattrs, options.block_size);
            data_blocks_needed += 1;
        }
    }

    // The journal already owns reserved inode 8, which every layout counts as
    // used whether or not it holds anything, so only its blocks are new.
    const journal = try buildJournalNode(allocator, journal_blocks);
    errdefer allocator.free(journal);
    data_blocks_needed = std.math.add(u32, data_blocks_needed, journal_blocks) catch
        return error.NotEnoughSpace;

    return .{
        .entries = try entries_list.toOwnedSlice(),
        .nodes = nodes,
        .journal = journal,
        .feature_compat = if (journal_blocks == 0)
            writer_feature_compat
        else
            writer_feature_compat | feature_compat_has_journal,
        .feature_ro_compat = feature_ro_compat,
        .data_blocks_needed = data_blocks_needed,
        .inode_count = inode_count,
    };
}

fn buildLayout(allocator: std.mem.Allocator, total_blocks: u32, node_count: usize, data_blocks_needed: u32) PopulateError!Layout {
    const group_count = blocksToGroups(total_blocks, default_blocks_per_group);
    const gdt_blocks = @max(@as(u32, 1), blocksForBytes(@as(u64, group_count) * group_desc_size, default_block_size));

    const usable_nodes = std.math.cast(u32, node_count - 1) orelse return error.TooManyInodes;
    const total_used_inodes = first_non_reserved_inode - 1 + usable_nodes;
    var inodes_per_group = divCeil(total_used_inodes, group_count);
    const inodes_per_block = default_block_size / writer_inode_size;
    inodes_per_group = alignUpU32(@max(inodes_per_group, inodes_per_block), inodes_per_block);
    if (inodes_per_group > default_block_size * 8) return error.TooManyInodes;

    const inode_table_blocks = divCeil(@as(u32, inodes_per_group) * writer_inode_size, default_block_size);
    const groups = try allocator.alloc(GroupLayout, group_count);
    errdefer allocator.free(groups);

    var group_index: u32 = 0;
    var free_blocks: u32 = 0;
    while (group_index < group_count) : (group_index += 1) {
        const start_block = @as(u64, group_index) * default_blocks_per_group;
        const block_count = @min(default_blocks_per_group, total_blocks - @as(u32, @intCast(start_block)));
        const has_super_copy = group_index == 0 or isSparseSuperGroup(group_index);
        const super_gdt_blocks: u32 = if (has_super_copy) 1 + gdt_blocks else 0;
        const reserved_block_count = super_gdt_blocks + 2 + inode_table_blocks;
        if (reserved_block_count >= block_count) return error.NotEnoughSpace;
        groups[group_index] = .{
            .index = group_index,
            .start_block = start_block,
            .block_count = block_count,
            .has_super_copy = has_super_copy,
            .block_bitmap_block = @intCast(start_block + super_gdt_blocks),
            .inode_bitmap_block = @intCast(start_block + super_gdt_blocks + 1),
            .inode_table_block = @intCast(start_block + super_gdt_blocks + 2),
            .data_start_block = start_block + reserved_block_count,
            .reserved_block_count = reserved_block_count,
            .data_capacity = block_count - reserved_block_count,
        };
        free_blocks += groups[group_index].data_capacity;
    }
    if (data_blocks_needed > free_blocks) return error.NotEnoughSpace;

    return .{
        .total_blocks = total_blocks,
        .group_count = group_count,
        .gdt_blocks = gdt_blocks,
        .inodes_per_group = inodes_per_group,
        .inode_table_blocks = inode_table_blocks,
        .groups = groups,
    };
}

fn buildFixedLayout(
    allocator: std.mem.Allocator,
    total_blocks: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    inode_table_blocks: u32,
    gdt_blocks: u32,
) ResizeError!Layout {
    const group_count = blocksToGroups(total_blocks, blocks_per_group);
    const groups = try allocator.alloc(GroupLayout, group_count);
    errdefer allocator.free(groups);

    var group_index: u32 = 0;
    while (group_index < group_count) : (group_index += 1) {
        const start_block = @as(u64, group_index) * blocks_per_group;
        const block_count = @min(blocks_per_group, total_blocks - @as(u32, @intCast(start_block)));
        const has_super_copy = group_index == 0 or isSparseSuperGroup(group_index);
        const super_gdt_blocks: u32 = if (has_super_copy) 1 + gdt_blocks else 0;
        const reserved_block_count = super_gdt_blocks + 2 + inode_table_blocks;
        if (reserved_block_count >= block_count) return error.UnsupportedResizeLayout;
        groups[group_index] = .{
            .index = group_index,
            .start_block = start_block,
            .block_count = block_count,
            .has_super_copy = has_super_copy,
            .block_bitmap_block = @intCast(start_block + super_gdt_blocks),
            .inode_bitmap_block = @intCast(start_block + super_gdt_blocks + 1),
            .inode_table_block = @intCast(start_block + super_gdt_blocks + 2),
            .data_start_block = start_block + reserved_block_count,
            .reserved_block_count = reserved_block_count,
            .data_capacity = block_count - reserved_block_count,
        };
    }

    return .{
        .total_blocks = total_blocks,
        .group_count = group_count,
        .gdt_blocks = gdt_blocks,
        .inodes_per_group = inodes_per_group,
        .inode_table_blocks = inode_table_blocks,
        .groups = groups,
    };
}

fn assignInodesToGroups(nodes: []Node, groups: []GroupLayout, inodes_per_group: u32) void {
    for (nodes) |node| {
        if (!node.owns_inode) continue;
        const group_index = (node.inode - 1) / inodes_per_group;
        groups[group_index].used_inode_count += 1;
        if (node.kind == .directory) groups[group_index].used_dir_count += 1;
    }
    // Reserved inodes 1..10 live in group 0.
    groups[0].used_inode_count += first_non_reserved_inode - 2;
}

fn allocateNodeBlocks(
    allocator: std.mem.Allocator,
    nodes: []Node,
    block_allocator: *BlockAllocator,
) PopulateError!void {
    for (nodes) |*node| {
        if (node.data_block_count == 0) {
            node.extents = &.{};
        } else {
            node.extents = try block_allocator.allocate(allocator, node.data_block_count);
        }
        if (!node.uses_fast_symlink) {
            try allocateExtentTreeBlocks(allocator, block_allocator, node, default_block_size);
        }
        if (node.xattr_block_bytes != null) {
            node.xattr_block = try block_allocator.allocateSingle();
        }
    }
}

const BlockAllocator = struct {
    groups: []GroupLayout,
    current_group: usize = 0,

    fn allocate(self: *BlockAllocator, allocator: std.mem.Allocator, block_count: u32) PopulateError![]Extent {
        var extents = std.array_list.Managed(Extent).init(allocator);
        errdefer extents.deinit();
        var remaining = block_count;
        var logical: u32 = 0;
        while (remaining > 0) {
            while (self.current_group < self.groups.len and self.groups[self.current_group].used_data_blocks == self.groups[self.current_group].data_capacity) {
                self.current_group += 1;
            }
            if (self.current_group >= self.groups.len) return error.NotEnoughSpace;

            var group = &self.groups[self.current_group];
            const available = group.data_capacity - group.used_data_blocks;
            const take = @min(remaining, available);
            try extents.append(.{
                .logical_block = logical,
                .start_block = group.data_start_block + group.used_data_blocks,
                .block_count = @intCast(take),
            });
            group.used_data_blocks += take;
            logical += take;
            remaining -= take;
        }
        return extents.toOwnedSlice();
    }

    fn allocateSingle(self: *BlockAllocator) PopulateError!u64 {
        while (self.current_group < self.groups.len and self.groups[self.current_group].used_data_blocks == self.groups[self.current_group].data_capacity) {
            self.current_group += 1;
        }
        if (self.current_group >= self.groups.len) return error.NotEnoughSpace;
        const group = &self.groups[self.current_group];
        const block = group.data_start_block + group.used_data_blocks;
        group.used_data_blocks += 1;
        return block;
    }
};

fn writeNodeData(io: Io, file: Io.File, nodes: []Node, options: PopulateOptions) PopulateError!void {
    var scratch: [default_block_size]u8 = [_]u8{0} ** default_block_size;
    const block_len: usize = @intCast(options.block_size);
    const uuid = options.uuid orelse [_]u8{0} ** 16;
    for (nodes) |node| {
        switch (node.kind) {
            // Nothing outside the inode itself, so nothing to write here.
            .hardlink, .block_device, .char_device, .fifo => {},
            .directory => {
                const bytes = node.dir_bytes.?;
                const dir_bytes = try std.heap.page_allocator.dupe(u8, bytes);
                defer std.heap.page_allocator.free(dir_bytes);
                var block_index: usize = 0;
                while (block_index < dir_bytes.len / options.block_size) : (block_index += 1) {
                    const block = dir_bytes[block_index * options.block_size .. (block_index + 1) * options.block_size];
                    if (node.uses_hashed_directory and block_index < node.hashed_directory_index_block_count) {
                        const count_offset: usize = if (block_index == 0) 32 else 8;
                        const limit = readInt(u16, block[count_offset .. count_offset + 2]);
                        const count = readInt(u16, block[count_offset + 2 .. count_offset + 4]);
                        setDxChecksum(block, count_offset, count, limit, uuid, node.inode, 0);
                    } else {
                        setDirectoryLeafChecksum(block, uuid, node.inode, 0);
                    }
                }
                var extent_index: usize = 0;
                while (extent_index < node.extents.len) : (extent_index += 1) {
                    const extent = node.extents[extent_index];
                    const byte_len = @as(usize, extent.block_count) * options.block_size;
                    const file_off = options.offset + extent.start_block * options.block_size;
                    const src_off = @as(usize, extent.logical_block) * options.block_size;
                    try file.writePositionalAll(io, dir_bytes[src_off .. src_off + byte_len], file_off);
                }
            },
            .file, .symlink => {
                if (!node.uses_fast_symlink and node.data_block_count != 0) {
                    const content = node.content orelse return error.MissingContentReader;
                    var written_data: u64 = 0;
                    var extent_index: usize = 0;
                    while (extent_index < node.extents.len) : (extent_index += 1) {
                        const extent = node.extents[extent_index];
                        var block_index: u16 = 0;
                        while (block_index < extent.block_count) : (block_index += 1) {
                            @memset(&scratch, 0);
                            const copy_off = written_data;
                            const remaining = node.size_on_disk - copy_off;
                            const to_read = @min(@as(u64, options.block_size), remaining);
                            const want = @as(usize, @intCast(to_read));
                            if (want > 0) {
                                const got = try content.readAt(scratch[0..want], copy_off);
                                if (got != want) return error.UnexpectedContentLength;
                            }
                            const physical_block = extent.start_block + block_index;
                            try file.writePositionalAll(io, &scratch, options.offset + physical_block * options.block_size);
                            written_data += want;
                        }
                    }
                }
            },
        }
        for (node.extent_tree_blocks) |block| {
            var extent_block = block.bytes;
            setExtentBlockChecksum(extent_block[0..block_len], uuid, node.inode, 0);
            try file.writePositionalAll(io, extent_block[0..block_len], options.offset + block.block_number * options.block_size);
        }
        if (node.xattr_block_bytes) |xattr_block| {
            const block_number = node.xattr_block orelse unreachable;
            const scratch_block = try std.heap.page_allocator.dupe(u8, xattr_block);
            defer std.heap.page_allocator.free(scratch_block);
            setXattrBlockChecksum(scratch_block, uuid, block_number);
            try file.writePositionalAll(io, scratch_block, options.offset + block_number * options.block_size);
        }
    }
}

/// Writes the journal's own blocks: a JBD2 superblock in logical block 0 and
/// zeros everywhere else. Zeroing the rest is not decoration -- the range may
/// hold whatever the output file already contained, and a stale block that
/// happens to carry a JBD2 descriptor magic is exactly the kind of thing a
/// recovery pass is built to believe.
fn writeJournalData(io: Io, file: Io.File, journal: []const Node, options: PopulateOptions) PopulateError!void {
    if (journal.len == 0) return;
    const node = journal[0];
    const uuid = options.uuid orelse [_]u8{0} ** 16;
    const block_len: usize = @intCast(options.block_size);

    var block: [default_block_size]u8 = undefined;
    encodeJournalSuperblock(&block, node.data_block_count, uuid);
    var written_blocks: u32 = 0;
    for (node.extents) |extent| {
        var index: u16 = 0;
        while (index < extent.block_count) : (index += 1) {
            const physical = extent.start_block + index;
            try file.writePositionalAll(io, block[0..block_len], options.offset + physical * options.block_size);
            written_blocks += 1;
            // Every block after the superblock is an unwritten log block.
            if (written_blocks == 1) @memset(&block, 0);
        }
    }

    for (node.extent_tree_blocks) |tree_block| {
        var extent_block = tree_block.bytes;
        setExtentBlockChecksum(extent_block[0..block_len], uuid, node.inode, 0);
        try file.writePositionalAll(io, extent_block[0..block_len], options.offset + tree_block.block_number * options.block_size);
    }
}

/// Encodes the JBD2 superblock exactly as `mke2fs` does for an internal
/// journal: a V2 header, an empty log (`s_start == 0`, so nothing is ever
/// replayed from it), and no journal feature bits at all. The absence of
/// bits is deliberate rather than an omission -- e2fsprogs leaves
/// `CSUM_V3` unset even on a `metadata_csum` filesystem, and the kernel sets
/// it, together with the superblock checksum it then implies, on first mount.
/// Writing a checksum here that the kernel would recompute differently is
/// worse than writing none, because a journal superblock the kernel trusts
/// and cannot verify is how a bad log gets replayed over good data.
///
/// Every field is big-endian, unlike the rest of ext4.
fn encodeJournalSuperblock(block: *[default_block_size]u8, block_count: u32, uuid: [16]u8) void {
    @memset(block, 0);
    writeBigInt(u32, block[0x00..0x04], jbd2_magic);
    writeBigInt(u32, block[0x04..0x08], jbd2_superblock_v2);
    // s_header.h_sequence stays 0; only log blocks carry a sequence.
    writeBigInt(u32, block[0x0C..0x10], default_block_size);
    writeBigInt(u32, block[0x10..0x14], block_count);
    // s_first: log data starts in the block after the superblock.
    writeBigInt(u32, block[0x14..0x18], 1);
    // s_sequence: the first commit ID the log expects. s_start stays 0, which
    // is what marks the log empty.
    writeBigInt(u32, block[0x18..0x1C], 1);
    @memcpy(block[0x30..0x40], &uuid);
    // s_nr_users: one filesystem shares this log, namely its own.
    writeBigInt(u32, block[0x40..0x44], 1);
}

fn zeroUnusedInodeTableBlocks(io: Io, file: Io.File, layout: Layout, offset: u64) PopulateError!void {
    const zero_block: [default_block_size]u8 = [_]u8{0} ** default_block_size;
    for (layout.groups) |group| {
        var block: u32 = 0;
        while (block < layout.inode_table_blocks) : (block += 1) {
            try file.writePositionalAll(io, &zero_block, offset + (@as(u64, group.inode_table_block) + block) * default_block_size);
        }
    }
}

fn buildGroupBitmaps(layout: Layout, group: GroupLayout, block_bitmap: []u8, inode_bitmap: []u8) void {
    @memset(block_bitmap, 0);
    @memset(inode_bitmap, 0);

    var bit: u32 = 0;
    while (bit < group.reserved_block_count + group.used_data_blocks) : (bit += 1) {
        setBitmapBit(block_bitmap, bit);
    }
    bit = group.block_count;
    while (bit < default_block_size * 8) : (bit += 1) {
        setBitmapBit(block_bitmap, bit);
    }

    bit = 0;
    while (bit < group.used_inode_count) : (bit += 1) {
        setBitmapBit(inode_bitmap, bit);
    }
    bit = layout.inodes_per_group;
    while (bit < default_block_size * 8) : (bit += 1) {
        setBitmapBit(inode_bitmap, bit);
    }
}

fn writeBitmaps(io: Io, file: Io.File, layout: Layout, offset: u64) PopulateError!void {
    var block_bitmap: [default_block_size]u8 = undefined;
    var inode_bitmap: [default_block_size]u8 = undefined;

    for (layout.groups) |group| {
        buildGroupBitmaps(layout, group, &block_bitmap, &inode_bitmap);
        try file.writePositionalAll(io, &block_bitmap, offset + @as(u64, group.block_bitmap_block) * default_block_size);
        try file.writePositionalAll(io, &inode_bitmap, offset + @as(u64, group.inode_bitmap_block) * default_block_size);
    }
}

fn writeInodes(io: Io, file: Io.File, nodes: []Node, layout: Layout, options: PopulateOptions) PopulateError!void {
    const uuid = options.uuid orelse [_]u8{0} ** 16;
    for (nodes) |node| {
        // A hardlink shares the target's inode, which the target already
        // wrote; writing it twice would be redundant at best and would
        // overwrite the target's own link count at worst.
        if (!node.owns_inode) continue;
        var buf: [writer_inode_size]u8 = [_]u8{0} ** writer_inode_size;
        writeInt(u16, buf[0..2], inodeMode(node));
        writeInt(u16, buf[2..4], @truncate(node.uid));
        writeInt(u32, buf[4..8], @truncate(node.size_on_disk));
        const times = node.times.resolve(options.timestamp);
        const atime = try encodeInodeTime(times[0]);
        const ctime = try encodeInodeTime(times[1]);
        const mtime = try encodeInodeTime(times[2]);
        writeInt(u32, buf[8..12], atime.seconds);
        writeInt(u32, buf[12..16], ctime.seconds);
        writeInt(u32, buf[16..20], mtime.seconds);
        writeInt(u16, buf[24..26], @truncate(node.gid));
        writeInt(u16, buf[26..28], node.link_count);
        writeInt(u32, buf[28..32], inodeSectorCount(node));
        const inline_inode = node.uses_fast_symlink or
            node.kind == .block_device or node.kind == .char_device or node.kind == .fifo;
        var inode_flags: u32 = if (inline_inode) 0 else inode_flag_extents;
        if (node.uses_hashed_directory) inode_flags |= inode_flag_index;
        writeInt(u32, buf[32..36], inode_flags);

        if (node.kind == .block_device or node.kind == .char_device) {
            // The Linux-native encoding in the second `i_block` word covers
            // every number a modern device can carry; the legacy first-word
            // form is left zero so the kernel reads the wide one.
            writeInt(u32, buf[44..48], (node.device.major << 8) |
                (node.device.minor & 0xFF) | ((node.device.minor & 0xFFF00) << 12));
        } else if (node.kind == .fifo) {
            // A FIFO stores nothing at all.
        } else if (node.uses_fast_symlink) {
            const want: usize = @intCast(node.declared_size);
            if (want > 0) {
                const content = node.content orelse return error.MissingContentReader;
                const got = try content.readAt(buf[40 .. 40 + want], 0);
                if (got != want) return error.UnexpectedContentLength;
            }
        } else {
            @memcpy(buf[40..100], &node.extent_root);
        }

        writeInt(u32, buf[104..108], @truncate(node.xattr_block orelse 0));
        writeInt(u32, buf[108..112], @as(u32, @truncate(node.size_on_disk >> 32)));
        writeInt(u16, buf[120..122], @as(u16, @truncate(node.uid >> 16)));
        writeInt(u16, buf[122..124], @as(u16, @truncate(node.gid >> 16)));

        // The extra region. `i_extra_isize` has to come first: every other
        // field here is only considered present because it covers them, and
        // that includes `i_checksum_hi`, so it must be set before the
        // checksum is computed.
        writeInt(u16, buf[128..130], writer_extra_isize);
        writeInt(u32, buf[132..136], encodeInodeExtra(ctime.epoch, node.times.ctime_nsec));
        writeInt(u32, buf[136..140], encodeInodeExtra(mtime.epoch, node.times.mtime_nsec));
        writeInt(u32, buf[140..144], encodeInodeExtra(atime.epoch, node.times.atime_nsec));
        // A node the source carried keeps the creation time the source gave
        // it. A node this build is genuinely creating has none to keep, and
        // the build timestamp is then the honest answer rather than a
        // borrowed one.
        const crtime = try encodeInodeTime(node.times.crtime orelse options.timestamp);
        writeInt(u32, buf[144..148], crtime.seconds);
        writeInt(u32, buf[148..152], encodeInodeExtra(crtime.epoch, node.times.crtime_nsec));

        setInodeChecksum(&buf, uuid, node.inode);

        const group_index = (node.inode - 1) / layout.inodes_per_group;
        const index_in_group = (node.inode - 1) % layout.inodes_per_group;
        const group = layout.groups[group_index];
        const inode_offset = options.offset + @as(u64, group.inode_table_block) * options.block_size + @as(u64, index_in_group) * writer_inode_size;
        try file.writePositionalAll(io, &buf, inode_offset);
    }
}

fn writeGroupDescriptorTables(io: Io, file: Io.File, layout: Layout, offset: u64, uuid: [16]u8) PopulateError!void {
    const desc_bytes = @as(usize, layout.group_count) * group_desc_size;
    const table_bytes = @as(usize, layout.gdt_blocks) * default_block_size;
    const buf = try std.heap.page_allocator.alloc(u8, table_bytes);
    defer std.heap.page_allocator.free(buf);
    @memset(buf, 0);
    var block_bitmap: [default_block_size]u8 = undefined;
    var inode_bitmap: [default_block_size]u8 = undefined;
    for (layout.groups, 0..) |group, index| {
        const base = index * group_desc_size;
        buildGroupBitmaps(layout, group, &block_bitmap, &inode_bitmap);
        writeInt(u32, buf[base + 0 .. base + 4], group.block_bitmap_block);
        writeInt(u32, buf[base + 4 .. base + 8], group.inode_bitmap_block);
        writeInt(u32, buf[base + 8 .. base + 12], group.inode_table_block);
        writeInt(u16, buf[base + 12 .. base + 14], @intCast(group.block_count - group.reserved_block_count - group.used_data_blocks));
        writeInt(u16, buf[base + 14 .. base + 16], @intCast(layout.inodes_per_group - group.used_inode_count));
        writeInt(u16, buf[base + 16 .. base + 18], @intCast(group.used_dir_count));
        writeInt(u16, buf[base + 0x18 .. base + 0x1A], @truncate(bitmapChecksum(uuid, &block_bitmap, default_blocks_per_group / 8)));
        writeInt(u16, buf[base + 0x1A .. base + 0x1C], @truncate(bitmapChecksum(uuid, &inode_bitmap, layout.inodes_per_group / 8)));
        writeInt(u16, buf[base + 0x1C .. base + 0x1E], @intCast(layout.inodes_per_group - group.used_inode_count));
    }
    _ = desc_bytes;
    setGroupDescriptorChecksums(buf[0 .. @as(usize, layout.group_count) * group_desc_size], layout, uuid);

    try file.writePositionalAll(io, buf, offset + default_block_size);
    for (layout.groups) |group| {
        if (group.index == 0 or !group.has_super_copy) continue;
        try file.writePositionalAll(io, buf, offset + (group.start_block + 1) * default_block_size);
    }
}

fn writeSuperblocks(io: Io, file: Io.File, layout: Layout, plan: WriterPlan, options: PopulateOptions) PopulateError!void {
    var sb: [superblock_size]u8 = [_]u8{0} ** superblock_size;
    const label = encodeLabel(options.label);
    const uuid = options.uuid orelse [_]u8{0} ** 16;
    const free_blocks = countFreeBlocks(layout.groups);
    const free_inodes = countFreeInodes(layout.groups, layout.inodes_per_group);

    writeInt(u32, sb[0x00..0x04], layout.group_count * layout.inodes_per_group);
    writeInt(u32, sb[0x04..0x08], layout.total_blocks);
    writeInt(u32, sb[0x08..0x0C], 0);
    writeInt(u32, sb[0x0C..0x10], free_blocks);
    writeInt(u32, sb[0x10..0x14], free_inodes);
    writeInt(u32, sb[0x14..0x18], 0);
    writeInt(u32, sb[0x18..0x1C], 2);
    writeInt(u32, sb[0x1C..0x20], 2);
    writeInt(u32, sb[0x20..0x24], default_blocks_per_group);
    writeInt(u32, sb[0x24..0x28], default_blocks_per_group);
    writeInt(u32, sb[0x28..0x2C], layout.inodes_per_group);
    writeInt(u32, sb[0x2C..0x30], options.timestamp);
    writeInt(u32, sb[0x30..0x34], options.timestamp);
    writeInt(u16, sb[0x34..0x36], 0);
    writeInt(u16, sb[0x36..0x38], 0xFFFF);
    writeInt(u16, sb[0x38..0x3A], super_magic);
    writeInt(u16, sb[0x3A..0x3C], state_clean);
    writeInt(u16, sb[0x3C..0x3E], errors_continue);
    writeInt(u16, sb[0x3E..0x40], 0);
    writeInt(u32, sb[0x40..0x44], options.timestamp);
    writeInt(u32, sb[0x44..0x48], 0);
    writeInt(u32, sb[0x48..0x4C], creator_os_linux);
    writeInt(u32, sb[0x4C..0x50], rev_dynamic);
    writeInt(u16, sb[0x50..0x52], 0);
    writeInt(u16, sb[0x52..0x54], 0);
    writeInt(u32, sb[0x54..0x58], first_non_reserved_inode);
    writeInt(u16, sb[0x58..0x5A], writer_inode_size);
    writeInt(u16, sb[0x5A..0x5C], 0);
    writeInt(u32, sb[0x5C..0x60], plan.feature_compat);
    writeInt(u32, sb[0x60..0x64], writer_feature_incompat);
    writeInt(u32, sb[0x64..0x68], plan.feature_ro_compat);
    sb[0x68..0x78].* = uuid;
    sb[0x78..0x88].* = label;
    writeInt(u8, sb[0xCC..0xCD], 0);
    writeInt(u8, sb[0xCD..0xCE], 0);
    writeInt(u16, sb[0xCE..0xD0], 0);
    writeInt(u8, sb[0xFC..0xFD], dx_hash_half_md4);
    writeInt(u8, sb[0xFD..0xFE], 0);
    writeInt(u16, sb[0xFE..0x100], group_desc_size);
    writeInt(u32, sb[0x108..0x10C], options.timestamp);
    // `s_min_extra_isize` / `s_want_extra_isize`. The first is a promise that
    // every inode already has that many extra bytes filled in, which is what
    // makes `RO_COMPAT_EXTRA_ISIZE` safe to set; the second is what a kernel
    // growing an inode should aim for. `mke2fs` writes 32 for both.
    writeInt(u16, sb[0x15C..0x15E], writer_extra_isize);
    writeInt(u16, sb[0x15E..0x160], writer_extra_isize);
    writeInt(u8, sb[0x175..0x176], super_checksum_type_crc32c);
    if (plan.journal.len != 0) {
        const journal = plan.journal[0];
        writeInt(u32, sb[0xE0..0xE4], journal_inode);
        // `s_journal_uuid` stays zero: that field names an *external* journal
        // device, and a non-zero value there would send the kernel looking
        // for a separate volume that does not exist.
        writeInt(u8, sb[0xFD..0xFE], jnl_backup_type_blocks);
        // `s_jnl_blocks` is the journal inode's 60-byte `i_block` array
        // followed by the high and low halves of its size, in that order.
        @memcpy(sb[0x10C..0x148], &journal.extent_root);
        writeInt(u32, sb[0x148..0x14C], @as(u32, @truncate(journal.size_on_disk >> 32)));
        writeInt(u32, sb[0x14C..0x150], @as(u32, @truncate(journal.size_on_disk)));
    }
    setSuperblockChecksum(&sb);

    try file.writePositionalAll(io, &sb, options.offset + superblock_offset);
    for (layout.groups) |group| {
        if (group.index == 0 or !group.has_super_copy) continue;
        writeInt(u16, sb[0x5A..0x5C], @intCast(group.index));
        setSuperblockChecksum(&sb);
        try file.writePositionalAll(io, &sb, options.offset + group.start_block * options.block_size);
    }
}

fn buildDirectoryPayloads(allocator: std.mem.Allocator, nodes: []Node, block_size: u32) PopulateError!void {
    for (nodes, 0..) |*node, index| {
        if (node.kind != .directory) continue;

        var linear_specs = std.array_list.Managed(DirEntrySpec).init(allocator);
        defer linear_specs.deinit();

        try linear_specs.append(.{ .inode = node.inode, .kind = .directory, .name = "." });
        const parent_inode = if (index == 0) node.inode else nodes[node.parent_index].inode;
        try linear_specs.append(.{ .inode = parent_inode, .kind = .directory, .name = ".." });

        var child_specs = std.array_list.Managed(DirEntrySpec).init(allocator);
        defer child_specs.deinit();

        for (nodes, 0..) |child, child_index| {
            if (child_index == 0) continue;
            if (child.parent_index == index) {
                const spec: DirEntrySpec = .{ .inode = child.inode, .kind = child.kind, .name = child.name };
                try linear_specs.append(spec);
                try child_specs.append(spec);
            }
        }

        const linear_bytes = try buildLinearDirectoryBytes(allocator, linear_specs.items, block_size);
        if (linear_bytes.len <= block_size or child_specs.items.len == 0) {
            node.dir_bytes = linear_bytes;
            continue;
        }

        allocator.free(linear_bytes);
        node.uses_hashed_directory = true;
        const indexed = try buildIndexedDirectoryBytes(allocator, node.inode, parent_inode, child_specs.items, block_size);
        node.dir_bytes = indexed.bytes;
        node.hashed_directory_index_block_count = indexed.index_block_count;
    }
}

const DirEntrySpec = struct {
    inode: u32,
    kind: Kind,
    name: []const u8,
};

const HashedDirEntry = struct {
    spec: DirEntrySpec,
    hash: u32,
};

const IndexedDirectoryBytes = struct {
    bytes: []u8,
    index_block_count: u32,
};

const HtreeChild = struct {
    start_hash: u32,
    target: union(enum) {
        leaf: usize,
        node: struct {
            level: usize,
            index: usize,
        },
    },
};

const HtreeInteriorNode = struct {
    start_hash: u32,
    children: []HtreeChild,
    logical_block: u32 = 0,
};

fn dirEntryMinRecLen(name_len: usize) u16 {
    return alignUpU16(@as(u16, @intCast(8 + name_len)), dir_entry_alignment);
}

fn buildLinearDirectoryBytes(allocator: std.mem.Allocator, specs: []const DirEntrySpec, block_size: u32) PopulateError![]u8 {
    var bytes = std.array_list.Managed(u8).init(allocator);
    errdefer bytes.deinit();
    try appendDirectoryLeafBlocks(&bytes, specs, block_size);
    return bytes.toOwnedSlice();
}

fn appendDirectoryLeafBlocks(bytes: *std.array_list.Managed(u8), specs: []const DirEntrySpec, block_size: u32) PopulateError!void {
    const usable = block_size - 12;
    var cursor: usize = 0;
    while (cursor < specs.len) {
        const block_start = bytes.items.len;
        try bytes.appendNTimes(0, block_size);
        var pos: usize = 0;
        while (cursor < specs.len) {
            const entry = specs[cursor];
            const min_rec_len = dirEntryMinRecLen(entry.name.len);
            const next_min = if (cursor + 1 < specs.len) dirEntryMinRecLen(specs[cursor + 1].name.len) else 0;
            if (pos + min_rec_len > usable) return error.InvalidDirectorySize;
            const rec_len: u16 = if (cursor + 1 == specs.len or pos + min_rec_len + next_min > usable)
                @intCast(usable - pos)
            else
                min_rec_len;
            encodeDirEntry(bytes.items[block_start + pos .. block_start + pos + rec_len], entry, rec_len);
            pos += rec_len;
            cursor += 1;
            if (pos == usable) break;
        }
        putDirectoryLeafTail(bytes.items[block_start .. block_start + block_size]);
    }
}

fn hashedDirEntryLess(lhs: HashedDirEntry, rhs: HashedDirEntry) bool {
    if (lhs.hash != rhs.hash) return lhs.hash < rhs.hash;
    return std.mem.order(u8, lhs.spec.name, rhs.spec.name) == .lt;
}

fn sortHashedDirEntries(entries: []HashedDirEntry) void {
    var i: usize = 1;
    while (i < entries.len) : (i += 1) {
        var j = i;
        while (j > 0 and hashedDirEntryLess(entries[j], entries[j - 1])) : (j -= 1) {
            std.mem.swap(HashedDirEntry, &entries[j], &entries[j - 1]);
        }
    }
}

fn buildIndexedDirectoryBytes(
    allocator: std.mem.Allocator,
    inode_number: u32,
    parent_inode: u32,
    children: []const DirEntrySpec,
    block_size: u32,
) PopulateError!IndexedDirectoryBytes {
    const hashed = try allocator.alloc(HashedDirEntry, children.len);
    defer allocator.free(hashed);
    for (children, 0..) |child, index| {
        hashed[index] = .{ .spec = child, .hash = dirHash(child.name) };
    }
    sortHashedDirEntries(hashed);

    const leaves = try buildIndexedDirectoryLeaves(allocator, hashed, block_size);
    defer allocator.free(leaves.start_hashes);
    errdefer allocator.free(leaves.bytes);

    const root_limit = dxRootLimit(block_size);
    const node_limit = dxNodeLimit(block_size);

    var level_nodes = std.array_list.Managed([]HtreeInteriorNode).init(allocator);
    defer {
        for (level_nodes.items) |nodes| {
            for (nodes) |node| allocator.free(node.children);
            allocator.free(nodes);
        }
        level_nodes.deinit();
    }

    var root_children = try allocator.alloc(HtreeChild, leaves.start_hashes.len);
    defer allocator.free(root_children);
    for (leaves.start_hashes, 0..) |start_hash, index| {
        root_children[index] = .{
            .start_hash = start_hash,
            .target = .{ .leaf = index },
        };
    }

    while (root_children.len > root_limit) {
        const level_index = level_nodes.items.len;
        const node_count = divCeil(root_children.len, node_limit);
        const nodes = try allocator.alloc(HtreeInteriorNode, node_count);
        errdefer allocator.free(nodes);

        const next_children = try allocator.alloc(HtreeChild, node_count);
        errdefer allocator.free(next_children);

        var built: usize = 0;
        errdefer {
            while (built > 0) : (built -= 1) allocator.free(nodes[built - 1].children);
        }

        for (0..node_count) |node_index| {
            const start = node_index * node_limit;
            const end = @min(start + node_limit, root_children.len);
            const node_children = try allocator.dupe(HtreeChild, root_children[start..end]);
            nodes[node_index] = .{
                .start_hash = root_children[start].start_hash,
                .children = node_children,
            };
            next_children[node_index] = .{
                .start_hash = root_children[start].start_hash,
                .target = .{ .node = .{ .level = level_index, .index = node_index } },
            };
            built += 1;
        }

        try level_nodes.append(nodes);
        allocator.free(root_children);
        root_children = next_children;
    }

    var next_logical_block: u32 = 1;
    var reverse_level = level_nodes.items.len;
    while (reverse_level > 0) {
        reverse_level -= 1;
        for (level_nodes.items[reverse_level]) |*node| {
            node.logical_block = next_logical_block;
            next_logical_block += 1;
        }
    }

    const index_block_count = next_logical_block;
    const leaf_block_base = index_block_count;
    const total_blocks = index_block_count + @as(u32, @intCast(leaves.start_hashes.len));
    const total_bytes = @as(usize, total_blocks) * block_size;
    const bytes = try allocator.alloc(u8, total_bytes);
    @memset(bytes, 0);

    encodeDxRootBlock(
        bytes[0..block_size],
        inode_number,
        parent_inode,
        @intCast(level_nodes.items.len),
        root_limit,
        root_children,
        level_nodes.items,
        leaf_block_base,
    );

    reverse_level = level_nodes.items.len;
    while (reverse_level > 0) {
        reverse_level -= 1;
        for (level_nodes.items[reverse_level]) |node| {
            const block_start = @as(usize, node.logical_block) * block_size;
            encodeDxNodeBlock(
                bytes[block_start .. block_start + block_size],
                node_limit,
                node.children,
                level_nodes.items,
                leaf_block_base,
            );
        }
    }

    const leaf_bytes_start = @as(usize, leaf_block_base) * block_size;
    @memcpy(bytes[leaf_bytes_start .. leaf_bytes_start + leaves.bytes.len], leaves.bytes);
    allocator.free(leaves.bytes);

    return .{
        .bytes = bytes,
        .index_block_count = index_block_count,
    };
}

fn buildIndexedDirectoryLeaves(
    allocator: std.mem.Allocator,
    hashed: []const HashedDirEntry,
    block_size: u32,
) PopulateError!struct { bytes: []u8, start_hashes: []u32 } {
    var bytes = std.array_list.Managed(u8).init(allocator);
    errdefer bytes.deinit();

    var start_hashes = std.array_list.Managed(u32).init(allocator);
    errdefer start_hashes.deinit();

    const usable = block_size - 12;
    var cursor: usize = 0;
    while (cursor < hashed.len) {
        try start_hashes.append(hashed[cursor].hash);
        const block_start = bytes.items.len;
        try bytes.appendNTimes(0, block_size);
        var pos: usize = 0;
        while (cursor < hashed.len) {
            const entry = hashed[cursor].spec;
            const min_rec_len = dirEntryMinRecLen(entry.name.len);
            const next_min = if (cursor + 1 < hashed.len) dirEntryMinRecLen(hashed[cursor + 1].spec.name.len) else 0;
            if (pos + min_rec_len > usable) return error.InvalidDirectorySize;
            const rec_len: u16 = if (cursor + 1 == hashed.len or pos + min_rec_len + next_min > usable)
                @intCast(usable - pos)
            else
                min_rec_len;
            encodeDirEntry(bytes.items[block_start + pos .. block_start + pos + rec_len], entry, rec_len);
            pos += rec_len;
            cursor += 1;
            if (pos == usable) break;
        }
        putDirectoryLeafTail(bytes.items[block_start .. block_start + block_size]);
    }

    return .{
        .bytes = try bytes.toOwnedSlice(),
        .start_hashes = try start_hashes.toOwnedSlice(),
    };
}

fn dxRootLimit(block_size: u32) usize {
    return (block_size - 32 - 8) / 8;
}

fn dxNodeLimit(block_size: u32) usize {
    return (block_size - 8 - 8) / 8;
}

fn dxBoundaryHash(previous_start_hash: u32, current_start_hash: u32) u32 {
    return if (current_start_hash == previous_start_hash) current_start_hash | 1 else current_start_hash;
}

fn resolveHtreeChildBlock(
    child: HtreeChild,
    levels: []const []const HtreeInteriorNode,
    leaf_block_base: u32,
) u32 {
    return switch (child.target) {
        .leaf => |index| leaf_block_base + @as(u32, @intCast(index)),
        .node => |node_ref| levels[node_ref.level][node_ref.index].logical_block,
    };
}

fn writeDxEntries(
    buf: []u8,
    count_offset: usize,
    limit: usize,
    children: []const HtreeChild,
    levels: []const []const HtreeInteriorNode,
    leaf_block_base: u32,
) void {
    std.debug.assert(children.len > 0);
    writeInt(u16, buf[count_offset .. count_offset + 2], @intCast(limit));
    writeInt(u16, buf[count_offset + 2 .. count_offset + 4], @intCast(children.len));
    writeInt(u32, buf[count_offset + 4 .. count_offset + 8], resolveHtreeChildBlock(children[0], levels, leaf_block_base));

    var previous_start_hash = children[0].start_hash;
    for (children[1..], 1..) |child, child_index| {
        const base = count_offset + child_index * 8;
        writeInt(u32, buf[base .. base + 4], dxBoundaryHash(previous_start_hash, child.start_hash));
        writeInt(u32, buf[base + 4 .. base + 8], resolveHtreeChildBlock(child, levels, leaf_block_base));
        previous_start_hash = child.start_hash;
    }
}

fn encodeDxRootBlock(
    buf: []u8,
    inode_number: u32,
    parent_inode: u32,
    indirect_levels: u8,
    limit: usize,
    children: []const HtreeChild,
    levels: []const []const HtreeInteriorNode,
    leaf_block_base: u32,
) void {
    @memset(buf, 0);
    encodeDirEntry(buf[0..12], .{ .inode = inode_number, .kind = .directory, .name = "." }, 12);
    encodeDirEntry(buf[12..buf.len], .{ .inode = parent_inode, .kind = .directory, .name = ".." }, @intCast(buf.len - 12));
    buf[28] = dx_hash_half_md4;
    buf[29] = 8;
    buf[30] = indirect_levels;
    writeDxEntries(buf, 32, limit, children, levels, leaf_block_base);
}

fn encodeDxNodeBlock(
    buf: []u8,
    limit: usize,
    children: []const HtreeChild,
    levels: []const []const HtreeInteriorNode,
    leaf_block_base: u32,
) void {
    @memset(buf, 0);
    writeInt(u16, buf[4..6], @intCast(buf.len));
    writeDxEntries(buf, 8, limit, children, levels, leaf_block_base);
}

fn validateTreeEntry(entry: FileTreeView.Entry) PopulateError!void {
    if (entry.path.len == 0) return error.RootEntryForbidden;
    if (entry.path[0] == '/' or entry.path[entry.path.len - 1] == '/') return error.InvalidPath;
    if (entry.kind == .directory and entry.size != 0) return error.InvalidDirectorySize;
    if ((entry.kind == .file or entry.kind == .symlink) and entry.size > 0 and entry.content == null) return error.MissingContentReader;
    switch (entry.kind) {
        .hardlink => {
            if (entry.hardlink_target.len == 0) return error.MissingHardlinkTarget;
            if (std.mem.eql(u8, entry.hardlink_target, entry.path)) return error.UnsupportedHardlinkTarget;
            if (entry.size != 0 or entry.xattrs.len != 0) return error.UnsupportedHardlinkTarget;
        },
        .block_device, .char_device => {
            // The device numbers are the entire content of the node, so a
            // truncating write would produce a node pointing somewhere else.
            if (entry.size != 0) return error.InvalidDeviceEntry;
            if (entry.device.major > 0xFFF or entry.device.minor > 0xF_FFFF) {
                return error.InvalidDeviceEntry;
            }
        },
        .fifo => if (entry.size != 0) return error.InvalidDeviceEntry,
        .directory, .file, .symlink => if (entry.hardlink_target.len != 0) {
            return error.UnsupportedHardlinkTarget;
        },
    }
    if (std.mem.eql(u8, entry.path, ".") or std.mem.eql(u8, entry.path, "..")) return error.InvalidPath;

    var start: usize = 0;
    while (start < entry.path.len) {
        var end = start;
        while (end < entry.path.len and entry.path[end] != '/') : (end += 1) {
            if (entry.path[end] == 0) return error.InvalidPath;
        }
        if (end == start) return error.InvalidPath;
        const component = entry.path[start..end];
        if (component.len > 255 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.InvalidPath;
        start = end + 1;
    }

    for (entry.xattrs, 0..) |xattr, index| {
        _ = try splitXattrName(xattr.name);
        var other = index + 1;
        while (other < entry.xattrs.len) : (other += 1) {
            if (std.mem.eql(u8, xattr.name, entry.xattrs[other].name)) return error.InvalidXattr;
        }
    }
}

fn sortOwnedEntries(entries: []OwnedEntry) void {
    var i: usize = 1;
    while (i < entries.len) : (i += 1) {
        var j = i;
        while (j > 0 and ownedEntryLess(entries[j], entries[j - 1])) : (j -= 1) {
            std.mem.swap(OwnedEntry, &entries[j], &entries[j - 1]);
        }
    }
}

fn hasDuplicatePaths(entries: []const OwnedEntry) bool {
    var i: usize = 1;
    while (i < entries.len) : (i += 1) {
        if (std.mem.eql(u8, entries[i - 1].path, entries[i].path)) return true;
    }
    return false;
}

fn ownedEntryLess(a: OwnedEntry, b: OwnedEntry) bool {
    const da = pathDepth(a.path);
    const db = pathDepth(b.path);
    if (da != db) return da < db;
    return std.mem.order(u8, a.path, b.path) == .lt;
}

fn pathDepth(path: []const u8) usize {
    if (path.len == 0) return 0;
    var count: usize = 1;
    for (path) |c| {
        if (c == '/') count += 1;
    }
    return count;
}

fn pathParent(path: []const u8) []const u8 {
    const index = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "";
    return path[0..index];
}

fn pathBase(path: []const u8) []const u8 {
    const index = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[index + 1 ..];
}

fn findNodeIndexByPath(nodes: []const Node, path: []const u8) ?usize {
    for (nodes, 0..) |node, index| {
        if (std.mem.eql(u8, node.path, path)) return index;
    }
    return null;
}

fn countDirectoryLinks(nodes: []const Node, dir_inode: u32) u16 {
    var count: u16 = 2;
    for (nodes) |node| {
        if (node.kind == .directory and node.inode != dir_inode) {
            const parent_inode = nodes[node.parent_index].inode;
            if (parent_inode == dir_inode) count += 1;
        }
    }
    return count;
}

fn blocksForBytes(bytes: u64, block_size: u32) u32 {
    if (bytes == 0) return 0;
    return @intCast(divCeil(bytes, block_size));
}

fn blocksToGroups(total_blocks: u32, blocks_per_group: u32) u32 {
    return @intCast(divCeil(total_blocks, blocks_per_group));
}

fn countFreeBlocks(groups: []const GroupLayout) u32 {
    var total: u32 = 0;
    for (groups) |group| total += group.block_count - group.reserved_block_count - group.used_data_blocks;
    return total;
}

fn countFreeInodes(groups: []const GroupLayout, inodes_per_group: u32) u32 {
    var total: u32 = 0;
    for (groups) |group| total += inodes_per_group - group.used_inode_count;
    return total;
}

fn isSparseSuperGroup(index: u32) bool {
    if (index <= 1) return true;
    return isPowerOf(index, 3) or isPowerOf(index, 5) or isPowerOf(index, 7);
}

fn isPowerOf(value: u32, base: u32) bool {
    var current = value;
    while (current > 1 and current % base == 0) current /= base;
    return current == 1;
}

fn encodeDirEntry(buf: []u8, entry: DirEntrySpec, rec_len: u16) void {
    @memset(buf, 0);
    writeInt(u32, buf[0..4], entry.inode);
    writeInt(u16, buf[4..6], rec_len);
    buf[6] = @intCast(entry.name.len);
    buf[7] = kindToDirFileType(entry.kind);
    @memcpy(buf[8 .. 8 + entry.name.len], entry.name);
}

fn setBitmapBit(bitmap: []u8, index: u32) void {
    bitmap[index / 8] |= @as(u8, 1) << @intCast(index % 8);
}

fn inodeMode(node: Node) u16 {
    return kindToModeBits(node.kind) | (node.mode & 0x0FFF);
}

fn inodeSectorCount(node: Node) u32 {
    const extent_tree_block_count: u32 = @intCast(node.extent_tree_blocks.len);
    const xattr_block_count: u32 = if (node.xattr_block != null) 1 else 0;
    return (node.data_block_count + extent_tree_block_count + xattr_block_count) * sectors_per_block;
}

fn encodeExtentHeader(buf: []u8, entries: usize, max_entries: usize, depth: u16) void {
    @memset(buf, 0);
    writeInt(u16, buf[0..2], extent_magic);
    writeInt(u16, buf[2..4], @intCast(entries));
    writeInt(u16, buf[4..6], @intCast(max_entries));
    writeInt(u16, buf[6..8], depth);
    writeInt(u32, buf[8..12], 0);
}

fn encodeExtentLeafNode(buf: []u8, max_entries: usize, extents: []const Extent) void {
    encodeExtentHeader(buf, extents.len, max_entries, 0);
    for (extents, 0..) |extent, index| {
        const base = extent_header_size + index * extent_entry_size;
        writeInt(u32, buf[base .. base + 4], extent.logical_block);
        writeInt(u16, buf[base + 4 .. base + 6], extent.block_count);
        writeInt(u16, buf[base + 6 .. base + 8], @as(u16, @truncate(extent.start_block >> 32)));
        writeInt(u32, buf[base + 8 .. base + 12], @as(u32, @truncate(extent.start_block)));
    }
}

fn encodeExtentIndexNode(buf: []u8, max_entries: usize, depth: u16, children: []const ExtentNodeRef) void {
    encodeExtentHeader(buf, children.len, max_entries, depth);
    for (children, 0..) |child, index| {
        const base = extent_header_size + index * extent_entry_size;
        writeInt(u32, buf[base .. base + 4], child.logical_block);
        writeInt(u32, buf[base + 4 .. base + 8], @as(u32, @truncate(child.block_number)));
        writeInt(u16, buf[base + 8 .. base + 10], @as(u16, @truncate(child.block_number >> 32)));
        writeInt(u16, buf[base + 10 .. base + 12], 0);
    }
}

fn extentTailOffset(max_entries: usize) usize {
    return extent_header_size + max_entries * extent_entry_size;
}

fn extentEntriesPerBlock(block_size: u32) usize {
    const max_entries: usize = @intCast((block_size - extent_header_size) / extent_entry_size);
    const block_len: usize = @intCast(block_size);
    std.debug.assert(extentTailOffset(max_entries) + extent_tail_size <= block_len);
    return max_entries;
}

fn extentTreeShape(extent_count: usize, block_size: u32) PopulateError!struct { depth: u16, block_count: usize } {
    if (extent_count <= max_inline_extents) return .{ .depth = 0, .block_count = 0 };

    const block_capacity = extentEntriesPerBlock(block_size);
    var depth: u16 = 1;
    var nodes_at_level = divCeil(extent_count, block_capacity);
    var total_blocks = nodes_at_level;
    while (nodes_at_level > max_inline_extents) {
        if (depth == max_supported_extent_depth) return error.TooManyExtents;
        nodes_at_level = divCeil(nodes_at_level, block_capacity);
        total_blocks += nodes_at_level;
        depth += 1;
    }
    return .{ .depth = depth, .block_count = total_blocks };
}

fn allocateExtentTreeBlocks(
    allocator: std.mem.Allocator,
    block_allocator: *BlockAllocator,
    node: *Node,
    block_size: u32,
) PopulateError!void {
    const shape = try extentTreeShape(node.extents.len, block_size);
    if (shape.block_count > 0) {
        // Published to the node only once every block number in it has been
        // filled in. Failing part-way through must not leave the node
        // holding a slice this function has already freed: whoever owns the
        // node frees it again on the way out, and a double free of a
        // half-built plan is a crash a long way from its cause.
        const blocks = try allocator.alloc(ExtentTreeBlock, shape.block_count);
        errdefer allocator.free(blocks);
        for (blocks) |*block| {
            block.* = .{ .block_number = try block_allocator.allocateSingle() };
        }
        node.extent_tree_blocks = blocks;
    } else {
        node.extent_tree_blocks = &.{};
    }
    try buildExtentTree(allocator, node, block_size, shape.depth);
}

fn buildExtentTree(allocator: std.mem.Allocator, node: *Node, block_size: u32, depth: u16) PopulateError!void {
    if (depth == 0) {
        encodeExtentLeafNode(node.extent_root[0..], max_inline_extents, node.extents);
        return;
    }

    const block_capacity = extentEntriesPerBlock(block_size);
    const leaf_count = divCeil(node.extents.len, block_capacity);
    var current = try allocator.alloc(ExtentNodeRef, leaf_count);
    defer allocator.free(current);

    var block_cursor: usize = 0;
    var leaf_index: usize = 0;
    while (leaf_index < leaf_count) : (leaf_index += 1) {
        const start = leaf_index * block_capacity;
        const end = @min(start + block_capacity, node.extents.len);
        encodeExtentLeafNode(node.extent_tree_blocks[block_cursor].bytes[0..], block_capacity, node.extents[start..end]);
        current[leaf_index] = .{
            .logical_block = node.extents[start].logical_block,
            .block_number = node.extent_tree_blocks[block_cursor].block_number,
        };
        block_cursor += 1;
    }

    var child_depth: u16 = 0;
    while (current.len > max_inline_extents) {
        const next_count = divCeil(current.len, block_capacity);
        const next = try allocator.alloc(ExtentNodeRef, next_count);
        var parent_index: usize = 0;
        while (parent_index < next_count) : (parent_index += 1) {
            const start = parent_index * block_capacity;
            const end = @min(start + block_capacity, current.len);
            encodeExtentIndexNode(
                node.extent_tree_blocks[block_cursor].bytes[0..],
                block_capacity,
                child_depth + 1,
                current[start..end],
            );
            next[parent_index] = .{
                .logical_block = current[start].logical_block,
                .block_number = node.extent_tree_blocks[block_cursor].block_number,
            };
            block_cursor += 1;
        }
        allocator.free(current);
        current = next;
        child_depth += 1;
    }

    encodeExtentIndexNode(node.extent_root[0..], max_inline_extents, child_depth + 1, current);
}

fn encodeLabel(label: []const u8) [16]u8 {
    var out: [16]u8 = [_]u8{0} ** 16;
    @memcpy(out[0..label.len], label);
    return out;
}

fn kindToModeBits(kind: Kind) u16 {
    return switch (kind) {
        .directory => mode_dir,
        .file, .hardlink => mode_reg,
        .symlink => mode_symlink,
        .block_device => mode_block_device,
        .char_device => mode_char_device,
        .fifo => mode_fifo,
    };
}

fn kindToDirFileType(kind: Kind) u8 {
    return switch (kind) {
        .directory => dir_ft_dir,
        .file, .hardlink => dir_ft_reg,
        .symlink => dir_ft_symlink,
        .block_device => dir_ft_block_device,
        .char_device => dir_ft_char_device,
        .fifo => dir_ft_fifo,
    };
}

fn dirFileTypeToKind(file_type: u8) Kind {
    return switch (file_type) {
        dir_ft_dir => .directory,
        dir_ft_symlink => .symlink,
        else => .file,
    };
}

fn modeToKind(mode: u16) ?Kind {
    return switch (mode & 0xF000) {
        mode_dir => .directory,
        mode_reg => .file,
        mode_symlink => .symlink,
        else => null,
    };
}

fn parseExtentHeader(buf: []const u8) ReadError!ExtentHeader {
    if (readInt(u16, buf[0..2]) != extent_magic) return error.UnsupportedInodeLayout;
    return .{
        .entries = readInt(u16, buf[2..4]),
        .max = readInt(u16, buf[4..6]),
        .depth = readInt(u16, buf[6..8]),
        .generation = readInt(u32, buf[8..12]),
    };
}

fn decodeExtent(buf: []const u8) Extent {
    const start_hi = readInt(u16, buf[6..8]);
    const start_lo = readInt(u32, buf[8..12]);
    return .{
        .logical_block = readInt(u32, buf[0..4]),
        .start_block = (@as(u64, start_hi) << 32) | start_lo,
        .block_count = readInt(u16, buf[4..6]),
    };
}

fn decodeExtentIndex(buf: []const u8) ExtentIndex {
    const leaf_lo = readInt(u32, buf[4..8]);
    const leaf_hi = readInt(u16, buf[8..10]);
    return .{
        .logical_block = readInt(u32, buf[0..4]),
        .leaf_block = (@as(u64, leaf_hi) << 32) | leaf_lo,
    };
}

fn findPhysicalBlock(extents: []const Extent, logical_block: u32) ?u64 {
    for (extents) |extent| {
        if (logical_block >= extent.logical_block and logical_block < extent.logical_block + extent.block_count) {
            return extent.start_block + (logical_block - extent.logical_block);
        }
    }
    return null;
}

fn readInt(comptime T: type, buf: []const u8) T {
    return std.mem.readInt(T, buf[0..@sizeOf(T)], .little);
}

fn writeInt(comptime T: type, buf: []u8, value: T) void {
    std.mem.writeInt(T, buf[0..@sizeOf(T)], value, .little);
}

/// JBD2 stores every field big-endian, so its encoder needs a writer of its
/// own rather than silently reusing the little-endian one beside it.
fn writeBigInt(comptime T: type, buf: []u8, value: T) void {
    std.mem.writeInt(T, buf[0..@sizeOf(T)], value, .big);
}

fn divCeil(a: anytype, b: anytype) @TypeOf(a, b) {
    return std.math.divCeil(@TypeOf(a, b), a, b) catch unreachable;
}

fn alignUpU16(value: u16, alignment: usize) u16 {
    return @intCast((@as(usize, value) + alignment - 1) / alignment * alignment);
}

fn alignUpU32(value: u32, alignment: u32) u32 {
    return @intCast((@as(u64, value) + alignment - 1) / alignment * alignment);
}

fn alignUpUsize(value: usize, alignment: usize) usize {
    return (value + alignment - 1) / alignment * alignment;
}

fn alignDownUsize(value: usize, alignment: usize) usize {
    return value / alignment * alignment;
}

fn freeOwnedXattrSlice(allocator: std.mem.Allocator, xattrs: []OwnedXattr) void {
    for (xattrs) |xattr| {
        allocator.free(xattr.name);
        allocator.free(xattr.value);
    }
    allocator.free(xattrs);
}

fn dupXattrs(allocator: std.mem.Allocator, xattrs: []const Xattr) PopulateError![]OwnedXattr {
    const owned = try allocator.alloc(OwnedXattr, xattrs.len);
    errdefer {
        var index: usize = 0;
        while (index < xattrs.len) : (index += 1) {
            allocator.free(owned[index].name);
            allocator.free(owned[index].value);
        }
        allocator.free(owned);
    }
    for (xattrs, 0..) |xattr, index| {
        owned[index] = .{
            .name = try allocator.dupe(u8, xattr.name),
            .value = try allocator.dupe(u8, xattr.value),
        };
    }
    return owned;
}

/// ext4 stores an attribute name as a prefix index plus the remainder, and
/// POSIX ACLs have whole-name indexes of their own rather than sharing the
/// generic `system.` prefix. Those two names are matched first so an imported
/// ACL is re-emitted with the same index a kernel would have written.
fn splitXattrName(full_name: []const u8) PopulateError!struct { index: u8, short_name: []const u8 } {
    if (full_name.len == 0) return error.InvalidXattr;
    if (std.mem.eql(u8, full_name, posix_acl_access_name)) {
        return .{ .index = xattr_name_posix_acl_access, .short_name = "" };
    }
    if (std.mem.eql(u8, full_name, posix_acl_default_name)) {
        return .{ .index = xattr_name_posix_acl_default, .short_name = "" };
    }
    inline for (.{
        .{ .prefix = "user.", .index = xattr_name_user },
        .{ .prefix = "trusted.", .index = xattr_name_trusted },
        .{ .prefix = "security.", .index = xattr_name_security },
        .{ .prefix = "system.", .index = xattr_name_system },
    }) |candidate| {
        if (std.mem.startsWith(u8, full_name, candidate.prefix)) {
            const short_name = full_name[candidate.prefix.len..];
            if (short_name.len == 0 or short_name.len > 255) return error.InvalidXattr;
            return .{ .index = candidate.index, .short_name = short_name };
        }
    }
    if (full_name.len > 255) return error.InvalidXattr;
    return .{ .index = 0, .short_name = full_name };
}

const posix_acl_access_name = "system.posix_acl_access";
const posix_acl_default_name = "system.posix_acl_default";

fn joinXattrName(allocator: std.mem.Allocator, index: u8, short_name: []const u8) std.mem.Allocator.Error![]u8 {
    const prefix = switch (index) {
        xattr_name_user => "user.",
        xattr_name_posix_acl_access => posix_acl_access_name,
        xattr_name_posix_acl_default => posix_acl_default_name,
        xattr_name_trusted => "trusted.",
        xattr_name_security => "security.",
        xattr_name_system => "system.",
        else => "",
    };
    var full_name = try allocator.alloc(u8, prefix.len + short_name.len);
    std.mem.copyForwards(u8, full_name[0..prefix.len], prefix);
    std.mem.copyForwards(u8, full_name[prefix.len..], short_name);
    return full_name;
}

const XattrBlockEntry = struct {
    name_index: u8,
    short_name: []const u8,
    value: []const u8,
};

fn xattrEntryLess(lhs: XattrBlockEntry, rhs: XattrBlockEntry) bool {
    if (lhs.name_index != rhs.name_index) return lhs.name_index < rhs.name_index;
    if (lhs.short_name.len != rhs.short_name.len) return lhs.short_name.len < rhs.short_name.len;
    return std.mem.order(u8, lhs.short_name, rhs.short_name) == .lt;
}

fn sortXattrEntries(entries: []XattrBlockEntry) void {
    var i: usize = 1;
    while (i < entries.len) : (i += 1) {
        var j = i;
        while (j > 0 and xattrEntryLess(entries[j], entries[j - 1])) : (j -= 1) {
            std.mem.swap(XattrBlockEntry, &entries[j], &entries[j - 1]);
        }
    }
}

const Ext4Crc32c = std.hash.crc.Crc(u32, .{
    .polynomial = 0x1edc6f41,
    .initial = 0xffff_ffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000_0000,
});

fn ext4Crc32c(chunks: []const []const u8) u32 {
    var hasher = Ext4Crc32c.init();
    for (chunks) |chunk| hasher.update(chunk);
    return hasher.final();
}

fn xattrEntryHash(name: []const u8, value: []const u8) u32 {
    var hash: u32 = 0;
    for (name) |byte| {
        hash = (hash << 5) ^ (hash >> (32 - 5)) ^ byte;
    }
    var index: usize = 0;
    while (index < value.len) : (index += 4) {
        const word = readInt(u32, value[index .. index + 4]);
        hash = (hash << 16) ^ (hash >> (32 - 16)) ^ word;
    }
    return hash;
}

fn xattrBlockHash(entry_hashes: []const u32) u32 {
    var hash: u32 = 0;
    for (entry_hashes) |entry_hash| {
        if (entry_hash == 0) return 0;
        hash = (hash << 16) ^ (hash >> (32 - 16)) ^ entry_hash;
    }
    return hash;
}

fn buildXattrBlock(allocator: std.mem.Allocator, xattrs: []const OwnedXattr, block_size: u32) PopulateError![]u8 {
    var entries = try allocator.alloc(XattrBlockEntry, xattrs.len);
    defer allocator.free(entries);
    for (xattrs, 0..) |xattr, index| {
        const parsed = try splitXattrName(xattr.name);
        entries[index] = .{
            .name_index = parsed.index,
            .short_name = parsed.short_name,
            .value = xattr.value,
        };
    }
    sortXattrEntries(entries);

    const block = try allocator.alloc(u8, block_size);
    errdefer allocator.free(block);
    @memset(block, 0);

    writeInt(u32, block[0..4], ext4_xattr_magic);
    writeInt(u32, block[4..8], 1);
    writeInt(u32, block[8..12], 1);

    var value_cursor: usize = block_size;
    var entry_cursor: usize = 32;
    const entry_hashes = try allocator.alloc(u32, entries.len);
    defer allocator.free(entry_hashes);

    for (entries, 0..) |entry, index| {
        const entry_len = alignUpU16(@as(u16, @intCast(16 + entry.short_name.len)), 4);
        if (entry_cursor + entry_len + 4 > value_cursor) return error.XattrTooLarge;

        const padded_len = alignUpUsize(entry.value.len, 4);
        value_cursor = alignDownUsize(value_cursor - padded_len, 4);
        if (value_cursor < entry_cursor + entry_len + 4) return error.XattrTooLarge;
        std.mem.copyForwards(u8, block[value_cursor .. value_cursor + entry.value.len], entry.value);

        const value_words = block[value_cursor .. value_cursor + padded_len];
        entry_hashes[index] = xattrEntryHash(entry.short_name, value_words);

        block[entry_cursor] = @intCast(entry.short_name.len);
        block[entry_cursor + 1] = entry.name_index;
        writeInt(u16, block[entry_cursor + 2 .. entry_cursor + 4], @intCast(value_cursor));
        writeInt(u32, block[entry_cursor + 4 .. entry_cursor + 8], 0);
        writeInt(u32, block[entry_cursor + 8 .. entry_cursor + 12], @intCast(entry.value.len));
        writeInt(u32, block[entry_cursor + 12 .. entry_cursor + 16], entry_hashes[index]);
        std.mem.copyForwards(u8, block[entry_cursor + 16 .. entry_cursor + 16 + entry.short_name.len], entry.short_name);
        entry_cursor += entry_len;
    }

    if (entry_cursor + 4 > value_cursor) return error.XattrTooLarge;
    writeInt(u32, block[12..16], xattrBlockHash(entry_hashes));
    return block;
}

fn putDirectoryLeafTail(block: []u8) void {
    const tail = block[block.len - 12 ..];
    @memset(tail, 0);
    writeInt(u16, tail[4..6], 12);
    tail[7] = dir_ft_checksum;
}

fn setDirectoryLeafChecksum(block: []u8, uuid: [16]u8, inode_number: u32, inode_generation: u32) void {
    var inode_le = std.mem.nativeToLittle(u32, inode_number);
    var generation_le = std.mem.nativeToLittle(u32, inode_generation);
    writeInt(u32, block[block.len - 4 ..], ext4Crc32c(&.{
        &uuid,
        std.mem.asBytes(&inode_le),
        std.mem.asBytes(&generation_le),
        block[0 .. block.len - 12],
    }));
}

fn setExtentBlockChecksum(block: []u8, uuid: [16]u8, inode_number: u32, inode_generation: u32) void {
    std.debug.assert(readInt(u16, block[0..2]) == extent_magic);
    const tail_offset = extentTailOffset(@intCast(readInt(u16, block[4..6])));
    std.debug.assert(tail_offset + extent_tail_size <= block.len);

    var inode_le = std.mem.nativeToLittle(u32, inode_number);
    var generation_le = std.mem.nativeToLittle(u32, inode_generation);
    writeInt(u32, block[tail_offset .. tail_offset + extent_tail_size], ext4Crc32c(&.{
        &uuid,
        std.mem.asBytes(&inode_le),
        std.mem.asBytes(&generation_le),
        block[0..tail_offset],
    }));
}

fn setDxChecksum(block: []u8, count_offset: usize, count: usize, limit: usize, uuid: [16]u8, inode_number: u32, inode_generation: u32) void {
    var inode_le = std.mem.nativeToLittle(u32, inode_number);
    var generation_le = std.mem.nativeToLittle(u32, inode_generation);
    const tail_offset = count_offset + limit * 8;
    const tail = block[tail_offset .. tail_offset + 8];
    @memset(tail, 0);
    writeInt(u32, tail[4..8], ext4Crc32c(&.{
        &uuid,
        std.mem.asBytes(&inode_le),
        std.mem.asBytes(&generation_le),
        block[0 .. count_offset + count * 8],
        tail[0..4],
        tail[4..8],
    }));
}

fn setXattrBlockChecksum(block: []u8, uuid: [16]u8, block_number: u64) void {
    var block_le = std.mem.nativeToLittle(u64, block_number);
    writeInt(u32, block[0x10..0x14], 0);
    writeInt(u32, block[0x10..0x14], ext4Crc32c(&.{
        &uuid,
        std.mem.asBytes(&block_le),
        block,
    }));
}

/// crc32c over the whole raw inode with the stored checksum zeroed. On an
/// inode wide enough for `i_checksum_hi` -- which `i_extra_isize` has to
/// reach for the field to count as present -- the checksum is 32 bits split
/// across two non-adjacent halves, and both must be cleared before hashing.
fn setInodeChecksum(block: []u8, uuid: [16]u8, inode_number: u32) void {
    var inode_le = std.mem.nativeToLittle(u32, inode_number);
    var generation_le = std.mem.nativeToLittle(u32, @as(u32, 0));
    const wide = block.len >= 132 and readInt(u16, block[128..130]) >= 4;
    writeInt(u16, block[124..126], 0);
    if (wide) writeInt(u16, block[130..132], 0);
    const checksum = ext4Crc32c(&.{
        &uuid,
        std.mem.asBytes(&inode_le),
        std.mem.asBytes(&generation_le),
        block,
    });
    writeInt(u16, block[124..126], @truncate(checksum));
    if (wide) writeInt(u16, block[130..132], @truncate(checksum >> 16));
}

fn setSuperblockChecksum(sb: []u8) void {
    writeInt(u32, sb[0x3FC..0x400], ext4Crc32c(&.{sb[0..0x3FC]}));
}

fn bitmapChecksum(uuid: [16]u8, bitmap: []const u8, used_bytes: usize) u32 {
    return ext4Crc32c(&.{ &uuid, bitmap[0..used_bytes] });
}

fn setGroupDescriptorChecksums(gdt: []u8, layout: Layout, uuid: [16]u8) void {
    for (layout.groups, 0..) |_, index| {
        const base = index * group_desc_size;
        const desc = gdt[base .. base + group_desc_size];
        var group_le = std.mem.nativeToLittle(u32, @as(u32, @intCast(index)));
        writeInt(u16, desc[0x1E..0x20], 0);
        writeInt(u16, desc[0x1E..0x20], @truncate(ext4Crc32c(&.{
            &uuid,
            std.mem.asBytes(&group_le),
            desc,
        })));
    }
}

fn md4Rotate(value: u32, comptime shift: u5) u32 {
    return std.math.rotl(u32, value, shift);
}

fn md4F(x: u32, y: u32, z: u32) u32 {
    return z ^ (x & (y ^ z));
}

fn md4G(x: u32, y: u32, z: u32) u32 {
    return (x & y) +% ((x ^ y) & z);
}

fn md4H(x: u32, y: u32, z: u32) u32 {
    return x ^ y ^ z;
}

fn halfMd4Transform(buf: *[4]u32, input: [8]u32) u32 {
    var a = buf[0];
    var b = buf[1];
    var c = buf[2];
    var d = buf[3];

    inline for (.{
        .{ .f = md4F, .x = 0, .s = @as(u5, 3) },  .{ .f = md4F, .x = 1, .s = @as(u5, 7) },
        .{ .f = md4F, .x = 2, .s = @as(u5, 11) }, .{ .f = md4F, .x = 3, .s = @as(u5, 19) },
        .{ .f = md4F, .x = 4, .s = @as(u5, 3) },  .{ .f = md4F, .x = 5, .s = @as(u5, 7) },
        .{ .f = md4F, .x = 6, .s = @as(u5, 11) }, .{ .f = md4F, .x = 7, .s = @as(u5, 19) },
    }, 0..) |step, index| {
        switch (index % 4) {
            0 => a = md4Rotate(a +% step.f(b, c, d) +% input[step.x], step.s),
            1 => d = md4Rotate(d +% step.f(a, b, c) +% input[step.x], step.s),
            2 => c = md4Rotate(c +% step.f(d, a, b) +% input[step.x], step.s),
            else => b = md4Rotate(b +% step.f(c, d, a) +% input[step.x], step.s),
        }
    }

    inline for (.{
        .{ .x = 1, .s = @as(u5, 3) }, .{ .x = 3, .s = @as(u5, 5) },
        .{ .x = 5, .s = @as(u5, 9) }, .{ .x = 7, .s = @as(u5, 13) },
        .{ .x = 0, .s = @as(u5, 3) }, .{ .x = 2, .s = @as(u5, 5) },
        .{ .x = 4, .s = @as(u5, 9) }, .{ .x = 6, .s = @as(u5, 13) },
    }, 0..) |step, index| {
        const value = input[step.x] +% 0x5A82_7999;
        switch (index % 4) {
            0 => a = md4Rotate(a +% md4G(b, c, d) +% value, step.s),
            1 => d = md4Rotate(d +% md4G(a, b, c) +% value, step.s),
            2 => c = md4Rotate(c +% md4G(d, a, b) +% value, step.s),
            else => b = md4Rotate(b +% md4G(c, d, a) +% value, step.s),
        }
    }

    inline for (.{
        .{ .x = 3, .s = @as(u5, 3) },  .{ .x = 7, .s = @as(u5, 9) },
        .{ .x = 2, .s = @as(u5, 11) }, .{ .x = 6, .s = @as(u5, 15) },
        .{ .x = 1, .s = @as(u5, 3) },  .{ .x = 5, .s = @as(u5, 9) },
        .{ .x = 0, .s = @as(u5, 11) }, .{ .x = 4, .s = @as(u5, 15) },
    }, 0..) |step, index| {
        const value = input[step.x] +% 0x6ED9_EBA1;
        switch (index % 4) {
            0 => a = md4Rotate(a +% md4H(b, c, d) +% value, step.s),
            1 => d = md4Rotate(d +% md4H(a, b, c) +% value, step.s),
            2 => c = md4Rotate(c +% md4H(d, a, b) +% value, step.s),
            else => b = md4Rotate(b +% md4H(c, d, a) +% value, step.s),
        }
    }

    buf[0] +%= a;
    buf[1] +%= b;
    buf[2] +%= c;
    buf[3] +%= d;
    return buf[1];
}

fn strToHalfMd4Words(name: []const u8, start: usize) [8]u32 {
    var out: [8]u32 = undefined;
    const remaining = if (start < name.len) name[start..] else "";
    const len = @min(remaining.len, 32);
    var pad = @as(u32, @intCast(len));
    pad |= pad << 8;
    pad |= pad << 16;

    var index: usize = 0;
    while (index < out.len) : (index += 1) out[index] = pad;

    var cursor: usize = 0;
    index = 0;
    while (cursor + 4 <= len and index < out.len) : ({
        cursor += 4;
        index += 1;
    }) {
        const chunk = remaining[cursor .. cursor + 4];
        out[index] = (signedByteToU32(chunk[0]) << 24) |
            (signedByteToU32(chunk[1]) << 16) |
            (signedByteToU32(chunk[2]) << 8) |
            signedByteToU32(chunk[3]);
    }

    if (index < out.len) {
        var value = pad;
        var offset = cursor;
        while (offset < len) : (offset += 1) {
            value = signedByteToU32(remaining[offset]) +% (value << 8);
        }
        out[index] = value;
    }
    return out;
}

fn signedByteToU32(byte: u8) u32 {
    const signed: i32 = @as(i8, @bitCast(byte));
    return @bitCast(signed);
}

fn dirHash(name: []const u8) u32 {
    var buf = [4]u32{ 0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476 };
    var offset: usize = 0;
    while (offset < name.len or (name.len == 0 and offset == 0)) : (offset += 32) {
        const words = strToHalfMd4Words(name, offset);
        _ = halfMd4Transform(&buf, words);
        if (name.len == 0) break;
    }
    var hash = buf[1] & ~@as(u32, 1);
    if (hash == 0xFFFF_FFFE) hash = 0xFFFF_FFFC;
    return hash;
}

test "populate ext4 and round-trip a small tree with a multi-extent file" {
    const io = std.testing.io;
    const path = "test-ext4-roundtrip.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const fs_size: u64 = 160 * 1024 * 1024;
    const big_size: u64 = 130 * 1024 * 1024;

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "boot", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "boot/kernel.bin", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 14, .bytes = "kernel-payload" },
        .{ .path = "boot/initrd.img", .kind = .file, .mode = 0o600, .uid = 42, .gid = 24, .size = big_size, .generator = .pattern },
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 1000, .gid = 1000, .size = 10, .bytes = "zvmi-test\n" },
        .{ .path = "usr", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "usr/bin", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "usr/bin/tool", .kind = .file, .mode = 0o755, .uid = 0, .gid = 0, .size = 7, .bytes = "#!/bin\n" },
        .{ .path = "vmlinuz", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 15, .bytes = "boot/kernel.bin" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    const info = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = fs_size,
        .label = "zvmi-ext4",
        .uuid = [_]u8{0x10} ** 16,
        .timestamp = 1_717_171_717,
    });
    try std.testing.expectEqual(writer_feature_compat, info.feature_compat);
    try std.testing.expectEqual(writer_feature_incompat, info.feature_incompat);
    try std.testing.expectEqual(writer_feature_ro_compat_base, info.feature_ro_compat & writer_feature_ro_compat_base);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    const root_entries = try reader.listDir(io, std.testing.allocator, "");
    defer freeDirEntries(std.testing.allocator, root_entries);
    try expectDirNames(root_entries, &.{ "boot", "etc", "usr", "vmlinuz" });

    const boot_entries = try reader.listDir(io, std.testing.allocator, "boot");
    defer freeDirEntries(std.testing.allocator, boot_entries);
    try expectDirNames(boot_entries, &.{ "initrd.img", "kernel.bin" });

    const hostname = try reader.readFileAlloc(io, std.testing.allocator, "etc/hostname");
    defer std.testing.allocator.free(hostname);
    try std.testing.expectEqualSlices(u8, "zvmi-test\n", hostname);

    const link = try reader.readLinkAlloc(io, std.testing.allocator, "vmlinuz");
    defer std.testing.allocator.free(link);
    try std.testing.expectEqualSlices(u8, "boot/kernel.bin", link);

    const tool_stat = try reader.statPath(io, "usr/bin/tool");
    try std.testing.expectEqual(Kind.file, tool_stat.kind);
    try std.testing.expectEqual(@as(u16, 0o755), tool_stat.mode);

    const big_stat = try reader.statPath(io, "boot/initrd.img");
    try std.testing.expectEqual(Kind.file, big_stat.kind);
    try std.testing.expectEqual(big_size, big_stat.size);
    try std.testing.expectEqual(@as(u32, 42), big_stat.uid);
    try std.testing.expectEqual(@as(u32, 24), big_stat.gid);

    const extents = try reader.readExtents(io, std.testing.allocator, "boot/initrd.img");
    defer std.testing.allocator.free(extents);
    try std.testing.expect(extents.len >= 2);

    var offset: u64 = 0;
    var buf: [64 * 1024]u8 = undefined;
    var expected: [64 * 1024]u8 = undefined;
    while (offset < big_size) {
        const chunk = @min(buf.len, @as(usize, @intCast(big_size - offset)));
        const got = try reader.preadPath(io, "boot/initrd.img", buf[0..chunk], offset);
        try std.testing.expectEqual(chunk, got);
        fillPattern(expected[0..chunk], offset);
        try std.testing.expectEqualSlices(u8, expected[0..chunk], buf[0..chunk]);
        offset += chunk;
    }
}

test "symlink targets at the 60-byte fast-symlink boundary round-trip correctly" {
    // Regression test for a real off-by-one bug found via real QEMU boot
    // testing against a real Azure Linux image (see issue #74): a symlink
    // target of exactly 60 characters was incorrectly written as a "fast"
    // (inline) symlink, filling the entire 60-byte i_block region with no
    // room for the implicit NUL terminator real ext4 requires -- the real
    // kernel rejected it on read with "invalid fast symlink length 60".
    // The real ext4 limit is `strlen <= 59` for fast symlinks; anything
    // longer must be stored as a regular (data-block-backed) symlink.
    const io = std.testing.io;
    const path = "test-ext4-symlink-boundary.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const target_59 = "a" ** 59;
    const target_60 = "a" ** 60;
    const target_61 = "a" ** 61;

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "link-59", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = target_59.len, .bytes = target_59 },
        .{ .path = "link-60", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = target_60.len, .bytes = target_60 },
        .{ .path = "link-61", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = target_61.len, .bytes = target_61 },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = 64 * 1024 * 1024,
        .label = "zvmi-ext4",
        .uuid = [_]u8{0x11} ** 16,
        .timestamp = 1_717_171_717,
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    const link_59 = try reader.readLinkAlloc(io, std.testing.allocator, "link-59");
    defer std.testing.allocator.free(link_59);
    try std.testing.expectEqualSlices(u8, target_59, link_59);

    const link_60 = try reader.readLinkAlloc(io, std.testing.allocator, "link-60");
    defer std.testing.allocator.free(link_60);
    try std.testing.expectEqualSlices(u8, target_60, link_60);

    const link_61 = try reader.readLinkAlloc(io, std.testing.allocator, "link-61");
    defer std.testing.allocator.free(link_61);
    try std.testing.expectEqualSlices(u8, target_61, link_61);

    // Verify the on-disk representation, not just content round-trip:
    // a 59-char target must be stored inline (no extents at all), while
    // 60+ char targets must be stored as real, block-mapped ("slow")
    // symlinks with at least one extent. Content-only round-trip alone
    // doesn't catch the original bug, since a self-consistent writer+reader
    // pair that both share the same off-by-one still round-trips content
    // correctly -- it's only incompatible with a *real* Linux kernel, which
    // enforces `strlen < 60` for inline storage independently.
    const extents_59 = try reader.readExtents(io, std.testing.allocator, "link-59");
    defer std.testing.allocator.free(extents_59);
    try std.testing.expectEqual(@as(usize, 0), extents_59.len);

    const extents_60 = try reader.readExtents(io, std.testing.allocator, "link-60");
    defer std.testing.allocator.free(extents_60);
    try std.testing.expect(extents_60.len >= 1);

    const extents_61 = try reader.readExtents(io, std.testing.allocator, "link-61");
    defer std.testing.allocator.free(extents_61);
    try std.testing.expect(extents_61.len >= 1);
}

test "populate round-trips files that require extent index blocks" {
    const io = std.testing.io;
    const path = "test-ext4-multilevel-extents.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const fs_size: u64 = 768 * 1024 * 1024;
    const big_size: u64 = 544 * 1024 * 1024;

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "boot", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "boot/rootfs.img", .kind = .file, .mode = 0o600, .uid = 0, .gid = 0, .size = big_size, .generator = .pattern },
    });
    tree.bind();

    {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        _ = try populate(io, file, std.testing.allocator, &tree.view, .{
            .length = fs_size,
            .uuid = [_]u8{0x33} ** 16,
            .timestamp = 1_717_171_717,
        });

        var reader = try open(io, file, std.testing.allocator, .{});
        defer reader.deinit();

        const inode_number = try reader.lookupPath(io, "boot/rootfs.img");
        const inode = try reader.readInode(io, inode_number);
        const root_header = try parseExtentHeader(inode.block_bytes[0..extent_header_size]);
        try std.testing.expectEqual(@as(u16, 1), root_header.depth);

        const extents = try reader.readExtents(io, std.testing.allocator, "boot/rootfs.img");
        defer std.testing.allocator.free(extents);
        try std.testing.expect(extents.len > max_inline_extents);

        var offset: u64 = 0;
        var buf: [1024 * 1024]u8 = undefined;
        var expected: [1024 * 1024]u8 = undefined;
        while (offset < big_size) {
            const chunk = @min(buf.len, @as(usize, @intCast(big_size - offset)));
            const got = try reader.preadPath(io, "boot/rootfs.img", buf[0..chunk], offset);
            try std.testing.expectEqual(chunk, got);
            fillPattern(expected[0..chunk], offset);
            try std.testing.expectEqualSlices(u8, expected[0..chunk], buf[0..chunk]);
            offset += chunk;
        }
    }

    const maybe_result = try runE2fsck(std.testing.allocator, path);
    const result = maybe_result orelse {
        std.debug.print("skipping e2fsck validation: e2fsck not found (tried PATH, /sbin, /usr/sbin)\n", .{});
        return error.SkipZigTest;
    };
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("e2fsck -f -n reported problems (exit {d}):\nstdout:\n{s}\nstderr:\n{s}\n", .{ code, result.stdout, result.stderr });
            }
            try std.testing.expectEqual(@as(u8, 0), code);
        },
        else => {
            std.debug.print("e2fsck did not exit normally:\nstdout:\n{s}\nstderr:\n{s}\n", .{ result.stdout, result.stderr });
            return error.TestUnexpectedResult;
        },
    }
}

test "synthetic extent trees encode and decode beyond depth one" {
    const extent_count = max_inline_extents * extentEntriesPerBlock(default_block_size) + 1;
    const extents = try std.testing.allocator.alloc(Extent, extent_count);
    defer std.testing.allocator.free(extents);
    for (extents, 0..) |*extent, index| {
        extent.* = .{
            .logical_block = @intCast(index),
            .start_block = 10_000 + index,
            .block_count = 1,
        };
    }

    var node = Node{
        .path = "synthetic",
        .name = "synthetic",
        .parent_path = "",
        .parent_index = 0,
        .inode = 12,
        .kind = .file,
        .mode = 0o644,
        .uid = 0,
        .gid = 0,
        .declared_size = @as(u64, extent_count) * default_block_size,
        .content = null,
        .xattrs = &.{},
        .extents = extents,
    };

    const shape = try extentTreeShape(extent_count, default_block_size);
    try std.testing.expectEqual(@as(u16, 2), shape.depth);
    try std.testing.expectEqual(@as(usize, 6), shape.block_count);

    node.extent_tree_blocks = try std.testing.allocator.alloc(ExtentTreeBlock, shape.block_count);
    defer std.testing.allocator.free(node.extent_tree_blocks);
    for (node.extent_tree_blocks, 0..) |*block, index| {
        block.* = .{ .block_number = 20_000 + index };
    }

    try buildExtentTree(std.testing.allocator, &node, default_block_size, shape.depth);

    const root_header = try parseExtentHeader(node.extent_root[0..extent_header_size]);
    try std.testing.expectEqual(@as(u16, 2), root_header.depth);
    try std.testing.expectEqual(@as(u16, 1), root_header.entries);
    const root_child = decodeExtentIndex(node.extent_root[extent_header_size .. extent_header_size + extent_entry_size]);
    try std.testing.expectEqual(node.extent_tree_blocks[shape.block_count - 1].block_number, root_child.leaf_block);
    const internal_header = try parseExtentHeader(node.extent_tree_blocks[shape.block_count - 1].bytes[0..extent_header_size]);
    try std.testing.expectEqual(@as(u16, 1), internal_header.depth);
    try std.testing.expectEqual(@as(u16, 5), internal_header.entries);
    for (0..internal_header.entries) |entry_index| {
        const base = extent_header_size + entry_index * extent_entry_size;
        const child = decodeExtentIndex(node.extent_tree_blocks[shape.block_count - 1].bytes[base .. base + extent_entry_size]);
        try std.testing.expectEqual(node.extent_tree_blocks[entry_index].block_number, child.leaf_block);
    }

    const decoded = try decodeSyntheticExtentTree(std.testing.allocator, node.extent_root[0..], node.extent_tree_blocks[0..]);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqual(extents.len, decoded.len);
    for (extents, decoded) |expected, actual| {
        try std.testing.expectEqualDeep(expected, actual);
    }
}

test "reader rejects missing paths and wrong node kinds" {
    const io = std.testing.io;
    const path = "test-ext4-errors.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "dir", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "dir/file", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 4, .bytes = "test" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 8 * 1024 * 1024 });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    try std.testing.expectError(error.NotFound, reader.statPath(io, "missing"));
    try std.testing.expectError(error.NotDirectory, reader.listDir(io, std.testing.allocator, "dir/file"));
    try std.testing.expectError(error.NotFile, reader.readFileAlloc(io, std.testing.allocator, "dir"));
}

test "reader exposes inode link counts" {
    const io = std.testing.io;
    const path = "test-ext4-link-count.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "empty-dir", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "parent", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "parent/child", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "file", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 4, .bytes = "test" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 8 * 1024 * 1024 });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    // A regular file always has link_count == 1 (this writer never creates hardlinks).
    const file_inode_number = try reader.lookupPath(io, "file");
    const file_inode = try reader.readInode(io, file_inode_number);
    try std.testing.expectEqual(@as(u16, 1), file_inode.link_count);

    // A directory with no subdirectories has link_count == 2 (its own "." plus the parent's entry).
    const empty_dir_number = try reader.lookupPath(io, "empty-dir");
    const empty_dir_inode = try reader.readInode(io, empty_dir_number);
    try std.testing.expectEqual(@as(u16, 2), empty_dir_inode.link_count);

    // A directory with one subdirectory gains one extra link from that child's "..".
    const parent_number = try reader.lookupPath(io, "parent");
    const parent_inode = try reader.readInode(io, parent_number);
    try std.testing.expectEqual(@as(u16, 3), parent_inode.link_count);
}

test "strict writer-compatible scan exposes deterministic owned view" {
    const io = std.testing.io;
    const path = "test-ext4-strict-scan.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const attrs = [_]Xattr{.{ .name = "user.test", .value = "value" }};
    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o750, .uid = 1, .gid = 2 },
        .{ .path = "etc/file", .kind = .file, .mode = 0o640, .uid = 3, .gid = 4, .size = 4, .bytes = "test", .xattrs = &attrs },
        .{ .path = "link", .kind = .symlink, .mode = 0o777, .uid = 5, .gid = 6, .size = 8, .bytes = "etc/file" },
    });
    tree.bind();

    const length = 160 * 1024 * 1024;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = length,
        .label = "strict",
        .uuid = [_]u8{0x5A} ** 16,
        .timestamp = 1_717_171_717,
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    var scanned = try scanWriterCompatible(&reader, io, std.testing.allocator, .{
        .expected_length = length,
    });
    defer scanned.deinit();
    try std.testing.expectEqual(@as(usize, 3), scanned.nodeCount());
    try std.testing.expectEqual(@as(u32, 1_717_171_717), scanned.identity.global_timestamp);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x5A} ** 16), &scanned.identity.uuid);

    const view = scanned.fileTreeView();
    const first = (try view.next()).?;
    try std.testing.expectEqualStrings("etc", first.path);
    const second = (try view.next()).?;
    try std.testing.expectEqualStrings("etc/file", second.path);
    try std.testing.expectEqual(@as(usize, 1), second.xattrs.len);
}

test "strict writer-compatible scan rejects divergent inode timestamps" {
    const io = std.testing.io;
    const path = "test-ext4-strict-timestamp.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "file", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 4, .bytes = "test" },
    });
    tree.bind();
    const length = 8 * 1024 * 1024;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = length,
        .uuid = [_]u8{0x33} ** 16,
        .timestamp = 1_717_171_717,
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    const inode_number = try reader.lookupPath(io, "/file");
    const group_index = (inode_number - 1) / reader.inodes_per_group;
    const index_in_group = (inode_number - 1) % reader.inodes_per_group;
    const inode_offset = reader.blockOffset(reader.groups[group_index].inode_table_block) +
        @as(u64, index_in_group) * reader.inode_size;
    var raw: [max_supported_reader_inode_size]u8 = undefined;
    const raw_inode = raw[0..reader.inode_size];
    _ = try file.readPositionalAll(io, raw_inode, inode_offset);
    writeInt(u32, raw_inode[8..12], 1_717_171_718);
    setInodeChecksum(raw_inode, reader.uuid, inode_number);
    try file.writePositionalAll(io, raw_inode, inode_offset);

    try std.testing.expectError(
        error.DivergentInodeTimestamp,
        scanWriterCompatible(&reader, io, std.testing.allocator, .{
            .expected_length = length,
        }),
    );
}

test "reader opens read-only-safe 64-byte group descriptor ext4 images" {
    const io = std.testing.io;
    const path = "test-ext4-reader-64byte-gdt.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 9, .bytes = "NAME=zvmi" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 8 * 1024 * 1024 });

    var sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sb, superblock_offset);
    writeInt(u32, sb[0x5C..0x60], readInt(u32, sb[0x5C..0x60]) | feature_compat_orphan_file);
    writeInt(u32, sb[0x60..0x64], readInt(u32, sb[0x60..0x64]) | feature_incompat_64bit | feature_incompat_flex_bg | feature_incompat_csum_seed);
    writeInt(u32, sb[0x64..0x68], readInt(u32, sb[0x64..0x68]) | feature_ro_compat_huge_file | feature_ro_compat_dir_nlink | feature_ro_compat_extra_isize);
    writeInt(u16, sb[0xFE..0x100], 64);
    try file.writePositionalAll(io, &sb, superblock_offset);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    const contents = try reader.readFileAlloc(io, std.testing.allocator, "etc/os-release");
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualSlices(u8, "NAME=zvmi", contents);
}

test "populate respects non-zero partition-relative offsets" {
    const io = std.testing.io;
    const path = "test-ext4-offset.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const prefix_off: u64 = 1 * 1024 * 1024;
    const fs_len: u64 = 8 * 1024 * 1024;
    const suffix_off = prefix_off + fs_len;

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 9, .bytes = "NAME=zvmi" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, suffix_off + default_block_size);

    const prefix_guard: [32]u8 = [_]u8{0xA5} ** 32;
    const suffix_guard: [32]u8 = [_]u8{0x5A} ** 32;
    try file.writePositionalAll(io, &prefix_guard, prefix_off - prefix_guard.len);
    try file.writePositionalAll(io, &suffix_guard, suffix_off);

    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .offset = prefix_off,
        .length = fs_len,
        .label = "offsetfs",
    });

    var check_prefix: [32]u8 = undefined;
    var check_suffix: [32]u8 = undefined;
    _ = try file.readPositionalAll(io, &check_prefix, prefix_off - check_prefix.len);
    _ = try file.readPositionalAll(io, &check_suffix, suffix_off);
    try std.testing.expectEqualSlices(u8, &prefix_guard, &check_prefix);
    try std.testing.expectEqualSlices(u8, &suffix_guard, &check_suffix);

    var reader = try open(io, file, std.testing.allocator, .{ .offset = prefix_off });
    defer reader.deinit();
    const contents = try reader.readFileAlloc(io, std.testing.allocator, "etc/os-release");
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualSlices(u8, "NAME=zvmi", contents);
}

test "populate round-trips empty regular files" {
    const io = std.testing.io;
    const path = "test-ext4-empty.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "empty", .kind = .file, .mode = 0o640, .uid = 7, .gid = 8, .size = 0 },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 8 * 1024 * 1024 });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    const stat = try reader.statPath(io, "empty");
    try std.testing.expectEqual(Kind.file, stat.kind);
    try std.testing.expectEqual(@as(u16, 0o640), stat.mode);
    try std.testing.expectEqual(@as(u64, 0), stat.size);

    const contents = try reader.readFileAlloc(io, std.testing.allocator, "empty");
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqual(@as(usize, 0), contents.len);
}

test "populate round-trips xattrs and metadata checksums" {
    const io = std.testing.io;
    const path = "test-ext4-xattrs.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const selinux = [_]Xattr{
        .{ .name = "security.selinux", .value = "system_u:object_r:bin_t:s0" },
        .{ .name = "user.comment", .value = "hello-from-zvmi" },
    };
    const dir_xattrs = [_]Xattr{
        .{ .name = "user.label", .value = "config-dir" },
    };

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0, .xattrs = &dir_xattrs },
        .{ .path = "etc/empty", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 0, .xattrs = &selinux },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 10, .bytes = "zvmi-test\n", .xattrs = &selinux },
        .{ .path = "etc/hostname-link", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 8, .bytes = "hostname", .xattrs = &selinux },
    });
    tree.bind();

    {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);

        const info = try populate(io, file, std.testing.allocator, &tree.view, .{
            .length = 16 * 1024 * 1024,
            .uuid = [_]u8{0x42} ** 16,
            .timestamp = 1_717_171_717,
            .root_xattrs = &selinux,
        });
        try std.testing.expectEqual(writer_feature_compat, info.feature_compat);
        try std.testing.expect(info.feature_ro_compat & feature_ro_compat_metadata_csum != 0);

        var reader = try open(io, file, std.testing.allocator, .{});
        defer reader.deinit();

        const file_xattrs = try reader.readXattrsAlloc(io, std.testing.allocator, "etc/hostname");
        defer freeXattrs(std.testing.allocator, file_xattrs);
        try expectXattrValue(file_xattrs, "security.selinux", "system_u:object_r:bin_t:s0");
        try expectXattrValue(file_xattrs, "user.comment", "hello-from-zvmi");

        const root_xattrs = try reader.readXattrsAlloc(io, std.testing.allocator, "/");
        defer freeXattrs(std.testing.allocator, root_xattrs);
        try expectXattrValue(root_xattrs, "security.selinux", "system_u:object_r:bin_t:s0");

        const dir_entries = try reader.listDir(io, std.testing.allocator, "etc");
        defer freeDirEntries(std.testing.allocator, dir_entries);
        try expectDirNames(dir_entries, &.{ "empty", "hostname", "hostname-link" });

        const dir_attrs = try reader.readXattrsAlloc(io, std.testing.allocator, "etc");
        defer freeXattrs(std.testing.allocator, dir_attrs);
        try expectXattrValue(dir_attrs, "user.label", "config-dir");

        const empty_xattrs = try reader.readXattrsAlloc(io, std.testing.allocator, "etc/empty");
        defer freeXattrs(std.testing.allocator, empty_xattrs);
        try expectXattrValue(empty_xattrs, "security.selinux", "system_u:object_r:bin_t:s0");

        const link_xattrs = try reader.readXattrsAlloc(io, std.testing.allocator, "etc/hostname-link");
        defer freeXattrs(std.testing.allocator, link_xattrs);
        try expectXattrValue(link_xattrs, "security.selinux", "system_u:object_r:bin_t:s0");

        const raw_hostname_inode = try readRawInodeForPath(io, file, &reader, "etc/hostname");
        try std.testing.expect(readInt(u32, raw_hostname_inode.bytes[104..108]) != 0);
        try std.testing.expectEqual(@as(u32, 2 * sectors_per_block), readInt(u32, raw_hostname_inode.bytes[28..32]));

        try expectMetadataChecksumsValid(io, file, 0, "etc/hostname", "etc");
        try expectMetadataChecksumsValid(io, file, 0, "etc/empty", "etc");
        try expectMetadataChecksumsValid(io, file, 0, "etc/hostname-link", "etc");
    }

    try expectE2fsckClean(path);
}

test "large directories use htree indexing" {
    const io = std.testing.io;
    const path = "test-ext4-htree.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var entries = std.array_list.Managed(InMemoryEntry).init(std.testing.allocator);
    defer entries.deinit();
    try entries.append(.{ .path = "big", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    var names: [300][16]u8 = undefined;
    var index: usize = 0;
    while (index < 300) : (index += 1) {
        const name = try std.fmt.bufPrint(&names[index], "big/file-{d:0>3}", .{index});
        try entries.append(.{
            .path = name,
            .kind = .file,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .size = 0,
        });
    }

    var tree = InMemoryTree.init(entries.items);
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = 32 * 1024 * 1024,
        .uuid = [_]u8{0x24} ** 16,
        .timestamp = 1_717_171_717,
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    const dir_entries = try reader.listDir(io, std.testing.allocator, "big");
    defer freeDirEntries(std.testing.allocator, dir_entries);
    try std.testing.expectEqual(@as(usize, 300), dir_entries.len);
    _ = try reader.statPath(io, "big/file-000");
    _ = try reader.statPath(io, "big/file-127");
    _ = try reader.statPath(io, "big/file-299");

    const dir_inode = try reader.readInode(io, try reader.lookupPath(io, "big"));
    try std.testing.expect(dir_inode.flags & inode_flag_index != 0);
    const extents = try reader.readInodeExtentsAlloc(io, std.testing.allocator, dir_inode);
    defer std.testing.allocator.free(extents);
    try std.testing.expect(extents.len >= 1);

    var root_block: [default_block_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &root_block, extents[0].start_block * default_block_size);
    try std.testing.expectEqual(dx_hash_half_md4, root_block[28]);
    try std.testing.expectEqual(@as(u8, 0), root_block[30]);
    try std.testing.expect(readInt(u16, root_block[34..36]) > 1);

    {
        var strict = try scanWriterCompatible(&reader, io, std.testing.allocator, .{
            .expected_length = 32 * 1024 * 1024,
        });
        defer strict.deinit();
        try std.testing.expectEqual(@as(usize, 301), strict.nodeCount());
    }

    writeInt(u32, root_block[36..40], readInt(u32, root_block[36..40]) + 1);
    const limit = readInt(u16, root_block[32..34]);
    const count = readInt(u16, root_block[34..36]);
    setDxChecksum(
        &root_block,
        32,
        count,
        limit,
        reader.uuid,
        dir_inode.inode,
        dir_inode.generation,
    );
    try file.writePositionalAll(
        io,
        &root_block,
        extents[0].start_block * default_block_size,
    );
    try std.testing.expectError(
        error.UnsupportedDirectoryLayout,
        scanWriterCompatible(&reader, io, std.testing.allocator, .{
            .expected_length = 32 * 1024 * 1024,
        }),
    );
}

test "very large directories use multi-level htree indexing" {
    const io = std.testing.io;
    const path = "test-ext4-multilevel-htree.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const entry_count = 8_200;
    var entries = std.array_list.Managed(InMemoryEntry).init(std.testing.allocator);
    defer entries.deinit();

    var owned_paths = std.array_list.Managed([]u8).init(std.testing.allocator);
    defer {
        for (owned_paths.items) |owned_path| std.testing.allocator.free(owned_path);
        owned_paths.deinit();
    }

    try entries.append(.{ .path = "huge", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    for (0..entry_count) |index| {
        const path_bytes = try std.testing.allocator.alloc(u8, "huge/".len + 255);
        try owned_paths.append(path_bytes);
        std.mem.copyForwards(u8, path_bytes[0.."huge/".len], "huge/");
        @memset(path_bytes["huge/".len..], 'a');
        _ = try std.fmt.bufPrint(path_bytes["huge/".len .. "huge/".len + 7], "{d:0>6}-", .{index});
        try entries.append(.{
            .path = path_bytes,
            .kind = .file,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .size = 0,
        });
    }

    var tree = InMemoryTree.init(entries.items);
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = 128 * 1024 * 1024,
        .uuid = [_]u8{0x66} ** 16,
        .timestamp = 1_717_171_717,
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    const dir_entries = try reader.listDir(io, std.testing.allocator, "huge");
    defer freeDirEntries(std.testing.allocator, dir_entries);
    try std.testing.expectEqual(@as(usize, entry_count), dir_entries.len);

    _ = try reader.statPath(io, owned_paths.items[0]);
    _ = try reader.statPath(io, owned_paths.items[entry_count / 2]);
    _ = try reader.statPath(io, owned_paths.items[entry_count - 1]);

    const dir_inode = try reader.readInode(io, try reader.lookupPath(io, "huge"));
    try std.testing.expect(dir_inode.flags & inode_flag_index != 0);
    const extents = try reader.readInodeExtentsAlloc(io, std.testing.allocator, dir_inode);
    defer std.testing.allocator.free(extents);

    var root_block: [default_block_size]u8 = undefined;
    try readDirectoryLogicalBlock(io, file, extents, 0, &root_block);
    try std.testing.expectEqual(dx_hash_half_md4, root_block[28]);
    try std.testing.expectEqual(@as(u8, 1), root_block[30]);

    const root_limit = readInt(u16, root_block[32..34]);
    const root_count = readInt(u16, root_block[34..36]);
    try std.testing.expect(root_count > 1);

    var total_leaf_blocks: usize = 0;
    for (0..root_count) |entry_index| {
        const block_field_offset = if (entry_index == 0) 36 else 32 + entry_index * 8 + 4;
        const child_logical_block = readInt(u32, root_block[block_field_offset .. block_field_offset + 4]);
        try std.testing.expect(child_logical_block >= 1);
        try std.testing.expect(child_logical_block <= @as(u32, root_count));

        var node_block: [default_block_size]u8 = undefined;
        try readDirectoryLogicalBlock(io, file, extents, child_logical_block, &node_block);
        try std.testing.expectEqual(@as(u32, 0), readInt(u32, node_block[0..4]));
        try std.testing.expectEqual(@as(u16, @intCast(default_block_size)), readInt(u16, node_block[4..6]));
        try std.testing.expectEqual(@as(u16, @intCast(dxNodeLimit(default_block_size))), readInt(u16, node_block[8..10]));
        const node_count = readInt(u16, node_block[10..12]);
        total_leaf_blocks += node_count;
        try std.testing.expect(readInt(u32, node_block[12..16]) > @as(u32, root_count));
    }
    try std.testing.expect(total_leaf_blocks > root_limit);
}

test "resize grows ext4 filesystems in place" {
    const io = std.testing.io;
    const path = "test-ext4-resize.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 9, .bytes = "NAME=zvmi" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    const before = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = 64 * 1024 * 1024,
        .uuid = [_]u8{0x55} ** 16,
        .timestamp = 1_717_171_717,
    });
    const after = try resize(io, file, std.testing.allocator, .{ .length = 192 * 1024 * 1024 });
    try std.testing.expect(after.block_count > before.block_count);
    try std.testing.expect(after.group_count > before.group_count);
    try std.testing.expect(after.free_block_count > before.free_block_count);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    const bytes = try reader.readFileAlloc(io, std.testing.allocator, "etc/os-release");
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, "NAME=zvmi", bytes);
}

test "Editor.open loads live free-space state and a no-op flush leaves the image untouched" {
    const io = std.testing.io;
    const path = "test-ext4-editor-open.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 9, .bytes = "NAME=zvmi" },
        .{ .path = "var", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    const fs_size: u64 = 16 * 1024 * 1024;
    const info = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = fs_size,
        .uuid = [_]u8{0x21} ** 16,
        .timestamp = 1_717_171_717,
    });

    const before = try std.testing.allocator.alloc(u8, fs_size);
    defer std.testing.allocator.free(before);
    _ = try file.readPositionalAll(io, before, 0);

    var editor = try Editor.open(io, file, std.testing.allocator, .{});
    defer editor.deinit();

    var total_free_blocks: u32 = 0;
    var total_used_inodes: u32 = 0;
    for (editor.groups) |group| {
        total_free_blocks += group.data_capacity - group.used_data_blocks;
        total_used_inodes += group.used_inode_count;
    }
    try std.testing.expectEqual(info.free_block_count, total_free_blocks);
    try std.testing.expectEqual(info.inode_count - info.free_inode_count, total_used_inodes);

    try editor.flush(io);

    const after = try std.testing.allocator.alloc(u8, fs_size);
    defer std.testing.allocator.free(after);
    _ = try file.readPositionalAll(io, after, 0);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "Editor.open rejects images with a foreign group descriptor layout" {
    const io = std.testing.io;
    const path = "test-ext4-editor-reject.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 8 * 1024 * 1024 });

    // Widen the on-disk group descriptor size to 64 bytes, a layout Editor
    // deliberately does not support (it only ever exists on images this
    // writer produces itself, which always use 32-byte descriptors).
    var desc_size_bytes: [2]u8 = undefined;
    writeInt(u16, &desc_size_bytes, 64);
    try file.writePositionalAll(io, &desc_size_bytes, superblock_offset + 0xFE);
    var sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sb, superblock_offset);
    setSuperblockChecksum(&sb);
    try file.writePositionalAll(io, &sb, superblock_offset);

    try std.testing.expectError(error.UnsupportedEditLayout, Editor.open(io, file, std.testing.allocator, .{}));
}

test "Editor frees an inode's extent-tree blocks (leaf, index, and xattr) and reuses them" {
    const io = std.testing.io;
    const path = "test-ext4-editor-free-extents.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Large enough to force real extent index blocks (see "populate round-trips
    // files that require extent index blocks"), so freeing exercises the
    // interior-node path, not just leaf extents.
    const fs_size: u64 = 768 * 1024 * 1024;
    const big_size: u64 = 544 * 1024 * 1024;

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "big.bin", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = big_size, .generator = .pattern },
        .{ .path = "small.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 5, .bytes = "hello", .xattrs = &.{.{ .name = "user.tag", .value = "v" }} },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    const info = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = fs_size, .uuid = [_]u8{0x30} ** 16 });

    var editor = try Editor.open(io, file, std.testing.allocator, .{});
    defer editor.deinit();

    var free_before: u32 = 0;
    for (editor.groups) |group| free_before += group.data_capacity - group.used_data_blocks;
    try std.testing.expectEqual(info.free_block_count, free_before);

    const big_inode_number = try editor.reader.lookupPath(io, "big.bin");
    const big_inode = try editor.reader.readInode(io, big_inode_number);
    try std.testing.expect((big_inode.flags & inode_flag_extents) != 0);

    // Confirm this file really does have extent index blocks, so freeing it
    // exercises the interior-node collection path, not just leaf extents.
    const root_header = try parseExtentHeader(big_inode.block_bytes[0..extent_header_size]);
    try std.testing.expect(root_header.depth > 0);

    const small_inode_number = try editor.reader.lookupPath(io, "small.txt");
    const small_inode = try editor.reader.readInode(io, small_inode_number);
    try std.testing.expect(small_inode.file_acl_block != 0);

    try editor.freeInodeAllocations(io, big_inode, true);
    try editor.freeInodeAllocations(io, small_inode, true);

    var free_after: u32 = 0;
    for (editor.groups) |group| free_after += group.data_capacity - group.used_data_blocks;
    try std.testing.expect(free_after > free_before);

    // The freed space must be immediately reusable within the same session.
    const reclaimed = try editor.allocateExtents(std.testing.allocator, free_after);
    defer std.testing.allocator.free(reclaimed);
    var reclaimed_total: u32 = 0;
    for (reclaimed) |extent| reclaimed_total += extent.block_count;
    try std.testing.expectEqual(free_after, reclaimed_total);

    try std.testing.expectError(error.NotEnoughSpace, editor.allocateExtents(std.testing.allocator, 1));
}

test "splitParentAndName splits paths and rejects the root" {
    {
        const split = try splitParentAndName("etc/hostname");
        try std.testing.expectEqualStrings("etc", split.parent);
        try std.testing.expectEqualStrings("hostname", split.name);
    }
    {
        const split = try splitParentAndName("hostname");
        try std.testing.expectEqualStrings("", split.parent);
        try std.testing.expectEqualStrings("hostname", split.name);
    }
    {
        const split = try splitParentAndName("etc/hostname/");
        try std.testing.expectEqualStrings("etc", split.parent);
        try std.testing.expectEqualStrings("hostname", split.name);
    }
    try std.testing.expectError(error.RootPathForbidden, splitParentAndName(""));
    try std.testing.expectError(error.RootPathForbidden, splitParentAndName("/"));
}

test "Editor removes directory entries by splicing, across a large htree-indexed directory" {
    const io = std.testing.io;
    const path = "test-ext4-editor-unlink-htree.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var entries = std.array_list.Managed(InMemoryEntry).init(std.testing.allocator);
    defer entries.deinit();
    try entries.append(.{ .path = "big", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    var names: [300][16]u8 = undefined;
    var index: usize = 0;
    while (index < 300) : (index += 1) {
        const name = try std.fmt.bufPrint(&names[index], "big/file-{d:0>3}", .{index});
        try entries.append(.{ .path = name, .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 0 });
    }

    var tree = InMemoryTree.init(entries.items);
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = 32 * 1024 * 1024,
        .uuid = [_]u8{0x25} ** 16,
    });

    var editor = try Editor.open(io, file, std.testing.allocator, .{});
    defer editor.deinit();
    const dir_inode_number = try editor.reader.lookupPath(io, "big");

    // Spread across the whole directory (start/middle/end) so this
    // implicitly exercises both splice branches -- some of these names will
    // land as the first entry within their particular htree leaf block
    // (splice zeroes the inode field in place), others will have a real
    // preceding sibling in the same block (splice merges rec_len into it) --
    // without needing to know in advance which is which.
    const to_remove = [_][]const u8{ "file-000", "file-050", "file-127", "file-299" };
    for (to_remove) |name| try editor.removeDirEntryFromParent(io, dir_inode_number, name);
    try std.testing.expectError(error.NotFound, editor.removeDirEntryFromParent(io, dir_inode_number, "file-000"));

    try editor.flush(io);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    const dir_entries = try reader.listDir(io, std.testing.allocator, "big");
    defer freeDirEntries(std.testing.allocator, dir_entries);
    try std.testing.expectEqual(@as(usize, 300 - to_remove.len), dir_entries.len);

    for (to_remove) |name| {
        var buf: [32]u8 = undefined;
        const full = try std.fmt.bufPrint(&buf, "big/{s}", .{name});
        try std.testing.expectError(error.NotFound, reader.statPath(io, full));
    }
    _ = try reader.statPath(io, "big/file-001");
    _ = try reader.statPath(io, "big/file-128");
    _ = try reader.statPath(io, "big/file-298");
}

test "Editor.deleteFile removes a regular file, frees its inode/blocks, and leaves siblings intact" {
    const io = std.testing.io;
    const path = "test-ext4-editor-deletefile.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const big_size: u64 = 544 * 1024 * 1024;
    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/keep.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 4, .bytes = "keep" },
        .{ .path = "etc/remove.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 6, .bytes = "remove" },
        .{ .path = "big.bin", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = big_size, .generator = .pattern },
        .{ .path = "link", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 4, .bytes = "keep" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 768 * 1024 * 1024, .uuid = [_]u8{0x40} ** 16 });

    var editor = try Editor.open(io, file, std.testing.allocator, .{});
    defer editor.deinit();

    var free_blocks_before: u32 = 0;
    var free_inodes_before: u32 = 0;
    for (editor.groups) |group| {
        free_blocks_before += group.data_capacity - group.used_data_blocks;
        free_inodes_before += editor.reader.inodes_per_group - group.used_inode_count;
    }

    // Deleting a large multi-extent-block file must free its interior
    // extent-tree index blocks too, not just its leaf data blocks.
    try editor.deleteFile(io, "big.bin");
    try editor.deleteFile(io, "etc/remove.txt");
    try std.testing.expectError(error.IsDirectory, editor.deleteFile(io, "etc"));
    try std.testing.expectError(error.NotFound, editor.deleteFile(io, "etc/remove.txt"));
    try std.testing.expectError(error.NotFound, editor.deleteFile(io, "missing"));

    var free_blocks_after: u32 = 0;
    var free_inodes_after: u32 = 0;
    for (editor.groups) |group| {
        free_blocks_after += group.data_capacity - group.used_data_blocks;
        free_inodes_after += editor.reader.inodes_per_group - group.used_inode_count;
    }
    try std.testing.expect(free_blocks_after > free_blocks_before);
    try std.testing.expectEqual(free_inodes_before + 2, free_inodes_after);

    try editor.flush(io);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    try std.testing.expectError(error.NotFound, reader.statPath(io, "big.bin"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "etc/remove.txt"));

    const kept = try reader.readFileAlloc(io, std.testing.allocator, "etc/keep.txt");
    defer std.testing.allocator.free(kept);
    try std.testing.expectEqualSlices(u8, "keep", kept);

    // The symlink is untouched -- deleteFile only removes the exact path
    // requested, never anything else that merely shares its content.
    const link_target = try reader.readLinkAlloc(io, std.testing.allocator, "link");
    defer std.testing.allocator.free(link_target);
    try std.testing.expectEqualSlices(u8, "keep", link_target);

    const dir_entries = try reader.listDir(io, std.testing.allocator, "etc");
    defer freeDirEntries(std.testing.allocator, dir_entries);
    try expectDirNames(dir_entries, &.{"keep.txt"});
}

test "Editor.deleteTree recursively removes a directory and adjusts the parent's link count" {
    const io = std.testing.io;
    const path = "test-ext4-editor-deletetree.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "keep", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "keep/file.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 4, .bytes = "keep" },
        .{ .path = "doomed", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "doomed/a.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 1, .bytes = "A" },
        .{ .path = "doomed/nested", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "doomed/nested/b.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 1, .bytes = "B" },
        .{ .path = "doomed/nested/link", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 5, .bytes = "b.txt" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 16 * 1024 * 1024, .uuid = [_]u8{0x41} ** 16 });

    const root_link_count_before = blk: {
        var reader = try open(io, file, std.testing.allocator, .{});
        defer reader.deinit();
        break :blk (try reader.readInode(io, root_inode)).link_count;
    };

    var editor = try Editor.open(io, file, std.testing.allocator, .{});
    defer editor.deinit();

    try editor.deleteTree(io, "doomed");
    try std.testing.expectError(error.NotFound, editor.deleteTree(io, "doomed"));
    try std.testing.expectError(error.RootPathForbidden, editor.deleteTree(io, "/"));
    try std.testing.expectError(error.RootPathForbidden, editor.deleteTree(io, ""));

    try editor.flush(io);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    try std.testing.expectError(error.NotFound, reader.statPath(io, "doomed"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "doomed/a.txt"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "doomed/nested"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "doomed/nested/b.txt"));

    const root_entries = try reader.listDir(io, std.testing.allocator, "");
    defer freeDirEntries(std.testing.allocator, root_entries);
    try expectDirNames(root_entries, &.{"keep"});

    const kept = try reader.readFileAlloc(io, std.testing.allocator, "keep/file.txt");
    defer std.testing.allocator.free(kept);
    try std.testing.expectEqualSlices(u8, "keep", kept);

    // Removing "doomed" (which itself had one subdirectory, "nested") must
    // drop the root's link count by exactly one, for "doomed"'s own ".."
    // reference going away.
    const root_inode_after = try reader.readInode(io, root_inode);
    try std.testing.expectEqual(root_link_count_before - 1, root_inode_after.link_count);
}

test "Editor.writeFile overwrites content, preserves xattrs, and handles growth/shrink" {
    const io = std.testing.io;
    const path = "test-ext4-editor-writefile.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{
            .path = "etc/config.txt",
            .kind = .file,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .size = 5,
            .bytes = "hello",
            .xattrs = &.{.{ .name = "user.tag", .value = "original" }},
        },
        .{ .path = "etc/dir-not-a-file", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 16 * 1024 * 1024, .uuid = [_]u8{0x42} ** 16 });

    var editor = try Editor.open(io, file, std.testing.allocator, .{});
    defer editor.deinit();

    // Shrink: smaller than the original 5-byte content.
    try editor.writeFile(io, "etc/config.txt", "hi");
    try std.testing.expectError(error.NotFound, editor.writeFile(io, "etc/missing.txt", "x"));
    try std.testing.expectError(error.NotFile, editor.writeFile(io, "etc/dir-not-a-file", "x"));
    try editor.flush(io);

    {
        var reader = try open(io, file, std.testing.allocator, .{});
        defer reader.deinit();
        const bytes = try reader.readFileAlloc(io, std.testing.allocator, "etc/config.txt");
        defer std.testing.allocator.free(bytes);
        try std.testing.expectEqualSlices(u8, "hi", bytes);
        const tag = try reader.readXattrAlloc(io, std.testing.allocator, "etc/config.txt", "user.tag");
        defer std.testing.allocator.free(tag);
        try std.testing.expectEqualSlices(u8, "original", tag);
        try expectInodeBlocksForPath(io, file, &reader, "etc/config.txt", 2 * sectors_per_block);
    }

    // Grow: large enough to require multiple full 4 KiB blocks.
    var big_content: [10 * 1024]u8 = undefined;
    fillPattern(&big_content, 0);
    try editor.writeFile(io, "etc/config.txt", &big_content);
    try editor.flush(io);

    {
        var reader = try open(io, file, std.testing.allocator, .{});
        defer reader.deinit();
        const bytes = try reader.readFileAlloc(io, std.testing.allocator, "etc/config.txt");
        defer std.testing.allocator.free(bytes);
        try std.testing.expectEqualSlices(u8, &big_content, bytes);
        const tag = try reader.readXattrAlloc(io, std.testing.allocator, "etc/config.txt", "user.tag");
        defer std.testing.allocator.free(tag);
        try std.testing.expectEqualSlices(u8, "original", tag);
        try expectInodeBlocksForPath(io, file, &reader, "etc/config.txt", 4 * sectors_per_block);
    }

    // Empty content is a valid, well-formed zero-block file.
    try editor.writeFile(io, "etc/config.txt", "");
    try editor.flush(io);
    {
        var reader = try open(io, file, std.testing.allocator, .{});
        defer reader.deinit();
        const stat = try reader.statPath(io, "etc/config.txt");
        try std.testing.expectEqual(@as(u64, 0), stat.size);
        try expectInodeBlocksForPath(io, file, &reader, "etc/config.txt", sectors_per_block);
    }
}

test "Editor.writeFile rolls back and reports TooManyExtents when free space is too fragmented" {
    const io = std.testing.io;
    const path = "test-ext4-editor-writefile-fragmented.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var entries = std.array_list.Managed(InMemoryEntry).init(std.testing.allocator);
    defer entries.deinit();
    try entries.append(.{ .path = "d", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    var names: [20][16]u8 = undefined;
    var index: usize = 0;
    while (index < 20) : (index += 1) {
        const name = try std.fmt.bufPrint(&names[index], "d/f{d:0>2}", .{index});
        try entries.append(.{ .path = name, .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = default_block_size, .generator = .pattern });
    }

    var tree = InMemoryTree.init(entries.items);
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 16 * 1024 * 1024, .uuid = [_]u8{0x43} ** 16 });

    var editor = try Editor.open(io, file, std.testing.allocator, .{});
    defer editor.deinit();

    // Delete every other single-block file, leaving isolated one-block
    // holes interleaved with still-used blocks -- the worst case for
    // contiguous-run allocation.
    index = 1;
    while (index < 20) : (index += 2) {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "d/f{d:0>2}", .{index});
        try editor.deleteFile(io, name);
    }

    var free_blocks_before: u32 = 0;
    for (editor.groups) |group| free_blocks_before += group.data_capacity - group.used_data_blocks;

    // 8 blocks of new content cannot fit in <= 4 single-block-run extents.
    var content: [8 * default_block_size]u8 = undefined;
    fillPattern(&content, 0);
    try std.testing.expectError(error.TooManyExtents, editor.writeFile(io, "d/f00", &content));

    // A failed overwrite must not leak the space it provisionally claimed,
    // nor touch the target file's original content.
    var free_blocks_after: u32 = 0;
    for (editor.groups) |group| free_blocks_after += group.data_capacity - group.used_data_blocks;
    try std.testing.expectEqual(free_blocks_before, free_blocks_after);

    try editor.flush(io);
    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    const bytes = try reader.readFileAlloc(io, std.testing.allocator, "d/f00");
    defer std.testing.allocator.free(bytes);
    var expected: [default_block_size]u8 = undefined;
    fillPattern(&expected, 0);
    try std.testing.expectEqualSlices(u8, &expected, bytes);
}

test "Editor.flush keeps sparse-super backup superblocks and GDT copies in sync with the primary" {
    const io = std.testing.io;
    const path = "test-ext4-editor-flush-backups.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // >= 3 groups (each default_blocks_per_group is 128 MiB), so group 1 has
    // a real sparse-super backup copy distinct from the primary in group 0.
    const fs_size: u64 = 400 * 1024 * 1024;

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "a.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 1, .bytes = "A" },
        .{ .path = "b.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 1, .bytes = "B" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = fs_size, .uuid = [_]u8{0x50} ** 16 });

    var editor = try Editor.open(io, file, std.testing.allocator, .{});
    defer editor.deinit();
    try std.testing.expect(editor.groups.len >= 3);

    // Force both a group-bitmap/GDT change and a superblock free-count
    // change, so flush() has real work to mirror into the backups.
    try editor.deleteFile(io, "a.txt");
    try editor.flush(io);

    var primary_sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &primary_sb, superblock_offset);

    const backup_group_start_block = editor.groups[1].start_block;
    var backup_sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &backup_sb, backup_group_start_block * default_block_size);

    // Backups are byte-for-byte identical to the primary except for their
    // own s_block_group_nr field (and the checksum that covers it).
    try std.testing.expectEqualSlices(u8, primary_sb[0..0x5A], backup_sb[0..0x5A]);
    try std.testing.expectEqual(@as(u16, 0), readInt(u16, primary_sb[0x5A..0x5C]));
    try std.testing.expectEqual(@as(u16, 1), readInt(u16, backup_sb[0x5A..0x5C]));
    try std.testing.expectEqualSlices(u8, primary_sb[0x5C..0x3FC], backup_sb[0x5C..0x3FC]);

    var recomputed_backup_sb = backup_sb;
    setSuperblockChecksum(&recomputed_backup_sb);
    try std.testing.expectEqualSlices(u8, &recomputed_backup_sb, &backup_sb);

    const gdt_blocks = @max(@as(u32, 1), blocksForBytes(@as(u64, editor.groups.len) * group_desc_size, default_block_size));
    const gdt_bytes_len = @as(usize, gdt_blocks) * default_block_size;
    const primary_gdt = try std.testing.allocator.alloc(u8, gdt_bytes_len);
    defer std.testing.allocator.free(primary_gdt);
    _ = try file.readPositionalAll(io, primary_gdt, default_block_size);
    const backup_gdt = try std.testing.allocator.alloc(u8, gdt_bytes_len);
    defer std.testing.allocator.free(backup_gdt);
    _ = try file.readPositionalAll(io, backup_gdt, (backup_group_start_block + 1) * default_block_size);
    try std.testing.expectEqualSlices(u8, primary_gdt, backup_gdt);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    try std.testing.expectError(error.NotFound, reader.statPath(io, "a.txt"));
    const kept = try reader.readFileAlloc(io, std.testing.allocator, "b.txt");
    defer std.testing.allocator.free(kept);
    try std.testing.expectEqualSlices(u8, "B", kept);
}

/// Runs `e2fsck -f -n` against a real on-disk image, trying a few common
/// install locations since e2fsprogs's sbin binaries often aren't on an
/// unprivileged user's PATH even when installed (this repo's CI runs on
/// ubuntu-latest, which ships e2fsprogs by default). Returns `null`
/// (rather than failing) when it truly can't be found anywhere, so this
/// opportunistic external-tool check is skipped gracefully instead of
/// breaking builds/dev machines that lack it -- matching the pattern
/// `tests/boot_smoke.zig` uses for qemu-system-x86_64.
pub fn runE2fsck(allocator: std.mem.Allocator, path: []const u8) !?std.process.RunResult {
    const candidates = [_][]const u8{ "e2fsck", "/sbin/e2fsck", "/usr/sbin/e2fsck" };
    for (candidates) |bin| {
        const result = std.process.run(allocator, std.testing.io, .{
            .argv = &.{ bin, "-f", "-n", path },
            .cwd = .{ .path = "." },
        }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return result;
    }
    return null;
}

pub fn expectE2fsckClean(path: []const u8) !void {
    const maybe_result = try runE2fsck(std.testing.allocator, path);
    const result = maybe_result orelse {
        std.debug.print("skipping e2fsck validation: e2fsck not found (tried PATH, /sbin, /usr/sbin)\n", .{});
        return error.SkipZigTest;
    };
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("e2fsck -f -n reported problems (exit {d}):\nstdout:\n{s}\nstderr:\n{s}\n", .{ code, result.stdout, result.stderr });
            }
            try std.testing.expectEqual(@as(u8, 0), code);
        },
        else => {
            std.debug.print("e2fsck did not exit normally:\nstdout:\n{s}\nstderr:\n{s}\n", .{ result.stdout, result.stderr });
            return error.TestUnexpectedResult;
        },
    }
}

test "Editor edits (deletes, recursive tree removal, and overwrite) pass a real e2fsck -f check" {
    const io = std.testing.io;
    const path = "test-ext4-editor-e2fsck.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var entries = std.array_list.Managed(InMemoryEntry).init(std.testing.allocator);
    defer entries.deinit();
    try entries.append(.{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    try entries.append(.{
        .path = "etc/keep.conf",
        .kind = .file,
        .mode = 0o644,
        .uid = 0,
        .gid = 0,
        .size = 4,
        .bytes = "keep",
        .xattrs = &.{.{ .name = "user.tag", .value = "original" }},
    });
    try entries.append(.{ .path = "etc/remove.conf", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 6, .bytes = "remove" });
    try entries.append(.{ .path = "var", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    try entries.append(.{ .path = "var/log", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    try entries.append(.{ .path = "var/log/app.log", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 3, .bytes = "log" });
    try entries.append(.{ .path = "doomed", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    try entries.append(.{ .path = "doomed/nested", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    try entries.append(.{ .path = "doomed/nested/file.txt", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 4, .bytes = "data" });
    try entries.append(.{ .path = "doomed/link", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 4, .bytes = "keep" });
    // Multi-extent (2 extents, crossing one group boundary) but deliberately
    // *not* deep enough to need an extent-tree index block, so this test
    // stays focused on editor behavior rather than deeper extent-tree shape.
    try entries.append(.{ .path = "big.bin", .kind = .file, .mode = 0o600, .uid = 42, .gid = 24, .size = 150 * 1024 * 1024, .generator = .pattern });
    try entries.append(.{ .path = "many", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 });
    var names: [300][20]u8 = undefined;
    var name_index: usize = 0;
    while (name_index < 300) : (name_index += 1) {
        const name = try std.fmt.bufPrint(&names[name_index], "many/file-{d:0>3}", .{name_index});
        try entries.append(.{ .path = name, .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 0 });
    }

    var tree = InMemoryTree.init(entries.items);
    tree.bind();

    const fs_size: u64 = 900 * 1024 * 1024;
    {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = fs_size, .uuid = [_]u8{0x60} ** 16 });

        var editor = try Editor.open(io, file, std.testing.allocator, .{});
        defer editor.deinit();

        try editor.deleteFile(io, "etc/remove.conf");
        try editor.deleteTree(io, "doomed");

        var remove_index: usize = 1;
        while (remove_index < 300) : (remove_index += 2) {
            var buf: [20]u8 = undefined;
            const name = try std.fmt.bufPrint(&buf, "many/file-{d:0>3}", .{remove_index});
            try editor.deleteFile(io, name);
        }

        var grown: [10 * 1024]u8 = undefined;
        fillPattern(&grown, 0);
        try editor.writeFile(io, "etc/keep.conf", &grown);

        try editor.flush(io);
    }

    try expectE2fsckClean(path);

    // Also confirm the edits themselves are still correct from zvmi's own
    // Reader, independent of e2fsck's own verdict.
    const reopened_file = try Io.Dir.cwd().openFile(io, path, .{});
    defer reopened_file.close(io);
    var reader = try open(io, reopened_file, std.testing.allocator, .{});
    defer reader.deinit();

    try std.testing.expectError(error.NotFound, reader.statPath(io, "etc/remove.conf"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "doomed"));

    const kept = try reader.readFileAlloc(io, std.testing.allocator, "etc/keep.conf");
    defer std.testing.allocator.free(kept);
    var expected_kept: [10 * 1024]u8 = undefined;
    fillPattern(&expected_kept, 0);
    try std.testing.expectEqualSlices(u8, &expected_kept, kept);
    const kept_tag = try reader.readXattrAlloc(io, std.testing.allocator, "etc/keep.conf", "user.tag");
    defer std.testing.allocator.free(kept_tag);
    try std.testing.expectEqualSlices(u8, "original", kept_tag);

    const remaining = try reader.listDir(io, std.testing.allocator, "many");
    defer freeDirEntries(std.testing.allocator, remaining);
    try std.testing.expectEqual(@as(usize, 150), remaining.len);
}

// ---------------------------------------------------------------------------
// Minimum-size tests
//
// The contract is narrow and worth stating exactly: `minimumPopulateLength`
// returns a size `populate` accepts, and no smaller size works. Both halves
// are checked with `preflightPopulate`, which plans precisely what `populate`
// would without writing anything, so proving minimality costs no I/O at all.
// ---------------------------------------------------------------------------

fn minimumSizeTestTree() InMemoryTree {
    return InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 10, .bytes = "zvmi-test\n" },
        .{ .path = "etc/empty", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 0 },
        .{ .path = "usr", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "usr/payload.bin", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 3 * 1024 * 1024, .generator = .pattern },
        .{ .path = "link", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 12, .bytes = "etc/hostname" },
    });
}

/// Asserts both halves of the contract, plus that the reported breakdown
/// accounts for every block of the answer. The tree is walked again for each
/// check, which is exactly what `populate` would do.
fn expectMinimalPopulateLength(
    tree: *FileTreeView,
    options: PopulateOptions,
    minimum: MinimumSize,
) !void {
    try std.testing.expectEqual(
        minimum.total_blocks,
        minimum.content_blocks + minimum.extent_tree_blocks +
            minimum.journal_blocks + minimum.metadata_blocks + minimum.free_blocks,
    );
    try std.testing.expectEqual(@as(u64, minimum.total_blocks) * options.block_size, minimum.length);

    var accepted = options;
    accepted.length = minimum.length;
    const info = try preflightPopulate(std.testing.allocator, tree, accepted);
    try std.testing.expectEqual(minimum.total_blocks, info.block_count);
    try std.testing.expectEqual(minimum.free_blocks, info.free_block_count);
    try std.testing.expectEqual(minimum.journal_blocks, info.journal_block_count);
    try std.testing.expectEqual(minimum.inode_count, info.inode_count);
    try std.testing.expectEqual(minimum.group_count, info.group_count);

    var undersized = options;
    undersized.length = minimum.length - options.block_size;
    // Every smaller size must be refused. Which refusal depends on what runs
    // out first -- free blocks, or the journal's own floor -- and all three
    // are the writer declining to build the filesystem, which is the whole
    // property under test.
    if (preflightPopulate(std.testing.allocator, tree, undersized)) |_| {
        std.debug.print(
            "a filesystem one block below the reported minimum still planned\n",
            .{},
        );
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.NotEnoughSpace,
        error.FilesystemTooSmallForJournal,
        error.JournalSizeTooLarge,
        => {},
        else => return err,
    }
}

test "the minimum size is the smallest one that populates, and it really populates" {
    const io = std.testing.io;
    const path = "test-ext4-minimum-size.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = minimumSizeTestTree();
    tree.bind();
    const options: PopulateOptions = .{
        .length = 0,
        .label = "zvmi-min",
        .uuid = [_]u8{0x44} ** 16,
        .timestamp = 1_717_171_717,
    };

    const minimum = try minimumPopulateLength(std.testing.allocator, &tree.view, options);
    try expectMinimalPopulateLength(&tree.view, options, minimum);

    // The tree holds a 3 MiB file, so a filesystem that fits it cannot be
    // smaller than that; and the whole point is that it is not much larger.
    try std.testing.expect(minimum.length > 3 * 1024 * 1024);
    try std.testing.expect(minimum.length < 8 * 1024 * 1024);
    try std.testing.expectEqual(@as(u32, 0), minimum.journal_blocks);

    // Without a journal there is only one way for a smaller filesystem to be
    // refused, and it should be that one.
    var undersized = options;
    undersized.length = minimum.length - default_block_size;
    try std.testing.expectError(
        error.NotEnoughSpace,
        preflightPopulate(std.testing.allocator, &tree.view, undersized),
    );

    var written = options;
    written.length = minimum.length;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    const populated = try populate(io, file, std.testing.allocator, &tree.view, written);
    try std.testing.expectEqual(minimum.total_blocks, populated.block_count);
    try std.testing.expectEqual(minimum.free_blocks, populated.free_block_count);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    var hostname: [10]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, hostname.len),
        try reader.preadPath(io, "etc/hostname", &hostname, 0),
    );
    try std.testing.expectEqualSlices(u8, "zvmi-test\n", &hostname);

    const maybe_result = try runE2fsck(std.testing.allocator, path);
    const result = maybe_result orelse {
        std.debug.print("skipping e2fsck validation: e2fsck not found (tried PATH, /sbin, /usr/sbin)\n", .{});
        return error.SkipZigTest;
    };
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("e2fsck -f -n reported problems (exit {d}):\nstdout:\n{s}\nstderr:\n{s}\n", .{ code, result.stdout, result.stderr });
            }
            try std.testing.expectEqual(@as(u8, 0), code);
        },
        else => {
            std.debug.print("e2fsck did not exit normally:\nstdout:\n{s}\nstderr:\n{s}\n", .{ result.stdout, result.stderr });
            return error.TestUnexpectedResult;
        },
    }
}

test "the minimum size grows by exactly the journal the ladder chose" {
    var tree = minimumSizeTestTree();
    tree.bind();
    const plain: PopulateOptions = .{ .length = 0, .uuid = [_]u8{0x45} ** 16 };
    var journalled = plain;
    journalled.journal = .{ .enabled = true };

    const without = try minimumPopulateLength(std.testing.allocator, &tree.view, plain);
    const with = try minimumPopulateLength(std.testing.allocator, &tree.view, journalled);
    try expectMinimalPopulateLength(&tree.view, journalled, with);

    // The journal is chosen for the size it is part of, not for the size the
    // tree alone would need, so the ladder is re-read at the answer.
    try std.testing.expectEqual(defaultJournalBlocks(with.total_blocks).?, with.journal_blocks);
    try std.testing.expect(with.journal_blocks > 0);
    try std.testing.expect(with.total_blocks > without.total_blocks);
    try std.testing.expectEqual(without.content_blocks, with.content_blocks);
}

test "an explicit journal size is bounded and honoured when solving for the minimum" {
    var tree = minimumSizeTestTree();
    tree.bind();
    const explicit_blocks: u32 = 2048;
    var options: PopulateOptions = .{ .length = 0, .uuid = [_]u8{0x46} ** 16 };
    options.journal = .{
        .enabled = true,
        .size_bytes = @as(u64, explicit_blocks) * default_block_size,
    };

    const minimum = try minimumPopulateLength(std.testing.allocator, &tree.view, options);
    try expectMinimalPopulateLength(&tree.view, options, minimum);
    try std.testing.expectEqual(explicit_blocks, minimum.journal_blocks);
    // `populate` refuses a journal larger than half the filesystem, so the
    // answer can never be smaller than twice the journal.
    try std.testing.expect(minimum.total_blocks >= explicit_blocks * 2);

    // The same bounds `populate` applies are applied here, before any
    // geometry is searched -- an unusable request is named, not solved for.
    var unaligned = options;
    unaligned.journal = .{ .enabled = true, .size_bytes = default_block_size + 1 };
    try std.testing.expectError(
        error.UnalignedJournalSize,
        minimumPopulateLength(std.testing.allocator, &tree.view, unaligned),
    );
    var tiny = options;
    tiny.journal = .{ .enabled = true, .size_bytes = default_block_size };
    try std.testing.expectError(
        error.JournalSizeTooSmall,
        minimumPopulateLength(std.testing.allocator, &tree.view, tiny),
    );
}

test "the minimum size counts the extent-tree blocks a large file needs" {
    // A file large enough that its extents no longer fit in the four the
    // inode holds inline pays for index blocks out of the same free space
    // its data comes from. Nothing outside the allocator knows how many, so
    // this is the case a size computed from content alone gets wrong.
    //
    // Planning only: `preflightPopulate` proves the answer without writing
    // half a gigabyte to a shared disk.
    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "boot", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "boot/rootfs.img", .kind = .file, .mode = 0o600, .uid = 0, .gid = 0, .size = 544 * 1024 * 1024, .generator = .pattern },
    });
    tree.bind();
    const options: PopulateOptions = .{ .length = 0, .uuid = [_]u8{0x47} ** 16 };

    const minimum = try minimumPopulateLength(std.testing.allocator, &tree.view, options);
    try expectMinimalPopulateLength(&tree.view, options, minimum);
    try std.testing.expect(minimum.extent_tree_blocks > 0);
}

test "an empty tree still needs a filesystem, and the minimum one is valid" {
    var tree = InMemoryTree.init(&[_]InMemoryEntry{});
    tree.bind();
    const options: PopulateOptions = .{ .length = 0, .uuid = [_]u8{0x48} ** 16 };

    const minimum = try minimumPopulateLength(std.testing.allocator, &tree.view, options);
    try expectMinimalPopulateLength(&tree.view, options, minimum);
    // Not zero: the root directory is implicit rather than absent, and its
    // one block is the smallest thing an ext4 filesystem can contain.
    try std.testing.expectEqual(@as(u32, 1), minimum.content_blocks);
    try std.testing.expectEqual(@as(u32, 0), minimum.extent_tree_blocks);
    try std.testing.expectEqual(@as(u32, 1), minimum.group_count);
}

test "a tree of many small files is bound by its inodes, not by its bytes" {
    // Every file here is empty, so a size derived from content alone would
    // land far too small: the inode tables cost several times what the
    // directory listing does, and nothing about that is visible in the byte
    // count the operator sees.
    const file_count = 4096;
    const entries = try std.testing.allocator.alloc(InMemoryEntry, file_count);
    defer std.testing.allocator.free(entries);
    const names = try std.testing.allocator.alloc([16]u8, file_count);
    defer std.testing.allocator.free(names);
    for (entries, names, 0..) |*entry, *name, index| {
        entry.* = .{
            .path = try std.fmt.bufPrint(name, "f{d}", .{index}),
            .kind = .file,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .size = 0,
        };
    }
    var tree = InMemoryTree.init(entries);
    tree.bind();
    const options: PopulateOptions = .{ .length = 0, .uuid = [_]u8{0x49} ** 16 };

    const minimum = try minimumPopulateLength(std.testing.allocator, &tree.view, options);
    try expectMinimalPopulateLength(&tree.view, options, minimum);
    try std.testing.expect(minimum.inode_count >= file_count + first_non_reserved_inode - 1);
    try std.testing.expect(minimum.metadata_blocks > minimum.content_blocks);
}

test "a floor raises the answer without giving up minimality above it" {
    var tree = minimumSizeTestTree();
    tree.bind();
    const options: PopulateOptions = .{ .length = 0, .uuid = [_]u8{0x4A} ** 16 };

    const minimum = try minimumPopulateLength(std.testing.allocator, &tree.view, options);
    // A floor the answer already clears changes nothing at all.
    const unchanged = try minimumPopulateLengthAtLeast(
        std.testing.allocator,
        &tree.view,
        options,
        minimum.length,
    );
    try std.testing.expectEqual(minimum.length, unchanged.length);
    const below = try minimumPopulateLengthAtLeast(
        std.testing.allocator,
        &tree.view,
        options,
        minimum.length / 2,
    );
    try std.testing.expectEqual(minimum.length, below.length);

    // A floor above it is met exactly whenever the layout accepts that size,
    // which for a filesystem well inside its first block group it always
    // does.
    const raised = minimum.length + 16 * 1024 * 1024;
    const floored = try minimumPopulateLengthAtLeast(std.testing.allocator, &tree.view, options, raised);
    try std.testing.expectEqual(raised, floored.length);
    try std.testing.expect(floored.free_blocks > minimum.free_blocks);
    try std.testing.expectEqual(minimum.content_blocks, floored.content_blocks);

    var accepted = options;
    accepted.length = floored.length;
    const info = try preflightPopulate(std.testing.allocator, &tree.view, accepted);
    try std.testing.expectEqual(floored.total_blocks, info.block_count);
}

test "a floor lands past the block-group boundary that would have refused it" {
    // The hole this steps over is real, and this is what it looks like. A
    // filesystem sized to just past a group boundary owes that group a
    // superblock copy, a group descriptor table, two bitmaps and an inode
    // table before it may store anything, and `buildLayout` refuses a group
    // that cannot pay. How wide the hole is depends on how many inodes the
    // tree has, so a caller adding headroom to a minimum has no way to know
    // where the boundaries fall or how far past one it has to reach.
    var tree = minimumSizeTestTree();
    tree.bind();
    const options: PopulateOptions = .{ .length = 0, .uuid = [_]u8{0x4B} ** 16 };

    const minimum = try minimumPopulateLength(std.testing.allocator, &tree.view, options);
    const boundary = default_blocks_per_group;
    try std.testing.expect(minimum.total_blocks < boundary);

    // One block into the second group is refused outright, so a floor there
    // has to come back with something larger.
    var refused = options;
    refused.length = @as(u64, boundary + 1) * default_block_size;
    try std.testing.expectError(
        error.NotEnoughSpace,
        preflightPopulate(std.testing.allocator, &tree.view, refused),
    );

    const floored = try minimumPopulateLengthAtLeast(
        std.testing.allocator,
        &tree.view,
        options,
        refused.length,
    );
    try std.testing.expect(floored.length > refused.length);
    try std.testing.expectEqual(@as(u32, 2), floored.group_count);

    var accepted = options;
    accepted.length = floored.length;
    _ = try preflightPopulate(std.testing.allocator, &tree.view, accepted);

    // And it is the *smallest* size past the hole, not merely one that works.
    var one_less = options;
    one_less.length = floored.length - default_block_size;
    try std.testing.expectError(
        error.NotEnoughSpace,
        preflightPopulate(std.testing.allocator, &tree.view, one_less),
    );
}

// ---------------------------------------------------------------------------
// Journal tests
//
// A malformed JBD2 superblock is strictly worse than none at all: the kernel
// trusts what it finds there and replays accordingly. So the on-disk shape is
// checked two ways -- `e2fsck -f -n` has to call the result a clean journalled
// filesystem, and the journal superblock itself is compared byte for byte
// against the one `mke2fs` writes for the same geometry.
// ---------------------------------------------------------------------------

const journal_test_uuid: [16]u8 = [_]u8{0x11} ** 16;
const journal_test_uuid_text = "11111111-1111-1111-1111-111111111111";

fn journalTestTree() InMemoryTree {
    return InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/hostname", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 10, .bytes = "zvmi-test\n" },
        .{ .path = "usr", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "usr/payload.bin", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 3 * 1024 * 1024, .generator = .pattern },
        .{ .path = "link", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 12, .bytes = "etc/hostname" },
    });
}

/// Runs an e2fsprogs tool that prints what the test wants to assert on, and
/// returns its stdout. Null means the tool is not installed anywhere this
/// looks, which the callers decline over rather than pass vacuously.
fn runToolCapture(
    allocator: std.mem.Allocator,
    name: []const u8,
    args: []const []const u8,
) !?[]u8 {
    const maybe_result = try runExternalTool(allocator, name, args);
    const result = maybe_result orelse return null;
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.debug.print("{s} failed (exit {d}):\n{s}\n{s}\n", .{ name, code, result.stdout, result.stderr });
            return error.ExternalToolFailed;
        },
        else => return error.ExternalToolFailed,
    }
    return result.stdout;
}

/// Extracts a file from an image by inode number. The journal has no name, so
/// this is the only way to read the bytes the kernel would recover from.
fn dumpInodeAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    image_path: []const u8,
    inode_number: u32,
    scratch_path: []const u8,
    max_bytes: usize,
) !?[]u8 {
    var command: [64]u8 = undefined;
    const request = try std.fmt.bufPrint(&command, "dump <{d}> {s}", .{ inode_number, scratch_path });
    const output = (try runToolCapture(allocator, "debugfs", &.{ "-R", request, image_path })) orelse
        return null;
    allocator.free(output);
    defer Io.Dir.cwd().deleteFile(io, scratch_path) catch {};

    const file = try Io.Dir.cwd().openFile(io, scratch_path, .{});
    defer file.close(io);
    const bytes = try allocator.alloc(u8, max_bytes);
    errdefer allocator.free(bytes);
    const read = try file.readPositionalAll(io, bytes, 0);
    if (read != max_bytes) return error.UnexpectedEndOfStream;
    return bytes;
}

test "the default journal size follows mke2fs's own ladder" {
    // e2fsprogs 1.47 `ext2fs_default_journal_size`, tier by tier, at the
    // boundary blocks where it changes answer.
    try std.testing.expectEqual(@as(?u32, null), defaultJournalBlocks(2047));
    try std.testing.expectEqual(@as(?u32, 1024), defaultJournalBlocks(2048));
    try std.testing.expectEqual(@as(?u32, 1024), defaultJournalBlocks(32 * 1024 - 1));
    try std.testing.expectEqual(@as(?u32, 4096), defaultJournalBlocks(32 * 1024));
    try std.testing.expectEqual(@as(?u32, 4096), defaultJournalBlocks(256 * 1024 - 1));
    try std.testing.expectEqual(@as(?u32, 8192), defaultJournalBlocks(256 * 1024));
    try std.testing.expectEqual(@as(?u32, 8192), defaultJournalBlocks(512 * 1024 - 1));
    try std.testing.expectEqual(@as(?u32, 16384), defaultJournalBlocks(512 * 1024));
    try std.testing.expectEqual(@as(?u32, 16384), defaultJournalBlocks(4096 * 1024 - 1));
    try std.testing.expectEqual(@as(?u32, 32768), defaultJournalBlocks(4096 * 1024));
    try std.testing.expectEqual(@as(?u32, 65536), defaultJournalBlocks(8192 * 1024));
    try std.testing.expectEqual(@as(?u32, 131072), defaultJournalBlocks(16384 * 1024));
    try std.testing.expectEqual(@as(?u32, 262144), defaultJournalBlocks(32768 * 1024));

    // Spelled in bytes, with 4 KiB blocks: 4 MiB below 128 MiB, 16 MiB below
    // 1 GiB, 32 MiB below 2 GiB, 64 MiB below 16 GiB.
    try std.testing.expectEqual(@as(?u32, 1024), defaultJournalBlocks(64 * 1024 * 1024 / default_block_size));
    try std.testing.expectEqual(@as(?u32, 4096), defaultJournalBlocks(512 * 1024 * 1024 / default_block_size));
    try std.testing.expectEqual(@as(?u32, 8192), defaultJournalBlocks(1024 * 1024 * 1024 / default_block_size));
    try std.testing.expectEqual(@as(?u32, 16384), defaultJournalBlocks(4096 * 1024 * 1024 / @as(u64, default_block_size)));
}

test "the writer stays journal-less unless asked, and a journal moves no file" {
    const io = std.testing.io;
    const plain_path = "test-ext4-journal-absent.img";
    const journalled_path = "test-ext4-journal-present.img";
    defer Io.Dir.cwd().deleteFile(io, plain_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, journalled_path) catch {};

    const fs_size: u64 = 64 * 1024 * 1024;
    var plain_tree = journalTestTree();
    plain_tree.bind();
    var journalled_tree = journalTestTree();
    journalled_tree.bind();

    const plain_file = try Io.Dir.cwd().createFile(io, plain_path, .{ .read = true, .truncate = true });
    defer plain_file.close(io);
    const plain = try populate(io, plain_file, std.testing.allocator, &plain_tree.view, .{
        .length = fs_size,
        .uuid = journal_test_uuid,
    });
    try std.testing.expectEqual(writer_feature_compat, plain.feature_compat);
    try std.testing.expectEqual(@as(u32, 0), plain.journal_block_count);

    const journalled_file = try Io.Dir.cwd().createFile(io, journalled_path, .{ .read = true, .truncate = true });
    defer journalled_file.close(io);
    const journalled = try populate(io, journalled_file, std.testing.allocator, &journalled_tree.view, .{
        .length = fs_size,
        .uuid = journal_test_uuid,
        .journal = .{ .enabled = true },
    });
    try std.testing.expectEqual(
        writer_feature_compat | feature_compat_has_journal,
        journalled.feature_compat,
    );
    // 64 MiB is 16384 blocks, the ladder's first tier.
    try std.testing.expectEqual(@as(u32, 1024), journalled.journal_block_count);
    try std.testing.expectEqual(
        plain.free_block_count - journalled.journal_block_count,
        journalled.free_block_count,
    );
    // Reserved inode 8 was already counted as used, journal or not.
    try std.testing.expectEqual(plain.free_inode_count, journalled.free_inode_count);

    // Turning the journal on must not relocate anything the tree owns, which
    // is what makes a journalled and a journal-less build of the same tree
    // directly comparable.
    var plain_reader = try open(io, plain_file, std.testing.allocator, .{});
    defer plain_reader.deinit();
    var journalled_reader = try open(io, journalled_file, std.testing.allocator, .{});
    defer journalled_reader.deinit();
    for ([_][]const u8{ "etc/hostname", "usr/payload.bin", "etc" }) |path| {
        const plain_extents = try plain_reader.readExtents(io, std.testing.allocator, path);
        defer std.testing.allocator.free(plain_extents);
        const journalled_extents = try journalled_reader.readExtents(io, std.testing.allocator, path);
        defer std.testing.allocator.free(journalled_extents);
        try std.testing.expectEqualSlices(Extent, plain_extents, journalled_extents);
    }
}

test "a journalled filesystem passes e2fsck and reports the journal e2fsprogs expects" {
    const io = std.testing.io;
    const path = "test-ext4-journal-e2fsck.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = journalTestTree();
    tree.bind();
    const fs_size: u64 = 512 * 1024 * 1024;
    {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        const info = try populate(io, file, std.testing.allocator, &tree.view, .{
            .length = fs_size,
            .label = "zvmi-ext4",
            .uuid = journal_test_uuid,
            .timestamp = 1_717_171_717,
            .journal = .{ .enabled = true },
        });
        // 512 MiB is 131072 blocks: the ladder's 16 MiB tier.
        try std.testing.expectEqual(@as(u32, 4096), info.journal_block_count);
    }

    try expectE2fsckClean(path);

    const report = (try runToolCapture(std.testing.allocator, "dumpe2fs", &.{ "-h", path })) orelse
        return error.SkipZigTest;
    defer std.testing.allocator.free(report);
    for ([_][]const u8{
        "has_journal",
        "Journal inode:            8",
        "Journal backup:           inode blocks",
        "Total journal size:       16M",
        "Journal sequence:         0x00000001",
        "Journal start:            0",
    }) |needle| {
        if (std.mem.indexOf(u8, report, needle) == null) {
            std.debug.print("dumpe2fs output missing {s}:\n{s}\n", .{ needle, report });
            return error.TestUnexpectedResult;
        }
    }
}

test "the JBD2 superblock is byte-identical to the one mke2fs writes" {
    const io = std.testing.io;
    const ours_path = "test-ext4-journal-ours.img";
    const theirs_path = "test-ext4-journal-mke2fs.img";
    defer Io.Dir.cwd().deleteFile(io, ours_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, theirs_path) catch {};

    // 64 MiB, so both writers land on the ladder's 1024-block tier without
    // either being told a size.
    const fs_size: u64 = 64 * 1024 * 1024;
    var tree = journalTestTree();
    tree.bind();
    {
        const file = try Io.Dir.cwd().createFile(io, ours_path, .{ .read = true, .truncate = true });
        defer file.close(io);
        _ = try populate(io, file, std.testing.allocator, &tree.view, .{
            .length = fs_size,
            .uuid = journal_test_uuid,
            .journal = .{ .enabled = true },
        });
    }

    var block_text: [32]u8 = undefined;
    runExternalToolChecked(std.testing.allocator, "mke2fs", &.{
        "-q",
        "-F",
        "-t",
        "ext4",
        "-b",
        "4096",
        "-U",
        journal_test_uuid_text,
        theirs_path,
        try std.fmt.bufPrint(&block_text, "{d}", .{fs_size / default_block_size}),
    }) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const ours = (try dumpInodeAlloc(
        std.testing.allocator,
        io,
        ours_path,
        journal_inode,
        "test-ext4-journal-ours.jbd2",
        1024,
    )) orelse return error.SkipZigTest;
    defer std.testing.allocator.free(ours);
    const theirs = (try dumpInodeAlloc(
        std.testing.allocator,
        io,
        theirs_path,
        journal_inode,
        "test-ext4-journal-mke2fs.jbd2",
        1024,
    )) orelse return error.SkipZigTest;
    defer std.testing.allocator.free(theirs);

    try std.testing.expectEqualSlices(u8, theirs, ours);

    // Spelled out as well, so a future divergence says which field moved
    // rather than only that a thousand bytes differ.
    try std.testing.expectEqual(jbd2_magic, std.mem.readInt(u32, ours[0x00..0x04], .big));
    try std.testing.expectEqual(jbd2_superblock_v2, std.mem.readInt(u32, ours[0x04..0x08], .big));
    try std.testing.expectEqual(default_block_size, std.mem.readInt(u32, ours[0x0C..0x10], .big));
    try std.testing.expectEqual(@as(u32, 1024), std.mem.readInt(u32, ours[0x10..0x14], .big));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, ours[0x14..0x18], .big));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, ours[0x18..0x1C], .big));
    // s_start == 0 is what says "empty log", so nothing is ever replayed from
    // a freshly written image.
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, ours[0x1C..0x20], .big));
    try std.testing.expectEqualSlices(u8, &journal_test_uuid, ours[0x30..0x40]);
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, ours[0x40..0x44], .big));
}

test "the journal inode carries the layout e2fsprogs and the kernel read" {
    const io = std.testing.io;
    const path = "test-ext4-journal-inode.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = journalTestTree();
    tree.bind();
    const fs_size: u64 = 64 * 1024 * 1024;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    const info = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = fs_size,
        .uuid = journal_test_uuid,
        .journal = .{ .enabled = true },
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    const journal = try reader.readInode(io, journal_inode);
    try std.testing.expectEqual(Kind.file, journal.kind);
    try std.testing.expectEqual(@as(u16, journal_inode_mode), journal.mode);
    try std.testing.expectEqual(@as(u64, info.journal_block_count) * default_block_size, journal.size);
    try std.testing.expectEqual(@as(u16, 1), journal.link_count);

    var sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sb, superblock_offset);
    try std.testing.expectEqual(journal_inode, readInt(u32, sb[0xE0..0xE4]));
    // An external-journal device would be named here, and there is none.
    try std.testing.expectEqual(@as(u32, 0), readInt(u32, sb[0xE4..0xE8]));
    try std.testing.expect(allZero(sb[0xD0..0xE0]));
    try std.testing.expectEqual(jnl_backup_type_blocks, readInt(u8, sb[0xFD..0xFE]));
    // `s_jnl_blocks` backs up the inode's i_block array plus its size.
    const extents = try reader.readInodeExtentsAlloc(io, std.testing.allocator, journal);
    defer std.testing.allocator.free(extents);
    try std.testing.expectEqual(@as(usize, 1), extents.len);
    try std.testing.expectEqualSlices(u8, sb[0x10C..0x148], journal.block_bytes[0..60]);
    try std.testing.expectEqual(@as(u32, 0), readInt(u32, sb[0x148..0x14C]));
    try std.testing.expectEqual(
        @as(u32, info.journal_block_count * default_block_size),
        readInt(u32, sb[0x14C..0x150]),
    );
}

test "the writer names every journal size it refuses" {
    const io = std.testing.io;
    const path = "test-ext4-journal-refusals.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    var tree = InMemoryTree.init(&[_]InMemoryEntry{});
    tree.bind();

    const Case = struct {
        length: u64,
        journal: JournalOptions,
        expected: anyerror,
    };
    for ([_]Case{
        // Below 2048 blocks there is nowhere to put the JBD2 minimum.
        .{
            .length = 4 * 1024 * 1024,
            .journal = .{ .enabled = true },
            .expected = error.FilesystemTooSmallForJournal,
        },
        .{
            .length = 64 * 1024 * 1024,
            .journal = .{ .enabled = true, .size_bytes = 1023 * default_block_size },
            .expected = error.JournalSizeTooSmall,
        },
        // Above half the filesystem the log stops being overhead.
        .{
            .length = 64 * 1024 * 1024,
            .journal = .{ .enabled = true, .size_bytes = 48 * 1024 * 1024 },
            .expected = error.JournalSizeTooLarge,
        },
        .{
            .length = 64 * 1024 * 1024,
            .journal = .{ .enabled = true, .size_bytes = 4 * 1024 * 1024 + 1 },
            .expected = error.UnalignedJournalSize,
        },
        .{
            .length = 64 * 1024 * 1024,
            .journal = .{ .enabled = true, .size_bytes = 0 },
            .expected = error.UnalignedJournalSize,
        },
    }) |case| {
        try std.testing.expectError(case.expected, populate(
            io,
            file,
            std.testing.allocator,
            &tree.view,
            .{ .length = case.length, .journal = case.journal },
        ));
    }
}

test "an explicit journal size is honoured and still passes e2fsck" {
    const io = std.testing.io;
    const path = "test-ext4-journal-explicit.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = journalTestTree();
    tree.bind();
    {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        const info = try populate(io, file, std.testing.allocator, &tree.view, .{
            .length = 512 * 1024 * 1024,
            .uuid = journal_test_uuid,
            .journal = .{ .enabled = true, .size_bytes = 8 * 1024 * 1024 },
        });
        // The ladder would have chosen 4096 blocks here; the explicit size wins.
        try std.testing.expectEqual(@as(u32, 2048), info.journal_block_count);
    }
    try expectE2fsckClean(path);
}

test "resize grows a journalled filesystem and leaves its journal intact" {
    const io = std.testing.io;
    const path = "test-ext4-journal-resize.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = journalTestTree();
    tree.bind();
    const original_size: u64 = 64 * 1024 * 1024;
    const grown_size: u64 = 256 * 1024 * 1024;
    {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        _ = try populate(io, file, std.testing.allocator, &tree.view, .{
            .length = original_size,
            .uuid = journal_test_uuid,
            .journal = .{ .enabled = true },
        });

        const grown = try resize(io, file, std.testing.allocator, .{ .length = grown_size });
        try std.testing.expectEqual(@as(u32, grown_size / default_block_size), grown.block_count);
        try std.testing.expectEqual(
            writer_feature_compat | feature_compat_has_journal,
            grown.feature_compat,
        );
        // The journal neither grows nor moves; it is already inside the range
        // the grow leaves alone.
        try std.testing.expectEqual(@as(u32, 1024), grown.journal_block_count);
    }
    try expectE2fsckClean(path);

    const reopened = try Io.Dir.cwd().openFile(io, path, .{});
    defer reopened.close(io);
    var reader = try open(io, reopened, std.testing.allocator, .{});
    defer reader.deinit();
    const journal = try reader.readInode(io, journal_inode);
    try std.testing.expectEqual(@as(u64, 1024) * default_block_size, journal.size);
    const hostname = try reader.readFileAlloc(io, std.testing.allocator, "etc/hostname");
    defer std.testing.allocator.free(hostname);
    try std.testing.expectEqualSlices(u8, "zvmi-test\n", hostname);
}

test "resize refuses a resize_inode filesystem by name rather than by layout" {
    const io = std.testing.io;
    const path = "test-ext4-journal-resize-inode.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = journalTestTree();
    tree.bind();
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = 64 * 1024 * 1024,
        .uuid = journal_test_uuid,
    });

    // Set the bit the writer never sets, so the refusal names the feature
    // rather than blaming an unrelated layout mismatch.
    var sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sb, superblock_offset);
    writeInt(u32, sb[0x5C..0x60], readInt(u32, sb[0x5C..0x60]) | feature_compat_resize_inode);
    setSuperblockChecksum(&sb);
    try file.writePositionalAll(io, &sb, superblock_offset);

    try std.testing.expectError(
        error.ResizeInodeNotSupported,
        resize(io, file, std.testing.allocator, .{ .length = 128 * 1024 * 1024 }),
    );
}

test "a journalled image is a distinct profile the strict scan refuses" {
    const io = std.testing.io;
    const path = "test-ext4-journal-profile.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = journalTestTree();
    tree.bind();
    const fs_size: u64 = 64 * 1024 * 1024;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = fs_size,
        .uuid = journal_test_uuid,
        .journal = .{ .enabled = true },
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    // The strict profile is the exact feature set the byte-for-byte
    // reproducibility promise was made about, and HAS_JOURNAL is not in it.
    try std.testing.expectError(error.UnsupportedWriterProfile, scanWriterCompatible(
        &reader,
        io,
        std.testing.allocator,
        .{ .expected_length = fs_size },
    ));

    // The general importer reads it, and says so.
    var general = try scanReadable(&reader, io, std.testing.allocator, .{ .available_length = fs_size });
    defer general.deinit();
    try std.testing.expectEqual(SourceProfile.ext4_general_v1, general.identity.profile);
    try std.testing.expect(general.identity.has_journal);
    try std.testing.expect(findGeneralEntry(&general, "etc/hostname") != null);
}

const InMemoryEntry = struct {
    path: []const u8,
    kind: Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64 = 0,
    bytes: []const u8 = "",
    xattrs: []const Xattr = &.{},
    generator: enum { none, pattern } = .none,
    device: DeviceNumbers = .{},
    hardlink_target: []const u8 = "",
    atime: ?i64 = null,
    mtime: ?i64 = null,
    ctime: ?i64 = null,
    atime_nsec: u32 = 0,
    mtime_nsec: u32 = 0,
    ctime_nsec: u32 = 0,
    crtime: ?i64 = null,
    crtime_nsec: u32 = 0,
};

const InMemoryTree = struct {
    entries: []const InMemoryEntry,
    index: usize = 0,
    view: FileTreeView,

    fn init(entries: []const InMemoryEntry) InMemoryTree {
        return .{
            .entries = entries,
            .view = .{
                .ctx = undefined,
                .next_fn = next,
                .reset_fn = reset,
            },
        };
    }

    fn bind(self: *InMemoryTree) void {
        self.view = .{
            .ctx = self,
            .next_fn = next,
            .reset_fn = reset,
        };
    }

    fn reset(ctx: *anyopaque) void {
        const self: *InMemoryTree = @ptrCast(@alignCast(ctx));
        self.index = 0;
    }

    fn next(ctx: *anyopaque) FileTreeView.IteratorError!?FileTreeView.Entry {
        const self: *InMemoryTree = @ptrCast(@alignCast(ctx));
        if (self.index >= self.entries.len) return null;
        const entry = self.entries[self.index];
        self.index += 1;
        return .{
            .path = entry.path,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = switch (entry.kind) {
                .file, .symlink => .{
                    .ctx = &self.entries[self.index - 1],
                    .read_at_fn = readContent,
                },
                else => null,
            },
            .xattrs = entry.xattrs,
            .device = entry.device,
            .hardlink_target = entry.hardlink_target,
            .atime = entry.atime,
            .mtime = entry.mtime,
            .ctime = entry.ctime,
            .atime_nsec = entry.atime_nsec,
            .mtime_nsec = entry.mtime_nsec,
            .ctime_nsec = entry.ctime_nsec,
            .crtime = entry.crtime,
            .crtime_nsec = entry.crtime_nsec,
        };
    }

    fn readContent(ctx: *const anyopaque, buffer: []u8, offset: u64) FileTreeView.ContentError!usize {
        const entry: *const InMemoryEntry = @ptrCast(@alignCast(ctx));
        switch (entry.generator) {
            .none => {
                const off = std.math.cast(usize, offset) orelse return error.UnexpectedEndOfStream;
                if (off > entry.bytes.len) return error.UnexpectedEndOfStream;
                const n = @min(buffer.len, entry.bytes.len - off);
                std.mem.copyForwards(u8, buffer[0..n], entry.bytes[off .. off + n]);
                return n;
            },
            .pattern => {
                fillPattern(buffer, offset);
                return buffer.len;
            },
        }
    }
};

fn fillPattern(buffer: []u8, offset: u64) void {
    for (buffer, 0..) |*byte, index| {
        byte.* = @truncate(((offset + index) * 31 + 17) & 0xFF);
    }
}

fn decodeSyntheticExtentTree(
    allocator: std.mem.Allocator,
    root_bytes: []const u8,
    blocks: []const ExtentTreeBlock,
) ![]Extent {
    var extents = std.array_list.Managed(Extent).init(allocator);
    errdefer extents.deinit();
    try appendSyntheticExtentTreeEntries(&extents, root_bytes, max_inline_extents, blocks, null);
    return extents.toOwnedSlice();
}

fn appendSyntheticExtentTreeEntries(
    extents: *std.array_list.Managed(Extent),
    node_bytes: []const u8,
    node_capacity: usize,
    blocks: []const ExtentTreeBlock,
    expected_depth: ?u16,
) !void {
    const header = try parseExtentHeader(node_bytes[0..extent_header_size]);
    if (expected_depth) |depth| try std.testing.expectEqual(depth, header.depth);
    try std.testing.expect(header.entries <= header.max);
    try std.testing.expect(header.max <= node_capacity);

    if (header.depth == 0) {
        var entry_index: usize = 0;
        while (entry_index < header.entries) : (entry_index += 1) {
            const base = extent_header_size + entry_index * extent_entry_size;
            try extents.append(decodeExtent(node_bytes[base .. base + extent_entry_size]));
        }
        return;
    }

    var entry_index: usize = 0;
    while (entry_index < header.entries) : (entry_index += 1) {
        const base = extent_header_size + entry_index * extent_entry_size;
        const child = decodeExtentIndex(node_bytes[base .. base + extent_entry_size]);
        const child_block = findSyntheticExtentTreeBlock(blocks, child.leaf_block) orelse return error.TestUnexpectedResult;
        try appendSyntheticExtentTreeEntries(
            extents,
            child_block[0..],
            extentEntriesPerBlock(default_block_size),
            blocks,
            header.depth - 1,
        );
    }
}

fn findSyntheticExtentTreeBlock(blocks: []const ExtentTreeBlock, block_number: u64) ?[]const u8 {
    for (blocks) |*block| {
        if (block.block_number == block_number) return block.bytes[0..];
    }
    return null;
}

fn readDirectoryLogicalBlock(io: Io, file: Io.File, extents: []const Extent, logical_block: u32, block: []u8) !void {
    const physical_block = findPhysicalBlock(extents, logical_block) orelse return error.TestUnexpectedResult;
    _ = try file.readPositionalAll(io, block, physical_block * default_block_size);
}

fn expectXattrValue(xattrs: []const OwnedXattr, name: []const u8, value: []const u8) !void {
    for (xattrs) |xattr| {
        if (std.mem.eql(u8, xattr.name, name)) {
            try std.testing.expectEqualSlices(u8, value, xattr.value);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

const RawInodeForPath = struct {
    inode_number: u32,
    bytes: [max_supported_reader_inode_size]u8,
};

fn readRawInodeForPath(io: Io, file: Io.File, reader: *const Reader, path: []const u8) !RawInodeForPath {
    const inode_number = try reader.lookupPath(io, path);
    const group = (inode_number - 1) / reader.inodes_per_group;
    const index = (inode_number - 1) % reader.inodes_per_group;
    var bytes: [max_supported_reader_inode_size]u8 = undefined;
    _ = try file.readPositionalAll(io, bytes[0..reader.inode_size], reader.blockOffset(reader.groups[group].inode_table_block) + @as(u64, index) * reader.inode_size);
    return .{
        .inode_number = inode_number,
        .bytes = bytes,
    };
}

fn expectInodeBlocksForPath(io: Io, file: Io.File, reader: *const Reader, path: []const u8, expected_i_blocks: u32) !void {
    const raw_inode = try readRawInodeForPath(io, file, reader, path);
    try std.testing.expectEqual(expected_i_blocks, readInt(u32, raw_inode.bytes[28..32]));
}

fn expectMetadataChecksumsValid(io: Io, file: Io.File, offset: u64, file_path: []const u8, dir_path: []const u8) !void {
    var sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sb, offset + superblock_offset);
    const stored_sb_checksum = readInt(u32, sb[0x3FC..0x400]);
    var sb_copy = sb;
    setSuperblockChecksum(&sb_copy);
    try std.testing.expectEqual(stored_sb_checksum, readInt(u32, sb_copy[0x3FC..0x400]));

    var uuid: [16]u8 = undefined;
    @memcpy(&uuid, sb[0x68..0x78]);
    const total_blocks = readInt(u32, sb[0x04..0x08]);
    const inodes_per_group = readInt(u32, sb[0x28..0x2C]);
    const inode_table_blocks = divCeil(@as(u32, inodes_per_group) * readInt(u16, sb[0x58..0x5A]), default_block_size);
    const group_count = blocksToGroups(total_blocks, default_blocks_per_group);
    const gdt_blocks = blocksForBytes(@as(u64, group_count) * group_desc_size, default_block_size);

    const layout = try buildFixedLayout(std.testing.allocator, total_blocks, default_blocks_per_group, inodes_per_group, inode_table_blocks, gdt_blocks);
    defer std.testing.allocator.free(layout.groups);

    var gdt: [default_block_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &gdt, offset + default_block_size);
    for (layout.groups, 0..) |group, index| {
        const base = index * group_desc_size;
        var desc_copy: [group_desc_size]u8 = undefined;
        @memcpy(&desc_copy, gdt[base .. base + group_desc_size]);
        const stored_desc_checksum = readInt(u16, desc_copy[0x1E..0x20]);
        setGroupDescriptorChecksums(desc_copy[0..], .{
            .total_blocks = layout.total_blocks,
            .group_count = 1,
            .gdt_blocks = layout.gdt_blocks,
            .inodes_per_group = layout.inodes_per_group,
            .inode_table_blocks = layout.inode_table_blocks,
            .groups = @constCast(&[_]GroupLayout{group}),
        }, uuid);
        try std.testing.expectEqual(stored_desc_checksum, readInt(u16, desc_copy[0x1E..0x20]));

        var block_bitmap: [default_block_size]u8 = undefined;
        var inode_bitmap: [default_block_size]u8 = undefined;
        _ = try file.readPositionalAll(io, &block_bitmap, offset + @as(u64, group.block_bitmap_block) * default_block_size);
        _ = try file.readPositionalAll(io, &inode_bitmap, offset + @as(u64, group.inode_bitmap_block) * default_block_size);
        try std.testing.expectEqual(@as(u16, @truncate(bitmapChecksum(uuid, &block_bitmap, default_blocks_per_group / 8))), readInt(u16, gdt[base + 0x18 .. base + 0x1A]));
        try std.testing.expectEqual(@as(u16, @truncate(bitmapChecksum(uuid, &inode_bitmap, inodes_per_group / 8))), readInt(u16, gdt[base + 0x1A .. base + 0x1C]));
    }

    var reader = try open(io, file, std.testing.allocator, .{ .offset = offset });
    defer reader.deinit();

    const raw_inode = try readRawInodeForPath(io, file, &reader, file_path);
    const stored_inode_checksum = readInt(u16, raw_inode.bytes[124..126]);
    var inode_copy = raw_inode.bytes;
    setInodeChecksum(&inode_copy, uuid, raw_inode.inode_number);
    try std.testing.expectEqual(stored_inode_checksum, readInt(u16, inode_copy[124..126]));

    const parsed_inode = try reader.readInode(io, raw_inode.inode_number);
    if (parsed_inode.file_acl_block != 0) {
        var xattr_block: [default_block_size]u8 = undefined;
        _ = try file.readPositionalAll(io, &xattr_block, offset + @as(u64, parsed_inode.file_acl_block) * default_block_size);
        const stored_xattr_checksum = readInt(u32, xattr_block[0x10..0x14]);
        var xattr_copy = xattr_block;
        setXattrBlockChecksum(&xattr_copy, uuid, parsed_inode.file_acl_block);
        try std.testing.expectEqual(stored_xattr_checksum, readInt(u32, xattr_copy[0x10..0x14]));
    }

    const dir_inode_number = try reader.lookupPath(io, dir_path);
    const dir_inode = try reader.readInode(io, dir_inode_number);
    const dir_extents = try reader.readInodeExtentsAlloc(io, std.testing.allocator, dir_inode);
    defer std.testing.allocator.free(dir_extents);
    var dir_block: [default_block_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &dir_block, offset + dir_extents[0].start_block * default_block_size);
    const stored_dir_checksum = readInt(u32, dir_block[dir_block.len - 4 ..]);
    var dir_copy = dir_block;
    setDirectoryLeafChecksum(&dir_copy, uuid, dir_inode_number, 0);
    try std.testing.expectEqual(stored_dir_checksum, readInt(u32, dir_copy[dir_copy.len - 4 ..]));
}

fn expectDirNames(entries: []const DirEntry, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, entries.len);
    for (expected, 0..) |name, index| {
        try std.testing.expectEqualSlices(u8, name, entries[index].name);
    }
}

test "a strict scan reports peaks and names the limit that stopped it" {
    const io = std.testing.io;
    const path = "test-ext4-strict-limits.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const attrs = [_]Xattr{.{ .name = "user.test", .value = "value" }};
    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o750, .uid = 1, .gid = 2 },
        .{ .path = "etc/file", .kind = .file, .mode = 0o640, .uid = 3, .gid = 4, .size = 4, .bytes = "test", .xattrs = &attrs },
    });
    tree.bind();

    const length = 8 * 1024 * 1024;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = length,
        .uuid = [_]u8{0x21} ** 16,
        .timestamp = 1_717_171_717,
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    var measured = limits_mod.Diagnostic{};
    var scanned = try scanWriterCompatible(&reader, io, std.testing.allocator, .{
        .expected_length = length,
        .diagnostic = &measured,
    });
    defer scanned.deinit();

    try std.testing.expectEqual(@as(u64, 2), measured.peaks.nodes);
    // The directory inode's 4 KiB size is the largest inode size seen: the
    // scanner bounds every inode, not only regular files.
    try std.testing.expectEqual(@as(u64, 4096), measured.peaks.file_bytes);
    try std.testing.expectEqual(@as(u64, 4), measured.peaks.total_bytes);
    try std.testing.expectEqual(@as(u64, 1), measured.peaks.xattrs_per_node);
    try std.testing.expectEqual(@as(u64, 8), measured.peaks.path_bytes);
    try std.testing.expect(measured.peaks.scan_metadata_bytes != 0);
    try std.testing.expect(measured.exceeded == null);
    try std.testing.expectEqual(@as(u64, 4), scanned.content_bytes);

    var breached = limits_mod.Diagnostic{};
    try std.testing.expectError(
        error.NodeLimitExceeded,
        scanWriterCompatible(&reader, io, std.testing.allocator, .{
            .expected_length = length,
            .max_nodes = 1,
            .diagnostic = &breached,
        }),
    );
    try std.testing.expectEqual(limits_mod.Limit.nodes, breached.exceeded.?.limit);
    try std.testing.expectEqual(@as(u64, 2), breached.exceeded.?.observed);
    try std.testing.expectEqual(@as(u64, 1), breached.exceeded.?.configured);
}

// ---------------------------------------------------------------------------
// General import tests
//
// These build real filesystems with stock `mke2fs` defaults -- 256-byte
// inodes, a journal, `64bit`, `flex_bg`, `metadata_csum` -- because the whole
// point of the general importer is the profile this module's own writer will
// never produce. A fixture generated from a directory needs no privileges, so
// the coverage is real rather than synthetic; where the tool is missing the
// tests decline instead of passing vacuously.
// ---------------------------------------------------------------------------

fn runExternalTool(
    allocator: std.mem.Allocator,
    name: []const u8,
    args: []const []const u8,
) !?std.process.RunResult {
    const prefixes = [_][]const u8{ "", "/sbin/", "/usr/sbin/" };
    for (prefixes) |prefix| {
        const binary = try std.fmt.allocPrint(allocator, "{s}{s}", .{ prefix, name });
        defer allocator.free(binary);
        const argv = try allocator.alloc([]const u8, args.len + 1);
        defer allocator.free(argv);
        argv[0] = binary;
        @memcpy(argv[1..], args);
        const result = std.process.run(allocator, std.testing.io, .{
            .argv = argv,
            .cwd = .{ .path = "." },
        }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return result;
    }
    return null;
}

fn runExternalToolChecked(
    allocator: std.mem.Allocator,
    name: []const u8,
    args: []const []const u8,
) !void {
    const maybe_result = try runExternalTool(allocator, name, args);
    const result = maybe_result orelse return error.SkipZigTest;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.debug.print("{s} failed (exit {d}):\n{s}\n{s}\n", .{
                name,
                code,
                result.stdout,
                result.stderr,
            });
            return error.ExternalToolFailed;
        },
        else => return error.ExternalToolFailed,
    }
}

fn writeFixtureFile(io: Io, path: []const u8, bytes: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

fn findGeneralEntry(tree: *GeneralTree, path: []const u8) ?GeneralEntry {
    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const entry = tree.entryAt(index);
        if (std.mem.eql(u8, entry.path, path)) return entry;
    }
    return null;
}

fn readGeneralEntryAlloc(
    allocator: std.mem.Allocator,
    entry: GeneralEntry,
) ![]u8 {
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

fn expectGeneralXattr(entry: GeneralEntry, name: []const u8, value: []const u8) !void {
    for (entry.xattrs) |xattr| {
        if (!std.mem.eql(u8, xattr.name, name)) continue;
        try std.testing.expectEqualStrings(value, xattr.value);
        return;
    }
    std.debug.print("missing xattr {s} on {s}\n", .{ name, entry.path });
    return error.TestUnexpectedResult;
}

const stock_fixture_source = "test-ext4-general-src";
const stock_fixture_image = "test-ext4-general.img";
const stock_fixture_bytes: u64 = 16 * 1024 * 1024;
const stock_long_symlink_target = "../" ++ ("deep/" ** 20) ++ "target";

/// Builds a filesystem with `mke2fs`'s own ext4 defaults from a populated
/// directory, then adds through `debugfs` the things a directory cannot carry
/// without privileges: device nodes, a FIFO, fixed ownership and timestamps,
/// and both inline and block-backed extended attributes.
fn buildStockFixture(allocator: std.mem.Allocator, io: Io) !void {
    const cwd = Io.Dir.cwd();
    cwd.deleteTree(io, stock_fixture_source) catch {};
    cwd.deleteFile(io, stock_fixture_image) catch {};
    try cwd.createDirPath(io, stock_fixture_source ++ "/etc/rc.d");
    try cwd.createDirPath(io, stock_fixture_source ++ "/usr/bin");
    try cwd.createDirPath(io, stock_fixture_source ++ "/usr/lib");
    try cwd.createDirPath(io, stock_fixture_source ++ "/var/empty");
    try cwd.createDirPath(io, stock_fixture_source ++ "/dev");
    try writeFixtureFile(io, stock_fixture_source ++ "/etc/hostname", "zvmi-general\n");

    const tool_bytes = try allocator.alloc(u8, 9000);
    defer allocator.free(tool_bytes);
    for (tool_bytes, 0..) |*byte, index| byte.* = @truncate(index * 7 + 3);
    try writeFixtureFile(io, stock_fixture_source ++ "/usr/bin/tool", tool_bytes);
    try cwd.hardLink(
        stock_fixture_source ++ "/usr/bin/tool",
        cwd,
        stock_fixture_source ++ "/usr/bin/tool-alias",
        io,
        .{},
    );
    try cwd.symLink(io, "../bin/tool", stock_fixture_source ++ "/usr/lib/short", .{});
    try cwd.symLink(io, stock_long_symlink_target, stock_fixture_source ++ "/usr/lib/long", .{});

    const big_xattr_path = "test-ext4-general-xattr.bin";
    defer cwd.deleteFile(io, big_xattr_path) catch {};
    const big_xattr = try allocator.alloc(u8, 300);
    defer allocator.free(big_xattr);
    @memset(big_xattr, 'x');
    try writeFixtureFile(io, big_xattr_path, big_xattr);

    var size_text: [32]u8 = undefined;
    try runExternalToolChecked(allocator, "mke2fs", &.{
        "-q",
        "-t",
        "ext4",
        "-b",
        "4096",
        "-I",
        "256",
        "-d",
        stock_fixture_source,
        stock_fixture_image,
        // mke2fs counts in filesystem blocks, which `-b 4096` just set.
        try std.fmt.bufPrint(&size_text, "{d}", .{stock_fixture_bytes / 4096}),
    });

    const script_path = "test-ext4-general-debugfs.txt";
    defer cwd.deleteFile(io, script_path) catch {};
    try writeFixtureFile(io, script_path,
        \\cd /dev
        \\mknod console c 5 1
        \\mknod loop0 b 7 0
        \\mknod initctl p
        \\sif /dev/console mode 020600
        \\sif /dev/loop0 mode 060660
        \\sif /dev/initctl mode 010600
        \\sif /dev/console uid 0
        \\sif /dev/loop0 gid 6
        \\sif /etc/hostname mode 0100640
        \\sif /etc/hostname uid 1234
        \\sif /etc/hostname gid 5678
        \\sif /etc/hostname atime @1500000000
        \\sif /etc/hostname mtime @1400000000
        \\sif /etc/hostname ctime @1300000000
        \\ea_set /etc/hostname security.selinux system_u:object_r:etc_t:s0
        \\ea_set /etc/hostname user.small inline
        \\ea_set -f test-ext4-general-xattr.bin /usr/bin/tool user.big
        \\quit
        \\
    );
    try runExternalToolChecked(allocator, "debugfs", &.{
        "-w",
        "-f",
        script_path,
        stock_fixture_image,
    });
}

fn removeStockFixture(io: Io) void {
    const cwd = Io.Dir.cwd();
    cwd.deleteTree(io, stock_fixture_source) catch {};
    cwd.deleteFile(io, stock_fixture_image) catch {};
}

test "the general importer reads a stock mke2fs ext4 filesystem in full" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    defer removeStockFixture(io);
    buildStockFixture(allocator, io) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const file = try Io.Dir.cwd().openFile(io, stock_fixture_image, .{});
    defer file.close(io);
    var reader = try openGeneral(io, file, allocator, .{});
    defer reader.deinit();

    // Exactly the feature set the strict importer refuses, which is the whole
    // reason this path exists.
    try std.testing.expect(reader.inode_size == 256);
    try std.testing.expect(reader.feature_compat & feature_compat_has_journal != 0);
    try std.testing.expect(reader.feature_incompat & feature_incompat_64bit != 0);
    try std.testing.expect(reader.feature_incompat & feature_incompat_flex_bg != 0);
    const filesystem_length = @as(u64, reader.total_blocks) * reader.block_size;
    if (scanWriterCompatible(&reader, io, allocator, .{
        .expected_length = filesystem_length,
    })) |_| {
        return error.TestUnexpectedResult;
    } else |_| {
        // Which strict rule fires first is not the point; that no stock
        // filesystem can ever satisfy all of them is.
    }

    var tree = try scanReadable(&reader, io, allocator, .{
        .available_length = stock_fixture_bytes,
    });
    defer tree.deinit();

    try std.testing.expectEqual(SourceProfile.ext4_general_v1, tree.identity.profile);
    try std.testing.expect(tree.identity.has_journal);
    try std.testing.expectEqual(@as(u16, 256), tree.identity.inode_size);
    try std.testing.expectEqual(filesystem_length, tree.identity.filesystem_length);

    const hostname = findGeneralEntry(&tree, "etc/hostname").?;
    try std.testing.expectEqual(GeneralKind.file, hostname.kind);
    try std.testing.expectEqual(@as(u16, 0o640), hostname.mode);
    try std.testing.expectEqual(@as(u32, 1234), hostname.uid);
    try std.testing.expectEqual(@as(u32, 5678), hostname.gid);
    try std.testing.expectEqual(@as(i64, 1500000000), hostname.atime);
    try std.testing.expectEqual(@as(i64, 1400000000), hostname.mtime);
    try std.testing.expectEqual(@as(i64, 1300000000), hostname.ctime);
    const hostname_bytes = try readGeneralEntryAlloc(allocator, hostname);
    defer allocator.free(hostname_bytes);
    try std.testing.expectEqualStrings("zvmi-general\n", hostname_bytes);
    try expectGeneralXattr(hostname, "security.selinux", "system_u:object_r:etc_t:s0");
    try expectGeneralXattr(hostname, "user.small", "inline");

    const tool = findGeneralEntry(&tree, "usr/bin/tool").?;
    try std.testing.expectEqual(GeneralKind.file, tool.kind);
    try std.testing.expectEqual(@as(u64, 9000), tool.size);
    const tool_bytes = try readGeneralEntryAlloc(allocator, tool);
    defer allocator.free(tool_bytes);
    for (tool_bytes, 0..) |byte, index| {
        try std.testing.expectEqual(@as(u8, @truncate(index * 7 + 3)), byte);
    }
    // 300 bytes cannot fit beside a 256-byte inode, so this one proves the
    // external xattr block is read as well as the inline area.
    var expected_big: [300]u8 = undefined;
    @memset(&expected_big, 'x');
    try expectGeneralXattr(tool, "user.big", &expected_big);

    const alias = findGeneralEntry(&tree, "usr/bin/tool-alias").?;
    try std.testing.expectEqual(GeneralKind.hardlink, alias.kind);
    try std.testing.expectEqualStrings("usr/bin/tool", alias.hardlink_target);
    try std.testing.expectEqual(@as(?FileTreeView.ContentReader, null), alias.content);

    const short = findGeneralEntry(&tree, "usr/lib/short").?;
    try std.testing.expectEqual(GeneralKind.symlink, short.kind);
    const short_target = try readGeneralEntryAlloc(allocator, short);
    defer allocator.free(short_target);
    try std.testing.expectEqualStrings("../bin/tool", short_target);

    // Longer than 59 bytes, so ext4 stores it in a block rather than inline.
    const long = findGeneralEntry(&tree, "usr/lib/long").?;
    try std.testing.expectEqual(GeneralKind.symlink, long.kind);
    const long_target = try readGeneralEntryAlloc(allocator, long);
    defer allocator.free(long_target);
    try std.testing.expectEqualStrings(stock_long_symlink_target, long_target);

    const console = findGeneralEntry(&tree, "dev/console").?;
    try std.testing.expectEqual(GeneralKind.char_device, console.kind);
    try std.testing.expectEqual(@as(u32, 5), console.device.major);
    try std.testing.expectEqual(@as(u32, 1), console.device.minor);
    try std.testing.expectEqual(@as(u16, 0o600), console.mode);

    const loop0 = findGeneralEntry(&tree, "dev/loop0").?;
    try std.testing.expectEqual(GeneralKind.block_device, loop0.kind);
    try std.testing.expectEqual(@as(u32, 7), loop0.device.major);
    try std.testing.expectEqual(@as(u32, 0), loop0.device.minor);
    try std.testing.expectEqual(@as(u32, 6), loop0.gid);

    const initctl = findGeneralEntry(&tree, "dev/initctl").?;
    try std.testing.expectEqual(GeneralKind.fifo, initctl.kind);
    try std.testing.expectEqual(@as(u16, 0o600), initctl.mode);

    try std.testing.expectEqual(GeneralKind.directory, findGeneralEntry(&tree, "var/empty").?.kind);
    try std.testing.expectEqual(GeneralKind.directory, findGeneralEntry(&tree, "etc/rc.d").?.kind);

    // The hardlinked inode's bytes are billed once, not once per name.
    try std.testing.expectEqual(
        @as(u64, 9000 + "zvmi-general\n".len + "../bin/tool".len + stock_long_symlink_target.len),
        tree.content_bytes,
    );
}

test "the general importer names every feature it refuses" {
    const base_incompat = feature_incompat_extents | feature_incompat_filetype;
    const cases = [_]struct { compat: u32, incompat: u32, ro_compat: u32, expected: anyerror }{
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_bigalloc, .expected = error.UnsupportedBigallocFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_inline_data, .ro_compat = 0, .expected = error.UnsupportedInlineDataFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_casefold, .ro_compat = 0, .expected = error.UnsupportedCasefoldFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_encrypt, .ro_compat = 0, .expected = error.UnsupportedEncryptFeature },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_verity, .expected = error.UnsupportedVerityFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_mmp, .ro_compat = 0, .expected = error.UnsupportedMmpFeature },
        .{ .compat = feature_compat_fast_commit, .incompat = base_incompat, .ro_compat = 0, .expected = error.UnsupportedFastCommitFeature },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_quota, .expected = error.UnsupportedQuotaFeature },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_project, .expected = error.UnsupportedProjectFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_compression, .ro_compat = 0, .expected = error.UnsupportedCompressionFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_meta_bg, .ro_compat = 0, .expected = error.UnsupportedMetaBlockGroupFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_journal_dev, .ro_compat = 0, .expected = error.UnsupportedExternalJournalFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_ea_inode, .ro_compat = 0, .expected = error.UnsupportedXattrInodeFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_largedir, .ro_compat = 0, .expected = error.UnsupportedLargeDirFeature },
        .{ .compat = 0, .incompat = base_incompat | feature_incompat_dirdata, .ro_compat = 0, .expected = error.UnsupportedDirdataFeature },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_has_snapshot, .expected = error.UnsupportedSnapshotFeature },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_replica, .expected = error.UnsupportedReplicaFeature },
        // `orphan_present` says the orphan file still lists inodes to clean
        // up, which only a mount can do.
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_orphan_present, .expected = error.SourceHasOrphanInodes },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_shared_blocks, .expected = error.UnsupportedSharedBlocksFeature },
        .{ .compat = feature_compat_sparse_super2, .incompat = base_incompat, .ro_compat = 0, .expected = error.UnsupportedSparseSuper2Feature },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_gdt_csum, .expected = error.UnsupportedLegacyGroupChecksumFeature },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = feature_ro_compat_btree_dir, .expected = error.UnsupportedBtreeDirectoryFeature },
        .{ .compat = feature_compat_imagic_inodes, .incompat = base_incompat, .ro_compat = 0, .expected = error.UnsupportedImagicInodeFeature },
        .{ .compat = feature_compat_dir_prealloc, .incompat = base_incompat, .ro_compat = 0, .expected = error.UnsupportedDirectoryPreallocFeature },
        .{ .compat = feature_compat_stable_inodes, .incompat = base_incompat, .ro_compat = 0, .expected = error.UnsupportedStableInodesFeature },
        .{ .compat = 0, .incompat = feature_incompat_filetype, .ro_compat = 0, .expected = error.MissingExtentsFeature },
        .{ .compat = 0, .incompat = feature_incompat_extents, .ro_compat = 0, .expected = error.MissingFiletypeFeature },
        // An entirely unknown bit must still refuse rather than be ignored.
        .{ .compat = 0, .incompat = base_incompat | 0x8000_0000, .ro_compat = 0, .expected = error.UnsupportedFilesystemFeature },
        .{ .compat = 0x8000_0000, .incompat = base_incompat, .ro_compat = 0, .expected = error.UnsupportedFilesystemFeature },
        .{ .compat = 0, .incompat = base_incompat, .ro_compat = 0x8000_0000, .expected = error.UnsupportedFilesystemFeature },
    };
    for (cases) |case| {
        try std.testing.expectError(
            case.expected,
            classifyGeneralFeatures(case.compat, case.incompat, case.ro_compat),
        );
    }

    // The stock distro feature set is exactly what must be accepted.
    try classifyGeneralFeatures(
        feature_compat_has_journal | feature_compat_ext_attr | feature_compat_resize_inode |
            feature_compat_dir_index | feature_compat_orphan_file,
        base_incompat | feature_incompat_64bit | feature_incompat_flex_bg |
            feature_incompat_csum_seed,
        feature_ro_compat_sparse_super | feature_ro_compat_large_file |
            feature_ro_compat_huge_file | feature_ro_compat_dir_nlink |
            feature_ro_compat_extra_isize | feature_ro_compat_metadata_csum,
    );
}

fn writeGeneralFixture(io: Io, path: []const u8, length: u64) !Io.File {
    const attrs = [_]Xattr{.{ .name = "user.test", .value = "value" }};
    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o750, .uid = 1, .gid = 2 },
        .{ .path = "etc/file", .kind = .file, .mode = 0o640, .uid = 3, .gid = 4, .size = 4, .bytes = "test", .xattrs = &attrs },
        .{ .path = "etc/link", .kind = .symlink, .mode = 0o777, .uid = 0, .gid = 0, .size = 4, .bytes = "file" },
    });
    tree.bind();
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    errdefer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = length,
        .uuid = [_]u8{0x42} ** 16,
        .timestamp = 1_717_171_717,
    });
    return file;
}

test "the general importer accepts this module's own output and reports its profile" {
    const io = std.testing.io;
    const path = "test-ext4-general-self.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    const length = 8 * 1024 * 1024;
    const file = try writeGeneralFixture(io, path, length);
    defer file.close(io);

    var reader = try openGeneral(io, file, std.testing.allocator, .{});
    defer reader.deinit();

    var measured = limits_mod.Diagnostic{};
    var tree = try scanReadable(&reader, io, std.testing.allocator, .{
        .available_length = length,
        .diagnostic = &measured,
    });
    defer tree.deinit();

    try std.testing.expectEqual(SourceProfile.ext4_general_v1, tree.identity.profile);
    try std.testing.expect(!SourceProfile.ext4_general_v1.isByteReproducible());
    try std.testing.expect(SourceProfile.zvmi_ext4_v1.isByteReproducible());
    try std.testing.expectEqual(@as(usize, 3), tree.nodeCount());
    try std.testing.expectEqual(@as(u64, 3), measured.peaks.nodes);
    try std.testing.expectEqual(@as(u64, 1), measured.peaks.xattrs_per_node);
    try std.testing.expectEqual(@as(u64, 8), measured.peaks.path_bytes);
    try std.testing.expect(measured.peaks.scan_metadata_bytes != 0);
    try std.testing.expect(measured.exceeded == null);

    const entry = findGeneralEntry(&tree, "etc/file").?;
    try std.testing.expectEqual(@as(u16, 0o640), entry.mode);
    try expectGeneralXattr(entry, "user.test", "value");

    var breached = limits_mod.Diagnostic{};
    try std.testing.expectError(error.NodeLimitExceeded, scanReadable(&reader, io, std.testing.allocator, .{
        .available_length = length,
        .max_nodes = 1,
        .diagnostic = &breached,
    }));
    try std.testing.expectEqual(limits_mod.Limit.nodes, breached.exceeded.?.limit);
}

test "the general importer refuses a source the journal still owns" {
    const io = std.testing.io;
    const path = "test-ext4-general-dirty.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    const length = 8 * 1024 * 1024;
    const file = try writeGeneralFixture(io, path, length);
    defer file.close(io);

    // Clearing `s_state`'s clean bit is exactly what an unclean shutdown
    // leaves behind, and replaying the journal to recover it is out of scope.
    var state: [2]u8 = undefined;
    _ = try file.readPositionalAll(io, &state, superblock_offset + 0x3A);
    writeInt(u16, &state, readInt(u16, &state) & ~@as(u16, state_clean));
    try file.writePositionalAll(io, &state, superblock_offset + 0x3A);

    var reader = try openGeneral(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    try std.testing.expectError(
        error.SourceNotCleanlyUnmounted,
        scanReadable(&reader, io, std.testing.allocator, .{ .available_length = length }),
    );
}

test "the general importer refuses a source with orphan inodes pending" {
    const io = std.testing.io;
    const path = "test-ext4-general-orphan.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    const length = 8 * 1024 * 1024;
    const file = try writeGeneralFixture(io, path, length);
    defer file.close(io);

    // A non-empty orphan list means inodes were unlinked while still open, so
    // the on-disk tree is not the tree the guest last saw.
    var orphan: [4]u8 = undefined;
    writeInt(u32, &orphan, 11);
    try file.writePositionalAll(io, &orphan, superblock_offset + 0xE8);

    var reader = try openGeneral(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    try std.testing.expectError(
        error.SourceHasOrphanInodes,
        scanReadable(&reader, io, std.testing.allocator, .{ .available_length = length }),
    );
}

test "the writer emits hardlinks devices and FIFOs that fsck and the general importer accept" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-ext4-writer-special.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const attrs = [_]Xattr{.{ .name = "security.selinux", .value = "system_u:object_r:device_t:s0" }};
    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "dev", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "dev/console", .kind = .char_device, .mode = 0o600, .uid = 0, .gid = 0, .device = .{ .major = 5, .minor = 1 }, .xattrs = &attrs },
        .{ .path = "dev/initctl", .kind = .fifo, .mode = 0o600, .uid = 0, .gid = 0 },
        .{ .path = "dev/loop0", .kind = .block_device, .mode = 0o660, .uid = 0, .gid = 6, .device = .{ .major = 7, .minor = 300 } },
        .{ .path = "usr", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "usr/tool", .kind = .file, .mode = 0o755, .uid = 0, .gid = 0, .size = 5, .bytes = "hello" },
        .{ .path = "usr/alias", .kind = .hardlink, .mode = 0o755, .uid = 0, .gid = 0, .hardlink_target = "usr/tool" },
    });
    tree.bind();

    const length = 8 * 1024 * 1024;
    {
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        _ = try populate(io, file, allocator, &tree.view, .{
            .length = length,
            .uuid = [_]u8{0x5a} ** 16,
            .timestamp = 1_700_000_000,
        });
    }
    try expectE2fsckClean(path);

    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var reader = try openGeneral(io, file, allocator, .{});
    defer reader.deinit();
    var imported = try scanReadable(&reader, io, allocator, .{ .available_length = length });
    defer imported.deinit();

    const console = findGeneralEntry(&imported, "dev/console").?;
    try std.testing.expectEqual(GeneralKind.char_device, console.kind);
    try std.testing.expectEqual(@as(u32, 5), console.device.major);
    try std.testing.expectEqual(@as(u32, 1), console.device.minor);
    try expectGeneralXattr(console, "security.selinux", "system_u:object_r:device_t:s0");

    const loop0 = findGeneralEntry(&imported, "dev/loop0").?;
    try std.testing.expectEqual(GeneralKind.block_device, loop0.kind);
    try std.testing.expectEqual(@as(u32, 7), loop0.device.major);
    // Wider than eight bits, so this proves the Linux-native encoding is used.
    try std.testing.expectEqual(@as(u32, 300), loop0.device.minor);

    try std.testing.expectEqual(GeneralKind.fifo, findGeneralEntry(&imported, "dev/initctl").?.kind);

    // The importer walks names in sorted order and gives the content to the
    // first one it reaches, so `usr/alias` owns it and `usr/tool` links to it.
    const alias = findGeneralEntry(&imported, "usr/alias").?;
    const tool = findGeneralEntry(&imported, "usr/tool").?;
    try std.testing.expectEqual(GeneralKind.file, alias.kind);
    try std.testing.expectEqual(GeneralKind.hardlink, tool.kind);
    try std.testing.expectEqualStrings("usr/alias", tool.hardlink_target);
    const bytes = try readGeneralEntryAlloc(allocator, alias);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("hello", bytes);
}

test "the writer refuses hardlink and device entries it cannot represent" {
    const io = std.testing.io;
    const path = "test-ext4-writer-special-reject.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const Case = struct { entries: []const InMemoryEntry, expected: anyerror };
    const dangling = [_]InMemoryEntry{
        .{ .path = "a", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 1, .bytes = "x" },
        .{ .path = "b", .kind = .hardlink, .mode = 0o644, .uid = 0, .gid = 0, .hardlink_target = "missing" },
    };
    const to_directory = [_]InMemoryEntry{
        .{ .path = "d", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "b", .kind = .hardlink, .mode = 0o644, .uid = 0, .gid = 0, .hardlink_target = "d" },
    };
    const untargeted = [_]InMemoryEntry{
        .{ .path = "b", .kind = .hardlink, .mode = 0o644, .uid = 0, .gid = 0 },
    };
    const oversized_device = [_]InMemoryEntry{
        .{ .path = "n", .kind = .char_device, .mode = 0o600, .uid = 0, .gid = 0, .device = .{ .major = 0x1_0000, .minor = 0 } },
    };
    const cases = [_]Case{
        .{ .entries = &dangling, .expected = error.MissingHardlinkTarget },
        .{ .entries = &to_directory, .expected = error.UnsupportedHardlinkTarget },
        .{ .entries = &untargeted, .expected = error.MissingHardlinkTarget },
        .{ .entries = &oversized_device, .expected = error.InvalidDeviceEntry },
    };

    for (cases) |case| {
        var tree = InMemoryTree.init(case.entries);
        tree.bind();
        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        try std.testing.expectError(case.expected, populate(io, file, std.testing.allocator, &tree.view, .{
            .length = 8 * 1024 * 1024,
        }));
    }
}

test "the writer emits 256-byte inodes carrying the extra fields e2fsprogs reads" {
    const io = std.testing.io;
    const path = "test-ext4-inode256.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "file", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 5, .bytes = "hello" },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    const build_time: u32 = 1_700_000_000;
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = 8 * 1024 * 1024,
        .timestamp = build_time,
    });

    var sb: [superblock_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &sb, superblock_offset);
    try std.testing.expectEqual(@as(u16, 256), readInt(u16, sb[0x58..0x5A]));
    // `s_min_extra_isize` is a promise about every inode in the filesystem,
    // so it and the feature bit have to agree with what the inodes carry.
    try std.testing.expectEqual(@as(u16, 32), readInt(u16, sb[0x15C..0x15E]));
    try std.testing.expectEqual(@as(u16, 32), readInt(u16, sb[0x15E..0x160]));
    try std.testing.expect(readInt(u32, sb[0x64..0x68]) & feature_ro_compat_extra_isize != 0);

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    try std.testing.expectEqual(@as(u16, 256), reader.inode_size);

    const raw = try readRawInodeForPath(io, file, &reader, "/file");
    try std.testing.expectEqual(@as(u16, 32), readInt(u16, raw.bytes[128..130]));
    // The image is genuinely new, so its creation time is the build time.
    try std.testing.expectEqual(build_time, readInt(u32, raw.bytes[144..148]));
    try std.testing.expectEqual(@as(u32, 0), readInt(u32, raw.bytes[148..152]));
    // Left for the kernel: this writer never sets a version or a project id.
    try std.testing.expect(allZero(raw.bytes[152..160]));

    // The checksum is split across two non-adjacent halves on a wide inode
    // and e2fsck compares both, so a half-written one fails here.
    try expectE2fsckClean(path);
}

test "timestamps past 2038 survive a round trip through the extra epoch bits" {
    const io = std.testing.io;
    const path = "test-ext4-epoch.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // One value in each representable epoch, plus one before the 1970 origin,
    // because the seconds field is read back signed.
    const in_2049: i64 = 2_500_000_000;
    const in_2106: i64 = 4_300_000_000;
    const in_1960: i64 = -300_000_000;

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "future", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .atime = in_2049, .mtime = in_2106, .ctime = in_2049 },
        .{ .path = "past", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .atime = in_1960, .mtime = in_1960, .ctime = in_1960 },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{ .length = 8 * 1024 * 1024 });

    var reader = try openGeneral(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    var imported = try scanReadable(&reader, io, std.testing.allocator, .{
        .available_length = 8 * 1024 * 1024,
    });
    defer imported.deinit();

    const future = findGeneralEntry(&imported, "future").?;
    try std.testing.expectEqual(in_2049, future.atime);
    try std.testing.expectEqual(in_2106, future.mtime);
    try std.testing.expectEqual(in_2049, future.ctime);

    const past = findGeneralEntry(&imported, "past").?;
    try std.testing.expectEqual(in_1960, past.atime);
    try std.testing.expectEqual(in_1960, past.mtime);
    try std.testing.expectEqual(in_1960, past.ctime);

    try expectE2fsckClean(path);
}

test "creation times and sub-second precision survive a round trip" {
    const io = std.testing.io;
    const path = "test-ext4-crtime.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const build_time: u32 = 1_717_171_717;
    const created: i64 = 1_300_000_000;
    // Past 2038 as well, because the creation time is stored the same way
    // every other time is and has to carry its epoch bits alongside the
    // nanoseconds sharing the word.
    const created_late: i64 = 4_300_000_000;

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{
            .path = "captured",
            .kind = .file,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .atime = 1_500_000_000,
            .mtime = 1_400_000_000,
            .ctime = 1_450_000_000,
            .atime_nsec = 123_456_789,
            .mtime_nsec = 999_999_999,
            .ctime_nsec = 1,
            .crtime = created,
            .crtime_nsec = 500_000_000,
        },
        .{
            .path = "late",
            .kind = .file,
            .mode = 0o644,
            .uid = 0,
            .gid = 0,
            .crtime = created_late,
        },
        // Carries nothing, and so must come back exactly as it always did:
        // the build timestamp with no sub-second part at all.
        .{ .path = "fresh", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0 },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = 8 * 1024 * 1024,
        .timestamp = build_time,
    });

    var reader = try openGeneral(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    var imported = try scanReadable(&reader, io, std.testing.allocator, .{
        .available_length = 8 * 1024 * 1024,
    });
    defer imported.deinit();

    const captured = findGeneralEntry(&imported, "captured").?;
    try std.testing.expectEqual(@as(i64, 1_500_000_000), captured.atime);
    try std.testing.expectEqual(@as(i64, 1_400_000_000), captured.mtime);
    try std.testing.expectEqual(@as(i64, 1_450_000_000), captured.ctime);
    try std.testing.expectEqual(@as(u32, 123_456_789), captured.atime_nsec);
    try std.testing.expectEqual(@as(u32, 999_999_999), captured.mtime_nsec);
    try std.testing.expectEqual(@as(u32, 1), captured.ctime_nsec);
    try std.testing.expectEqual(@as(?i64, created), captured.crtime);
    try std.testing.expectEqual(@as(u32, 500_000_000), captured.crtime_nsec);

    const late = findGeneralEntry(&imported, "late").?;
    try std.testing.expectEqual(@as(?i64, created_late), late.crtime);
    try std.testing.expectEqual(@as(u32, 0), late.crtime_nsec);

    const fresh = findGeneralEntry(&imported, "fresh").?;
    try std.testing.expectEqual(@as(?i64, build_time), fresh.crtime);
    try std.testing.expectEqual(@as(u32, 0), fresh.atime_nsec);
    try std.testing.expectEqual(@as(u32, 0), fresh.mtime_nsec);
    try std.testing.expectEqual(@as(u32, 0), fresh.ctime_nsec);
    try std.testing.expectEqual(@as(u32, 0), fresh.crtime_nsec);

    try expectE2fsckClean(path);
}

test "a sub-second part that would overlap the epoch bits is refused" {
    const io = std.testing.io;
    const path = "test-ext4-nsec-refused.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // The `i_*_extra` word gives the nanoseconds thirty bits above the two
    // epoch bits. A billion still fits in thirty bits, so this is not caught
    // by truncation -- it has to be refused by name, or the value silently
    // becomes a legal nanosecond count with the wrong epoch beneath it.
    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "file", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .mtime_nsec = 1_000_000_000 },
    });
    tree.bind();

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try std.testing.expectError(
        error.TimestampOutOfRange,
        populate(io, file, std.testing.allocator, &tree.view, .{ .length = 8 * 1024 * 1024 }),
    );
}

test "the writer refuses a timestamp no inode can represent" {
    const io = std.testing.io;
    const path = "test-ext4-epoch-refused.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // 2446-05-10 is the last second the two epoch bits reach; 1901-12-13 is
    // the first. A value outside that window has to be named, not wrapped.
    for ([_]i64{ 15_032_385_536, -2_147_483_649 }) |unrepresentable| {
        var tree = InMemoryTree.init(&[_]InMemoryEntry{
            .{ .path = "file", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .mtime = unrepresentable },
        });
        tree.bind();

        const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
        defer file.close(io);
        try std.testing.expectError(
            error.TimestampOutOfRange,
            populate(io, file, std.testing.allocator, &tree.view, .{ .length = 8 * 1024 * 1024 }),
        );
    }
}

test "encodeInodeTime inverts decodeInodeTime across every epoch boundary" {
    const boundaries = [_]i64{
        -2_147_483_648, -1,            0,              1,
        2_147_483_647,  2_147_483_648, 4_294_967_295,  4_294_967_296,
        8_589_934_591,  8_589_934_592, 15_032_385_535,
    };
    for (boundaries) |value| {
        const encoded = try encodeInodeTime(value);
        try std.testing.expectEqual(value, decodeInodeTime(encoded.seconds, encoded.epoch));
    }
    try std.testing.expectError(error.TimestampOutOfRange, encodeInodeTime(15_032_385_536));
    try std.testing.expectError(error.TimestampOutOfRange, encodeInodeTime(-2_147_483_649));
}

test "strict writer-compatible scan rejects a tampered inode epoch" {
    const io = std.testing.io;
    const path = "test-ext4-strict-epoch.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "file", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = 4, .bytes = "test" },
    });
    tree.bind();
    const length = 8 * 1024 * 1024;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    _ = try populate(io, file, std.testing.allocator, &tree.view, .{
        .length = length,
        .uuid = [_]u8{0x44} ** 16,
        .timestamp = 1_717_171_717,
    });

    var reader = try open(io, file, std.testing.allocator, .{});
    defer reader.deinit();
    const inode_number = try reader.lookupPath(io, "/file");
    const group_index = (inode_number - 1) / reader.inodes_per_group;
    const index_in_group = (inode_number - 1) % reader.inodes_per_group;
    const inode_offset = reader.blockOffset(reader.groups[group_index].inode_table_block) +
        @as(u64, index_in_group) * reader.inode_size;
    var raw: [max_supported_reader_inode_size]u8 = undefined;
    const raw_inode = raw[0..reader.inode_size];
    _ = try file.readPositionalAll(io, raw_inode, inode_offset);

    // The seconds field is untouched, so the timestamp check that guards the
    // strict profile still sees the value it expects. Only the epoch moves --
    // 136 years, invisibly, because `ParsedInode` reads seconds alone.
    try std.testing.expectEqual(@as(u32, 0), readInt(u32, raw_inode[136..140]));
    writeInt(u32, raw_inode[136..140], 1);
    setInodeChecksum(raw_inode, reader.uuid, inode_number);
    try file.writePositionalAll(io, raw_inode, inode_offset);

    try std.testing.expectError(
        error.UnsupportedInodeMetadata,
        scanWriterCompatible(&reader, io, std.testing.allocator, .{
            .expected_length = length,
        }),
    );
}
