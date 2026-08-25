//! Filesystem-neutral pull cursor over a tree of files, directories, and
//! special nodes -- the shape a writer drains, not the shape any particular
//! filesystem happens to store.
//!
//! This lives outside `ext4.zig` and `root_tree.zig` on purpose: `ext4.zig`
//! is where the type was born (as `FileTreeView`, still aliased there for
//! source compatibility) but it is not an ext4 concept -- it carries exactly
//! the metadata `ext4.populate` needs to write an inode (path, kind,
//! mode/uid/gid, device numbers, hardlink target, size, a content reader,
//! and xattrs) plus the POSIX timestamps a real source tree carries, and
//! nothing that is specific to ext4's own on-disk representation. A future
//! writer for another filesystem drains the same shape.
//!
//! What this type deliberately does *not* carry is root-directory metadata:
//! the root inode of a filesystem is not an entry a cursor yields, so a
//! caller that needs the root's mode/ownership/timestamps carries them
//! separately (see `root_tree.RootMetadata` and `ext4.PopulateOptions`'s
//! `root_*` fields). That split is intentional, not an oversight: silently
//! folding root metadata into the entry stream would give it no distinct
//! home and no way to be validated on its own.
const std = @import("std");

/// Every guest-visible node kind a cursor can yield. `hardlink` is not an
/// on-disk inode type in any filesystem this models: it is how a second or
/// later directory entry pointing at an already-emitted inode is
/// represented, so a consumer neither duplicates the content nor loses the
/// fact that the two names share storage.
pub const Kind = enum(u8) {
    directory,
    file,
    symlink,
    hardlink,
    block_device,
    char_device,
    fifo,
};

/// Device major/minor numbers, meaningful only for `block_device` and
/// `char_device` entries.
pub const DeviceNumbers = struct {
    major: u32 = 0,
    minor: u32 = 0,
};

/// A logical range that reads as zero and has no initialized data blocks.
/// Ranges are expressed in filesystem blocks and may be omitted when a file
/// is fully dense.
pub const SparseExtent = struct {
    logical_block: u32,
    block_count: u32,
};

/// A borrowed extended attribute, valid only for as long as the entry that
/// yielded it.
pub const Xattr = struct {
    name: []const u8,
    value: []const u8,
};

/// An owned copy of an extended attribute, for a consumer that must outlive
/// the entry it was read from.
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

/// Small, self-contained tree-population interface for any writer to drain.
/// `populate()`-style consumers reset the cursor once, consume every yielded
/// entry, sort them by path depth/name, and then write the full filesystem
/// image in one pass. The root directory is implicit; entries must use
/// relative paths like `boot/kernel` rather than `/boot/kernel`.
pub const Cursor = struct {
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
        /// leaves these zero, which is what writers derived from this
        /// interface emitted for every inode before these existed.
        atime_nsec: u32 = 0,
        mtime_nsec: u32 = 0,
        ctime_nsec: u32 = 0,
        /// The node's creation time. Null means the source had none to give,
        /// and a consumer falls back to its own image-wide timestamp, which
        /// is the honest answer for a node a build is genuinely creating.
        crtime: ?i64 = null,
        crtime_nsec: u32 = 0,
        sparse_extents: []const SparseExtent = &.{},
    };

    pub fn reset(self: *Cursor) void {
        self.reset_fn(self.ctx);
    }

    pub fn next(self: *Cursor) IteratorError!?Entry {
        return self.next_fn(self.ctx);
    }
};
