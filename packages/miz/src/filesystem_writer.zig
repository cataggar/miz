//! Shared filesystem writer/sizing dispatch for the two filesystem kinds
//! miz can actually write: ext4 and FAT32 (`layout.FilesystemKind`).
//!
//! Before this module, "which writer for this partition" was knowledge held
//! at each call site rather than in any model: `build_image.zig` and
//! `disk_assembly.zig` called `ext4.populate`/`fat32.format`/
//! `RootTree.populateFat32`/`RootTree.minimumFat32VolumeLength` directly,
//! keyed off a partition's *role* (ESP vs root) even though
//! `layout.FilesystemKind` (see `layout.zig`) exists precisely because role
//! and filesystem are independent choices. This module is the seam issue
//! #327 asks for: a caller states a `FilesystemKind` alongside a tagged
//! options value, and gets the matching backend, untouched -- its own
//! options, its own errors, no fallback to some other backend if the tag
//! and the kind disagree.
//!
//! FAT32 does not consume `tree_cursor.Cursor` the way `ext4.populate` does:
//! `RootTree.populateFat32` is a push walk over the tree's own node list,
//! because turning FAT32's writer into a puller over the neutral cursor
//! would be an invasive change to `fat32.zig` for no behavior change (issue
//! #327 asks for "one [RootTree] consumption path", and settles for keeping
//! the push walk as an implementation detail when a pull rewrite isn't
//! warranted). That push walk is unchanged; it is simply no longer called
//! directly by production code, only from the `.fat32` arm below. That is
//! the migration boundary: everything on this module's public side is
//! filesystem-neutral, and the asymmetry between "ext4 pulls a cursor" and
//! "FAT32 pushes over a tree" lives only inside it.
//!
//! Deliberately covers only what `layout.FilesystemKind` covers: ext4, FAT32,
//! and -- now that `xfs_writer.zig` emits a bounded, deterministic,
//! `xfs_repair`-clean image (issue #327) -- XFS. A kind must have a real writer
//! behind it before it earns an arm here; see `layout.FilesystemKind`'s own doc
//! comment.
//!
//! XFS differs from the other two in *where* it writes. `ext4.populate` streams
//! into the image file and `fat32.format` writes through an `Image` handle, and
//! -- as of the bounded-writer work on issue #327 -- `xfs_writer.populateImage`
//! does too: it emits every metadata/data/log block through a random-access
//! `xfs_writer.Output` sink with one positional `pwrite` each. The `.xfs` arm
//! builds an `Image`-backed sink whose base offset is the partition's own image
//! offset, so the writer's absolute block addresses land at the right place
//! with no partition-sized buffer ever allocated -- public XFS output costs a
//! fixed amount of memory no matter how large the partition is. The old buffer
//! entry point (`xfs_writer.populate`) survives only as a compatibility/test
//! wrapper. Free space and the tail past the last allocation group are never
//! written; on the freshly created `Image` the public path always hands us,
//! they read back as deterministic zero through the backend's sparse guarantee.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const layout = @import("layout.zig");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const xfs_writer = @import("xfs_writer.zig");
const xfs = @import("xfs.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const root_tree_mod = @import("root_tree.zig");
const RootTree = root_tree_mod.RootTree;

/// Re-exported so a caller need only import this module to name a kind.
pub const Kind = layout.FilesystemKind;

pub const DispatchError = error{
    /// The active tag of the options union did not match the requested
    /// `Kind`. Kept distinct from every backend's own error so a caller
    /// cannot mistake "the wrong options were paired with this kind" for a
    /// real write/size failure, and so nothing here ever falls back to
    /// treating mismatched options as whichever kind they happened to tag.
    FilesystemOptionsMismatch,
    /// `.ext4` or `.xfs` was requested with `tree = null`. Neither has a
    /// format step separate from populating a tree -- `ext4.populate` and
    /// `xfs_writer.populate` both format and fill in one call -- so there is
    /// nothing a `null` tree could mean for them, unlike FAT32, which formats
    /// independently of any tree and can be left empty for a caller (such as
    /// `bootconfig.populateEsp`) that writes its own files afterward without
    /// going through a `RootTree` at all.
    MissingTree,
};

/// Tagged so ext4 options can never be paired with a FAT32 write (or vice
/// versa) without the mismatch being caught explicitly
/// (`error.FilesystemOptionsMismatch`) rather than silently reinterpreted.
pub const FormatOptions = union(Kind) {
    /// ext4 has no separate format step: `PopulateOptions.offset`/`.length`
    /// already say where and how big, so formatting and populating are one
    /// call.
    ext4: ext4.PopulateOptions,
    fat32: struct {
        format: fat32.FormatOptions,
        /// Applied only when a tree is supplied to `formatAndPopulate`;
        /// ignored when the caller only wanted an empty, formatted volume.
        populate: root_tree_mod.FatPopulateOptions = .{},
    },
    /// Like ext4, XFS formats and populates in one pass and cannot be written
    /// without a tree. `format.offset` is interpreted the same way ext4's is
    /// -- the partition's byte offset in the image -- and the `.xfs` arm hands
    /// it straight to the writer as the base offset of an `Image`-backed
    /// positional sink, so no partition-sized buffer is involved.
    xfs: xfs_writer.PopulateOptions,
};

pub const FormatResult = union(Kind) {
    ext4: ext4.FilesystemInfo,
    fat32: void,
    /// XFS carries no post-write info a caller needs (no journal to report, no
    /// group geometry to echo back), so like FAT32 its result is empty. A
    /// caller reading `ext4`-only fields must switch on the tag rather than
    /// assume ext4.
    xfs: void,
};

/// Adapts an `Image` into an `xfs_writer.Output`: every block the writer emits
/// becomes one bounded `Image.pwrite` at an absolute image offset (the
/// partition's own offset plus the filesystem-relative block address the writer
/// computes). This is what lets public XFS output stay bounded -- the writer
/// never holds more than a single block, and the huge free space is simply
/// never written, reading back as zero through the freshly created image's
/// sparse guarantee.
///
/// `Image.pwrite` fails with a rich error union, but `xfs_writer.Output` may
/// only report `error.OutputWriteFailed`. The real error is stashed in
/// `failure` and re-raised by the arm, so a backend write failure surfaces with
/// its true cause rather than a flattened placeholder.
const ImageOutputSink = struct {
    image: *Image,
    io: Io,
    failure: ?Image.PwriteError = null,

    fn writeAtImpl(context: *anyopaque, offset: u64, bytes: []const u8) xfs_writer.Output.Error!void {
        const self: *ImageOutputSink = @ptrCast(@alignCast(context));
        self.image.pwrite(self.io, bytes, offset) catch |err| {
            self.failure = err;
            return error.OutputWriteFailed;
        };
    }

    fn output(self: *ImageOutputSink) xfs_writer.Output {
        return .{ .context = self, .write_at_fn = writeAtImpl };
    }
};

/// Formats `image`'s region for `kind` per `options`, and -- when `tree` is
/// given -- populates it from `tree`'s content.
///
/// Rejects `options` whose tag disagrees with `kind` instead of trusting
/// the caller to have kept them in sync (`error.FilesystemOptionsMismatch`),
/// and rejects `.ext4` with no tree (`error.MissingTree`) since ext4 cannot
/// be formatted without one. Neither error is a fallback to some other
/// behavior: both stop the write outright.
pub fn formatAndPopulate(
    io: Io,
    allocator: Allocator,
    image: *Image,
    tree: ?*RootTree,
    kind: Kind,
    options: FormatOptions,
) !FormatResult {
    if (std.meta.activeTag(options) != kind) return error.FilesystemOptionsMismatch;
    switch (options) {
        .ext4 => |ext4_options| {
            const source = tree orelse return error.MissingTree;
            const info = try ext4.populate(io, image.file, allocator, try source.cursor(), ext4_options);
            return .{ .ext4 = info };
        },
        .fat32 => |fat_options| {
            try fat32.format(image, io, fat_options.format);
            if (tree) |source| {
                var fs = try fat32.open(image, io, .{
                    .offset = fat_options.format.partition_offset,
                    .length = fat_options.format.partition_len,
                });
                try source.populateFat32(&fs, fat_options.populate);
            }
            return .{ .fat32 = {} };
        },
        .xfs => |xfs_options| {
            const source = tree orelse return error.MissingTree;
            // The writer emits through a positional `Image` sink whose base is
            // the partition's own image offset (carried in `format.offset`), so
            // every block lands at the right absolute position without a
            // partition-sized buffer. The whole plan is validated before the
            // first byte is written, preserving reject-before-write; the fresh
            // image the public path supplies reads back as zero everywhere the
            // writer does not write.
            var sink = ImageOutputSink{ .image = image, .io = io };
            xfs_writer.populateImage(allocator, sink.output(), try source.cursor(), xfs_options) catch |err| switch (err) {
                // Re-raise the backend's true error rather than the writer's
                // opaque `OutputWriteFailed` placeholder.
                error.OutputWriteFailed => return sink.failure.?,
                else => return err,
            };
            return .{ .xfs = {} };
        },
    }
}

/// Tagged sizing options, mirroring `FormatOptions`.
pub const SizeOptions = union(Kind) {
    ext4: ext4.PopulateOptions,
    fat32: struct {
        populate: root_tree_mod.FatPopulateOptions = .{},
        volume: fat32.VolumeLengthOptions = .{},
    },
    xfs: xfs_writer.PopulateOptions,
};

/// A backend-neutral sizing answer. `ext4_journal_block_count` is populated
/// only for `.ext4` -- reporting a journal size for a FAT32 volume, which
/// has no journal concept at all, would be a lie rather than an honest
/// zero.
pub const MinimumSize = struct {
    length: u64,
    ext4_journal_block_count: ?u32 = null,
};

/// The smallest length `formatAndPopulate` would accept for `tree` under
/// `kind`, with no headroom.
pub fn minimumLength(
    allocator: Allocator,
    tree: *RootTree,
    kind: Kind,
    options: SizeOptions,
) !MinimumSize {
    return minimumLengthAtLeast(allocator, tree, kind, options, 0);
}

/// The smallest length `formatAndPopulate` would accept for `tree` under
/// `kind` that is also no smaller than `floor` bytes.
///
/// ext4's own solver (`ext4.minimumPopulateLengthAtLeast`) re-walks
/// candidate geometries because whether a length is accepted is not
/// monotone in the length: a filesystem is a whole number of block groups,
/// and the first few megabytes past a group boundary can buy a group
/// header the filesystem cannot pay for (see that function's own doc
/// comment). FAT32's search (`fat32.minimumVolumeLength`, reached through
/// `RootTree.minimumFat32VolumeLength`) already only considers aligned
/// candidates and returns the smallest one that fits, and a larger aligned
/// FAT32 volume never holds less than a smaller one did, so raising that
/// answer to `floor` and re-aligning is enough -- no re-search is needed.
pub fn minimumLengthAtLeast(
    allocator: Allocator,
    tree: *RootTree,
    kind: Kind,
    options: SizeOptions,
    floor: u64,
) !MinimumSize {
    if (std.meta.activeTag(options) != kind) return error.FilesystemOptionsMismatch;
    switch (options) {
        .ext4 => |ext4_options| {
            const result = try ext4.minimumPopulateLengthAtLeast(allocator, try tree.cursor(), ext4_options, floor);
            return .{ .length = result.length, .ext4_journal_block_count = result.journal_blocks };
        },
        .fat32 => |fat_options| {
            const minimum = try tree.minimumFat32VolumeLength(fat_options.populate, fat_options.volume);
            return .{ .length = alignUpTo(@max(minimum, floor), fat_options.volume.alignment) };
        },
        .xfs => |xfs_options| {
            // The XFS writer accepts any length at or above its content
            // minimum -- it rounds a larger request down to whole allocation
            // groups and clamps a smaller one back up to the minimum -- so, as
            // with FAT32, raising the answer to `floor` needs no re-search.
            // XFS has no journal, so the journal block count stays null rather
            // than a dishonest zero.
            const minimum = try xfs_writer.minimumSize(allocator, try tree.cursor(), xfs_options);
            return .{ .length = @max(minimum, floor), .ext4_journal_block_count = null };
        },
    }
}

fn alignUpTo(value: u64, alignment: u64) u64 {
    if (alignment <= 1) return value;
    const remainder = value % alignment;
    if (remainder == 0) return value;
    return value + (alignment - remainder);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn makeEmptyMemoryTree(allocator: Allocator, io: Io) RootTree {
    return RootTree.initMemory(allocator, io, .{});
}

test "formatAndPopulate rejects options tagged for the wrong kind" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();

    var img = try Image.create(io, "test-filesystem-writer-mismatch.raw", .raw, 64 * 1024 * 1024, .{});
    defer img.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-mismatch.raw") catch {};

    const result = formatAndPopulate(io, testing.allocator, &img, &tree, .ext4, .{
        .fat32 = .{ .format = .{ .partition_offset = 0, .partition_len = 64 * 1024 * 1024 } },
    });
    try testing.expectError(error.FilesystemOptionsMismatch, result);

    const reverse = formatAndPopulate(io, testing.allocator, &img, &tree, .fat32, .{
        .ext4 = .{ .length = 64 * 1024 * 1024 },
    });
    try testing.expectError(error.FilesystemOptionsMismatch, reverse);
}

test "formatAndPopulate rejects an ext4 request with no tree" {
    const io = testing.io;
    var img = try Image.create(io, "test-filesystem-writer-missing-tree.raw", .raw, 64 * 1024 * 1024, .{});
    defer img.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-missing-tree.raw") catch {};

    const result = formatAndPopulate(io, testing.allocator, &img, null, .ext4, .{
        .ext4 = .{ .length = 64 * 1024 * 1024 },
    });
    try testing.expectError(error.MissingTree, result);
}

test "formatAndPopulate dispatches ext4 and matches ext4.populate directly" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();
    try tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    var dispatched = try Image.create(io, "test-filesystem-writer-ext4-dispatch.raw", .raw, 64 * 1024 * 1024, .{});
    defer dispatched.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-ext4-dispatch.raw") catch {};

    const options = ext4.PopulateOptions{ .length = 16 * 1024 * 1024 };
    const result = try formatAndPopulate(io, testing.allocator, &dispatched, &tree, .ext4, .{ .ext4 = options });
    try testing.expect(result == .ext4);

    var direct_tree = makeEmptyMemoryTree(testing.allocator, io);
    defer direct_tree.deinit();
    try direct_tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    var direct = try Image.create(io, "test-filesystem-writer-ext4-direct.raw", .raw, 64 * 1024 * 1024, .{});
    defer direct.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-ext4-direct.raw") catch {};
    _ = try ext4.populate(io, direct.file, testing.allocator, try direct_tree.cursor(), options);

    const dispatched_bytes = try testing.allocator.alloc(u8, 16 * 1024 * 1024);
    defer testing.allocator.free(dispatched_bytes);
    const direct_bytes = try testing.allocator.alloc(u8, 16 * 1024 * 1024);
    defer testing.allocator.free(direct_bytes);
    try testing.expectEqual(dispatched_bytes.len, try dispatched.pread(io, dispatched_bytes, 0));
    try testing.expectEqual(direct_bytes.len, try direct.pread(io, direct_bytes, 0));
    try testing.expectEqualSlices(u8, direct_bytes, dispatched_bytes);
}

test "formatAndPopulate dispatches fat32 and matches direct format+populateFat32" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();
    try tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    var dispatched = try Image.create(io, "test-filesystem-writer-fat32-dispatch.raw", .raw, 64 * 1024 * 1024, .{});
    defer dispatched.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-fat32-dispatch.raw") catch {};

    const format_options = fat32.FormatOptions{ .partition_offset = 0, .partition_len = 64 * 1024 * 1024 };
    _ = try formatAndPopulate(io, testing.allocator, &dispatched, &tree, .fat32, .{
        .fat32 = .{ .format = format_options, .populate = .{ .metadata_policy = .lossy_posix_metadata } },
    });

    var direct_tree = makeEmptyMemoryTree(testing.allocator, io);
    defer direct_tree.deinit();
    try direct_tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    var direct = try Image.create(io, "test-filesystem-writer-fat32-direct.raw", .raw, 64 * 1024 * 1024, .{});
    defer direct.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-fat32-direct.raw") catch {};
    try fat32.format(&direct, io, format_options);
    var direct_fs = try fat32.open(&direct, io, .{ .offset = 0, .length = 64 * 1024 * 1024 });
    try direct_tree.populateFat32(&direct_fs, .{ .metadata_policy = .lossy_posix_metadata });

    const dispatched_bytes = try testing.allocator.alloc(u8, 64 * 1024 * 1024);
    defer testing.allocator.free(dispatched_bytes);
    const direct_bytes = try testing.allocator.alloc(u8, 64 * 1024 * 1024);
    defer testing.allocator.free(direct_bytes);
    try testing.expectEqual(dispatched_bytes.len, try dispatched.pread(io, dispatched_bytes, 0));
    try testing.expectEqual(direct_bytes.len, try direct.pread(io, direct_bytes, 0));
    try testing.expectEqualSlices(u8, direct_bytes, dispatched_bytes);
}

test "formatAndPopulate formats an empty fat32 volume when no tree is given" {
    const io = testing.io;
    var img = try Image.create(io, "test-filesystem-writer-fat32-empty.raw", .raw, 64 * 1024 * 1024, .{});
    defer img.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-fat32-empty.raw") catch {};

    const result = try formatAndPopulate(io, testing.allocator, &img, null, .fat32, .{
        .fat32 = .{ .format = .{ .partition_offset = 0, .partition_len = 64 * 1024 * 1024 } },
    });
    try testing.expect(result == .fat32);

    var fs = try fat32.open(&img, io, .{ .offset = 0, .length = 64 * 1024 * 1024 });
    const entries = try fs.listDirAlloc(io, testing.allocator, "");
    defer fat32.freeDirEntries(testing.allocator, entries);
    try testing.expectEqual(@as(usize, 0), entries.len);
}

test "minimumLength rejects options tagged for the wrong kind" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();

    const result = minimumLength(testing.allocator, &tree, .ext4, .{
        .fat32 = .{},
    });
    try testing.expectError(error.FilesystemOptionsMismatch, result);
}

test "minimumLength dispatches ext4 and reports its journal block count" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();
    try tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    const options = ext4.PopulateOptions{ .length = 0, .journal = .{ .enabled = true } };
    const dispatched = try minimumLength(testing.allocator, &tree, .ext4, .{ .ext4 = options });

    var direct_tree = makeEmptyMemoryTree(testing.allocator, io);
    defer direct_tree.deinit();
    try direct_tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });
    const direct = try ext4.minimumPopulateLength(testing.allocator, try direct_tree.cursor(), options);

    try testing.expectEqual(direct.length, dispatched.length);
    try testing.expect(dispatched.ext4_journal_block_count != null);
    try testing.expectEqual(direct.journal_blocks, dispatched.ext4_journal_block_count.?);
}

test "minimumLength dispatches fat32 and never reports a journal block count" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();
    try tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    const dispatched = try minimumLength(testing.allocator, &tree, .fat32, .{
        .fat32 = .{ .populate = .{ .metadata_policy = .lossy_posix_metadata } },
    });

    var direct_tree = makeEmptyMemoryTree(testing.allocator, io);
    defer direct_tree.deinit();
    try direct_tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });
    const direct = try direct_tree.minimumFat32VolumeLength(.{ .metadata_policy = .lossy_posix_metadata }, .{});

    try testing.expectEqual(direct, dispatched.length);
    try testing.expectEqual(@as(?u32, null), dispatched.ext4_journal_block_count);
}

test "minimumLengthAtLeast raises a fat32 answer to the floor without re-searching lower" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();
    try tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    const base = try minimumLength(testing.allocator, &tree, .fat32, .{ .fat32 = .{} });
    const floor = base.length + 4 * 1024 * 1024;
    const raised = try minimumLengthAtLeast(testing.allocator, &tree, .fat32, .{ .fat32 = .{} }, floor);
    try testing.expect(raised.length >= floor);

    const below_floor = try minimumLengthAtLeast(testing.allocator, &tree, .fat32, .{ .fat32 = .{} }, 0);
    try testing.expectEqual(base.length, below_floor.length);
}

test "minimumLength dispatches xfs and never reports a journal block count" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();
    try tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    const options = xfs_writer.PopulateOptions{ .format = .{ .length = 0, .label = "rootfs" } };
    const dispatched = try minimumLength(testing.allocator, &tree, .xfs, .{ .xfs = options });

    var direct_tree = makeEmptyMemoryTree(testing.allocator, io);
    defer direct_tree.deinit();
    try direct_tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });
    const direct = try xfs_writer.minimumSize(testing.allocator, try direct_tree.cursor(), options);

    try testing.expectEqual(direct, dispatched.length);
    // XFS has no journal, so an honest sizing answer leaves the ext4-only
    // journal field null rather than a misleading zero.
    try testing.expectEqual(@as(?u32, null), dispatched.ext4_journal_block_count);
}

test "minimumLength rejects an xfs label longer than twelve bytes before sizing" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();

    const options = xfs_writer.PopulateOptions{ .format = .{ .length = 0, .label = "this-label-is-way-too-long" } };
    const result = minimumLength(testing.allocator, &tree, .xfs, .{ .xfs = options });
    try testing.expectError(error.LabelTooLong, result);
}

test "formatAndPopulate rejects xfs options tagged for another kind" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();

    var img = try Image.create(io, "test-filesystem-writer-xfs-mismatch.raw", .raw, 64 * 1024 * 1024, .{});
    defer img.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-xfs-mismatch.raw") catch {};

    const as_ext4 = formatAndPopulate(io, testing.allocator, &img, &tree, .xfs, .{
        .ext4 = .{ .length = 64 * 1024 * 1024 },
    });
    try testing.expectError(error.FilesystemOptionsMismatch, as_ext4);

    const as_xfs = formatAndPopulate(io, testing.allocator, &img, &tree, .ext4, .{
        .xfs = .{ .format = .{ .length = 64 * 1024 * 1024 } },
    });
    try testing.expectError(error.FilesystemOptionsMismatch, as_xfs);
}

test "formatAndPopulate rejects an xfs request with no tree" {
    const io = testing.io;
    var img = try Image.create(io, "test-filesystem-writer-xfs-missing-tree.raw", .raw, 64 * 1024 * 1024, .{});
    defer img.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-xfs-missing-tree.raw") catch {};

    const result = formatAndPopulate(io, testing.allocator, &img, null, .xfs, .{
        .xfs = .{ .format = .{ .length = 64 * 1024 * 1024 } },
    });
    try testing.expectError(error.MissingTree, result);
}

test "formatAndPopulate dispatches xfs and the reader reads it back at a partition offset" {
    const io = testing.io;
    var tree = makeEmptyMemoryTree(testing.allocator, io);
    defer tree.deinit();
    try tree.putFileBytes("hello.txt", "hi\n", .{ .mode = 0o644 });

    // Size the partition through the neutral seam, then place it at a non-zero
    // offset so the `.xfs` arm's positional `Image` sink (base = partition
    // offset) and the reader's matching `openFileAt` are both exercised.
    const size_opts = xfs_writer.PopulateOptions{ .format = .{ .length = 0, .label = "rootfs" } };
    const min = try minimumLength(testing.allocator, &tree, .xfs, .{ .xfs = size_opts });

    const partition_offset: u64 = 1024 * 1024;
    var img = try Image.create(io, "test-filesystem-writer-xfs-dispatch.raw", .raw, partition_offset + min.length, .{});
    defer img.close(io);
    defer Io.Dir.cwd().deleteFile(io, "test-filesystem-writer-xfs-dispatch.raw") catch {};

    const result = try formatAndPopulate(io, testing.allocator, &img, &tree, .xfs, .{
        .xfs = .{ .format = .{ .offset = partition_offset, .length = min.length, .label = "rootfs" } },
    });
    try testing.expect(result == .xfs);

    var reader = try xfs.Reader.openFileAt(testing.allocator, io, img.file, partition_offset);
    defer reader.close(io);
    var rtree = try xfs.scanReadable(&reader, io, testing.allocator, .{ .available_length = min.length });
    defer rtree.deinit();

    try testing.expectEqualSlices(u8, "rootfs\x00\x00\x00\x00\x00\x00", &rtree.identity.label);

    var found = false;
    var index: usize = 0;
    while (index < rtree.nodeCount()) : (index += 1) {
        const entry = rtree.entryAt(index);
        if (!std.mem.eql(u8, entry.path, "hello.txt")) continue;
        found = true;
        try testing.expectEqual(xfs.Kind.file, entry.kind);
        try testing.expectEqual(@as(u64, 3), entry.size);
        const content = entry.content orelse return error.MissingContent;
        var buf: [3]u8 = undefined;
        var done: usize = 0;
        while (done < buf.len) {
            const got = try content.readAt(buf[done..], done);
            try testing.expect(got != 0);
            done += got;
        }
        try testing.expectEqualStrings("hi\n", &buf);
    }
    try testing.expect(found);
}
