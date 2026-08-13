//! Shared filesystem writer/sizing dispatch for the two filesystem kinds
//! zvmi can actually write: ext4 and FAT32 (`layout.FilesystemKind`).
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
//! Deliberately covers only what `layout.FilesystemKind` covers. There is no
//! XFS (or other) arm here, and none should be added without a real writer
//! behind it -- see `layout.FilesystemKind`'s own doc comment.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const layout = @import("layout.zig");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
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
    /// `.ext4` was requested with `tree = null`. ext4 has no format step
    /// separate from populating a tree -- `ext4.populate` does both in one
    /// call -- so there is nothing a `null` tree could mean for it, unlike
    /// FAT32, which formats independently of any tree and can be left
    /// empty for a caller (such as `bootconfig.populateEsp`) that writes
    /// its own files afterward without going through a `RootTree` at all.
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
};

pub const FormatResult = union(Kind) {
    ext4: ext4.FilesystemInfo,
    fat32: void,
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
    }
}

/// Tagged sizing options, mirroring `FormatOptions`.
pub const SizeOptions = union(Kind) {
    ext4: ext4.PopulateOptions,
    fat32: struct {
        populate: root_tree_mod.FatPopulateOptions = .{},
        volume: fat32.VolumeLengthOptions = .{},
    },
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
