//! dm-verity hash-tree generation helpers.
//!
//! This module implements the format-1 (`salt || block`) SHA-256 Merkle tree
//! layout used by modern dm-verity deployments. The emitted hash area omits the
//! optional verity superblock (`superblock=0`) and stores hash blocks in the
//! on-disk order the kernel's dm-verity target and `veritysetup` actually use:
//! the level closest to the root is stored *first* (right at `hash-offset=`),
//! and the leaf level (one hash per data block) is stored *last*. This
//! matches `hash_levels()`/`VERITY_create_or_verify_hash()` in cryptsetup's
//! `lib/verity/verity_hash.c`, which assigns on-disk positions to levels
//! starting from the root-adjacent level and working down to the leaf level.
//! See `buildTreeLevels`/`writeLevelsRootFirst` below.

const std = @import("std");
const Io = std.Io;

pub const default_data_block_size: u32 = 4096;
pub const default_hash_block_size: u32 = 4096;
pub const digest_size: usize = std.crypto.hash.sha2.Sha256.digest_length;
pub const salt_size: usize = digest_size;
pub const format_version: u32 = 1;
pub const hash_algorithm = "sha256";

pub const Info = struct {
    format: u32 = format_version,
    hashAlgorithm: []const u8 = hash_algorithm,
    dataBlockSize: u32,
    hashBlockSize: u32,
    dataBlocks: u64,
    hashOffset: u64,
    hashTreeSize: u64,
    salt: [salt_size]u8,
    rootHash: [digest_size]u8,

    pub fn formatRootHash(self: Info, buf: *[digest_size * 2]u8) []const u8 {
        buf.* = std.fmt.bytesToHex(self.rootHash, .lower);
        return buf;
    }

    pub fn formatSalt(self: Info, buf: *[salt_size * 2]u8) []const u8 {
        buf.* = std.fmt.bytesToHex(self.salt, .lower);
        return buf;
    }
};

pub const GeneratedTree = struct {
    info: Info,
    tree_bytes: []u8,

    pub fn deinit(self: *GeneratedTree, allocator: std.mem.Allocator) void {
        allocator.free(self.tree_bytes);
        self.* = undefined;
    }
};

pub const PartitionLayout = struct {
    data_size: u64,
    hash_offset: u64,
    hash_tree_size: u64,
    data_blocks: u64,
};

pub const GenerateOptions = struct {
    data_size: u64,
    data_block_size: u32 = default_data_block_size,
    hash_block_size: u32 = default_hash_block_size,
    salt: [salt_size]u8,
};

pub const WriteOptions = struct {
    device_offset: u64 = 0,
    data_size: u64,
    hash_offset: u64,
    data_block_size: u32 = default_data_block_size,
    hash_block_size: u32 = default_hash_block_size,
    salt: [salt_size]u8,
};

pub const GenerateError = std.mem.Allocator.Error || error{
    InvalidBlockSize,
    InvalidDataSize,
    NotEnoughSpace,
};

pub const WriteError = GenerateError || Io.File.ReadPositionalError || Io.File.WritePositionalError || error{
    HashAreaOverlapsData,
    ShortRead,
};

pub fn hashTreeSizeBytes(data_size: u64, data_block_size: u32, hash_block_size: u32) GenerateError!u64 {
    validateSizes(data_size, data_block_size, hash_block_size) catch |err| switch (err) {
        error.InvalidBlockSize => return error.InvalidBlockSize,
        error.InvalidDataSize => return error.InvalidDataSize,
        else => return err,
    };
    const data_blocks = data_size / data_block_size;
    return hashTreeBlockCount(data_blocks, hash_block_size) * hash_block_size;
}

pub fn splitPartition(total_bytes: u64, data_block_size: u32, hash_block_size: u32) GenerateError!PartitionLayout {
    if (data_block_size == 0 or hash_block_size == 0) return error.InvalidBlockSize;
    if (hash_block_size % digest_size != 0) return error.InvalidBlockSize;

    const max_data_blocks = total_bytes / data_block_size;
    if (max_data_blocks == 0) return error.NotEnoughSpace;

    var lo: u64 = 1;
    var hi: u64 = max_data_blocks;
    var best: u64 = 0;

    while (lo <= hi) {
        const mid = lo + (hi - lo) / 2;
        const tree_blocks = hashTreeBlockCount(mid, hash_block_size);
        const data_bytes = std.math.mul(u64, mid, data_block_size) catch {
            hi = mid - 1;
            continue;
        };
        const tree_bytes = std.math.mul(u64, tree_blocks, hash_block_size) catch {
            hi = mid - 1;
            continue;
        };
        const used_bytes = std.math.add(u64, data_bytes, tree_bytes) catch {
            hi = mid - 1;
            continue;
        };
        if (used_bytes <= total_bytes) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }

    if (best == 0) return error.NotEnoughSpace;

    const hash_tree_size = hashTreeBlockCount(best, hash_block_size) * hash_block_size;
    return .{
        .data_size = best * data_block_size,
        .hash_offset = best * data_block_size,
        .hash_tree_size = hash_tree_size,
        .data_blocks = best,
    };
}

test "splitPartition handles maximum-size inputs without arithmetic overflow" {
    const split = try splitPartition(std.math.maxInt(u64), default_data_block_size, default_hash_block_size);
    const used = try std.math.add(u64, split.data_size, split.hash_tree_size);
    try std.testing.expect(used <= std.math.maxInt(u64));
}

pub fn generateFromBytes(allocator: std.mem.Allocator, data: []const u8, options: GenerateOptions) GenerateError!GeneratedTree {
    try validateSizes(options.data_size, options.data_block_size, options.hash_block_size);
    if (data.len != options.data_size) return error.InvalidDataSize;

    const data_blocks = options.data_size / options.data_block_size;
    const leaf_level = try buildLeafLevelFromBytes(allocator, data, options);
    const levels = try buildTreeLevels(allocator, leaf_level, options.hash_block_size, options.salt);
    defer {
        for (levels) |level| allocator.free(level);
        allocator.free(levels);
    }

    const tree_bytes = try writeLevelsRootFirst(allocator, levels);
    errdefer allocator.free(tree_bytes);

    var root_hash: [digest_size]u8 = undefined;
    const root_level = levels[levels.len - 1];
    hashBlock(root_level[0..options.hash_block_size], options.salt, &root_hash);

    return .{
        .info = .{
            .dataBlockSize = options.data_block_size,
            .hashBlockSize = options.hash_block_size,
            .dataBlocks = data_blocks,
            .hashOffset = 0,
            .hashTreeSize = tree_bytes.len,
            .salt = options.salt,
            .rootHash = root_hash,
        },
        .tree_bytes = tree_bytes,
    };
}

pub fn generateAndWrite(io: Io, file: Io.File, allocator: std.mem.Allocator, options: WriteOptions) WriteError!Info {
    try validateSizes(options.data_size, options.data_block_size, options.hash_block_size);
    if (options.hash_offset < options.data_size) return error.HashAreaOverlapsData;

    const data_blocks = options.data_size / options.data_block_size;
    const leaf_level = try buildLeafLevelFromFile(allocator, io, file, options);
    const levels = try buildTreeLevels(allocator, leaf_level, options.hash_block_size, options.salt);
    defer {
        for (levels) |level| allocator.free(level);
        allocator.free(levels);
    }

    var root_hash: [digest_size]u8 = undefined;
    const root_level = levels[levels.len - 1];
    hashBlock(root_level[0..options.hash_block_size], options.salt, &root_hash);

    // On-disk order is root-adjacent level first, leaf level last (see the
    // module doc comment), i.e. the reverse of `levels`, which is ordered
    // leaf-first/root-last since that's the order each level can be built in.
    var write_offset = options.device_offset + options.hash_offset;
    var index = levels.len;
    while (index > 0) {
        index -= 1;
        try file.writePositionalAll(io, levels[index], write_offset);
        write_offset += levels[index].len;
    }
    const hash_tree_size = write_offset - (options.device_offset + options.hash_offset);

    return .{
        .dataBlockSize = options.data_block_size,
        .hashBlockSize = options.hash_block_size,
        .dataBlocks = data_blocks,
        .hashOffset = options.hash_offset,
        .hashTreeSize = hash_tree_size,
        .salt = options.salt,
        .rootHash = root_hash,
    };
}

/// Builds every level of the Merkle tree above `leaf_level` (which must
/// already be caller-owned and is taken over by this function), returning an
/// owned slice of owned level buffers ordered leaf-first, root-last (i.e. the
/// order each level must be *built* in, since each parent level is derived
/// from the previous one). `writeLevelsRootFirst` (or the direct file-write
/// loop in `generateAndWrite`) is responsible for reversing this into the
/// actual on-disk order.
fn buildTreeLevels(
    allocator: std.mem.Allocator,
    leaf_level: []u8,
    hash_block_size: u32,
    salt: [salt_size]u8,
) std.mem.Allocator.Error![][]u8 {
    var levels = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (levels.items) |level| allocator.free(level);
        levels.deinit();
    }

    try levels.append(leaf_level);
    var current = leaf_level;
    while (current.len != hash_block_size) {
        const next = try buildParentLevel(allocator, current, hash_block_size, salt);
        try levels.append(next);
        current = next;
    }

    return levels.toOwnedSlice();
}

/// Concatenates `levels` (ordered leaf-first, root-last, as returned by
/// `buildTreeLevels`) into a single buffer in the on-disk order dm-verity
/// actually expects: root-adjacent level first, leaf level last.
fn writeLevelsRootFirst(allocator: std.mem.Allocator, levels: []const []const u8) std.mem.Allocator.Error![]u8 {
    var total_len: usize = 0;
    for (levels) |level| total_len += level.len;

    const out = try allocator.alloc(u8, total_len);
    errdefer allocator.free(out);

    var offset: usize = 0;
    var index = levels.len;
    while (index > 0) {
        index -= 1;
        @memcpy(out[offset..][0..levels[index].len], levels[index]);
        offset += levels[index].len;
    }

    return out;
}

pub fn hashTreeBlockCount(data_blocks: u64, hash_block_size: u32) u64 {
    std.debug.assert(data_blocks > 0);
    const per_block = hashesPerBlock(hash_block_size);
    var blocks = data_blocks;
    var total: u64 = 0;
    while (true) {
        blocks = std.math.divCeil(u64, blocks, per_block) catch unreachable;
        total += blocks;
        if (blocks == 1) break;
    }
    return total;
}

fn validateSizes(data_size: u64, data_block_size: u32, hash_block_size: u32) GenerateError!void {
    if (data_block_size == 0 or hash_block_size == 0) return error.InvalidBlockSize;
    if (data_size == 0 or data_size % data_block_size != 0) return error.InvalidDataSize;
    if (hash_block_size % digest_size != 0) return error.InvalidBlockSize;
}

fn hashesPerBlock(hash_block_size: u32) u64 {
    return hash_block_size / digest_size;
}

fn buildLeafLevelFromBytes(
    allocator: std.mem.Allocator,
    data: []const u8,
    options: GenerateOptions,
) std.mem.Allocator.Error![]u8 {
    const data_blocks = options.data_size / options.data_block_size;
    const level_blocks = hashTreeBlockCountOneLevel(data_blocks, options.hash_block_size);
    const level_len: usize = @intCast(level_blocks * options.hash_block_size);
    const out = try allocator.alloc(u8, level_len);
    @memset(out, 0);

    const block_len: usize = @intCast(options.data_block_size);
    const per_block = hashesPerBlock(options.hash_block_size);

    var block_index: u64 = 0;
    while (block_index < data_blocks) : (block_index += 1) {
        const data_offset: usize = @intCast(block_index * options.data_block_size);
        var digest: [digest_size]u8 = undefined;
        hashBlock(data[data_offset .. data_offset + block_len], options.salt, &digest);

        const hash_block_index = block_index / per_block;
        const digest_index = block_index % per_block;
        const dst_offset: usize = @intCast(hash_block_index * options.hash_block_size + digest_index * digest_size);
        std.mem.copyForwards(u8, out[dst_offset .. dst_offset + digest_size], &digest);
    }

    return out;
}

fn buildLeafLevelFromFile(
    allocator: std.mem.Allocator,
    io: Io,
    file: Io.File,
    options: WriteOptions,
) WriteError![]u8 {
    const data_blocks = options.data_size / options.data_block_size;
    const level_blocks = hashTreeBlockCountOneLevel(data_blocks, options.hash_block_size);
    const level_len: usize = @intCast(level_blocks * options.hash_block_size);
    const out = try allocator.alloc(u8, level_len);
    errdefer allocator.free(out);
    @memset(out, 0);

    const block_len: usize = @intCast(options.data_block_size);
    const per_block = hashesPerBlock(options.hash_block_size);
    const block = try allocator.alloc(u8, block_len);
    defer allocator.free(block);

    var block_index: u64 = 0;
    while (block_index < data_blocks) : (block_index += 1) {
        const got = try file.readPositionalAll(io, block, options.device_offset + block_index * options.data_block_size);
        if (got != block.len) return error.ShortRead;

        var digest: [digest_size]u8 = undefined;
        hashBlock(block, options.salt, &digest);

        const hash_block_index = block_index / per_block;
        const digest_index = block_index % per_block;
        const dst_offset: usize = @intCast(hash_block_index * options.hash_block_size + digest_index * digest_size);
        std.mem.copyForwards(u8, out[dst_offset .. dst_offset + digest_size], &digest);
    }

    return out;
}

fn buildParentLevel(
    allocator: std.mem.Allocator,
    child_level: []const u8,
    hash_block_size: u32,
    salt: [salt_size]u8,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(child_level.len % hash_block_size == 0);
    const child_blocks = child_level.len / hash_block_size;
    const level_blocks = hashTreeBlockCountOneLevel(child_blocks, hash_block_size);
    const level_len: usize = @intCast(level_blocks * hash_block_size);
    const out = try allocator.alloc(u8, level_len);
    @memset(out, 0);

    const per_block = hashesPerBlock(hash_block_size);
    const block_len: usize = @intCast(hash_block_size);

    var child_index: u64 = 0;
    while (child_index < child_blocks) : (child_index += 1) {
        const child_offset: usize = @intCast(child_index * hash_block_size);
        var digest: [digest_size]u8 = undefined;
        hashBlock(child_level[child_offset .. child_offset + block_len], salt, &digest);

        const hash_block_index = child_index / per_block;
        const digest_index = child_index % per_block;
        const dst_offset: usize = @intCast(hash_block_index * hash_block_size + digest_index * digest_size);
        std.mem.copyForwards(u8, out[dst_offset .. dst_offset + digest_size], &digest);
    }

    return out;
}

fn hashTreeBlockCountOneLevel(child_blocks: u64, hash_block_size: u32) u64 {
    return std.math.divCeil(u64, child_blocks, hashesPerBlock(hash_block_size)) catch unreachable;
}

fn hashBlock(block: []const u8, salt: [salt_size]u8, out: *[digest_size]u8) void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&salt);
    hasher.update(block);
    hasher.final(out);
}

test "generateFromBytes builds a format-1 SHA-256 dm-verity tree" {
    var data = try std.testing.allocator.alloc(u8, default_data_block_size * 2);
    defer std.testing.allocator.free(data);
    @memset(data[0..default_data_block_size], 0x00);
    @memset(data[default_data_block_size..], 0xFF);

    var salt: [salt_size]u8 = undefined;
    for (&salt, 0..) |*byte, index| byte.* = @intCast(index);

    var generated = try generateFromBytes(std.testing.allocator, data, .{
        .data_size = data.len,
        .salt = salt,
    });
    defer generated.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 2), generated.info.dataBlocks);
    try std.testing.expectEqual(@as(u64, default_hash_block_size), generated.info.hashTreeSize);
    try std.testing.expectEqual(@as(usize, default_hash_block_size), generated.tree_bytes.len);

    var expected_tree = try std.testing.allocator.alloc(u8, default_hash_block_size);
    defer std.testing.allocator.free(expected_tree);
    @memset(expected_tree, 0);

    var leaf0: [digest_size]u8 = undefined;
    var leaf1: [digest_size]u8 = undefined;
    hashBlock(data[0..default_data_block_size], salt, &leaf0);
    hashBlock(data[default_data_block_size .. default_data_block_size * 2], salt, &leaf1);
    std.mem.copyForwards(u8, expected_tree[0..digest_size], &leaf0);
    std.mem.copyForwards(u8, expected_tree[digest_size .. digest_size * 2], &leaf1);

    try std.testing.expectEqualSlices(u8, expected_tree, generated.tree_bytes);

    var expected_root: [digest_size]u8 = undefined;
    hashBlock(expected_tree, salt, &expected_root);
    try std.testing.expectEqualSlices(u8, &expected_root, &generated.info.rootHash);
}

test "splitPartition reserves appended hash blocks after the protected data area" {
    const total = 10 * 1024 * 1024;
    const layout = try splitPartition(total, default_data_block_size, default_hash_block_size);
    try std.testing.expect(layout.data_size < total);
    try std.testing.expectEqual(layout.data_size, layout.hash_offset);
    try std.testing.expect(layout.hash_tree_size > 0);
    try std.testing.expect(layout.data_size + layout.hash_tree_size <= total);
}

test "generateFromBytes stores a multi-level tree root-first, leaf-last on disk" {
    // Regression test for issue #77's real-boot investigation: with a tiny
    // hash_block_size (64 bytes = 2 sha256 digests/block) and 3 data blocks,
    // the leaf level needs 2 hash blocks (3 leaf hashes, 2 per block) and so
    // requires a parent/root level combining them into a single block --
    // the smallest case that can distinguish "leaf-first" from "root-first"
    // on-disk ordering. Real dm-verity (see cryptsetup's
    // `lib/verity/verity_hash.c` `hash_levels()`/`VERITY_create_or_verify_hash()`)
    // stores the root-adjacent level first (right at the hash area's start)
    // and the leaf level last.
    const data_block_size: u32 = 16;
    const hash_block_size: u32 = 64;

    var data: [data_block_size * 3]u8 = undefined;
    for (&data, 0..) |*byte, index| byte.* = @intCast(index);

    var salt: [salt_size]u8 = undefined;
    for (&salt, 0..) |*byte, index| byte.* = @intCast(index + 100);

    var generated = try generateFromBytes(std.testing.allocator, &data, .{
        .data_size = data.len,
        .data_block_size = data_block_size,
        .hash_block_size = hash_block_size,
        .salt = salt,
    });
    defer generated.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 3), generated.info.dataBlocks);
    // leaf level: ceil(3/2) = 2 hash blocks; root level: ceil(2/2) = 1 hash block.
    try std.testing.expectEqual(@as(u64, 3 * hash_block_size), generated.info.hashTreeSize);

    var leaf0: [digest_size]u8 = undefined;
    var leaf1: [digest_size]u8 = undefined;
    var leaf2: [digest_size]u8 = undefined;
    hashBlock(data[0 * data_block_size ..][0..data_block_size], salt, &leaf0);
    hashBlock(data[1 * data_block_size ..][0..data_block_size], salt, &leaf1);
    hashBlock(data[2 * data_block_size ..][0..data_block_size], salt, &leaf2);

    var leaf_level: [2 * hash_block_size]u8 = undefined;
    @memset(&leaf_level, 0);
    std.mem.copyForwards(u8, leaf_level[0..digest_size], &leaf0);
    std.mem.copyForwards(u8, leaf_level[digest_size .. 2 * digest_size], &leaf1);
    std.mem.copyForwards(u8, leaf_level[hash_block_size .. hash_block_size + digest_size], &leaf2);

    var root_of_leaf0: [digest_size]u8 = undefined;
    var root_of_leaf1: [digest_size]u8 = undefined;
    hashBlock(leaf_level[0..hash_block_size], salt, &root_of_leaf0);
    hashBlock(leaf_level[hash_block_size .. 2 * hash_block_size], salt, &root_of_leaf1);

    var root_level: [hash_block_size]u8 = undefined;
    @memset(&root_level, 0);
    std.mem.copyForwards(u8, root_level[0..digest_size], &root_of_leaf0);
    std.mem.copyForwards(u8, root_level[digest_size .. 2 * digest_size], &root_of_leaf1);

    var expected_tree: [3 * hash_block_size]u8 = undefined;
    @memcpy(expected_tree[0..hash_block_size], &root_level);
    @memcpy(expected_tree[hash_block_size..], &leaf_level);

    try std.testing.expectEqualSlices(u8, &expected_tree, generated.tree_bytes);

    var expected_root_hash: [digest_size]u8 = undefined;
    hashBlock(&root_level, salt, &expected_root_hash);
    try std.testing.expectEqualSlices(u8, &expected_root_hash, &generated.info.rootHash);
}
