//! SquashFS 4.0 reader **and writer**.
//!
//! The reader supports uncompressed blocks plus XZ- and zstd-compressed
//! metadata, data, and fragment blocks. This covers the real Azure Linux
//! installer media used by `miz build-image`, while keeping the
//! implementation focused on the documented SquashFS 4.0 on-disk layout.
//!
//! The writer (`writeImage`/`writeImagePath`) emits a valid SquashFS 4.0
//! image from a generic pull-based `TreeSource`. It streams regular-file
//! content block by block -- never holding a whole file in memory -- and
//! produces byte-for-byte deterministic output. It supports directories,
//! regular files (including multi-block and >4 GiB files via extended
//! inodes), and symlinks with POSIX mode/uid/gid, an uncompressed mode and
//! zstd compression, and optional tail fragments. This is enough to build the
//! outer LiveOS SquashFS wrapper that carries an ext4 `rootfs.img`. The
//! reader above round-trips everything the writer emits.

const std = @import("std");
const Io = std.Io;
const zstd = @import("zstd.zig");

pub const magic: u32 = 0x7371_7368; // "hsqs" little-endian on disk
pub const major_version: u16 = 4;
pub const metadata_block_size: usize = 8192;
pub const metadata_uncompressed_bit: u16 = 1 << 15;
pub const data_uncompressed_bit: u32 = 1 << 24;
pub const invalid_fragment: u32 = 0xFFFF_FFFF;
pub const invalid_table: u64 = std.math.maxInt(u64);
pub const compressor_options_flag: u16 = 0x0400;

pub const Compression = enum(u16) {
    gzip = 1,
    lzma = 2,
    lzo = 3,
    xz = 4,
    lz4 = 5,
    zstd = 6,
    _,
};

pub const XzCompressorOptions = struct {
    dictionary_size: u32,
    flags: u32,
};

pub const CompressorOptions = union(enum) {
    xz: XzCompressorOptions,
};

pub const SyntheticCompression = enum {
    none,
    xz,
    zstd,
};

pub const SyntheticImageOptions = struct {
    compression: SyntheticCompression = .none,
    block_size: u32 = 1024,
    full_data_blocks: u32 = 1,
    fragment_tail_size: u32 = 476,
    file_bytes: ?[]const u8 = null,
};

pub const EntryKind = enum { file, directory, symlink };

pub const DirEntry = struct {
    name: []const u8,
    index: usize,
    kind: EntryKind,
};

pub const Entry = struct {
    name: []const u8,
    parent: ?usize,
    kind: EntryKind,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    data_start: u64,
    block_sizes: []u32,
    fragment_index: ?u32,
    fragment_offset: u32,
    symlink_target: ?[]const u8,
};

pub const Superblock = struct {
    inodes: u32,
    block_size: u32,
    fragments: u32,
    compression: u16,
    block_log: u16,
    flags: u16,
    no_ids: u16,
    root_inode: u64,
    bytes_used: u64,
    id_table_start: u64,
    xattr_id_table_start: u64,
    inode_table_start: u64,
    directory_table_start: u64,
    fragment_table_start: u64,
    lookup_table_start: u64,
};

pub const OpenError = error{
    BadMagic,
    UnsupportedVersion,
    CompressedMetadataUnsupported,
    CompressedDataUnsupported,
    InvalidMetadataBlock,
    InvalidMetadataReference,
    InvalidDirectoryEntry,
    InvalidFragmentIndex,
    InvalidIdIndex,
    UnsupportedInodeType,
} || Io.File.OpenError || Io.File.ReadPositionalError || Io.File.StatError || std.mem.Allocator.Error;

pub const LookupError = error{ NotFound, NotADirectory, TooManySymlinks, BrokenSymlink } || std.mem.Allocator.Error;
pub const ReadError = error{ NotAFile, NotASymlink, CompressedDataUnsupported, InvalidDataBlock, InvalidFragmentIndex } || Io.File.ReadPositionalError || std.mem.Allocator.Error;

pub const CacheStats = struct {
    data_block_decompressions: usize = 0,
    fragment_block_decompressions: usize = 0,
};

const DataBlockCache = struct {
    file_offset: ?u64 = null,
    expected_size: usize = 0,
    bytes: []u8 = &.{},

    fn matches(self: DataBlockCache, file_offset: u64, expected_size: usize) bool {
        return self.file_offset != null and self.file_offset.? == file_offset and self.expected_size == expected_size;
    }

    fn replace(self: *DataBlockCache, allocator: std.mem.Allocator, file_offset: u64, expected_size: usize, bytes: []u8) void {
        self.clear(allocator);
        self.file_offset = file_offset;
        self.expected_size = expected_size;
        self.bytes = bytes;
    }

    fn clear(self: *DataBlockCache, allocator: std.mem.Allocator) void {
        if (self.bytes.len != 0) allocator.free(self.bytes);
        self.* = .{};
    }
};

const FragmentBlockCache = struct {
    start_block: ?u64 = null,
    raw_size: u32 = 0,
    bytes: []u8 = &.{},

    fn matches(self: FragmentBlockCache, fragment: FragmentEntry) bool {
        return self.start_block != null and self.start_block.? == fragment.start_block and self.raw_size == fragment.raw_size;
    }

    fn replace(self: *FragmentBlockCache, allocator: std.mem.Allocator, fragment: FragmentEntry, bytes: []u8) void {
        self.clear(allocator);
        self.start_block = fragment.start_block;
        self.raw_size = fragment.raw_size;
        self.bytes = bytes;
    }

    fn clear(self: *FragmentBlockCache, allocator: std.mem.Allocator) void {
        if (self.bytes.len != 0) allocator.free(self.bytes);
        self.* = .{};
    }
};

pub const Reader = struct {
    allocator: std.mem.Allocator,
    file: Io.File,
    superblock: Superblock,
    compressor_options: ?CompressorOptions,
    ids: []u32,
    fragments: []FragmentEntry,
    entries: []Entry,
    root_index: usize,
    // A single-entry cache is enough for the current hot path: ext4.populate()
    // reads squashfs-backed files sequentially in 4 KiB chunks, so most calls
    // stay within the same much-larger compressed block.
    data_block_cache: DataBlockCache = .{},
    fragment_block_cache: FragmentBlockCache = .{},
    cache_stats: CacheStats = .{},

    pub fn openPath(allocator: std.mem.Allocator, io: Io, path: []const u8) OpenError!Reader {
        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        errdefer file.close(io);
        return openFile(allocator, io, file);
    }

    pub fn openFile(allocator: std.mem.Allocator, io: Io, file: Io.File) OpenError!Reader {
        const stat = try file.stat(io);
        var sb_buf: [96]u8 = undefined;
        _ = try file.readPositionalAll(io, &sb_buf, 0);
        const sb = try parseSuperblock(&sb_buf);
        const compressor_options = try parseCompressorOptions(io, file, sb);

        const fragment_meta_start = try firstIndexedMetadataStart(allocator, io, file, sb.fragment_table_start, sb.fragments, @sizeOf(FragmentEntry));
        const id_meta_start = try firstIndexedMetadataStart(allocator, io, file, sb.id_table_start, sb.no_ids, @sizeOf(u32));

        const compression: Compression = @enumFromInt(sb.compression);

        var inode_table = try readMetadataTable(allocator, io, file, compression, sb.inode_table_start, sb.directory_table_start);
        var inode_table_owned = true;
        errdefer if (inode_table_owned) inode_table.deinit(allocator);

        const directory_table_end = minOptionalU64(
            minOptionalU64(
                tableSectionStart(sb.fragment_table_start, fragment_meta_start),
                tableSectionStart(sb.id_table_start, id_meta_start),
            ),
            minOptionalU64(optionalTableStart(sb.lookup_table_start), optionalTableStart(sb.xattr_id_table_start)),
        ) orelse stat.size;
        var directory_table = try readMetadataTable(allocator, io, file, compression, sb.directory_table_start, directory_table_end);
        var directory_table_owned = true;
        errdefer if (directory_table_owned) directory_table.deinit(allocator);

        const ids = try readIdTable(allocator, io, file, sb, compression, id_meta_start);
        errdefer allocator.free(ids);

        const fragments = try readFragmentTable(allocator, io, file, sb, compression, fragment_meta_start);
        errdefer allocator.free(fragments);

        var builder = Builder{
            .allocator = allocator,
            .ids = ids,
            .fragments = fragments,
            .inode_table = inode_table,
            .directory_table = directory_table,
            .block_size = sb.block_size,
            .entries = std.array_list.Managed(Entry).init(allocator),
        };
        errdefer builder.deinit();
        inode_table_owned = false;
        directory_table_owned = false;

        const root_index = try builder.parseNode(sb.root_inode, null, "/");

        const entries = try builder.entries.toOwnedSlice();
        builder.entries = std.array_list.Managed(Entry).init(allocator);
        builder.inode_table.deinit(allocator);
        builder.directory_table.deinit(allocator);

        return .{
            .allocator = allocator,
            .file = file,
            .superblock = sb,
            .compressor_options = compressor_options,
            .ids = ids,
            .fragments = fragments,
            .entries = entries,
            .root_index = root_index,
        };
    }

    pub fn close(self: *Reader, io: Io) void {
        self.clearBlockCache();
        for (self.entries) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.block_sizes);
            if (entry.symlink_target) |target| self.allocator.free(target);
        }
        self.allocator.free(self.entries);
        self.allocator.free(self.ids);
        self.allocator.free(self.fragments);
        self.file.close(io);
        self.* = undefined;
    }

    /// Frees any memoized decompressed data while keeping the reader open.
    pub fn clearBlockCache(self: *Reader) void {
        self.data_block_cache.clear(self.allocator);
        self.fragment_block_cache.clear(self.allocator);
    }

    /// Returns decompression counters for tests and diagnostics.
    pub fn cacheStats(self: *const Reader) CacheStats {
        return self.cache_stats;
    }

    pub fn getEntry(self: *const Reader, index: usize) *const Entry {
        return &self.entries[index];
    }

    pub fn lookup(self: *const Reader, path: []const u8) LookupError!usize {
        return self.lookupFrom(self.root_index, path, false, 0);
    }

    pub fn listDirAlloc(self: *const Reader, allocator: std.mem.Allocator, index: usize) (std.mem.Allocator.Error || error{NotADirectory})![]DirEntry {
        if (self.entries[index].kind != .directory) return error.NotADirectory;
        var list = std.array_list.Managed(DirEntry).init(allocator);
        errdefer list.deinit();
        for (self.entries, 0..) |entry, i| {
            if (entry.parent == index) try list.append(.{ .name = entry.name, .index = i, .kind = entry.kind });
        }
        std.mem.sort(DirEntry, list.items, {}, dirEntryLessThan);
        return list.toOwnedSlice();
    }

    pub fn readFileAlloc(self: *Reader, allocator: std.mem.Allocator, io: Io, index: usize) ReadError![]u8 {
        const entry = self.entries[index];
        if (entry.kind != .file) return error.NotAFile;

        const out = try allocator.alloc(u8, @intCast(entry.size));
        errdefer allocator.free(out);
        _ = try self.readFileAt(allocator, io, index, out, 0);
        return out;
    }

    pub fn readFileAt(self: *Reader, allocator: std.mem.Allocator, io: Io, index: usize, buffer: []u8, offset: u64) ReadError!usize {
        const entry = self.entries[index];
        if (entry.kind != .file) return error.NotAFile;
        if (offset >= entry.size or buffer.len == 0) return 0;

        const total: usize = @intCast(@min(@as(u64, buffer.len), entry.size - offset));
        var produced: usize = 0;
        const block_size = self.superblock.block_size;
        const full_blocks_to_skip: usize = @intCast(offset / block_size);
        var block_inner_offset: u32 = @intCast(offset % block_size);
        var stored_file_offset = entry.data_start;

        var block_index: usize = 0;
        while (block_index < full_blocks_to_skip and block_index < entry.block_sizes.len) : (block_index += 1) {
            const raw_size = entry.block_sizes[block_index];
            if (raw_size != 0) stored_file_offset += raw_size & ~data_uncompressed_bit;
        }

        while (block_index < entry.block_sizes.len and produced < total) : (block_index += 1) {
            const raw_size = entry.block_sizes[block_index];
            const block_take: usize = @intCast(@min(@as(u64, total - produced), block_size - block_inner_offset));
            if (raw_size == 0) {
                @memset(buffer[produced .. produced + block_take], 0);
            } else if ((raw_size & data_uncompressed_bit) != 0) {
                const stored_size = raw_size & ~data_uncompressed_bit;
                const got = try self.file.readPositionalAll(io, buffer[produced .. produced + block_take], stored_file_offset + block_inner_offset);
                if (got < block_take) @memset(buffer[produced + got .. produced + block_take], 0);
                stored_file_offset += stored_size;
            } else {
                const stored_size = raw_size & ~data_uncompressed_bit;
                const block_bytes = try self.readCachedDataBlock(allocator, io, stored_file_offset, stored_size, @intCast(@min(@as(u64, block_size), entry.size - @as(u64, block_index) * block_size)));
                const block_offset: usize = block_inner_offset;
                if (block_offset + block_take > block_bytes.len) return error.InvalidDataBlock;
                @memcpy(buffer[produced .. produced + block_take], block_bytes[block_offset .. block_offset + block_take]);
                stored_file_offset += stored_size;
            }
            produced += block_take;
            block_inner_offset = 0;
        }

        if (produced < total) {
            const fragment_index = entry.fragment_index orelse {
                @memset(buffer[produced..total], 0);
                return total;
            };
            if (fragment_index >= self.fragments.len) return error.InvalidFragmentIndex;
            const fragment_bytes = try self.readCachedFragmentBlock(allocator, io, self.fragments[fragment_index]);

            const data_region_bytes = @as(u64, entry.block_sizes.len) * block_size;
            const fragment_skip = (offset + produced) - data_region_bytes;
            const fragment_inner_offset = entry.fragment_offset + @as(u32, @intCast(fragment_skip));
            const take = total - produced;
            const fragment_offset: usize = fragment_inner_offset;
            if (fragment_offset + take > fragment_bytes.len) return error.InvalidDataBlock;
            @memcpy(buffer[produced .. produced + take], fragment_bytes[fragment_offset .. fragment_offset + take]);
            produced += take;
        }

        return produced;
    }

    pub fn readLink(self: *const Reader, index: usize) ReadError![]const u8 {
        if (self.entries[index].kind != .symlink) return error.NotASymlink;
        return self.entries[index].symlink_target.?;
    }

    pub fn resolveSymlink(self: *const Reader, index: usize) LookupError!usize {
        if (self.entries[index].kind != .symlink) return error.BrokenSymlink;
        return self.lookupFrom(self.entries[index].parent orelse self.root_index, self.entries[index].symlink_target.?, true, 1);
    }

    fn readCachedDataBlock(self: *Reader, allocator: std.mem.Allocator, io: Io, file_offset: u64, stored_size: u32, expected_size: usize) ReadError![]const u8 {
        if (!self.data_block_cache.matches(file_offset, expected_size)) {
            const block = try self.readDataBlockAlloc(allocator, io, file_offset, stored_size, expected_size);
            self.data_block_cache.replace(allocator, file_offset, expected_size, block);
        }
        return self.data_block_cache.bytes;
    }

    fn readDataBlockAlloc(self: *Reader, allocator: std.mem.Allocator, io: Io, file_offset: u64, stored_size: u32, expected_size: usize) ReadError![]u8 {
        const stored = try allocator.alloc(u8, stored_size);
        defer allocator.free(stored);
        _ = try self.file.readPositionalAll(io, stored, file_offset);

        self.cache_stats.data_block_decompressions += 1;
        const block = try decompressDataBlockAlloc(allocator, @enumFromInt(self.superblock.compression), stored, expected_size);
        if (block.len != expected_size) {
            allocator.free(block);
            return error.InvalidDataBlock;
        }
        return block;
    }

    fn readCachedFragmentBlock(self: *Reader, allocator: std.mem.Allocator, io: Io, fragment: FragmentEntry) ReadError![]const u8 {
        if (!self.fragment_block_cache.matches(fragment)) {
            const block = try self.readFragmentBlockAlloc(allocator, io, fragment);
            self.fragment_block_cache.replace(allocator, fragment, block);
        }
        return self.fragment_block_cache.bytes;
    }

    fn readFragmentBlockAlloc(self: *Reader, allocator: std.mem.Allocator, io: Io, fragment: FragmentEntry) ReadError![]u8 {
        const stored_size = fragment.raw_size & ~data_uncompressed_bit;
        const stored = try allocator.alloc(u8, stored_size);
        defer allocator.free(stored);
        _ = try self.file.readPositionalAll(io, stored, fragment.start_block);

        if ((fragment.raw_size & data_uncompressed_bit) != 0) return allocator.dupe(u8, stored);
        self.cache_stats.fragment_block_decompressions += 1;
        return decompressDataBlockAlloc(allocator, @enumFromInt(self.superblock.compression), stored, self.superblock.block_size);
    }

    fn lookupFrom(self: *const Reader, start_index: usize, path: []const u8, follow_final_symlink: bool, depth: u8) LookupError!usize {
        if (depth > 16) return error.TooManySymlinks;
        var current = if (std.mem.startsWith(u8, path, "/")) self.root_index else start_index;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        while (it.next()) |component| {
            if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
            if (std.mem.eql(u8, component, "..")) {
                current = self.entries[current].parent orelse self.root_index;
                continue;
            }
            if (self.entries[current].kind != .directory) return error.NotADirectory;
            const child = self.findChild(current, component) orelse return error.NotFound;
            const is_last = it.peek() == null;
            if (self.entries[child].kind == .symlink and (!is_last or follow_final_symlink)) {
                current = self.lookupFrom(self.entries[child].parent orelse self.root_index, self.entries[child].symlink_target.?, true, depth + 1) catch |err| switch (err) {
                    error.NotFound, error.NotADirectory => return error.BrokenSymlink,
                    else => return err,
                };
            } else {
                current = child;
            }
        }
        return current;
    }

    fn findChild(self: *const Reader, parent: usize, name: []const u8) ?usize {
        for (self.entries, 0..) |entry, i| {
            if (entry.parent == parent and std.mem.eql(u8, entry.name, name)) return i;
        }
        return null;
    }
};

const FragmentEntry = struct {
    start_block: u64,
    raw_size: u32,
};

const MetaBlockMap = struct {
    disk_rel_offset: u64,
    decompressed_offset: usize,
    size: usize,
};

const TableData = struct {
    bytes: []u8 = &.{},
    maps: []MetaBlockMap = &.{},

    fn deinit(self: *const TableData, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        allocator.free(self.maps);
    }
};

const InodeData = struct {
    kind: EntryKind,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    data_start: u64,
    block_sizes: []u32,
    fragment_index: ?u32,
    fragment_offset: u32,
    symlink_target: ?[]u8,
    dir_start_block: u32,
    dir_offset: u16,
    dir_size: u32,

    fn deinit(self: *InodeData, allocator: std.mem.Allocator) void {
        allocator.free(self.block_sizes);
        if (self.symlink_target) |target| allocator.free(target);
    }
};

const Builder = struct {
    allocator: std.mem.Allocator,
    ids: []const u32,
    fragments: []const FragmentEntry,
    inode_table: TableData,
    directory_table: TableData,
    block_size: u32,
    entries: std.array_list.Managed(Entry),

    fn deinit(self: *Builder) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.block_sizes);
            if (entry.symlink_target) |target| self.allocator.free(target);
        }
        self.entries.deinit();
        self.inode_table.deinit(self.allocator);
        self.directory_table.deinit(self.allocator);
    }

    fn parseNode(self: *Builder, inode_ref: u64, parent: ?usize, display_name: []const u8) OpenError!usize {
        var inode = try self.readInode(inode_ref);
        defer inode.deinit(self.allocator);

        const name = try self.allocator.dupe(u8, display_name);
        const block_sizes = try self.allocator.dupe(u32, inode.block_sizes);
        const target = if (inode.symlink_target) |link| try self.allocator.dupe(u8, link) else null;
        var appended = false;
        errdefer if (!appended) {
            self.allocator.free(name);
            self.allocator.free(block_sizes);
            if (target) |link| self.allocator.free(link);
        };

        try self.entries.append(.{
            .name = name,
            .parent = parent,
            .kind = inode.kind,
            .size = inode.size,
            .mode = inode.mode,
            .uid = inode.uid,
            .gid = inode.gid,
            .data_start = inode.data_start,
            .block_sizes = block_sizes,
            .fragment_index = inode.fragment_index,
            .fragment_offset = inode.fragment_offset,
            .symlink_target = target,
        });
        appended = true;
        const index = self.entries.items.len - 1;

        if (inode.kind == .directory) {
            try self.parseDirectory(index, inode.dir_start_block, inode.dir_offset, inode.dir_size);
        }
        return index;
    }

    fn parseDirectory(self: *Builder, parent_index: usize, start_block: u32, start_offset: u16, dir_size: u32) OpenError!void {
        var cursor = try translateMetadataRef(&self.directory_table, start_block, start_offset);
        const end = cursor + dir_size;
        if (end > self.directory_table.bytes.len) return error.InvalidDirectoryEntry;

        while (cursor < end) {
            if (cursor + 12 > end) return error.InvalidDirectoryEntry;
            const header = self.directory_table.bytes[cursor .. cursor + 12];
            cursor += 12;
            const count = std.mem.readInt(u32, header[0..4], .little) + 1;
            const shared_block = std.mem.readInt(u32, header[4..8], .little);
            const _inode_base = std.mem.readInt(u32, header[8..12], .little);
            _ = _inode_base;

            var i: u32 = 0;
            while (i < count) : (i += 1) {
                if (cursor + 8 > end) return error.InvalidDirectoryEntry;
                const entry = self.directory_table.bytes[cursor .. cursor + 8];
                cursor += 8;

                const inode_offset = std.mem.readInt(u16, entry[0..2], .little);
                const name_len = std.mem.readInt(u16, entry[6..8], .little) + 1;
                if (cursor + name_len > end) return error.InvalidDirectoryEntry;
                const name_bytes = self.directory_table.bytes[cursor .. cursor + name_len];
                cursor += name_len;

                const inode_ref = (@as(u64, shared_block) << 16) | inode_offset;
                _ = try self.parseNode(inode_ref, parent_index, name_bytes);
            }
        }
    }

    fn readInode(self: *Builder, inode_ref: u64) OpenError!InodeData {
        const block = inode_ref >> 16;
        const offset: u16 = @intCast(inode_ref & 0xFFFF);
        const base_index = try translateMetadataRef(&self.inode_table, block, offset);
        if (base_index + 16 > self.inode_table.bytes.len) return error.InvalidMetadataReference;
        const base = self.inode_table.bytes[base_index..];

        const inode_type = std.mem.readInt(u16, base[0..2], .little);
        const base_mode = std.mem.readInt(u16, base[2..4], .little);
        const uid_index = std.mem.readInt(u16, base[4..6], .little);
        const gid_index = std.mem.readInt(u16, base[6..8], .little);
        if (uid_index >= self.ids.len or gid_index >= self.ids.len) return error.InvalidIdIndex;

        const uid = self.ids[uid_index];
        const gid = self.ids[gid_index];

        return switch (inode_type) {
            1 => try self.readDirInode(base, base_mode, uid, gid, false),
            2 => try self.readRegInode(base, base_mode, uid, gid, false),
            3 => try self.readSymlinkInode(base, base_mode, uid, gid, false),
            8 => try self.readDirInode(base, base_mode, uid, gid, true),
            9 => try self.readRegInode(base, base_mode, uid, gid, true),
            10 => try self.readSymlinkInode(base, base_mode, uid, gid, true),
            else => error.UnsupportedInodeType,
        };
    }

    fn readDirInode(self: *Builder, base: []const u8, base_mode: u16, uid: u32, gid: u32, long: bool) OpenError!InodeData {
        if (long) {
            if (base.len < 40) return error.InvalidMetadataReference;
            const raw_size = std.mem.readInt(u32, base[20..24], .little);
            if (raw_size < 3) return error.InvalidMetadataReference;
            const dir_size = raw_size - 3;
            return .{
                .kind = .directory,
                .mode = typeBits(.directory) | base_mode,
                .uid = uid,
                .gid = gid,
                .size = dir_size,
                .data_start = 0,
                .block_sizes = try self.allocator.alloc(u32, 0),
                .fragment_index = null,
                .fragment_offset = 0,
                .symlink_target = null,
                .dir_start_block = std.mem.readInt(u32, base[24..28], .little),
                .dir_offset = std.mem.readInt(u16, base[34..36], .little),
                .dir_size = dir_size,
            };
        }
        if (base.len < 32) return error.InvalidMetadataReference;
        const raw_size = std.mem.readInt(u16, base[24..26], .little);
        if (raw_size < 3) return error.InvalidMetadataReference;
        const dir_size = raw_size - 3;
        return .{
            .kind = .directory,
            .mode = typeBits(.directory) | base_mode,
            .uid = uid,
            .gid = gid,
            .size = dir_size,
            .data_start = 0,
            .block_sizes = try self.allocator.alloc(u32, 0),
            .fragment_index = null,
            .fragment_offset = 0,
            .symlink_target = null,
            .dir_start_block = std.mem.readInt(u32, base[16..20], .little),
            .dir_offset = std.mem.readInt(u16, base[26..28], .little),
            .dir_size = dir_size,
        };
    }

    fn readRegInode(self: *Builder, base: []const u8, base_mode: u16, uid: u32, gid: u32, long: bool) OpenError!InodeData {
        if (long) {
            if (base.len < 56) return error.InvalidMetadataReference;
            const file_size = std.mem.readInt(u64, base[24..32], .little);
            const fragment = std.mem.readInt(u32, base[44..48], .little);
            const remainder = file_size % self.block_size;
            const full_blocks = file_size / self.block_size;
            const block_count: usize = @intCast(full_blocks + (if (fragment == invalid_fragment and remainder != 0) @as(u64, 1) else 0));
            const block_list = try readBlockSizes(self.allocator, base[56..], block_count);
            return .{
                .kind = .file,
                .mode = typeBits(.file) | base_mode,
                .uid = uid,
                .gid = gid,
                .size = file_size,
                .data_start = std.mem.readInt(u64, base[16..24], .little),
                .block_sizes = block_list,
                .fragment_index = if (fragment == invalid_fragment) null else fragment,
                .fragment_offset = std.mem.readInt(u32, base[48..52], .little),
                .symlink_target = null,
                .dir_start_block = 0,
                .dir_offset = 0,
                .dir_size = 0,
            };
        }

        if (base.len < 32) return error.InvalidMetadataReference;
        const file_size = std.mem.readInt(u32, base[28..32], .little);
        const fragment = std.mem.readInt(u32, base[20..24], .little);
        const remainder = file_size % self.block_size;
        const full_blocks = file_size / self.block_size;
        const block_count: usize = @intCast(full_blocks + (if (fragment == invalid_fragment and remainder != 0) @as(u32, 1) else 0));
        const block_list = try readBlockSizes(self.allocator, base[32..], block_count);
        return .{
            .kind = .file,
            .mode = typeBits(.file) | base_mode,
            .uid = uid,
            .gid = gid,
            .size = file_size,
            .data_start = std.mem.readInt(u32, base[16..20], .little),
            .block_sizes = block_list,
            .fragment_index = if (fragment == invalid_fragment) null else fragment,
            .fragment_offset = std.mem.readInt(u32, base[24..28], .little),
            .symlink_target = null,
            .dir_start_block = 0,
            .dir_offset = 0,
            .dir_size = 0,
        };
    }

    fn readSymlinkInode(self: *Builder, base: []const u8, base_mode: u16, uid: u32, gid: u32, long: bool) OpenError!InodeData {
        if (base.len < 24) return error.InvalidMetadataReference;
        const symlink_size = std.mem.readInt(u32, base[20..24], .little);
        const extra: usize = if (long) 4 else 0;
        if (24 + symlink_size + extra > base.len) return error.InvalidMetadataReference;
        const target = try self.allocator.dupe(u8, base[24 .. 24 + symlink_size]);
        return .{
            .kind = .symlink,
            .mode = typeBits(.symlink) | base_mode,
            .uid = uid,
            .gid = gid,
            .size = symlink_size,
            .data_start = 0,
            .block_sizes = try self.allocator.alloc(u32, 0),
            .fragment_index = null,
            .fragment_offset = 0,
            .symlink_target = target,
            .dir_start_block = 0,
            .dir_offset = 0,
            .dir_size = 0,
        };
    }
};

fn parseSuperblock(buf: *const [96]u8) OpenError!Superblock {
    if (std.mem.readInt(u32, buf[0..4], .little) != magic) return error.BadMagic;
    if (std.mem.readInt(u16, buf[28..30], .little) != major_version) return error.UnsupportedVersion;

    return .{
        .inodes = std.mem.readInt(u32, buf[4..8], .little),
        .block_size = std.mem.readInt(u32, buf[12..16], .little),
        .fragments = std.mem.readInt(u32, buf[16..20], .little),
        .compression = std.mem.readInt(u16, buf[20..22], .little),
        .block_log = std.mem.readInt(u16, buf[22..24], .little),
        .flags = std.mem.readInt(u16, buf[24..26], .little),
        .no_ids = std.mem.readInt(u16, buf[26..28], .little),
        .root_inode = std.mem.readInt(u64, buf[32..40], .little),
        .bytes_used = std.mem.readInt(u64, buf[40..48], .little),
        .id_table_start = std.mem.readInt(u64, buf[48..56], .little),
        .xattr_id_table_start = std.mem.readInt(u64, buf[56..64], .little),
        .inode_table_start = std.mem.readInt(u64, buf[64..72], .little),
        .directory_table_start = std.mem.readInt(u64, buf[72..80], .little),
        .fragment_table_start = std.mem.readInt(u64, buf[80..88], .little),
        .lookup_table_start = std.mem.readInt(u64, buf[88..96], .little),
    };
}

fn parseCompressorOptions(io: Io, file: Io.File, sb: Superblock) OpenError!?CompressorOptions {
    if ((sb.flags & compressor_options_flag) == 0) return null;

    return switch (@as(Compression, @enumFromInt(sb.compression))) {
        .xz => blk: {
            var buf: [8]u8 = undefined;
            _ = try file.readPositionalAll(io, &buf, 96);
            break :blk .{ .xz = .{
                .dictionary_size = std.mem.readInt(u32, buf[0..4], .little),
                .flags = std.mem.readInt(u32, buf[4..8], .little),
            } };
        },
        else => null,
    };
}

fn firstIndexedMetadataStart(allocator: std.mem.Allocator, io: Io, file: Io.File, index_table_start: u64, item_count: anytype, item_size: usize) OpenError!?u64 {
    if (index_table_start == invalid_table or item_count == 0) return null;
    const count = std.math.divCeil(usize, @as(usize, item_count) * item_size, metadata_block_size) catch unreachable;
    if (count == 0) return null;
    const table = try allocator.alloc(u8, count * 8);
    defer allocator.free(table);
    _ = try file.readPositionalAll(io, table, index_table_start);
    return std.mem.readInt(u64, table[0..8], .little);
}

fn readIndexedTableOffsets(allocator: std.mem.Allocator, io: Io, file: Io.File, index_table_start: u64, item_count: usize, item_size: usize) OpenError![]u64 {
    const count = std.math.divCeil(usize, item_count * item_size, metadata_block_size) catch unreachable;
    if (count == 0) return allocator.alloc(u64, 0);
    const table = try allocator.alloc(u8, count * 8);
    defer allocator.free(table);
    _ = try file.readPositionalAll(io, table, index_table_start);
    const out = try allocator.alloc(u64, count);
    for (out, 0..) |*value, i| value.* = std.mem.readInt(u64, table[i * 8 ..][0..8], .little);
    return out;
}

fn readMetadataTable(allocator: std.mem.Allocator, io: Io, file: Io.File, compression: Compression, start: u64, end: u64) OpenError!TableData {
    var bytes = std.array_list.Managed(u8).init(allocator);
    errdefer bytes.deinit();
    var maps = std.array_list.Managed(MetaBlockMap).init(allocator);
    errdefer maps.deinit();

    var offset = start;
    while (offset < end) {
        var header_buf: [2]u8 = undefined;
        _ = try file.readPositionalAll(io, &header_buf, offset);
        const header = std.mem.readInt(u16, &header_buf, .little);
        const size = header & ~metadata_uncompressed_bit;
        if (size == 0) return error.InvalidMetadataBlock;
        if (offset + 2 + size > end) return error.InvalidMetadataBlock;

        const payload = try allocator.alloc(u8, size);
        defer allocator.free(payload);
        _ = try file.readPositionalAll(io, payload, offset + 2);

        const block_bytes = if ((header & metadata_uncompressed_bit) != 0)
            try allocator.dupe(u8, payload)
        else
            try decompressMetadataBlockAlloc(allocator, compression, payload, metadata_block_size);
        defer allocator.free(block_bytes);

        try maps.append(.{ .disk_rel_offset = offset - start, .decompressed_offset = bytes.items.len, .size = block_bytes.len });
        try bytes.appendSlice(block_bytes);
        offset += 2 + size;
    }

    return .{ .bytes = try bytes.toOwnedSlice(), .maps = try maps.toOwnedSlice() };
}

fn decompressMetadataBlockAlloc(allocator: std.mem.Allocator, compression: Compression, bytes: []const u8, max_size: usize) OpenError![]u8 {
    return switch (compression) {
        .xz => decompressXzAlloc(allocator, bytes, max_size) catch |err| switch (err) {
            error.Unsupported => error.CompressedMetadataUnsupported,
            else => error.InvalidMetadataBlock,
        },
        .zstd => decompressZstdAlloc(allocator, bytes, max_size) catch |err| switch (err) {
            error.Unsupported => error.CompressedMetadataUnsupported,
            else => error.InvalidMetadataBlock,
        },
        else => error.CompressedMetadataUnsupported,
    };
}

fn decompressDataBlockAlloc(allocator: std.mem.Allocator, compression: Compression, bytes: []const u8, max_size: usize) ReadError![]u8 {
    return switch (compression) {
        .xz => decompressXzAlloc(allocator, bytes, max_size) catch |err| switch (err) {
            error.Unsupported => error.CompressedDataUnsupported,
            else => error.InvalidDataBlock,
        },
        .zstd => decompressZstdAlloc(allocator, bytes, max_size) catch |err| switch (err) {
            error.Unsupported => error.CompressedDataUnsupported,
            else => error.InvalidDataBlock,
        },
        else => error.CompressedDataUnsupported,
    };
}

const BlockDecompressionError = anyerror;

fn decompressXzAlloc(allocator: std.mem.Allocator, bytes: []const u8, max_size: usize) BlockDecompressionError![]u8 {
    var input = Io.Reader.fixed(bytes);
    var decompressor = std.compress.xz.Decompress.init(&input, allocator, &.{}) catch |err| switch (err) {
        error.NotXzStream, error.WrongChecksum, error.EndOfStream, error.ReadFailed => return error.Invalid,
    };
    defer decompressor.deinit();
    const limit = std.math.add(usize, max_size, 1) catch max_size;

    const out = decompressor.reader.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.StreamTooLong,
        error.ReadFailed => return switch (decompressor.err orelse error.CorruptInput) {
            error.Unsupported => decompressXzBcjAlloc(allocator, bytes, max_size) catch |bcj_err| switch (bcj_err) {
                error.Unsupported => error.Unsupported,
                error.StreamTooLong => error.StreamTooLong,
                error.OutOfMemory => error.OutOfMemory,
                else => error.Invalid,
            },
            else => error.Invalid,
        },
    };
    if (out.len > max_size) {
        allocator.free(out);
        return error.StreamTooLong;
    }
    return out;
}

const XzFilter = union(enum) {
    x86: u32,
    lzma2,
};

const XzBlockInfo = struct {
    packed_size: u64,
    unpacked_size: ?u64,
    header_size: usize,
    filters: [2]XzFilter,
    filter_count: usize,
};

const XzIndexInfo = struct {
    unpadded_size: u64,
    unpacked_size: u64,
};

fn decompressXzBcjAlloc(allocator: std.mem.Allocator, bytes: []const u8, max_size: usize) BlockDecompressionError![]u8 {
    const info = try parseXzBcjBlock(bytes);
    if (info.filter_count != 2) return error.Unsupported;

    const start_offset = switch (info.filters[0]) {
        .x86 => |value| value,
        else => return error.Unsupported,
    };
    switch (info.filters[1]) {
        .lzma2 => {},
        else => return error.Unsupported,
    }

    var input = Io.Reader.fixed(bytes);
    _ = input.take(12 + info.header_size + 4) catch return error.Invalid;
    const packed_slice = input.take(@intCast(info.packed_size)) catch return error.Invalid;

    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();

    var packed_input = Io.Reader.fixed(packed_slice);
    var lzma2_decode = try std.compress.lzma2.Decode.init(allocator);
    defer lzma2_decode.deinit(allocator);
    _ = try lzma2_decode.decompress(&packed_input, &out);

    const decoded = try out.toOwnedSlice();
    errdefer allocator.free(decoded);

    if (info.unpacked_size) |expected| {
        if (decoded.len != expected) return error.Invalid;
    }
    if (decoded.len > max_size) return error.StreamTooLong;

    x86BcjDecode(start_offset, decoded);
    return decoded;
}

fn parseXzBcjBlock(bytes: []const u8) BlockDecompressionError!XzBlockInfo {
    const xz = std.compress.xz.Decompress;
    const Crc32 = std.hash.Crc32;

    var input = Io.Reader.fixed(bytes);
    const stream_magic = input.takeArray(6) catch return error.Invalid;
    if (!std.mem.eql(u8, stream_magic, &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00 })) return error.Invalid;

    const computed_checksum = Crc32.hash(input.peek(@sizeOf(xz.StreamFlags)) catch return error.Invalid);
    const stream_flags = input.takeStruct(xz.StreamFlags, .little) catch return error.Invalid;
    const stored_hash = input.takeInt(u32, .little) catch return error.Invalid;
    if (computed_checksum != stored_hash) return error.Invalid;

    const first_byte: usize = input.peekByte() catch return error.Invalid;
    if (first_byte == 0) return error.Invalid;
    const declared_header_size = first_byte * 4;
    input.fill(declared_header_size) catch return error.Invalid;
    const header_seek_start = input.seek;
    input.toss(1);

    const Flags = packed struct(u8) {
        last_filter_index: u2,
        reserved: u4,
        has_packed_size: bool,
        has_unpacked_size: bool,
    };
    const flags = input.takeStruct(Flags, .little) catch return error.Invalid;
    if (flags.reserved != 0) return error.Invalid;

    const filter_count = @as(usize, flags.last_filter_index) + 1;
    if (filter_count > 2) return error.Unsupported;

    var packed_size = if (flags.has_packed_size)
        input.takeLeb128(u64) catch return error.Invalid
    else
        null;
    var unpacked_size = if (flags.has_unpacked_size)
        input.takeLeb128(u64) catch return error.Invalid
    else
        null;

    var filters: [2]XzFilter = undefined;
    var i: usize = 0;
    while (i < filter_count) : (i += 1) {
        const filter_id = input.takeLeb128(u64) catch return error.Invalid;
        const properties_size = input.takeLeb128(u64) catch return error.Invalid;
        filters[i] = switch (filter_id) {
            0x04 => blk: {
                const start_offset = switch (properties_size) {
                    0 => @as(u32, 0),
                    4 => input.takeInt(u32, .little) catch return error.Invalid,
                    else => return error.Unsupported,
                };
                break :blk .{ .x86 = start_offset };
            },
            0x21 => blk: {
                if (properties_size != 1) return error.Invalid;
                _ = input.takeByte() catch return error.Invalid;
                break :blk .lzma2;
            },
            else => return error.Unsupported,
        };
    }

    const actual_header_size = input.seek - header_seek_start;
    if (actual_header_size > declared_header_size) return error.Invalid;
    const remaining_bytes = declared_header_size - actual_header_size;
    for (0..remaining_bytes) |_| {
        if ((input.takeByte() catch return error.Invalid) != 0) return error.Invalid;
    }

    const header_slice = input.buffer[header_seek_start..][0..declared_header_size];
    const declared_checksum = input.takeInt(u32, .little) catch return error.Invalid;
    if (Crc32.hash(header_slice) != declared_checksum) return error.Invalid;

    if (packed_size == null or unpacked_size == null) {
        const index = try parseXzIndex(bytes);
        if (packed_size == null) {
            const check_size = xzCheckSize(stream_flags.check) orelse return error.Unsupported;
            if (index.unpadded_size < declared_header_size + check_size) return error.Invalid;
            packed_size = index.unpadded_size - declared_header_size - check_size;
        }
        if (unpacked_size == null) unpacked_size = index.unpacked_size;
    }

    return .{
        .packed_size = packed_size.?,
        .unpacked_size = unpacked_size,
        .header_size = declared_header_size,
        .filters = filters,
        .filter_count = filter_count,
    };
}

fn xzCheckSize(check: std.compress.xz.Decompress.Check) ?u64 {
    return switch (check) {
        .none => 0,
        .crc32 => 4,
        .crc64 => 8,
        .sha256 => 32,
        else => null,
    };
}

fn parseXzIndex(bytes: []const u8) BlockDecompressionError!XzIndexInfo {
    if (bytes.len < 12) return error.Invalid;

    const footer_start = bytes.len - 12;
    if (!std.mem.eql(u8, bytes[footer_start + 10 .. footer_start + 12], "YZ")) return error.Invalid;
    const backward_size = (@as(u64, std.mem.readInt(u32, @ptrCast(bytes[footer_start + 4 ..][0..4]), .little)) + 1) * 4;
    if (backward_size > footer_start) return error.Invalid;

    const index_start: usize = @intCast(footer_start - backward_size);
    var input = Io.Reader.fixed(bytes[index_start..footer_start]);
    if ((input.takeByte() catch return error.Invalid) != 0) return error.Invalid;

    const record_count = input.takeLeb128(u64) catch return error.Invalid;
    if (record_count != 1) return error.Unsupported;

    return .{
        .unpadded_size = input.takeLeb128(u64) catch return error.Invalid,
        .unpacked_size = input.takeLeb128(u64) catch return error.Invalid,
    };
}

fn x86BcjDecode(start_offset: u32, buffer: []u8) void {
    const mask_to_bit_number = [_]u32{ 0, 1, 2, 2, 3 };

    var prev_mask: u32 = 0;
    var prev_pos: u32 = 0xFFFF_FFFB;
    if (buffer.len < 5) return;

    const now_pos = start_offset;
    if (now_pos -% prev_pos > 5) prev_pos = now_pos -% 5;

    const limit = buffer.len - 5;
    var buffer_pos: usize = 0;

    while (buffer_pos <= limit) {
        var b = buffer[buffer_pos];
        if (b != 0xE8 and b != 0xE9) {
            buffer_pos += 1;
            continue;
        }

        const offset = now_pos +% @as(u32, @intCast(buffer_pos)) -% prev_pos;
        prev_pos = now_pos +% @as(u32, @intCast(buffer_pos));

        if (offset > 5) {
            prev_mask = 0;
        } else {
            var step: u32 = 0;
            while (step < offset) : (step += 1) {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }

        b = buffer[buffer_pos + 4];
        if (test86MsByte(b) and (prev_mask >> 1) <= 4 and (prev_mask >> 1) != 3) {
            var src: u32 = (@as(u32, b) << 24) |
                (@as(u32, buffer[buffer_pos + 3]) << 16) |
                (@as(u32, buffer[buffer_pos + 2]) << 8) |
                @as(u32, buffer[buffer_pos + 1]);

            var dest: u32 = undefined;
            while (true) {
                dest = src -% (now_pos +% @as(u32, @intCast(buffer_pos)) +% 5);
                if (prev_mask == 0) break;

                const index = mask_to_bit_number[prev_mask >> 1];
                b = @truncate(dest >> @as(u5, @intCast(24 - index * 8)));
                if (!test86MsByte(b)) break;

                src = dest ^ @as(u32, @truncate((@as(u64, 1) << @as(u6, @intCast(32 - index * 8))) - 1));
            }

            buffer[buffer_pos + 4] = @truncate(~(((dest >> 24) & 1) -% 1));
            buffer[buffer_pos + 3] = @truncate(dest >> 16);
            buffer[buffer_pos + 2] = @truncate(dest >> 8);
            buffer[buffer_pos + 1] = @truncate(dest);
            buffer_pos += 5;
            prev_mask = 0;
        } else {
            buffer_pos += 1;
            prev_mask |= 1;
            if (test86MsByte(b)) prev_mask |= 0x10;
        }
    }
}

fn test86MsByte(value: u8) bool {
    return value == 0 or value == 0xFF;
}

fn decompressZstdAlloc(allocator: std.mem.Allocator, bytes: []const u8, max_size: usize) BlockDecompressionError![]u8 {
    var input = Io.Reader.fixed(bytes);
    // Indirect mode with an explicitly-sized window buffer -- see
    // packages/miz/src/verity_tooling.zig's decompressZstd for why the empty-
    // buffer "direct" mode used previously is unsafe for arbitrary input
    // sizes (it happened to work for squashfs's typically-small
    // independently-compressed blocks, but relied on a fragile invariant).
    const window_len = std.compress.zstd.default_window_len;
    const window_buf = try allocator.alloc(u8, window_len + std.compress.zstd.block_size_max);
    defer allocator.free(window_buf);
    var decompressor = std.compress.zstd.Decompress.init(&input, window_buf, .{ .window_len = window_len });
    const limit = std.math.add(usize, max_size, 1) catch max_size;

    const out = decompressor.reader.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.StreamTooLong,
        error.ReadFailed => return switch (decompressor.err orelse error.MalformedFrame) {
            error.WindowOversize => error.Unsupported,
            else => error.Invalid,
        },
    };
    if (out.len > max_size) {
        allocator.free(out);
        return error.StreamTooLong;
    }
    return out;
}

fn translateMetadataRef(table: *const TableData, block: u64, offset: u16) OpenError!usize {
    for (table.maps) |map| {
        if (map.disk_rel_offset == block) {
            if (offset > map.size) return error.InvalidMetadataReference;
            return map.decompressed_offset + offset;
        }
    }
    return error.InvalidMetadataReference;
}

fn readIdTable(allocator: std.mem.Allocator, io: Io, file: Io.File, sb: Superblock, compression: Compression, id_meta_start: ?u64) OpenError![]u32 {
    if (sb.no_ids == 0) return allocator.alloc(u32, 0);
    const start = id_meta_start orelse return error.InvalidMetadataBlock;
    var table = try readMetadataTable(allocator, io, file, compression, start, sb.id_table_start);
    defer table.deinit(allocator);

    const ids = try allocator.alloc(u32, sb.no_ids);
    for (ids, 0..) |*id, i| {
        const off = i * 4;
        id.* = std.mem.readInt(u32, table.bytes[off..][0..4], .little);
    }
    return ids;
}

fn readFragmentTable(allocator: std.mem.Allocator, io: Io, file: Io.File, sb: Superblock, compression: Compression, fragment_meta_start: ?u64) OpenError![]FragmentEntry {
    if (sb.fragments == 0) return allocator.alloc(FragmentEntry, 0);
    const start = fragment_meta_start orelse return error.InvalidMetadataBlock;
    const offsets = try readIndexedTableOffsets(allocator, io, file, sb.fragment_table_start, sb.fragments, @sizeOf(FragmentEntry));
    defer allocator.free(offsets);

    var table = try readMetadataTable(allocator, io, file, compression, start, sb.fragment_table_start);
    defer table.deinit(allocator);

    const entries = try allocator.alloc(FragmentEntry, sb.fragments);
    for (entries, 0..) |*entry, i| {
        const off = i * 16;
        entry.* = .{
            .start_block = std.mem.readInt(u64, table.bytes[off..][0..8], .little),
            .raw_size = std.mem.readInt(u32, table.bytes[off + 8 ..][0..4], .little),
        };
    }
    return entries;
}

fn readBlockSizes(allocator: std.mem.Allocator, bytes: []const u8, count: usize) OpenError![]u32 {
    const out = try allocator.alloc(u32, count);
    for (out, 0..) |*value, i| {
        const off = i * 4;
        if (off + 4 > bytes.len) return error.InvalidMetadataReference;
        value.* = std.mem.readInt(u32, bytes[off..][0..4], .little);
    }
    return out;
}

fn typeBits(kind: EntryKind) u32 {
    return switch (kind) {
        .directory => 0o040000,
        .file => 0o100000,
        .symlink => 0o120000,
    };
}

fn minOptionalU64(a: ?u64, b: ?u64) ?u64 {
    if (a == null) return b;
    if (b == null) return a;
    return @min(a.?, b.?);
}

fn optionalTableStart(start: u64) ?u64 {
    return if (start == invalid_table) null else start;
}

fn tableSectionStart(index_table_start: u64, first_metadata_start: ?u64) ?u64 {
    return first_metadata_start orelse optionalTableStart(index_table_start);
}

fn dirEntryLessThan(_: void, a: DirEntry, b: DirEntry) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

// ===========================================================================
// Writer
// ===========================================================================

/// Block compressor used for data, fragment, and metadata blocks. `zstd`
/// produces frames the reader above (and Zig's stdlib zstd decoder) round-trip;
/// `none` stores every block verbatim with the on-disk "uncompressed" bit set.
pub const WriterCompression = enum { none, zstd };

/// Node kinds the writer can encode. RootTree kinds outside this set
/// (hardlink, device, fifo) are rejected with a precise error by the adapter
/// rather than being silently dropped.
pub const SourceKind = enum { directory, file, symlink };

/// One node pulled from a `TreeSource`, addressed by its root-relative path.
/// Paths carry no leading slash and use '/' separators; the root directory is
/// described separately by `SourceRoot` and is never returned as a node.
pub const SourceNode = struct {
    path: []const u8,
    kind: SourceKind,
    /// POSIX mode. Only the low 12 bits (permissions + setuid/setgid/sticky)
    /// are used; the type bits are derived from `kind`.
    mode: u16,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: u32 = 0,
    /// Byte length for regular files. For symlinks this is the target length
    /// when the target is delivered through `read` rather than
    /// `symlink_target`; ignored for directories.
    size: u64 = 0,
    /// Link target for symlinks, borrowed for the duration of the write call.
    /// May be left empty for sources that expose the target through `read`
    /// (in which case `size` gives its length); ignored for other kinds.
    symlink_target: []const u8 = &.{},
};

/// Metadata for the image root directory.
pub const SourceRoot = struct {
    mode: u16 = 0o755,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: u32 = 0,
};

/// Generic pull-based source the writer consumes. Any tree (RootTree included)
/// can expose one without the SquashFS codec depending on its concrete type.
/// `node` may fail so an adapter can reject unrepresentable nodes precisely.
pub const TreeSource = struct {
    context: *const anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        root: *const fn (context: *const anyopaque) SourceRoot,
        count: *const fn (context: *const anyopaque) usize,
        node: *const fn (context: *const anyopaque, index: usize) anyerror!SourceNode,
        read: *const fn (context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize,
    };

    pub fn root(self: TreeSource) SourceRoot {
        return self.vtable.root(self.context);
    }
    pub fn count(self: TreeSource) usize {
        return self.vtable.count(self.context);
    }
    pub fn node(self: TreeSource, index: usize) anyerror!SourceNode {
        return self.vtable.node(self.context, index);
    }
    pub fn read(self: TreeSource, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        return self.vtable.read(self.context, index, buffer, offset);
    }
};

pub const WriteOptions = struct {
    compression: WriterCompression = .zstd,
    /// Data block size. Must be a power of two in [4096, 1 MiB].
    block_size: u32 = 128 * 1024,
    /// Pack sub-block file tails into shared fragment blocks. Disable for a
    /// deterministic layout that stores each tail as its own data block.
    use_fragments: bool = true,
    /// Deterministic image modification time stamped into the superblock.
    mtime: u32 = 0,
};

pub const WriteResult = struct {
    /// Total image length in bytes.
    bytes_written: u64,
    inode_count: u32,
    fragment_count: u32,
};

pub const WriteError = error{
    EmptyBlockSize,
    BlockSizeNotPowerOfTwo,
    BlockSizeOutOfRange,
    InvalidPath,
    MissingParentDirectory,
    DuplicatePath,
    NameTooLong,
    SymlinkTargetTooLong,
    TooManyIds,
    ContentReadShort,
};

/// Writes a SquashFS 4.0 image describing `source` to `output`, which must be
/// a writable file positioned at offset 0. Streams file content block by block
/// and returns the image length plus inode/fragment counts.
pub fn writeImage(
    allocator: std.mem.Allocator,
    io: Io,
    output: Io.File,
    source: TreeSource,
    options: WriteOptions,
) anyerror!WriteResult {
    if (options.block_size == 0) return error.EmptyBlockSize;
    if (!std.math.isPowerOfTwo(options.block_size)) return error.BlockSizeNotPowerOfTwo;
    if (options.block_size < 4096 or options.block_size > 1 << 20) return error.BlockSizeOutOfRange;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var writer = Writer{
        .allocator = allocator,
        .arena = arena.allocator(),
        .io = io,
        .file = output,
        .options = options,
        .compress = options.compression == .zstd,
        .inode_table = MetaWriter.init(allocator, options.compression == .zstd),
        .directory_table = MetaWriter.init(allocator, options.compression == .zstd),
        .fragments = std.array_list.Managed(FragmentRecord).init(allocator),
        .ids = std.array_list.Managed(u32).init(allocator),
        .fragment_buffer = std.array_list.Managed(u8).init(allocator),
    };
    defer writer.deinit();

    return writer.run(source);
}

/// Convenience wrapper that creates (truncating) `path` and writes the image.
pub fn writeImagePath(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    source: TreeSource,
    options: WriteOptions,
) anyerror!WriteResult {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    return writeImage(allocator, io, file, source, options);
}

const FragmentRecord = struct {
    start_block: u64,
    size_field: u32,
};

const BuildNode = struct {
    kind: SourceKind,
    name: []const u8,
    mode: u16,
    uid: u32,
    gid: u32,
    mtime: u32,
    file_size: u64,
    symlink_target: []const u8,
    source_index: ?usize,
    children: std.array_list.Managed(usize),

    inode_number: u32 = 0,
    parent_inode: u32 = 0,
    inode_ref: u64 = 0,
    entry_type: u16 = 0,

    data_start: u64 = 0,
    block_sizes: []u32 = &.{},
    fragment_index: u32 = invalid_fragment,
    fragment_offset: u32 = 0,

    dir_start_block: u32 = 0,
    dir_offset: u16 = 0,
    dir_size: u32 = 0,
};

const CompressedBlock = struct {
    bytes: []u8,
    uncompressed: bool,
};

fn compressBlock(allocator: std.mem.Allocator, compress: bool, payload: []const u8) !CompressedBlock {
    if (!compress or payload.len == 0) {
        return .{ .bytes = try allocator.dupe(u8, payload), .uncompressed = true };
    }
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), payload.len / 2));
    defer out.deinit();
    zstd.writeFrameForSlice(&out.writer, payload, null) catch {
        return .{ .bytes = try allocator.dupe(u8, payload), .uncompressed = true };
    };
    const compressed = out.written();
    if (compressed.len < payload.len) {
        return .{ .bytes = try allocator.dupe(u8, compressed), .uncompressed = false };
    }
    return .{ .bytes = try allocator.dupe(u8, payload), .uncompressed = true };
}

/// Streams uncompressed metadata into a sequence of 8 KiB SquashFS metadata
/// blocks. `currentRef` yields the (block, offset) reference of the next byte
/// to be written, matching the inode/directory reference encoding the reader
/// resolves.
const MetaWriter = struct {
    allocator: std.mem.Allocator,
    compress: bool,
    out: std.array_list.Managed(u8),
    block: std.array_list.Managed(u8),
    block_starts: std.array_list.Managed(u64),

    fn init(allocator: std.mem.Allocator, compress: bool) MetaWriter {
        return .{
            .allocator = allocator,
            .compress = compress,
            .out = std.array_list.Managed(u8).init(allocator),
            .block = std.array_list.Managed(u8).init(allocator),
            .block_starts = std.array_list.Managed(u64).init(allocator),
        };
    }

    fn deinit(self: *MetaWriter) void {
        self.out.deinit();
        self.block.deinit();
        self.block_starts.deinit();
    }

    const Ref = struct { block: u32, offset: u16 };

    fn currentRef(self: *const MetaWriter) Ref {
        return .{ .block = @intCast(self.out.items.len), .offset = @intCast(self.block.items.len) };
    }

    fn write(self: *MetaWriter, bytes: []const u8) !void {
        try self.block.appendSlice(bytes);
        while (self.block.items.len >= metadata_block_size) {
            try self.emitBlock(self.block.items[0..metadata_block_size]);
            const remainder = self.block.items.len - metadata_block_size;
            std.mem.copyForwards(u8, self.block.items[0..remainder], self.block.items[metadata_block_size..]);
            self.block.shrinkRetainingCapacity(remainder);
        }
    }

    fn finish(self: *MetaWriter) !void {
        if (self.block.items.len > 0) {
            try self.emitBlock(self.block.items);
            self.block.clearRetainingCapacity();
        }
    }

    fn emitBlock(self: *MetaWriter, payload: []const u8) !void {
        try self.block_starts.append(self.out.items.len);
        const stored = try compressBlock(self.allocator, self.compress, payload);
        defer self.allocator.free(stored.bytes);
        const header: u16 = if (stored.uncompressed)
            @as(u16, @intCast(stored.bytes.len)) | metadata_uncompressed_bit
        else
            @intCast(stored.bytes.len);
        try appendU16Le(&self.out, header);
        try self.out.appendSlice(stored.bytes);
    }
};

const Writer = struct {
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: Io,
    file: Io.File,
    options: WriteOptions,
    compress: bool,
    cursor: u64 = 0,

    nodes: []BuildNode = &.{},
    root_ref: u64 = 0,

    inode_table: MetaWriter,
    directory_table: MetaWriter,
    fragments: std.array_list.Managed(FragmentRecord),
    ids: std.array_list.Managed(u32),
    fragment_buffer: std.array_list.Managed(u8),
    read_buffer: []u8 = &.{},

    fn deinit(self: *Writer) void {
        self.inode_table.deinit();
        self.directory_table.deinit();
        self.fragments.deinit();
        self.ids.deinit();
        self.fragment_buffer.deinit();
        if (self.read_buffer.len != 0) self.allocator.free(self.read_buffer);
    }

    fn run(self: *Writer, source: TreeSource) anyerror!WriteResult {
        try self.buildTree(source);

        var counter: u32 = 0;
        assignInodeNumbers(self.nodes, 0, &counter);
        self.nodes[0].parent_inode = @intCast(self.nodes.len + 1);

        self.read_buffer = try self.allocator.alloc(u8, self.options.block_size);
        self.cursor = superblock_size;

        // Data pass: stream every regular file, packing tails into fragments.
        for (self.nodes) |*node| {
            if (node.kind == .file) try self.writeFileData(source, node);
        }
        try self.flushFragment();

        // Inode + directory tables, post-order so children precede parents.
        try self.writeSubtree(0);
        self.root_ref = self.nodes[0].inode_ref;
        try self.inode_table.finish();
        try self.directory_table.finish();
        // Guarantee a resolvable directory block for empty directories.
        if (self.directory_table.out.items.len == 0) try self.directory_table.write(&.{0});
        try self.directory_table.finish();

        const inode_table_start = self.cursor;
        try self.writeRaw(self.inode_table.out.items);
        const directory_table_start = self.cursor;
        try self.writeRaw(self.directory_table.out.items);

        const fragment_table_start = if (self.fragments.items.len > 0)
            try self.writeFragmentTable()
        else
            invalid_table;

        const id_table_start = try self.writeIdTable();

        const bytes_used = self.cursor;
        try self.writeSuperblock(.{
            .inode_table_start = inode_table_start,
            .directory_table_start = directory_table_start,
            .fragment_table_start = fragment_table_start,
            .id_table_start = id_table_start,
            .bytes_used = bytes_used,
        });

        return .{
            .bytes_written = bytes_used,
            .inode_count = @intCast(self.nodes.len),
            .fragment_count = @intCast(self.fragments.items.len),
        };
    }

    fn buildTree(self: *Writer, source: TreeSource) anyerror!void {
        const total = source.count();
        const Collected = struct { index: usize, node: SourceNode };
        var collected = try std.array_list.Managed(Collected).initCapacity(self.arena, total);
        var i: usize = 0;
        while (i < total) : (i += 1) {
            collected.appendAssumeCapacity(.{ .index = i, .node = try source.node(i) });
        }
        std.mem.sort(Collected, collected.items, {}, struct {
            fn less(_: void, a: Collected, b: Collected) bool {
                return std.mem.lessThan(u8, a.node.path, b.node.path);
            }
        }.less);

        var nodes = std.array_list.Managed(BuildNode).init(self.arena);
        var map = std.StringHashMap(usize).init(self.arena);

        const root = source.root();
        try nodes.append(.{
            .kind = .directory,
            .name = "",
            .mode = root.mode,
            .uid = root.uid,
            .gid = root.gid,
            .mtime = root.mtime,
            .file_size = 0,
            .symlink_target = &.{},
            .source_index = null,
            .children = std.array_list.Managed(usize).init(self.arena),
        });
        try map.put("", 0);

        for (collected.items) |item| {
            const sn = item.node;
            var path = sn.path;
            while (path.len > 0 and path[0] == '/') path = path[1..];
            if (path.len == 0) return error.InvalidPath;

            const parent_path, const name = splitLast(path);
            if (name.len == 0 or name.len > 256) return error.NameTooLong;
            const parent_index = map.get(parent_path) orelse return error.MissingParentDirectory;
            if (map.contains(path)) return error.DuplicatePath;

            // Symlink targets may be handed over as a borrowed slice or, when a
            // source only exposes them through its content channel (RootTree
            // spools them), pulled via `read`. Either way we copy into the
            // arena so the bytes stay valid until the inode is emitted.
            const symlink_target: []const u8 = if (sn.kind == .symlink) blk: {
                const target = if (sn.symlink_target.len > 0)
                    try self.arena.dupe(u8, sn.symlink_target)
                else target_blk: {
                    const buffer = try self.arena.alloc(u8, @intCast(sn.size));
                    try self.readExact(source, item.index, buffer, 0);
                    break :target_blk buffer;
                };
                if (target.len > std.math.maxInt(u16)) return error.SymlinkTargetTooLong;
                break :blk target;
            } else &.{};

            const new_index = nodes.items.len;
            try nodes.append(.{
                .kind = sn.kind,
                .name = name,
                .mode = sn.mode,
                .uid = sn.uid,
                .gid = sn.gid,
                .mtime = sn.mtime,
                .file_size = if (sn.kind == .file) sn.size else 0,
                .symlink_target = symlink_target,
                .source_index = item.index,
                .children = std.array_list.Managed(usize).init(self.arena),
            });
            try map.put(path, new_index);
            try nodes.items[parent_index].children.append(new_index);
        }

        self.nodes = nodes.items;
        for (self.nodes) |*node| {
            std.mem.sort(usize, node.children.items, self.nodes, childNameLess);
        }
    }

    fn writeFileData(self: *Writer, source: TreeSource, node: *BuildNode) anyerror!void {
        const source_index = node.source_index.?;
        const block_size: u64 = self.options.block_size;
        const size = node.file_size;
        const full_blocks: usize = @intCast(size / block_size);
        const remainder: usize = @intCast(size % block_size);
        const tail_as_fragment = self.options.use_fragments and remainder > 0;
        const block_count = full_blocks + (if (remainder > 0 and !tail_as_fragment) @as(usize, 1) else 0);

        node.data_start = self.cursor;
        node.block_sizes = try self.arena.alloc(u32, block_count);

        var offset: u64 = 0;
        var block_index: usize = 0;
        while (block_index < full_blocks) : (block_index += 1) {
            try self.readExact(source, source_index, self.read_buffer[0..self.options.block_size], offset);
            node.block_sizes[block_index] = try self.storeDataBlock(self.read_buffer[0..self.options.block_size]);
            offset += block_size;
        }

        if (remainder > 0) {
            try self.readExact(source, source_index, self.read_buffer[0..remainder], offset);
            if (tail_as_fragment) {
                const placement = try self.addFragment(self.read_buffer[0..remainder]);
                node.fragment_index = placement.index;
                node.fragment_offset = placement.offset;
            } else {
                node.block_sizes[full_blocks] = try self.storeDataBlock(self.read_buffer[0..remainder]);
                node.fragment_index = invalid_fragment;
            }
        } else {
            node.fragment_index = invalid_fragment;
        }
    }

    fn readExact(self: *Writer, source: TreeSource, index: usize, buffer: []u8, offset: u64) anyerror!void {
        _ = self;
        var done: usize = 0;
        while (done < buffer.len) {
            const got = try source.read(index, buffer[done..], offset + done);
            if (got == 0) return error.ContentReadShort;
            done += got;
        }
    }

    fn storeDataBlock(self: *Writer, payload: []const u8) anyerror!u32 {
        const stored = try compressBlock(self.allocator, self.compress, payload);
        defer self.allocator.free(stored.bytes);
        try self.writeRaw(stored.bytes);
        const raw: u32 = @intCast(stored.bytes.len);
        return if (stored.uncompressed) raw | data_uncompressed_bit else raw;
    }

    const FragmentPlacement = struct { index: u32, offset: u32 };

    fn addFragment(self: *Writer, tail: []const u8) anyerror!FragmentPlacement {
        if (self.fragment_buffer.items.len + tail.len > self.options.block_size) {
            try self.flushFragment();
        }
        const placement = FragmentPlacement{
            .index = @intCast(self.fragments.items.len),
            .offset = @intCast(self.fragment_buffer.items.len),
        };
        try self.fragment_buffer.appendSlice(tail);
        return placement;
    }

    fn flushFragment(self: *Writer) anyerror!void {
        if (self.fragment_buffer.items.len == 0) return;
        const start = self.cursor;
        const size_field = try self.storeDataBlock(self.fragment_buffer.items);
        try self.fragments.append(.{ .start_block = start, .size_field = size_field });
        self.fragment_buffer.clearRetainingCapacity();
    }

    fn writeSubtree(self: *Writer, node_index: usize) anyerror!void {
        // Children first: leaf inodes and subdirectory inodes must exist before
        // this directory's listing can reference them.
        for (self.nodes[node_index].children.items) |child_index| {
            switch (self.nodes[child_index].kind) {
                .directory => try self.writeSubtree(child_index),
                .file, .symlink => try self.writeLeafInode(child_index),
            }
        }
        try self.writeDirectory(node_index);
    }

    fn writeLeafInode(self: *Writer, node_index: usize) anyerror!void {
        switch (self.nodes[node_index].kind) {
            .file => try self.writeFileInode(node_index),
            .symlink => try self.writeSymlinkInode(node_index),
            .directory => unreachable,
        }
    }

    fn writeFileInode(self: *Writer, node_index: usize) anyerror!void {
        const node = &self.nodes[node_index];
        const uid_index = try self.idIndex(node.uid);
        const gid_index = try self.idIndex(node.gid);
        const mode = fullMode(node.kind, node.mode);
        const extended = node.file_size > std.math.maxInt(u32) or node.data_start > std.math.maxInt(u32);

        var buf = std.array_list.Managed(u8).init(self.arena);
        defer buf.deinit();
        if (extended) {
            try appendU16Le(&buf, @intFromEnum(InodeType.ext_file));
            try appendU16Le(&buf, mode);
            try appendU16Le(&buf, uid_index);
            try appendU16Le(&buf, gid_index);
            try appendU32Le(&buf, node.mtime);
            try appendU32Le(&buf, node.inode_number);
            try appendU64Le(&buf, node.data_start);
            try appendU64Le(&buf, node.file_size);
            try appendU64Le(&buf, 0); // sparse
            try appendU32Le(&buf, 1); // nlink
            try appendU32Le(&buf, node.fragment_index);
            try appendU32Le(&buf, node.fragment_offset);
            try appendU32Le(&buf, no_xattr);
            node.entry_type = @intFromEnum(InodeType.ext_file);
        } else {
            try appendU16Le(&buf, @intFromEnum(InodeType.basic_file));
            try appendU16Le(&buf, mode);
            try appendU16Le(&buf, uid_index);
            try appendU16Le(&buf, gid_index);
            try appendU32Le(&buf, node.mtime);
            try appendU32Le(&buf, node.inode_number);
            try appendU32Le(&buf, @intCast(node.data_start));
            try appendU32Le(&buf, node.fragment_index);
            try appendU32Le(&buf, node.fragment_offset);
            try appendU32Le(&buf, @intCast(node.file_size));
            node.entry_type = @intFromEnum(InodeType.basic_file);
        }
        for (node.block_sizes) |size_field| try appendU32Le(&buf, size_field);

        node.inode_ref = self.inodeRefForNext();
        try self.inode_table.write(buf.items);
    }

    fn writeSymlinkInode(self: *Writer, node_index: usize) anyerror!void {
        const node = &self.nodes[node_index];
        const uid_index = try self.idIndex(node.uid);
        const gid_index = try self.idIndex(node.gid);
        const mode = fullMode(node.kind, node.mode);

        var buf = std.array_list.Managed(u8).init(self.arena);
        defer buf.deinit();
        try appendU16Le(&buf, @intFromEnum(InodeType.basic_symlink));
        try appendU16Le(&buf, mode);
        try appendU16Le(&buf, uid_index);
        try appendU16Le(&buf, gid_index);
        try appendU32Le(&buf, node.mtime);
        try appendU32Le(&buf, node.inode_number);
        try appendU32Le(&buf, 1); // nlink
        try appendU32Le(&buf, @intCast(node.symlink_target.len));
        try buf.appendSlice(node.symlink_target);
        node.entry_type = @intFromEnum(InodeType.basic_symlink);

        node.inode_ref = self.inodeRefForNext();
        try self.inode_table.write(buf.items);
    }

    fn writeDirectory(self: *Writer, node_index: usize) anyerror!void {
        try self.writeDirectoryListing(node_index);

        const node = &self.nodes[node_index];
        const uid_index = try self.idIndex(node.uid);
        const gid_index = try self.idIndex(node.gid);
        const mode = fullMode(node.kind, node.mode);
        var subdirs: u32 = 0;
        for (node.children.items) |child_index| {
            if (self.nodes[child_index].kind == .directory) subdirs += 1;
        }
        const nlink = subdirs + 2;
        const raw_size = node.dir_size + 3;
        const extended = raw_size > std.math.maxInt(u16);

        var buf = std.array_list.Managed(u8).init(self.arena);
        defer buf.deinit();
        if (extended) {
            try appendU16Le(&buf, @intFromEnum(InodeType.ext_dir));
            try appendU16Le(&buf, mode);
            try appendU16Le(&buf, uid_index);
            try appendU16Le(&buf, gid_index);
            try appendU32Le(&buf, node.mtime);
            try appendU32Le(&buf, node.inode_number);
            try appendU32Le(&buf, nlink);
            try appendU32Le(&buf, raw_size);
            try appendU32Le(&buf, node.dir_start_block);
            try appendU32Le(&buf, node.parent_inode);
            try appendU16Le(&buf, 0); // index count
            try appendU16Le(&buf, node.dir_offset);
            try appendU32Le(&buf, no_xattr);
            node.entry_type = @intFromEnum(InodeType.ext_dir);
        } else {
            try appendU16Le(&buf, @intFromEnum(InodeType.basic_dir));
            try appendU16Le(&buf, mode);
            try appendU16Le(&buf, uid_index);
            try appendU16Le(&buf, gid_index);
            try appendU32Le(&buf, node.mtime);
            try appendU32Le(&buf, node.inode_number);
            try appendU32Le(&buf, node.dir_start_block);
            try appendU32Le(&buf, nlink);
            try appendU16Le(&buf, @intCast(raw_size));
            try appendU16Le(&buf, node.dir_offset);
            try appendU32Le(&buf, node.parent_inode);
            node.entry_type = @intFromEnum(InodeType.basic_dir);
        }

        node.inode_ref = self.inodeRefForNext();
        try self.inode_table.write(buf.items);
    }

    fn writeDirectoryListing(self: *Writer, node_index: usize) anyerror!void {
        const children = self.nodes[node_index].children.items;
        if (children.len == 0) {
            self.nodes[node_index].dir_start_block = 0;
            self.nodes[node_index].dir_offset = 0;
            self.nodes[node_index].dir_size = 0;
            return;
        }

        var listing = std.array_list.Managed(u8).init(self.arena);
        defer listing.deinit();

        var i: usize = 0;
        while (i < children.len) {
            const first = self.nodes[children[i]];
            const group_block: u32 = @intCast(first.inode_ref >> 16);
            const base_inode = first.inode_number;

            var j = i;
            var count: usize = 0;
            while (j < children.len and count < 256) {
                const child = self.nodes[children[j]];
                if (@as(u32, @intCast(child.inode_ref >> 16)) != group_block) break;
                const delta = @as(i64, child.inode_number) - @as(i64, base_inode);
                if (delta < std.math.minInt(i16) or delta > std.math.maxInt(i16)) break;
                j += 1;
                count += 1;
            }

            try appendU32Le(&listing, @intCast(count - 1));
            try appendU32Le(&listing, group_block);
            try appendU32Le(&listing, base_inode);
            var k = i;
            while (k < j) : (k += 1) {
                const child = self.nodes[children[k]];
                const inode_offset: u16 = @intCast(child.inode_ref & 0xFFFF);
                const delta: i16 = @intCast(@as(i64, child.inode_number) - @as(i64, base_inode));
                try appendU16Le(&listing, inode_offset);
                try appendI16Le(&listing, delta);
                try appendU16Le(&listing, child.entry_type);
                try appendU16Le(&listing, @intCast(child.name.len - 1));
                try listing.appendSlice(child.name);
            }
            i = j;
        }

        const ref = self.directory_table.currentRef();
        self.nodes[node_index].dir_start_block = ref.block;
        self.nodes[node_index].dir_offset = ref.offset;
        self.nodes[node_index].dir_size = @intCast(listing.items.len);
        try self.directory_table.write(listing.items);
    }

    fn inodeRefForNext(self: *const Writer) u64 {
        const ref = self.inode_table.currentRef();
        return (@as(u64, ref.block) << 16) | ref.offset;
    }

    fn idIndex(self: *Writer, value: u32) !u16 {
        for (self.ids.items, 0..) |existing, index| {
            if (existing == value) return @intCast(index);
        }
        if (self.ids.items.len > std.math.maxInt(u16)) return error.TooManyIds;
        try self.ids.append(value);
        return @intCast(self.ids.items.len - 1);
    }

    fn writeFragmentTable(self: *Writer) anyerror!u64 {
        var payload = std.array_list.Managed(u8).init(self.arena);
        defer payload.deinit();
        for (self.fragments.items) |fragment| {
            try appendU64Le(&payload, fragment.start_block);
            try appendU32Le(&payload, fragment.size_field);
            try appendU32Le(&payload, 0); // unused
        }
        return self.writeIndexedMetaTable(payload.items);
    }

    fn writeIdTable(self: *Writer) anyerror!u64 {
        var payload = std.array_list.Managed(u8).init(self.arena);
        defer payload.deinit();
        for (self.ids.items) |id| try appendU32Le(&payload, id);
        return self.writeIndexedMetaTable(payload.items);
    }

    fn writeIndexedMetaTable(self: *Writer, payload: []const u8) anyerror!u64 {
        var meta = MetaWriter.init(self.allocator, self.compress);
        defer meta.deinit();
        try meta.write(payload);
        try meta.finish();

        const meta_image_start = self.cursor;
        try self.writeRaw(meta.out.items);

        const index_table_start = self.cursor;
        for (meta.block_starts.items) |relative| {
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, meta_image_start + relative, .little);
            try self.writeRaw(&buf);
        }
        return index_table_start;
    }

    fn writeRaw(self: *Writer, bytes: []const u8) anyerror!void {
        if (bytes.len == 0) return;
        try self.file.writePositionalAll(self.io, bytes, self.cursor);
        self.cursor += bytes.len;
    }

    const SuperblockLayout = struct {
        inode_table_start: u64,
        directory_table_start: u64,
        fragment_table_start: u64,
        id_table_start: u64,
        bytes_used: u64,
    };

    fn writeSuperblock(self: *Writer, layout: SuperblockLayout) anyerror!void {
        const block_log: u16 = @intCast(std.math.log2_int(u32, self.options.block_size));
        const compression_id: u16 = switch (self.options.compression) {
            .none => @intFromEnum(Compression.gzip),
            .zstd => @intFromEnum(Compression.zstd),
        };
        var flags: u16 = no_xattrs_flag;
        if (self.options.compression == .none) {
            flags |= uncompressed_inodes_flag | uncompressed_data_flag |
                uncompressed_fragments_flag | uncompressed_ids_flag;
        }
        if (self.fragments.items.len == 0) flags |= no_fragments_flag;

        var sb: [superblock_size]u8 = undefined;
        @memset(&sb, 0);
        std.mem.writeInt(u32, sb[0..4], magic, .little);
        std.mem.writeInt(u32, sb[4..8], @intCast(self.nodes.len), .little);
        std.mem.writeInt(u32, sb[8..12], self.options.mtime, .little);
        std.mem.writeInt(u32, sb[12..16], self.options.block_size, .little);
        std.mem.writeInt(u32, sb[16..20], @intCast(self.fragments.items.len), .little);
        std.mem.writeInt(u16, sb[20..22], compression_id, .little);
        std.mem.writeInt(u16, sb[22..24], block_log, .little);
        std.mem.writeInt(u16, sb[24..26], flags, .little);
        std.mem.writeInt(u16, sb[26..28], @intCast(self.ids.items.len), .little);
        std.mem.writeInt(u16, sb[28..30], major_version, .little);
        std.mem.writeInt(u16, sb[30..32], 0, .little);
        std.mem.writeInt(u64, sb[32..40], self.root_ref, .little);
        std.mem.writeInt(u64, sb[40..48], layout.bytes_used, .little);
        std.mem.writeInt(u64, sb[48..56], layout.id_table_start, .little);
        std.mem.writeInt(u64, sb[56..64], invalid_table, .little);
        std.mem.writeInt(u64, sb[64..72], layout.inode_table_start, .little);
        std.mem.writeInt(u64, sb[72..80], layout.directory_table_start, .little);
        std.mem.writeInt(u64, sb[80..88], layout.fragment_table_start, .little);
        std.mem.writeInt(u64, sb[88..96], invalid_table, .little);
        try self.file.writePositionalAll(self.io, &sb, 0);
    }
};

const superblock_size: usize = 96;
const no_xattr: u32 = 0xFFFF_FFFF;
const uncompressed_inodes_flag: u16 = 0x0001;
const uncompressed_data_flag: u16 = 0x0002;
const uncompressed_fragments_flag: u16 = 0x0008;
const no_fragments_flag: u16 = 0x0010;
const no_xattrs_flag: u16 = 0x0200;
const uncompressed_ids_flag: u16 = 0x0800;

const InodeType = enum(u16) {
    basic_dir = 1,
    basic_file = 2,
    basic_symlink = 3,
    ext_dir = 8,
    ext_file = 9,
    ext_symlink = 10,
};

fn fullMode(kind: SourceKind, mode: u16) u16 {
    const type_bits: u16 = switch (kind) {
        .directory => 0o040000,
        .file => 0o100000,
        .symlink => 0o120000,
    };
    return (mode & 0o7777) | type_bits;
}

fn splitLast(path: []const u8) struct { []const u8, []const u8 } {
    const separator = std.mem.lastIndexOfScalar(u8, path, '/') orelse return .{ "", path };
    return .{ path[0..separator], path[separator + 1 ..] };
}

fn childNameLess(nodes: []BuildNode, a: usize, b: usize) bool {
    return std.mem.lessThan(u8, nodes[a].name, nodes[b].name);
}

fn assignInodeNumbers(nodes: []BuildNode, index: usize, counter: *u32) void {
    counter.* += 1;
    nodes[index].inode_number = counter.*;
    for (nodes[index].children.items) |child_index| {
        nodes[child_index].parent_inode = nodes[index].inode_number;
        assignInodeNumbers(nodes, child_index, counter);
    }
}

fn appendI16Le(list: *std.array_list.Managed(u8), value: i16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(i16, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn appendU16Le(list: *std.array_list.Managed(u8), value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn appendU32Le(list: *std.array_list.Managed(u8), value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn appendU64Le(list: *std.array_list.Managed(u8), value: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn appendMetadataBlock(allocator: std.mem.Allocator, list: *std.array_list.Managed(u8), compression: SyntheticCompression, payload: []const u8) !void {
    const stored = try compressSyntheticBytes(allocator, compression, payload);
    defer allocator.free(stored);

    const header_value: u16 = if (compression == .none)
        @as(u16, @intCast(stored.len)) | metadata_uncompressed_bit
    else
        @intCast(stored.len);
    try appendU16Le(list, header_value);
    try list.appendSlice(stored);
}

fn compressSyntheticBytes(allocator: std.mem.Allocator, compression: SyntheticCompression, payload: []const u8) ![]u8 {
    return switch (compression) {
        .none => allocator.dupe(u8, payload),
        .xz => compressSyntheticXz(allocator, payload),
        .zstd => compressSyntheticZstd(allocator, payload),
    };
}

fn compressSyntheticXz(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(payload.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, payload);
    const script =
        \\import base64
        \\import lzma
        \\import sys
        \\sys.stdout.buffer.write(lzma.compress(base64.b64decode(sys.argv[1]), format=lzma.FORMAT_XZ))
    ;
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "python3", "-c", script, encoded },
        .cwd = .{ .path = "." },
    });
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);
    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }
    allocator.free(result.stdout);
    return error.ExternalCompressionFailed;
}

fn compressSyntheticZstd(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), payload.len));
    errdefer out.deinit();
    try zstd.writeRawFrameForSlice(&out.writer, payload, null);
    return out.toOwnedSlice();
}

pub fn buildSyntheticSquashfsImage(allocator: std.mem.Allocator, options: SyntheticImageOptions) ![]u8 {
    std.debug.assert(options.block_size != 0);
    std.debug.assert(std.math.isPowerOfTwo(options.block_size));

    const block_size = options.block_size;
    const block_size_usize: usize = @intCast(block_size);
    const block_log: u16 = @intCast(std.math.log2_int(u32, block_size));
    const full_data_block_count: usize = if (options.file_bytes) |bytes|
        bytes.len / block_size_usize
    else
        @intCast(options.full_data_blocks);
    const fragment_tail_size: usize = if (options.file_bytes) |bytes|
        bytes.len % block_size_usize
    else
        @intCast(options.fragment_tail_size);
    const compression_id: u16 = switch (options.compression) {
        .none => @intFromEnum(Compression.gzip),
        .xz => @intFromEnum(Compression.xz),
        .zstd => @intFromEnum(Compression.zstd),
    };
    const compressor_options_len: usize = if (options.compression == .xz) 8 else 0;
    const data_block_start: u64 = 96 + compressor_options_len;

    const full_block_bytes = try allocator.alloc(u8, block_size_usize);
    defer allocator.free(full_block_bytes);
    const stored_full_blocks = try allocator.alloc(?[]u8, full_data_block_count);
    @memset(stored_full_blocks, null);
    defer {
        for (stored_full_blocks) |stored_full_block| {
            if (stored_full_block) |bytes| allocator.free(bytes);
        }
        allocator.free(stored_full_blocks);
    }
    for (stored_full_blocks, 0..) |*stored_full_block, block_index| {
        const block_payload = if (options.file_bytes) |bytes|
            bytes[block_index * block_size_usize ..][0..block_size_usize]
        else blk: {
            @memset(full_block_bytes, syntheticFullBlockByte(block_index));
            break :blk full_block_bytes[0..];
        };
        stored_full_block.* = try compressSyntheticBytes(allocator, options.compression, block_payload);
    }
    const fragment_data_start: u64 = blk: {
        var stored_len: u64 = data_block_start;
        for (stored_full_blocks) |stored_full_block| stored_len += stored_full_block.?.len;
        break :blk stored_len;
    };

    const stored_fragment_tail: ?[]u8 = if (fragment_tail_size == 0)
        null
    else blk: {
        const fragment_tail = try allocator.alloc(u8, fragment_tail_size);
        defer allocator.free(fragment_tail);
        if (options.file_bytes) |bytes| {
            @memcpy(fragment_tail, bytes[full_data_block_count * block_size_usize ..][0..fragment_tail_size]);
        } else {
            @memset(fragment_tail, syntheticFragmentByte(full_data_block_count));
        }
        break :blk try compressSyntheticBytes(allocator, options.compression, fragment_tail);
    };
    defer if (stored_fragment_tail) |bytes| allocator.free(bytes);

    const file_size: u64 = if (options.file_bytes) |bytes|
        bytes.len
    else
        @as(u64, options.full_data_blocks) * @as(u64, block_size) + @as(u64, options.fragment_tail_size);
    const fragment_index: u32 = if (fragment_tail_size == 0) invalid_fragment else 0;

    var inode_payload = std.array_list.Managed(u8).init(allocator);
    defer inode_payload.deinit();

    const root_inode_offset: u16 = @intCast(inode_payload.items.len);
    _ = root_inode_offset;
    try appendU16Le(&inode_payload, 1);
    try appendU16Le(&inode_payload, 0o755);
    try appendU16Le(&inode_payload, 0);
    try appendU16Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 1);
    try appendU32Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 2);
    try appendU16Le(&inode_payload, 26);
    try appendU16Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 1);

    const nested_inode_offset: u16 = @intCast(inode_payload.items.len);
    try appendU16Le(&inode_payload, 1);
    try appendU16Le(&inode_payload, 0o755);
    try appendU16Le(&inode_payload, 0);
    try appendU16Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 2);
    try appendU32Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 2);
    try appendU16Le(&inode_payload, 34);
    try appendU16Le(&inode_payload, 23);
    try appendU32Le(&inode_payload, 1);

    const file_inode_offset: u16 = @intCast(inode_payload.items.len);
    try appendU16Le(&inode_payload, 2);
    try appendU16Le(&inode_payload, 0o644);
    try appendU16Le(&inode_payload, 0);
    try appendU16Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, 3);
    try appendU32Le(&inode_payload, @intCast(data_block_start));
    try appendU32Le(&inode_payload, fragment_index);
    try appendU32Le(&inode_payload, 0);
    try appendU32Le(&inode_payload, @intCast(file_size));
    for (stored_full_blocks) |stored_full_block| {
        try appendU32Le(&inode_payload, if (options.compression == .none)
            block_size | data_uncompressed_bit
        else
            @as(u32, @intCast(stored_full_block.?.len)));
    }

    var dir_payload = std.array_list.Managed(u8).init(allocator);
    defer dir_payload.deinit();
    try appendU32Le(&dir_payload, 0);
    try appendU32Le(&dir_payload, 0);
    try appendU32Le(&dir_payload, 2);
    try appendU16Le(&dir_payload, nested_inode_offset);
    try appendU16Le(&dir_payload, 0);
    try appendU16Le(&dir_payload, 1);
    try appendU16Le(&dir_payload, 2);
    try dir_payload.appendSlice("etc");

    try appendU32Le(&dir_payload, 0);
    try appendU32Le(&dir_payload, 0);
    try appendU32Le(&dir_payload, 3);
    try appendU16Le(&dir_payload, file_inode_offset);
    try appendU16Le(&dir_payload, 0);
    try appendU16Le(&dir_payload, 2);
    try appendU16Le(&dir_payload, 10);
    try dir_payload.appendSlice("message.txt");

    var fragment_payload = std.array_list.Managed(u8).init(allocator);
    defer fragment_payload.deinit();
    if (stored_fragment_tail) |bytes| {
        try appendU64Le(&fragment_payload, fragment_data_start);
        try appendU32Le(&fragment_payload, if (options.compression == .none)
            options.fragment_tail_size | data_uncompressed_bit
        else
            @as(u32, @intCast(bytes.len)));
        try appendU32Le(&fragment_payload, 0);
    }

    var id_payload = std.array_list.Managed(u8).init(allocator);
    defer id_payload.deinit();
    try appendU32Le(&id_payload, 0);

    var image = std.array_list.Managed(u8).init(allocator);
    errdefer image.deinit();
    try image.resize(96);
    @memset(image.items, 0);
    if (options.compression == .xz) {
        try appendU32Le(&image, block_size);
        try appendU32Le(&image, 0);
    }
    for (stored_full_blocks) |stored_full_block| try image.appendSlice(stored_full_block.?);
    if (stored_fragment_tail) |bytes| try image.appendSlice(bytes);

    const inode_table_start: u64 = image.items.len;
    try appendMetadataBlock(allocator, &image, options.compression, inode_payload.items);
    const directory_table_start: u64 = image.items.len;
    try appendMetadataBlock(allocator, &image, options.compression, dir_payload.items);
    const fragment_meta_start: u64 = if (stored_fragment_tail != null) blk: {
        const start = image.items.len;
        try appendMetadataBlock(allocator, &image, options.compression, fragment_payload.items);
        break :blk start;
    } else invalid_table;
    const fragment_table_start: u64 = if (stored_fragment_tail != null) blk: {
        const start = image.items.len;
        try appendU64Le(&image, fragment_meta_start);
        break :blk start;
    } else invalid_table;
    const id_meta_start: u64 = image.items.len;
    try appendMetadataBlock(allocator, &image, options.compression, id_payload.items);
    const id_table_start: u64 = image.items.len;
    try appendU64Le(&image, id_meta_start);
    const bytes_used: u64 = image.items.len;

    std.mem.writeInt(u32, image.items[0..4], magic, .little);
    std.mem.writeInt(u32, image.items[4..8], 3, .little);
    std.mem.writeInt(u32, image.items[8..12], 0, .little);
    std.mem.writeInt(u32, image.items[12..16], block_size, .little);
    std.mem.writeInt(u32, image.items[16..20], if (stored_fragment_tail == null) 0 else 1, .little);
    std.mem.writeInt(u16, image.items[20..22], compression_id, .little);
    std.mem.writeInt(u16, image.items[22..24], block_log, .little);
    std.mem.writeInt(u16, image.items[24..26], if (options.compression == .xz) 0b1011 | compressor_options_flag else 0b1011, .little);
    std.mem.writeInt(u16, image.items[26..28], 1, .little);
    std.mem.writeInt(u16, image.items[28..30], major_version, .little);
    std.mem.writeInt(u16, image.items[30..32], 0, .little);
    std.mem.writeInt(u64, image.items[32..40], 0, .little);
    std.mem.writeInt(u64, image.items[40..48], bytes_used, .little);
    std.mem.writeInt(u64, image.items[48..56], id_table_start, .little);
    std.mem.writeInt(u64, image.items[56..64], invalid_table, .little);
    std.mem.writeInt(u64, image.items[64..72], inode_table_start, .little);
    std.mem.writeInt(u64, image.items[72..80], directory_table_start, .little);
    std.mem.writeInt(u64, image.items[80..88], fragment_table_start, .little);
    std.mem.writeInt(u64, image.items[88..96], invalid_table, .little);

    return image.toOwnedSlice();
}

fn syntheticFullBlockByte(block_index: usize) u8 {
    return @as(u8, 'A') + @as(u8, @intCast(block_index % 26));
}

fn syntheticFragmentByte(full_data_block_count: usize) u8 {
    return @as(u8, 'A') + @as(u8, @intCast(full_data_block_count % 26));
}

fn buildExpectedSyntheticFileBytesAlloc(allocator: std.mem.Allocator, options: SyntheticImageOptions) ![]u8 {
    if (options.file_bytes) |bytes| return allocator.dupe(u8, bytes);

    const block_size: usize = @intCast(options.block_size);
    const full_data_block_count: usize = @intCast(options.full_data_blocks);
    const fragment_tail_size: usize = @intCast(options.fragment_tail_size);

    const total_len = full_data_block_count * block_size + fragment_tail_size;
    const bytes = try allocator.alloc(u8, total_len);
    var offset: usize = 0;

    for (0..full_data_block_count) |block_index| {
        @memset(bytes[offset..][0..block_size], syntheticFullBlockByte(block_index));
        offset += block_size;
    }

    if (fragment_tail_size > 0) {
        @memset(bytes[offset..][0..fragment_tail_size], syntheticFragmentByte(full_data_block_count));
    }
    return bytes;
}

fn writeFixture(path: []const u8, bytes: []const u8) !void {
    const io = std.testing.io;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

fn expectSyntheticReaderRoundTrip(compression: SyntheticCompression, path: []const u8) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const options = SyntheticImageOptions{ .compression = compression };
    const image = try buildSyntheticSquashfsImage(allocator, options);
    defer allocator.free(image);
    try writeFixture(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try std.testing.expectEqual(@as(u32, 1024), reader.superblock.block_size);
    try std.testing.expectEqual(@as(usize, 1), reader.fragments.len);
    try std.testing.expectEqual(compression == .xz, reader.compressor_options != null);
    if (reader.compressor_options) |compressor_options| switch (compressor_options) {
        .xz => |xz_options| {
            try std.testing.expectEqual(@as(u32, 1024), xz_options.dictionary_size);
            try std.testing.expectEqual(@as(u32, 0), xz_options.flags);
        },
    };

    const dir_index = try reader.lookup("/etc");
    try std.testing.expectEqual(EntryKind.directory, reader.getEntry(dir_index).kind);

    const file_index = try reader.lookup("/etc/message.txt");
    const contents = try reader.readFileAlloc(allocator, io, file_index);
    defer allocator.free(contents);
    const expected = try buildExpectedSyntheticFileBytesAlloc(allocator, options);
    defer allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, contents);

    const root_entries = try reader.listDirAlloc(allocator, reader.root_index);
    defer allocator.free(root_entries);
    try std.testing.expectEqual(@as(usize, 1), root_entries.len);
    try std.testing.expectEqualStrings("etc", root_entries[0].name);
}

fn expectSequentialReadCaching(compression: SyntheticCompression, path: []const u8) !void {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const options = SyntheticImageOptions{
        .compression = compression,
        .block_size = 64 * 1024,
        .full_data_blocks = 48,
        .fragment_tail_size = 8192,
    };
    const image = try buildSyntheticSquashfsImage(allocator, options);
    defer allocator.free(image);
    try writeFixture(path, image);

    const expected = try buildExpectedSyntheticFileBytesAlloc(allocator, options);
    defer allocator.free(expected);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    const file_index = try reader.lookup("/etc/message.txt");
    const actual = try allocator.alloc(u8, expected.len);
    defer allocator.free(actual);

    const chunk_size = 4096;
    var offset: usize = 0;
    while (offset < expected.len) {
        const want = @min(chunk_size, expected.len - offset);
        const got = try reader.readFileAt(allocator, io, file_index, actual[offset..][0..want], offset);
        try std.testing.expectEqual(want, got);
        offset += got;
    }

    try std.testing.expectEqualSlices(u8, expected, actual);

    const stats = reader.cacheStats();
    try std.testing.expectEqual(@as(usize, @intCast(options.full_data_blocks)), stats.data_block_decompressions);
    try std.testing.expectEqual(@as(usize, 1), stats.fragment_block_decompressions);
}

test "squashfs reader enumerates nested directories and extracts fragment-backed file" {
    try expectSyntheticReaderRoundTrip(.none, "test-squashfs-uncompressed.sqsh");
}

test "squashfs reader decodes xz-compressed metadata data and fragments" {
    try expectSyntheticReaderRoundTrip(.xz, "test-squashfs-xz.sqsh");
}

test "squashfs reader decodes zstd-compressed metadata data and fragments" {
    try expectSyntheticReaderRoundTrip(.zstd, "test-squashfs-zstd.sqsh");
}

test "squashfs reader caches repeated sequential reads within compressed data and fragment blocks" {
    try expectSequentialReadCaching(.xz, "test-squashfs-read-cache.sqsh");
}

test "xz decompressor supports x86 BCJ + LZMA2 filter chains" {
    const encoded = [_]u8{
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
        0x02, 0x01, 0x04, 0x00, 0x21, 0x01, 0x16, 0x00, 0x0d, 0x86, 0x35, 0x1f,
        0xe0, 0x01, 0xff, 0x00, 0x6a, 0x5d, 0x00, 0x48, 0x39, 0xfc, 0xc0, 0xf8,
        0x06, 0x62, 0xee, 0x42, 0x66, 0xad, 0x64, 0x13, 0x30, 0x3e, 0xec, 0xd9,
        0x09, 0xa6, 0x85, 0x0c, 0x1f, 0xbd, 0xfd, 0x4c, 0xa3, 0x85, 0x1e, 0x8b,
        0x8a, 0xdd, 0x6c, 0x96, 0x2b, 0x81, 0x1c, 0x58, 0xa2, 0xab, 0xb2, 0xf3,
        0xb8, 0xd9, 0x2b, 0x07, 0x5f, 0x1b, 0x64, 0x4d, 0x9f, 0x1e, 0xed, 0x49,
        0x14, 0x2f, 0x20, 0x57, 0xd1, 0x28, 0x94, 0xcb, 0x5b, 0x8d, 0x8f, 0xe9,
        0x00, 0xfe, 0xa6, 0xdf, 0x95, 0xec, 0xc5, 0xd5, 0x63, 0x74, 0xcc, 0xf4,
        0xbc, 0xfc, 0x2a, 0x3d, 0x90, 0x51, 0x1b, 0x3e, 0x68, 0xa3, 0x1f, 0xd0,
        0xb3, 0x65, 0xb4, 0xba, 0x9a, 0x1a, 0xde, 0x99, 0x43, 0x50, 0xe2, 0xc8,
        0x5e, 0xd6, 0xdc, 0x85, 0x00, 0x00, 0x00, 0x00, 0x4b, 0x8b, 0x09, 0xc0,
        0x6d, 0xcd, 0x02, 0x51, 0x00, 0x01, 0x86, 0x01, 0x80, 0x04, 0x00, 0x00,
        0x4f, 0x14, 0x8c, 0xdc, 0xb1, 0xc4, 0x67, 0xfb, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x59, 0x5a,
    };
    var expected: [512]u8 = undefined;
    var offset: usize = 0;
    while (offset < expected.len) : (offset += 16) {
        expected[offset..][0..16].* = .{
            0x90,                               0xE8,
            @truncate((0x1000 + offset) >> 0),  @truncate((0x1000 + offset) >> 8),
            @truncate((0x1000 + offset) >> 16), @truncate((0x1000 + offset) >> 24),
            0x90,                               0xE9,
            @truncate((0x2000 + offset) >> 0),  @truncate((0x2000 + offset) >> 8),
            @truncate((0x2000 + offset) >> 16), @truncate((0x2000 + offset) >> 24),
            0x90,                               0x90,
            0xCC,                               0x90,
        };
    }

    const decoded = try decompressXzAlloc(std.testing.allocator, &encoded, expected.len);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &expected, decoded);
}

// ===========================================================================
// Writer tests
// ===========================================================================

const TestNode = struct {
    path: []const u8,
    kind: SourceKind,
    mode: u16,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: u32 = 0,
    content: []const u8 = &.{},
    target: []const u8 = &.{},
};

const TestSource = struct {
    root_meta: SourceRoot = .{},
    nodes: []const TestNode,

    fn cast(context: *const anyopaque) *const TestSource {
        return @ptrCast(@alignCast(context));
    }

    fn source(self: *const TestSource) TreeSource {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable = TreeSource.VTable{
        .root = rootFn,
        .count = countFn,
        .node = nodeFn,
        .read = readFn,
    };

    fn rootFn(context: *const anyopaque) SourceRoot {
        return cast(context).root_meta;
    }
    fn countFn(context: *const anyopaque) usize {
        return cast(context).nodes.len;
    }
    fn nodeFn(context: *const anyopaque, index: usize) anyerror!SourceNode {
        const node = cast(context).nodes[index];
        return .{
            .path = node.path,
            .kind = node.kind,
            .mode = node.mode,
            .uid = node.uid,
            .gid = node.gid,
            .mtime = node.mtime,
            .size = node.content.len,
            .symlink_target = node.target,
        };
    }
    fn readFn(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        const node = cast(context).nodes[index];
        if (offset >= node.content.len) return 0;
        const want: usize = @intCast(@min(@as(u64, buffer.len), node.content.len - offset));
        @memcpy(buffer[0..want], node.content[@intCast(offset)..][0..want]);
        return want;
    }
};

fn buildTestImageAlloc(
    allocator: std.mem.Allocator,
    source: TreeSource,
    options: WriteOptions,
    path: []const u8,
) ![]u8 {
    const io = std.testing.io;
    _ = try writeImagePath(allocator, io, path, source, options);
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    const stat = try file.stat(io);
    const bytes = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(bytes);
    _ = try file.readPositionalAll(io, bytes, 0);
    return bytes;
}

test "squashfs writer round-trips nested directories, metadata, and a symlink" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-squashfs-writer-basic.sqsh";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "bin", .kind = .directory, .mode = 0o755 },
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .uid = 1000, .gid = 1001, .content = "NAME=miz\n" },
        .{ .path = "etc/nested", .kind = .directory, .mode = 0o700 },
        .{ .path = "etc/nested/hello.txt", .kind = .file, .mode = 0o600, .content = "hello world" },
        .{ .path = "bin/sh", .kind = .symlink, .mode = 0o777, .target = "busybox" },
    };
    var test_source = TestSource{ .nodes = &nodes };

    const result = try writeImagePath(allocator, io, path, test_source.source(), .{ .compression = .zstd });
    try std.testing.expectEqual(@as(u32, nodes.len + 1), result.inode_count);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    const etc = try reader.lookup("/etc");
    try std.testing.expectEqual(EntryKind.directory, reader.getEntry(etc).kind);

    const os_release = try reader.lookup("/etc/os-release");
    const os_entry = reader.getEntry(os_release);
    try std.testing.expectEqual(@as(u32, 0o644), os_entry.mode & 0o7777);
    try std.testing.expectEqual(@as(u32, 1000), os_entry.uid);
    try std.testing.expectEqual(@as(u32, 1001), os_entry.gid);
    const os_bytes = try reader.readFileAlloc(allocator, io, os_release);
    defer allocator.free(os_bytes);
    try std.testing.expectEqualStrings("NAME=miz\n", os_bytes);

    const hello = try reader.lookup("/etc/nested/hello.txt");
    const hello_bytes = try reader.readFileAlloc(allocator, io, hello);
    defer allocator.free(hello_bytes);
    try std.testing.expectEqualStrings("hello world", hello_bytes);

    const sh = try reader.lookup("/bin/sh");
    try std.testing.expectEqual(EntryKind.symlink, reader.getEntry(sh).kind);
    try std.testing.expectEqualStrings("busybox", try reader.readLink(sh));

    const nested = reader.getEntry(try reader.lookup("/etc/nested"));
    try std.testing.expectEqual(@as(u32, 0o700), nested.mode & 0o7777);
}

fn multiBlockContentAlloc(allocator: std.mem.Allocator, len: usize) ![]u8 {
    const bytes = try allocator.alloc(u8, len);
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    for (bytes) |*byte| byte.* = random.int(u8);
    return bytes;
}

test "squashfs writer streams a multi-block file across fragment and no-fragment modes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // 4 KiB blocks with a 300 KiB body -> many full blocks plus a tail.
    const content = try multiBlockContentAlloc(allocator, 300 * 1024 + 123);
    defer allocator.free(content);

    inline for (.{ true, false }) |use_fragments| {
        const path = if (use_fragments) "test-squashfs-writer-frag.sqsh" else "test-squashfs-writer-nofrag.sqsh";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};

        const nodes = [_]TestNode{
            .{ .path = "big.bin", .kind = .file, .mode = 0o644, .content = content },
        };
        var test_source = TestSource{ .nodes = &nodes };
        const result = try writeImagePath(allocator, io, path, test_source.source(), .{
            .compression = .zstd,
            .block_size = 4096,
            .use_fragments = use_fragments,
        });
        try std.testing.expectEqual(use_fragments, result.fragment_count > 0);

        var reader = try Reader.openPath(allocator, io, path);
        defer reader.close(io);

        const index = try reader.lookup("/big.bin");
        try std.testing.expectEqual(@as(u64, content.len), reader.getEntry(index).size);

        // Read back in small chunks to exercise the streaming read path.
        const actual = try allocator.alloc(u8, content.len);
        defer allocator.free(actual);
        var offset: u64 = 0;
        while (offset < content.len) {
            const got = try reader.readFileAt(allocator, io, index, actual[@intCast(offset)..], offset);
            try std.testing.expect(got > 0);
            offset += got;
        }
        try std.testing.expectEqualSlices(u8, content, actual);
    }
}

test "squashfs writer supports the uncompressed option" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-squashfs-writer-none.sqsh";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "a", .kind = .directory, .mode = 0o755 },
        .{ .path = "a/data", .kind = .file, .mode = 0o644, .content = "uncompressed payload bytes" },
    };
    var test_source = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, test_source.source(), .{ .compression = .none, .block_size = 4096 });

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    const index = try reader.lookup("/a/data");
    const bytes = try reader.readFileAlloc(allocator, io, index);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("uncompressed payload bytes", bytes);
}

test "squashfs writer output is byte-for-byte deterministic" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path_a = "test-squashfs-writer-det-a.sqsh";
    const path_b = "test-squashfs-writer-det-b.sqsh";
    defer Io.Dir.cwd().deleteFile(io, path_a) catch {};
    defer Io.Dir.cwd().deleteFile(io, path_b) catch {};

    const body = try multiBlockContentAlloc(allocator, 200 * 1024 + 7);
    defer allocator.free(body);
    const nodes = [_]TestNode{
        .{ .path = "etc", .kind = .directory, .mode = 0o755 },
        .{ .path = "etc/conf", .kind = .file, .mode = 0o644, .content = "config" },
        .{ .path = "rootfs.img", .kind = .file, .mode = 0o644, .content = body },
        .{ .path = "link", .kind = .symlink, .mode = 0o777, .target = "etc/conf" },
    };
    var test_source = TestSource{ .nodes = &nodes };

    const image_a = try buildTestImageAlloc(allocator, test_source.source(), .{}, path_a);
    defer allocator.free(image_a);
    const image_b = try buildTestImageAlloc(allocator, test_source.source(), .{}, path_b);
    defer allocator.free(image_b);
    try std.testing.expectEqualSlices(u8, image_a, image_b);
}

test "squashfs writer zstd option actually shrinks compressible data" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path_z = "test-squashfs-writer-zstd.sqsh";
    const path_n = "test-squashfs-writer-raw.sqsh";
    defer Io.Dir.cwd().deleteFile(io, path_z) catch {};
    defer Io.Dir.cwd().deleteFile(io, path_n) catch {};

    const body = try allocator.alloc(u8, 256 * 1024);
    defer allocator.free(body);
    @memset(body, 'Z');
    const nodes = [_]TestNode{
        .{ .path = "rootfs.img", .kind = .file, .mode = 0o644, .content = body },
    };
    var test_source = TestSource{ .nodes = &nodes };

    const zstd_result = try writeImagePath(allocator, io, path_z, test_source.source(), .{ .compression = .zstd });
    const none_result = try writeImagePath(allocator, io, path_n, test_source.source(), .{ .compression = .none });
    try std.testing.expect(zstd_result.bytes_written < none_result.bytes_written);
}

test "squashfs writer rejects a node whose parent directory is missing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const path = "test-squashfs-writer-badparent.sqsh";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "missing/child", .kind = .file, .mode = 0o644, .content = "x" },
    };
    var test_source = TestSource{ .nodes = &nodes };
    try std.testing.expectError(error.MissingParentDirectory, writeImagePath(allocator, io, path, test_source.source(), .{}));
}
