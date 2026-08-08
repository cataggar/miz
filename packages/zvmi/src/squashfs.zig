//! SquashFS 4.0 **read-only** reader.
//!
//! Supports uncompressed blocks plus XZ- and zstd-compressed metadata, data,
//! and fragment blocks. This covers the real Azure Linux installer media used
//! by `zvmi build-image`, while keeping the implementation focused on the
//! documented SquashFS 4.0 on-disk layout.

const std = @import("std");
const Io = std.Io;

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
    // packages/zvmi/src/verity_tooling.zig's decompressZstd for why the empty-
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
    const zstd = @import("zstd.zig");
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
