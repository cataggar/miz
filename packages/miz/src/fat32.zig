//! FAT32 filesystem read/write support over a partition-sized region inside a
//! `miz.Image`. The public API is image+region based rather than owning a raw
//! file handle, so callers can point the filesystem codec at any partition
//! inside a larger disk image and keep using the existing `Image` abstraction.

const std = @import("std");
const Io = std.Io;
const Image = @import("image.zig").Image;
const ext4 = @import("ext4.zig");
const limits_mod = @import("limits.zig");

/// Byte range inside the backing `Image` that contains the FAT32 volume.
pub const Region = struct {
    offset: u64,
    length: u64,
};

/// Format-time geometry and metadata. `partition_offset`/`partition_len`
/// describe the partition-relative range to populate inside the backing image.
pub const FormatOptions = struct {
    partition_offset: u64,
    partition_len: u64,
    bytes_per_sector: u16 = default_bytes_per_sector,
    sectors_per_cluster: ?u8 = null,
    fat_count: u8 = 2,
    reserved_sector_count: u16 = 32,
    media_descriptor: u8 = 0xF8,
    sectors_per_track: u16 = 63,
    head_count: u16 = 255,
    hidden_sectors: u32 = 0,
    volume_id: u32 = 0x5A56_4D49,
    volume_label: [11]u8 = "NO NAME    ".*,
};

pub fn validateFormatOptions(options: FormatOptions) Error!void {
    _ = try computeLayout(options);
}

/// Validates a non-root relative path using FAT long-filename rules.
pub fn validateRelativePath(path: []const u8) Error!void {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') return error.InvalidPath;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| try validateComponent(component);
}

pub const DirEntryKind = enum { file, directory };

pub const DirEntry = struct {
    name: []u8,
    kind: DirEntryKind,
    size: u32,
};

/// Frees the slice returned by `FileSystem.listDirAlloc`.
pub fn freeDirEntries(allocator: std.mem.Allocator, entries: []DirEntry) void {
    for (entries) |entry| allocator.free(entry.name);
    allocator.free(entries);
}

/// Directory-entry slots one child name occupies inside its parent: the 8.3
/// entry that carries the child's cluster and size, plus the long-name
/// entries that precede it.
///
/// Whether a name also fits in 8.3 is not decided by the name alone -- a
/// short name that collides with one already written picks up a `~1` tail,
/// and the long-name entries are then what records the real name -- so this
/// counts them for every name. That makes it an upper bound for the handful
/// of names where it is wrong, which is the safe direction for anything
/// choosing a volume size from it.
pub fn nameSlotCount(name: []const u8) Error!u32 {
    try validateComponent(name);
    var units: [max_long_name_units]u16 = undefined;
    const utf16 = try encodeLongName(name, &units);
    const long_name_slots = std.math.divCeil(usize, utf16.len + 1, 13) catch unreachable;
    return @intCast(long_name_slots + 1);
}

/// Slots a subdirectory holds before any child: its own `.` and `..`, and
/// the empty slot that terminates the listing.
pub const subdirectory_overhead_slots: u32 = 3;
/// The root directory has no `.`/`..` pair, only the terminating slot.
pub const root_directory_overhead_slots: u32 = 1;

/// What a populated volume has to hold. Stated in bytes and slots rather
/// than in clusters because cluster size is not an input: it is chosen from
/// the volume length, which is the thing being solved for.
pub const SpaceRequest = struct {
    /// Byte length of every regular file, in any order.
    file_sizes: []const u64,
    /// Directory-entry slots each directory needs, the root's included.
    /// Each is the sum of `nameSlotCount` over that directory's children
    /// plus its own overhead constant above.
    directory_slots: []const u32,
};

pub const VolumeLengthOptions = struct {
    bytes_per_sector: u16 = default_bytes_per_sector,
    fat_count: u8 = 2,
    reserved_sector_count: u16 = 32,
    /// Candidate lengths are whole multiples of this, because the answer is
    /// normally a partition length and partitions are aligned.
    alignment: u64 = 1024 * 1024,
    /// Where the search gives up. An EFI system partition that will not fit
    /// below this is not a sizing problem, so it is refused by name rather
    /// than solved for.
    max_length: u64 = 8 * 1024 * 1024 * 1024,
};

/// The smallest aligned volume length that `format` accepts and that holds
/// `request`.
///
/// Candidate lengths are tried in order rather than solved for, because the
/// cluster size `format` picks is a step function of the length and the
/// cluster count a file needs is a step function of the cluster size.
/// Neither step is expensive: the per-cluster-size totals are computed once
/// each, so a candidate costs a layout calculation and a comparison.
pub fn minimumVolumeLength(request: SpaceRequest, options: VolumeLengthOptions) Error!u64 {
    if (!isSupportedBytesPerSector(options.bytes_per_sector)) return error.UnsupportedBytesPerSector;
    if (options.alignment == 0 or options.alignment % options.bytes_per_sector != 0) {
        return error.PartitionLengthNotAligned;
    }

    // One entry per power-of-two sectors-per-cluster value `format` may
    // choose, so a total is computed at most once for each.
    var needed_by_cluster_shift = [_]?u64{null} ** 8;
    var length: u64 = options.alignment;
    while (length <= options.max_length) : (length += options.alignment) {
        const info = computeLayout(.{
            .partition_offset = 0,
            .partition_len = length,
            .bytes_per_sector = options.bytes_per_sector,
            .fat_count = options.fat_count,
            .reserved_sector_count = options.reserved_sector_count,
        }) catch |err| switch (err) {
            error.VolumeTooSmall => continue,
            else => |other| return other,
        };
        const shift = @ctz(info.sectors_per_cluster);
        const needed = needed_by_cluster_shift[shift] orelse blk: {
            const total = try clustersFor(request, info.clusterSize());
            needed_by_cluster_shift[shift] = total;
            break :blk total;
        };
        // `needed` counts the root directory's own cluster, which `format`
        // hands out before the free pool exists -- hence the comparison
        // against the whole data area rather than against
        // `free_cluster_count`, which is that total less the root's one.
        if (needed <= info.data_cluster_count) return length;
    }
    return error.VolumeTooSmall;
}

fn clustersFor(request: SpaceRequest, cluster_bytes: usize) Error!u64 {
    var total: u64 = 0;
    for (request.file_sizes) |size| {
        // An empty file has no cluster chain at all; its directory entry
        // records first cluster 0.
        if (size > std.math.maxInt(u32)) return error.FileTooLarge;
        total += std.math.divCeil(u64, size, cluster_bytes) catch unreachable;
    }
    for (request.directory_slots) |slots| {
        const bytes = @as(u64, slots) * directory_entry_size;
        total += @max(@as(u64, 1), std.math.divCeil(u64, bytes, cluster_bytes) catch unreachable);
    }
    return total;
}

pub const Error = error{
    VolumeTooSmall,
    UnsupportedBytesPerSector,
    InvalidSectorsPerCluster,
    InvalidFatCount,
    PartitionLengthNotAligned,
    PartitionOutOfBounds,
    InvalidBootSector,
    NotFat32,
    InvalidPath,
    PathComponentTooLong,
    UnsupportedName,
    PathNotFound,
    NotDirectory,
    IsDirectory,
    DirectoryNotEmpty,
    DuplicateName,
    AlreadyExists,
    FilesystemFull,
    NoSpaceLeft,
    BadClusterChain,
    UnexpectedEndOfFile,
    FileTooLarge,
    DirectoryTooLarge,
    InvalidTruncateSize,
    StreamClosed,
};

pub const FormatError = Error || Image.PreadError || Image.PwriteError;
pub const OpenError = Error || Image.PreadError || Image.PwriteError;
pub const MutationError = Error || Image.PreadError || Image.PwriteError;
pub const ListError = Error || Image.PreadError || Image.PwriteError || std.mem.Allocator.Error;
pub const ReadFileError = Error || Image.PreadError || Image.PwriteError || std.mem.Allocator.Error;

pub const VolumeMetadata = struct {
    volume_id: u32,
    volume_label: [11]u8,
};

/// Incremental file writer returned by `FileSystem.beginFile`.
pub const FileWriter = struct {
    fs: *FileSystem,
    dir_cluster: u32,
    entry_location: DirectoryEntryLocation,
    first_cluster: u32 = 0,
    last_cluster: u32 = 0,
    size: u32 = 0,
    closed: bool = false,

    /// Appends `chunk` to the file at the current end offset.
    pub fn writeChunk(self: *FileWriter, io: Io, chunk: []const u8) MutationError!void {
        if (self.closed) return error.StreamClosed;
        if (chunk.len == 0) return;
        if (chunk.len > std.math.maxInt(u32) - self.size) return error.FileTooLarge;

        const cluster_size = self.fs.info.clusterSize();
        var written: usize = 0;
        while (written < chunk.len) {
            const offset_in_cluster = self.size % cluster_size;
            if (self.first_cluster == 0) {
                const cluster = try self.fs.allocateCluster(io);
                self.first_cluster = cluster;
                self.last_cluster = cluster;
            } else if (self.size != 0 and offset_in_cluster == 0) {
                const cluster = try self.fs.allocateCluster(io);
                try self.fs.writeFatEntry(io, self.last_cluster, cluster);
                self.last_cluster = cluster;
            }

            const take = @min(chunk.len - written, cluster_size - offset_in_cluster);
            try self.fs.writeRegion(
                io,
                chunk[written .. written + take],
                self.fs.clusterOffset(self.last_cluster) + offset_in_cluster,
            );
            written += take;
            self.size += @intCast(take);
        }

        try self.fs.updateDirectoryEntry(io, self.dir_cluster, self.entry_location, self.first_cluster, self.size);
    }

    /// Finalizes the file and zero-fills the unused tail of the last cluster.
    pub fn endFile(self: *FileWriter, io: Io) MutationError!void {
        if (self.closed) return error.StreamClosed;
        if (self.first_cluster != 0) {
            const cluster_size = self.fs.info.clusterSize();
            const tail = self.size % cluster_size;
            if (tail != 0) {
                var zeros: [max_cluster_size]u8 = [_]u8{0} ** max_cluster_size;
                try self.fs.writeRegion(
                    io,
                    zeros[0 .. cluster_size - tail],
                    self.fs.clusterOffset(self.last_cluster) + tail,
                );
            }
        }

        try self.fs.updateDirectoryEntry(io, self.dir_cluster, self.entry_location, self.first_cluster, self.size);
        self.closed = true;
    }

    /// Removes the partially written file and frees any allocated clusters.
    pub fn abort(self: *FileWriter, io: Io) MutationError!void {
        if (self.closed) return;
        if (self.first_cluster != 0) try self.fs.releaseChain(io, self.first_cluster);
        try self.fs.markEntryDeleted(io, self.dir_cluster, self.entry_location);
        self.closed = true;
    }
};

pub const FileSystem = struct {
    image: *Image,
    region: Region,
    info: VolumeInfo,
    free_cluster_count: u32,
    next_free_cluster: u32,
    fat_cache_sector: ?u32 = null,
    fat_cache: [max_bytes_per_sector]u8 = undefined,

    pub fn volumeMetadata(self: *const FileSystem) VolumeMetadata {
        return .{
            .volume_id = self.info.volume_id,
            .volume_label = self.info.volume_label,
        };
    }

    /// Ensures every component of `path` exists, creating missing
    /// directories along the way (`mkdir -p` semantics).
    pub fn createDir(self: *FileSystem, io: Io, path: []const u8) MutationError!void {
        var current = self.info.root_cluster;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        while (it.next()) |component| {
            try validateComponent(component);
            if (try self.findEntry(io, current, component)) |entry| {
                if (entry.kind() != .directory) return error.NotDirectory;
                current = entry.first_cluster;
                continue;
            }

            const cluster = try self.allocateCluster(io);
            errdefer self.releaseChain(io, cluster) catch {};
            try self.initDirectoryCluster(io, cluster, current);
            try self.appendDirectoryEntry(io, current, component, .directory, cluster, 0);
            current = cluster;
        }
    }

    /// Begins creating a new file whose contents will be supplied via
    /// repeated `FileWriter.writeChunk` calls followed by `FileWriter.endFile`.
    /// Call `FileWriter.abort` to remove a partially written file.
    pub fn beginFile(self: *FileSystem, io: Io, path: []const u8) MutationError!FileWriter {
        const parent = try self.resolveParent(io, path);
        if (parent.name.len == 0) return error.InvalidPath;
        if (try self.findEntry(io, parent.cluster, parent.name)) |_| return error.AlreadyExists;

        const entry_location = try self.appendDirectoryEntryTracked(io, parent.cluster, parent.name, .file, 0, 0);
        return .{
            .fs = self,
            .dir_cluster = parent.cluster,
            .entry_location = entry_location,
        };
    }

    /// Creates a new file and writes its full contents in one call.
    pub fn writeFile(self: *FileSystem, io: Io, path: []const u8, contents: []const u8) MutationError!void {
        const parent = try self.resolveParent(io, path);
        if (parent.name.len == 0) return error.InvalidPath;
        if (try self.findEntry(io, parent.cluster, parent.name)) |_| return error.AlreadyExists;
        if (contents.len > std.math.maxInt(u32)) return error.FileTooLarge;

        var first_cluster: u32 = 0;
        if (contents.len > 0) {
            const cluster_size = self.info.clusterSize();
            const needed_clusters: u32 = @intCast(std.math.divCeil(u64, contents.len, cluster_size) catch unreachable);
            first_cluster = try self.allocateChain(io, needed_clusters);
            errdefer self.releaseChain(io, first_cluster) catch {};
            try self.writeChainData(io, first_cluster, contents);
        }

        try self.appendDirectoryEntry(io, parent.cluster, parent.name, .file, first_cluster, @intCast(contents.len));
    }

    /// Deletes an existing file or empty directory.
    pub fn deletePath(self: *FileSystem, io: Io, path: []const u8) MutationError!void {
        const parent = try self.resolveParent(io, path);
        if (parent.name.len == 0) return error.InvalidPath;
        const entry = (try self.findEntry(io, parent.cluster, parent.name)) orelse return error.PathNotFound;

        try self.deleteLocatedEntry(io, parent.cluster, entry, false);
    }

    /// Deletes an existing file or directory tree recursively.
    pub fn deleteTree(self: *FileSystem, io: Io, path: []const u8) MutationError!void {
        const parent = try self.resolveParent(io, path);
        if (parent.name.len == 0) return error.InvalidPath;
        const entry = (try self.findEntry(io, parent.cluster, parent.name)) orelse return error.PathNotFound;

        try self.deleteLocatedEntry(io, parent.cluster, entry, true);
    }

    /// Shrinks an existing file to `new_size`, freeing no-longer-needed clusters.
    pub fn truncateFile(self: *FileSystem, io: Io, path: []const u8, new_size: u32) MutationError!void {
        const parent = try self.resolveParent(io, path);
        if (parent.name.len == 0) return error.InvalidPath;
        const entry = (try self.findEntry(io, parent.cluster, parent.name)) orelse return error.PathNotFound;
        if (entry.kind() != .file) return error.IsDirectory;
        if (new_size > entry.size) return error.InvalidTruncateSize;
        if (new_size == entry.size) return;

        if (new_size == 0) {
            if (entry.first_cluster != 0) try self.releaseChain(io, entry.first_cluster);
            try self.updateDirectoryEntry(io, parent.cluster, entry.location(), 0, 0);
            return;
        }
        if (entry.first_cluster == 0) return error.BadClusterChain;

        const cluster_size = self.info.clusterSize();
        const needed_clusters: u32 = @intCast(std.math.divCeil(u64, new_size, cluster_size) catch unreachable);
        var keep_cluster = entry.first_cluster;
        var cluster_index: u32 = 1;
        while (cluster_index < needed_clusters) : (cluster_index += 1) {
            keep_cluster = (try self.nextCluster(io, keep_cluster)) orelse return error.BadClusterChain;
        }

        const tail_cluster = try self.nextCluster(io, keep_cluster);
        if (tail_cluster) |cluster| {
            try self.writeFatEntry(io, keep_cluster, fat_entry_eoc);
            try self.releaseChain(io, cluster);
        }

        const tail_bytes = new_size % cluster_size;
        if (tail_bytes != 0) {
            var zeros: [max_cluster_size]u8 = [_]u8{0} ** max_cluster_size;
            try self.writeRegion(
                io,
                zeros[0 .. cluster_size - tail_bytes],
                self.clusterOffset(keep_cluster) + tail_bytes,
            );
        }

        try self.updateDirectoryEntry(io, parent.cluster, entry.location(), entry.first_cluster, new_size);
    }

    /// Returns the immediate children of `path` (`/` or empty for the root).
    pub fn listDirAlloc(self: *FileSystem, io: Io, allocator: std.mem.Allocator, path: []const u8) ListError![]DirEntry {
        return self.listDirAllocLimited(
            io,
            allocator,
            path,
            std.math.maxInt(usize),
        );
    }

    /// Returns at most `max_entries` immediate children of `path`.
    pub fn listDirAllocLimited(
        self: *FileSystem,
        io: Io,
        allocator: std.mem.Allocator,
        path: []const u8,
        max_entries: usize,
    ) ListError![]DirEntry {
        const cluster = if (isRootPath(path)) self.info.root_cluster else blk: {
            const entry = (try self.lookup(io, path)) orelse return error.PathNotFound;
            if (entry.kind() != .directory) return error.NotDirectory;
            break :blk entry.first_cluster;
        };

        var entries = std.array_list.Managed(DirEntry).init(allocator);
        errdefer {
            for (entries.items) |entry| allocator.free(entry.name);
            entries.deinit();
        }

        var iter = try DirectoryIterator.init(self, io, cluster);
        while (try iter.next(io, null)) |raw| {
            if (raw.attr & attr_volume_id != 0) continue;
            if (entries.items.len >= max_entries)
                return error.DirectoryTooLarge;
            const name = try raw.nameAlloc(allocator);
            errdefer allocator.free(name);
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) {
                allocator.free(name);
                continue;
            }
            try validateComponent(name);
            for (entries.items) |existing| {
                if (std.ascii.eqlIgnoreCase(existing.name, name))
                    return error.DuplicateName;
            }
            try entries.append(.{
                .name = name,
                .kind = if (raw.attr & attr_directory != 0) .directory else .file,
                .size = raw.size,
            });
        }

        return entries.toOwnedSlice();
    }

    /// Reads the full contents of `path`, following the FAT chain for the
    /// file's data clusters.
    pub fn readFileAlloc(self: *FileSystem, io: Io, allocator: std.mem.Allocator, path: []const u8) ReadFileError![]u8 {
        const entry = (try self.lookup(io, path)) orelse return error.PathNotFound;
        if (entry.kind() != .file) return error.IsDirectory;
        if (entry.size != 0 and !self.isDataCluster(entry.first_cluster))
            return error.BadClusterChain;

        const buffer = try allocator.alloc(u8, entry.size);
        errdefer allocator.free(buffer);
        if (entry.size == 0) return buffer;

        try self.readChainData(io, entry.first_cluster, buffer);
        return buffer;
    }

    fn resolveParent(self: *FileSystem, io: Io, path: []const u8) MutationError!struct { cluster: u32, name: []const u8 } {
        var last_component: []const u8 = "";
        var current = self.info.root_cluster;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        while (it.next()) |component| {
            try validateComponent(component);
            if (it.peek() == null) {
                last_component = component;
                break;
            }
            const entry = (try self.findEntry(io, current, component)) orelse return error.PathNotFound;
            if (entry.kind() != .directory) return error.NotDirectory;
            current = entry.first_cluster;
        }
        return .{ .cluster = current, .name = last_component };
    }

    fn lookup(self: *FileSystem, io: Io, path: []const u8) OpenError!?LocatedEntry {
        if (isRootPath(path)) return null;
        var current = self.info.root_cluster;
        var found: ?LocatedEntry = null;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        while (it.next()) |component| {
            try validateComponent(component);
            found = (try self.findEntry(io, current, component)) orelse return null;
            if (it.peek() != null) {
                if (found.?.kind() != .directory) return error.NotDirectory;
                current = found.?.first_cluster;
            }
        }
        return found;
    }

    fn appendDirectoryEntry(
        self: *FileSystem,
        io: Io,
        dir_cluster: u32,
        name: []const u8,
        kind: DirEntryKind,
        first_cluster: u32,
        size: u32,
    ) MutationError!void {
        _ = try self.appendDirectoryEntryTracked(io, dir_cluster, name, kind, first_cluster, size);
    }

    fn appendDirectoryEntryTracked(
        self: *FileSystem,
        io: Io,
        dir_cluster: u32,
        name: []const u8,
        kind: DirEntryKind,
        first_cluster: u32,
        size: u32,
    ) MutationError!DirectoryEntryLocation {
        var utf16_units: [max_long_name_units]u16 = undefined;
        const utf16_name = try encodeLongName(name, &utf16_units);

        const short_name = try chooseShortName(self, io, dir_cluster, name);
        const use_lfn = requiresLongName(name, short_name);
        const lfn_count: usize = if (use_lfn) std.math.divCeil(usize, utf16_name.len + 1, 13) catch unreachable else 0;
        const total_slots = lfn_count + 1;

        var slots: [max_directory_slots][directory_entry_size]u8 = [_][directory_entry_size]u8{[_]u8{0} ** directory_entry_size} ** max_directory_slots;
        if (use_lfn) buildLfnEntries(slots[0..lfn_count], utf16_name, short_name);
        slots[lfn_count] = buildShortEntry(short_name, kind, first_cluster, size);

        const start_slot = try self.findDirectoryEnd(io, dir_cluster);
        try self.ensureDirectorySlots(io, dir_cluster, start_slot + total_slots + 1);
        try self.writeDirectorySlots(io, dir_cluster, start_slot, slots[0..total_slots]);
        return .{ .first_slot = start_slot, .slot_count = total_slots };
    }

    fn findEntry(self: *FileSystem, io: Io, dir_cluster: u32, wanted: []const u8) MutationError!?LocatedEntry {
        var iter = try DirectoryIterator.init(self, io, dir_cluster);
        while (try iter.next(io, wanted)) |entry| {
            if (entry.matches(wanted)) return entry;
        }
        return null;
    }

    fn findDirectoryEnd(self: *FileSystem, io: Io, dir_cluster: u32) MutationError!usize {
        var cluster = dir_cluster;
        var slot_index: usize = 0;
        const slots_per_cluster = self.info.clusterSize() / directory_entry_size;
        var cluster_buf: [max_cluster_size]u8 = undefined;

        while (true) {
            const slice = cluster_buf[0..self.info.clusterSize()];
            try self.readCluster(io, cluster, slice);
            var i: usize = 0;
            while (i < slots_per_cluster) : (i += 1) {
                if (slice[i * directory_entry_size] == 0x00) return slot_index + i;
            }
            slot_index += slots_per_cluster;
            const next = try self.nextCluster(io, cluster);
            if (next == null) return slot_index;
            cluster = next.?;
        }
    }

    fn ensureDirectorySlots(self: *FileSystem, io: Io, dir_cluster: u32, needed_slots: usize) MutationError!void {
        const slots_per_cluster = self.info.clusterSize() / directory_entry_size;
        var have_clusters: usize = 0;
        var last_cluster = dir_cluster;
        var cluster = dir_cluster;
        while (true) {
            have_clusters += 1;
            last_cluster = cluster;
            const next = try self.nextCluster(io, cluster);
            if (next == null) break;
            cluster = next.?;
        }

        const required_clusters = std.math.divCeil(usize, needed_slots, slots_per_cluster) catch unreachable;
        while (have_clusters < required_clusters) : (have_clusters += 1) {
            const new_cluster = try self.allocateCluster(io);
            try self.zeroCluster(io, new_cluster);
            try self.writeFatEntry(io, last_cluster, new_cluster);
            last_cluster = new_cluster;
        }
    }

    fn writeDirectorySlots(self: *FileSystem, io: Io, dir_cluster: u32, start_slot: usize, slots: []const [directory_entry_size]u8) MutationError!void {
        const slots_per_cluster = self.info.clusterSize() / directory_entry_size;
        var cluster = dir_cluster;
        var remaining = start_slot;
        while (remaining >= slots_per_cluster) : (remaining -= slots_per_cluster) {
            cluster = (try self.nextCluster(io, cluster)) orelse return error.BadClusterChain;
        }

        var slot_in_cluster = remaining;
        for (slots) |slot| {
            const rel = self.clusterOffset(cluster) + slot_in_cluster * directory_entry_size;
            try self.writeRegion(io, &slot, rel);
            slot_in_cluster += 1;
            if (slot_in_cluster == slots_per_cluster) {
                slot_in_cluster = 0;
                cluster = (try self.nextCluster(io, cluster)) orelse return error.BadClusterChain;
            }
        }
    }

    fn directorySlotOffset(self: *FileSystem, io: Io, dir_cluster: u32, slot_index: usize) MutationError!u64 {
        const slots_per_cluster = self.info.clusterSize() / directory_entry_size;
        var cluster = dir_cluster;
        var remaining = slot_index;
        while (remaining >= slots_per_cluster) : (remaining -= slots_per_cluster) {
            cluster = (try self.nextCluster(io, cluster)) orelse return error.BadClusterChain;
        }
        return self.clusterOffset(cluster) + remaining * directory_entry_size;
    }

    fn readDirectorySlot(self: *FileSystem, io: Io, dir_cluster: u32, slot_index: usize, slot: *[directory_entry_size]u8) MutationError!void {
        try self.readRegion(io, slot, try self.directorySlotOffset(io, dir_cluster, slot_index));
    }

    fn updateDirectoryEntry(
        self: *FileSystem,
        io: Io,
        dir_cluster: u32,
        location: DirectoryEntryLocation,
        first_cluster: u32,
        size: u32,
    ) MutationError!void {
        var slot: [directory_entry_size]u8 = undefined;
        try self.readDirectorySlot(io, dir_cluster, location.shortSlot(), &slot);
        std.mem.writeInt(u16, slot[20..22], @intCast(first_cluster >> 16), .little);
        std.mem.writeInt(u16, slot[26..28], @intCast(first_cluster & 0xFFFF), .little);
        std.mem.writeInt(u32, slot[28..32], size, .little);
        try self.writeRegion(io, &slot, try self.directorySlotOffset(io, dir_cluster, location.shortSlot()));
    }

    fn markEntryDeleted(self: *FileSystem, io: Io, dir_cluster: u32, location: DirectoryEntryLocation) MutationError!void {
        var deleted = [_]u8{0xE5};
        for (0..location.slot_count) |slot_index| {
            try self.writeRegion(io, &deleted, try self.directorySlotOffset(io, dir_cluster, location.first_slot + slot_index));
        }
    }

    fn deleteLocatedEntry(
        self: *FileSystem,
        io: Io,
        parent_cluster: u32,
        entry: LocatedEntry,
        recursive: bool,
    ) MutationError!void {
        if (entry.kind() == .directory) {
            if (recursive) {
                try self.deleteDirectoryChildren(io, entry.first_cluster);
            } else if (!(try self.isDirectoryEmpty(io, entry.first_cluster))) {
                return error.DirectoryNotEmpty;
            }
        }

        try self.releaseEntry(io, parent_cluster, entry.location(), entry.first_cluster);
    }

    fn deleteDirectoryChildren(self: *FileSystem, io: Io, dir_cluster: u32) MutationError!void {
        var iter = try DirectoryIterator.init(self, io, dir_cluster);
        while (try iter.next(io, null)) |entry| {
            if (entry.attr & attr_volume_id != 0) continue;
            if (isDotEntry(entry.short_name)) continue;
            try self.deleteLocatedEntry(io, dir_cluster, entry, true);
        }
    }

    fn releaseEntry(
        self: *FileSystem,
        io: Io,
        parent_cluster: u32,
        location: DirectoryEntryLocation,
        first_cluster: u32,
    ) MutationError!void {
        if (first_cluster != 0) try self.releaseChain(io, first_cluster);
        try self.markEntryDeleted(io, parent_cluster, location);
    }

    fn isDirectoryEmpty(self: *FileSystem, io: Io, dir_cluster: u32) MutationError!bool {
        var iter = try DirectoryIterator.init(self, io, dir_cluster);
        while (try iter.next(io, null)) |entry| {
            if (entry.attr & attr_volume_id != 0) continue;
            if (isDotEntry(entry.short_name)) continue;
            return false;
        }
        return true;
    }

    fn initDirectoryCluster(self: *FileSystem, io: Io, cluster: u32, parent_cluster: u32) MutationError!void {
        try self.zeroCluster(io, cluster);
        const dot = buildDotEntry(false, cluster);
        const dotdot = buildDotEntry(true, parent_cluster);
        try self.writeRegion(io, &dot, self.clusterOffset(cluster));
        try self.writeRegion(io, &dotdot, self.clusterOffset(cluster) + directory_entry_size);
    }

    fn allocateChain(self: *FileSystem, io: Io, count: u32) MutationError!u32 {
        std.debug.assert(count > 0);
        var first: u32 = 0;
        var prev: u32 = 0;
        errdefer if (first != 0) self.releaseChain(io, first) catch {};
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const cluster = try self.allocateCluster(io);
            if (first == 0) first = cluster else try self.writeFatEntry(io, prev, cluster);
            prev = cluster;
        }
        return first;
    }

    fn releaseChain(self: *FileSystem, io: Io, first_cluster: u32) MutationError!void {
        if (first_cluster == 0) return;
        var cluster = first_cluster;
        while (true) {
            const next = try self.nextCluster(io, cluster);
            try self.writeFatEntry(io, cluster, 0);
            self.free_cluster_count += 1;
            if (cluster < self.next_free_cluster) self.next_free_cluster = cluster;
            if (next == null) break;
            cluster = next.?;
        }
        try self.persistFsInfo(io);
    }

    fn allocateCluster(self: *FileSystem, io: Io) MutationError!u32 {
        if (self.free_cluster_count == 0) return error.FilesystemFull;
        const max_cluster = self.info.maxClusterNumber();
        var probe = if (self.next_free_cluster < 2 or self.next_free_cluster > max_cluster) @as(u32, 2) else self.next_free_cluster;
        const start = probe;
        while (true) {
            if (try self.readFatEntry(io, probe) == 0) {
                try self.writeFatEntry(io, probe, fat_entry_eoc);
                self.free_cluster_count -= 1;
                self.next_free_cluster = if (probe == max_cluster) 2 else probe + 1;
                try self.persistFsInfo(io);
                return probe;
            }
            probe = if (probe == max_cluster) 2 else probe + 1;
            if (probe == start) return error.FilesystemFull;
        }
    }

    fn writeChainData(self: *FileSystem, io: Io, first_cluster: u32, data: []const u8) MutationError!void {
        const cluster_size = self.info.clusterSize();
        var cluster = first_cluster;
        var offset: usize = 0;
        var zero_buf: [max_cluster_size]u8 = [_]u8{0} ** max_cluster_size;
        while (true) {
            const take = @min(data.len - offset, cluster_size);
            const cluster_rel = self.clusterOffset(cluster);
            try self.writeRegion(io, data[offset .. offset + take], cluster_rel);
            if (take < cluster_size) {
                try self.writeRegion(io, zero_buf[0 .. cluster_size - take], cluster_rel + take);
            }
            offset += take;
            if (offset == data.len) break;
            cluster = (try self.nextCluster(io, cluster)) orelse return error.BadClusterChain;
        }
    }

    fn readChainData(self: *FileSystem, io: Io, first_cluster: u32, buffer: []u8) MutationError!void {
        if (buffer.len == 0) return;
        if (!self.isDataCluster(first_cluster)) return error.BadClusterChain;
        var cluster = first_cluster;
        var tracker = ChainTracker.init(first_cluster);
        const cluster_size = self.info.clusterSize();
        var offset: usize = 0;
        while (offset < buffer.len) {
            const take = @min(buffer.len - offset, cluster_size);
            try self.readRegion(io, buffer[offset .. offset + take], self.clusterOffset(cluster));
            offset += take;
            if (offset == buffer.len) break;
            const next = (try self.nextCluster(io, cluster)) orelse
                return error.BadClusterChain;
            try tracker.advance(next, self.info.data_cluster_count);
            cluster = next;
        }
    }

    fn persistFsInfo(self: *FileSystem, io: Io) MutationError!void {
        var sector: [default_bytes_per_sector]u8 = [_]u8{0} ** default_bytes_per_sector;
        std.mem.writeInt(u32, sector[0..4], fsinfo_lead_signature, .little);
        std.mem.writeInt(u32, sector[484..488], fsinfo_struct_signature, .little);
        std.mem.writeInt(u32, sector[488..492], self.free_cluster_count, .little);
        std.mem.writeInt(u32, sector[492..496], self.next_free_cluster, .little);
        std.mem.writeInt(u32, sector[508..512], fsinfo_trail_signature, .little);

        const primary = @as(u64, self.info.fsinfo_sector) * self.info.bytes_per_sector;
        try self.writeRegion(io, &sector, primary);
        if (self.info.backup_boot_sector + 1 < self.info.reserved_sector_count) {
            const backup = @as(u64, self.info.backup_boot_sector + 1) * self.info.bytes_per_sector;
            try self.writeRegion(io, &sector, backup);
        }
    }

    fn recountFreeClusters(self: *FileSystem, io: Io) MutationError!void {
        var free: u32 = 0;
        var next_free: u32 = 0;
        var cluster: u32 = 2;
        const max_cluster = self.info.maxClusterNumber();
        while (cluster <= max_cluster) : (cluster += 1) {
            if (try self.readFatEntry(io, cluster) == 0) {
                free += 1;
                if (next_free == 0) next_free = cluster;
            }
        }
        self.free_cluster_count = free;
        self.next_free_cluster = if (next_free == 0) 2 else next_free;
    }

    fn nextCluster(self: *FileSystem, io: Io, cluster: u32) MutationError!?u32 {
        if (!self.isDataCluster(cluster)) return error.BadClusterChain;
        const entry = try self.readFatEntry(io, cluster);
        if (entry == 0) return error.BadClusterChain;
        if (entry >= fat_entry_eoc_min and entry <= fat_entry_mask) return null;
        if (entry == fat_entry_bad or entry < 2 or entry > self.info.maxClusterNumber()) return error.BadClusterChain;
        return entry;
    }

    fn readFatEntry(self: *FileSystem, io: Io, cluster: u32) MutationError!u32 {
        const sector_size: usize = self.info.bytes_per_sector;
        const fat_offset = @as(u64, cluster) * 4;
        const sector: u32 = @intCast(fat_offset / @as(u64, sector_size));
        const entry_offset: usize = @intCast(fat_offset % @as(u64, sector_size));
        if (self.fat_cache_sector != sector) {
            const rel = (@as(u64, self.info.reserved_sector_count) + sector) *
                self.info.bytes_per_sector;
            try self.readRegion(io, self.fat_cache[0..sector_size], rel);
            self.fat_cache_sector = sector;
        }
        return std.mem.readInt(
            u32,
            self.fat_cache[entry_offset..][0..4],
            .little,
        ) & fat_entry_mask;
    }

    fn writeFatEntry(self: *FileSystem, io: Io, cluster: u32, value: u32) MutationError!void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, .little);
        self.fat_cache_sector = null;
        var fat_index: u8 = 0;
        while (fat_index < self.info.fat_count) : (fat_index += 1) {
            const rel = (@as(u64, self.info.reserved_sector_count) + @as(u64, fat_index) * self.info.fat_size_sectors) * self.info.bytes_per_sector + @as(u64, cluster) * 4;
            try self.writeRegion(io, &buf, rel);
        }
    }

    fn readCluster(self: *FileSystem, io: Io, cluster: u32, buffer: []u8) MutationError!void {
        if (!self.isDataCluster(cluster)) return error.BadClusterChain;
        try self.readRegion(io, buffer, self.clusterOffset(cluster));
    }

    fn zeroCluster(self: *FileSystem, io: Io, cluster: u32) MutationError!void {
        var zeros: [max_cluster_size]u8 = [_]u8{0} ** max_cluster_size;
        try self.writeRegion(io, zeros[0..self.info.clusterSize()], self.clusterOffset(cluster));
    }

    fn clusterOffset(self: *const FileSystem, cluster: u32) u64 {
        const data_sector = self.info.data_start_sector + @as(u64, cluster - 2) * self.info.sectors_per_cluster;
        return data_sector * self.info.bytes_per_sector;
    }

    fn isDataCluster(self: *const FileSystem, cluster: u32) bool {
        return cluster >= 2 and cluster <= self.info.maxClusterNumber();
    }

    fn readRegion(self: *const FileSystem, io: Io, buffer: []u8, relative_offset: u64) MutationError!void {
        if (relative_offset + buffer.len > self.region.length) return error.PartitionOutOfBounds;
        const got = try self.image.pread(io, buffer, self.region.offset + relative_offset);
        if (got != buffer.len) return error.UnexpectedEndOfFile;
    }

    fn writeRegion(self: *const FileSystem, io: Io, buffer: []const u8, relative_offset: u64) MutationError!void {
        if (relative_offset + buffer.len > self.region.length) return error.PartitionOutOfBounds;
        try self.image.pwrite(io, buffer, self.region.offset + relative_offset);
    }
};

/// Formats `options.partition_offset..partition_offset+partition_len` inside
/// `image` as a FAT32 volume with an empty root directory.
pub fn format(image: *Image, io: Io, options: FormatOptions) FormatError!void {
    const layout = try computeLayout(options);
    var fs = FileSystem{
        .image = image,
        .region = .{ .offset = options.partition_offset, .length = options.partition_len },
        .info = layout,
        .free_cluster_count = layout.data_cluster_count - 1,
        .next_free_cluster = 3,
    };

    try zeroRange(&fs, io, 0, @as(u64, layout.reserved_sector_count) * layout.bytes_per_sector);
    try zeroRange(&fs, io, @as(u64, layout.reserved_sector_count) * layout.bytes_per_sector, @as(u64, layout.fat_count) * layout.fat_size_sectors * layout.bytes_per_sector);
    try fs.zeroCluster(io, layout.root_cluster);

    const boot_sector = buildBootSector(layout);
    try fs.writeRegion(io, &boot_sector, 0);

    var fsinfo_sector_buf: [default_bytes_per_sector]u8 = [_]u8{0} ** default_bytes_per_sector;
    std.mem.writeInt(u32, fsinfo_sector_buf[0..4], fsinfo_lead_signature, .little);
    std.mem.writeInt(u32, fsinfo_sector_buf[484..488], fsinfo_struct_signature, .little);
    std.mem.writeInt(u32, fsinfo_sector_buf[488..492], layout.data_cluster_count - 1, .little);
    std.mem.writeInt(u32, fsinfo_sector_buf[492..496], 3, .little);
    std.mem.writeInt(u32, fsinfo_sector_buf[508..512], fsinfo_trail_signature, .little);
    try fs.writeRegion(io, &fsinfo_sector_buf, @as(u64, layout.fsinfo_sector) * layout.bytes_per_sector);

    if (layout.backup_boot_sector < layout.reserved_sector_count) {
        try fs.writeRegion(io, &boot_sector, @as(u64, layout.backup_boot_sector) * layout.bytes_per_sector);
    }
    if (layout.backup_boot_sector + 1 < layout.reserved_sector_count) {
        try fs.writeRegion(io, &fsinfo_sector_buf, @as(u64, layout.backup_boot_sector + 1) * layout.bytes_per_sector);
    }

    try fs.writeFatEntry(io, 0, (@as(u32, 0x0FFF_FF00) | options.media_descriptor));
    try fs.writeFatEntry(io, 1, fat_entry_mask);
    try fs.writeFatEntry(io, layout.root_cluster, fat_entry_eoc);
}

/// Opens an existing FAT32 volume that lives inside `region` of `image`.
pub fn open(image: *Image, io: Io, region: Region) OpenError!FileSystem {
    var boot_sector: [default_bytes_per_sector]u8 = undefined;
    if (region.length < default_bytes_per_sector) return error.InvalidBootSector;
    const got = try image.pread(io, &boot_sector, region.offset);
    if (got != boot_sector.len) return error.UnexpectedEndOfFile;

    if (boot_sector[510] != 0x55 or boot_sector[511] != 0xAA) return error.InvalidBootSector;

    const bytes_per_sector = std.mem.readInt(u16, boot_sector[11..13], .little);
    if (!isSupportedBytesPerSector(bytes_per_sector)) return error.UnsupportedBytesPerSector;
    const sectors_per_cluster = boot_sector[13];
    if (!isValidSectorsPerCluster(sectors_per_cluster)) return error.InvalidSectorsPerCluster;

    const reserved_sector_count = std.mem.readInt(u16, boot_sector[14..16], .little);
    const fat_count = boot_sector[16];
    const root_entry_count = std.mem.readInt(u16, boot_sector[17..19], .little);
    const total_sectors_16 = std.mem.readInt(u16, boot_sector[19..21], .little);
    const fat_size_16 = std.mem.readInt(u16, boot_sector[22..24], .little);
    const total_sectors_32 = std.mem.readInt(u32, boot_sector[32..36], .little);
    const fat_size_32 = std.mem.readInt(u32, boot_sector[36..40], .little);
    const root_cluster = std.mem.readInt(u32, boot_sector[44..48], .little);
    const fsinfo_sector = std.mem.readInt(u16, boot_sector[48..50], .little);
    const backup_boot_sector = std.mem.readInt(u16, boot_sector[50..52], .little);
    const hidden_sectors = std.mem.readInt(u32, boot_sector[28..32], .little);
    const media_descriptor = boot_sector[21];
    const sectors_per_track = std.mem.readInt(u16, boot_sector[24..26], .little);
    const head_count = std.mem.readInt(u16, boot_sector[26..28], .little);
    const volume_id = std.mem.readInt(u32, boot_sector[67..71], .little);
    const boot_signature = boot_sector[66];

    if (root_entry_count != 0 or total_sectors_16 != 0 or fat_size_16 != 0) return error.NotFat32;
    if (boot_signature != 0x29) return error.InvalidBootSector;
    if (!std.mem.eql(u8, boot_sector[82..90], "FAT32   ")) return error.NotFat32;
    if (fat_count == 0) return error.InvalidFatCount;
    if (fat_size_32 == 0 or root_cluster < 2) return error.InvalidBootSector;
    if (@as(u64, total_sectors_32) * bytes_per_sector > region.length) return error.PartitionOutOfBounds;

    const data_start_sector = @as(u64, reserved_sector_count) + @as(u64, fat_count) * fat_size_32;
    if (total_sectors_32 <= data_start_sector) return error.InvalidBootSector;
    const data_cluster_count: u32 = @intCast((@as(u64, total_sectors_32) - data_start_sector) / sectors_per_cluster);
    if (data_cluster_count < min_fat32_clusters) return error.NotFat32;
    if (root_cluster > data_cluster_count + 1)
        return error.InvalidBootSector;

    var label: [11]u8 = undefined;
    @memcpy(&label, boot_sector[71..82]);

    var fs = FileSystem{
        .image = image,
        .region = region,
        .info = .{
            .bytes_per_sector = bytes_per_sector,
            .sectors_per_cluster = sectors_per_cluster,
            .reserved_sector_count = reserved_sector_count,
            .fat_count = fat_count,
            .fat_size_sectors = fat_size_32,
            .total_sectors = total_sectors_32,
            .root_cluster = root_cluster,
            .fsinfo_sector = fsinfo_sector,
            .backup_boot_sector = backup_boot_sector,
            .hidden_sectors = hidden_sectors,
            .media_descriptor = media_descriptor,
            .sectors_per_track = sectors_per_track,
            .head_count = head_count,
            .volume_id = volume_id,
            .volume_label = label,
            .data_start_sector = data_start_sector,
            .data_cluster_count = data_cluster_count,
        },
        .free_cluster_count = 0,
        .next_free_cluster = 2,
    };

    if (fsinfo_sector < reserved_sector_count) {
        var sector: [default_bytes_per_sector]u8 = undefined;
        try fs.readRegion(io, &sector, @as(u64, fsinfo_sector) * bytes_per_sector);
        if (std.mem.readInt(u32, sector[0..4], .little) == fsinfo_lead_signature and
            std.mem.readInt(u32, sector[484..488], .little) == fsinfo_struct_signature and
            std.mem.readInt(u32, sector[508..512], .little) == fsinfo_trail_signature)
        {
            fs.free_cluster_count = std.mem.readInt(u32, sector[488..492], .little);
            fs.next_free_cluster = std.mem.readInt(u32, sector[492..496], .little);
        } else {
            try fs.recountFreeClusters(io);
        }
    } else {
        try fs.recountFreeClusters(io);
    }

    return fs;
}

const default_bytes_per_sector: usize = 512;
const max_bytes_per_sector: usize = 4096;
const max_cluster_size: usize = 32 * 1024;
const min_fat32_clusters: u32 = 65_525;
const max_long_name_units: usize = 255;
const directory_entry_size: usize = 32;
const max_directory_slots: usize = 21;
const fat_entry_mask: u32 = 0x0FFF_FFFF;
const fat_entry_eoc: u32 = 0x0FFF_FFFF;
const fat_entry_eoc_min: u32 = 0x0FFF_FFF8;
const fat_entry_bad: u32 = 0x0FFF_FFF7;
const fsinfo_lead_signature: u32 = 0x4161_5252;
const fsinfo_struct_signature: u32 = 0x6141_7272;
const fsinfo_trail_signature: u32 = 0xAA55_0000;
const attr_read_only: u8 = 0x01;
const attr_hidden: u8 = 0x02;
const attr_system: u8 = 0x04;
const attr_volume_id: u8 = 0x08;
const attr_directory: u8 = 0x10;
const attr_archive: u8 = 0x20;
const attr_long_name: u8 = attr_read_only | attr_hidden | attr_system | attr_volume_id;
const timestamp_date_placeholder: u16 = 1 << 5 | 1;

const VolumeInfo = struct {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    fat_count: u8,
    fat_size_sectors: u32,
    total_sectors: u32,
    root_cluster: u32,
    fsinfo_sector: u16,
    backup_boot_sector: u16,
    hidden_sectors: u32,
    media_descriptor: u8,
    sectors_per_track: u16,
    head_count: u16,
    volume_id: u32,
    volume_label: [11]u8,
    data_start_sector: u64,
    data_cluster_count: u32,

    fn clusterSize(self: VolumeInfo) usize {
        return @as(usize, self.bytes_per_sector) * self.sectors_per_cluster;
    }

    fn maxClusterNumber(self: VolumeInfo) u32 {
        return self.data_cluster_count + 1;
    }
};

const DirectoryEntryLocation = struct {
    first_slot: usize,
    slot_count: usize,

    fn shortSlot(self: DirectoryEntryLocation) usize {
        return self.first_slot + self.slot_count - 1;
    }
};

const LocatedEntry = struct {
    short_name: [11]u8,
    utf16_name: [max_long_name_units]u16,
    utf16_len: usize,
    attr: u8,
    first_cluster: u32,
    size: u32,
    first_slot: usize,
    slot_count: usize,

    fn kind(self: LocatedEntry) DirEntryKind {
        return if (self.attr & attr_directory != 0) .directory else .file;
    }

    fn location(self: LocatedEntry) DirectoryEntryLocation {
        return .{ .first_slot = self.first_slot, .slot_count = self.slot_count };
    }

    fn matches(self: LocatedEntry, wanted: []const u8) bool {
        var utf16: [max_long_name_units]u16 = undefined;
        const units = encodeLongName(wanted, &utf16) catch return false;
        if (units.len != self.utf16_len) return false;
        var i: usize = 0;
        while (i < units.len) : (i += 1) {
            if (!utf16EqualFold(units[i], self.utf16_name[i])) return false;
        }
        return true;
    }

    fn nameAlloc(
        self: LocatedEntry,
        allocator: std.mem.Allocator,
    ) (Error || std.mem.Allocator.Error)![]u8 {
        var utf8_len: usize = 0;
        var i: usize = 0;
        while (i < self.utf16_len) {
            const scalar, const consumed = try decodeUtf16Scalar(
                self.utf16_name[i..self.utf16_len],
            );
            utf8_len += std.unicode.utf8CodepointSequenceLength(
                scalar,
            ) catch return error.UnsupportedName;
            i += consumed;
        }
        const out = try allocator.alloc(u8, utf8_len);
        var out_i: usize = 0;
        i = 0;
        while (i < self.utf16_len) {
            const scalar, const consumed = try decodeUtf16Scalar(
                self.utf16_name[i..self.utf16_len],
            );
            out_i += std.unicode.utf8Encode(
                scalar,
                out[out_i..],
            ) catch return error.UnsupportedName;
            i += consumed;
        }
        return out;
    }
};

const DirectoryIterator = struct {
    fs: *FileSystem,
    cluster: u32,
    cluster_buf: [max_cluster_size]u8 = undefined,
    offset_in_cluster: usize = 0,
    slot_index: usize = 0,
    eof: bool = false,
    lfn: LongNameState = .{},
    chain_tracker: ChainTracker,

    fn init(fs: *FileSystem, io: Io, cluster: u32) MutationError!DirectoryIterator {
        if (!fs.isDataCluster(cluster)) return error.BadClusterChain;
        var iter = DirectoryIterator{
            .fs = fs,
            .cluster = cluster,
            .chain_tracker = ChainTracker.init(cluster),
        };
        try iter.fs.readCluster(io, cluster, iter.cluster_buf[0..iter.fs.info.clusterSize()]);
        return iter;
    }

    fn next(self: *DirectoryIterator, io: Io, _: ?[]const u8) MutationError!?LocatedEntry {
        if (self.eof) return null;
        const cluster_size = self.fs.info.clusterSize();

        while (true) {
            if (self.offset_in_cluster == cluster_size) {
                const next_cluster = try self.fs.nextCluster(io, self.cluster);
                if (next_cluster == null) {
                    self.eof = true;
                    return null;
                }
                try self.chain_tracker.advance(
                    next_cluster.?,
                    self.fs.info.data_cluster_count,
                );
                self.cluster = next_cluster.?;
                self.offset_in_cluster = 0;
                try self.fs.readCluster(io, self.cluster, self.cluster_buf[0..cluster_size]);
            }

            const slot_index = self.slot_index;
            self.slot_index += 1;
            const entry = self.cluster_buf[self.offset_in_cluster .. self.offset_in_cluster + directory_entry_size];
            self.offset_in_cluster += directory_entry_size;

            if (entry[0] == 0x00) {
                self.eof = true;
                return null;
            }
            if (entry[0] == 0xE5) {
                self.lfn.reset();
                continue;
            }
            if (entry[11] == attr_long_name) {
                self.lfn.push(entry) catch self.lfn.reset();
                continue;
            }

            const located = try makeLocatedEntry(entry, &self.lfn, slot_index);
            self.lfn.reset();
            return located;
        }
    }
};

const ChainTracker = struct {
    anchor: u32,
    power: u32 = 1,
    length: u32 = 0,
    steps: u32 = 0,

    fn init(first: u32) ChainTracker {
        return .{ .anchor = first };
    }

    fn advance(
        self: *ChainTracker,
        next: u32,
        max_steps: u32,
    ) Error!void {
        self.steps = std.math.add(u32, self.steps, 1) catch
            return error.BadClusterChain;
        if (self.steps > max_steps or next == self.anchor)
            return error.BadClusterChain;
        self.length += 1;
        if (self.length == self.power) {
            self.anchor = next;
            self.power = std.math.mul(u32, self.power, 2) catch
                max_steps;
            self.length = 0;
        }
    }
};

const LongNameState = struct {
    units: [max_long_name_units]u16 = undefined,
    len: usize = 0,
    checksum: u8 = 0,
    expected_sequence: u8 = 0,
    slot_count: usize = 0,
    active: bool = false,

    fn reset(self: *LongNameState) void {
        self.* = .{};
    }

    fn push(self: *LongNameState, entry: []const u8) Error!void {
        const sequence = entry[0] & 0x1F;
        if (sequence == 0) return error.InvalidBootSector;
        const is_last = entry[0] & 0x40 != 0;
        const checksum = entry[13];
        if (is_last) {
            self.reset();
            self.active = true;
            self.expected_sequence = sequence;
            self.checksum = checksum;
            self.len = @as(usize, sequence) * 13;
            if (self.len > self.units.len) return error.PathComponentTooLong;
        } else if (!self.active or sequence != self.expected_sequence - 1 or checksum != self.checksum) {
            return error.InvalidBootSector;
        }
        self.expected_sequence = sequence;
        self.slot_count += 1;
        const index = (@as(usize, sequence) - 1) * 13;
        copyLfnUnits(self.units[index .. index + 13], entry);
        if (sequence == 1) {
            var actual_len: usize = 0;
            while (actual_len < self.len and self.units[actual_len] != 0x0000 and self.units[actual_len] != 0xFFFF) : (actual_len += 1) {}
            self.len = actual_len;
        }
    }
};

fn computeLayout(options: FormatOptions) Error!VolumeInfo {
    if (!isSupportedBytesPerSector(options.bytes_per_sector)) return error.UnsupportedBytesPerSector;
    if (options.partition_len % options.bytes_per_sector != 0) return error.PartitionLengthNotAligned;
    if (options.fat_count == 0) return error.InvalidFatCount;
    if (options.reserved_sector_count < 8) return error.InvalidBootSector;

    const total_sectors_u64 = options.partition_len / options.bytes_per_sector;
    if (total_sectors_u64 > std.math.maxInt(u32)) return error.VolumeTooSmall;
    const total_sectors: u32 = @intCast(total_sectors_u64);

    const sectors_per_cluster = if (options.sectors_per_cluster) |spc| blk: {
        if (!isValidSectorsPerCluster(spc)) return error.InvalidSectorsPerCluster;
        if (@as(u32, spc) * options.bytes_per_sector > max_cluster_size) return error.InvalidSectorsPerCluster;
        break :blk spc;
    } else try chooseSectorsPerCluster(total_sectors, options.bytes_per_sector, options.reserved_sector_count, options.fat_count);

    const layout = try layoutFor(total_sectors, options.bytes_per_sector, options.reserved_sector_count, options.fat_count, sectors_per_cluster);
    if (layout.data_cluster_count < min_fat32_clusters) return error.VolumeTooSmall;

    return .{
        .bytes_per_sector = options.bytes_per_sector,
        .sectors_per_cluster = sectors_per_cluster,
        .reserved_sector_count = options.reserved_sector_count,
        .fat_count = options.fat_count,
        .fat_size_sectors = layout.fat_size_sectors,
        .total_sectors = total_sectors,
        .root_cluster = 2,
        .fsinfo_sector = 1,
        .backup_boot_sector = 6,
        .hidden_sectors = options.hidden_sectors,
        .media_descriptor = options.media_descriptor,
        .sectors_per_track = options.sectors_per_track,
        .head_count = options.head_count,
        .volume_id = options.volume_id,
        .volume_label = options.volume_label,
        .data_start_sector = layout.data_start_sector,
        .data_cluster_count = layout.data_cluster_count,
    };
}

fn chooseSectorsPerCluster(total_sectors: u32, bytes_per_sector: u16, reserved_sector_count: u16, fat_count: u8) Error!u8 {
    const candidates = [_]u8{ 1, 2, 4, 8, 16, 32, 64, 128 };
    for (candidates) |candidate| {
        if (@as(u32, candidate) * bytes_per_sector > max_cluster_size) continue;
        const layout = try layoutFor(total_sectors, bytes_per_sector, reserved_sector_count, fat_count, candidate);
        if (layout.data_cluster_count >= min_fat32_clusters) return candidate;
    }
    return error.VolumeTooSmall;
}

fn layoutFor(total_sectors: u32, bytes_per_sector: u16, reserved_sector_count: u16, fat_count: u8, sectors_per_cluster: u8) Error!struct { fat_size_sectors: u32, data_start_sector: u64, data_cluster_count: u32 } {
    var fat_size: u32 = 1;
    while (true) {
        const metadata_sectors = @as(u64, reserved_sector_count) + @as(u64, fat_count) * fat_size;
        if (metadata_sectors >= total_sectors) return error.VolumeTooSmall;
        const data_sectors = @as(u64, total_sectors) - metadata_sectors;
        const cluster_count: u32 = @intCast(data_sectors / sectors_per_cluster);
        if (cluster_count == 0) return error.VolumeTooSmall;
        const needed_fat = std.math.divCeil(u64, (@as(u64, cluster_count) + 2) * 4, bytes_per_sector) catch unreachable;
        if (needed_fat <= fat_size) {
            return .{
                .fat_size_sectors = fat_size,
                .data_start_sector = metadata_sectors,
                .data_cluster_count = cluster_count,
            };
        }
        fat_size = @intCast(needed_fat);
    }
}

fn buildBootSector(info: VolumeInfo) [default_bytes_per_sector]u8 {
    var sector: [default_bytes_per_sector]u8 = [_]u8{0} ** default_bytes_per_sector;
    sector[0] = 0xEB;
    sector[1] = 0x58;
    sector[2] = 0x90;
    sector[3..11].* = "mizFAT  ".*;
    std.mem.writeInt(u16, sector[11..13], info.bytes_per_sector, .little);
    sector[13] = info.sectors_per_cluster;
    std.mem.writeInt(u16, sector[14..16], info.reserved_sector_count, .little);
    sector[16] = info.fat_count;
    std.mem.writeInt(u16, sector[17..19], 0, .little);
    std.mem.writeInt(u16, sector[19..21], 0, .little);
    sector[21] = info.media_descriptor;
    std.mem.writeInt(u16, sector[22..24], 0, .little);
    std.mem.writeInt(u16, sector[24..26], info.sectors_per_track, .little);
    std.mem.writeInt(u16, sector[26..28], info.head_count, .little);
    std.mem.writeInt(u32, sector[28..32], info.hidden_sectors, .little);
    std.mem.writeInt(u32, sector[32..36], info.total_sectors, .little);
    std.mem.writeInt(u32, sector[36..40], info.fat_size_sectors, .little);
    std.mem.writeInt(u16, sector[40..42], 0, .little);
    std.mem.writeInt(u16, sector[42..44], 0, .little);
    std.mem.writeInt(u32, sector[44..48], info.root_cluster, .little);
    std.mem.writeInt(u16, sector[48..50], info.fsinfo_sector, .little);
    std.mem.writeInt(u16, sector[50..52], info.backup_boot_sector, .little);
    sector[64] = 0x80;
    sector[66] = 0x29;
    std.mem.writeInt(u32, sector[67..71], info.volume_id, .little);
    sector[71..82].* = info.volume_label;
    sector[82..90].* = "FAT32   ".*;
    sector[510] = 0x55;
    sector[511] = 0xAA;
    return sector;
}

fn zeroRange(fs: *const FileSystem, io: Io, start: u64, length: u64) MutationError!void {
    var zeros: [4096]u8 = [_]u8{0} ** 4096;
    var written: u64 = 0;
    while (written < length) {
        const take: usize = @intCast(@min(length - written, zeros.len));
        try fs.writeRegion(io, zeros[0..take], start + written);
        written += take;
    }
}

fn isSupportedBytesPerSector(value: u16) bool {
    return value == 512 or value == 1024 or value == 2048 or value == 4096;
}

fn isValidSectorsPerCluster(value: u8) bool {
    return value != 0 and std.math.isPowerOfTwo(value) and value <= 128;
}

fn isRootPath(path: []const u8) bool {
    return path.len == 0 or std.mem.eql(u8, path, "/");
}

fn validateComponent(component: []const u8) Error!void {
    if (component.len == 0) return error.InvalidPath;
    if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return error.InvalidPath;
    if (component[component.len - 1] == ' ' or component[component.len - 1] == '.') return error.UnsupportedName;

    var utf16_units: [max_long_name_units]u16 = undefined;
    const units = try encodeLongName(component, &utf16_units);
    if (units.len == 0) return error.InvalidPath;
}

fn encodeLongName(name: []const u8, out: *[max_long_name_units]u16) Error![]const u16 {
    var in_i: usize = 0;
    var out_i: usize = 0;
    while (in_i < name.len) {
        const cp_len = std.unicode.utf8ByteSequenceLength(name[in_i]) catch return error.UnsupportedName;
        if (in_i + cp_len > name.len) return error.UnsupportedName;
        const codepoint = std.unicode.utf8Decode(name[in_i .. in_i + cp_len]) catch return error.UnsupportedName;
        switch (codepoint) {
            0...31 => return error.UnsupportedName,
            '/', '\\', ':', '*', '?', '"', '<', '>', '|' => return error.UnsupportedName,
            else => {},
        }
        if (codepoint <= 0xFFFF) {
            if (out_i >= out.len) return error.PathComponentTooLong;
            out[out_i] = @intCast(codepoint);
            out_i += 1;
        } else {
            if (out_i + 1 >= out.len) return error.PathComponentTooLong;
            const scalar = codepoint - 0x1_0000;
            out[out_i] = @intCast(0xD800 + (scalar >> 10));
            out[out_i + 1] = @intCast(0xDC00 + (scalar & 0x3FF));
            out_i += 2;
        }
        in_i += cp_len;
    }
    return out[0..out_i];
}

fn decodeUtf16Scalar(units: []const u16) Error!struct { u21, usize } {
    const first = units[0];
    if (first >= 0xD800 and first <= 0xDBFF) {
        if (units.len < 2) return error.UnsupportedName;
        const second = units[1];
        if (second < 0xDC00 or second > 0xDFFF) return error.UnsupportedName;
        const scalar = 0x1_0000 + (((@as(u21, first) - 0xD800) << 10) | (@as(u21, second) - 0xDC00));
        return .{ scalar, 2 };
    }
    if (first >= 0xDC00 and first <= 0xDFFF) return error.UnsupportedName;
    return .{ first, 1 };
}

fn utf16EqualFold(a: u16, b: u16) bool {
    if (a < 128 and b < 128) return std.ascii.toUpper(@intCast(a)) == std.ascii.toUpper(@intCast(b));
    return a == b;
}

fn makeLocatedEntry(entry: []const u8, lfn: *LongNameState, short_slot: usize) MutationError!LocatedEntry {
    var result = LocatedEntry{
        .short_name = undefined,
        .utf16_name = undefined,
        .utf16_len = 0,
        .attr = entry[11],
        .first_cluster = (@as(u32, std.mem.readInt(u16, entry[20..22], .little)) << 16) | std.mem.readInt(u16, entry[26..28], .little),
        .size = std.mem.readInt(u32, entry[28..32], .little),
        .first_slot = short_slot,
        .slot_count = 1,
    };
    @memcpy(&result.short_name, entry[0..11]);

    const has_lfn = lfn.active and lfn.expected_sequence == 1 and shortNameChecksum(result.short_name) == lfn.checksum and lfn.len > 0;
    if (has_lfn) {
        result.utf16_len = lfn.len;
        @memcpy(result.utf16_name[0..lfn.len], lfn.units[0..lfn.len]);
        result.first_slot = short_slot - lfn.slot_count;
        result.slot_count = lfn.slot_count + 1;
    } else {
        result.utf16_len = try decodeShortNameUtf16(result.short_name, &result.utf16_name);
    }
    return result;
}

fn decodeShortNameUtf16(short_name: [11]u8, out: *[max_long_name_units]u16) Error!usize {
    var len: usize = 0;
    var base_end: usize = 8;
    while (base_end > 0 and short_name[base_end - 1] == ' ') : (base_end -= 1) {}
    var i: usize = 0;
    while (i < base_end) : (i += 1) {
        out[len] = if (i == 0 and short_name[i] == 0x05) 0x00E5 else short_name[i];
        len += 1;
    }
    var ext_end: usize = 11;
    while (ext_end > 8 and short_name[ext_end - 1] == ' ') : (ext_end -= 1) {}
    if (ext_end > 8) {
        out[len] = '.';
        len += 1;
        i = 8;
        while (i < ext_end) : (i += 1) {
            out[len] = short_name[i];
            len += 1;
        }
    }
    return len;
}

fn requiresLongName(name: []const u8, short_name: [11]u8) bool {
    if (isCanonicalShortName(name)) {
        var utf16_name: [max_long_name_units]u16 = undefined;
        const units = encodeLongName(name, &utf16_name) catch return true;
        var short_units: [max_long_name_units]u16 = undefined;
        const short_len = decodeShortNameUtf16(short_name, &short_units) catch return true;
        if (units.len != short_len) return true;
        var i: usize = 0;
        while (i < units.len) : (i += 1) {
            if (units[i] != short_units[i]) return true;
        }
        return false;
    }
    return true;
}

fn isCanonicalShortName(name: []const u8) bool {
    const split = splitName(name);
    if (split.base.len == 0 or split.base.len > 8 or split.ext.len > 3) return false;
    for (split.base) |ch| if (!isCanonicalShortChar(ch)) return false;
    for (split.ext) |ch| if (!isCanonicalShortChar(ch)) return false;
    return true;
}

fn isCanonicalShortChar(ch: u8) bool {
    return (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or switch (ch) {
        '$', '%', '\'', '-', '_', '@', '~', '`', '!', '(', ')', '{', '}', '^', '#', '&' => true,
        else => false,
    };
}

fn sanitizeShortComponent(source: []const u8, max_len: usize, default_value: []const u8, out: []u8) usize {
    var len: usize = 0;
    for (source) |ch| {
        if (ch == ' ' or ch == '.') continue;
        const upper = std.ascii.toUpper(ch);
        if (isCanonicalShortChar(upper)) {
            out[len] = upper;
        } else if (upper < 128) {
            out[len] = '_';
        } else {
            continue;
        }
        len += 1;
        if (len == max_len) break;
    }
    if (len == 0) {
        const take = @min(max_len, default_value.len);
        @memcpy(out[0..take], default_value[0..take]);
        return take;
    }
    return len;
}

fn splitName(name: []const u8) struct { base: []const u8, ext: []const u8 } {
    if (std.mem.lastIndexOfScalar(u8, name, '.')) |dot| {
        if (dot == 0 or dot == name.len - 1) return .{ .base = name, .ext = "" };
        return .{ .base = name[0..dot], .ext = name[dot + 1 ..] };
    }
    return .{ .base = name, .ext = "" };
}

fn buildShortName(base: []const u8, ext: []const u8) [11]u8 {
    var short_name = [_]u8{' '} ** 11;
    @memcpy(short_name[0..base.len], base);
    @memcpy(short_name[8 .. 8 + ext.len], ext);
    return short_name;
}

fn chooseShortName(fs: *FileSystem, io: Io, dir_cluster: u32, name: []const u8) MutationError![11]u8 {
    const split = splitName(name);
    if (isCanonicalShortName(name)) {
        const direct = buildShortName(split.base, split.ext);
        if (try shortNameExists(fs, io, dir_cluster, direct)) return error.AlreadyExists;
        return direct;
    }

    var base_buf: [8]u8 = undefined;
    var ext_buf: [3]u8 = undefined;
    const ext_len = sanitizeShortComponent(split.ext, 3, "", &ext_buf);
    const stem_len = sanitizeShortComponent(split.base, 8, "FILE", &base_buf);

    var suffix_num: u32 = 1;
    while (suffix_num < 1_000_000) : (suffix_num += 1) {
        var suffix_buf: [8]u8 = undefined;
        const suffix = try std.fmt.bufPrint(&suffix_buf, "~{d}", .{suffix_num});
        var stem_with_suffix: [8]u8 = [_]u8{' '} ** 8;
        const prefix_len = 8 - suffix.len;
        const copy_len = @min(prefix_len, stem_len);
        @memcpy(stem_with_suffix[0..copy_len], base_buf[0..copy_len]);
        @memcpy(stem_with_suffix[prefix_len .. prefix_len + suffix.len], suffix);
        const candidate = buildShortName(trimSpaces(&stem_with_suffix), ext_buf[0..ext_len]);
        if (!(try shortNameExists(fs, io, dir_cluster, candidate))) return candidate;
    }
    return error.NoSpaceLeft;
}

fn trimSpaces(buf: []const u8) []const u8 {
    var end = buf.len;
    while (end > 0 and buf[end - 1] == ' ') : (end -= 1) {}
    return buf[0..end];
}

fn shortNameExists(fs: *FileSystem, io: Io, dir_cluster: u32, short_name: [11]u8) MutationError!bool {
    var iter = try DirectoryIterator.init(fs, io, dir_cluster);
    while (try iter.next(io, null)) |entry| {
        if (std.mem.eql(u8, &entry.short_name, &short_name)) return true;
    }
    return false;
}

fn shortNameChecksum(short_name: [11]u8) u8 {
    var sum: u8 = 0;
    for (short_name) |ch| {
        sum = (((sum & 1) << 7) +% (sum >> 1)) +% ch;
    }
    return sum;
}

fn buildShortEntry(short_name: [11]u8, kind: DirEntryKind, first_cluster: u32, size: u32) [directory_entry_size]u8 {
    var entry: [directory_entry_size]u8 = [_]u8{0} ** directory_entry_size;
    entry[0..11].* = short_name;
    entry[11] = if (kind == .directory) attr_directory else attr_archive;
    std.mem.writeInt(u16, entry[14..16], 0, .little);
    std.mem.writeInt(u16, entry[16..18], timestamp_date_placeholder, .little);
    std.mem.writeInt(u16, entry[18..20], timestamp_date_placeholder, .little);
    std.mem.writeInt(u16, entry[20..22], @intCast(first_cluster >> 16), .little);
    std.mem.writeInt(u16, entry[22..24], 0, .little);
    std.mem.writeInt(u16, entry[24..26], timestamp_date_placeholder, .little);
    std.mem.writeInt(u16, entry[26..28], @intCast(first_cluster & 0xFFFF), .little);
    std.mem.writeInt(u32, entry[28..32], size, .little);
    return entry;
}

fn buildDotEntry(parent: bool, cluster: u32) [directory_entry_size]u8 {
    var name = [_]u8{' '} ** 11;
    name[0] = '.';
    if (parent) name[1] = '.';
    return buildShortEntry(name, .directory, cluster, 0);
}

fn isDotEntry(short_name: [11]u8) bool {
    return short_name[0] == '.' and (short_name[1] == ' ' or short_name[1] == '.');
}

fn buildLfnEntries(entries: [][directory_entry_size]u8, utf16_name: []const u16, short_name: [11]u8) void {
    const checksum = shortNameChecksum(short_name);
    const count = entries.len;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const sequence = count - index;
        var entry: [directory_entry_size]u8 = [_]u8{0} ** directory_entry_size;
        entry[0] = @intCast(sequence);
        if (index == 0) entry[0] |= 0x40;
        entry[11] = attr_long_name;
        entry[12] = 0;
        entry[13] = checksum;
        std.mem.writeInt(u16, entry[26..28], 0, .little);

        const start = (sequence - 1) * 13;
        var units: [13]u16 = [_]u16{0xFFFF} ** 13;
        var i: usize = 0;
        while (i < 13 and start + i < utf16_name.len) : (i += 1) units[i] = utf16_name[start + i];
        if (start + i == utf16_name.len and i < 13) {
            units[i] = 0x0000;
            i += 1;
            while (i < 13) : (i += 1) units[i] = 0xFFFF;
        }
        writeLfnUnitSlice(entry[1..11], units[0..5]);
        writeLfnUnitSlice(entry[14..26], units[5..11]);
        writeLfnUnitSlice(entry[28..32], units[11..13]);
        entries[index] = entry;
    }
}

fn writeLfnUnitSlice(bytes: []u8, units: []const u16) void {
    var i: usize = 0;
    while (i < units.len) : (i += 1) {
        std.mem.writeInt(u16, bytes[i * 2 ..][0..2], units[i], .little);
    }
}

fn copyLfnUnits(out: []u16, entry: []const u8) void {
    readLfnUnitSlice(out[0..5], entry[1..11]);
    readLfnUnitSlice(out[5..11], entry[14..26]);
    readLfnUnitSlice(out[11..13], entry[28..32]);
}

fn readLfnUnitSlice(out: []u16, bytes: []const u8) void {
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = std.mem.readInt(u16, bytes[i * 2 ..][0..2], .little);
    }
}

fn allocPattern(allocator: std.mem.Allocator, len: usize, seed: u32) std.mem.Allocator.Error![]u8 {
    const buffer = try allocator.alloc(u8, len);
    for (buffer, 0..) |*byte, index| {
        byte.* = @truncate((seed +% @as(u32, @intCast(index)) *% 31) & 0xFF);
    }
    return buffer;
}

fn collectClusterChain(fs: *FileSystem, io: Io, allocator: std.mem.Allocator, first_cluster: u32) (MutationError || std.mem.Allocator.Error)![]u32 {
    if (first_cluster == 0) return allocator.alloc(u32, 0);

    var clusters = std.array_list.Managed(u32).init(allocator);
    errdefer clusters.deinit();

    var cluster = first_cluster;
    while (true) {
        try clusters.append(cluster);
        const next = try fs.nextCluster(io, cluster);
        if (next == null) break;
        cluster = next.?;
    }

    return clusters.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Read-only tree import
//
// An ESP is vfat, so merging a real installed system into one root filesystem
// means reading a FAT volume out as a tree and handing it to the same
// `FileTreeView` interface `bootconfig` already populates an ESP through. The
// direction is the only new part: everything below reads, and nothing here
// ever writes.
//
// vfat records none of the metadata a POSIX tree needs -- no ownership, no
// permission bits, no symlinks, no hardlinks, no device nodes, no extended
// attributes, and no timestamps this project would trust. Every one of those
// therefore has to be *invented* at the boundary. That is exactly why
// `SynthesizedMetadata` is a value the caller passes rather than a constant
// buried in the scanner: an image whose `/boot/efi` is `root:root 0755` should
// say so somewhere an operator can read, not have it silently assumed.
// ---------------------------------------------------------------------------

const limit_defaults = limits_mod.ImportLimits{};

/// The POSIX metadata synthesized for every entry read out of a FAT volume,
/// because the volume itself carries none of it.
///
/// The defaults describe an ESP as every Linux distribution mounts one: owned
/// by root, readable by everyone, writable by nobody else.
pub const SynthesizedMetadata = struct {
    /// `0755`. A directory has to stay traversable, or the bootloader files
    /// under it become unreachable to anything not running as root.
    directory_mode: u16 = 0o755,
    /// `0644`. The execute bit means nothing on a real vfat mount -- it comes
    /// from the mount options, not the file -- so granting it here would be
    /// inventing a permission the source never had.
    file_mode: u16 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
};

pub const ScanOptions = struct {
    /// What to invent for metadata vfat cannot store. Never defaulted
    /// silently at a call site: the caller either accepts these documented
    /// values or states its own.
    metadata: SynthesizedMetadata = .{},
    max_nodes: usize = limit_defaults.max_nodes,
    max_path_bytes: usize = limit_defaults.max_path_bytes,
    max_component_bytes: usize = limit_defaults.max_component_bytes,
    max_file_bytes: u64 = limit_defaults.max_file_bytes,
    max_total_bytes: u64 = limit_defaults.max_total_bytes,
    max_scan_metadata_bytes: usize = limit_defaults.max_scan_metadata_bytes,
    /// Optional sink for the peak measurements and the first limit breach.
    /// The scanner is torn down before `scanTree` returns, so a failure can
    /// only report through a sink the caller still owns.
    diagnostic: ?*limits_mod.Diagnostic = null,
};

pub const ScanError = Error || Image.PreadError || Image.PwriteError ||
    std.mem.Allocator.Error || limits_mod.Error || error{
    /// A mode carrying more than the permission/setuid/sticky bits would
    /// turn a synthesized entry into a different file type entirely.
    InvalidSynthesizedMode,
    /// A directory reachable from itself. FAT stores no parent pointer worth
    /// trusting, so a corrupt `..` or a hand-edited chain can describe an
    /// infinitely deep tree; refusing beats walking it forever.
    DirectoryCycle,
    /// A name FAT permits but a POSIX tree cannot carry, such as one holding
    /// a `/` or a NUL.
    InvalidImportedName,
};

pub const TreeKind = enum { directory, file };

pub const TreeEntry = struct {
    /// Relative path with `/` separators and no leading `/`.
    path: []const u8,
    kind: TreeKind,
    /// Synthesized; see `SynthesizedMetadata`.
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    content: ?ext4.FileTreeView.ContentReader,
};

/// A contiguous span of clusters inside one file.
///
/// The chain is resolved once, at scan time, and stored as runs rather than
/// walked again per read. Walking it per read would make a sequential copy of
/// an n-cluster file quadratic in n, and storing one entry per cluster would
/// cost 4 bytes per 4 KiB of ESP. A file written once by a bootloader
/// installer is almost always a single run, so runs are both the cheapest and
/// the fastest representation for the case that actually occurs.
const ClusterRun = struct {
    start_cluster: u32,
    cluster_count: u32,
};

/// Enough state to read one file's bytes without touching the directory tree
/// again. `fs` is borrowed, so the filesystem must outlive the tree.
const FatContent = struct {
    fs: *FileSystem,
    io: Io,
    size: u64,
    cluster_bytes: u32,
    runs: []const ClusterRun,
};

const TreeNode = struct {
    path: []u8,
    kind: TreeKind,
    size: u64,
    runs: []ClusterRun,
    content: FatContent,
};

/// A FAT volume read out as an ordered tree: every directory appears before
/// its children, so an importer that creates parents implicitly never has to.
/// File bytes stay in the volume until an importer spools them.
pub const Tree = struct {
    allocator: std.mem.Allocator,
    entries: []TreeNode,
    /// Repeated on every entry, and on the root, because vfat has no per-file
    /// metadata to differ from it.
    metadata: SynthesizedMetadata,
    /// The volume's 11-byte label field, exactly as stored.
    label: [11]u8,
    volume_id: u32,
    /// Guest-visible file bytes. This is the scratch space an import needs.
    content_bytes: u64,
    view: ext4.FileTreeView = .{
        .ctx = undefined,
        .next_fn = treeViewNext,
        .reset_fn = treeViewReset,
    },
    iteration_index: usize = 0,

    pub fn deinit(self: *Tree) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.path);
            self.allocator.free(entry.runs);
        }
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    /// Excludes the implicit root directory, matching the ext4 importers.
    pub fn nodeCount(self: *const Tree) usize {
        return self.entries.len;
    }

    pub fn entryAt(self: *Tree, index: usize) TreeEntry {
        const node = &self.entries[index];
        return .{
            .path = node.path,
            .kind = node.kind,
            .mode = switch (node.kind) {
                .directory => self.metadata.directory_mode,
                .file => self.metadata.file_mode,
            },
            .uid = self.metadata.uid,
            .gid = self.metadata.gid,
            .size = node.size,
            .content = if (node.kind == .file) .{
                .ctx = &node.content,
                .read_at_fn = treeContentReadAt,
            } else null,
        };
    }

    pub fn fileTreeView(self: *Tree) *ext4.FileTreeView {
        self.iteration_index = 0;
        self.view = .{
            .ctx = self,
            .next_fn = treeViewNext,
            .reset_fn = treeViewReset,
        };
        return &self.view;
    }

    fn treeViewReset(ctx: *anyopaque) void {
        const self: *Tree = @ptrCast(@alignCast(ctx));
        self.iteration_index = 0;
    }

    fn treeViewNext(ctx: *anyopaque) ext4.FileTreeView.IteratorError!?ext4.FileTreeView.Entry {
        const self: *Tree = @ptrCast(@alignCast(ctx));
        if (self.iteration_index >= self.entries.len) return null;
        const entry = self.entryAt(self.iteration_index);
        self.iteration_index += 1;
        return .{
            .path = entry.path,
            .kind = switch (entry.kind) {
                .directory => .directory,
                .file => .file,
            },
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = entry.content,
        };
    }
};

fn treeContentReadAt(
    ctx: *const anyopaque,
    buffer: []u8,
    offset: u64,
) ext4.FileTreeView.ContentError!usize {
    const content: *const FatContent = @ptrCast(@alignCast(ctx));
    return readFatContent(content, buffer, offset) catch error.ReadFailed;
}

fn readFatContent(content: *const FatContent, buffer: []u8, offset: u64) !usize {
    if (offset >= content.size) return 0;
    const remaining = content.size - offset;
    const wanted: usize = @intCast(@min(@as(u64, buffer.len), remaining));
    if (wanted == 0) return 0;

    const cluster_index = offset / content.cluster_bytes;
    const inside = offset % content.cluster_bytes;
    var skipped: u64 = 0;
    for (content.runs) |run| {
        const next = skipped + run.cluster_count;
        if (cluster_index >= next) {
            skipped = next;
            continue;
        }
        const within_run = cluster_index - skipped;
        const cluster: u32 = @intCast(run.start_cluster + within_run);
        // Clusters inside one run are physically adjacent, so a read may
        // cross cluster boundaries without another chain lookup.
        const run_tail = (@as(u64, run.cluster_count) - within_run) * content.cluster_bytes - inside;
        const take: usize = @intCast(@min(@as(u64, wanted), run_tail));
        const start = content.fs.clusterOffset(cluster) + inside;
        try content.fs.readRegion(content.io, buffer[0..take], start);
        return take;
    }
    return error.BadClusterChain;
}

/// Reads `fs` out as a tree. Nothing is written, and the volume is never
/// opened for writing. `fs` must outlive the returned tree, which keeps
/// read-only references into it for file content.
pub fn scanTree(
    fs: *FileSystem,
    io: Io,
    allocator: std.mem.Allocator,
    options: ScanOptions,
) ScanError!Tree {
    if (options.metadata.directory_mode > 0o7777 or options.metadata.file_mode > 0o7777) {
        return error.InvalidSynthesizedMode;
    }
    var scanner = TreeScanner{
        .fs = fs,
        .io = io,
        .allocator = allocator,
        .options = options,
        .entries = .init(allocator),
        .visited = .init(allocator),
    };
    defer scanner.deinit();
    try scanner.walk(fs.info.root_cluster, "");
    return scanner.finish();
}

const TreeScanner = struct {
    fs: *FileSystem,
    io: Io,
    allocator: std.mem.Allocator,
    options: ScanOptions,
    entries: std.array_list.Managed(TreeNode),
    /// Directory clusters already entered. FAT has no inode table to mark, so
    /// the first cluster of a directory is its identity.
    visited: std.AutoHashMap(u32, void),
    content_bytes: u64 = 0,
    metadata_bytes: usize = 0,
    finished: bool = false,

    fn deinit(self: *TreeScanner) void {
        if (!self.finished) {
            for (self.entries.items) |entry| {
                self.allocator.free(entry.path);
                self.allocator.free(entry.runs);
            }
        }
        self.entries.deinit();
        self.visited.deinit();
    }

    fn finish(self: *TreeScanner) ScanError!Tree {
        const entries = try self.entries.toOwnedSlice();
        self.finished = true;
        return .{
            .allocator = self.allocator,
            .entries = entries,
            .metadata = self.options.metadata,
            .label = self.fs.info.volume_label,
            .volume_id = self.fs.info.volume_id,
            .content_bytes = self.content_bytes,
        };
    }

    /// Depth needs no separate limit: every level appends at least two bytes
    /// to `prefix`, so `max_path_bytes` already bounds the recursion.
    fn walk(self: *TreeScanner, cluster: u32, prefix: []const u8) ScanError!void {
        if ((try self.visited.getOrPut(cluster)).found_existing) return error.DirectoryCycle;

        var children = std.array_list.Managed(Child).init(self.allocator);
        defer {
            for (children.items) |child| self.allocator.free(child.name);
            children.deinit();
        }

        var iterator = try DirectoryIterator.init(self.fs, self.io, cluster);
        while (try iterator.next(self.io, null)) |raw| {
            if (raw.attr & attr_volume_id != 0) continue;
            const name = try raw.nameAlloc(self.allocator);
            var owned = true;
            defer if (owned) self.allocator.free(name);
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            // `validateComponent` rejects the names FAT allows but a path
            // cannot carry; the extra guard below names the two that would
            // otherwise split or truncate a path.
            try validateComponent(name);
            if (std.mem.indexOfScalar(u8, name, '/') != null or
                std.mem.indexOfScalar(u8, name, 0) != null)
            {
                return error.InvalidImportedName;
            }
            limits_mod.observe(self.options.diagnostic, .component_bytes, name.len);
            if (name.len > self.options.max_component_bytes) {
                return limits_mod.exceeded(
                    self.options.diagnostic,
                    .component_bytes,
                    name.len,
                    self.options.max_component_bytes,
                );
            }
            for (children.items) |existing| {
                if (std.ascii.eqlIgnoreCase(existing.name, name)) return error.DuplicateName;
            }
            try children.append(.{
                .name = name,
                .kind = raw.kind(),
                .first_cluster = raw.first_cluster,
                .size = raw.size,
            });
            owned = false;
        }

        // Pre-order, so a directory always precedes everything under it and
        // an importer never has to invent a parent.
        for (children.items) |child| {
            const path = try self.joinPath(prefix, child.name);
            var path_owned = true;
            errdefer if (path_owned) self.allocator.free(path);
            switch (child.kind) {
                .directory => {
                    try self.append(.{
                        .path = path,
                        .kind = .directory,
                        .size = 0,
                        .runs = &.{},
                        .content = undefined,
                    });
                    path_owned = false;
                    try self.walk(child.first_cluster, path);
                },
                .file => {
                    limits_mod.observe(self.options.diagnostic, .file_bytes, child.size);
                    if (child.size > self.options.max_file_bytes) {
                        return limits_mod.exceeded(
                            self.options.diagnostic,
                            .file_bytes,
                            child.size,
                            self.options.max_file_bytes,
                        );
                    }
                    self.content_bytes = std.math.add(u64, self.content_bytes, child.size) catch
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
                    const runs = try self.collectRuns(child.first_cluster, child.size);
                    errdefer self.allocator.free(runs);
                    try self.append(.{
                        .path = path,
                        .kind = .file,
                        .size = child.size,
                        .runs = runs,
                        .content = .{
                            .fs = self.fs,
                            .io = self.io,
                            .size = child.size,
                            .cluster_bytes = @intCast(self.fs.info.clusterSize()),
                            .runs = runs,
                        },
                    });
                    path_owned = false;
                },
            }
        }
        _ = self.visited.remove(cluster);
    }

    const Child = struct {
        name: []u8,
        kind: DirEntryKind,
        first_cluster: u32,
        size: u32,
    };

    fn append(self: *TreeScanner, node: TreeNode) ScanError!void {
        const count = self.entries.items.len + 1;
        limits_mod.observe(self.options.diagnostic, .nodes, count);
        if (count > self.options.max_nodes) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .nodes,
                count,
                self.options.max_nodes,
            );
        }
        try self.entries.append(node);
    }

    fn joinPath(self: *TreeScanner, prefix: []const u8, name: []const u8) ScanError![]u8 {
        const length = if (prefix.len == 0) name.len else prefix.len + 1 + name.len;
        limits_mod.observe(self.options.diagnostic, .path_bytes, length);
        if (length > self.options.max_path_bytes) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .path_bytes,
                length,
                self.options.max_path_bytes,
            );
        }
        const path = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(path);
        if (prefix.len == 0) {
            @memcpy(path, name);
        } else {
            @memcpy(path[0..prefix.len], prefix);
            path[prefix.len] = '/';
            @memcpy(path[prefix.len + 1 ..], name);
        }
        try self.chargeMetadata(length);
        return path;
    }

    /// The cluster chain, collapsed into contiguous runs, plus the guard that
    /// keeps a cyclic or over-long chain from being followed forever: the
    /// file's own size says exactly how many clusters it may occupy.
    fn collectRuns(self: *TreeScanner, first_cluster: u32, size: u32) ScanError![]ClusterRun {
        if (size == 0) return self.allocator.alloc(ClusterRun, 0);
        const cluster_bytes = self.fs.info.clusterSize();
        const needed: u64 = std.math.divCeil(u64, size, cluster_bytes) catch unreachable;

        var runs = std.array_list.Managed(ClusterRun).init(self.allocator);
        errdefer runs.deinit();
        var cluster = first_cluster;
        var seen: u64 = 0;
        while (true) {
            if (!self.fs.isDataCluster(cluster)) return error.BadClusterChain;
            if (runs.items.len != 0) {
                const last = &runs.items[runs.items.len - 1];
                if (last.start_cluster + last.cluster_count == cluster) {
                    last.cluster_count += 1;
                } else {
                    try self.appendRun(&runs, cluster);
                }
            } else {
                try self.appendRun(&runs, cluster);
            }
            seen += 1;
            if (seen == needed) break;
            // A chain longer than the file needs is a corrupt volume, not a
            // file with slack: reading past it would hand the guest bytes the
            // directory entry says are not part of this file.
            cluster = (try self.fs.nextCluster(self.io, cluster)) orelse return error.BadClusterChain;
        }
        return runs.toOwnedSlice();
    }

    fn appendRun(
        self: *TreeScanner,
        runs: *std.array_list.Managed(ClusterRun),
        cluster: u32,
    ) ScanError!void {
        try self.chargeMetadata(@sizeOf(ClusterRun));
        try runs.append(.{ .start_cluster = cluster, .cluster_count = 1 });
    }

    /// Everything the scan itself allocates and keeps, which is what the
    /// scan-metadata limit exists to bound.
    fn chargeMetadata(self: *TreeScanner, bytes: usize) ScanError!void {
        self.metadata_bytes = std.math.add(usize, self.metadata_bytes, bytes) catch
            return error.ScanMetadataLimitExceeded;
        limits_mod.observe(self.options.diagnostic, .scan_metadata_bytes, self.metadata_bytes);
        if (self.metadata_bytes > self.options.max_scan_metadata_bytes) {
            return limits_mod.exceeded(
                self.options.diagnostic,
                .scan_metadata_bytes,
                self.metadata_bytes,
                self.options.max_scan_metadata_bytes,
            );
        }
    }
};

fn temporaryTestPath(
    allocator: std.mem.Allocator,
    io: Io,
    temporary: *std.testing.TmpDir,
    sub_path: []const u8,
) ![]const u8 {
    var root_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    return std.fs.path.join(allocator, &.{ root_buffer[0..root_length], sub_path });
}

test "format writes FAT32 boot sector, FSInfo, backup boot sector, and root FAT anchor" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-format.img");
    defer std.testing.allocator.free(path);

    const partition_offset: u64 = 1024 * 1024;
    const partition_len: u64 = 64 * 1024 * 1024;
    const image_len = partition_offset + partition_len + 4096;

    var img = try Image.create(io, path, .raw, image_len, .{});
    defer img.close(io);

    try format(&img, io, .{ .partition_offset = partition_offset, .partition_len = partition_len });

    var boot: [512]u8 = undefined;
    _ = try img.pread(io, &boot, partition_offset);
    try std.testing.expectEqualSlices(u8, "FAT32   ", boot[82..90]);
    try std.testing.expectEqual(@as(u16, 512), std.mem.readInt(u16, boot[11..13], .little));
    try std.testing.expectEqual(@as(u8, 32), std.mem.readInt(u16, boot[14..16], .little));
    try std.testing.expectEqual(@as(u8, 2), boot[16]);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, boot[44..48], .little));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, boot[48..50], .little));
    try std.testing.expectEqual(@as(u16, 6), std.mem.readInt(u16, boot[50..52], .little));
    try std.testing.expectEqual(@as(u8, 0x55), boot[510]);
    try std.testing.expectEqual(@as(u8, 0xAA), boot[511]);

    var fsinfo_sector: [512]u8 = undefined;
    _ = try img.pread(io, &fsinfo_sector, partition_offset + 512);
    try std.testing.expectEqual(fsinfo_lead_signature, std.mem.readInt(u32, fsinfo_sector[0..4], .little));
    try std.testing.expectEqual(fsinfo_struct_signature, std.mem.readInt(u32, fsinfo_sector[484..488], .little));
    try std.testing.expectEqual(fsinfo_trail_signature, std.mem.readInt(u32, fsinfo_sector[508..512], .little));

    var backup_boot: [512]u8 = undefined;
    _ = try img.pread(io, &backup_boot, partition_offset + 6 * 512);
    try std.testing.expectEqualSlices(u8, &boot, &backup_boot);

    var fat0: [12]u8 = undefined;
    _ = try img.pread(io, &fat0, partition_offset + 32 * 512);
    try std.testing.expectEqual(@as(u32, 0x0FFF_FFF8), std.mem.readInt(u32, fat0[0..4], .little) & fat_entry_mask);
    try std.testing.expectEqual(fat_entry_mask, std.mem.readInt(u32, fat0[4..8], .little) & fat_entry_mask);
    try std.testing.expectEqual(fat_entry_eoc, std.mem.readInt(u32, fat0[8..12], .little) & fat_entry_mask);
}

test "cluster exhaustion is distinct from host NoSpaceLeft" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(
        std.testing.allocator,
        io,
        &temporary,
        "test-fat32-full.img",
    );
    defer std.testing.allocator.free(path);

    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);
    try format(&img, io, .{ .partition_offset = 0, .partition_len = partition_len });
    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    fs.free_cluster_count = 0;
    try std.testing.expectError(error.FilesystemFull, fs.writeFile(io, "full.bin", "x"));
}

test "format, write nested tree with VFAT long names, list, and read back" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-roundtrip.img");
    defer std.testing.allocator.free(path);

    const partition_offset: u64 = 2 * 1024 * 1024;
    const partition_len: u64 = 96 * 1024 * 1024;
    const image_len = partition_offset + partition_len;

    var img = try Image.create(io, path, .raw, image_len, .{});
    try format(&img, io, .{ .partition_offset = partition_offset, .partition_len = partition_len });

    var fs = try open(&img, io, .{ .offset = partition_offset, .length = partition_len });
    try fs.createDir(io, "EFI/BOOT");
    try fs.createDir(io, "EFI/tools and utilities");
    try fs.writeFile(io, "EFI/BOOT/BOOTX64.EFI", "shim payload");
    try fs.writeFile(io, "EFI/BOOT/grub configuration.cfg", "set timeout=0\nmenuentry 'test' {}\n");
    try fs.writeFile(io, "EFI/tools and utilities/fallback bootloader path.txt", "EFI/BOOT/BOOTX64.EFI\n");
    img.close(io);

    var reopened = try Image.openPath(io, path);
    defer reopened.close(io);
    var reopened_fs = try open(&reopened, io, .{ .offset = partition_offset, .length = partition_len });

    const root_entries = try reopened_fs.listDirAlloc(io, std.testing.allocator, "/");
    defer freeDirEntries(std.testing.allocator, root_entries);
    try std.testing.expectEqual(@as(usize, 1), root_entries.len);
    try std.testing.expectEqualStrings("EFI", root_entries[0].name);
    try std.testing.expectEqual(DirEntryKind.directory, root_entries[0].kind);

    const boot_entries = try reopened_fs.listDirAlloc(io, std.testing.allocator, "EFI/BOOT");
    defer freeDirEntries(std.testing.allocator, boot_entries);
    try std.testing.expectEqual(@as(usize, 2), boot_entries.len);
    try std.testing.expectEqualStrings("BOOTX64.EFI", boot_entries[0].name);
    try std.testing.expectEqualStrings("grub configuration.cfg", boot_entries[1].name);

    const cfg = try reopened_fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/grub configuration.cfg");
    defer std.testing.allocator.free(cfg);
    try std.testing.expectEqualStrings("set timeout=0\nmenuentry 'test' {}\n", cfg);

    const fallback = try reopened_fs.readFileAlloc(io, std.testing.allocator, "EFI/tools and utilities/fallback bootloader path.txt");
    defer std.testing.allocator.free(fallback);
    try std.testing.expectEqualStrings("EFI/BOOT/BOOTX64.EFI\n", fallback);
}

test "FAT32 path lookup is case-insensitive for mixed-case names" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-casefold.img");
    defer std.testing.allocator.free(path);

    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);

    try format(&img, io, .{ .partition_offset = 0, .partition_len = partition_len });

    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    try fs.createDir(io, "EFI/Boot");
    try fs.writeFile(io, "EFI/Boot/BootX64.Efi", "hello");

    const lower = try fs.readFileAlloc(io, std.testing.allocator, "efi/boot/bootx64.efi");
    defer std.testing.allocator.free(lower);
    try std.testing.expectEqualStrings("hello", lower);

    const upper = try fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/BOOTX64.EFI");
    defer std.testing.allocator.free(upper);
    try std.testing.expectEqualStrings("hello", upper);
}

test "directory enumeration rejects cyclic FAT chains" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-cyclic-directory.img");
    defer std.testing.allocator.free(path);
    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);
    try format(&img, io, .{
        .partition_offset = 0,
        .partition_len = partition_len,
    });
    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    var directory: [max_cluster_size]u8 = [_]u8{0} ** max_cluster_size;
    const cluster_size = fs.info.clusterSize();
    var slot: usize = 0;
    while (slot < cluster_size) : (slot += directory_entry_size) {
        directory[slot] = 0xe5;
    }
    try fs.writeRegion(
        io,
        directory[0..cluster_size],
        fs.clusterOffset(fs.info.root_cluster),
    );
    try fs.writeFatEntry(io, fs.info.root_cluster, fs.info.root_cluster);
    try std.testing.expectError(
        error.BadClusterChain,
        fs.listDirAlloc(io, std.testing.allocator, ""),
    );
}

test "directory enumeration rejects invalid UTF-16 long names" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-invalid-long-name.img");
    defer std.testing.allocator.free(path);
    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);
    try format(&img, io, .{
        .partition_offset = 0,
        .partition_len = partition_len,
    });
    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    const name = "invalid-surrogate-name.efi";
    try fs.writeFile(io, name, "payload");
    const entry = (try fs.findEntry(
        io,
        fs.info.root_cluster,
        name,
    )).?;
    var lfn_slot: [directory_entry_size]u8 = undefined;
    try fs.readDirectorySlot(
        io,
        fs.info.root_cluster,
        entry.first_slot,
        &lfn_slot,
    );
    std.mem.writeInt(u16, lfn_slot[1..3], 0xd800, .little);
    try fs.writeDirectorySlots(
        io,
        fs.info.root_cluster,
        entry.first_slot,
        &.{lfn_slot},
    );
    try std.testing.expectError(
        error.UnsupportedName,
        fs.listDirAlloc(io, std.testing.allocator, ""),
    );
}

test "directory enumeration rejects separator-bearing long names" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-separator-long-name.img");
    defer std.testing.allocator.free(path);
    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);
    try format(&img, io, .{
        .partition_offset = 0,
        .partition_len = partition_len,
    });
    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    const name = "separator-name.efi";
    try fs.writeFile(io, name, "payload");
    const entry = (try fs.findEntry(
        io,
        fs.info.root_cluster,
        name,
    )).?;
    var lfn_slot: [directory_entry_size]u8 = undefined;
    try fs.readDirectorySlot(
        io,
        fs.info.root_cluster,
        entry.first_slot,
        &lfn_slot,
    );
    std.mem.writeInt(u16, lfn_slot[1..3], '/', .little);
    try fs.writeDirectorySlots(
        io,
        fs.info.root_cluster,
        entry.first_slot,
        &.{lfn_slot},
    );
    try std.testing.expectError(
        error.UnsupportedName,
        fs.listDirAlloc(io, std.testing.allocator, ""),
    );
}

test "directory enumeration rejects case-insensitive duplicate names" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-duplicate-name.img");
    defer std.testing.allocator.free(path);
    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);
    try format(&img, io, .{
        .partition_offset = 0,
        .partition_len = partition_len,
    });
    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    try fs.writeFile(io, "alpha.efi", "first");
    try fs.writeFile(io, "bravo.efi", "second");
    const second = (try fs.findEntry(
        io,
        fs.info.root_cluster,
        "bravo.efi",
    )).?;
    var duplicate_units: [max_long_name_units]u16 = undefined;
    const duplicate_name = try encodeLongName("ALPHA.EFI", &duplicate_units);
    var lfn_slots: [1][directory_entry_size]u8 = undefined;
    buildLfnEntries(&lfn_slots, duplicate_name, second.short_name);
    try fs.writeDirectorySlots(
        io,
        fs.info.root_cluster,
        second.first_slot,
        &lfn_slots,
    );
    try std.testing.expectError(
        error.DuplicateName,
        fs.listDirAlloc(io, std.testing.allocator, ""),
    );
}

test "file reads reject nonempty entries without a data cluster" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-invalid-file-cluster.img");
    defer std.testing.allocator.free(path);
    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);
    try format(&img, io, .{
        .partition_offset = 0,
        .partition_len = partition_len,
    });
    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    const name = "bad.bin";
    try fs.writeFile(io, name, "payload");
    const entry = (try fs.findEntry(
        io,
        fs.info.root_cluster,
        name,
    )).?;
    var short_slot: [directory_entry_size]u8 = undefined;
    try fs.readDirectorySlot(
        io,
        fs.info.root_cluster,
        entry.location().shortSlot(),
        &short_slot,
    );
    short_slot[20..22].* = .{ 0, 0 };
    short_slot[26..28].* = .{ 0, 0 };
    try fs.writeDirectorySlots(
        io,
        fs.info.root_cluster,
        entry.location().shortSlot(),
        &.{short_slot},
    );
    try std.testing.expectError(
        error.BadClusterChain,
        fs.readFileAlloc(io, std.testing.allocator, name),
    );
}

test "delete frees directory entries and FAT chains for reuse" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-delete.img");
    defer std.testing.allocator.free(path);

    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);

    try format(&img, io, .{ .partition_offset = 0, .partition_len = partition_len });

    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    const cluster_size = fs.info.clusterSize();

    try fs.createDir(io, "EFI/BOOT");
    try fs.createDir(io, "EFI/EMPTY");

    const keep_contents = try allocPattern(std.testing.allocator, cluster_size + 37, 0x11);
    defer std.testing.allocator.free(keep_contents);
    const deleted_contents = try allocPattern(std.testing.allocator, cluster_size * 3 + 29, 0x37);
    defer std.testing.allocator.free(deleted_contents);
    const reused_contents = try allocPattern(std.testing.allocator, cluster_size * 3 + 97, 0x59);
    defer std.testing.allocator.free(reused_contents);

    try fs.writeFile(io, "EFI/BOOT/keep.bin", keep_contents);
    try fs.writeFile(io, "EFI/BOOT/delete me.bin", deleted_contents);

    const parent = try fs.resolveParent(io, "EFI/BOOT/delete me.bin");
    const deleted_entry = (try fs.findEntry(io, parent.cluster, parent.name)).?;
    const deleted_chain = try collectClusterChain(&fs, io, std.testing.allocator, deleted_entry.first_cluster);
    defer std.testing.allocator.free(deleted_chain);
    const free_before = fs.free_cluster_count;

    try std.testing.expectError(error.DirectoryNotEmpty, fs.deletePath(io, "EFI"));
    try fs.deletePath(io, "EFI/BOOT/delete me.bin");

    try std.testing.expectEqual(free_before + @as(u32, @intCast(deleted_chain.len)), fs.free_cluster_count);
    try std.testing.expectError(error.PathNotFound, fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/delete me.bin"));

    for (deleted_chain) |cluster| {
        try std.testing.expectEqual(@as(u32, 0), try fs.readFatEntry(io, cluster));
    }
    for (0..deleted_entry.slot_count) |slot_index| {
        var slot: [directory_entry_size]u8 = undefined;
        try fs.readDirectorySlot(io, parent.cluster, deleted_entry.first_slot + slot_index, &slot);
        try std.testing.expectEqual(@as(u8, 0xE5), slot[0]);
    }

    const boot_entries_after_delete = try fs.listDirAlloc(io, std.testing.allocator, "EFI/BOOT");
    defer freeDirEntries(std.testing.allocator, boot_entries_after_delete);
    try std.testing.expectEqual(@as(usize, 1), boot_entries_after_delete.len);
    try std.testing.expectEqualStrings("keep.bin", boot_entries_after_delete[0].name);

    try fs.writeFile(io, "EFI/BOOT/reused.bin", reused_contents);
    const reused_parent = try fs.resolveParent(io, "EFI/BOOT/reused.bin");
    const reused_entry = (try fs.findEntry(io, reused_parent.cluster, reused_parent.name)).?;
    try std.testing.expectEqual(deleted_chain[0], reused_entry.first_cluster);

    const kept = try fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/keep.bin");
    defer std.testing.allocator.free(kept);
    try std.testing.expectEqualSlices(u8, keep_contents, kept);

    const reused = try fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/reused.bin");
    defer std.testing.allocator.free(reused);
    try std.testing.expectEqualSlices(u8, reused_contents, reused);

    try fs.deletePath(io, "EFI/EMPTY");
    try std.testing.expectError(error.PathNotFound, fs.listDirAlloc(io, std.testing.allocator, "EFI/EMPTY"));
}

test "deleteTree removes nested directories and reuses freed clusters" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-delete-tree.img");
    defer std.testing.allocator.free(path);

    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);

    try format(&img, io, .{ .partition_offset = 0, .partition_len = partition_len });

    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    const cluster_size = fs.info.clusterSize();

    const survivor_contents = try allocPattern(std.testing.allocator, cluster_size + 23, 0x14);
    defer std.testing.allocator.free(survivor_contents);
    const alpha_contents = try allocPattern(std.testing.allocator, cluster_size * 2 + 13, 0x31);
    defer std.testing.allocator.free(alpha_contents);
    const beta_contents = try allocPattern(std.testing.allocator, cluster_size + 19, 0x42);
    defer std.testing.allocator.free(beta_contents);
    const gamma_contents = try allocPattern(std.testing.allocator, cluster_size * 2 + 5, 0x53);
    defer std.testing.allocator.free(gamma_contents);
    const replacement_contents = try allocPattern(std.testing.allocator, cluster_size * 3 + 41, 0x64);
    defer std.testing.allocator.free(replacement_contents);

    try fs.writeFile(io, "survivor.bin", survivor_contents);
    try fs.createDir(io, "trash/dir1/dir2");
    try fs.writeFile(io, "trash/alpha.bin", alpha_contents);
    try fs.writeFile(io, "trash/dir1/beta.bin", beta_contents);
    try fs.writeFile(io, "trash/dir1/dir2/gamma.bin", gamma_contents);

    const trash_entry = (try fs.lookup(io, "trash")).?;
    const dir1_entry = (try fs.lookup(io, "trash/dir1")).?;
    const dir2_entry = (try fs.lookup(io, "trash/dir1/dir2")).?;
    const alpha_entry = (try fs.lookup(io, "trash/alpha.bin")).?;
    const beta_entry = (try fs.lookup(io, "trash/dir1/beta.bin")).?;
    const gamma_entry = (try fs.lookup(io, "trash/dir1/dir2/gamma.bin")).?;

    const trash_chain = try collectClusterChain(&fs, io, std.testing.allocator, trash_entry.first_cluster);
    defer std.testing.allocator.free(trash_chain);
    const dir1_chain = try collectClusterChain(&fs, io, std.testing.allocator, dir1_entry.first_cluster);
    defer std.testing.allocator.free(dir1_chain);
    const dir2_chain = try collectClusterChain(&fs, io, std.testing.allocator, dir2_entry.first_cluster);
    defer std.testing.allocator.free(dir2_chain);
    const alpha_chain = try collectClusterChain(&fs, io, std.testing.allocator, alpha_entry.first_cluster);
    defer std.testing.allocator.free(alpha_chain);
    const beta_chain = try collectClusterChain(&fs, io, std.testing.allocator, beta_entry.first_cluster);
    defer std.testing.allocator.free(beta_chain);
    const gamma_chain = try collectClusterChain(&fs, io, std.testing.allocator, gamma_entry.first_cluster);
    defer std.testing.allocator.free(gamma_chain);

    const deleted_cluster_count = trash_chain.len + dir1_chain.len + dir2_chain.len + alpha_chain.len + beta_chain.len + gamma_chain.len;
    const free_before = fs.free_cluster_count;

    try fs.deleteTree(io, "trash");

    try std.testing.expectEqual(
        free_before + @as(u32, @intCast(deleted_cluster_count)),
        fs.free_cluster_count,
    );
    try std.testing.expect((try fs.lookup(io, "trash")) == null);
    try std.testing.expect((try fs.lookup(io, "trash/dir1")) == null);
    try std.testing.expectError(error.PathNotFound, fs.readFileAlloc(io, std.testing.allocator, "trash/alpha.bin"));

    const root_entries_after_delete = try fs.listDirAlloc(io, std.testing.allocator, "");
    defer freeDirEntries(std.testing.allocator, root_entries_after_delete);
    try std.testing.expectEqual(@as(usize, 1), root_entries_after_delete.len);
    try std.testing.expectEqualStrings("survivor.bin", root_entries_after_delete[0].name);

    try fs.writeFile(io, "replacement.bin", replacement_contents);
    const replacement_entry = (try fs.lookup(io, "replacement.bin")).?;
    try std.testing.expectEqual(trash_entry.first_cluster, replacement_entry.first_cluster);

    const survivor = try fs.readFileAlloc(io, std.testing.allocator, "survivor.bin");
    defer std.testing.allocator.free(survivor);
    try std.testing.expectEqualSlices(u8, survivor_contents, survivor);

    const replacement = try fs.readFileAlloc(io, std.testing.allocator, "replacement.bin");
    defer std.testing.allocator.free(replacement);
    try std.testing.expectEqualSlices(u8, replacement_contents, replacement);
}

test "truncate shrinks files and frees unused clusters" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-truncate.img");
    defer std.testing.allocator.free(path);

    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);

    try format(&img, io, .{ .partition_offset = 0, .partition_len = partition_len });

    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    const cluster_size = fs.info.clusterSize();

    const contents = try allocPattern(std.testing.allocator, cluster_size * 3 + 57, 0x21);
    defer std.testing.allocator.free(contents);
    try fs.writeFile(io, "payload.bin", contents);

    const parent = try fs.resolveParent(io, "payload.bin");
    const entry = (try fs.findEntry(io, parent.cluster, parent.name)).?;
    const original_chain = try collectClusterChain(&fs, io, std.testing.allocator, entry.first_cluster);
    defer std.testing.allocator.free(original_chain);
    const free_before = fs.free_cluster_count;

    const truncated_size: u32 = @intCast(cluster_size + 31);
    try fs.truncateFile(io, "payload.bin", truncated_size);

    const truncated_entry = (try fs.findEntry(io, parent.cluster, parent.name)).?;
    try std.testing.expectEqual(truncated_size, truncated_entry.size);
    try std.testing.expectEqual(original_chain[0], truncated_entry.first_cluster);
    try std.testing.expectEqual(fat_entry_eoc, try fs.readFatEntry(io, original_chain[1]));
    for (original_chain[2..]) |cluster| {
        try std.testing.expectEqual(@as(u32, 0), try fs.readFatEntry(io, cluster));
    }
    try std.testing.expectEqual(
        free_before + @as(u32, @intCast(original_chain.len - 2)),
        fs.free_cluster_count,
    );

    const truncated = try fs.readFileAlloc(io, std.testing.allocator, "payload.bin");
    defer std.testing.allocator.free(truncated);
    try std.testing.expectEqualSlices(u8, contents[0..truncated_size], truncated);

    var tail: [64]u8 = undefined;
    try fs.readRegion(io, &tail, fs.clusterOffset(original_chain[1]) + truncated_size % cluster_size);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** tail.len), &tail);

    try std.testing.expectError(error.InvalidTruncateSize, fs.truncateFile(io, "payload.bin", truncated_size + 1));

    try fs.truncateFile(io, "payload.bin", 0);
    const emptied_entry = (try fs.findEntry(io, parent.cluster, parent.name)).?;
    try std.testing.expectEqual(@as(u32, 0), emptied_entry.size);
    try std.testing.expectEqual(@as(u32, 0), emptied_entry.first_cluster);
    try std.testing.expectEqual(@as(u32, 0), try fs.readFatEntry(io, original_chain[0]));
    try std.testing.expectEqual(@as(u32, 0), try fs.readFatEntry(io, original_chain[1]));

    const emptied = try fs.readFileAlloc(io, std.testing.allocator, "payload.bin");
    defer std.testing.allocator.free(emptied);
    try std.testing.expectEqual(@as(usize, 0), emptied.len);
}

test "streaming writes match whole-buffer writes" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-stream.img");
    defer std.testing.allocator.free(path);

    const partition_len: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, partition_len, .{});
    defer img.close(io);

    try format(&img, io, .{ .partition_offset = 0, .partition_len = partition_len });

    var fs = try open(&img, io, .{ .offset = 0, .length = partition_len });
    const cluster_size = fs.info.clusterSize();
    try fs.createDir(io, "EFI/BOOT");

    const contents = try allocPattern(std.testing.allocator, cluster_size * 2 + 137, 0x73);
    defer std.testing.allocator.free(contents);

    var writer = try fs.beginFile(io, "EFI/BOOT/streamed payload.bin");
    errdefer writer.abort(io) catch {};
    try writer.writeChunk(io, contents[0..17]);
    try writer.writeChunk(io, contents[17 .. 17 + cluster_size + 9]);
    try writer.writeChunk(io, contents[17 + cluster_size + 9 ..]);
    try writer.endFile(io);

    var empty_writer = try fs.beginFile(io, "EFI/BOOT/empty.bin");
    errdefer empty_writer.abort(io) catch {};
    try empty_writer.endFile(io);

    try fs.writeFile(io, "EFI/BOOT/whole payload.bin", contents);

    const streamed = try fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/streamed payload.bin");
    defer std.testing.allocator.free(streamed);
    const whole = try fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/whole payload.bin");
    defer std.testing.allocator.free(whole);
    const empty = try fs.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/empty.bin");
    defer std.testing.allocator.free(empty);

    try std.testing.expectEqualSlices(u8, contents, streamed);
    try std.testing.expectEqualSlices(u8, contents, whole);
    try std.testing.expectEqualSlices(u8, whole, streamed);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "scanTree reads a FAT volume out in parent-before-child order" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-scan-tree.img");
    defer std.testing.allocator.free(path);

    const partition_offset: u64 = 1024 * 1024;
    const partition_len: u64 = 64 * 1024 * 1024;

    var image = try Image.create(io, path, .raw, partition_offset + partition_len, .{});
    defer image.close(io);
    try format(&image, io, .{
        .partition_offset = partition_offset,
        .partition_len = partition_len,
    });

    // A file larger than one cluster proves the run walk, not just the first
    // cluster, is what the content reader follows.
    const payload = try allocPattern(allocator, 200 * 1024, 7);
    defer allocator.free(payload);

    var writable = try open(&image, io, .{ .offset = partition_offset, .length = partition_len });
    try writable.createDir(io, "EFI/BOOT");
    try writable.writeFile(io, "EFI/BOOT/BOOTX64.EFI", payload);
    try writable.writeFile(io, "EFI/BOOT/grub.cfg", "set timeout=0\n");
    try writable.writeFile(io, "empty", "");

    var filesystem = try open(&image, io, .{ .offset = partition_offset, .length = partition_len });
    var tree = try scanTree(&filesystem, io, allocator, .{});
    defer tree.deinit();

    try std.testing.expectEqual(@as(usize, 5), tree.nodeCount());
    try std.testing.expectEqual(
        @as(u64, payload.len + "set timeout=0\n".len),
        tree.content_bytes,
    );

    // A parent always precedes everything beneath it, so an importer never
    // has to invent a directory that the source in fact carries.
    var index: usize = 0;
    var seen_efi = false;
    var seen_boot = false;
    var checked_payload = false;
    while (index < tree.nodeCount()) : (index += 1) {
        const entry = tree.entryAt(index);
        if (std.mem.eql(u8, entry.path, "EFI")) {
            seen_efi = true;
            try std.testing.expectEqual(TreeKind.directory, entry.kind);
            try std.testing.expectEqual(@as(u16, 0o755), entry.mode);
        }
        if (std.mem.eql(u8, entry.path, "EFI/BOOT")) {
            try std.testing.expect(seen_efi);
            seen_boot = true;
        }
        if (std.mem.eql(u8, entry.path, "EFI/BOOT/BOOTX64.EFI")) {
            try std.testing.expect(seen_boot);
            try std.testing.expectEqual(TreeKind.file, entry.kind);
            try std.testing.expectEqual(@as(u16, 0o644), entry.mode);
            try std.testing.expectEqual(@as(u32, 0), entry.uid);
            try std.testing.expectEqual(@as(u32, 0), entry.gid);
            try std.testing.expectEqual(@as(u64, payload.len), entry.size);

            const read_back = try allocator.alloc(u8, payload.len);
            defer allocator.free(read_back);
            var offset: u64 = 0;
            while (offset < payload.len) {
                const got = try entry.content.?.readAt(read_back[@intCast(offset)..], offset);
                try std.testing.expect(got != 0);
                offset += got;
            }
            try std.testing.expectEqualSlices(u8, payload, read_back);
            checked_payload = true;
        }
        if (std.mem.eql(u8, entry.path, "empty")) {
            try std.testing.expectEqual(@as(u64, 0), entry.size);
            try std.testing.expectEqual(@as(usize, 0), try entry.content.?.readAt(&.{}, 0));
        }
    }
    try std.testing.expect(checked_payload);
}

test "scanTree synthesizes exactly the metadata it is given" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-scan-metadata.img");
    defer std.testing.allocator.free(path);

    const partition_offset: u64 = 0;
    const partition_len: u64 = 64 * 1024 * 1024;

    var image = try Image.create(io, path, .raw, partition_len, .{});
    defer image.close(io);
    try format(&image, io, .{
        .partition_offset = partition_offset,
        .partition_len = partition_len,
    });
    var writable = try open(&image, io, .{ .offset = partition_offset, .length = partition_len });
    try writable.createDir(io, "EFI");
    try writable.writeFile(io, "EFI/boot.cfg", "boot\n");

    var filesystem = try open(&image, io, .{ .offset = partition_offset, .length = partition_len });
    var tree = try scanTree(&filesystem, io, allocator, .{ .metadata = .{
        .directory_mode = 0o700,
        .file_mode = 0o600,
        .uid = 42,
        .gid = 43,
    } });
    defer tree.deinit();

    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const entry = tree.entryAt(index);
        try std.testing.expectEqual(@as(u32, 42), entry.uid);
        try std.testing.expectEqual(@as(u32, 43), entry.gid);
        try std.testing.expectEqual(
            @as(u16, switch (entry.kind) {
                .directory => 0o700,
                .file => 0o600,
            }),
            entry.mode,
        );
    }

    // A mode with file-type bits in it would describe a different kind of
    // file entirely, so it is refused rather than masked down.
    try std.testing.expectError(error.InvalidSynthesizedMode, scanTree(
        &filesystem,
        io,
        allocator,
        .{ .metadata = .{ .file_mode = 0o100644 } },
    ));
}

test "scanTree accounts every limit it enforces" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-scan-limits.img");
    defer std.testing.allocator.free(path);

    const partition_len: u64 = 64 * 1024 * 1024;
    var image = try Image.create(io, path, .raw, partition_len, .{});
    defer image.close(io);
    try format(&image, io, .{ .partition_offset = 0, .partition_len = partition_len });
    var writable = try open(&image, io, .{ .offset = 0, .length = partition_len });
    try writable.createDir(io, "EFI/BOOT");
    try writable.writeFile(io, "EFI/BOOT/BOOTX64.EFI", "payload");

    var filesystem = try open(&image, io, .{ .offset = 0, .length = partition_len });

    var diagnostic = limits_mod.Diagnostic{};
    var tree = try scanTree(&filesystem, io, allocator, .{ .diagnostic = &diagnostic });
    tree.deinit();
    try std.testing.expectEqual(@as(u64, 3), diagnostic.peaks.nodes);
    try std.testing.expectEqual(@as(u64, 7), diagnostic.peaks.total_bytes);
    try std.testing.expect(diagnostic.peaks.scan_metadata_bytes != 0);
    try std.testing.expectEqual(@as(?limits_mod.Exceeded, null), diagnostic.exceeded);

    try std.testing.expectError(
        error.NodeLimitExceeded,
        scanTree(&filesystem, io, allocator, .{ .max_nodes = 2 }),
    );
    try std.testing.expectError(
        error.FileLimitExceeded,
        scanTree(&filesystem, io, allocator, .{ .max_file_bytes = 6 }),
    );
    try std.testing.expectError(
        error.TotalContentLimitExceeded,
        scanTree(&filesystem, io, allocator, .{ .max_total_bytes = 6 }),
    );
    try std.testing.expectError(
        error.PathLimitExceeded,
        scanTree(&filesystem, io, allocator, .{ .max_path_bytes = 8 }),
    );
    try std.testing.expectError(
        error.ComponentLimitExceeded,
        scanTree(&filesystem, io, allocator, .{ .max_component_bytes = 3 }),
    );
    try std.testing.expectError(
        error.ScanMetadataLimitExceeded,
        scanTree(&filesystem, io, allocator, .{ .max_scan_metadata_bytes = 4 }),
    );
}

test "scanTree refuses a directory that contains itself" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-scan-cycle.img");
    defer std.testing.allocator.free(path);

    const partition_len: u64 = 64 * 1024 * 1024;
    var image = try Image.create(io, path, .raw, partition_len, .{});
    defer image.close(io);
    try format(&image, io, .{ .partition_offset = 0, .partition_len = partition_len });
    var writable = try open(&image, io, .{ .offset = 0, .length = partition_len });
    try writable.createDir(io, "loop/inner");

    // Point `loop/inner` back at `loop`. FAT has no parent pointer a scanner
    // can trust, so nothing but a visited set stops this walking forever.
    const outer = (try writable.findEntry(io, writable.info.root_cluster, "loop")).?;
    const inner = (try writable.findEntry(io, outer.first_cluster, "inner")).?;
    var cluster_buffer: [max_cluster_size]u8 = undefined;
    const cluster_bytes = writable.info.clusterSize();
    try writable.readCluster(io, outer.first_cluster, cluster_buffer[0..cluster_bytes]);
    // A lowercase name needs long-filename slots ahead of the short entry,
    // and only the short entry carries the cluster number.
    const slot = (inner.first_slot + inner.slot_count - 1) * directory_entry_size;
    const entry = cluster_buffer[slot..][0..directory_entry_size];
    std.mem.writeInt(u16, entry[20..22], @intCast(outer.first_cluster >> 16), .little);
    std.mem.writeInt(u16, entry[26..28], @truncate(outer.first_cluster), .little);
    try writable.writeRegion(
        io,
        cluster_buffer[0..cluster_bytes],
        writable.clusterOffset(outer.first_cluster),
    );

    var filesystem = try open(&image, io, .{ .offset = 0, .length = partition_len });
    try std.testing.expectError(
        error.DirectoryCycle,
        scanTree(&filesystem, io, allocator, .{}),
    );
}

test "a name's slot count covers its long-name entries and its short one" {
    // One short entry always, plus a long-name entry per 13 UTF-16 units of
    // name including the terminator.
    try std.testing.expectEqual(@as(u32, 2), try nameSlotCount("A"));
    try std.testing.expectEqual(@as(u32, 2), try nameSlotCount("BOOTX64.EFI"));
    // Twelve characters plus the terminator still fits one long entry.
    try std.testing.expectEqual(@as(u32, 2), try nameSlotCount("abcdefghijkl"));
    // Thirteen does not: the terminator pushes it into a second.
    try std.testing.expectEqual(@as(u32, 3), try nameSlotCount("abcdefghijklm"));
    try std.testing.expectEqual(@as(u32, 3), try nameSlotCount("a" ** 25));
    try std.testing.expectEqual(@as(u32, 4), try nameSlotCount("a" ** 26));
}

test "an empty volume is sized by FAT32's own cluster floor, not by its content" {
    const empty = try minimumVolumeLength(.{
        .file_sizes = &.{},
        .directory_slots = &.{root_directory_overhead_slots},
    }, .{});

    // FAT32 is defined as having at least 65525 clusters, so the smallest
    // legal volume is around 33.5 MiB with 512-byte clusters however little
    // it holds. Anything that expects an ESP to shrink towards zero is
    // expecting the wrong thing.
    try std.testing.expect(empty >= 33 * 1024 * 1024);
    try std.testing.expect(empty <= 40 * 1024 * 1024);
    try std.testing.expectEqual(@as(u64, 0), empty % (1024 * 1024));

    // A little content changes nothing, because the floor still dominates.
    const small = try minimumVolumeLength(.{
        .file_sizes = &.{ 1024, 4096 },
        .directory_slots = &.{ root_directory_overhead_slots + 4, subdirectory_overhead_slots + 2 },
    }, .{});
    try std.testing.expectEqual(empty, small);
}

test "content above the cluster floor grows the volume by what it needs" {
    const floor = try minimumVolumeLength(.{
        .file_sizes = &.{},
        .directory_slots = &.{root_directory_overhead_slots},
    }, .{});

    var sizes: [1]u64 = .{64 * 1024 * 1024};
    const with_file = try minimumVolumeLength(.{
        .file_sizes = &sizes,
        .directory_slots = &.{root_directory_overhead_slots + 2},
    }, .{});
    try std.testing.expect(with_file > floor);
    try std.testing.expect(with_file >= 64 * 1024 * 1024);
    // The overhead over the file itself is metadata, not slack: a few
    // percent, not a doubling.
    try std.testing.expect(with_file < 74 * 1024 * 1024);
}

test "the length a volume is sized to is one format accepts and can be filled to" {
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporaryTestPath(std.testing.allocator, io, &temporary, "test-fat32-minimum-round-trip.img");
    defer std.testing.allocator.free(path);

    // Two files large enough that the data area, not the 65525-cluster
    // floor, decides the answer.
    const file_bytes: u64 = 24 * 1024 * 1024;
    const request = SpaceRequest{
        .file_sizes = &.{ file_bytes, file_bytes },
        .directory_slots = &.{ root_directory_overhead_slots + 2, subdirectory_overhead_slots + 4 },
    };
    const length = try minimumVolumeLength(request, .{});

    var img = try Image.create(io, path, .raw, length, .{});
    defer img.close(io);
    try format(&img, io, .{
        .partition_offset = 0,
        .partition_len = length,
        .volume_id = 0x1234_5678,
    });
    var fs = try open(&img, io, .{ .offset = 0, .length = length });

    const payload = try std.testing.allocator.alloc(u8, @intCast(file_bytes));
    defer std.testing.allocator.free(payload);
    @memset(payload, 0xA5);

    try fs.createDir(io, "sub");
    try fs.writeFile(io, "one.bin", payload);
    try fs.writeFile(io, "sub/two.bin", payload);

    // Sized to hold it, and it did.
    const read_back = try fs.readFileAlloc(io, std.testing.allocator, "sub/two.bin");
    defer std.testing.allocator.free(read_back);
    try std.testing.expectEqualSlices(u8, payload, read_back);
}
