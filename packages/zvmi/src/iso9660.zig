//! ISO9660 (ECMA-119) reader **and** writer with enough Rock Ridge (RRIP)
//! and Joliet support to enumerate directory trees, read file extents, and
//! resolve symbolic links without shelling out to external tooling.
//!
//! Scope / limitations:
//!  - The reader is read-only; the writer (`writeImage`/`writeImagePath`)
//!    emits a deterministic ISO9660 image from a generic pull-based
//!    `TreeSource`, streaming file content so large files never load into
//!    memory whole. It writes directories, regular files, and symlinks with
//!    POSIX mode/uid/gid via Rock Ridge, both-endian path tables, a primary
//!    volume descriptor and terminator, and optional El Torito boot support
//!    (no-emulation BIOS and/or UEFI entries with a validation entry and boot
//!    catalog). Joliet emission and arbitrary-source El Torito preservation
//!    (reading back an existing catalog into a new image) are out of scope for
//!    this pass.
//!  - Rock Ridge support covers the SUSP/RRIP records needed for real Linux
//!    install media navigation: `SP`, `ST`, `RR`, `PX`, `NM`, `SL`, and `CE`.
//!    Directory relocation (`CL`/`PL`/`RE`) is not implemented.
//!  - Joliet support decodes UCS-2BE names from a supplementary volume
//!    descriptor and prefers Rock Ridge names when both are present, matching
//!    common Unix reader behavior.
//!  - File reading currently assumes each directory record describes a single
//!    contiguous extent, which is the common case for installer/live-media
//!    ISOs and for the synthetic fixtures used here.

const std = @import("std");
const Io = std.Io;

pub const volume_descriptor_lba: u32 = 16;
pub const descriptor_size: usize = 2048;
pub const standard_id: [5]u8 = "CD001".*;

pub const EntryKind = enum {
    file,
    directory,
    symlink,
};

pub const Extent = struct {
    lba: u32,
    size: u32,
};

pub const DirEntry = struct {
    name: []const u8,
    index: usize,
    kind: EntryKind,
};

pub const PathTableEntry = struct {
    name: []const u8,
    extent_lba: u32,
    parent_index: u16,
};

pub const Entry = struct {
    name: []const u8,
    parent: ?usize,
    kind: EntryKind,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    extents: []Extent,
    symlink_target: ?[]const u8,

    pub fn isDirectory(self: Entry) bool {
        return self.kind == .directory;
    }
};

pub const NameSource = enum {
    iso9660,
    rock_ridge,
    joliet,
};

pub const OpenError = error{
    BadVolumeDescriptor,
    MissingPrimaryVolumeDescriptor,
    InvalidRootDirectoryRecord,
    UnsupportedLogicalBlockSize,
    TooManyRockRidgeContinuations,
    UnsupportedRockRidgeRelocation,
    InvalidDirectoryRecord,
    InvalidJolietName,
} || Io.File.OpenError || Io.File.ReadPositionalError || Io.File.StatError || std.mem.Allocator.Error;

pub const LookupError = error{ NotFound, NotADirectory, TooManySymlinks, BrokenSymlink } || std.mem.Allocator.Error;
pub const ReadError = error{ NotAFile, NotASymlink } || Io.File.ReadPositionalError || std.mem.Allocator.Error;

pub const Reader = struct {
    allocator: std.mem.Allocator,
    file: Io.File,
    logical_block_size: u16,
    path_table: []PathTableEntry,
    entries: []Entry,
    root_index: usize,
    has_rock_ridge: bool,
    has_joliet: bool,
    name_source: NameSource,

    pub fn openPath(allocator: std.mem.Allocator, io: Io, path: []const u8) OpenError!Reader {
        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        errdefer file.close(io);
        return openFile(allocator, io, file);
    }

    pub fn openFile(allocator: std.mem.Allocator, io: Io, file: Io.File) OpenError!Reader {
        const descriptors = try scanDescriptors(io, file);
        const path_table = try parsePathTable(allocator, io, file, descriptors.primary);
        errdefer freePathTable(allocator, path_table);

        var primary_tree = try buildTree(allocator, io, file, descriptors.primary, false);
        errdefer primary_tree.deinit(allocator);

        if (primary_tree.has_rock_ridge or descriptors.joliet == null) {
            return .{
                .allocator = allocator,
                .file = file,
                .logical_block_size = descriptors.primary.logical_block_size,
                .path_table = path_table,
                .entries = try primary_tree.entries.toOwnedSlice(),
                .root_index = primary_tree.root_index,
                .has_rock_ridge = primary_tree.has_rock_ridge,
                .has_joliet = descriptors.joliet != null,
                .name_source = if (primary_tree.has_rock_ridge) .rock_ridge else .iso9660,
            };
        }

        primary_tree.deinit(allocator);

        var joliet_tree = try buildTree(allocator, io, file, descriptors.joliet.?, true);
        errdefer joliet_tree.deinit(allocator);

        return .{
            .allocator = allocator,
            .file = file,
            .logical_block_size = descriptors.joliet.?.logical_block_size,
            .path_table = path_table,
            .entries = try joliet_tree.entries.toOwnedSlice(),
            .root_index = joliet_tree.root_index,
            .has_rock_ridge = false,
            .has_joliet = true,
            .name_source = .joliet,
        };
    }

    pub fn close(self: *Reader, io: Io) void {
        freeEntries(self.allocator, self.entries);
        freePathTable(self.allocator, self.path_table);
        self.file.close(io);
        self.* = undefined;
    }

    pub fn getEntry(self: Reader, index: usize) *const Entry {
        return &self.entries[index];
    }

    pub fn lookup(self: Reader, path: []const u8) LookupError!usize {
        return self.lookupFrom(self.root_index, path, false, 0);
    }

    pub fn listDirAlloc(self: Reader, allocator: std.mem.Allocator, index: usize) (std.mem.Allocator.Error || error{NotADirectory})![]DirEntry {
        if (self.entries[index].kind != .directory) return error.NotADirectory;

        var list = std.array_list.Managed(DirEntry).init(allocator);
        errdefer list.deinit();

        for (self.entries, 0..) |entry, i| {
            if (entry.parent == index) {
                try list.append(.{ .name = entry.name, .index = i, .kind = entry.kind });
            }
        }
        std.mem.sort(DirEntry, list.items, {}, dirEntryLessThan);
        return list.toOwnedSlice();
    }

    pub fn readFileAlloc(self: Reader, allocator: std.mem.Allocator, io: Io, index: usize) ReadError![]u8 {
        const entry = self.entries[index];
        if (entry.kind != .file) return error.NotAFile;

        const out = try allocator.alloc(u8, @intCast(entry.size));
        errdefer allocator.free(out);

        var dst_offset: usize = 0;
        for (entry.extents) |extent| {
            const extent_len: usize = @intCast(@min(@as(u64, extent.size), entry.size - dst_offset));
            const file_offset = @as(u64, extent.lba) * self.logical_block_size;
            const got = try self.file.readPositionalAll(io, out[dst_offset..][0..extent_len], file_offset);
            if (got < extent_len) @memset(out[dst_offset + got ..][0 .. extent_len - got], 0);
            dst_offset += extent_len;
            if (dst_offset == out.len) break;
        }
        return out;
    }

    pub fn readLink(self: Reader, index: usize) ReadError![]const u8 {
        if (self.entries[index].kind != .symlink) return error.NotASymlink;
        return self.entries[index].symlink_target.?;
    }

    pub fn resolveSymlink(self: Reader, index: usize) LookupError!usize {
        const entry = self.entries[index];
        if (entry.kind != .symlink) return error.BrokenSymlink;
        return self.lookupFrom(entry.parent orelse self.root_index, entry.symlink_target.?, true, 1);
    }

    fn lookupFrom(self: Reader, start_index: usize, path: []const u8, follow_final_symlink: bool, depth: u8) LookupError!usize {
        if (depth > 16) return error.TooManySymlinks;

        var current = if (std.mem.startsWith(u8, path, "/")) self.root_index else start_index;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        var had_component = false;

        while (it.next()) |component| {
            had_component = true;
            if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
            if (std.mem.eql(u8, component, "..")) {
                current = self.entries[current].parent orelse self.root_index;
                continue;
            }

            if (self.entries[current].kind != .directory) return error.NotADirectory;
            const child = self.findChild(current, component) orelse return error.NotFound;
            const is_last = it.peek() == null;
            if (self.entries[child].kind == .symlink and (!is_last or follow_final_symlink)) {
                const target = self.entries[child].symlink_target.?;
                current = self.lookupFrom(self.entries[child].parent orelse self.root_index, target, true, depth + 1) catch |err| switch (err) {
                    error.NotFound, error.NotADirectory => return error.BrokenSymlink,
                    else => return err,
                };
            } else {
                current = child;
            }
        }

        if (!had_component and std.mem.startsWith(u8, path, "/")) return self.root_index;
        return current;
    }

    fn findChild(self: Reader, parent: usize, name: []const u8) ?usize {
        for (self.entries, 0..) |entry, i| {
            if (entry.parent == parent and std.mem.eql(u8, entry.name, name)) return i;
        }
        return null;
    }
};

const DescriptorRef = struct {
    logical_block_size: u16,
    path_table_size: u32,
    type_l_path_table: u32,
    root_record: DirectoryRecord,
};

const ScannedDescriptors = struct {
    primary: DescriptorRef,
    joliet: ?DescriptorRef,
};

const DirectoryRecord = struct {
    length: u8,
    extent_lba: u32,
    data_length: u32,
    flags: u8,
    file_identifier: []const u8,
    system_use: []const u8,
};

const RockRidgeInfo = struct {
    name: ?[]u8 = null,
    symlink_target: ?[]u8 = null,
    mode: ?u32 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,

    fn deinit(self: *RockRidgeInfo, allocator: std.mem.Allocator) void {
        if (self.name) |name| allocator.free(name);
        if (self.symlink_target) |target| allocator.free(target);
        self.* = .{};
    }
};

const TreeBuilder = struct {
    entries: std.array_list.Managed(Entry),
    root_index: usize,
    has_rock_ridge: bool = false,
    logical_block_size: u16,
    joliet: bool,
    susp_skip: ?u8 = null,

    fn deinit(self: *TreeBuilder, allocator: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.extents);
            if (entry.symlink_target) |target| allocator.free(target);
        }
        self.entries.deinit();
    }
};

fn buildTree(allocator: std.mem.Allocator, io: Io, file: Io.File, descriptor: DescriptorRef, joliet: bool) OpenError!TreeBuilder {
    var builder = TreeBuilder{
        .entries = std.array_list.Managed(Entry).init(allocator),
        .root_index = 0,
        .logical_block_size = descriptor.logical_block_size,
        .joliet = joliet,
    };
    errdefer builder.deinit(allocator);

    const root_name = try allocator.dupe(u8, "/");
    errdefer allocator.free(root_name);
    const root_extents = try allocator.alloc(Extent, 1);
    errdefer allocator.free(root_extents);
    root_extents[0] = .{ .lba = descriptor.root_record.extent_lba, .size = descriptor.root_record.data_length };

    try builder.entries.append(.{
        .name = root_name,
        .parent = null,
        .kind = .directory,
        .size = descriptor.root_record.data_length,
        .mode = 0o040755,
        .uid = 0,
        .gid = 0,
        .extents = root_extents,
        .symlink_target = null,
    });
    builder.root_index = 0;

    try parseDirectory(allocator, io, file, &builder, 0, descriptor.root_record, 0);
    return builder;
}

fn parseDirectory(allocator: std.mem.Allocator, io: Io, file: Io.File, builder: *TreeBuilder, parent_index: usize, record: DirectoryRecord, depth: usize) OpenError!void {
    if (depth > 128) return error.InvalidDirectoryRecord;
    const size: usize = @intCast(record.data_length);
    const dir_buf = try allocator.alloc(u8, size);
    defer allocator.free(dir_buf);
    _ = try file.readPositionalAll(io, dir_buf, @as(u64, record.extent_lba) * builder.logical_block_size);

    var offset: usize = 0;
    while (offset < dir_buf.len) {
        const length = dir_buf[offset];
        if (length == 0) {
            const sector_off = offset % builder.logical_block_size;
            offset += builder.logical_block_size - sector_off;
            continue;
        }
        if (offset + length > dir_buf.len) return error.InvalidDirectoryRecord;

        const child_record = try parseDirectoryRecord(dir_buf[offset .. offset + length]);
        defer if (child_record.file_identifier.len == 0) {};

        const is_special = child_record.file_identifier.len == 1 and (child_record.file_identifier[0] == 0 or child_record.file_identifier[0] == 1);

        var rr = RockRidgeInfo{};
        defer rr.deinit(allocator);
        if (!builder.joliet) {
            rr = try parseRockRidge(allocator, io, file, builder, child_record.system_use);
        }

        if (is_special) {
            if (child_record.file_identifier[0] == 0) {
                if (rr.mode) |mode| builder.entries.items[parent_index].mode = mode;
                if (rr.uid) |uid| builder.entries.items[parent_index].uid = uid;
                if (rr.gid) |gid| builder.entries.items[parent_index].gid = gid;
            }
            offset += child_record.length;
            continue;
        }

        const decoded_name = if (rr.name) |name|
            try allocator.dupe(u8, name)
        else if (builder.joliet)
            try decodeJolietName(allocator, child_record.file_identifier)
        else
            try decodeIsoName(allocator, child_record.file_identifier);
        errdefer allocator.free(decoded_name);

        const extents = try allocator.alloc(Extent, 1);
        errdefer allocator.free(extents);
        extents[0] = .{ .lba = child_record.extent_lba, .size = child_record.data_length };

        const kind: EntryKind = if (rr.symlink_target != null)
            .symlink
        else if (child_record.flags & 0x02 != 0)
            .directory
        else
            .file;

        const target = if (rr.symlink_target) |link| try allocator.dupe(u8, link) else null;
        errdefer if (target) |link| allocator.free(link);

        const entry_mode: u32 = rr.mode orelse switch (kind) {
            .directory => @as(u32, 0o040755),
            .file => @as(u32, 0o100644),
            .symlink => @as(u32, 0o120777),
        };

        try builder.entries.append(.{
            .name = decoded_name,
            .parent = parent_index,
            .kind = kind,
            .size = child_record.data_length,
            .mode = entry_mode,
            .uid = rr.uid orelse 0,
            .gid = rr.gid orelse 0,
            .extents = extents,
            .symlink_target = target,
        });
        const child_index = builder.entries.items.len - 1;

        if (kind == .directory) {
            try parseDirectory(allocator, io, file, builder, child_index, child_record, depth + 1);
        }

        offset += child_record.length;
    }
}

fn scanDescriptors(io: Io, file: Io.File) OpenError!ScannedDescriptors {
    var sector: [descriptor_size]u8 = undefined;
    var lba: u32 = volume_descriptor_lba;
    var primary: ?DescriptorRef = null;
    var joliet: ?DescriptorRef = null;

    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * descriptor_size);
        if (!std.mem.eql(u8, sector[1..6], &standard_id)) return error.BadVolumeDescriptor;

        switch (sector[0]) {
            1 => {
                if (primary == null) primary = try parseDescriptorRef(&sector);
            },
            2 => {
                if (joliet == null and isJolietEscape(sector[88..120])) {
                    joliet = try parseDescriptorRef(&sector);
                }
            },
            255 => break,
            else => {},
        }
    }

    return .{
        .primary = primary orelse return error.MissingPrimaryVolumeDescriptor,
        .joliet = joliet,
    };
}

fn parseDescriptorRef(sector: *const [descriptor_size]u8) OpenError!DescriptorRef {
    const logical_block_size = read723(sector[128..132]);
    if (logical_block_size == 0) return error.UnsupportedLogicalBlockSize;
    const root = try parseDirectoryRecord(sector[156..190]);
    return .{
        .logical_block_size = logical_block_size,
        .path_table_size = read733(sector[132..140]),
        .type_l_path_table = read731(sector[140..144]),
        .root_record = root,
    };
}

fn parsePathTable(allocator: std.mem.Allocator, io: Io, file: Io.File, descriptor: DescriptorRef) OpenError![]PathTableEntry {
    if (descriptor.path_table_size == 0 or descriptor.type_l_path_table == 0) return allocator.alloc(PathTableEntry, 0);

    const buf = try allocator.alloc(u8, descriptor.path_table_size);
    defer allocator.free(buf);
    _ = try file.readPositionalAll(io, buf, @as(u64, descriptor.type_l_path_table) * descriptor.logical_block_size);

    var list = std.array_list.Managed(PathTableEntry).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item.name);
        list.deinit();
    }

    var offset: usize = 0;
    while (offset + 8 <= buf.len) {
        const name_len = buf[offset];
        if (name_len == 0) break;
        const extent = read731(buf[offset + 2 .. offset + 6]);
        const parent = read721(buf[offset + 6 .. offset + 8]);
        const name_start = offset + 8;
        const name_end = name_start + name_len;
        if (name_end > buf.len) break;

        const name = if (name_len == 1 and buf[name_start] == 0)
            try allocator.dupe(u8, "/")
        else
            try allocator.dupe(u8, buf[name_start..name_end]);
        try list.append(.{ .name = name, .extent_lba = extent, .parent_index = parent });

        offset = name_end;
        if (name_len % 2 == 1) offset += 1;
    }

    return list.toOwnedSlice();
}

fn parseDirectoryRecord(buf: []const u8) OpenError!DirectoryRecord {
    if (buf.len < 34) return error.InvalidDirectoryRecord;
    const length = buf[0];
    if (length < 34 or length > buf.len) return error.InvalidDirectoryRecord;

    const name_len = buf[32];
    const name_start = 33;
    const name_end = name_start + name_len;
    if (name_end > length) return error.InvalidDirectoryRecord;
    const pad = if (name_len % 2 == 0) @as(usize, 1) else 0;
    const system_use_start = name_end + pad;
    if (system_use_start > length) return error.InvalidDirectoryRecord;

    return .{
        .length = length,
        .extent_lba = read733(buf[2..10]),
        .data_length = read733(buf[10..18]),
        .flags = buf[25],
        .file_identifier = buf[name_start..name_end],
        .system_use = buf[system_use_start..length],
    };
}

fn parseRockRidge(allocator: std.mem.Allocator, io: Io, file: Io.File, builder: *TreeBuilder, system_use: []const u8) OpenError!RockRidgeInfo {
    var info = RockRidgeInfo{};
    errdefer info.deinit(allocator);

    var name_buf = std.array_list.Managed(u8).init(allocator);
    defer name_buf.deinit();
    var link_buf = std.array_list.Managed(u8).init(allocator);
    defer link_buf.deinit();

    var pending = std.array_list.Managed(Continuation).init(allocator);
    defer pending.deinit();

    var initial = system_use;
    if (builder.susp_skip) |skip| {
        if (skip <= initial.len) initial = initial[skip..] else initial = &.{};
    }

    var queue = std.array_list.Managed([]const u8).init(allocator);
    defer queue.deinit();
    try queue.append(initial);

    var continuation_loops: usize = 0;
    var index: usize = 0;
    while (index < queue.items.len) : (index += 1) {
        var rest = queue.items[index];
        while (rest.len >= 4) {
            const sig = rest[0..2];
            const entry_len = rest[2];
            if (entry_len < 4 or entry_len > rest.len) break;
            const entry = rest[0..entry_len];
            rest = rest[entry_len..];

            if (std.mem.eql(u8, sig, "SP")) {
                if (entry_len >= 7 and entry[4] == 0xBE and entry[5] == 0xEF) {
                    builder.susp_skip = entry[6];
                    builder.has_rock_ridge = true;
                }
            } else if (std.mem.eql(u8, sig, "RR")) {
                builder.has_rock_ridge = true;
            } else if (std.mem.eql(u8, sig, "CE")) {
                if (entry_len >= 28) {
                    try pending.append(.{
                        .extent_lba = read733(entry[4..12]),
                        .offset = read733(entry[12..20]),
                        .size = read733(entry[20..28]),
                    });
                }
            } else if (std.mem.eql(u8, sig, "ST")) {
                break;
            } else if (std.mem.eql(u8, sig, "ER")) {
                builder.has_rock_ridge = true;
            } else if (std.mem.eql(u8, sig, "PX")) {
                if (entry_len >= 36) {
                    info.mode = read733(entry[4..12]);
                    info.uid = read733(entry[20..28]);
                    info.gid = read733(entry[28..36]);
                    builder.has_rock_ridge = true;
                }
            } else if (std.mem.eql(u8, sig, "NM")) {
                if (entry_len >= 5) {
                    const flags = entry[4];
                    if ((flags & 0x06) == 0) {
                        try name_buf.appendSlice(entry[5..]);
                        builder.has_rock_ridge = true;
                    }
                }
            } else if (std.mem.eql(u8, sig, "SL")) {
                if (entry_len >= 5) {
                    try appendSymlinkComponents(&link_buf, entry[5..]);
                    builder.has_rock_ridge = true;
                }
            }
        }

        while (pending.items.len > 0) {
            if (continuation_loops >= 32) return error.TooManyRockRidgeContinuations;
            continuation_loops += 1;
            const ce = pending.orderedRemove(0);
            const continuation = try allocator.alloc(u8, ce.size);
            _ = try file.readPositionalAll(io, continuation, @as(u64, ce.extent_lba) * builder.logical_block_size + ce.offset);
            try queue.append(continuation);
        }
    }

    for (queue.items[1..]) |item| allocator.free(item);

    if (name_buf.items.len > 0) info.name = try name_buf.toOwnedSlice();
    if (link_buf.items.len > 0) info.symlink_target = try link_buf.toOwnedSlice();
    return info;
}

const Continuation = struct {
    extent_lba: u32,
    offset: u32,
    size: u32,
};

fn appendSymlinkComponents(buf: *std.array_list.Managed(u8), payload: []const u8) std.mem.Allocator.Error!void {
    var rest = payload;
    while (rest.len >= 2) {
        const flags = rest[0];
        const len = rest[1];
        if (2 + len > rest.len) break;
        const text = rest[2 .. 2 + len];

        const continued = (flags & 0x01) != 0;
        switch (flags & ~@as(u8, 0x01)) {
            0 => try buf.appendSlice(text),
            2 => try buf.append('.'),
            4 => try buf.appendSlice(".."),
            8 => try buf.append('/'),
            else => {},
        }

        rest = rest[2 + len ..];
        if ((flags & ~@as(u8, 0x01)) != 8 and !continued and rest.len >= 2) {
            try buf.append('/');
        }
    }
}

fn decodeIsoName(allocator: std.mem.Allocator, raw: []const u8) std.mem.Allocator.Error![]u8 {
    var name = raw;
    if (std.mem.lastIndexOfScalar(u8, name, ';')) |semi| {
        if (semi + 2 == name.len and name[semi + 1] == '1') name = name[0..semi];
    }
    while (name.len > 0 and name[name.len - 1] == '.') name = name[0 .. name.len - 1];
    return allocator.dupe(u8, name);
}

fn decodeJolietName(allocator: std.mem.Allocator, raw: []const u8) OpenError![]u8 {
    if (raw.len % 2 != 0) return error.InvalidJolietName;

    var list = std.array_list.Managed(u8).init(allocator);
    errdefer list.deinit();

    var i: usize = 0;
    while (i < raw.len) : (i += 2) {
        const codepoint = std.mem.readInt(u16, raw[i..][0..2], .big);
        if (codepoint == 0) break;
        var utf8: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(codepoint, &utf8) catch return error.InvalidJolietName;
        try list.appendSlice(utf8[0..len]);
    }

    var name = try list.toOwnedSlice();
    errdefer allocator.free(name);

    if (name.len >= 2 and name[name.len - 2] == ';' and name[name.len - 1] == '1') {
        name = try allocator.realloc(name, name.len - 2);
    }
    while (name.len > 0 and name[name.len - 1] == '.') {
        name = try allocator.realloc(name, name.len - 1);
    }
    return name;
}

fn isJolietEscape(escape: []const u8) bool {
    return escape.len >= 3 and escape[0] == '%' and escape[1] == '/' and (escape[2] == '@' or escape[2] == 'C' or escape[2] == 'E');
}

fn read721(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .little);
}

fn read723(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .little);
}

fn read731(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn read733(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn freeEntries(allocator: std.mem.Allocator, entries: []Entry) void {
    for (entries) |entry| {
        allocator.free(entry.name);
        allocator.free(entry.extents);
        if (entry.symlink_target) |target| allocator.free(target);
    }
    allocator.free(entries);
}

fn freePathTable(allocator: std.mem.Allocator, path_table: []PathTableEntry) void {
    for (path_table) |entry| allocator.free(entry.name);
    allocator.free(path_table);
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

fn write723(dst: []u8, value: u16) void {
    std.mem.writeInt(u16, dst[0..2], value, .little);
    std.mem.writeInt(u16, dst[2..4], value, .big);
}

fn write733(dst: []u8, value: u32) void {
    std.mem.writeInt(u32, dst[0..4], value, .little);
    std.mem.writeInt(u32, dst[4..8], value, .big);
}

/// Computes the directory-record length in a wide type so callers can validate
/// it against the 255-byte record limit (`max_record_len`) before narrowing to
/// the single-byte on-disk field. Casting here would truncate/panic for records
/// whose Rock Ridge system-use area must spill into a `CE` continuation.
fn recordLength(name_len: usize, system_use_len: usize) usize {
    const pad: usize = if (name_len % 2 == 0) 1 else 0;
    return 33 + name_len + pad + system_use_len;
}

fn makeDirectoryRecord(name: []const u8, extent_lba: u32, size: u32, flags: u8, system_use: []const u8) [256]u8 {
    var out: [256]u8 = [_]u8{0} ** 256;
    const len = recordLength(name.len, system_use.len);
    out[0] = @intCast(len);
    out[1] = 0;
    write733(out[2..10], extent_lba);
    write733(out[10..18], size);
    out[18] = 124; // 2024-01-01 00:00:00 GMT offset 0, synthetic/stable enough for tests.
    out[19] = 1;
    out[20] = 1;
    out[21] = 0;
    out[22] = 0;
    out[23] = 0;
    out[24] = 0;
    out[25] = flags;
    out[26] = 0;
    out[27] = 0;
    write723(out[28..32], 1);
    out[32] = @intCast(name.len);
    @memcpy(out[33 .. 33 + name.len], name);
    const pad: usize = if (name.len % 2 == 0) 1 else 0;
    if (pad == 1) out[33 + name.len] = 0;
    @memcpy(out[33 + name.len + pad ..][0..system_use.len], system_use);
    return out;
}

fn buildSpSystemUse() [7]u8 {
    return .{ 'S', 'P', 7, 1, 0xBE, 0xEF, 7 };
}

fn buildErSystemUse() [20]u8 {
    return .{ 'E', 'R', 20, 1, 10, 0, 0, 1, 'R', 'R', 'I', 'P', '_', '1', '9', '9', '1', 'A', 0, 0 };
}

fn buildRrSystemUse(flags: u8) [5]u8 {
    return .{ 'R', 'R', 5, 1, flags };
}

fn buildPxSystemUse(mode: u32, uid: u32, gid: u32) [36]u8 {
    var out: [36]u8 = [_]u8{0} ** 36;
    out[0] = 'P';
    out[1] = 'X';
    out[2] = 36;
    out[3] = 1;
    write733(out[4..12], mode);
    write733(out[12..20], 1);
    write733(out[20..28], uid);
    write733(out[28..36], gid);
    return out;
}

fn buildNmSystemUse(name: []const u8) [260]u8 {
    var out: [260]u8 = [_]u8{0} ** 260;
    out[0] = 'N';
    out[1] = 'M';
    out[2] = @intCast(5 + name.len);
    out[3] = 1;
    out[4] = 0;
    @memcpy(out[5 .. 5 + name.len], name);
    return out;
}

fn buildSlSystemUse(target: []const u8) [260]u8 {
    var out: [260]u8 = [_]u8{0} ** 260;
    var cursor: usize = 5;
    out[0] = 'S';
    out[1] = 'L';
    out[3] = 1;
    out[4] = 0;

    var it = std.mem.tokenizeScalar(u8, target, '/');
    const absolute = std.mem.startsWith(u8, target, "/");
    if (absolute) {
        out[cursor] = 8;
        out[cursor + 1] = 0;
        cursor += 2;
    }
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, ".")) {
            out[cursor] = 2;
            out[cursor + 1] = 0;
            cursor += 2;
        } else if (std.mem.eql(u8, component, "..")) {
            out[cursor] = 4;
            out[cursor + 1] = 0;
            cursor += 2;
        } else {
            out[cursor] = 0;
            out[cursor + 1] = @intCast(component.len);
            @memcpy(out[cursor + 2 .. cursor + 2 + component.len], component);
            cursor += 2 + component.len;
        }
    }
    out[2] = @intCast(cursor);
    return out;
}

fn buildStSystemUse() [4]u8 {
    return .{ 'S', 'T', 4, 1 };
}

fn writeIsoFile(path: []const u8, bytes: []const u8) !void {
    const io = std.testing.io;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

test "iso9660 reader enumerates rock ridge names and resolves symlinks" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-rr.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const root_lba: u32 = 20;
    const dir_lba: u32 = 21;
    const file_lba: u32 = 22;
    const file_bytes = "hello from rock ridge\n";
    const susp_prefix = [_]u8{0} ** 7;

    var image = std.array_list.Managed(u8).init(allocator);
    defer image.deinit();
    try image.resize((file_lba + 1) * descriptor_size);
    @memset(image.items, 0);

    var pvd: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    pvd[0] = 1;
    pvd[1..6].* = standard_id;
    pvd[6] = 1;
    pvd[40..48].* = .{ 'Z', 'V', 'M', 'I', ' ', 'R', 'R', ' ' };
    write733(pvd[80..88], @intCast(image.items.len / descriptor_size));
    write723(pvd[128..132], descriptor_size);
    write733(pvd[132..140], 0);
    std.mem.writeInt(u32, pvd[140..144], 19, .little);

    const root_record = makeDirectoryRecord(&.{0}, root_lba, descriptor_size, 0x02, &.{});
    @memcpy(pvd[156 .. 156 + root_record[0]], root_record[0..root_record[0]]);
    image.items[volume_descriptor_lba * descriptor_size .. (volume_descriptor_lba + 1) * descriptor_size].* = pvd;

    var terminator: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    terminator[0] = 255;
    terminator[1..6].* = standard_id;
    terminator[6] = 1;
    image.items[(volume_descriptor_lba + 1) * descriptor_size .. (volume_descriptor_lba + 2) * descriptor_size].* = terminator;

    var path_table = std.array_list.Managed(u8).init(allocator);
    defer path_table.deinit();
    try path_table.append(1);
    try path_table.append(0);
    try appendU32Le(&path_table, root_lba);
    try appendU16Le(&path_table, 1);
    try path_table.append(0);
    try path_table.append(0);
    try path_table.append(3);
    try path_table.append(0);
    try appendU32Le(&path_table, dir_lba);
    try appendU16Le(&path_table, 1);
    try path_table.appendSlice("DIR");
    try path_table.append(0);
    write733(image.items[16 * descriptor_size + 132 .. 16 * descriptor_size + 140], @intCast(path_table.items.len));
    @memcpy(image.items[19 * descriptor_size ..][0..path_table.items.len], path_table.items);

    var root_dir = std.array_list.Managed(u8).init(allocator);
    defer root_dir.deinit();
    var dot_su = std.array_list.Managed(u8).init(allocator);
    defer dot_su.deinit();
    try dot_su.appendSlice(&buildSpSystemUse());
    try dot_su.appendSlice(&buildErSystemUse());
    try dot_su.appendSlice(&buildPxSystemUse(0o040755, 0, 0));
    try dot_su.appendSlice(&buildStSystemUse());
    const dot = makeDirectoryRecord(&.{0}, root_lba, descriptor_size, 0x02, dot_su.items);
    try root_dir.appendSlice(dot[0..dot[0]]);

    var dotdot_su = std.array_list.Managed(u8).init(allocator);
    defer dotdot_su.deinit();
    try dotdot_su.appendSlice(&susp_prefix);
    try dotdot_su.appendSlice(&buildPxSystemUse(0o040755, 0, 0));
    try dotdot_su.appendSlice(&buildStSystemUse());
    const dotdot = makeDirectoryRecord(&.{1}, root_lba, descriptor_size, 0x02, dotdot_su.items);
    try root_dir.appendSlice(dotdot[0..dotdot[0]]);

    var file_su = std.array_list.Managed(u8).init(allocator);
    defer file_su.deinit();
    try file_su.appendSlice(&susp_prefix);
    try file_su.appendSlice(&buildRrSystemUse(1 | 8));
    try file_su.appendSlice(&buildPxSystemUse(0o100644, 1000, 1000));
    const file_nm = buildNmSystemUse("hello.txt");
    try file_su.appendSlice(file_nm[0..file_nm[2]]);
    try file_su.appendSlice(&buildStSystemUse());
    const file_record = makeDirectoryRecord("HELLO.TXT;1", file_lba, file_bytes.len, 0, file_su.items);
    try root_dir.appendSlice(file_record[0..file_record[0]]);

    var dir_su = std.array_list.Managed(u8).init(allocator);
    defer dir_su.deinit();
    try dir_su.appendSlice(&susp_prefix);
    try dir_su.appendSlice(&buildRrSystemUse(1 | 8));
    try dir_su.appendSlice(&buildPxSystemUse(0o040755, 0, 0));
    const dir_nm = buildNmSystemUse("dir");
    try dir_su.appendSlice(dir_nm[0..dir_nm[2]]);
    try dir_su.appendSlice(&buildStSystemUse());
    const dir_record = makeDirectoryRecord("DIR", dir_lba, descriptor_size, 0x02, dir_su.items);
    try root_dir.appendSlice(dir_record[0..dir_record[0]]);
    @memcpy(image.items[root_lba * descriptor_size ..][0..root_dir.items.len], root_dir.items);

    var subdir = std.array_list.Managed(u8).init(allocator);
    defer subdir.deinit();
    const sub_dot = makeDirectoryRecord(&.{0}, dir_lba, descriptor_size, 0x02, dotdot_su.items);
    try subdir.appendSlice(sub_dot[0..sub_dot[0]]);
    const sub_dotdot = makeDirectoryRecord(&.{1}, root_lba, descriptor_size, 0x02, dotdot_su.items);
    try subdir.appendSlice(sub_dotdot[0..sub_dotdot[0]]);

    var link_su = std.array_list.Managed(u8).init(allocator);
    defer link_su.deinit();
    try link_su.appendSlice(&susp_prefix);
    try link_su.appendSlice(&buildRrSystemUse(1 | 4 | 8));
    try link_su.appendSlice(&buildPxSystemUse(0o120777, 0, 0));
    const link_nm = buildNmSystemUse("motd-link");
    try link_su.appendSlice(link_nm[0..link_nm[2]]);
    const link_sl = buildSlSystemUse("../hello.txt");
    try link_su.appendSlice(link_sl[0..link_sl[2]]);
    try link_su.appendSlice(&buildStSystemUse());
    const link_record = makeDirectoryRecord("MOTD.LNK;1", file_lba, 0, 0, link_su.items);
    try subdir.appendSlice(link_record[0..link_record[0]]);
    @memcpy(image.items[dir_lba * descriptor_size ..][0..subdir.items.len], subdir.items);

    @memcpy(image.items[file_lba * descriptor_size ..][0..file_bytes.len], file_bytes);

    try writeIsoFile(path, image.items);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try std.testing.expect(reader.has_rock_ridge);
    try std.testing.expectEqual(NameSource.rock_ridge, reader.name_source);
    try std.testing.expectEqual(@as(usize, 2), reader.path_table.len);

    const file_index = try reader.lookup("/hello.txt");
    try std.testing.expectEqual(EntryKind.file, reader.getEntry(file_index).kind);
    const contents = try reader.readFileAlloc(allocator, io, file_index);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings(file_bytes, contents);

    const link_index = try reader.lookup("/dir/motd-link");
    try std.testing.expectEqualStrings("../hello.txt", try reader.readLink(link_index));
    const resolved_index = try reader.resolveSymlink(link_index);
    try std.testing.expectEqual(file_index, resolved_index);

    const dir_entries = try reader.listDirAlloc(allocator, reader.root_index);
    defer allocator.free(dir_entries);
    try std.testing.expectEqualStrings("dir", dir_entries[0].name);
    try std.testing.expectEqualStrings("hello.txt", dir_entries[1].name);
}

test "iso9660 reader falls back to joliet unicode names" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-joliet.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const primary_root_lba: u32 = 21;
    const joliet_root_lba: u32 = 22;
    const file_lba: u32 = 23;
    const file_bytes = "joliet works\n";

    var image = std.array_list.Managed(u8).init(allocator);
    defer image.deinit();
    try image.resize((file_lba + 1) * descriptor_size);
    @memset(image.items, 0);

    var pvd: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    pvd[0] = 1;
    pvd[1..6].* = standard_id;
    pvd[6] = 1;
    write733(pvd[80..88], @intCast(image.items.len / descriptor_size));
    write723(pvd[128..132], descriptor_size);
    write733(pvd[132..140], 0);
    std.mem.writeInt(u32, pvd[140..144], 20, .little);
    const root_record = makeDirectoryRecord(&.{0}, primary_root_lba, descriptor_size, 0x02, &.{});
    @memcpy(pvd[156 .. 156 + root_record[0]], root_record[0..root_record[0]]);
    image.items[16 * descriptor_size .. 17 * descriptor_size].* = pvd;

    var svd: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    svd[0] = 2;
    svd[1..6].* = standard_id;
    svd[6] = 1;
    svd[88] = '%';
    svd[89] = '/';
    svd[90] = 'E';
    write733(svd[80..88], @intCast(image.items.len / descriptor_size));
    write723(svd[128..132], descriptor_size);
    write733(svd[132..140], 0);
    std.mem.writeInt(u32, svd[140..144], 20, .little);
    const joliet_root = makeDirectoryRecord(&.{0}, joliet_root_lba, descriptor_size, 0x02, &.{});
    @memcpy(svd[156 .. 156 + joliet_root[0]], joliet_root[0..joliet_root[0]]);
    image.items[17 * descriptor_size .. 18 * descriptor_size].* = svd;

    var terminator: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    terminator[0] = 255;
    terminator[1..6].* = standard_id;
    terminator[6] = 1;
    image.items[18 * descriptor_size .. 19 * descriptor_size].* = terminator;

    var path_table = std.array_list.Managed(u8).init(allocator);
    defer path_table.deinit();
    try path_table.append(1);
    try path_table.append(0);
    try appendU32Le(&path_table, primary_root_lba);
    try appendU16Le(&path_table, 1);
    try path_table.append(0);
    try path_table.append(0);
    @memcpy(image.items[20 * descriptor_size ..][0..path_table.items.len], path_table.items);
    write733(image.items[16 * descriptor_size + 132 .. 16 * descriptor_size + 140], @intCast(path_table.items.len));
    write733(image.items[17 * descriptor_size + 132 .. 17 * descriptor_size + 140], @intCast(path_table.items.len));

    var primary_root = std.array_list.Managed(u8).init(allocator);
    defer primary_root.deinit();
    const primary_dot = makeDirectoryRecord(&.{0}, primary_root_lba, descriptor_size, 0x02, &buildStSystemUse());
    try primary_root.appendSlice(primary_dot[0..primary_dot[0]]);
    const primary_dotdot = makeDirectoryRecord(&.{1}, primary_root_lba, descriptor_size, 0x02, &buildStSystemUse());
    try primary_root.appendSlice(primary_dotdot[0..primary_dotdot[0]]);
    const primary_file = makeDirectoryRecord("UNICODE.TXT;1", file_lba, file_bytes.len, 0, &buildStSystemUse());
    try primary_root.appendSlice(primary_file[0..primary_file[0]]);
    @memcpy(image.items[primary_root_lba * descriptor_size ..][0..primary_root.items.len], primary_root.items);

    var joliet_root_dir = std.array_list.Managed(u8).init(allocator);
    defer joliet_root_dir.deinit();
    const joliet_dot = makeDirectoryRecord(&.{0}, joliet_root_lba, descriptor_size, 0x02, &buildStSystemUse());
    try joliet_root_dir.appendSlice(joliet_dot[0..joliet_dot[0]]);
    const joliet_dotdot = makeDirectoryRecord(&.{1}, joliet_root_lba, descriptor_size, 0x02, &buildStSystemUse());
    try joliet_root_dir.appendSlice(joliet_dotdot[0..joliet_dotdot[0]]);
    const joliet_name = [_]u8{ 0x00, 'h', 0x00, 0xE9, 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00, '.', 0x00, 't', 0x00, 'x', 0x00, 't', 0x00, ';', 0x00, '1' };
    const joliet_file = makeDirectoryRecord(&joliet_name, file_lba, file_bytes.len, 0, &buildStSystemUse());
    try joliet_root_dir.appendSlice(joliet_file[0..joliet_file[0]]);
    @memcpy(image.items[joliet_root_lba * descriptor_size ..][0..joliet_root_dir.items.len], joliet_root_dir.items);

    @memcpy(image.items[file_lba * descriptor_size ..][0..file_bytes.len], file_bytes);

    try writeIsoFile(path, image.items);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try std.testing.expect(!reader.has_rock_ridge);
    try std.testing.expect(reader.has_joliet);
    try std.testing.expectEqual(NameSource.joliet, reader.name_source);

    const file_index = try reader.lookup("/héllo.txt");
    const contents = try reader.readFileAlloc(allocator, io, file_index);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings(file_bytes, contents);
}

// ===========================================================================
// El Torito boot catalog readback
// ===========================================================================

pub const boot_platform_bios: u8 = 0x00;
pub const boot_platform_uefi: u8 = 0xEF;

/// A single El Torito boot entry as recovered from a boot catalog. The reader
/// only reproduces what the writer in this module emits: no-emulation entries
/// for one or both firmware platforms.
pub const BootCatalogEntry = struct {
    platform: u8,
    media_type: u8,
    bootable: bool,
    load_segment: u16,
    system_type: u8,
    load_sectors: u16,
    image_lba: u32,
};

pub const BootCatalog = struct {
    /// Platform id declared by the catalog validation entry.
    validation_platform: u8,
    entries: []BootCatalogEntry,

    pub fn deinit(self: *BootCatalog, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        self.* = undefined;
    }
};

pub const BootCatalogError = error{
    NoBootRecord,
    InvalidBootCatalog,
    BadBootCatalogChecksum,
} || Io.File.ReadPositionalError || std.mem.Allocator.Error;

/// Locates the El Torito boot record volume descriptor, follows it to the boot
/// catalog, validates the validation-entry checksum, and returns the boot
/// entries. Returns `error.NoBootRecord` when the image carries no El Torito
/// boot record. Caller owns the returned catalog.
pub fn readBootCatalog(allocator: std.mem.Allocator, io: Io, file: Io.File) BootCatalogError!BootCatalog {
    var sector: [descriptor_size]u8 = undefined;
    var lba: u32 = volume_descriptor_lba;
    var catalog_lba: ?u32 = null;
    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * descriptor_size);
        if (!std.mem.eql(u8, sector[1..6], &standard_id)) return error.InvalidBootCatalog;
        switch (sector[0]) {
            0 => {
                if (std.mem.startsWith(u8, sector[7..], "EL TORITO SPECIFICATION")) {
                    catalog_lba = read731(sector[71..75]);
                }
            },
            255 => break,
            else => {},
        }
    }

    const cat_lba = catalog_lba orelse return error.NoBootRecord;
    var catalog: [descriptor_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &catalog, @as(u64, cat_lba) * descriptor_size);

    // Validation entry: header id 0x01, key bytes 0x55 0xAA, and all 16-bit
    // little-endian words summing to zero.
    if (catalog[0] != 0x01 or catalog[30] != 0x55 or catalog[31] != 0xAA) return error.InvalidBootCatalog;
    var sum: u16 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 2) sum +%= std.mem.readInt(u16, catalog[i..][0..2], .little);
    if (sum != 0) return error.BadBootCatalogChecksum;
    const validation_platform = catalog[1];

    var entries = std.array_list.Managed(BootCatalogEntry).init(allocator);
    errdefer entries.deinit();

    // Default/initial entry immediately follows the validation entry and
    // inherits the validation entry's platform id.
    try parseBootEntry(&entries, catalog[32..64], validation_platform);

    // Section headers (0x90/0x91) each introduce a run of section entries for a
    // possibly different platform.
    var offset: usize = 64;
    while (offset + 32 <= catalog.len) {
        const header_id = catalog[offset];
        if (header_id != 0x90 and header_id != 0x91) break;
        const section_platform = catalog[offset + 1];
        const count = std.mem.readInt(u16, catalog[offset + 2 ..][0..2], .little);
        offset += 32;
        var seen: u16 = 0;
        while (seen < count and offset + 32 <= catalog.len) : (seen += 1) {
            try parseBootEntry(&entries, catalog[offset .. offset + 32], section_platform);
            offset += 32;
        }
        if (header_id == 0x91) break;
    }

    return .{ .validation_platform = validation_platform, .entries = try entries.toOwnedSlice() };
}

fn parseBootEntry(list: *std.array_list.Managed(BootCatalogEntry), entry: []const u8, platform: u8) std.mem.Allocator.Error!void {
    try list.append(.{
        .platform = platform,
        .media_type = entry[1],
        .bootable = entry[0] == 0x88,
        .load_segment = std.mem.readInt(u16, entry[2..4], .little),
        .system_type = entry[4],
        .load_sectors = std.mem.readInt(u16, entry[6..8], .little),
        .image_lba = std.mem.readInt(u32, entry[8..12], .little),
    });
}

pub const VolumeIdError = error{
    BadVolumeDescriptor,
    MissingPrimaryVolumeDescriptor,
} || Io.File.ReadPositionalError || std.mem.Allocator.Error;

/// Reads the primary volume descriptor's 32-byte volume identifier, trimmed of
/// trailing spaces and NULs. A regenerating pipeline (e.g. `build_iso`) reuses
/// it so a `root=live:CDLABEL=<id>` boot line still finds the volume after the
/// image is rewritten. Caller owns the returned slice.
pub fn readVolumeIdAlloc(allocator: std.mem.Allocator, io: Io, file: Io.File) VolumeIdError![]u8 {
    var sector: [descriptor_size]u8 = undefined;
    var lba: u32 = volume_descriptor_lba;
    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * descriptor_size);
        if (!std.mem.eql(u8, sector[1..6], &standard_id)) return error.BadVolumeDescriptor;
        switch (sector[0]) {
            1 => {
                const raw = sector[40..72];
                var end: usize = raw.len;
                while (end > 0 and (raw[end - 1] == ' ' or raw[end - 1] == 0)) end -= 1;
                return allocator.dupe(u8, raw[0..end]);
            },
            255 => break,
            else => {},
        }
    }
    return error.MissingPrimaryVolumeDescriptor;
}

// ===========================================================================
// Writer
// ===========================================================================

/// Node kinds the writer can encode. Adapters reject anything outside this set
/// (hardlinks, devices, fifos) with a precise error rather than dropping it.
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
    /// Deterministic modification time in epoch seconds, stamped into the
    /// directory record's recording date. Negative values clamp to 0.
    mtime: i64 = 0,
    /// Byte length for regular files; ignored for directories and symlinks.
    size: u64 = 0,
    /// Link target for symlinks, borrowed for the duration of the write call.
    /// May be empty for sources that expose the target through `read` (in
    /// which case `size` gives its length); ignored for other kinds.
    symlink_target: []const u8 = &.{},
};

/// Metadata for the image root directory.
pub const SourceRoot = struct {
    mode: u16 = 0o755,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: i64 = 0,
};

/// Generic pull-based source the writer consumes. Any tree (RootTree included)
/// can expose one without the ISO codec depending on its concrete type.
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

/// El Torito firmware platform for a boot entry.
pub const BootPlatform = enum(u8) {
    bios = boot_platform_bios,
    uefi = boot_platform_uefi,
};

/// A single El Torito boot entry the writer should emit. `image_path` names a
/// regular file already present in the source tree; its assigned LBA is wired
/// into the boot catalog.
pub const BootEntry = struct {
    platform: BootPlatform,
    /// Root-relative path (no leading slash) of the boot image file.
    image_path: []const u8,
    /// Load segment in real-mode paragraphs; 0 selects the El Torito default
    /// (0x07C0). Ignored by UEFI firmware but preserved in the catalog.
    load_segment: u16 = 0,
    /// System type byte (partition type of the boot image); 0 is typical for
    /// no-emulation images.
    system_type: u8 = 0,
    /// Virtual 512-byte sectors to load; 0 lets the writer derive it from the
    /// boot image size.
    load_sectors: u16 = 0,
    bootable: bool = true,
};

pub const WriteOptions = struct {
    /// Volume identifier written to the primary volume descriptor (d-chars,
    /// truncated/space-padded to 32 bytes).
    volume_id: []const u8 = "ISOIMAGE",
    /// System identifier (a-chars, truncated/space-padded to 32 bytes).
    system_id: []const u8 = "",
    /// El Torito boot entries. Empty means a plain (non-bootable) ISO. At most
    /// one entry per platform is supported.
    boot_entries: []const BootEntry = &.{},
};

pub const WriteResult = struct {
    /// Total image length in bytes (always a multiple of 2048).
    bytes_written: u64,
    /// Number of 2048-byte logical sectors in the image.
    total_sectors: u32,
    /// Directory + file + symlink nodes emitted (excludes the root directory).
    node_count: u32,
};

pub const WriteError = error{
    InvalidPath,
    MissingParentDirectory,
    DuplicatePath,
    NameTooLong,
    SymlinkTargetTooLong,
    EmptyName,
    TooManyBootEntries,
    DuplicateBootPlatform,
    BootImageNotFound,
    ContentReadShort,
    SystemUseAreaTooLong,
};

/// Writes a deterministic ISO9660 image describing `source` to `output`, which
/// must be a writable file positioned at offset 0. Streams file content sector
/// by sector and returns the image length plus counts.
pub fn writeImage(
    allocator: std.mem.Allocator,
    io: Io,
    output: Io.File,
    source: TreeSource,
    options: WriteOptions,
) anyerror!WriteResult {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    var writer = IsoWriter{
        .allocator = allocator,
        .arena = arena_state.allocator(),
        .io = io,
        .file = output,
        .options = options,
    };
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

const sector_size: u32 = descriptor_size;
const system_area_sectors: u32 = 16;
const max_record_len: usize = 255;
const max_name_len: usize = 250;

const IsoBuildNode = struct {
    kind: SourceKind,
    name: []const u8,
    iso_id: []const u8,
    mode: u16,
    uid: u32,
    gid: u32,
    mtime: i64,
    file_size: u64,
    symlink_target: []const u8,
    source_index: ?usize,
    parent_index: usize,
    children: std.array_list.Managed(usize),

    // The full Rock Ridge SUSP for this node's record inside its parent
    // directory, and the record length that produces.
    child_susp: []u8 = &.{},
    child_uses_ce: bool = false,
    child_record_len: u8 = 0,
    ce_offset: u32 = 0,

    // Assigned during layout.
    extent_lba: u32 = 0,
    data_len: u32 = 0,
    dir_number: u16 = 0,
};

const IsoWriter = struct {
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: Io,
    file: Io.File,
    options: WriteOptions,

    nodes: []IsoBuildNode = &.{},
    dir_order: []usize = &.{},
    continuation: std.array_list.Managed(u8) = undefined,

    // Layout.
    pvd_lba: u32 = 0,
    boot_record_lba: u32 = 0,
    terminator_lba: u32 = 0,
    path_table_l_lba: u32 = 0,
    path_table_m_lba: u32 = 0,
    path_table_size: u32 = 0,
    continuation_lba: u32 = 0,
    boot_catalog_lba: u32 = 0,
    total_sectors: u32 = 0,

    fn run(self: *IsoWriter, source: TreeSource) anyerror!WriteResult {
        self.continuation = std.array_list.Managed(u8).init(self.arena);

        try self.buildTree(source);
        try self.orderDirectories();
        try self.buildSusp();
        try self.assignLayout();
        try self.emit(source);

        return .{
            .bytes_written = @as(u64, self.total_sectors) * sector_size,
            .total_sectors = self.total_sectors,
            .node_count = @intCast(self.nodes.len - 1),
        };
    }

    fn buildTree(self: *IsoWriter, source: TreeSource) anyerror!void {
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

        var nodes = std.array_list.Managed(IsoBuildNode).init(self.arena);
        var map = std.StringHashMap(usize).init(self.arena);

        const root = source.root();
        try nodes.append(.{
            .kind = .directory,
            .name = "",
            .iso_id = "",
            .mode = root.mode,
            .uid = root.uid,
            .gid = root.gid,
            .mtime = clamp(root.mtime),
            .file_size = 0,
            .symlink_target = &.{},
            .source_index = null,
            .parent_index = 0,
            .children = std.array_list.Managed(usize).init(self.arena),
        });
        try map.put("", 0);

        for (collected.items) |item| {
            const sn = item.node;
            var path = sn.path;
            while (path.len > 0 and path[0] == '/') path = path[1..];
            if (path.len == 0) return error.InvalidPath;

            const parent_path, const name = splitLast(path);
            if (name.len == 0) return error.EmptyName;
            if (name.len > max_name_len) return error.NameTooLong;
            const parent_index = map.get(parent_path) orelse return error.MissingParentDirectory;
            if (map.contains(path)) return error.DuplicatePath;

            const symlink_target: []const u8 = if (sn.kind == .symlink) blk: {
                const target = if (sn.symlink_target.len > 0)
                    try self.arena.dupe(u8, sn.symlink_target)
                else target_blk: {
                    const buffer = try self.arena.alloc(u8, @intCast(sn.size));
                    try self.readExact(source, item.index, buffer, 0);
                    break :target_blk buffer;
                };
                break :blk target;
            } else &.{};

            const new_index = nodes.items.len;
            try nodes.append(.{
                .kind = sn.kind,
                .name = try self.arena.dupe(u8, name),
                .iso_id = "",
                .mode = sn.mode,
                .uid = sn.uid,
                .gid = sn.gid,
                .mtime = clamp(sn.mtime),
                .file_size = if (sn.kind == .file) sn.size else 0,
                .symlink_target = symlink_target,
                .source_index = item.index,
                .parent_index = parent_index,
                .children = std.array_list.Managed(usize).init(self.arena),
            });
            try map.put(try self.arena.dupe(u8, path), new_index);
            try nodes.items[parent_index].children.append(new_index);
        }

        self.nodes = nodes.items;
        for (self.nodes) |*node| {
            std.mem.sort(usize, node.children.items, self.nodes, childNameLess);
        }
        try self.assignIsoIdentifiers();
    }

    fn assignIsoIdentifiers(self: *IsoWriter) anyerror!void {
        for (self.nodes) |*dir| {
            if (dir.kind != .directory) continue;
            var used = std.StringHashMap(void).init(self.arena);
            for (dir.children.items) |child_index| {
                const child = &self.nodes[child_index];
                child.iso_id = try self.mangleIdentifier(child.name, child.kind == .directory, &used);
            }
        }
    }

    fn mangleIdentifier(self: *IsoWriter, name: []const u8, is_dir: bool, used: *std.StringHashMap(void)) anyerror![]const u8 {
        var base = std.array_list.Managed(u8).init(self.arena);
        const limit: usize = if (is_dir) 30 else 26;
        for (name) |c| {
            if (base.items.len >= limit) break;
            const up = std.ascii.toUpper(c);
            if ((up >= 'A' and up <= 'Z') or (up >= '0' and up <= '9') or up == '_') {
                try base.append(up);
            } else {
                try base.append('_');
            }
        }
        if (base.items.len == 0) try base.append('_');

        var suffix: u32 = 0;
        while (true) {
            var candidate = std.array_list.Managed(u8).init(self.arena);
            try candidate.appendSlice(base.items);
            if (suffix > 0) {
                var buf: [12]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{suffix}) catch unreachable;
                const keep = @min(base.items.len, limit - s.len);
                candidate.clearRetainingCapacity();
                try candidate.appendSlice(base.items[0..keep]);
                try candidate.appendSlice(s);
            }
            if (!is_dir) try candidate.appendSlice(";1");
            const key = candidate.items;
            if (!used.contains(key)) {
                try used.put(key, {});
                return key;
            }
            suffix += 1;
        }
    }

    fn orderDirectories(self: *IsoWriter) anyerror!void {
        var order = std.array_list.Managed(usize).init(self.arena);
        try order.append(0);
        self.nodes[0].dir_number = 1;
        var cursor: usize = 0;
        while (cursor < order.items.len) : (cursor += 1) {
            const dir_index = order.items[cursor];
            for (self.nodes[dir_index].children.items) |child_index| {
                if (self.nodes[child_index].kind == .directory) {
                    self.nodes[child_index].dir_number = @intCast(order.items.len + 1);
                    try order.append(child_index);
                }
            }
        }
        self.dir_order = order.items;
    }

    fn buildSusp(self: *IsoWriter) anyerror!void {
        for (self.nodes, 0..) |*node, idx| {
            if (idx == 0) continue;
            var susp = std.array_list.Managed(u8).init(self.arena);
            try susp.appendSlice(&buildPxSystemUse(fullMode(node.kind, node.mode), node.uid, node.gid));
            const nm = buildNmSystemUse(node.name);
            try susp.appendSlice(nm[0..nm[2]]);
            if (node.kind == .symlink) {
                if (symlinkComponentsLen(node.symlink_target) > max_record_len) return error.SymlinkTargetTooLong;
                const sl = buildSlSystemUse(node.symlink_target);
                try susp.appendSlice(sl[0..sl[2]]);
            }
            node.child_susp = susp.items;

            const id_len = node.iso_id.len;
            const inline_len = recordLength(id_len, susp.items.len);
            if (inline_len <= max_record_len) {
                node.child_uses_ce = false;
                node.child_record_len = @intCast(inline_len);
            } else {
                // The record itself only carries the fixed-size `CE` pointer, so
                // its length is always well within `max_record_len`.
                node.child_uses_ce = true;
                node.child_record_len = @intCast(recordLength(id_len, ce_record_len));

                // A System Use payload referenced by `CE` must not straddle a
                // logical-block boundary (SUSP §4). Pad the continuation area up
                // to the next sector when the payload would not fit in what
                // remains of the current one. A single payload larger than a
                // logical block cannot be represented; reject it precisely.
                if (susp.items.len > sector_size) return error.SystemUseAreaTooLong;
                const used = self.continuation.items.len % sector_size;
                const remaining = sector_size - used;
                if (susp.items.len > remaining) {
                    try self.continuation.appendNTimes(0, remaining);
                }

                node.ce_offset = @intCast(self.continuation.items.len);
                try self.continuation.appendSlice(susp.items);
            }
        }

        // Compute each directory's extent size from its record layout.
        for (self.dir_order) |dir_index| {
            self.nodes[dir_index].data_len = self.directoryExtentSize(dir_index);
        }
    }

    fn directoryExtentSize(self: *IsoWriter, dir_index: usize) u32 {
        const dir = &self.nodes[dir_index];
        var pos: u32 = 0;
        // '.' and '..' records.
        pos = placeRecord(pos, dotRecordLen(dir_index == 0));
        pos = placeRecord(pos, dotdotRecordLen());
        for (dir.children.items) |child_index| {
            pos = placeRecord(pos, self.nodes[child_index].child_record_len);
        }
        return roundUpSector(pos);
    }

    fn assignLayout(self: *IsoWriter) anyerror!void {
        const has_boot = self.options.boot_entries.len > 0;
        try self.validateBootEntries();

        var lba: u32 = system_area_sectors;
        self.pvd_lba = lba;
        lba += 1;
        if (has_boot) {
            self.boot_record_lba = lba;
            lba += 1;
        }
        self.terminator_lba = lba;
        lba += 1;

        self.path_table_size = self.computePathTableSize();
        const path_table_sectors = sectorsFor(self.path_table_size);
        self.path_table_l_lba = lba;
        lba += path_table_sectors;
        self.path_table_m_lba = lba;
        lba += path_table_sectors;

        for (self.dir_order) |dir_index| {
            self.nodes[dir_index].extent_lba = lba;
            lba += sectorsFor(self.nodes[dir_index].data_len);
        }

        if (self.continuation.items.len > 0) {
            self.continuation_lba = lba;
            lba += sectorsFor(@intCast(self.continuation.items.len));
        }

        if (has_boot) {
            self.boot_catalog_lba = lba;
            lba += 1;
        }

        // File data extents (symlinks carry their target in Rock Ridge and use
        // no data extent). Deterministic path order = build order.
        for (self.nodes) |*node| {
            if (node.kind != .file) continue;
            node.extent_lba = lba;
            lba += sectorsFor64(node.file_size);
        }

        // ISO9660 addresses sectors with a 32-bit count; `lba` is already u32,
        // so accumulation past that range would have trapped earlier.
        self.total_sectors = lba;
    }

    fn validateBootEntries(self: *IsoWriter) anyerror!void {
        if (self.options.boot_entries.len == 0) return;
        if (self.options.boot_entries.len > 2) return error.TooManyBootEntries;
        var seen_bios = false;
        var seen_uefi = false;
        for (self.options.boot_entries) |entry| {
            switch (entry.platform) {
                .bios => {
                    if (seen_bios) return error.DuplicateBootPlatform;
                    seen_bios = true;
                },
                .uefi => {
                    if (seen_uefi) return error.DuplicateBootPlatform;
                    seen_uefi = true;
                },
            }
            _ = self.findFileNode(entry.image_path) orelse return error.BootImageNotFound;
        }
    }

    fn findFileNode(self: *IsoWriter, path: []const u8) ?usize {
        var p = path;
        while (p.len > 0 and p[0] == '/') p = p[1..];
        for (self.nodes, 0..) |node, idx| {
            if (node.kind != .file) continue;
            if (std.mem.eql(u8, self.nodePath(idx), p)) return idx;
        }
        return null;
    }

    fn nodePath(self: *IsoWriter, index: usize) []const u8 {
        // Reconstruct the root-relative path by walking parents. Bounded by
        // tree depth; used only for boot-image resolution.
        var parts = std.array_list.Managed([]const u8).init(self.arena);
        var cur = index;
        while (cur != 0) {
            parts.append(self.nodes[cur].name) catch return "";
            cur = self.nodes[cur].parent_index;
        }
        var out = std.array_list.Managed(u8).init(self.arena);
        var i: usize = parts.items.len;
        while (i > 0) {
            i -= 1;
            if (out.items.len > 0) out.append('/') catch return "";
            out.appendSlice(parts.items[i]) catch return "";
        }
        return out.items;
    }

    fn computePathTableSize(self: *IsoWriter) u32 {
        var size: u32 = 0;
        for (self.dir_order) |dir_index| {
            const id_len: usize = if (dir_index == 0) 1 else self.nodes[dir_index].iso_id.len;
            size += @intCast(8 + id_len + (id_len & 1));
        }
        return size;
    }

    fn emit(self: *IsoWriter, source: TreeSource) anyerror!void {
        try self.emitPrimaryVolumeDescriptor();
        if (self.options.boot_entries.len > 0) try self.emitBootRecord();
        try self.emitTerminator();
        try self.emitPathTable(true);
        try self.emitPathTable(false);
        try self.emitDirectories();
        try self.emitContinuation();
        if (self.options.boot_entries.len > 0) try self.emitBootCatalog();
        try self.emitFiles(source);
        try self.padImage();
    }

    fn emitPrimaryVolumeDescriptor(self: *IsoWriter) anyerror!void {
        var pvd = [_]u8{0} ** sector_size;
        pvd[0] = 1;
        pvd[1..6].* = standard_id;
        pvd[6] = 1;
        setAField(pvd[8..40], self.options.system_id);
        setDField(pvd[40..72], self.options.volume_id);
        write733(pvd[80..88], self.total_sectors);
        write723(pvd[120..124], 1); // volume set size
        write723(pvd[124..128], 1); // volume sequence number
        write723(pvd[128..132], sector_size);
        write733(pvd[132..140], self.path_table_size);
        write731(pvd[140..144], self.path_table_l_lba);
        write731(pvd[144..148], 0);
        write732(pvd[148..152], self.path_table_m_lba);
        write732(pvd[152..156], 0);
        const root_record = self.makeRootRecord();
        @memcpy(pvd[156 .. 156 + root_record.len], &root_record);
        // Volume descriptor date/time fields left as zeros for determinism.
        pvd[881] = 1; // file structure version
        try self.writeSector(self.pvd_lba, &pvd);
    }

    fn makeRootRecord(self: *IsoWriter) [34]u8 {
        var out = [_]u8{0} ** 34;
        const root = &self.nodes[0];
        out[0] = 34;
        write733(out[2..10], root.extent_lba);
        write733(out[10..18], root.data_len);
        writeRecordDate(out[18..25], root.mtime);
        out[25] = 0x02;
        write723(out[28..32], 1);
        out[32] = 1;
        out[33] = 0;
        return out;
    }

    fn emitBootRecord(self: *IsoWriter) anyerror!void {
        var br = [_]u8{0} ** sector_size;
        br[0] = 0;
        br[1..6].* = standard_id;
        br[6] = 1;
        const boot_sys_id = "EL TORITO SPECIFICATION";
        @memcpy(br[7 .. 7 + boot_sys_id.len], boot_sys_id);
        write731(br[71..75], self.boot_catalog_lba);
        try self.writeSector(self.boot_record_lba, &br);
    }

    fn emitTerminator(self: *IsoWriter) anyerror!void {
        var term = [_]u8{0} ** sector_size;
        term[0] = 255;
        term[1..6].* = standard_id;
        term[6] = 1;
        try self.writeSector(self.terminator_lba, &term);
    }

    fn emitPathTable(self: *IsoWriter, little_endian: bool) anyerror!void {
        const bytes = try self.arena.alloc(u8, roundUpSector(self.path_table_size));
        @memset(bytes, 0);
        var pos: usize = 0;
        for (self.dir_order) |dir_index| {
            const dir = &self.nodes[dir_index];
            const is_root = dir_index == 0;
            const id: []const u8 = if (is_root) &[_]u8{0} else dir.iso_id;
            const parent_number: u16 = if (is_root) 1 else self.nodes[dir.parent_index].dir_number;
            bytes[pos] = @intCast(id.len);
            bytes[pos + 1] = 0;
            if (little_endian) {
                write731(bytes[pos + 2 .. pos + 6], dir.extent_lba);
                write721(bytes[pos + 6 .. pos + 8], parent_number);
            } else {
                write732(bytes[pos + 2 .. pos + 6], dir.extent_lba);
                write722(bytes[pos + 6 .. pos + 8], parent_number);
            }
            @memcpy(bytes[pos + 8 ..][0..id.len], id);
            pos += 8 + id.len;
            if (id.len & 1 == 1) {
                bytes[pos] = 0;
                pos += 1;
            }
        }
        const lba = if (little_endian) self.path_table_l_lba else self.path_table_m_lba;
        try self.writeSector(lba, bytes);
    }

    fn emitDirectories(self: *IsoWriter) anyerror!void {
        for (self.dir_order) |dir_index| {
            const dir = &self.nodes[dir_index];
            const bytes = try self.arena.alloc(u8, dir.data_len);
            @memset(bytes, 0);
            var pos: u32 = 0;
            pos = try self.writeDirRecord(bytes, pos, dir_index, .dot);
            pos = try self.writeDirRecord(bytes, pos, dir_index, .dotdot);
            for (dir.children.items) |child_index| {
                pos = try self.writeDirRecord(bytes, pos, child_index, .child);
            }
            try self.writeSector(dir.extent_lba, bytes);
        }
    }

    const RecordRole = enum { dot, dotdot, child };

    fn writeDirRecord(self: *IsoWriter, buf: []u8, pos_in: u32, node_index: usize, role: RecordRole) anyerror!u32 {
        var pos = pos_in;
        const rec_len = switch (role) {
            .dot => dotRecordLen(node_index == 0),
            .dotdot => dotdotRecordLen(),
            .child => self.nodes[node_index].child_record_len,
        };
        // Records may not span a 2048-byte logical sector boundary.
        const sector_off = pos % sector_size;
        if (sector_off + rec_len > sector_size) {
            pos += sector_size - sector_off;
        }

        var identifier: []const u8 = undefined;
        var extent_lba: u32 = 0;
        var data_len: u32 = 0;
        var flags: u8 = 0;
        var mtime: i64 = 0;
        var susp: []const u8 = &.{};
        var ce: ?CeRef = null;

        switch (role) {
            .dot => {
                identifier = &[_]u8{0};
                const dir = &self.nodes[node_index];
                extent_lba = dir.extent_lba;
                data_len = dir.data_len;
                flags = 0x02;
                mtime = dir.mtime;
                susp = self.dotSusp(node_index);
            },
            .dotdot => {
                identifier = &[_]u8{1};
                const parent = &self.nodes[self.nodes[node_index].parent_index];
                extent_lba = parent.extent_lba;
                data_len = parent.data_len;
                flags = 0x02;
                mtime = parent.mtime;
            },
            .child => {
                const child = &self.nodes[node_index];
                identifier = child.iso_id;
                flags = if (child.kind == .directory) 0x02 else 0x00;
                mtime = child.mtime;
                switch (child.kind) {
                    .directory => {
                        extent_lba = child.extent_lba;
                        data_len = child.data_len;
                    },
                    .file => {
                        extent_lba = child.extent_lba;
                        data_len = @intCast(child.file_size);
                    },
                    .symlink => {
                        extent_lba = 0;
                        data_len = 0;
                    },
                }
                if (child.child_uses_ce) {
                    ce = .{
                        .lba = self.continuation_lba + child.ce_offset / sector_size,
                        .offset = child.ce_offset % sector_size,
                        .len = @intCast(child.child_susp.len),
                    };
                } else {
                    susp = child.child_susp;
                }
            },
        }

        writeDirectoryRecordInto(buf[pos..], identifier, extent_lba, data_len, flags, mtime, susp, ce);
        return pos + rec_len;
    }

    fn dotSusp(self: *IsoWriter, dir_index: usize) []u8 {
        // Recomputed lazily so the byte layout matches dotRecordLen exactly.
        var susp = std.array_list.Managed(u8).init(self.arena);
        if (dir_index == 0) {
            susp.appendSlice(&buildSpSkip0()) catch return &.{};
            susp.appendSlice(&buildErSystemUse()) catch return &.{};
        }
        const dir = &self.nodes[dir_index];
        susp.appendSlice(&buildPxSystemUse(fullMode(.directory, dir.mode), dir.uid, dir.gid)) catch return &.{};
        return susp.items;
    }

    fn emitContinuation(self: *IsoWriter) anyerror!void {
        if (self.continuation.items.len == 0) return;
        const bytes = try self.arena.alloc(u8, roundUpSector(@intCast(self.continuation.items.len)));
        @memset(bytes, 0);
        @memcpy(bytes[0..self.continuation.items.len], self.continuation.items);
        try self.writeSector(self.continuation_lba, bytes);
    }

    fn emitBootCatalog(self: *IsoWriter) anyerror!void {
        var cat = [_]u8{0} ** sector_size;

        // Order: BIOS first (if present) becomes the validation platform and
        // default entry; the remaining platform is emitted as a section.
        var default_entry: ?BootEntry = null;
        var section_entry: ?BootEntry = null;
        for (self.options.boot_entries) |entry| {
            if (entry.platform == .bios) default_entry = entry else section_entry = entry;
        }
        if (default_entry == null) {
            // UEFI-only: the single entry is the default with a UEFI-platform
            // validation entry.
            default_entry = section_entry;
            section_entry = null;
        }
        const default = default_entry.?;

        // Validation entry.
        cat[0] = 0x01;
        cat[1] = @intFromEnum(default.platform);
        cat[30] = 0x55;
        cat[31] = 0xAA;
        var sum: u16 = 0;
        var i: usize = 0;
        while (i < 32) : (i += 2) {
            if (i == 28) continue;
            sum +%= std.mem.readInt(u16, cat[i..][0..2], .little);
        }
        std.mem.writeInt(u16, cat[28..30], (~sum +% 1), .little);

        self.writeBootEntry(cat[32..64], default);

        if (section_entry) |entry| {
            cat[64] = 0x91; // final section header
            cat[65] = @intFromEnum(entry.platform);
            std.mem.writeInt(u16, cat[66..68], 1, .little);
            self.writeBootEntry(cat[96..128], entry);
        }

        try self.writeSector(self.boot_catalog_lba, &cat);
    }

    fn writeBootEntry(self: *IsoWriter, dst: []u8, entry: BootEntry) void {
        const node_index = self.findFileNode(entry.image_path).?;
        const image_lba = self.nodes[node_index].extent_lba;
        const image_size = self.nodes[node_index].file_size;
        const sectors: u16 = if (entry.load_sectors != 0)
            entry.load_sectors
        else
            @intCast(@min(@as(u64, std.math.maxInt(u16)), std.math.divCeil(u64, @max(image_size, 1), 512) catch 1));
        dst[0] = if (entry.bootable) 0x88 else 0x00;
        dst[1] = 0x00; // no emulation
        std.mem.writeInt(u16, dst[2..4], entry.load_segment, .little);
        dst[4] = entry.system_type;
        dst[5] = 0;
        std.mem.writeInt(u16, dst[6..8], sectors, .little);
        std.mem.writeInt(u32, dst[8..12], image_lba, .little);
    }

    fn emitFiles(self: *IsoWriter, source: TreeSource) anyerror!void {
        var chunk = try self.allocator.alloc(u8, sector_size * 8);
        defer self.allocator.free(chunk);
        for (self.nodes) |*node| {
            if (node.kind != .file or node.file_size == 0) continue;
            const source_index = node.source_index.?;
            var offset: u64 = 0;
            var sector = node.extent_lba;
            while (offset < node.file_size) {
                const want: usize = @intCast(@min(@as(u64, chunk.len), node.file_size - offset));
                try self.readExact(source, source_index, chunk[0..want], offset);
                // Pad the final partial sector with zeros so extents stay
                // sector-aligned on disk.
                const padded = roundUpSector(@intCast(want));
                if (padded != want) @memset(chunk[want..padded], 0);
                try self.file.writePositionalAll(self.io, chunk[0..padded], @as(u64, sector) * sector_size);
                offset += want;
                sector += @intCast(padded / sector_size);
            }
        }
    }

    fn padImage(self: *IsoWriter) anyerror!void {
        // Guarantee the backing file spans the full image even when it ends on
        // a hole (e.g. trailing zero-length files) by writing the final sector.
        const last = self.total_sectors - 1;
        var probe: [1]u8 = undefined;
        const end = @as(u64, self.total_sectors) * sector_size;
        const got = try self.file.readPositionalAll(self.io, probe[0..], end - 1);
        if (got == 0) {
            var zero = [_]u8{0} ** sector_size;
            try self.writeSector(last, &zero);
        }
    }

    fn writeSector(self: *IsoWriter, lba: u32, bytes: []const u8) anyerror!void {
        try self.file.writePositionalAll(self.io, bytes, @as(u64, lba) * sector_size);
    }

    fn readExact(self: *IsoWriter, source: TreeSource, index: usize, buffer: []u8, offset: u64) anyerror!void {
        _ = self;
        var done: usize = 0;
        while (done < buffer.len) {
            const got = try source.read(index, buffer[done..], offset + done);
            if (got == 0) return error.ContentReadShort;
            done += got;
        }
    }
};

const CeRef = struct { lba: u32, offset: u32, len: u32 };

const ce_record_len: usize = 28;

fn splitLast(path: []const u8) struct { []const u8, []const u8 } {
    const separator = std.mem.lastIndexOfScalar(u8, path, '/') orelse return .{ "", path };
    return .{ path[0..separator], path[separator + 1 ..] };
}

fn childNameLess(nodes: []IsoBuildNode, a: usize, b: usize) bool {
    return std.mem.lessThan(u8, nodes[a].name, nodes[b].name);
}

fn clamp(value: i64) i64 {
    return if (value < 0) 0 else value;
}

fn fullMode(kind: SourceKind, mode: u16) u32 {
    const type_bits: u32 = switch (kind) {
        .directory => 0o040000,
        .file => 0o100000,
        .symlink => 0o120000,
    };
    return type_bits | (@as(u32, mode) & 0o7777);
}

fn dotRecordLen(is_root: bool) u8 {
    // '.' identifier is one byte (0x00): 33 + 1 + pad(0) + susp.
    var susp: usize = px_len;
    if (is_root) susp += sp_len + er_len;
    return @intCast(recordLength(1, susp));
}

fn dotdotRecordLen() u8 {
    return @intCast(recordLength(1, 0));
}

fn placeRecord(pos: u32, rec_len: u8) u32 {
    var p = pos;
    const sector_off = p % sector_size;
    if (sector_off + rec_len > sector_size) {
        p += sector_size - sector_off;
    }
    return p + rec_len;
}

fn roundUpSector(len: u32) u32 {
    return (len + sector_size - 1) / sector_size * sector_size;
}

fn sectorsFor(len: u32) u32 {
    return (len + sector_size - 1) / sector_size;
}

fn sectorsFor64(len: u64) u32 {
    return @intCast((len + sector_size - 1) / sector_size);
}

const px_len: usize = 36;
const sp_len: usize = 7;
const er_len: usize = 20;

fn buildSpSkip0() [7]u8 {
    return .{ 'S', 'P', 7, 1, 0xBE, 0xEF, 0 };
}

fn symlinkComponentsLen(target: []const u8) usize {
    var len: usize = 5;
    if (std.mem.startsWith(u8, target, "/")) len += 2;
    var it = std.mem.tokenizeScalar(u8, target, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) {
            len += 2;
        } else {
            len += 2 + component.len;
        }
    }
    return len;
}

fn writeDirectoryRecordInto(
    dst: []u8,
    identifier: []const u8,
    extent_lba: u32,
    data_len: u32,
    flags: u8,
    mtime: i64,
    susp: []const u8,
    ce: ?CeRef,
) void {
    const ce_len: usize = if (ce != null) ce_record_len else 0;
    const rec_len = recordLength(identifier.len, susp.len + ce_len);
    @memset(dst[0..rec_len], 0);
    dst[0] = @intCast(rec_len);
    dst[1] = 0;
    write733(dst[2..10], extent_lba);
    write733(dst[10..18], data_len);
    writeRecordDate(dst[18..25], mtime);
    dst[25] = flags;
    dst[26] = 0;
    dst[27] = 0;
    write723(dst[28..32], 1);
    dst[32] = @intCast(identifier.len);
    @memcpy(dst[33 .. 33 + identifier.len], identifier);
    const pad: usize = if (identifier.len % 2 == 0) 1 else 0;
    if (pad == 1) dst[33 + identifier.len] = 0;
    var su = 33 + identifier.len + pad;
    if (ce) |c| {
        writeCe(dst[su .. su + ce_record_len], c);
        su += ce_record_len;
    }
    @memcpy(dst[su .. su + susp.len], susp);
}

fn writeCe(dst: []u8, ce: CeRef) void {
    dst[0] = 'C';
    dst[1] = 'E';
    dst[2] = 28;
    dst[3] = 1;
    write733(dst[4..12], ce.lba);
    write733(dst[12..20], ce.offset);
    write733(dst[20..28], ce.len);
}

fn writeRecordDate(dst: []u8, epoch: i64) void {
    const dt = civilFromEpoch(epoch);
    dst[0] = @intCast(@as(i64, dt.year) - 1900);
    dst[1] = dt.month;
    dst[2] = dt.day;
    dst[3] = dt.hour;
    dst[4] = dt.minute;
    dst[5] = dt.second;
    dst[6] = 0; // GMT offset in 15-minute intervals
}

const CivilTime = struct { year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8 };

fn civilFromEpoch(epoch_in: i64) CivilTime {
    const epoch = if (epoch_in < 0) 0 else epoch_in;
    var days = @divFloor(epoch, 86400);
    const secs_of_day = epoch - days * 86400;
    const hour: u8 = @intCast(@divFloor(secs_of_day, 3600));
    const minute: u8 = @intCast(@divFloor(@mod(secs_of_day, 3600), 60));
    const second: u8 = @intCast(@mod(secs_of_day, 60));

    // Howard Hinnant's civil_from_days.
    days += 719468;
    const era = @divFloor(if (days >= 0) days else days - 146096, 146097);
    const doe = days - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const year = if (m <= 2) y + 1 else y;
    return .{
        .year = year,
        .month = @intCast(m),
        .day = @intCast(d),
        .hour = hour,
        .minute = minute,
        .second = second,
    };
}

fn setAField(dst: []u8, value: []const u8) void {
    @memset(dst, ' ');
    const n = @min(dst.len, value.len);
    for (value[0..n], 0..) |c, i| dst[i] = std.ascii.toUpper(c);
}

fn setDField(dst: []u8, value: []const u8) void {
    @memset(dst, ' ');
    const n = @min(dst.len, value.len);
    for (value[0..n], 0..) |c, i| {
        const up = std.ascii.toUpper(c);
        dst[i] = if ((up >= 'A' and up <= 'Z') or (up >= '0' and up <= '9') or up == '_') up else '_';
    }
}

fn write721(dst: []u8, value: u16) void {
    std.mem.writeInt(u16, dst[0..2], value, .little);
}

fn write722(dst: []u8, value: u16) void {
    std.mem.writeInt(u16, dst[0..2], value, .big);
}

fn write731(dst: []u8, value: u32) void {
    std.mem.writeInt(u32, dst[0..4], value, .little);
}

fn write732(dst: []u8, value: u32) void {
    std.mem.writeInt(u32, dst[0..4], value, .big);
}

// ===========================================================================
// Writer tests
// ===========================================================================

const TestNode = struct {
    path: []const u8,
    kind: SourceKind,
    mode: u16 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: i64 = 0,
    bytes: []const u8 = &.{},
    target: []const u8 = &.{},
};

const TestSource = struct {
    root_meta: SourceRoot = .{},
    nodes: []const TestNode,

    fn source(self: *const TestSource) TreeSource {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable = TreeSource.VTable{
        .root = rootFn,
        .count = countFn,
        .node = nodeFn,
        .read = readFn,
    };

    fn ctx(context: *const anyopaque) *const TestSource {
        return @ptrCast(@alignCast(context));
    }
    fn rootFn(context: *const anyopaque) SourceRoot {
        return ctx(context).root_meta;
    }
    fn countFn(context: *const anyopaque) usize {
        return ctx(context).nodes.len;
    }
    fn nodeFn(context: *const anyopaque, index: usize) anyerror!SourceNode {
        const n = ctx(context).nodes[index];
        return .{
            .path = n.path,
            .kind = n.kind,
            .mode = n.mode,
            .uid = n.uid,
            .gid = n.gid,
            .mtime = n.mtime,
            .size = if (n.kind == .file) n.bytes.len else n.target.len,
            .symlink_target = n.target,
        };
    }
    fn readFn(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        const n = ctx(context).nodes[index];
        const data = if (n.kind == .symlink) n.target else n.bytes;
        if (offset >= data.len) return 0;
        const n_bytes = @min(buffer.len, data.len - @as(usize, @intCast(offset)));
        @memcpy(buffer[0..n_bytes], data[@intCast(offset)..][0..n_bytes]);
        return n_bytes;
    }
};

/// Walks every directory extent in `reader`, inspecting each directory record's
/// System Use area for `CE` continuation references. Asserts that every
/// referenced continuation range stays within a single logical block, appends
/// the Rock Ridge `NM` name decoded from each continuation to `names` (each
/// entry owned by the caller), and returns the number of `CE` records found.
fn collectContinuationRefs(
    allocator: std.mem.Allocator,
    io: Io,
    reader: *const Reader,
    names: *std.array_list.Managed([]u8),
) !usize {
    const bs: u64 = reader.logical_block_size;
    var ce_count: usize = 0;
    for (reader.entries) |entry| {
        if (entry.kind != .directory) continue;
        for (entry.extents) |ext| {
            const dir_buf = try allocator.alloc(u8, ext.size);
            defer allocator.free(dir_buf);
            _ = try reader.file.readPositionalAll(io, dir_buf, @as(u64, ext.lba) * bs);

            var off: usize = 0;
            while (off < dir_buf.len) {
                const len = dir_buf[off];
                if (len == 0) {
                    off += @intCast(bs - (off % bs));
                    continue;
                }
                const rec = dir_buf[off .. off + len];
                const name_len = rec[32];
                const pad: usize = if (name_len % 2 == 0) 1 else 0;
                const su = rec[33 + name_len + pad ..];

                var p: usize = 0;
                while (p + 4 <= su.len) {
                    const elen = su[p + 2];
                    if (elen < 4 or p + elen > su.len) break;
                    if (su[p] == 'C' and su[p + 1] == 'E' and elen >= 28) {
                        const ce_lba = read733(su[p + 4 .. p + 12]);
                        const ce_off = read733(su[p + 12 .. p + 20]);
                        const ce_size = read733(su[p + 20 .. p + 28]);
                        ce_count += 1;

                        // The continuation range referenced by CE must lie
                        // entirely within one logical block.
                        try std.testing.expect(ce_off < bs);
                        try std.testing.expect(@as(u64, ce_off) + ce_size <= bs);

                        const cont = try allocator.alloc(u8, ce_size);
                        defer allocator.free(cont);
                        _ = try reader.file.readPositionalAll(io, cont, @as(u64, ce_lba) * bs + ce_off);

                        var q: usize = 0;
                        while (q + 4 <= cont.len) {
                            const clen = cont[q + 2];
                            if (clen < 4 or q + clen > cont.len) break;
                            if (cont[q] == 'N' and cont[q + 1] == 'M' and clen >= 5) {
                                try names.append(try allocator.dupe(u8, cont[q + 5 .. q + clen]));
                            }
                            q += clen;
                        }
                    }
                    p += elen;
                }
                off += len;
            }
        }
    }
    return ce_count;
}

test "iso writer spills a ~200-character name into a CE continuation and round-trips" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-ce-longname.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // A regular filename long enough that PX + NM overflow a 255-byte directory
    // record and must spill into a CE continuation. Before the fix, computing
    // the record length in a u8 panicked here.
    var name_buf: [200]u8 = undefined;
    for (&name_buf, 0..) |*c, i| c.* = 'a' + @as(u8, @intCast(i % 26));
    const long_name = &name_buf;

    const nodes = [_]TestNode{
        .{ .path = long_name, .kind = .file, .mode = 0o644, .uid = 7, .gid = 8, .bytes = "long name payload\n" },
    };
    const ts = TestSource{ .nodes = &nodes };

    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    try std.testing.expect(reader.has_rock_ridge);

    // The name round-trips through the CE continuation.
    const lookup_path = try std.fmt.allocPrint(allocator, "/{s}", .{long_name});
    defer allocator.free(lookup_path);
    const idx = try reader.lookup(lookup_path);
    const entry = reader.getEntry(idx);
    try std.testing.expectEqual(@as(u32, 7), entry.uid);
    try std.testing.expectEqual(@as(u32, 8), entry.gid);
    const bytes = try reader.readFileAlloc(allocator, io, idx);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("long name payload\n", bytes);

    // The record actually exercised a CE continuation, and that continuation
    // stays within one logical block.
    var names = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (names.items) |n| allocator.free(n);
        names.deinit();
    }
    const ce_count = try collectContinuationRefs(allocator, io, &reader, &names);
    try std.testing.expect(ce_count >= 1);

    var found = false;
    for (names.items) |n| {
        if (std.mem.eql(u8, n, long_name)) found = true;
    }
    try std.testing.expect(found);
}

test "iso writer keeps many long-name CE continuations within one logical block" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-ce-manylong.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Enough long-named files that the accumulated continuation area spans
    // several logical blocks; without boundary padding, some CE payloads would
    // straddle a 2048-byte block.
    const count = 40;
    var name_bufs = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (name_bufs.items) |nb| allocator.free(nb);
        name_bufs.deinit();
    }
    var nodes = std.array_list.Managed(TestNode).init(allocator);
    defer nodes.deinit();

    var i: usize = 0;
    while (i < count) : (i += 1) {
        // ~200-character unique names (each forces a CE continuation).
        var nb = try allocator.alloc(u8, 200);
        for (nb, 0..) |*c, j| c.* = 'a' + @as(u8, @intCast((i + j) % 26));
        const tag = try std.fmt.allocPrint(allocator, "{d:0>3}", .{i});
        defer allocator.free(tag);
        @memcpy(nb[0..3], tag);
        try name_bufs.append(nb);
        try nodes.append(.{ .path = nb, .kind = .file, .mode = 0o644, .bytes = "x" });
    }
    const ts = TestSource{ .nodes = nodes.items };

    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    try std.testing.expect(reader.has_rock_ridge);

    // Every file round-trips by its full Rock Ridge name.
    for (name_bufs.items) |nb| {
        const p = try std.fmt.allocPrint(allocator, "/{s}", .{nb});
        defer allocator.free(p);
        const idx = try reader.lookup(p);
        const got = try reader.readFileAlloc(allocator, io, idx);
        defer allocator.free(got);
        try std.testing.expectEqualStrings("x", got);
    }

    // Parse the emitted CE references and prove each referenced continuation
    // range stays within one logical block; every long name is recovered from
    // its continuation.
    var names = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (names.items) |n| allocator.free(n);
        names.deinit();
    }
    const ce_count = try collectContinuationRefs(allocator, io, &reader, &names);
    try std.testing.expectEqual(@as(usize, count), ce_count);

    for (name_bufs.items) |nb| {
        var found = false;
        for (names.items) |n| {
            if (std.mem.eql(u8, n, nb)) found = true;
        }
        try std.testing.expect(found);
    }
}

test "iso writer round-trips nested rock ridge tree with metadata and symlinks" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-rr.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const long_name = "a-Very-Long-Mixed-Case-Directory-Name-For-Rock-Ridge-Round-Tripping";
    const nodes = [_]TestNode{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .uid = 5, .gid = 6, .bytes = "NAME=zvmi\n" },
        .{ .path = "etc/alias", .kind = .symlink, .mode = 0o777, .target = "os-release" },
        .{ .path = long_name, .kind = .directory, .mode = 0o750, .uid = 1, .gid = 2 },
        .{ .path = long_name ++ "/Readme.TXT", .kind = .file, .mode = 0o600, .bytes = "mixed case file\n" },
    };
    const ts = TestSource{ .nodes = &nodes };

    _ = try writeImagePath(allocator, io, path, ts.source(), .{ .volume_id = "ZVMI_TEST" });

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try std.testing.expect(reader.has_rock_ridge);

    const file_index = try reader.lookup("/etc/os-release");
    const entry = reader.getEntry(file_index);
    try std.testing.expectEqual(@as(u32, 5), entry.uid);
    try std.testing.expectEqual(@as(u32, 6), entry.gid);
    try std.testing.expectEqual(@as(u32, 0o100644), entry.mode);
    const bytes = try reader.readFileAlloc(allocator, io, file_index);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("NAME=zvmi\n", bytes);

    const link_index = try reader.lookup("/etc/alias");
    try std.testing.expectEqual(EntryKind.symlink, reader.getEntry(link_index).kind);
    try std.testing.expectEqualStrings("os-release", try reader.readLink(link_index));
    try std.testing.expectEqual(file_index, try reader.resolveSymlink(link_index));

    const long_dir_index = try reader.lookup("/" ++ long_name);
    try std.testing.expectEqual(EntryKind.directory, reader.getEntry(long_dir_index).kind);
    try std.testing.expectEqual(@as(u32, 1), reader.getEntry(long_dir_index).uid);
    const long_file_index = try reader.lookup("/" ++ long_name ++ "/Readme.TXT");
    const long_bytes = try reader.readFileAlloc(allocator, io, long_file_index);
    defer allocator.free(long_bytes);
    try std.testing.expectEqualStrings("mixed case file\n", long_bytes);
}

test "iso writer handles multi-sector files and directories crossing sector boundaries" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-multisector.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // A file spanning several logical sectors.
    const big = try allocator.alloc(u8, 5000);
    defer allocator.free(big);
    for (big, 0..) |*b, i| b.* = @intCast(i % 251);

    // Enough children that the root directory extent crosses a 2048-byte
    // boundary (each Rock Ridge record is ~90-120 bytes).
    var name_bufs = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (name_bufs.items) |nb| allocator.free(nb);
        name_bufs.deinit();
    }
    var nodes = std.array_list.Managed(TestNode).init(allocator);
    defer nodes.deinit();
    try nodes.append(.{ .path = "bigfile.bin", .kind = .file, .mode = 0o644, .bytes = big });
    var i: usize = 0;
    while (i < 60) : (i += 1) {
        const nb = try std.fmt.allocPrint(allocator, "file-entry-number-{d:0>3}.txt", .{i});
        try name_bufs.append(nb);
        try nodes.append(.{ .path = nb, .kind = .file, .mode = 0o644, .bytes = "x" });
    }
    const ts = TestSource{ .nodes = nodes.items };

    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    const idx = try reader.lookup("/bigfile.bin");
    const got = try reader.readFileAlloc(allocator, io, idx);
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, big, got);

    const listing = try reader.listDirAlloc(allocator, reader.root_index);
    defer allocator.free(listing);
    try std.testing.expectEqual(@as(usize, 61), listing.len);

    const last = try reader.lookup("/file-entry-number-059.txt");
    const last_bytes = try reader.readFileAlloc(allocator, io, last);
    defer allocator.free(last_bytes);
    try std.testing.expectEqualStrings("x", last_bytes);
}

test "iso writer output is deterministic" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path_a = "test-iso-writer-det-a.iso";
    const path_b = "test-iso-writer-det-b.iso";
    defer Io.Dir.cwd().deleteFile(io, path_a) catch {};
    defer Io.Dir.cwd().deleteFile(io, path_b) catch {};

    const nodes = [_]TestNode{
        .{ .path = "boot", .kind = .directory, .mode = 0o755 },
        .{ .path = "boot/grub.cfg", .kind = .file, .mode = 0o644, .bytes = "set timeout=0\n" },
        .{ .path = "readme", .kind = .file, .mode = 0o644, .bytes = "hello\n" },
    };
    const ts = TestSource{ .nodes = &nodes };

    _ = try writeImagePath(allocator, io, path_a, ts.source(), .{ .volume_id = "DET" });
    _ = try writeImagePath(allocator, io, path_b, ts.source(), .{ .volume_id = "DET" });

    const a = try Io.Dir.cwd().readFileAlloc(io, path_a, allocator, .unlimited);
    defer allocator.free(a);
    const b = try Io.Dir.cwd().readFileAlloc(io, path_b, allocator, .unlimited);
    defer allocator.free(b);
    try std.testing.expectEqualSlices(u8, a, b);
}

test "iso writer sets configurable volume identifier" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-volid.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "f", .kind = .file, .mode = 0o644, .bytes = "x" },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{ .volume_id = "MYVOL123" });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var pvd: [descriptor_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &pvd, volume_descriptor_lba * descriptor_size);
    try std.testing.expectEqualStrings("MYVOL123", pvd[40..48]);
    try std.testing.expectEqual(@as(u8, ' '), pvd[48]);
}

fn expectBootEntry(entry: BootCatalogEntry, platform: u8, media: u8) !void {
    try std.testing.expectEqual(platform, entry.platform);
    try std.testing.expectEqual(media, entry.media_type);
    try std.testing.expect(entry.bootable);
    try std.testing.expect(entry.image_lba != 0);
}

test "iso writer emits BIOS-only el torito catalog" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-bios.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "boot", .kind = .directory, .mode = 0o755 },
        .{ .path = "boot/isolinux.bin", .kind = .file, .mode = 0o644, .bytes = "BIOSBOOT" ** 100 },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .bios, .image_path = "boot/isolinux.bin", .load_sectors = 4 },
        },
    });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(boot_platform_bios, catalog.validation_platform);
    try std.testing.expectEqual(@as(usize, 1), catalog.entries.len);
    try expectBootEntry(catalog.entries[0], boot_platform_bios, 0);
    try std.testing.expectEqual(@as(u16, 4), catalog.entries[0].load_sectors);

    // The referenced boot image LBA must hold the boot image bytes.
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    const idx = try reader.lookup("/boot/isolinux.bin");
    try std.testing.expectEqual(reader.getEntry(idx).extents[0].lba, catalog.entries[0].image_lba);
}

test "iso writer emits UEFI-only el torito catalog" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-uefi.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "EFI", .kind = .directory, .mode = 0o755 },
        .{ .path = "EFI/BOOT", .kind = .directory, .mode = 0o755 },
        .{ .path = "EFI/BOOT/bootx64.efi", .kind = .file, .mode = 0o644, .bytes = "EFIBOOT!" ** 300 },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .uefi, .image_path = "EFI/BOOT/bootx64.efi" },
        },
    });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(boot_platform_uefi, catalog.validation_platform);
    try std.testing.expectEqual(@as(usize, 1), catalog.entries.len);
    try expectBootEntry(catalog.entries[0], boot_platform_uefi, 0);
}

test "iso writer emits dual BIOS and UEFI el torito catalog" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-dual.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "boot", .kind = .directory, .mode = 0o755 },
        .{ .path = "boot/bios.img", .kind = .file, .mode = 0o644, .bytes = "BIOS" ** 200 },
        .{ .path = "EFI", .kind = .directory, .mode = 0o755 },
        .{ .path = "EFI/efiboot.img", .kind = .file, .mode = 0o644, .bytes = "UEFI" ** 200 },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .bios, .image_path = "boot/bios.img" },
            .{ .platform = .uefi, .image_path = "EFI/efiboot.img" },
        },
    });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(boot_platform_bios, catalog.validation_platform);
    try std.testing.expectEqual(@as(usize, 2), catalog.entries.len);
    try expectBootEntry(catalog.entries[0], boot_platform_bios, 0);
    try expectBootEntry(catalog.entries[1], boot_platform_uefi, 0);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    const bios_idx = try reader.lookup("/boot/bios.img");
    const uefi_idx = try reader.lookup("/EFI/efiboot.img");
    try std.testing.expectEqual(reader.getEntry(bios_idx).extents[0].lba, catalog.entries[0].image_lba);
    try std.testing.expectEqual(reader.getEntry(uefi_idx).extents[0].lba, catalog.entries[1].image_lba);
}

test "iso writer reports no boot record for a plain image" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-noboot.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{.{ .path = "f", .kind = .file, .mode = 0o644, .bytes = "x" }};
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    try std.testing.expectError(error.NoBootRecord, readBootCatalog(allocator, io, file));
}

test "iso writer rejects a missing boot image" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-badboot.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{.{ .path = "f", .kind = .file, .mode = 0o644, .bytes = "x" }};
    const ts = TestSource{ .nodes = &nodes };
    try std.testing.expectError(error.BootImageNotFound, writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{.{ .platform = .bios, .image_path = "does/not/exist" }},
    }));
}
