//! ISO9660 (ECMA-119) **read-only** reader with enough Rock Ridge (RRIP)
//! and Joliet support to enumerate directory trees, read file extents, and
//! resolve symbolic links without shelling out to external tooling.
//!
//! Scope / limitations:
//!  - Read-only only; image creation/writing is out of scope.
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

fn recordLength(name_len: usize, system_use_len: usize) u8 {
    const pad: usize = if (name_len % 2 == 0) 1 else 0;
    return @intCast(33 + name_len + pad + system_use_len);
}

fn makeDirectoryRecord(name: []const u8, extent_lba: u32, size: u32, flags: u8, system_use: []const u8) [256]u8 {
    var out: [256]u8 = @as([256]u8, @splat(0));
    const len = recordLength(name.len, system_use.len);
    out[0] = len;
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
    var out: [36]u8 = @as([36]u8, @splat(0));
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
    var out: [260]u8 = @as([260]u8, @splat(0));
    out[0] = 'N';
    out[1] = 'M';
    out[2] = @intCast(5 + name.len);
    out[3] = 1;
    out[4] = 0;
    @memcpy(out[5 .. 5 + name.len], name);
    return out;
}

fn buildSlSystemUse(target: []const u8) [260]u8 {
    var out: [260]u8 = @as([260]u8, @splat(0));
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
    const susp_prefix = @as([7]u8, @splat(0));

    var image = std.array_list.Managed(u8).init(allocator);
    defer image.deinit();
    try image.resize((file_lba + 1) * descriptor_size);
    @memset(image.items, 0);

    var pvd: [descriptor_size]u8 = @as([descriptor_size]u8, @splat(0));
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

    var terminator: [descriptor_size]u8 = @as([descriptor_size]u8, @splat(0));
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

    var pvd: [descriptor_size]u8 = @as([descriptor_size]u8, @splat(0));
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

    var svd: [descriptor_size]u8 = @as([descriptor_size]u8, @splat(0));
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

    var terminator: [descriptor_size]u8 = @as([descriptor_size]u8, @splat(0));
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
