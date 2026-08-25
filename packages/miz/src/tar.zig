//! Minimal USTAR reader/writer shared by OCI layer ingestion and COSI packaging.

const std = @import("std");
const Io = std.Io;

pub const block_size: usize = 512;

pub const Kind = enum {
    file,
    directory,
    symlink,
    hardlink,
    character_device,
    block_device,
    fifo,
};

pub const Xattr = struct {
    name: []const u8,
    value: []const u8,
};

pub const Timestamp = struct {
    seconds: i64 = 0,
    nanoseconds: u32 = 0,
};

pub const Entry = struct {
    path: []const u8,
    kind: Kind,
    mode: u32,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: Timestamp = .{},
    size: u64,
    content: []const u8,
    link_name: ?[]const u8 = null,
    device_major: u32 = 0,
    device_minor: u32 = 0,
    xattrs: []const Xattr = &.{},
};

const max_pax_xattrs_per_entry = 256;
const max_pax_xattr_bytes_per_entry = 1024 * 1024;

pub const Error = std.Io.Writer.Error || error{
    InvalidHeader,
    InvalidOctal,
    InvalidPaxRecord,
    TruncatedArchive,
    UnsupportedType,
    ArchiveTooLarge,
    EntryStillOpen,
    EntryNotOpen,
    SizeMismatch,
    PathTooLong,
    ValueTooLarge,
    PaxXattrLimitExceeded,
    InvalidChecksum,
    InvalidTimestamp,
    EntryTooLarge,
    TooManyEntries,
    ArchiveByteLimitExceeded,
    PaxRecordLimitExceeded,
    DuplicatePath,
} || std.mem.Allocator.Error || Io.Reader.Error || Io.File.ReadPositionalError || Io.File.StatError;

pub const Reader = struct {
    data: []const u8,
    offset: usize = 0,
    pending_pax_path: ?[]const u8 = null,
    pending_pax_link_path: ?[]const u8 = null,
    pending_pax_uid: ?u32 = null,
    pending_pax_gid: ?u32 = null,
    pending_pax_xattrs: [max_pax_xattrs_per_entry]Xattr = undefined,
    pending_pax_xattr_count: usize = 0,
    pending_pax_xattr_bytes: usize = 0,
    path_buffer: [256]u8 = undefined,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn next(self: *Reader) Error!?Entry {
        while (true) {
            if (self.offset == self.data.len) return null;
            if (self.offset + block_size > self.data.len) return error.TruncatedArchive;

            const header = self.data[self.offset .. self.offset + block_size];
            self.offset += block_size;

            if (isZeroBlock(header)) {
                self.clearPendingPax();
                return null;
            }

            const size = try parseOctal(trimField(header[124..136]));
            const next_offset = self.offset + alignBlock(size);
            if (next_offset > self.data.len) return error.TruncatedArchive;

            const typeflag: u8 = header[156];
            const content = self.data[self.offset .. self.offset + size];
            self.offset = next_offset;

            switch (typeflag) {
                0, '0', '1', '2', '5' => {
                    const entry = try self.parseEntry(header, typeflag, content, size);
                    self.clearPendingPax();
                    return entry;
                },
                'x', 'g' => {
                    try self.parsePax(content, typeflag == 'x');
                    continue;
                },
                else => return error.UnsupportedType,
            }
        }
    }

    fn parseEntry(self: *Reader, header: []const u8, typeflag: u8, content: []const u8, size: usize) Error!Entry {
        const raw_name = trimField(header[0..100]);
        const prefix = trimField(header[345..500]);
        const raw_path = if (self.pending_pax_path) |path|
            path
        else if (prefix.len == 0)
            raw_name
        else blk: {
            if (prefix.len + 1 + raw_name.len > self.path_buffer.len) return error.InvalidHeader;
            @memcpy(self.path_buffer[0..prefix.len], prefix);
            self.path_buffer[prefix.len] = '/';
            @memcpy(self.path_buffer[prefix.len + 1 ..][0..raw_name.len], raw_name);
            break :blk self.path_buffer[0 .. prefix.len + 1 + raw_name.len];
        };

        if (raw_path.len == 0) return error.InvalidHeader;

        const mode: u32 = @intCast(try parseOctal(trimField(header[100..108])));
        const header_uid = std.math.cast(u32, try parseOctal(trimField(header[108..116]))) orelse return error.InvalidOctal;
        const header_gid = std.math.cast(u32, try parseOctal(trimField(header[116..124]))) orelse return error.InvalidOctal;
        const link_name = if (self.pending_pax_link_path) |path| path else blk: {
            const trimmed = trimField(header[157..257]);
            break :blk if (trimmed.len == 0) null else trimmed;
        };

        return .{
            .path = raw_path,
            .kind = switch (typeflag) {
                0, '0' => .file,
                '1' => .hardlink,
                '2' => .symlink,
                '5' => .directory,
                else => unreachable,
            },
            .mode = mode,
            .uid = self.pending_pax_uid orelse header_uid,
            .gid = self.pending_pax_gid orelse header_gid,
            .size = size,
            .content = content,
            .link_name = link_name,
            .xattrs = self.pending_pax_xattrs[0..self.pending_pax_xattr_count],
        };
    }

    fn parsePax(self: *Reader, content: []const u8, local_only: bool) Error!void {
        var cursor: usize = 0;
        while (cursor < content.len) {
            const len_end = std.mem.indexOfScalarPos(u8, content, cursor, ' ') orelse return error.InvalidPaxRecord;
            const record_len = std.fmt.parseInt(usize, content[cursor..len_end], 10) catch return error.InvalidPaxRecord;
            if (record_len == 0 or record_len > content.len - cursor) return error.InvalidPaxRecord;

            const record = content[cursor .. cursor + record_len];
            if (record[record.len - 1] != '\n') return error.InvalidPaxRecord;

            const kv = record[(len_end - cursor + 1) .. record.len - 1];
            const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return error.InvalidPaxRecord;
            const key = kv[0..eq];
            const value = kv[eq + 1 ..];

            if (local_only) {
                if (std.mem.eql(u8, key, "path")) {
                    self.pending_pax_path = value;
                } else if (std.mem.eql(u8, key, "linkpath")) {
                    self.pending_pax_link_path = value;
                } else if (std.mem.eql(u8, key, "uid")) {
                    self.pending_pax_uid = std.fmt.parseInt(u32, value, 10) catch return error.InvalidPaxRecord;
                } else if (std.mem.eql(u8, key, "gid")) {
                    self.pending_pax_gid = std.fmt.parseInt(u32, value, 10) catch return error.InvalidPaxRecord;
                } else if (paxXattrName(key)) |name| {
                    try self.appendPaxXattr(name, value);
                }
            }

            cursor += record_len;
        }
    }

    fn clearPendingPax(self: *Reader) void {
        self.pending_pax_path = null;
        self.pending_pax_link_path = null;
        self.pending_pax_uid = null;
        self.pending_pax_gid = null;
        self.pending_pax_xattr_count = 0;
        self.pending_pax_xattr_bytes = 0;
    }

    fn appendPaxXattr(self: *Reader, name: []const u8, value: []const u8) Error!void {
        if (!isRelevantXattrName(name)) return;
        if (self.pending_pax_xattr_count == max_pax_xattrs_per_entry) return error.PaxXattrLimitExceeded;
        const bytes = std.math.add(usize, name.len, value.len) catch return error.PaxXattrLimitExceeded;
        const total = std.math.add(usize, self.pending_pax_xattr_bytes, bytes) catch return error.PaxXattrLimitExceeded;
        if (total > max_pax_xattr_bytes_per_entry) return error.PaxXattrLimitExceeded;
        self.pending_pax_xattrs[self.pending_pax_xattr_count] = .{ .name = name, .value = value };
        self.pending_pax_xattr_count += 1;
        self.pending_pax_xattr_bytes = total;
    }
};

fn paxXattrName(key: []const u8) ?[]const u8 {
    inline for (.{
        "SCHILY.xattr.",
        "LIBARCHIVE.xattr.",
    }) |prefix| {
        if (std.mem.startsWith(u8, key, prefix)) return key[prefix.len..];
    }
    return null;
}

fn isRelevantXattrName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255) return false;
    inline for (.{
        "user.",
        "trusted.",
        "security.",
        "system.",
    }) |prefix| {
        if (std.mem.startsWith(u8, name, prefix)) return name.len > prefix.len;
    }
    return false;
}

pub const OwnedArchive = struct {
    bytes: []u8,

    pub fn deinit(self: *OwnedArchive, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn reader(self: OwnedArchive) Reader {
        return Reader.init(self.bytes);
    }
};

pub fn readFile(io: Io, allocator: std.mem.Allocator, file: Io.File, max_size: usize) Error!OwnedArchive {
    const stat = try file.stat(io);
    if (stat.size > max_size) return error.ArchiveTooLarge;
    const bytes = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(bytes);
    _ = try file.readPositionalAll(io, bytes, 0);
    return .{ .bytes = bytes };
}

pub const StreamLimits = struct {
    max_archive_bytes: u64 = 64 * 1024 * 1024 * 1024,
    max_entry_size: u64 = 8 * 1024 * 1024 * 1024,
    max_entries: usize = 1_000_000,
    max_path_bytes: usize = Io.Dir.max_path_bytes,
    max_pax_bytes: usize = max_pax_xattr_bytes_per_entry + 64 * 1024,
    max_pax_records: usize = 512,
};

pub const StreamEntry = struct {
    path: []const u8,
    kind: Kind,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: Timestamp,
    size: u64,
    link_name: ?[]const u8,
    device_major: u32,
    device_minor: u32,
    xattrs: []const Xattr,
};

/// Bounded streaming tar reader. Entry metadata remains valid until the next
/// call to `next`; file content is consumed through `readEntry` or
/// `streamEntry`.
pub const StreamReader = struct {
    allocator: std.mem.Allocator,
    input: *Io.Reader,
    limits: StreamLimits,
    global_arena: std.heap.ArenaAllocator,
    entry_arena: std.heap.ArenaAllocator,
    global_pax: std.StringHashMap([]const u8),
    entry_pax: std.StringHashMap([]const u8),
    seen_paths: std.StringHashMap(void),
    remaining: u64 = 0,
    padding: usize = 0,
    archive_bytes: u64 = 0,
    entry_count: usize = 0,
    global_pax_bytes: usize = 0,
    global_pax_records: usize = 0,
    entry_pax_bytes: usize = 0,
    entry_pax_records: usize = 0,
    header: [block_size]u8 = undefined,

    pub fn init(
        allocator: std.mem.Allocator,
        input: *Io.Reader,
        limits: StreamLimits,
    ) StreamReader {
        const global_arena = std.heap.ArenaAllocator.init(allocator);
        const entry_arena = std.heap.ArenaAllocator.init(allocator);
        return .{
            .allocator = allocator,
            .input = input,
            .limits = limits,
            .global_arena = global_arena,
            .entry_arena = entry_arena,
            .global_pax = std.StringHashMap([]const u8).init(allocator),
            .entry_pax = std.StringHashMap([]const u8).init(allocator),
            .seen_paths = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *StreamReader) void {
        var iterator = self.seen_paths.keyIterator();
        while (iterator.next()) |path| self.allocator.free(path.*);
        self.seen_paths.deinit();
        self.entry_pax.deinit();
        self.global_pax.deinit();
        self.entry_arena.deinit();
        self.global_arena.deinit();
        self.* = undefined;
    }

    pub fn next(self: *StreamReader) Error!?StreamEntry {
        try self.finishEntry();
        self.entry_pax.clearRetainingCapacity();
        _ = self.entry_arena.reset(.retain_capacity);
        self.entry_pax_bytes = 0;
        self.entry_pax_records = 0;

        while (true) {
            const count = try self.input.readSliceShort(&self.header);
            if (count == 0) return null;
            if (count != block_size) return error.TruncatedArchive;
            try self.addArchiveBytes(block_size);
            if (isZeroBlock(&self.header)) return null;
            try validateChecksum(&self.header);

            const header_size = try parseNumericU64(self.header[124..136]);
            const typeflag = self.header[156];
            if (typeflag == 'x' or typeflag == 'g') {
                try self.readPaxHeader(header_size, typeflag == 'g');
                continue;
            }

            const size = try self.paxUnsigned("size") orelse header_size;
            if (size > self.limits.max_entry_size) return error.EntryTooLarge;
            if (self.entry_count == self.limits.max_entries) return error.TooManyEntries;

            const path = try self.entryPath();
            if (path.len == 0 or path.len > self.limits.max_path_bytes or
                std.mem.indexOfScalar(u8, path, 0) != null)
            {
                return error.PathTooLong;
            }
            const owned_seen_path = try self.allocator.dupe(u8, path);
            const result = self.seen_paths.getOrPut(owned_seen_path) catch |err| {
                self.allocator.free(owned_seen_path);
                return err;
            };
            if (result.found_existing) {
                self.allocator.free(owned_seen_path);
                return error.DuplicatePath;
            }

            const link_name = try self.entryLinkName();
            if (link_name) |value| {
                if (value.len > self.limits.max_path_bytes or
                    std.mem.indexOfScalar(u8, value, 0) != null)
                {
                    return error.PathTooLong;
                }
            }
            const kind: Kind = switch (typeflag) {
                0, '0' => .file,
                '1' => .hardlink,
                '2' => .symlink,
                '3' => .character_device,
                '4' => .block_device,
                '5' => .directory,
                '6' => .fifo,
                else => return error.UnsupportedType,
            };
            const mode = std.math.cast(u32, try parseNumericU64(self.header[100..108])) orelse
                return error.InvalidOctal;
            const uid = std.math.cast(
                u32,
                try self.paxUnsigned("uid") orelse try parseNumericU64(self.header[108..116]),
            ) orelse return error.InvalidOctal;
            const gid = std.math.cast(
                u32,
                try self.paxUnsigned("gid") orelse try parseNumericU64(self.header[116..124]),
            ) orelse return error.InvalidOctal;
            const mtime: Timestamp = if (self.paxValue("mtime")) |value|
                try parsePaxTimestamp(value)
            else
                .{
                    .seconds = std.math.cast(
                        i64,
                        try parseNumericU64(self.header[136..148]),
                    ) orelse return error.InvalidTimestamp,
                };
            const device_major = std.math.cast(
                u32,
                try parseNumericU64(self.header[329..337]),
            ) orelse return error.InvalidOctal;
            const device_minor = std.math.cast(
                u32,
                try parseNumericU64(self.header[337..345]),
            ) orelse return error.InvalidOctal;

            self.entry_count += 1;
            self.remaining = size;
            self.padding = padLen(size);
            return .{
                .path = path,
                .kind = kind,
                .mode = mode,
                .uid = uid,
                .gid = gid,
                .mtime = mtime,
                .size = size,
                .link_name = link_name,
                .device_major = device_major,
                .device_minor = device_minor,
                .xattrs = try self.entryXattrs(),
            };
        }
    }

    pub fn readEntry(self: *StreamReader, buffer: []u8) Error!usize {
        if (self.remaining == 0 or buffer.len == 0) return 0;
        const limit: usize = @intCast(@min(self.remaining, buffer.len));
        const count = try self.input.readSliceShort(buffer[0..limit]);
        if (count == 0) return error.TruncatedArchive;
        self.remaining -= count;
        try self.addArchiveBytes(count);
        return count;
    }

    pub fn streamEntry(self: *StreamReader, writer: *Io.Writer) Error!void {
        const count = self.remaining;
        try self.reserveArchiveBytes(count);
        try self.input.streamExact64(writer, count);
        self.archive_bytes += count;
        self.remaining = 0;
    }

    pub fn finishEntry(self: *StreamReader) Error!void {
        if (self.remaining > 0) {
            try self.reserveArchiveBytes(self.remaining);
            self.input.discardAll64(self.remaining) catch return error.TruncatedArchive;
            self.archive_bytes += self.remaining;
            self.remaining = 0;
        }
        if (self.padding > 0) {
            try self.reserveArchiveBytes(self.padding);
            self.input.discardAll(self.padding) catch return error.TruncatedArchive;
            self.archive_bytes += self.padding;
            self.padding = 0;
        }
    }

    fn readPaxHeader(self: *StreamReader, size: u64, global: bool) Error!void {
        if (size > self.limits.max_pax_bytes or size > std.math.maxInt(usize)) {
            return error.ValueTooLarge;
        }
        const size_usize: usize = @intCast(size);
        const aggregate_bytes = if (global)
            &self.global_pax_bytes
        else
            &self.entry_pax_bytes;
        aggregate_bytes.* = std.math.add(
            usize,
            aggregate_bytes.*,
            size_usize,
        ) catch return error.ValueTooLarge;
        if (aggregate_bytes.* > self.limits.max_pax_bytes) {
            return error.ValueTooLarge;
        }
        const arena = if (global)
            self.global_arena.allocator()
        else
            self.entry_arena.allocator();
        const data = try arena.alloc(u8, size_usize);
        if (data.len > 0) {
            try self.reserveArchiveBytes(data.len);
            self.input.readSliceAll(data) catch return error.TruncatedArchive;
            self.archive_bytes += data.len;
        }
        const padding = padLen(size);
        if (padding > 0) {
            try self.reserveArchiveBytes(padding);
            self.input.discardAll(padding) catch return error.TruncatedArchive;
            self.archive_bytes += padding;
        }
        try parsePaxValues(
            if (global) &self.global_pax else &self.entry_pax,
            data,
            global,
            if (global) &self.global_pax_records else &self.entry_pax_records,
            self.limits.max_pax_records,
        );
    }

    fn entryPath(self: *StreamReader) Error![]const u8 {
        if (self.paxValue("path")) |path| return path;
        const name = trimField(self.header[0..100]);
        const prefix = trimField(self.header[345..500]);
        if (prefix.len == 0) return self.entry_arena.allocator().dupe(u8, name);
        return std.fmt.allocPrint(
            self.entry_arena.allocator(),
            "{s}/{s}",
            .{ prefix, name },
        );
    }

    fn entryLinkName(self: *StreamReader) Error!?[]const u8 {
        if (self.paxValue("linkpath")) |link_path| return link_path;
        const link_name = trimField(self.header[157..257]);
        if (link_name.len == 0) return null;
        const owned = try self.entry_arena.allocator().dupe(u8, link_name);
        return owned;
    }

    fn entryXattrs(self: *StreamReader) Error![]const Xattr {
        var xattrs = std.array_list.Managed(Xattr).init(self.entry_arena.allocator());
        var global_iterator = self.global_pax.iterator();
        while (global_iterator.next()) |item| {
            const name = paxXattrName(item.key_ptr.*) orelse continue;
            if (self.entry_pax.contains(item.key_ptr.*)) continue;
            if (!isRelevantXattrName(name)) continue;
            try xattrs.append(.{ .name = name, .value = item.value_ptr.* });
        }
        var entry_iterator = self.entry_pax.iterator();
        while (entry_iterator.next()) |item| {
            const name = paxXattrName(item.key_ptr.*) orelse continue;
            if (!isRelevantXattrName(name)) continue;
            try xattrs.append(.{ .name = name, .value = item.value_ptr.* });
        }
        std.mem.sort(Xattr, xattrs.items, {}, struct {
            fn lessThan(_: void, left: Xattr, right: Xattr) bool {
                return std.mem.lessThan(u8, left.name, right.name);
            }
        }.lessThan);
        return xattrs.toOwnedSlice();
    }

    fn paxUnsigned(self: *StreamReader, key: []const u8) Error!?u64 {
        const value = self.paxValue(key) orelse return null;
        return std.fmt.parseUnsigned(u64, value, 10) catch error.InvalidPaxRecord;
    }

    fn paxValue(self: *StreamReader, key: []const u8) ?[]const u8 {
        return self.entry_pax.get(key) orelse self.global_pax.get(key);
    }

    fn reserveArchiveBytes(self: *StreamReader, count: u64) Error!void {
        const total = std.math.add(u64, self.archive_bytes, count) catch
            return error.ArchiveByteLimitExceeded;
        if (total > self.limits.max_archive_bytes) {
            return error.ArchiveByteLimitExceeded;
        }
    }

    fn addArchiveBytes(self: *StreamReader, count: u64) Error!void {
        try self.reserveArchiveBytes(count);
        self.archive_bytes += count;
    }
};

fn parsePaxValues(
    values: *std.StringHashMap([]const u8),
    data: []const u8,
    global: bool,
    records: *usize,
    max_records: usize,
) Error!void {
    var cursor: usize = 0;
    while (cursor < data.len) {
        if (records.* == max_records) return error.PaxRecordLimitExceeded;
        const length_end = std.mem.indexOfScalarPos(u8, data, cursor, ' ') orelse
            return error.InvalidPaxRecord;
        const record_length = std.fmt.parseUnsigned(
            usize,
            data[cursor..length_end],
            10,
        ) catch return error.InvalidPaxRecord;
        if (record_length == 0 or record_length > data.len - cursor) {
            return error.InvalidPaxRecord;
        }
        const record = data[cursor .. cursor + record_length];
        if (record[record.len - 1] != '\n') return error.InvalidPaxRecord;
        const payload = record[length_end - cursor + 1 .. record.len - 1];
        const equals = std.mem.indexOfScalar(u8, payload, '=') orelse
            return error.InvalidPaxRecord;
        const key = payload[0..equals];
        const value = payload[equals + 1 ..];
        if (key.len == 0 or std.mem.indexOfScalar(u8, key, 0) != null) {
            return error.InvalidPaxRecord;
        }
        if (global and value.len == 0) {
            _ = values.remove(key);
        } else {
            try values.put(key, value);
        }
        cursor += record_length;
        records.* += 1;
    }
}

fn parsePaxTimestamp(value: []const u8) Error!Timestamp {
    if (value.len == 0) return error.InvalidTimestamp;
    const negative = value[0] == '-';
    const dot = std.mem.indexOfScalar(u8, value, '.');
    const whole = if (dot) |index| value[0..index] else value;
    var seconds = std.fmt.parseInt(i64, whole, 10) catch return error.InvalidTimestamp;
    var nanoseconds: u32 = 0;
    if (dot) |index| {
        const fraction = value[index + 1 ..];
        if (fraction.len == 0) return error.InvalidTimestamp;
        var digits: usize = 0;
        while (digits < fraction.len and digits < 9) : (digits += 1) {
            const byte = fraction[digits];
            if (!std.ascii.isDigit(byte)) return error.InvalidTimestamp;
            nanoseconds = nanoseconds * 10 + byte - '0';
        }
        for (fraction[digits..]) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidTimestamp;
        }
        var padding = 9 - digits;
        while (padding > 0) : (padding -= 1) nanoseconds *= 10;
        if (negative and nanoseconds != 0) {
            if (seconds == std.math.minInt(i64)) return error.InvalidTimestamp;
            seconds -= 1;
            nanoseconds = 1_000_000_000 - nanoseconds;
        }
    }
    return .{ .seconds = seconds, .nanoseconds = nanoseconds };
}

fn parseNumericU64(field: []const u8) Error!u64 {
    if (field.len == 0) return error.InvalidOctal;
    if (field[0] & 0x80 != 0) {
        if (field[0] & 0x40 != 0) return error.InvalidOctal;
        var value: u64 = field[0] & 0x3f;
        for (field[1..]) |byte| {
            value = std.math.mul(u64, value, 256) catch return error.InvalidOctal;
            value = std.math.add(u64, value, byte) catch return error.InvalidOctal;
        }
        return value;
    }
    return parseOctal(std.mem.trim(u8, field, " \x00"));
}

fn validateChecksum(header: *const [block_size]u8) Error!void {
    const expected = try parseNumericU64(header[148..156]);
    var unsigned: u64 = 0;
    var signed: i64 = 0;
    for (header, 0..) |byte, index| {
        const value: u8 = if (index >= 148 and index < 156) ' ' else byte;
        unsigned += value;
        signed += @as(i8, @bitCast(value));
    }
    if (expected != unsigned and
        (signed < 0 or expected != @as(u64, @intCast(signed))))
    {
        return error.InvalidChecksum;
    }
}

pub const StreamingEntryWriter = struct {
    parent: *Writer,
    interface: std.Io.Writer,

    pub fn init(parent: *Writer, buffer: []u8) StreamingEntryWriter {
        return .{
            .parent = parent,
            .interface = .{
                .buffer = buffer,
                .vtable = &.{
                    .drain = drain,
                    .flush = flush,
                },
            },
        };
    }

    fn commit(self: *StreamingEntryWriter, bytes: []const u8) std.Io.Writer.Error!void {
        if (!self.parent.entry_open or bytes.len > self.parent.bytes_remaining) return error.WriteFailed;
        try self.parent.out.writeAll(bytes);
        self.parent.bytes_remaining -= bytes.len;
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *StreamingEntryWriter = @alignCast(@fieldParentPtr("interface", w));
        const buffered = w.buffered();
        if (buffered.len > 0) try self.commit(buffered);
        w.end = 0;

        var total: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            try self.commit(slice);
            total += slice.len;
        }
        const pattern = data[data.len - 1];
        for (0..splat) |_| {
            try self.commit(pattern);
            total += pattern.len;
        }
        return total;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *StreamingEntryWriter = @alignCast(@fieldParentPtr("interface", w));
        const buffered = w.buffered();
        if (buffered.len > 0) try self.commit(buffered);
        w.end = 0;
    }
};

pub const Writer = struct {
    out: *std.Io.Writer,
    bytes_remaining: u64 = 0,
    pad_bytes: usize = 0,
    entry_open: bool = false,
    entry_index: u64 = 0,

    pub fn init(out: *std.Io.Writer) Writer {
        return .{ .out = out };
    }

    pub fn beginFile(self: *Writer, path: []const u8, mode: u32, size: u64) Error!void {
        return self.beginEntry(.{
            .path = path,
            .kind = .file,
            .mode = mode,
            .size = size,
        });
    }

    pub fn beginEntry(self: *Writer, entry: WriteEntry) Error!void {
        if (self.entry_open) return error.EntryStillOpen;
        try validateWriteEntry(entry);

        const path_requires_pax = !pathFitsUstar(entry.path);
        const link_requires_pax = if (entry.link_name) |link_name|
            link_name.len > 100
        else
            false;
        var timestamp_buffer: [48]u8 = undefined;
        const timestamp_value = if (entry.mtime.nanoseconds != 0 or entry.mtime.seconds < 0)
            try formatPaxTimestamp(&timestamp_buffer, entry.mtime)
        else
            null;
        var pax_size: usize = 0;
        if (path_requires_pax) {
            pax_size = try addPaxRecordSize(pax_size, "path", entry.path);
        }
        if (link_requires_pax) {
            pax_size = try addPaxRecordSize(pax_size, "linkpath", entry.link_name.?);
        }
        if (timestamp_value) |value| {
            pax_size = try addPaxRecordSize(pax_size, "mtime", value);
        }
        for (entry.xattrs) |xattr| {
            if (!isRelevantXattrName(xattr.name)) return error.InvalidPaxRecord;
            var key_buffer: [270]u8 = undefined;
            const key = std.fmt.bufPrint(
                &key_buffer,
                "SCHILY.xattr.{s}",
                .{xattr.name},
            ) catch return error.ValueTooLarge;
            pax_size = try addPaxRecordSize(pax_size, key, xattr.value);
        }
        if (pax_size > 0) {
            try self.writePaxHeader(pax_size);
            if (path_requires_pax) try writePaxRecord(self.out, "path", entry.path);
            if (link_requires_pax) {
                try writePaxRecord(self.out, "linkpath", entry.link_name.?);
            }
            if (timestamp_value) |value| try writePaxRecord(self.out, "mtime", value);
            for (entry.xattrs) |xattr| {
                var key_buffer: [270]u8 = undefined;
                const key = std.fmt.bufPrint(
                    &key_buffer,
                    "SCHILY.xattr.{s}",
                    .{xattr.name},
                ) catch return error.ValueTooLarge;
                try writePaxRecord(self.out, key, xattr.value);
            }
            if (padLen(pax_size) > 0) {
                const zeros = [_]u8{0} ** block_size;
                try self.out.writeAll(zeros[0..padLen(pax_size)]);
            }
        }

        const header_path = if (path_requires_pax) "PaxPath" else entry.path;
        const header_link = if (link_requires_pax) null else entry.link_name;
        var header = try makeEntryHeader(entry, header_path, header_link);
        try self.out.writeAll(&header);
        self.bytes_remaining = entry.size;
        self.pad_bytes = padLen(entry.size);
        self.entry_open = true;
        self.entry_index += 1;
    }

    pub fn writeAll(self: *Writer, bytes: []const u8) Error!void {
        if (!self.entry_open) return error.EntryNotOpen;
        if (bytes.len > self.bytes_remaining) return error.SizeMismatch;
        try self.out.writeAll(bytes);
        self.bytes_remaining -= bytes.len;
    }

    pub fn endFile(self: *Writer) Error!void {
        return self.endEntry();
    }

    pub fn endEntry(self: *Writer) Error!void {
        if (!self.entry_open) return error.EntryNotOpen;
        if (self.bytes_remaining != 0) return error.SizeMismatch;

        if (self.pad_bytes > 0) {
            const zeros = [_]u8{0} ** block_size;
            try self.out.writeAll(zeros[0..self.pad_bytes]);
        }
        self.pad_bytes = 0;
        self.entry_open = false;
    }

    pub fn entryWriter(self: *Writer, buffer: []u8) StreamingEntryWriter {
        return StreamingEntryWriter.init(self, buffer);
    }

    pub fn writeFile(self: *Writer, path: []const u8, mode: u32, bytes: []const u8) Error!void {
        try self.beginFile(path, mode, bytes.len);
        try self.writeAll(bytes);
        try self.endFile();
    }

    pub fn writeEntry(self: *Writer, entry: WriteEntry) Error!void {
        if (entry.size != 0) return error.SizeMismatch;
        try self.beginEntry(entry);
        try self.endEntry();
    }

    pub fn finish(self: *Writer) Error!void {
        if (self.entry_open) return error.EntryStillOpen;
        const zeros = [_]u8{0} ** block_size;
        try self.out.writeAll(&zeros);
        try self.out.writeAll(&zeros);
        try self.out.flush();
    }

    fn writePaxHeader(self: *Writer, size: usize) Error!void {
        var path_buffer: [100]u8 = undefined;
        const path = std.fmt.bufPrint(
            &path_buffer,
            "PaxHeaders.miz/{d}",
            .{self.entry_index},
        ) catch return error.PathTooLong;
        var header = try makeRawHeader(.{
            .path = path,
            .mode = 0o600,
            .uid = 0,
            .gid = 0,
            .size = size,
            .mtime = 0,
            .typeflag = 'x',
        });
        try self.out.writeAll(&header);
    }
};

pub const WriteEntry = struct {
    path: []const u8,
    kind: Kind,
    mode: u32,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: Timestamp = .{},
    size: u64 = 0,
    link_name: ?[]const u8 = null,
    device_major: u32 = 0,
    device_minor: u32 = 0,
    xattrs: []const Xattr = &.{},
};

fn isZeroBlock(block: []const u8) bool {
    for (block) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn trimField(field: []const u8) []const u8 {
    const nul = std.mem.indexOfScalar(u8, field, 0) orelse field.len;
    var trimmed = field[0..nul];
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == ' ') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    return trimmed;
}

fn parseOctal(field: []const u8) Error!usize {
    if (field.len == 0) return 0;
    return std.fmt.parseInt(usize, field, 8) catch error.InvalidOctal;
}

fn alignBlock(size: usize) usize {
    return std.mem.alignForward(usize, size, block_size);
}

fn padLen(size: u64) usize {
    const rem: usize = @intCast(size % block_size);
    return if (rem == 0) 0 else block_size - rem;
}

const RawHeader = struct {
    path: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: u64,
    typeflag: u8,
    link_name: ?[]const u8 = null,
    device_major: u32 = 0,
    device_minor: u32 = 0,
};

fn makeEntryHeader(
    entry: WriteEntry,
    path: []const u8,
    link_name: ?[]const u8,
) Error![block_size]u8 {
    return makeRawHeader(.{
        .path = path,
        .mode = entry.mode,
        .uid = entry.uid,
        .gid = entry.gid,
        .size = entry.size,
        .mtime = if (entry.mtime.seconds < 0)
            0
        else
            @intCast(entry.mtime.seconds),
        .typeflag = switch (entry.kind) {
            .file => '0',
            .hardlink => '1',
            .symlink => '2',
            .character_device => '3',
            .block_device => '4',
            .directory => '5',
            .fifo => '6',
        },
        .link_name = link_name,
        .device_major = entry.device_major,
        .device_minor = entry.device_minor,
    });
}

fn makeRawHeader(raw: RawHeader) Error![block_size]u8 {
    var header: [block_size]u8 = [_]u8{0} ** block_size;

    splitPath(raw.path, header[0..100], header[345..500]) catch
        return error.PathTooLong;
    try writeNumeric(header[100..108], raw.mode);
    try writeNumeric(header[108..116], raw.uid);
    try writeNumeric(header[116..124], raw.gid);
    try writeNumeric(header[124..136], raw.size);
    try writeNumeric(header[136..148], raw.mtime);
    @memset(header[148..156], ' ');
    header[156] = raw.typeflag;
    if (raw.link_name) |link_name| {
        if (link_name.len > 100) return error.PathTooLong;
        @memcpy(header[157..][0..link_name.len], link_name);
    }
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");
    try writeNumeric(header[329..337], raw.device_major);
    try writeNumeric(header[337..345], raw.device_minor);

    const checksum = checksumForHeader(&header);
    writeChecksum(header[148..156], checksum);
    return header;
}

fn validateWriteEntry(entry: WriteEntry) Error!void {
    if (entry.path.len == 0 or std.mem.indexOfScalar(u8, entry.path, 0) != null) {
        return error.PathTooLong;
    }
    switch (entry.kind) {
        .file => if (entry.link_name != null) return error.InvalidHeader,
        .symlink, .hardlink => {
            const link_name = entry.link_name orelse return error.InvalidHeader;
            if (link_name.len == 0 or std.mem.indexOfScalar(u8, link_name, 0) != null) {
                return error.InvalidHeader;
            }
            if (entry.size != 0) return error.SizeMismatch;
        },
        .directory, .character_device, .block_device, .fifo => {
            if (entry.size != 0 or entry.link_name != null) return error.SizeMismatch;
        },
    }
    var previous: ?[]const u8 = null;
    for (entry.xattrs) |xattr| {
        if (!isRelevantXattrName(xattr.name)) return error.InvalidPaxRecord;
        if (previous) |name| {
            if (!std.mem.lessThan(u8, name, xattr.name)) return error.InvalidPaxRecord;
        }
        previous = xattr.name;
    }
}

fn pathFitsUstar(path: []const u8) bool {
    var name: [100]u8 = undefined;
    var prefix: [155]u8 = undefined;
    @memset(&name, 0);
    @memset(&prefix, 0);
    splitPath(path, &name, &prefix) catch return false;
    return true;
}

fn writeNumeric(field: []u8, value: u64) Error!void {
    writeOctal(field, value, true) catch |err| switch (err) {
        error.ValueTooLarge => {
            @memset(field, 0);
            var remaining = value;
            var index = field.len;
            while (index > 0 and remaining > 0) {
                index -= 1;
                field[index] = @truncate(remaining);
                remaining >>= 8;
            }
            if (remaining != 0 or field[0] & 0x40 != 0) return error.ValueTooLarge;
            field[0] |= 0x80;
        },
        else => return err,
    };
}

fn addPaxRecordSize(total: usize, key: []const u8, value: []const u8) Error!usize {
    return std.math.add(usize, total, paxRecordLength(key, value)) catch
        error.ValueTooLarge;
}

fn paxRecordLength(key: []const u8, value: []const u8) usize {
    const body_length = 1 + key.len + 1 + value.len + 1;
    var length = body_length + 1;
    while (true) {
        const next = body_length + decimalDigits(length);
        if (next == length) return length;
        length = next;
    }
}

fn decimalDigits(value: usize) usize {
    var remaining = value;
    var digits: usize = 1;
    while (remaining >= 10) : (digits += 1) remaining /= 10;
    return digits;
}

fn writePaxRecord(out: *Io.Writer, key: []const u8, value: []const u8) Error!void {
    const length = paxRecordLength(key, value);
    try out.print("{d} {s}=", .{ length, key });
    try out.writeAll(value);
    try out.writeByte('\n');
}

fn formatPaxTimestamp(buffer: []u8, timestamp: Timestamp) Error![]const u8 {
    if (timestamp.nanoseconds >= 1_000_000_000) return error.InvalidTimestamp;
    if (timestamp.nanoseconds == 0) {
        return std.fmt.bufPrint(buffer, "{d}", .{timestamp.seconds}) catch
            error.InvalidTimestamp;
    }
    if (timestamp.seconds >= 0) {
        return std.fmt.bufPrint(
            buffer,
            "{d}.{d:0>9}",
            .{ timestamp.seconds, timestamp.nanoseconds },
        ) catch error.InvalidTimestamp;
    }
    const whole = -(timestamp.seconds + 1);
    const fraction = 1_000_000_000 - timestamp.nanoseconds;
    return std.fmt.bufPrint(
        buffer,
        "-{d}.{d:0>9}",
        .{ whole, fraction },
    ) catch error.InvalidTimestamp;
}

fn checksumForHeader(header: *const [block_size]u8) u32 {
    var sum: u32 = 0;
    for (header) |byte| sum += byte;
    return sum;
}

fn splitPath(path: []const u8, name_field: []u8, prefix_field: []u8) error{PathTooLong}!void {
    if (path.len <= name_field.len) {
        @memcpy(name_field[0..path.len], path);
        return;
    }

    var split_at: ?usize = null;
    var i: usize = path.len;
    while (i > 0) : (i -= 1) {
        if (path[i - 1] != '/') continue;
        const prefix = path[0 .. i - 1];
        const name = path[i..];
        if (prefix.len <= prefix_field.len and name.len <= name_field.len) {
            split_at = i;
            break;
        }
    }

    const split = split_at orelse return error.PathTooLong;
    const prefix = path[0 .. split - 1];
    const name = path[split..];
    @memcpy(prefix_field[0..prefix.len], prefix);
    @memcpy(name_field[0..name.len], name);
}

fn writeOctal(field: []u8, value: u64, nul_terminated: bool) Error!void {
    @memset(field, 0);
    const digits_len: usize = if (nul_terminated) field.len - 1 else field.len;
    var digits = field[0..digits_len];
    @memset(digits, '0');

    var n = value;
    var idx = digits.len;
    while (idx > 0 and n > 0) {
        idx -= 1;
        digits[idx] = @as(u8, @intCast('0' + (n & 7)));
        n >>= 3;
    }
    if (n != 0) return error.ValueTooLarge;
}

fn writeChecksum(field: []u8, checksum: u32) void {
    @memset(field, 0);
    const digits = field[0 .. field.len - 2];
    @memset(digits, '0');

    var n: u64 = checksum;
    var idx = digits.len;
    while (idx > 0 and n > 0) {
        idx -= 1;
        digits[idx] = @as(u8, @intCast('0' + (n & 7)));
        n >>= 3;
    }
    field[field.len - 2] = 0;
    field[field.len - 1] = ' ';
}

const ReaderTarSpec = struct {
    path: []const u8,
    mode: u32,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: u64 = 0,
    device_major: u32 = 0,
    device_minor: u32 = 0,
    typeflag: u8,
    content: []const u8,
    link_name: ?[]const u8,
};

fn buildTar(allocator: std.mem.Allocator, specs: []const ReaderTarSpec) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, 2048);
    errdefer out.deinit();

    for (specs) |spec| {
        try appendTarEntry(&out, spec);
    }
    try out.writer.splatByteAll(0, 2 * block_size);
    return out.toOwnedSlice();
}

fn appendTarEntry(out: *std.Io.Writer.Allocating, spec: ReaderTarSpec) !void {
    var header: [block_size]u8 = [_]u8{0} ** block_size;
    if (spec.path.len > 100) return error.InvalidHeader;
    @memcpy(header[0..spec.path.len], spec.path);
    try writeOctalField(header[100..108], spec.mode);
    try writeOctalField(header[108..116], spec.uid);
    try writeOctalField(header[116..124], spec.gid);
    try writeOctalField(header[124..136], spec.content.len);
    try writeOctalField(header[136..148], spec.mtime);
    @memset(header[148..156], ' ');
    header[156] = spec.typeflag;
    if (spec.link_name) |link_name| {
        if (link_name.len > 100) return error.InvalidHeader;
        @memcpy(header[157..][0..link_name.len], link_name);
    }
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");
    try writeOctalField(header[329..337], spec.device_major);
    try writeOctalField(header[337..345], spec.device_minor);

    var checksum: u32 = 0;
    for (header) |byte| checksum += byte;
    try writeChecksumField(header[148..156], checksum);

    try out.writer.writeAll(&header);
    try out.writer.writeAll(spec.content);
    const padding = alignBlock(spec.content.len) - spec.content.len;
    if (padding > 0) try out.writer.splatByteAll(0, padding);
}

fn buildPaxRecord(allocator: std.mem.Allocator, key: []const u8, value: []const u8) ![]u8 {
    var record_len: usize = 0;
    while (true) {
        const record = try std.fmt.allocPrint(allocator, "{d} {s}={s}\n", .{ record_len, key, value });
        if (record.len == record_len) return record;
        record_len = record.len;
        allocator.free(record);
    }
}

fn writeOctalField(field: []u8, value: u64) !void {
    if (field.len == 0) return;
    @memset(field, 0);
    var buf: [32]u8 = undefined;
    const octal = try std.fmt.bufPrint(&buf, "{o}", .{value});
    if (octal.len + 1 > field.len) return error.InvalidHeader;
    const digits = field.len - 1;
    @memset(field[0..digits], '0');
    const start = digits - octal.len;
    @memcpy(field[start .. start + octal.len], octal);
}

fn writeChecksumField(field: []u8, value: u32) !void {
    @memset(field, ' ');
    var buf: [16]u8 = undefined;
    const octal = try std.fmt.bufPrint(&buf, "{o}", .{value});
    if (octal.len + 2 > field.len) return error.InvalidHeader;
    const start = field.len - octal.len - 2;
    @memcpy(field[start .. start + octal.len], octal);
    field[field.len - 2] = 0;
    field[field.len - 1] = ' ';
}

const TarEntry = struct {
    path: []const u8,
    payload: []const u8,
};

fn parseEntries(allocator: std.mem.Allocator, archive: []const u8) ![]TarEntry {
    var list = std.array_list.Managed(TarEntry).init(allocator);
    errdefer list.deinit();

    var offset: usize = 0;
    while (offset + block_size <= archive.len) {
        const header = archive[offset .. offset + block_size];
        offset += block_size;
        if (std.mem.allEqual(u8, header, 0)) break;

        const name = trimNul(header[0..100]);
        const prefix = trimNul(header[345..500]);
        const full_path = if (prefix.len == 0)
            try allocator.dupe(u8, name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, name });

        const size = try parseTarEntryOctal(trimNul(header[124..136]));
        const payload = archive[offset .. offset + size];
        try list.append(.{ .path = full_path, .payload = payload });
        offset += size + padLen(size);
    }

    return list.toOwnedSlice();
}

fn trimNul(field: []const u8) []const u8 {
    return std.mem.sliceTo(field, 0);
}

fn parseTarEntryOctal(text: []const u8) !usize {
    const trimmed = std.mem.trim(u8, text, " \x00");
    if (trimmed.len == 0) return 0;
    return std.fmt.parseInt(usize, trimmed, 8);
}

test "reader iterates regular tar entries" {
    const bytes = try buildTar(std.testing.allocator, &.{
        .{ .path = "alpha.txt", .mode = 0o644, .typeflag = '0', .content = "alpha", .link_name = null },
        .{ .path = "dir/", .mode = 0o755, .typeflag = '5', .content = "", .link_name = null },
        .{ .path = "dir/link", .mode = 0o777, .typeflag = '2', .content = "", .link_name = "../alpha.txt" },
    });
    defer std.testing.allocator.free(bytes);

    var reader = Reader.init(bytes);

    const first = (try reader.next()).?;
    try std.testing.expectEqualStrings("alpha.txt", first.path);
    try std.testing.expectEqual(Kind.file, first.kind);
    try std.testing.expectEqual(@as(u64, 5), first.size);
    try std.testing.expectEqualSlices(u8, "alpha", first.content);

    const second = (try reader.next()).?;
    try std.testing.expectEqualStrings("dir/", second.path);
    try std.testing.expectEqual(Kind.directory, second.kind);

    const third = (try reader.next()).?;
    try std.testing.expectEqualStrings("dir/link", third.path);
    try std.testing.expectEqual(Kind.symlink, third.kind);
    try std.testing.expectEqualStrings("../alpha.txt", third.link_name.?);

    try std.testing.expect((try reader.next()) == null);
}

test "reader honors pax path override" {
    const long_path = "very/long/path/component-that-exceeds-ustar-name-field/with/a/final-file.txt";
    const pax_record = try buildPaxRecord(std.testing.allocator, "path", long_path);
    defer std.testing.allocator.free(pax_record);

    const bytes = try buildTar(std.testing.allocator, &.{
        .{ .path = "PaxHeaders/path", .mode = 0o644, .typeflag = 'x', .content = pax_record, .link_name = null },
        .{ .path = "placeholder", .mode = 0o644, .typeflag = '0', .content = "payload", .link_name = null },
    });
    defer std.testing.allocator.free(bytes);

    var reader = Reader.init(bytes);
    const entry = (try reader.next()).?;
    try std.testing.expectEqualStrings(long_path, entry.path);
    try std.testing.expectEqualSlices(u8, "payload", entry.content);
    try std.testing.expect((try reader.next()) == null);
}

test "reader preserves USTAR ownership and bounded relevant PAX xattrs" {
    const allocator = std.testing.allocator;
    const uid = try buildPaxRecord(allocator, "uid", "4242");
    defer allocator.free(uid);
    const gid = try buildPaxRecord(allocator, "gid", "4343");
    defer allocator.free(gid);
    const capability = try buildPaxRecord(allocator, "SCHILY.xattr.security.capability", "cap-bytes");
    defer allocator.free(capability);
    const ignored = try buildPaxRecord(allocator, "SCHILY.xattr.invalid.namespace", "ignored");
    defer allocator.free(ignored);
    const pax = try std.fmt.allocPrint(allocator, "{s}{s}{s}{s}", .{ uid, gid, capability, ignored });
    defer allocator.free(pax);

    const bytes = try buildTar(allocator, &.{
        .{ .path = "PaxHeaders/meta", .mode = 0o644, .typeflag = 'x', .content = pax, .link_name = null },
        .{ .path = "owned", .mode = 0o640, .uid = 1, .gid = 2, .typeflag = '0', .content = "payload", .link_name = null },
    });
    defer allocator.free(bytes);

    var reader = Reader.init(bytes);
    const entry = (try reader.next()).?;
    try std.testing.expectEqualStrings("owned", entry.path);
    try std.testing.expectEqual(@as(u32, 4242), entry.uid);
    try std.testing.expectEqual(@as(u32, 4343), entry.gid);
    try std.testing.expectEqual(@as(usize, 1), entry.xattrs.len);
    try std.testing.expectEqualStrings("security.capability", entry.xattrs[0].name);
    try std.testing.expectEqualStrings("cap-bytes", entry.xattrs[0].value);
}

test "reader rejects PAX xattrs beyond the per-entry bound" {
    const allocator = std.testing.allocator;
    var pax = std.Io.Writer.Allocating.init(allocator);
    defer pax.deinit();
    for (0..max_pax_xattrs_per_entry + 1) |index| {
        const value = try std.fmt.allocPrint(allocator, "{d}", .{index});
        defer allocator.free(value);
        const record = try buildPaxRecord(allocator, "SCHILY.xattr.user.bound", value);
        defer allocator.free(record);
        try pax.writer.writeAll(record);
    }
    const bytes = try buildTar(allocator, &.{
        .{ .path = "PaxHeaders/overflow", .mode = 0o644, .typeflag = 'x', .content = pax.written(), .link_name = null },
        .{ .path = "overflow", .mode = 0o644, .typeflag = '0', .content = "payload", .link_name = null },
    });
    defer allocator.free(bytes);

    var reader = Reader.init(bytes);
    try std.testing.expectError(error.PaxXattrLimitExceeded, reader.next());
}

test "reader rejects overflowing PAX record lengths without panicking" {
    const allocator = std.testing.allocator;
    const bytes = try buildTar(allocator, &.{
        .{
            .path = "PaxHeaders/overflow",
            .mode = 0o644,
            .typeflag = 'x',
            .content = "18446744073709551615 path=overflow\n",
            .link_name = null,
        },
        .{ .path = "placeholder", .mode = 0o644, .typeflag = '0', .content = "payload", .link_name = null },
    });
    defer allocator.free(bytes);

    var reader = Reader.init(bytes);
    try std.testing.expectError(error.InvalidPaxRecord, reader.next());
}

test "stream reader preserves PAX precedence metadata and special files" {
    const allocator = std.testing.allocator;
    const global_uid = try buildPaxRecord(allocator, "uid", "42");
    defer allocator.free(global_uid);
    const global_xattr = try buildPaxRecord(
        allocator,
        "SCHILY.xattr.user.global",
        "inherited",
    );
    defer allocator.free(global_xattr);
    const global_pax = try std.fmt.allocPrint(
        allocator,
        "{s}{s}",
        .{ global_uid, global_xattr },
    );
    defer allocator.free(global_pax);

    const local_uid = try buildPaxRecord(allocator, "uid", "1000");
    defer allocator.free(local_uid);
    const local_mtime = try buildPaxRecord(allocator, "mtime", "-1.5");
    defer allocator.free(local_mtime);
    const local_xattr = try buildPaxRecord(
        allocator,
        "LIBARCHIVE.xattr.security.capability",
        "capability",
    );
    defer allocator.free(local_xattr);
    const local_pax = try std.fmt.allocPrint(
        allocator,
        "{s}{s}{s}",
        .{ local_uid, local_mtime, local_xattr },
    );
    defer allocator.free(local_pax);

    const bytes = try buildTar(allocator, &.{
        .{
            .path = "GlobalHead",
            .mode = 0o644,
            .typeflag = 'g',
            .content = global_pax,
            .link_name = null,
        },
        .{
            .path = "PaxHeaders/file",
            .mode = 0o644,
            .typeflag = 'x',
            .content = local_pax,
            .link_name = null,
        },
        .{
            .path = "file",
            .mode = 0o640,
            .uid = 1,
            .gid = 2,
            .mtime = 123,
            .typeflag = '0',
            .content = "payload",
            .link_name = null,
        },
        .{
            .path = "pipe",
            .mode = 0o600,
            .typeflag = '6',
            .content = "",
            .link_name = null,
        },
        .{
            .path = "console",
            .mode = 0o600,
            .device_major = 5,
            .device_minor = 1,
            .typeflag = '3',
            .content = "",
            .link_name = null,
        },
    });
    defer allocator.free(bytes);

    var input = Io.Reader.fixed(bytes);
    var stream = StreamReader.init(allocator, &input, .{});
    defer stream.deinit();

    const file = (try stream.next()).?;
    try std.testing.expectEqualStrings("file", file.path);
    try std.testing.expectEqual(@as(u32, 1000), file.uid);
    try std.testing.expectEqual(@as(u32, 2), file.gid);
    try std.testing.expectEqual(@as(i64, -2), file.mtime.seconds);
    try std.testing.expectEqual(@as(u32, 500_000_000), file.mtime.nanoseconds);
    try std.testing.expectEqual(@as(usize, 2), file.xattrs.len);
    try std.testing.expectEqualStrings("security.capability", file.xattrs[0].name);
    try std.testing.expectEqualStrings("user.global", file.xattrs[1].name);
    var payload: [7]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 7), try stream.readEntry(&payload));
    try std.testing.expectEqualStrings("payload", &payload);

    const fifo = (try stream.next()).?;
    try std.testing.expectEqual(Kind.fifo, fifo.kind);
    try std.testing.expectEqual(@as(u32, 42), fifo.uid);

    const device = (try stream.next()).?;
    try std.testing.expectEqual(Kind.character_device, device.kind);
    try std.testing.expectEqual(@as(u32, 5), device.device_major);
    try std.testing.expectEqual(@as(u32, 1), device.device_minor);
    try std.testing.expect((try stream.next()) == null);
}

test "stream reader rejects duplicate paths and archive limit overflow" {
    const allocator = std.testing.allocator;
    const bytes = try buildTar(allocator, &.{
        .{
            .path = "same",
            .mode = 0o644,
            .typeflag = '0',
            .content = "first",
            .link_name = null,
        },
        .{
            .path = "same",
            .mode = 0o644,
            .typeflag = '0',
            .content = "second",
            .link_name = null,
        },
    });
    defer allocator.free(bytes);

    var duplicate_input = Io.Reader.fixed(bytes);
    var duplicate = StreamReader.init(allocator, &duplicate_input, .{});
    defer duplicate.deinit();
    _ = try duplicate.next();
    try std.testing.expectError(error.DuplicatePath, duplicate.next());

    var limited_input = Io.Reader.fixed(bytes);
    var limited = StreamReader.init(allocator, &limited_input, .{
        .max_archive_bytes = block_size,
    });
    defer limited.deinit();
    _ = try limited.next();
    try std.testing.expectError(error.ArchiveByteLimitExceeded, limited.next());
}

test "PAX timestamps normalize negative fractions without overflow" {
    try std.testing.expectEqual(
        Timestamp{ .seconds = -1, .nanoseconds = 500_000_000 },
        try parsePaxTimestamp("-0.5"),
    );
    try std.testing.expectEqual(
        Timestamp{ .seconds = -2, .nanoseconds = 500_000_000 },
        try parsePaxTimestamp("-1.5"),
    );
    try std.testing.expectEqual(
        Timestamp{ .seconds = std.math.minInt(i64) },
        try parsePaxTimestamp("-9223372036854775808.0"),
    );
    try std.testing.expectError(
        error.InvalidTimestamp,
        parsePaxTimestamp("-9223372036854775808.1"),
    );
}

test "stream reader bounds aggregate pending PAX headers" {
    const allocator = std.testing.allocator;
    const first = try buildPaxRecord(allocator, "uid", "1000");
    defer allocator.free(first);
    const second = try buildPaxRecord(allocator, "gid", "1000");
    defer allocator.free(second);
    const bytes = try buildTar(allocator, &.{
        .{
            .path = "PaxHeaders/first",
            .mode = 0o644,
            .typeflag = 'x',
            .content = first,
            .link_name = null,
        },
        .{
            .path = "PaxHeaders/second",
            .mode = 0o644,
            .typeflag = 'x',
            .content = second,
            .link_name = null,
        },
        .{
            .path = "file",
            .mode = 0o644,
            .typeflag = '0',
            .content = "",
            .link_name = null,
        },
    });
    defer allocator.free(bytes);

    var input = Io.Reader.fixed(bytes);
    var reader = StreamReader.init(allocator, &input, .{
        .max_pax_bytes = first.len + second.len - 1,
    });
    defer reader.deinit();
    try std.testing.expectError(error.ValueTooLarge, reader.next());
}

test "writer emits deterministic canonical PAX and special-file metadata" {
    const allocator = std.testing.allocator;
    const long_path = try allocator.alloc(u8, 300);
    defer allocator.free(long_path);
    @memset(long_path, 'a');
    const long_link = try allocator.alloc(u8, 150);
    defer allocator.free(long_link);
    @memset(long_link, 'b');
    const xattrs = [_]Xattr{
        .{ .name = "security.capability", .value = &.{ 0, 1, 0, 2 } },
        .{ .name = "user.origin", .value = "miz" },
    };

    var first = Io.Writer.Allocating.init(allocator);
    defer first.deinit();
    var first_writer = Writer.init(&first.writer);
    try first_writer.beginEntry(.{
        .path = long_path,
        .kind = .file,
        .mode = 0o640,
        .uid = std.math.maxInt(u32),
        .gid = 1234,
        .mtime = .{ .seconds = -2, .nanoseconds = 500_000_000 },
        .size = "payload".len,
        .xattrs = &xattrs,
    });
    try first_writer.writeAll("payload");
    try first_writer.endEntry();
    try first_writer.writeEntry(.{
        .path = "hardlink",
        .kind = .hardlink,
        .mode = 0o640,
        .link_name = long_link,
    });
    try first_writer.writeEntry(.{
        .path = "console",
        .kind = .character_device,
        .mode = 0o600,
        .device_major = 5,
        .device_minor = 1,
    });
    try first_writer.finish();

    var second = Io.Writer.Allocating.init(allocator);
    defer second.deinit();
    var second_writer = Writer.init(&second.writer);
    try second_writer.beginEntry(.{
        .path = long_path,
        .kind = .file,
        .mode = 0o640,
        .uid = std.math.maxInt(u32),
        .gid = 1234,
        .mtime = .{ .seconds = -2, .nanoseconds = 500_000_000 },
        .size = "payload".len,
        .xattrs = &xattrs,
    });
    try second_writer.writeAll("payload");
    try second_writer.endEntry();
    try second_writer.writeEntry(.{
        .path = "hardlink",
        .kind = .hardlink,
        .mode = 0o640,
        .link_name = long_link,
    });
    try second_writer.writeEntry(.{
        .path = "console",
        .kind = .character_device,
        .mode = 0o600,
        .device_major = 5,
        .device_minor = 1,
    });
    try second_writer.finish();
    try std.testing.expectEqualSlices(u8, first.written(), second.written());

    var input = Io.Reader.fixed(first.written());
    var reader = StreamReader.init(allocator, &input, .{});
    defer reader.deinit();
    const file = (try reader.next()).?;
    try std.testing.expectEqualStrings(long_path, file.path);
    try std.testing.expectEqual(std.math.maxInt(u32), file.uid);
    try std.testing.expectEqual(@as(i64, -2), file.mtime.seconds);
    try std.testing.expectEqual(@as(u32, 500_000_000), file.mtime.nanoseconds);
    try std.testing.expectEqual(@as(usize, 2), file.xattrs.len);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 0, 2 }, file.xattrs[0].value);
    var payload: [7]u8 = undefined;
    try std.testing.expectEqual(payload.len, try reader.readEntry(&payload));
    try std.testing.expectEqualStrings("payload", &payload);

    const hardlink = (try reader.next()).?;
    try std.testing.expectEqual(Kind.hardlink, hardlink.kind);
    try std.testing.expectEqualStrings(long_link, hardlink.link_name.?);
    const device = (try reader.next()).?;
    try std.testing.expectEqual(Kind.character_device, device.kind);
    try std.testing.expectEqual(@as(u32, 5), device.device_major);
    try std.testing.expectEqual(@as(u32, 1), device.device_minor);
}

test "writes a small USTAR archive" {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    var writer = Writer.init(&out.writer);
    try writer.writeFile("metadata.json", 0o400, "{}\n");
    try writer.writeFile("images/part.raw.zst", 0o400, "payload");
    try writer.finish();

    const entries = try parseEntries(std.testing.allocator, out.written());
    defer {
        for (entries) |entry| std.testing.allocator.free(entry.path);
        std.testing.allocator.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("metadata.json", entries[0].path);
    try std.testing.expectEqualStrings("{}\n", entries[0].payload);
    try std.testing.expectEqualStrings("images/part.raw.zst", entries[1].path);
    try std.testing.expectEqualStrings("payload", entries[1].payload);
}
