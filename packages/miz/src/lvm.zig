//! Read-only LVM2 reader for offline disk images.
//!
//! A default Ubuntu or Debian guided install puts the root filesystem on a
//! logical volume inside a physical volume that spans a whole partition, so
//! anything that stops at the partition table finds an opaque blob where the
//! root filesystem should be. On a *running* system the volume manager has
//! already published that logical volume as `/dev/mapper/vg-lv`, and opening
//! that node as a raw source (see `block_device`) reaches the filesystem
//! without parsing anything; this module exists for the image file that
//! nobody has activated.
//!
//! Everything here reads. There is no writer, no activation, and no repair:
//! the entire output of the module is names, sizes, and byte offsets, and
//! every entry point takes the image by value, so a caller that mutates an
//! image cannot route the mutation through here even by accident.
//!
//! The on-disk format is small, textual, and stable. Field layouts and
//! validation rules below are transcribed from the LVM2 sources:
//! `lib/label/label.h` (`struct label_header`, `LABEL_SCAN_SECTORS`),
//! `lib/format_text/layout.h` (`struct pv_header`, `struct mda_header`,
//! `struct raw_locn`, `FMTT_MAGIC`, `MDA_HEADER_SIZE`, `RAW_LOCN_IGNORED`),
//! `lib/format_text/format-text.c` (`raw_parse_mda_header`, the circular
//! buffer wrap rule), and `lib/misc/crc.c` plus `lib/misc/crc.h`
//! (`calc_crc`, `INITIAL_CRC`). Every multi-byte field is little-endian.
//!
//! Only plain linear mappings are understood -- a `striped` segment with one
//! stripe, which is what every default install produces. Mirrors, RAID, thin,
//! cache and snapshot segments each get their own error rather than being
//! read as if they were linear: misreading a thin or RAID mapping produces
//! bytes that look like a filesystem but are not one, which is far worse than
//! refusing to answer.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const mbr = @import("mbr.zig");

/// LVM addresses everything in 512-byte sectors regardless of the device's
/// logical sector size: `pe_start`, `extent_size` and `dev_size` in the
/// metadata text are all counts of these.
pub const sector_size: u64 = 512;

/// The label is looked for in the first four sectors of a physical volume.
/// `pvcreate` writes it to sector 1, but the format allows 0 through 3.
pub const label_scan_sectors: u64 = 4;
pub const label_size: usize = 512;
pub const label_id: [8]u8 = "LABELONE".*;
pub const label_type: [8]u8 = "LVM2 001".*;

/// `FMTT_MAGIC`, spelled in octal escapes in the LVM2 header.
pub const metadata_area_magic: [16]u8 = " LVM2 x[5A%r0N*>".*;
pub const metadata_area_header_size: u64 = 512;
pub const metadata_area_version: u32 = 1;

/// `RAW_LOCN_IGNORED`: the copy in this metadata area is deliberately not
/// maintained, so its text is stale by design and must never win the
/// newest-sequence-number comparison.
pub const raw_locn_ignored: u32 = 0x0000_0001;

/// LVM2's own `NAME_LEN`. Volume group and logical volume names are bounded
/// by it, so a selector naming something longer names nothing.
pub const max_name_len: usize = 128;

/// Ceiling on one committed metadata text. The default metadata area is
/// 1 MiB and `--metadatasize` is rarely raised past a few megabytes; the
/// bound exists so a corrupt `raw_locn` cannot ask for an arbitrary
/// allocation.
pub const max_metadata_bytes: usize = 8 * 1024 * 1024;

/// Ceiling on the number of nodes one metadata text may parse into. A large
/// volume group with hundreds of volumes stays far below it.
pub const max_metadata_nodes: usize = 1 << 16;

/// Ceiling on section nesting. Real metadata nests four deep
/// (vg / logical_volumes / lv / segment).
pub const max_metadata_depth: usize = 16;

/// Ceiling on the number of disk areas in either list of a PV header. LVM2
/// writes one data area and at most two metadata areas.
pub const max_disk_areas: usize = 8;

pub const ReadError = error{
    /// A structure pointed outside the region the physical volume occupies.
    LvmReadOutOfBounds,
    UnexpectedEndOfFile,
} || Image.PreadError;

pub const FormatError = error{
    InvalidLvmLabel,
    BadLvmLabelChecksum,
    UnsupportedLvmLabelType,
    InvalidLvmPvHeader,
    TooManyLvmDiskAreas,
    InvalidLvmMetadataArea,
    BadLvmMetadataAreaChecksum,
    UnsupportedLvmMetadataAreaVersion,
    InvalidLvmMetadataLocation,
    BadLvmMetadataChecksum,
    LvmMetadataTooLarge,
};

pub const TextError = error{
    InvalidLvmMetadataText,
    UnsupportedLvmMetadataValue,
    LvmMetadataTextTooDeep,
    LvmMetadataTextTooLarge,
};

pub const MetadataError = error{
    UnsupportedLvmMetadataFormat,
    InvalidLvmVolumeGroup,
    InvalidLvmName,
    /// Two physical volumes in the same image carry metadata for volume
    /// groups that share a name but not an identity, so a name selects
    /// nothing unambiguously.
    DuplicateLvmVolumeGroup,
};

/// Why a logical volume has no byte range on this disk. Each cause is its
/// own error because each one means something different to an operator: a
/// thin volume needs its pool, a RAID volume needs its mirrors, and a
/// volume group split across disks needs the other disk.
pub const MapError = error{
    UnsupportedLvmStripedSegment,
    UnsupportedLvmMirrorSegment,
    UnsupportedLvmRaidSegment,
    UnsupportedLvmThinSegment,
    UnsupportedLvmCacheSegment,
    UnsupportedLvmSnapshotSegment,
    UnsupportedLvmSegmentType,
    /// The volume group names a physical volume that this image does not
    /// contain, so part of the volume's data is on a disk nobody supplied.
    LvmPhysicalVolumeMissing,
    /// The volume's extents are not one unbroken run on one physical volume,
    /// so it cannot be handed to a reader that takes an offset and a length.
    LogicalVolumeNotContiguous,
    EmptyLogicalVolume,
    LvmExtentOutOfRange,
};

pub const SelectError = error{
    LvmVolumeGroupNotFound,
    AmbiguousLvmVolumeGroup,
    LogicalVolumeNotFound,
};

pub const ScanError = ReadError || FormatError || TextError || MetadataError ||
    gpt.ReadError || Allocator.Error;

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// `INITIAL_CRC` from `lib/misc/crc.h`. LVM2 seeds its CRC with this rather
/// than the usual all-ones and never inverts the result, so the standard
/// CRC-32 in `std.hash.crc` cannot be substituted.
pub const crc_initial: u32 = 0xf597_a6cf;

/// The nibble-wise lookup table for the reflected 0xedb88320 polynomial,
/// exactly as `_calc_crc_old` in `lib/misc/crc.c` uses it. A test derives it
/// from the polynomial so a typo here cannot pass unnoticed.
const crc_table = [16]u32{
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
};

/// LVM2's `calc_crc`. Chainable: a checksum over a buffer that wraps around
/// the end of the metadata area is this function applied to the first part
/// and then to the second, which is how LVM2 computes it too.
pub fn crc(initial: u32, bytes: []const u8) u32 {
    var value = initial;
    for (bytes) |byte| {
        value ^= byte;
        value = (value >> 4) ^ crc_table[value & 0xf];
        value = (value >> 4) ^ crc_table[value & 0xf];
    }
    return value;
}

// ---------------------------------------------------------------------------
// Regions and labels
// ---------------------------------------------------------------------------

/// Where on the disk a candidate physical volume was looked for. Carried so
/// output can say *which* partition holds a volume group rather than only
/// its byte offset.
pub const Location = union(enum) {
    /// The physical volume occupies the disk itself, with no partition table
    /// in front of it -- what `pvcreate /dev/sdb` produces.
    whole_disk,
    /// One-based GPT partition index.
    gpt_partition: u32,
    /// One-based MBR primary partition index.
    mbr_partition: u8,
};

/// A byte range of the disk that might hold a physical volume.
pub const Region = struct {
    offset: u64,
    length: u64,
    location: Location,
};

pub const DiskLocn = struct {
    offset: u64,
    size: u64,
};

/// The LVM2 label plus the physical volume header that follows it. Both live
/// inside a single 512-byte sector, so this is everything the first sector of
/// a physical volume says about itself.
pub const Label = struct {
    /// Sector within the region that carried the label, 0 through 3.
    sector: u64,
    /// The 32 uppercase base-58ish characters of the PV identity, exactly as
    /// stored: the metadata text spells the same value with dashes.
    pv_uuid: [32]u8,
    device_size: u64,
    /// The area lists are held inline, and reached through the accessors
    /// below, because a `Label` is returned and copied by value: slices into
    /// its own storage would dangle the moment it moved.
    data_area_count: usize,
    data_area_storage: [max_disk_areas]DiskLocn,
    metadata_area_count: usize,
    metadata_area_storage: [max_disk_areas]DiskLocn,

    pub fn dataAreas(self: *const Label) []const DiskLocn {
        return self.data_area_storage[0..self.data_area_count];
    }

    pub fn metadataAreas(self: *const Label) []const DiskLocn {
        return self.metadata_area_storage[0..self.metadata_area_count];
    }
};

fn readRegion(image: Image, io: Io, region: Region, buffer: []u8, offset: u64) ReadError!void {
    const end = std.math.add(u64, offset, buffer.len) catch return error.LvmReadOutOfBounds;
    if (end > region.length) return error.LvmReadOutOfBounds;
    const absolute = std.math.add(u64, region.offset, offset) catch return error.LvmReadOutOfBounds;
    if (try image.pread(io, buffer, absolute) != buffer.len) return error.UnexpectedEndOfFile;
}

/// Reads the LVM2 label from the first four sectors of `region`, or null when
/// the region holds no physical volume. A sector whose first eight bytes are
/// not `LABELONE` is simply not a label; one that says `LABELONE` but fails
/// its own checksum, names a different sector, or declares an unknown type is
/// corruption and is reported rather than skipped.
pub fn readLabel(image: Image, io: Io, region: Region) (ReadError || FormatError)!?Label {
    var sector: [label_size]u8 = undefined;
    var index: u64 = 0;
    while (index < label_scan_sectors) : (index += 1) {
        const offset = index * sector_size;
        if (offset + label_size > region.length) return null;
        try readRegion(image, io, region, &sector, offset);
        if (!std.mem.eql(u8, sector[0..8], &label_id)) continue;
        return try parseLabelSector(&sector, index);
    }
    return null;
}

/// Decodes one 512-byte label sector known to start with `LABELONE`.
/// `sector_index` is the sector's position within the physical volume, which
/// the label repeats and which therefore has to agree.
pub fn parseLabelSector(sector: *const [label_size]u8, sector_index: u64) FormatError!Label {
    if (!std.mem.eql(u8, sector[0..8], &label_id)) return error.InvalidLvmLabel;
    if (std.mem.readInt(u64, sector[8..16], .little) != sector_index) return error.InvalidLvmLabel;

    const stored_crc = std.mem.readInt(u32, sector[16..20], .little);
    // "From next field to end of sector": the checksum covers byte 20
    // onwards, which is `offset_xl` and everything the header points at.
    if (crc(crc_initial, sector[20..]) != stored_crc) return error.BadLvmLabelChecksum;

    if (!std.mem.eql(u8, sector[24..32], &label_type)) return error.UnsupportedLvmLabelType;

    const header_offset = std.mem.readInt(u32, sector[20..24], .little);
    // The physical volume header follows the 32-byte label header and, like
    // everything else the label describes, lives in this one sector.
    if (header_offset < 32 or header_offset + 40 > label_size) return error.InvalidLvmPvHeader;

    const header = sector[header_offset..];

    // Two null-terminated lists back to back: data areas first, then
    // metadata areas. A list runs to a zero offset, and the header extension
    // that may follow the second list is not read, because nothing here
    // needs a bootloader area.
    var data_storage: [max_disk_areas]DiskLocn = undefined;
    var metadata_storage: [max_disk_areas]DiskLocn = undefined;
    var cursor: usize = header_offset + 40;
    const data_count = try readDiskLocns(sector, &cursor, &data_storage);
    const metadata_count = try readDiskLocns(sector, &cursor, &metadata_storage);

    return .{
        .sector = sector_index,
        .pv_uuid = header[0..32].*,
        .device_size = std.mem.readInt(u64, header[32..40], .little),
        .data_area_count = data_count,
        .data_area_storage = data_storage,
        .metadata_area_count = metadata_count,
        .metadata_area_storage = metadata_storage,
    };
}

fn readDiskLocns(
    sector: *const [label_size]u8,
    cursor: *usize,
    storage: *[max_disk_areas]DiskLocn,
) FormatError!usize {
    var count: usize = 0;
    while (true) {
        if (cursor.* + 16 > label_size) return error.InvalidLvmPvHeader;
        const offset = std.mem.readInt(u64, sector[cursor.*..][0..8], .little);
        const size = std.mem.readInt(u64, sector[cursor.* + 8 ..][0..8], .little);
        cursor.* += 16;
        if (offset == 0) return count;
        if (count == max_disk_areas) return error.TooManyLvmDiskAreas;
        storage[count] = .{ .offset = offset, .size = size };
        count += 1;
    }
}

// ---------------------------------------------------------------------------
// Metadata areas
// ---------------------------------------------------------------------------

pub const RawLocn = struct {
    offset: u64,
    size: u64,
    checksum: u32,
    flags: u32,

    pub fn isIgnored(self: RawLocn) bool {
        return self.flags & raw_locn_ignored != 0;
    }

    pub fn isEmpty(self: RawLocn) bool {
        return self.offset == 0 and self.size == 0;
    }
};

pub const MetadataAreaHeader = struct {
    start: u64,
    size: u64,
    /// Slot 0 of the `raw_locn` list: the committed metadata. Slot 1 holds a
    /// precommitted copy that exists only mid-transaction and is deliberately
    /// never read here -- committed is the only state an offline image can be
    /// trusted to be in.
    committed: RawLocn,
};

/// Reads and validates the 512-byte metadata area header at `area.offset`
/// within `region`.
pub fn readMetadataAreaHeader(
    image: Image,
    io: Io,
    region: Region,
    area: DiskLocn,
) (ReadError || FormatError)!MetadataAreaHeader {
    var header: [metadata_area_header_size]u8 = undefined;
    try readRegion(image, io, region, &header, area.offset);
    return parseMetadataAreaHeader(&header, area);
}

pub fn parseMetadataAreaHeader(
    header: *const [metadata_area_header_size]u8,
    area: DiskLocn,
) FormatError!MetadataAreaHeader {
    const stored_crc = std.mem.readInt(u32, header[0..4], .little);
    if (crc(crc_initial, header[4..]) != stored_crc) return error.BadLvmMetadataAreaChecksum;
    if (!std.mem.eql(u8, header[4..20], &metadata_area_magic)) return error.InvalidLvmMetadataArea;
    if (std.mem.readInt(u32, header[20..24], .little) != metadata_area_version) {
        return error.UnsupportedLvmMetadataAreaVersion;
    }

    const start = std.mem.readInt(u64, header[24..32], .little);
    const size = std.mem.readInt(u64, header[32..40], .little);
    // The header repeats its own absolute position, and a copy that landed
    // somewhere other than where the PV header says it is describes a
    // different area than the one being read.
    if (start != area.offset) return error.InvalidLvmMetadataArea;
    if (size < metadata_area_header_size or size > area.size) return error.InvalidLvmMetadataArea;

    return .{
        .start = start,
        .size = size,
        .committed = .{
            .offset = std.mem.readInt(u64, header[40..48], .little),
            .size = std.mem.readInt(u64, header[48..56], .little),
            .checksum = std.mem.readInt(u32, header[56..60], .little),
            .flags = std.mem.readInt(u32, header[60..64], .little),
        },
    };
}

/// Reads the committed metadata text out of one metadata area, or null when
/// the area holds none (a freshly formatted area) or is flagged ignored (its
/// contents are stale by design and must not be compared for freshness).
///
/// The area is a circular buffer whose first 512 bytes are the header, so a
/// text that runs off the end resumes immediately after it. The stored
/// checksum covers the text in logical order, across the wrap.
pub fn readMetadataText(
    allocator: Allocator,
    image: Image,
    io: Io,
    region: Region,
    area: DiskLocn,
    header: MetadataAreaHeader,
) (ReadError || FormatError || Allocator.Error)!?[]u8 {
    const locn = header.committed;
    if (locn.isEmpty() or locn.isIgnored()) return null;

    if (locn.offset < metadata_area_header_size or
        locn.offset >= header.size or
        locn.size == 0 or
        locn.size > header.size - metadata_area_header_size)
    {
        return error.InvalidLvmMetadataLocation;
    }
    if (locn.size > max_metadata_bytes) return error.LvmMetadataTooLarge;

    const wrap: u64 = if (locn.offset + locn.size > header.size)
        (locn.offset + locn.size) - header.size
    else
        0;
    const head_len: usize = @intCast(locn.size - wrap);
    const wrap_len: usize = @intCast(wrap);

    const text = try allocator.alloc(u8, @intCast(locn.size));
    errdefer allocator.free(text);
    try readRegion(image, io, region, text[0..head_len], area.offset + locn.offset);
    if (wrap_len != 0) {
        try readRegion(
            image,
            io,
            region,
            text[head_len..],
            area.offset + metadata_area_header_size,
        );
    }

    if (crc(crc_initial, text) != locn.checksum) return error.BadLvmMetadataChecksum;
    return text;
}

// ---------------------------------------------------------------------------
// The metadata text
// ---------------------------------------------------------------------------

pub const Scalar = union(enum) {
    integer: i64,
    string: []const u8,
};

pub const Value = union(enum) {
    section: []const Node,
    integer: i64,
    string: []const u8,
    array: []const Scalar,
};

pub const Node = struct {
    name: []const u8,
    value: Value,
};

const Token = union(enum) {
    identifier: []const u8,
    string: []const u8,
    integer: i64,
    section_open,
    section_close,
    array_open,
    array_close,
    assign,
    comma,
    end,
};

fn isIdentifierByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '_' or byte == '-' or byte == '+' or byte == '.' or byte == '/';
}

const Tokenizer = struct {
    text: []const u8,
    index: usize = 0,
    arena: Allocator,

    fn skipTrivia(self: *Tokenizer) void {
        while (self.index < self.text.len) {
            const byte = self.text[self.index];
            if (byte == '#') {
                while (self.index < self.text.len and self.text[self.index] != '\n') {
                    self.index += 1;
                }
            } else if (std.ascii.isWhitespace(byte)) {
                self.index += 1;
            } else {
                return;
            }
        }
    }

    fn next(self: *Tokenizer) (TextError || Allocator.Error)!Token {
        self.skipTrivia();
        if (self.index >= self.text.len) return .end;
        const byte = self.text[self.index];
        switch (byte) {
            '{' => {
                self.index += 1;
                return .section_open;
            },
            '}' => {
                self.index += 1;
                return .section_close;
            },
            '[' => {
                self.index += 1;
                return .array_open;
            },
            ']' => {
                self.index += 1;
                return .array_close;
            },
            '=' => {
                self.index += 1;
                return .assign;
            },
            ',' => {
                self.index += 1;
                return .comma;
            },
            '"' => return .{ .string = try self.readString() },
            else => {
                if (byte == '-' or std.ascii.isDigit(byte)) {
                    return .{ .integer = try self.readInteger() };
                }
                if (isIdentifierByte(byte)) return .{ .identifier = self.readIdentifier() };
                return error.InvalidLvmMetadataText;
            },
        }
    }

    fn readIdentifier(self: *Tokenizer) []const u8 {
        const start = self.index;
        while (self.index < self.text.len and isIdentifierByte(self.text[self.index])) {
            self.index += 1;
        }
        return self.text[start..self.index];
    }

    fn readInteger(self: *Tokenizer) TextError!i64 {
        const start = self.index;
        if (self.text[self.index] == '-') self.index += 1;
        const digits_start = self.index;
        while (self.index < self.text.len and std.ascii.isDigit(self.text[self.index])) {
            self.index += 1;
        }
        if (self.index == digits_start) return error.InvalidLvmMetadataText;
        // A float would parse as an integer followed by a stray identifier
        // starting with '.', which is a confusing way to say "this value is
        // not one this reader understands".
        if (self.index < self.text.len and self.text[self.index] == '.') {
            return error.UnsupportedLvmMetadataValue;
        }
        return std.fmt.parseInt(i64, self.text[start..self.index], 10) catch
            error.InvalidLvmMetadataText;
    }

    fn readString(self: *Tokenizer) (TextError || Allocator.Error)![]const u8 {
        self.index += 1;
        const start = self.index;
        var escaped = false;
        while (self.index < self.text.len) : (self.index += 1) {
            const byte = self.text[self.index];
            if (byte == '\\') {
                if (self.index + 1 >= self.text.len) return error.InvalidLvmMetadataText;
                escaped = true;
                self.index += 1;
                continue;
            }
            if (byte == '"') {
                const raw = self.text[start..self.index];
                self.index += 1;
                if (!escaped) return raw;
                return try unescape(self.arena, raw);
            }
            if (byte == '\n') return error.InvalidLvmMetadataText;
        }
        return error.InvalidLvmMetadataText;
    }
};

/// LVM2 escapes only `"` and `\` when it writes a string, and unescapes any
/// backslash pair when it reads one.
fn unescape(arena: Allocator, raw: []const u8) Allocator.Error![]const u8 {
    var out = try arena.alloc(u8, raw.len);
    var len: usize = 0;
    var index: usize = 0;
    while (index < raw.len) : (index += 1) {
        if (raw[index] == '\\' and index + 1 < raw.len) index += 1;
        out[len] = raw[index];
        len += 1;
    }
    return out[0..len];
}

const Parser = struct {
    tokenizer: Tokenizer,
    arena: Allocator,
    pending: ?Token = null,
    depth: usize = 0,
    remaining_nodes: usize = max_metadata_nodes,

    fn take(self: *Parser) (TextError || Allocator.Error)!Token {
        if (self.pending) |token| {
            self.pending = null;
            return token;
        }
        return self.tokenizer.next();
    }

    fn put(self: *Parser, token: Token) void {
        std.debug.assert(self.pending == null);
        self.pending = token;
    }

    fn parseNodes(self: *Parser, terminator: enum { end_of_text, close_brace }) (TextError || Allocator.Error)![]const Node {
        var nodes = std.array_list.Managed(Node).init(self.arena);
        while (true) {
            const token = try self.take();
            switch (token) {
                .end => {
                    if (terminator != .end_of_text) return error.InvalidLvmMetadataText;
                    return nodes.toOwnedSlice();
                },
                .section_close => {
                    if (terminator != .close_brace) return error.InvalidLvmMetadataText;
                    return nodes.toOwnedSlice();
                },
                .identifier, .string => {
                    if (self.remaining_nodes == 0) return error.LvmMetadataTextTooLarge;
                    self.remaining_nodes -= 1;
                    const name = switch (token) {
                        .identifier => |text| text,
                        .string => |text| text,
                        else => unreachable,
                    };
                    try nodes.append(.{ .name = name, .value = try self.parseNodeValue() });
                },
                else => return error.InvalidLvmMetadataText,
            }
        }
    }

    fn parseNodeValue(self: *Parser) (TextError || Allocator.Error)!Value {
        switch (try self.take()) {
            .section_open => {
                if (self.depth == max_metadata_depth) return error.LvmMetadataTextTooDeep;
                self.depth += 1;
                // The nested nodes are parsed into a local and only then
                // wrapped in the union, so a failure part-way down cannot
                // publish a `.section` tag over a payload nobody filled.
                const nested = try self.parseNodes(.close_brace);
                self.depth -= 1;
                return .{ .section = nested };
            },
            .assign => return self.parseAssignment(),
            else => return error.InvalidLvmMetadataText,
        }
    }

    fn parseAssignment(self: *Parser) (TextError || Allocator.Error)!Value {
        switch (try self.take()) {
            .integer => |value| return .{ .integer = value },
            .string => |value| return .{ .string = value },
            .array_open => {
                var items = std.array_list.Managed(Scalar).init(self.arena);
                var expect_value = true;
                while (true) {
                    const token = try self.take();
                    switch (token) {
                        .array_close => {
                            // A trailing comma with nothing after it is not
                            // something LVM2 writes.
                            if (expect_value and items.items.len != 0) {
                                return error.InvalidLvmMetadataText;
                            }
                            return .{ .array = try items.toOwnedSlice() };
                        },
                        .comma => {
                            if (expect_value) return error.InvalidLvmMetadataText;
                            expect_value = true;
                        },
                        .integer => |value| {
                            if (!expect_value) return error.InvalidLvmMetadataText;
                            if (self.remaining_nodes == 0) return error.LvmMetadataTextTooLarge;
                            self.remaining_nodes -= 1;
                            try items.append(.{ .integer = value });
                            expect_value = false;
                        },
                        .string => |value| {
                            if (!expect_value) return error.InvalidLvmMetadataText;
                            if (self.remaining_nodes == 0) return error.LvmMetadataTextTooLarge;
                            self.remaining_nodes -= 1;
                            try items.append(.{ .string = value });
                            expect_value = false;
                        },
                        else => return error.InvalidLvmMetadataText,
                    }
                }
            },
            else => return error.InvalidLvmMetadataText,
        }
    }
};

/// Parses the declarative text LVM2 stores in a metadata area into a node
/// tree. `arena` owns every name and string in the result.
///
/// The committed text is stored with a trailing NUL that the checksum covers,
/// so parsing stops at the first NUL rather than treating it as a token.
pub fn parseText(arena: Allocator, text: []const u8) (TextError || Allocator.Error)![]const Node {
    const body = if (std.mem.indexOfScalar(u8, text, 0)) |nul| text[0..nul] else text;
    var parser = Parser{
        .tokenizer = .{ .text = body, .arena = arena },
        .arena = arena,
    };
    return parser.parseNodes(.end_of_text);
}

fn findNode(nodes: []const Node, name: []const u8) ?Value {
    for (nodes) |node| {
        if (std.mem.eql(u8, node.name, name)) return node.value;
    }
    return null;
}

fn findSection(nodes: []const Node, name: []const u8) ?[]const Node {
    const value = findNode(nodes, name) orelse return null;
    return switch (value) {
        .section => |children| children,
        else => null,
    };
}

fn requireString(nodes: []const Node, name: []const u8) MetadataError![]const u8 {
    const value = findNode(nodes, name) orelse return error.InvalidLvmVolumeGroup;
    return switch (value) {
        .string => |text| text,
        else => error.InvalidLvmVolumeGroup,
    };
}

fn requireUnsigned(nodes: []const Node, name: []const u8) MetadataError!u64 {
    const value = findNode(nodes, name) orelse return error.InvalidLvmVolumeGroup;
    return switch (value) {
        .integer => |number| if (number < 0)
            error.InvalidLvmVolumeGroup
        else
            @intCast(number),
        else => error.InvalidLvmVolumeGroup,
    };
}

fn hasStatus(nodes: []const Node, flag: []const u8) bool {
    const value = findNode(nodes, "status") orelse return false;
    const items = switch (value) {
        .array => |array| array,
        else => return false,
    };
    for (items) |item| {
        switch (item) {
            .string => |text| if (std.mem.eql(u8, text, flag)) return true,
            else => {},
        }
    }
    return false;
}

fn validateName(name: []const u8) MetadataError!void {
    if (name.len == 0 or name.len > max_name_len) return error.InvalidLvmName;
    for (name) |byte| {
        if (!isIdentifierByte(byte)) return error.InvalidLvmName;
    }
}

// ---------------------------------------------------------------------------
// The volume group model
// ---------------------------------------------------------------------------

/// A segment type this reader will not map, and why. Kept separate from the
/// raw type name so a caller switches on a closed set while output can still
/// print exactly what the metadata said.
pub const Unsupported = enum {
    /// `striped` with more than one stripe: real striping, not a linear map.
    striped,
    mirror,
    raid,
    thin,
    cache,
    snapshot,
    other,

    pub fn err(self: Unsupported) MapError {
        return switch (self) {
            .striped => error.UnsupportedLvmStripedSegment,
            .mirror => error.UnsupportedLvmMirrorSegment,
            .raid => error.UnsupportedLvmRaidSegment,
            .thin => error.UnsupportedLvmThinSegment,
            .cache => error.UnsupportedLvmCacheSegment,
            .snapshot => error.UnsupportedLvmSnapshotSegment,
            .other => error.UnsupportedLvmSegmentType,
        };
    }
};

/// Classifies a segment type name. Anything not recognised lands in `.other`
/// rather than being assumed linear, so a segment type invented after this
/// was written is refused instead of misread.
pub fn classify(type_name: []const u8) ?Unsupported {
    // LVM2 writes `striped` for a plain linear mapping and distinguishes it
    // from real striping by `stripe_count`; `linear` is accepted under the
    // same rule for the same reason.
    if (std.mem.eql(u8, type_name, "striped")) return null;
    if (std.mem.eql(u8, type_name, "linear")) return null;
    if (std.mem.eql(u8, type_name, "mirror")) return .mirror;
    if (std.mem.startsWith(u8, type_name, "raid")) return .raid;
    if (std.mem.eql(u8, type_name, "snapshot")) return .snapshot;
    if (std.mem.startsWith(u8, type_name, "thin")) return .thin;
    if (std.mem.startsWith(u8, type_name, "cache")) return .cache;
    if (std.mem.eql(u8, type_name, "writecache")) return .cache;
    return .other;
}

pub const Linear = struct {
    /// Index into the volume group's `physical_volumes`.
    physical_volume: usize,
    /// First physical extent of the run on that physical volume.
    start_extent: u64,
};

pub const SegmentMapping = union(enum) {
    linear: Linear,
    unsupported: Unsupported,
};

pub const Segment = struct {
    /// First extent of the logical volume this segment covers.
    start_extent: u64,
    extent_count: u64,
    /// The type name exactly as the metadata spells it.
    type_name: []const u8,
    mapping: SegmentMapping,
};

pub const PhysicalVolume = struct {
    /// The key the metadata uses to refer to this volume, such as `pv0`.
    key: []const u8,
    /// The identity, dashed, as the metadata spells it.
    id: []const u8,
    /// The device path LVM2 last saw this volume at. A hint written for
    /// humans; it names a device on the machine that wrote it, so nothing
    /// here resolves it.
    device_hint: []const u8,
    dev_size_sectors: u64,
    /// Sectors from the start of the physical volume to its first extent.
    pe_start_sectors: u64,
    pe_count: u64,
    /// Where this physical volume was found on the disk being read, or null
    /// when the image does not contain it.
    region: ?Region,
};

pub const LogicalVolume = struct {
    name: []const u8,
    id: []const u8,
    /// Whether the volume is one a user named, as opposed to an internal
    /// component such as a thin pool's data or metadata volume.
    visible: bool,
    /// In `start_extent` order, tiling the volume without gap or overlap.
    segments: []const Segment,
    extent_count: u64,
};

pub const VolumeGroup = struct {
    name: []const u8,
    id: []const u8,
    /// The metadata sequence number this copy carries. Higher is newer.
    seqno: u64,
    extent_size_sectors: u64,
    /// Not `const` because `scan` fills in each volume's `region` after the
    /// text has been parsed. Callers only ever receive a `*const
    /// VolumeGroup`, so the mutability does not escape this module.
    physical_volumes: []PhysicalVolume,
    logical_volumes: []const LogicalVolume,

    pub fn extentSizeBytes(self: *const VolumeGroup) u64 {
        return self.extent_size_sectors * sector_size;
    }

    /// Whether every physical volume the metadata names was found in the
    /// image. A volume group spread across disks that were not all supplied
    /// can still be listed, but only the volumes wholly on the disks present
    /// can be mapped.
    pub fn complete(self: *const VolumeGroup) bool {
        for (self.physical_volumes) |pv| {
            if (pv.region == null) return false;
        }
        return true;
    }

    pub fn findLogicalVolume(self: *const VolumeGroup, name: []const u8) ?*const LogicalVolume {
        for (self.logical_volumes) |*lv| {
            if (std.mem.eql(u8, lv.name, name)) return lv;
        }
        return null;
    }

    pub fn sizeBytes(self: *const VolumeGroup, lv: *const LogicalVolume) u64 {
        return lv.extent_count * self.extentSizeBytes();
    }
};

/// A byte range of the disk holding part of a logical volume.
pub const Extent = struct {
    offset: u64,
    length: u64,
};

/// Where the run of logical extents beginning at `lv_extent` lives on the
/// disk. The run ends where its segment does, so walking a volume means
/// asking again at `lv_extent + covered_extents`.
pub const Mapping = struct {
    disk: Extent,
    covered_extents: u64,
};

/// Maps a logical extent of `lv` to a byte offset on the disk.
///
/// The arithmetic is the whole point of this module, so it is spelled once:
/// a physical extent `pe` of a physical volume starts `pe_start` sectors plus
/// `pe * extent_size` sectors into that physical volume, and the physical
/// volume itself starts at `region.offset` bytes into the disk. Every
/// multiplication is checked, because an overflow here would land somewhere
/// plausible rather than somewhere obviously wrong.
pub fn mapExtent(
    group: *const VolumeGroup,
    lv: *const LogicalVolume,
    lv_extent: u64,
) MapError!Mapping {
    if (lv_extent >= lv.extent_count) return error.LvmExtentOutOfRange;
    const extent_bytes = std.math.mul(u64, group.extent_size_sectors, sector_size) catch
        return error.LvmExtentOutOfRange;

    for (lv.segments) |segment| {
        if (lv_extent < segment.start_extent or
            lv_extent >= segment.start_extent + segment.extent_count) continue;

        const linear = switch (segment.mapping) {
            .unsupported => |kind| return kind.err(),
            .linear => |linear| linear,
        };
        const pv = &group.physical_volumes[linear.physical_volume];
        const region = pv.region orelse return error.LvmPhysicalVolumeMissing;

        const into_segment = lv_extent - segment.start_extent;
        const physical_extent = std.math.add(u64, linear.start_extent, into_segment) catch
            return error.LvmExtentOutOfRange;
        const covered = segment.extent_count - into_segment;

        const pe_start_bytes = std.math.mul(u64, pv.pe_start_sectors, sector_size) catch
            return error.LvmExtentOutOfRange;
        const extent_offset = std.math.mul(u64, physical_extent, extent_bytes) catch
            return error.LvmExtentOutOfRange;
        const within_pv = std.math.add(u64, pe_start_bytes, extent_offset) catch
            return error.LvmExtentOutOfRange;
        const length = std.math.mul(u64, covered, extent_bytes) catch
            return error.LvmExtentOutOfRange;

        const end_within_pv = std.math.add(u64, within_pv, length) catch
            return error.LvmExtentOutOfRange;
        if (end_within_pv > region.length) return error.LvmExtentOutOfRange;
        const offset = std.math.add(u64, region.offset, within_pv) catch
            return error.LvmExtentOutOfRange;

        return .{
            .disk = .{ .offset = offset, .length = length },
            .covered_extents = covered,
        };
    }
    return error.LvmExtentOutOfRange;
}

/// The single byte range holding all of `lv`, for the readers that take an
/// offset and a length and nothing else.
///
/// A volume assembled from several runs, or from runs on more than one
/// physical volume, has no such range and is refused rather than silently
/// truncated to its first run.
pub fn contiguousRange(group: *const VolumeGroup, lv: *const LogicalVolume) MapError!Extent {
    if (lv.extent_count == 0 or lv.segments.len == 0) return error.EmptyLogicalVolume;

    const first = try mapExtent(group, lv, 0);
    var covered = first.covered_extents;
    var length = first.disk.length;
    while (covered < lv.extent_count) {
        const next = try mapExtent(group, lv, covered);
        if (next.disk.offset != first.disk.offset + length) {
            return error.LogicalVolumeNotContiguous;
        }
        covered += next.covered_extents;
        length = std.math.add(u64, length, next.disk.length) catch
            return error.LvmExtentOutOfRange;
    }
    return .{ .offset = first.disk.offset, .length = length };
}

// ---------------------------------------------------------------------------
// Building a volume group from parsed text
// ---------------------------------------------------------------------------

/// Turns one committed metadata text into a volume group. Nothing about the
/// disk is consulted: every physical volume comes back with a null `region`,
/// and `scan` matches them to the regions it found by identity.
pub fn parseVolumeGroup(
    arena: Allocator,
    text: []const u8,
) (TextError || MetadataError || Allocator.Error)!VolumeGroup {
    const nodes = try parseText(arena, text);

    const contents = requireString(nodes, "contents") catch return error.UnsupportedLvmMetadataFormat;
    if (!std.mem.eql(u8, contents, "Text Format Volume Group")) {
        return error.UnsupportedLvmMetadataFormat;
    }
    const version = requireUnsigned(nodes, "version") catch return error.UnsupportedLvmMetadataFormat;
    if (version != 1) return error.UnsupportedLvmMetadataFormat;

    var group_node: ?Node = null;
    for (nodes) |node| {
        if (node.value != .section) continue;
        if (group_node != null) return error.InvalidLvmVolumeGroup;
        group_node = node;
    }
    const group = group_node orelse return error.InvalidLvmVolumeGroup;
    const body = group.value.section;

    try validateName(group.name);
    const format = requireString(body, "format") catch return error.UnsupportedLvmMetadataFormat;
    if (!std.mem.eql(u8, format, "lvm2")) return error.UnsupportedLvmMetadataFormat;

    const extent_size = try requireUnsigned(body, "extent_size");
    if (extent_size == 0 or extent_size > std.math.maxInt(u64) / sector_size) {
        return error.InvalidLvmVolumeGroup;
    }

    const pv_nodes = findSection(body, "physical_volumes") orelse
        return error.InvalidLvmVolumeGroup;
    const physical_volumes = try arena.alloc(PhysicalVolume, pv_nodes.len);
    for (pv_nodes, physical_volumes) |node, *pv| {
        const fields = switch (node.value) {
            .section => |children| children,
            else => return error.InvalidLvmVolumeGroup,
        };
        pv.* = .{
            .key = node.name,
            .id = try requireString(fields, "id"),
            .device_hint = if (findNode(fields, "device")) |value| switch (value) {
                .string => |device| device,
                else => "",
            } else "",
            .dev_size_sectors = if (findNode(fields, "dev_size") != null)
                try requireUnsigned(fields, "dev_size")
            else
                0,
            .pe_start_sectors = try requireUnsigned(fields, "pe_start"),
            .pe_count = try requireUnsigned(fields, "pe_count"),
            .region = null,
        };
    }

    const lv_nodes = findSection(body, "logical_volumes") orelse &[_]Node{};
    const logical_volumes = try arena.alloc(LogicalVolume, lv_nodes.len);
    for (lv_nodes, logical_volumes) |node, *lv| {
        const fields = switch (node.value) {
            .section => |children| children,
            else => return error.InvalidLvmVolumeGroup,
        };
        try validateName(node.name);
        lv.* = .{
            .name = node.name,
            .id = try requireString(fields, "id"),
            .visible = hasStatus(fields, "VISIBLE"),
            .segments = try parseSegments(arena, fields, physical_volumes),
            .extent_count = 0,
        };
        for (lv.segments) |segment| lv.extent_count += segment.extent_count;
    }

    return .{
        .name = group.name,
        .id = try requireString(body, "id"),
        .seqno = try requireUnsigned(body, "seqno"),
        .extent_size_sectors = extent_size,
        .physical_volumes = physical_volumes,
        .logical_volumes = logical_volumes,
    };
}

fn parseSegments(
    arena: Allocator,
    lv_fields: []const Node,
    physical_volumes: []const PhysicalVolume,
) (MetadataError || Allocator.Error)![]const Segment {
    const count = try requireUnsigned(lv_fields, "segment_count");
    if (count > lv_fields.len) return error.InvalidLvmVolumeGroup;
    const segments = try arena.alloc(Segment, @intCast(count));

    var name_buffer: [32]u8 = undefined;
    var next_extent: u64 = 0;
    for (segments, 1..) |*segment, index| {
        const name = std.fmt.bufPrint(&name_buffer, "segment{d}", .{index}) catch
            return error.InvalidLvmVolumeGroup;
        const fields = findSection(lv_fields, name) orelse return error.InvalidLvmVolumeGroup;

        const start_extent = try requireUnsigned(fields, "start_extent");
        const extent_count = try requireUnsigned(fields, "extent_count");
        // Segments are numbered in order and must tile the volume exactly. A
        // gap would map an extent nobody allocated; an overlap would give one
        // extent two answers.
        if (start_extent != next_extent or extent_count == 0) {
            return error.InvalidLvmVolumeGroup;
        }
        next_extent = std.math.add(u64, start_extent, extent_count) catch
            return error.InvalidLvmVolumeGroup;

        const type_name = try requireString(fields, "type");
        // The mapping is computed into a local and only then stored, so a
        // half-built segment never becomes visible under a tag that claims
        // it is complete.
        const mapping: SegmentMapping = if (classify(type_name)) |kind|
            .{ .unsupported = kind }
        else
            try parseLinear(fields, extent_count, physical_volumes);
        segment.* = .{
            .start_extent = start_extent,
            .extent_count = extent_count,
            .type_name = type_name,
            .mapping = mapping,
        };
    }
    return segments;
}

/// Reads the one stripe of a linear segment. A `striped` segment with more
/// than one stripe is real striping, which this reader does not map, and is
/// recorded as such rather than having its first stripe treated as the whole
/// mapping.
fn parseLinear(
    fields: []const Node,
    extent_count: u64,
    physical_volumes: []const PhysicalVolume,
) MetadataError!SegmentMapping {
    const stripe_count = try requireUnsigned(fields, "stripe_count");
    if (stripe_count != 1) return .{ .unsupported = .striped };

    const value = findNode(fields, "stripes") orelse return error.InvalidLvmVolumeGroup;
    const items = switch (value) {
        .array => |array| array,
        else => return error.InvalidLvmVolumeGroup,
    };
    // One stripe is a physical volume key followed by the physical extent
    // the run starts at, so exactly two entries.
    if (items.len != 2) return error.InvalidLvmVolumeGroup;

    const key = switch (items[0]) {
        .string => |text| text,
        else => return error.InvalidLvmVolumeGroup,
    };
    const start_extent: u64 = switch (items[1]) {
        .integer => |number| if (number < 0)
            return error.InvalidLvmVolumeGroup
        else
            @intCast(number),
        else => return error.InvalidLvmVolumeGroup,
    };

    const index = for (physical_volumes, 0..) |pv, position| {
        if (std.mem.eql(u8, pv.key, key)) break position;
    } else return error.InvalidLvmVolumeGroup;

    // A run that ends past the physical volume's last extent would map to
    // bytes the volume group never owned.
    const end = std.math.add(u64, start_extent, extent_count) catch
        return error.InvalidLvmVolumeGroup;
    if (end > physical_volumes[index].pe_count) return error.InvalidLvmVolumeGroup;

    return .{ .linear = .{ .physical_volume = index, .start_extent = start_extent } };
}

// ---------------------------------------------------------------------------
// Scanning a disk
// ---------------------------------------------------------------------------

/// Every place on `image` that could hold a physical volume: the disk
/// itself, plus each partition of whatever table it carries. `pvcreate` is
/// routinely pointed at either, and a disk with a partition table may still
/// have been given to `pvcreate` whole, so both are tried.
///
/// A disk with no readable partition table yields only the whole-disk
/// candidate: an unreadable table is not an error here, because a physical
/// volume occupying the whole disk has no table to read in the first place.
pub fn candidateRegions(
    allocator: Allocator,
    image: Image,
    io: Io,
) (Image.PreadError || gpt.ReadError || Allocator.Error)![]Region {
    var regions = std.array_list.Managed(Region).init(allocator);
    errdefer regions.deinit();

    try regions.append(.{
        .offset = 0,
        .length = image.virtual_size,
        .location = .whole_disk,
    });

    var sector: [512]u8 = undefined;
    if (try image.pread(io, &sector, 0) != sector.len) return regions.toOwnedSlice();
    const table = mbr.Mbr.decode(&sector) catch return regions.toOwnedSlice();

    if (table.entries[0].partition_type == .gpt_protective) {
        const parsed = gpt.readGpt(image, io, allocator) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // A protective MBR over an unreadable GPT is a broken disk, but
            // not one this module is entitled to diagnose: the whole-disk
            // candidate still stands.
            else => return regions.toOwnedSlice(),
        };
        defer allocator.free(parsed.partitions);
        for (parsed.partitions) |partition| {
            if (partition.last_lba < partition.first_lba) continue;
            const offset = std.math.mul(u64, partition.first_lba, 512) catch continue;
            const sectors = partition.last_lba - partition.first_lba + 1;
            const length = std.math.mul(u64, sectors, 512) catch continue;
            if (offset >= image.virtual_size) continue;
            try regions.append(.{
                .offset = offset,
                .length = @min(length, image.virtual_size - offset),
                .location = .{ .gpt_partition = partition.table_index + 1 },
            });
        }
        return regions.toOwnedSlice();
    }

    for (table.entries, 1..) |entry, index| {
        if (entry.partition_type == .empty or entry.sector_count == 0) continue;
        // Extended partitions are containers, not physical volumes; their
        // logical partitions would need the chain walked, which no default
        // LVM install produces.
        switch (@intFromEnum(entry.partition_type)) {
            0x05, 0x0f, 0x85 => continue,
            else => {},
        }
        const offset = @as(u64, entry.first_lba) * 512;
        if (offset >= image.virtual_size) continue;
        const length = @as(u64, entry.sector_count) * 512;
        try regions.append(.{
            .offset = offset,
            .length = @min(length, image.virtual_size - offset),
            .location = .{ .mbr_partition = @intCast(index) },
        });
    }
    return regions.toOwnedSlice();
}

/// A physical volume found on the disk, before its metadata has been read.
const FoundPv = struct {
    region: Region,
    label: Label,
};

/// One committed copy of a volume group's metadata, with where it came from.
const Candidate = struct {
    group: VolumeGroup,
    /// Position of the physical volume in the scan order, then the metadata
    /// area within it. Only used to break a sequence-number tie in a fixed
    /// way, so a scan of the same disk always answers the same thing.
    pv_index: usize,
    mda_index: usize,
};

pub const Scan = struct {
    arena: std.heap.ArenaAllocator,
    groups: []const VolumeGroup,

    pub fn deinit(self: *Scan) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// Finds a volume group by name, or the only one there is when `name` is
    /// empty. An empty name with more than one volume group present is
    /// ambiguous and is refused rather than resolved by position.
    pub fn findVolumeGroup(self: *const Scan, name: []const u8) SelectError!*const VolumeGroup {
        if (name.len == 0) {
            if (self.groups.len == 0) return error.LvmVolumeGroupNotFound;
            if (self.groups.len > 1) return error.AmbiguousLvmVolumeGroup;
            return &self.groups[0];
        }
        for (self.groups) |*group| {
            if (std.mem.eql(u8, group.name, name)) return group;
        }
        return error.LvmVolumeGroupNotFound;
    }

    pub fn findLogicalVolume(
        self: *const Scan,
        group_name: []const u8,
        lv_name: []const u8,
    ) SelectError!Selected {
        const group = try self.findVolumeGroup(group_name);
        const volume = group.findLogicalVolume(lv_name) orelse return error.LogicalVolumeNotFound;
        return .{ .group = group, .volume = volume };
    }
};

pub const Selected = struct {
    group: *const VolumeGroup,
    volume: *const LogicalVolume,
};

/// Reads every volume group visible on `image`.
///
/// `image` is taken by value: this call cannot write, and no caller can make
/// it write.
///
/// A region whose first sectors hold no `LABELONE` is simply not a physical
/// volume and is passed over. A region that does carry one is parsed
/// strictly: a bad checksum, an impossible header, or metadata that does not
/// describe a volume group is corruption, and reporting it beats quietly
/// returning a shorter list than the disk really has.
///
/// Where several physical volumes carry copies of one volume group's
/// metadata -- the normal case, since every physical volume in a group keeps
/// its own -- the copy with the highest `seqno` wins, because `seqno` is
/// what LVM2 increments on each committed change. Ties, which mean the
/// copies agree, are settled by scan order so the same disk always reads the
/// same way.
pub fn scan(allocator: Allocator, image: Image, io: Io) ScanError!Scan {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const scratch = arena.allocator();

    const regions = try candidateRegions(scratch, image, io);

    var found = std.array_list.Managed(FoundPv).init(scratch);
    for (regions) |region| {
        const label = try readLabel(image, io, region) orelse continue;
        // The same physical volume can sit inside a candidate region and
        // inside the whole-disk candidate that contains it; the first sight
        // of it is the more specific one and is kept.
        const duplicate = for (found.items) |existing| {
            if (std.mem.eql(u8, &existing.label.pv_uuid, &label.pv_uuid)) break true;
        } else false;
        if (duplicate) continue;
        try found.append(.{ .region = region, .label = label });
    }

    var candidates = std.array_list.Managed(Candidate).init(scratch);
    for (found.items, 0..) |pv, pv_index| {
        for (pv.label.metadataAreas(), 0..) |area, mda_index| {
            const header = try readMetadataAreaHeader(image, io, pv.region, area);
            const text = try readMetadataText(scratch, image, io, pv.region, area, header) orelse
                continue;
            try candidates.append(.{
                .group = try parseVolumeGroup(scratch, text),
                .pv_index = pv_index,
                .mda_index = mda_index,
            });
        }
    }

    var groups = std.array_list.Managed(VolumeGroup).init(scratch);
    for (candidates.items, 0..) |candidate, index| {
        // Keep exactly one copy per volume group identity: the newest, and
        // among equally new ones the first encountered.
        const newest = for (candidates.items, 0..) |other, other_index| {
            if (!std.mem.eql(u8, other.group.id, candidate.group.id)) continue;
            if (other.group.seqno > candidate.group.seqno) break false;
            if (other.group.seqno == candidate.group.seqno and other_index < index) break false;
        } else true;
        if (!newest) continue;

        for (groups.items) |existing| {
            // Distinct volume groups sharing a name cannot both be selected
            // by that name, and picking one would be a guess.
            if (std.mem.eql(u8, existing.name, candidate.group.name)) {
                return error.DuplicateLvmVolumeGroup;
            }
        }

        for (candidate.group.physical_volumes) |*pv| {
            pv.region = locatePhysicalVolume(found.items, pv.id);
        }
        try groups.append(candidate.group);
    }

    // Built fully before it is published so no caller can observe a scan
    // whose group list is still being filled.
    const owned = try groups.toOwnedSlice();
    return .{ .arena = arena, .groups = owned };
}

/// Matches a physical volume identity from the metadata text, which is
/// written with dashes, against the 32 undashed characters in a label.
fn locatePhysicalVolume(found: []const FoundPv, id: []const u8) ?Region {
    var undashed: [32]u8 = undefined;
    var len: usize = 0;
    for (id) |byte| {
        if (byte == '-') continue;
        if (len == undashed.len) return null;
        undashed[len] = byte;
        len += 1;
    }
    if (len != undashed.len) return null;
    for (found) |pv| {
        if (std.mem.eql(u8, &pv.label.pv_uuid, &undashed)) return pv.region;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests
//
// `lvm2` needs root and device-mapper, so it cannot create a fixture here.
// The on-disk format is small enough to build byte by byte instead, which is
// also the only way to reach the cases that matter most: a wrapped circular
// buffer, a stale copy sitting next to a newer one, and each segment type
// that must be refused.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Spells a 32-character physical volume identity the way the metadata text
/// does, in 6-4-4-4-4-4-6 groups.
fn dashed(raw: [32]u8) [38]u8 {
    var out: [38]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out);
    writer.print("{s}-{s}-{s}-{s}-{s}-{s}-{s}", .{
        raw[0..6],   raw[6..10],  raw[10..14], raw[14..18],
        raw[18..22], raw[22..26], raw[26..32],
    }) catch unreachable;
    return out;
}

const LabelSpec = struct {
    sector: u64 = 1,
    pv_uuid: [32]u8,
    device_size: u64,
    data_areas: []const DiskLocn = &.{},
    metadata_areas: []const DiskLocn = &.{},
    /// Written into `type[8]`, so a test can present an unknown format.
    type_id: [8]u8 = label_type,
};

fn buildLabelSector(spec: LabelSpec) [label_size]u8 {
    var sector = [_]u8{0} ** label_size;
    sector[0..8].* = label_id;
    std.mem.writeInt(u64, sector[8..16], spec.sector, .little);
    std.mem.writeInt(u32, sector[20..24], 32, .little);
    sector[24..32].* = spec.type_id;

    const header: usize = 32;
    sector[header..][0..32].* = spec.pv_uuid;
    std.mem.writeInt(u64, sector[header + 32 ..][0..8], spec.device_size, .little);

    var cursor: usize = header + 40;
    for (spec.data_areas) |area| {
        std.mem.writeInt(u64, sector[cursor..][0..8], area.offset, .little);
        std.mem.writeInt(u64, sector[cursor + 8 ..][0..8], area.size, .little);
        cursor += 16;
    }
    cursor += 16; // null terminator for the data-area list
    for (spec.metadata_areas) |area| {
        std.mem.writeInt(u64, sector[cursor..][0..8], area.offset, .little);
        std.mem.writeInt(u64, sector[cursor + 8 ..][0..8], area.size, .little);
        cursor += 16;
    }

    std.mem.writeInt(u32, sector[16..20], crc(crc_initial, sector[20..]), .little);
    return sector;
}

const MdaSpec = struct {
    /// Absolute offset of the metadata area within the physical volume.
    start: u64,
    size: u64,
    /// Where the committed text begins within the area. Anything at or past
    /// `size - text.len - 1` exercises the wrap.
    text_offset: u64 = metadata_area_header_size,
    text: []const u8,
    ignored: bool = false,
    /// Corrupts the stored text checksum without touching the text.
    break_text_checksum: bool = false,
    version: u32 = metadata_area_version,
    magic: [16]u8 = metadata_area_magic,
};

/// Fills `area` (which must be exactly `spec.size` bytes long) with a
/// metadata-area header and one committed metadata text, wrapping the text
/// around the end of the buffer the way LVM2 does.
fn writeMetadataArea(area: []u8, spec: MdaSpec) void {
    std.debug.assert(area.len == spec.size);
    @memset(area, 0);

    const usable = spec.size - metadata_area_header_size;
    const stored_len = spec.text.len + 1; // the trailing NUL is part of the copy
    std.debug.assert(stored_len <= usable);

    var buffer = std.array_list.Managed(u8).init(testing.allocator);
    defer buffer.deinit();
    buffer.appendSlice(spec.text) catch unreachable;
    buffer.append(0) catch unreachable;

    var position = spec.text_offset;
    for (buffer.items) |byte| {
        area[@intCast(position)] = byte;
        position += 1;
        if (position == spec.size) position = metadata_area_header_size;
    }

    var checksum = crc(crc_initial, buffer.items);
    if (spec.break_text_checksum) checksum +%= 1;

    area[4..20].* = spec.magic;
    std.mem.writeInt(u32, area[20..24], spec.version, .little);
    std.mem.writeInt(u64, area[24..32], spec.start, .little);
    std.mem.writeInt(u64, area[32..40], spec.size, .little);
    std.mem.writeInt(u64, area[40..48], spec.text_offset, .little);
    std.mem.writeInt(u64, area[48..56], stored_len, .little);
    std.mem.writeInt(u32, area[56..60], checksum, .little);
    std.mem.writeInt(u32, area[60..64], if (spec.ignored) raw_locn_ignored else 0, .little);
    std.mem.writeInt(u32, area[0..4], crc(crc_initial, area[4..metadata_area_header_size]), .little);
}

const test_mda_offset: u64 = 4096;
const test_mda_size: u64 = 64 * 1024;
const test_pe_start: u64 = 2048; // sectors, the 1 MiB default
const test_extent_size: u64 = 8192; // sectors, the 4 MiB default

const test_pv0: [32]u8 = "0123456789abcdefghijklmnopqrstuv".*;
const test_pv1: [32]u8 = "wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01".*;
const test_vg_id: [32]u8 = "VG000000000000000000000000000000".*;
const test_lv_id: [32]u8 = "LV000000000000000000000000000000".*;

/// Assembles a physical volume image: a label at sector 1 pointing at one
/// metadata area holding `text`.
fn buildPv(allocator: Allocator, size: u64, uuid: [32]u8, spec: MdaSpec) ![]u8 {
    const bytes = try allocator.alloc(u8, @intCast(size));
    @memset(bytes, 0);
    const areas = [_]DiskLocn{.{ .offset = spec.start, .size = spec.size }};
    const data = [_]DiskLocn{.{ .offset = test_pe_start * sector_size, .size = 0 }};
    const label = buildLabelSector(.{
        .pv_uuid = uuid,
        .device_size = size,
        .data_areas = &data,
        .metadata_areas = &areas,
    });
    @memcpy(bytes[512..1024], &label);
    writeMetadataArea(bytes[@intCast(spec.start)..][0..@intCast(spec.size)], spec);
    return bytes;
}

const VgTextSpec = struct {
    vg_name: []const u8 = "vg",
    vg_id: [32]u8 = test_vg_id,
    seqno: u64 = 1,
    extent_size: u64 = test_extent_size,
    physical_volumes: []const u8,
    logical_volumes: []const u8,
};

fn vgText(allocator: Allocator, spec: VgTextSpec) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\# Generated by a test
        \\contents = "Text Format Volume Group"
        \\version = 1
        \\description = ""
        \\creation_host = "fixture"
        \\creation_time = 1700000000
        \\
        \\{s} {{
        \\id = "{s}"
        \\seqno = {d}
        \\format = "lvm2"
        \\status = ["RESIZEABLE", "READ", "WRITE"]
        \\flags = []
        \\extent_size = {d}
        \\max_lv = 0
        \\max_pv = 0
        \\metadata_copies = 0
        \\
        \\physical_volumes {{
        \\{s}
        \\}}
        \\
        \\logical_volumes {{
        \\{s}
        \\}}
        \\}}
        \\
    , .{ spec.vg_name, &dashed(spec.vg_id), spec.seqno, spec.extent_size, spec.physical_volumes, spec.logical_volumes });
}

fn pvText(allocator: Allocator, key: []const u8, uuid: [32]u8, pe_count: u64) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{s} {{
        \\id = "{s}"
        \\device = "/dev/vda3"
        \\status = ["ALLOCATABLE"]
        \\flags = []
        \\dev_size = 65536
        \\pe_start = {d}
        \\pe_count = {d}
        \\}}
    , .{ key, &dashed(uuid), test_pe_start, pe_count });
}

fn linearLvText(
    allocator: Allocator,
    name: []const u8,
    pv_key: []const u8,
    start_pe: u64,
    extents: u64,
) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{s} {{
        \\id = "{s}"
        \\status = ["READ", "WRITE", "VISIBLE"]
        \\flags = []
        \\segment_count = 1
        \\
        \\segment1 {{
        \\start_extent = 0
        \\extent_count = {d}
        \\type = "striped"
        \\stripe_count = 1
        \\stripes = [
        \\"{s}", {d}
        \\]
        \\}}
        \\}}
    , .{ name, &dashed(test_lv_id), extents, pv_key, start_pe });
}

/// A one-physical-volume, one-logical-volume group: the shape a default
/// Ubuntu or Debian guided install produces.
fn simpleVgText(allocator: Allocator, seqno: u64, extents: u64, start_pe: u64) ![]u8 {
    const pv = try pvText(allocator, "pv0", test_pv0, 1024);
    defer allocator.free(pv);
    const lv = try linearLvText(allocator, "root", "pv0", start_pe, extents);
    defer allocator.free(lv);
    return vgText(allocator, .{
        .seqno = seqno,
        .physical_volumes = pv,
        .logical_volumes = lv,
    });
}

test "the LVM2 CRC table is the reflected 0xedb88320 polynomial" {
    // Transcribed tables are exactly the kind of thing that survives a typo,
    // so the table is rebuilt from the polynomial it encodes.
    for (crc_table, 0..) |entry, index| {
        var value: u32 = @intCast(index);
        var bit: usize = 0;
        while (bit < 4) : (bit += 1) {
            value = if (value & 1 != 0) (value >> 1) ^ 0xedb88320 else value >> 1;
        }
        try testing.expectEqual(entry, value);
    }
}

test "crc chains across a split buffer the way a wrapped copy needs" {
    const whole = "the quick brown fox";
    const split = crc(crc(crc_initial, whole[0..7]), whole[7..]);
    try testing.expectEqual(crc(crc_initial, whole), split);
}

test "parseLabelSector reads the physical volume header and its area lists" {
    const data = [_]DiskLocn{.{ .offset = 1048576, .size = 0 }};
    const mdas = [_]DiskLocn{.{ .offset = 4096, .size = 1044480 }};
    const sector = buildLabelSector(.{
        .pv_uuid = test_pv0,
        .device_size = 1 << 30,
        .data_areas = &data,
        .metadata_areas = &mdas,
    });

    const label = try parseLabelSector(&sector, 1);
    try testing.expectEqualSlices(u8, &test_pv0, &label.pv_uuid);
    try testing.expectEqual(@as(u64, 1 << 30), label.device_size);
    try testing.expectEqual(@as(usize, 1), label.dataAreas().len);
    try testing.expectEqual(@as(u64, 1048576), label.dataAreas()[0].offset);
    try testing.expectEqual(@as(usize, 1), label.metadataAreas().len);
    try testing.expectEqual(@as(u64, 1044480), label.metadataAreas()[0].size);
}

test "parseLabelSector rejects a corrupted label" {
    var sector = buildLabelSector(.{ .pv_uuid = test_pv0, .device_size = 4096 });
    sector[100] +%= 1;
    try testing.expectError(error.BadLvmLabelChecksum, parseLabelSector(&sector, 1));
}

test "parseLabelSector rejects a label that names another sector" {
    const sector = buildLabelSector(.{ .sector = 2, .pv_uuid = test_pv0, .device_size = 4096 });
    try testing.expectError(error.InvalidLvmLabel, parseLabelSector(&sector, 1));
}

test "parseLabelSector rejects a label format it does not know" {
    const sector = buildLabelSector(.{
        .pv_uuid = test_pv0,
        .device_size = 4096,
        .type_id = "LVM2 002".*,
    });
    try testing.expectError(error.UnsupportedLvmLabelType, parseLabelSector(&sector, 1));
}

test "parseLabelSector rejects a physical volume header outside the label sector" {
    var sector = buildLabelSector(.{ .pv_uuid = test_pv0, .device_size = 4096 });
    // Point the physical volume header so far into the sector that its
    // fixed part would not fit, then re-checksum so only the offset is wrong.
    std.mem.writeInt(u32, sector[20..24], 500, .little);
    std.mem.writeInt(u32, sector[16..20], crc(crc_initial, sector[20..]), .little);
    try testing.expectError(error.InvalidLvmPvHeader, parseLabelSector(&sector, 1));

    std.mem.writeInt(u32, sector[20..24], 8, .little);
    std.mem.writeInt(u32, sector[16..20], crc(crc_initial, sector[20..]), .little);
    try testing.expectError(error.InvalidLvmPvHeader, parseLabelSector(&sector, 1));
}

test "parseLabelSector rejects an implausible number of disk areas" {
    var areas: [max_disk_areas + 1]DiskLocn = undefined;
    for (&areas, 1..) |*area, index| area.* = .{ .offset = index * 4096, .size = 4096 };
    const sector = buildLabelSector(.{
        .pv_uuid = test_pv0,
        .device_size = 4096,
        .data_areas = &areas,
    });
    try testing.expectError(error.TooManyLvmDiskAreas, parseLabelSector(&sector, 1));
}

test "parseMetadataAreaHeader validates magic, version, position and size" {
    var area: [1024]u8 = undefined;
    const locn = DiskLocn{ .offset = 4096, .size = 1024 };

    writeMetadataArea(&area, .{ .start = 4096, .size = 1024, .text = "x" });
    const header = try parseMetadataAreaHeader(area[0..512], locn);
    try testing.expectEqual(@as(u64, 4096), header.start);
    try testing.expectEqual(@as(u64, 1024), header.size);

    writeMetadataArea(&area, .{ .start = 4096, .size = 1024, .text = "x", .magic = "not lvm2 magic!!".* });
    try testing.expectError(
        error.InvalidLvmMetadataArea,
        parseMetadataAreaHeader(area[0..512], locn),
    );

    writeMetadataArea(&area, .{ .start = 4096, .size = 1024, .text = "x", .version = 2 });
    try testing.expectError(
        error.UnsupportedLvmMetadataAreaVersion,
        parseMetadataAreaHeader(area[0..512], locn),
    );

    // A header that says it lives somewhere other than where the physical
    // volume header points describes a different area.
    writeMetadataArea(&area, .{ .start = 8192, .size = 1024, .text = "x" });
    try testing.expectError(
        error.InvalidLvmMetadataArea,
        parseMetadataAreaHeader(area[0..512], locn),
    );

    writeMetadataArea(&area, .{ .start = 4096, .size = 1024, .text = "x" });
    area[100] +%= 1;
    try testing.expectError(
        error.BadLvmMetadataAreaChecksum,
        parseMetadataAreaHeader(area[0..512], locn),
    );
}

/// Wraps a physical volume image in an `Image` so the reading entry points
/// can be exercised. The caller closes the image and removes the file.
fn writeTestImage(io: Io, path: []const u8, bytes: []const u8) !Image {
    var img = try Image.create(io, path, .raw, bytes.len, .{});
    errdefer img.close(io);
    try img.pwrite(io, bytes, 0);
    return img;
}

fn wholeDisk(len: u64) Region {
    return .{ .offset = 0, .length = len, .location = .whole_disk };
}

test "readMetadataText reassembles a copy that wraps the circular buffer" {
    const io = testing.io;
    const path = "test-lvm-wrap.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const text = try simpleVgText(allocator, 7, 25, 0);
    defer allocator.free(text);

    // Start the copy close enough to the end of the area that most of it has
    // to resume just after the header.
    const text_offset = test_mda_size - 64;
    const bytes = try buildPv(allocator, 1 << 20, test_pv0, .{
        .start = test_mda_offset,
        .size = test_mda_size,
        .text_offset = text_offset,
        .text = text,
    });
    defer allocator.free(bytes);

    var img = try writeTestImage(io, path, bytes);
    defer img.close(io);

    const region = wholeDisk(bytes.len);
    const label = (try readLabel(img, io, region)).?;
    const area = label.metadataAreas()[0];
    const header = try readMetadataAreaHeader(img, io, region, area);
    const read = (try readMetadataText(allocator, img, io, region, area, header)).?;
    defer allocator.free(read);

    try testing.expectEqual(text.len + 1, read.len);
    try testing.expectEqualStrings(text, read[0..text.len]);
    try testing.expectEqual(@as(u8, 0), read[text.len]);
}

test "readMetadataText refuses a copy whose checksum does not match" {
    const io = testing.io;
    const path = "test-lvm-badsum.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const text = try simpleVgText(allocator, 1, 4, 0);
    defer allocator.free(text);
    const bytes = try buildPv(allocator, 1 << 20, test_pv0, .{
        .start = test_mda_offset,
        .size = test_mda_size,
        .text = text,
        .break_text_checksum = true,
    });
    defer allocator.free(bytes);

    var img = try writeTestImage(io, path, bytes);
    defer img.close(io);

    const region = wholeDisk(bytes.len);
    const label = (try readLabel(img, io, region)).?;
    const area = label.metadataAreas()[0];
    const header = try readMetadataAreaHeader(img, io, region, area);
    try testing.expectError(
        error.BadLvmMetadataChecksum,
        readMetadataText(allocator, img, io, region, area, header),
    );
}

test "readMetadataText passes over an area flagged as deliberately stale" {
    const io = testing.io;
    const path = "test-lvm-ignored.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const text = try simpleVgText(allocator, 1, 4, 0);
    defer allocator.free(text);
    const bytes = try buildPv(allocator, 1 << 20, test_pv0, .{
        .start = test_mda_offset,
        .size = test_mda_size,
        .text = text,
        .ignored = true,
    });
    defer allocator.free(bytes);

    var img = try writeTestImage(io, path, bytes);
    defer img.close(io);

    const region = wholeDisk(bytes.len);
    const label = (try readLabel(img, io, region)).?;
    const area = label.metadataAreas()[0];
    const header = try readMetadataAreaHeader(img, io, region, area);
    try testing.expectEqual(
        @as(?[]u8, null),
        try readMetadataText(allocator, img, io, region, area, header),
    );
}

test "readMetadataText refuses a location outside the metadata area" {
    const io = testing.io;
    const path = "test-lvm-oob.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const bytes = try buildPv(allocator, 1 << 20, test_pv0, .{
        .start = test_mda_offset,
        .size = test_mda_size,
        .text = "x",
    });
    defer allocator.free(bytes);

    var img = try writeTestImage(io, path, bytes);
    defer img.close(io);

    const region = wholeDisk(bytes.len);
    const label = (try readLabel(img, io, region)).?;
    const area = label.metadataAreas()[0];
    var header = try readMetadataAreaHeader(img, io, region, area);
    header.committed.offset = test_mda_size;
    try testing.expectError(
        error.InvalidLvmMetadataLocation,
        readMetadataText(allocator, img, io, region, area, header),
    );

    header.committed.offset = metadata_area_header_size;
    header.committed.size = test_mda_size;
    try testing.expectError(
        error.InvalidLvmMetadataLocation,
        readMetadataText(allocator, img, io, region, area, header),
    );
}

test "readLabel ignores a region that holds no physical volume" {
    const io = testing.io;
    const path = "test-lvm-nolabel.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const bytes = try allocator.alloc(u8, 1 << 16);
    defer allocator.free(bytes);
    @memset(bytes, 0);

    var img = try writeTestImage(io, path, bytes);
    defer img.close(io);

    try testing.expectEqual(
        @as(?Label, null),
        try readLabel(img, io, wholeDisk(bytes.len)),
    );
}

test "parseText handles sections, arrays, comments and escaped strings" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const nodes = try parseText(arena.allocator(),
        \\# leading comment
        \\name = "a \"quoted\" name"
        \\count = -1 # trailing comment
        \\outer {
        \\inner {
        \\list = ["one", 2]
        \\empty = []
        \\}
        \\}
        \\
    ++ "\x00trailing garbage after the NUL {{{");

    try testing.expectEqualStrings("a \"quoted\" name", (findNode(nodes, "name").?).string);
    try testing.expectEqual(@as(i64, -1), (findNode(nodes, "count").?).integer);
    const inner = findSection(findSection(nodes, "outer").?, "inner").?;
    const list = (findNode(inner, "list").?).array;
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqualStrings("one", list[0].string);
    try testing.expectEqual(@as(i64, 2), list[1].integer);
    try testing.expectEqual(@as(usize, 0), (findNode(inner, "empty").?).array.len);
}

test "parseText refuses text it cannot represent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectError(error.InvalidLvmMetadataText, parseText(allocator, "a = "));
    try testing.expectError(error.InvalidLvmMetadataText, parseText(allocator, "a { b = 1"));
    try testing.expectError(error.InvalidLvmMetadataText, parseText(allocator, "}"));
    try testing.expectError(error.InvalidLvmMetadataText, parseText(allocator, "a = \"unterminated"));
    try testing.expectError(error.UnsupportedLvmMetadataValue, parseText(allocator, "a = 1.5"));
}

test "parseVolumeGroup reads a default single-volume install" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const text = try simpleVgText(allocator, 12, 25, 3);
    const group = try parseVolumeGroup(allocator, text);

    try testing.expectEqualStrings("vg", group.name);
    try testing.expectEqualStrings(&dashed(test_vg_id), group.id);
    try testing.expectEqual(@as(u64, 12), group.seqno);
    try testing.expectEqual(test_extent_size, group.extent_size_sectors);
    try testing.expectEqual(@as(u64, 4 * 1024 * 1024), group.extentSizeBytes());

    try testing.expectEqual(@as(usize, 1), group.physical_volumes.len);
    try testing.expectEqual(test_pe_start, group.physical_volumes[0].pe_start_sectors);
    try testing.expectEqual(@as(u64, 1024), group.physical_volumes[0].pe_count);
    try testing.expect(group.physical_volumes[0].region == null);
    try testing.expect(!group.complete());

    const lv = group.findLogicalVolume("root").?;
    try testing.expect(lv.visible);
    try testing.expectEqual(@as(u64, 25), lv.extent_count);
    try testing.expectEqual(@as(u64, 100 * 1024 * 1024), group.sizeBytes(lv));
    try testing.expectEqual(@as(usize, 1), lv.segments.len);
    try testing.expectEqual(@as(u64, 3), lv.segments[0].mapping.linear.start_extent);
    try testing.expect(group.findLogicalVolume("swap") == null);
}

test "parseVolumeGroup refuses metadata that is not a volume group" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectError(
        error.UnsupportedLvmMetadataFormat,
        parseVolumeGroup(allocator, "contents = \"Text Format Config\"\nversion = 1\n"),
    );
    try testing.expectError(
        error.UnsupportedLvmMetadataFormat,
        parseVolumeGroup(allocator, "contents = \"Text Format Volume Group\"\nversion = 2\n"),
    );
}

test "parseVolumeGroup refuses segments that do not tile the volume" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const pv = try pvText(allocator, "pv0", test_pv0, 1024);
    // Two segments with a gap between them: extent 10 through 19 would have
    // no mapping at all.
    const lv = try std.fmt.allocPrint(allocator,
        \\root {{
        \\id = "{s}"
        \\status = ["READ", "WRITE", "VISIBLE"]
        \\segment_count = 2
        \\segment1 {{
        \\start_extent = 0
        \\extent_count = 10
        \\type = "striped"
        \\stripe_count = 1
        \\stripes = ["pv0", 0]
        \\}}
        \\segment2 {{
        \\start_extent = 20
        \\extent_count = 10
        \\type = "striped"
        \\stripe_count = 1
        \\stripes = ["pv0", 20]
        \\}}
        \\}}
    , .{&dashed(test_lv_id)});
    const text = try vgText(allocator, .{ .physical_volumes = pv, .logical_volumes = lv });

    try testing.expectError(error.InvalidLvmVolumeGroup, parseVolumeGroup(allocator, text));
}

test "parseVolumeGroup refuses a run that leaves its physical volume" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // The physical volume has 10 extents; the run wants extents 5 through 14.
    const pv = try pvText(allocator, "pv0", test_pv0, 10);
    const lv = try linearLvText(allocator, "root", "pv0", 5, 10);
    const text = try vgText(allocator, .{ .physical_volumes = pv, .logical_volumes = lv });
    try testing.expectError(error.InvalidLvmVolumeGroup, parseVolumeGroup(allocator, text));
}

test "parseVolumeGroup refuses a stripe naming a physical volume the group lacks" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const pv = try pvText(allocator, "pv0", test_pv0, 1024);
    const lv = try linearLvText(allocator, "root", "pv7", 0, 4);
    const text = try vgText(allocator, .{ .physical_volumes = pv, .logical_volumes = lv });
    try testing.expectError(error.InvalidLvmVolumeGroup, parseVolumeGroup(allocator, text));
}

test "classify recognises single-stripe striped and refuses everything else" {
    try testing.expectEqual(@as(?Unsupported, null), classify("striped"));
    try testing.expectEqual(@as(?Unsupported, null), classify("linear"));
    try testing.expectEqual(Unsupported.mirror, classify("mirror").?);
    try testing.expectEqual(Unsupported.raid, classify("raid1").?);
    try testing.expectEqual(Unsupported.raid, classify("raid5_ls").?);
    try testing.expectEqual(Unsupported.thin, classify("thin").?);
    try testing.expectEqual(Unsupported.thin, classify("thin-pool").?);
    try testing.expectEqual(Unsupported.cache, classify("cache").?);
    try testing.expectEqual(Unsupported.cache, classify("cache-pool").?);
    try testing.expectEqual(Unsupported.cache, classify("writecache").?);
    try testing.expectEqual(Unsupported.snapshot, classify("snapshot").?);
    try testing.expectEqual(Unsupported.other, classify("vdo").?);
    try testing.expectEqual(Unsupported.other, classify("error").?);
    try testing.expectEqual(Unsupported.other, classify("zero").?);
}

/// Builds a group whose single volume is one segment of `type_name`, so the
/// refusal for that type can be observed end to end.
fn groupWithSegmentType(allocator: Allocator, type_name: []const u8, stripes: u64) !VolumeGroup {
    const pv = try pvText(allocator, "pv0", test_pv0, 1024);
    const lv = try std.fmt.allocPrint(allocator,
        \\root {{
        \\id = "{s}"
        \\status = ["READ", "WRITE", "VISIBLE"]
        \\segment_count = 1
        \\segment1 {{
        \\start_extent = 0
        \\extent_count = 4
        \\type = "{s}"
        \\stripe_count = {d}
        \\stripes = ["pv0", 0, "pv0", 8]
        \\}}
        \\}}
    , .{ &dashed(test_lv_id), type_name, stripes });
    const text = try vgText(allocator, .{ .physical_volumes = pv, .logical_volumes = lv });
    var group = try parseVolumeGroup(allocator, text);
    group.physical_volumes[0].region = wholeDisk(1 << 30);
    return group;
}

test "mapExtent refuses each segment type it does not understand, distinguishably" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const cases = [_]struct { type_name: []const u8, expected: anyerror }{
        .{ .type_name = "mirror", .expected = error.UnsupportedLvmMirrorSegment },
        .{ .type_name = "raid1", .expected = error.UnsupportedLvmRaidSegment },
        .{ .type_name = "raid5_ls", .expected = error.UnsupportedLvmRaidSegment },
        .{ .type_name = "thin", .expected = error.UnsupportedLvmThinSegment },
        .{ .type_name = "thin-pool", .expected = error.UnsupportedLvmThinSegment },
        .{ .type_name = "cache", .expected = error.UnsupportedLvmCacheSegment },
        .{ .type_name = "cache-pool", .expected = error.UnsupportedLvmCacheSegment },
        .{ .type_name = "writecache", .expected = error.UnsupportedLvmCacheSegment },
        .{ .type_name = "snapshot", .expected = error.UnsupportedLvmSnapshotSegment },
        .{ .type_name = "vdo", .expected = error.UnsupportedLvmSegmentType },
    };
    for (cases) |case| {
        const group = try groupWithSegmentType(allocator, case.type_name, 1);
        const lv = group.findLogicalVolume("root").?;
        // The volume is still enumerated: only the mapping is refused, so
        // `miz map` can name what it found and say why it cannot use it.
        try testing.expectEqualStrings(case.type_name, lv.segments[0].type_name);
        try testing.expectEqual(@as(u64, 4), lv.extent_count);
        try testing.expectError(case.expected, mapExtent(&group, lv, 0));
        try testing.expectError(case.expected, contiguousRange(&group, lv));
    }
}

test "mapExtent refuses a striped segment with more than one stripe" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Real striping wears the same type name as a linear mapping and is told
    // apart only by `stripe_count`, so reading the first stripe as the whole
    // volume would produce data that looks right and is not.
    const group = try groupWithSegmentType(arena.allocator(), "striped", 2);
    const lv = group.findLogicalVolume("root").?;
    try testing.expectError(error.UnsupportedLvmStripedSegment, mapExtent(&group, lv, 0));
}

test "mapExtent computes exact byte offsets from pe_start and extent size" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // The volume starts at physical extent 3 of a physical volume that sits
    // 1 MiB into the disk, with a 1 MiB pe_start and 4 MiB extents.
    const text = try simpleVgText(allocator, 1, 25, 3);
    var group = try parseVolumeGroup(allocator, text);
    const region_offset: u64 = 1024 * 1024;
    group.physical_volumes[0].region = .{
        .offset = region_offset,
        .length = 8 * 1024 * 1024 * 1024,
        .location = .{ .gpt_partition = 3 },
    };
    const lv = group.findLogicalVolume("root").?;

    const extent_bytes: u64 = 4 * 1024 * 1024;
    const pe_start_bytes: u64 = test_pe_start * sector_size;
    try testing.expectEqual(@as(u64, 1024 * 1024), pe_start_bytes);

    const first = try mapExtent(&group, lv, 0);
    try testing.expectEqual(region_offset + pe_start_bytes + 3 * extent_bytes, first.disk.offset);
    try testing.expectEqual(@as(u64, 25), first.covered_extents);
    try testing.expectEqual(25 * extent_bytes, first.disk.length);
    // Spelled out: 1 MiB + 1 MiB + 3 * 4 MiB = 14 MiB.
    try testing.expectEqual(@as(u64, 14 * 1024 * 1024), first.disk.offset);

    const middle = try mapExtent(&group, lv, 7);
    try testing.expectEqual(@as(u64, (14 + 7 * 4) * 1024 * 1024), middle.disk.offset);
    try testing.expectEqual(@as(u64, 25 - 7), middle.covered_extents);

    const last = try mapExtent(&group, lv, 24);
    try testing.expectEqual(@as(u64, (14 + 24 * 4) * 1024 * 1024), last.disk.offset);
    try testing.expectEqual(extent_bytes, last.disk.length);

    try testing.expectError(error.LvmExtentOutOfRange, mapExtent(&group, lv, 25));

    const whole = try contiguousRange(&group, lv);
    try testing.expectEqual(@as(u64, 14 * 1024 * 1024), whole.offset);
    try testing.expectEqual(@as(u64, 100 * 1024 * 1024), whole.length);
}

test "mapExtent refuses a mapping that would run past the physical volume" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const text = try simpleVgText(allocator, 1, 25, 0);
    var group = try parseVolumeGroup(allocator, text);
    // A region far too small for the extents the metadata claims: reading
    // there would return bytes belonging to whatever follows.
    group.physical_volumes[0].region = wholeDisk(4 * 1024 * 1024);
    const lv = group.findLogicalVolume("root").?;
    try testing.expectError(error.LvmExtentOutOfRange, mapExtent(&group, lv, 0));
}

test "contiguousRange joins adjacent segments and refuses a split volume" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const pv = try pvText(allocator, "pv0", test_pv0, 1024);
    const adjacent = try std.fmt.allocPrint(allocator,
        \\root {{
        \\id = "{s}"
        \\status = ["READ", "WRITE", "VISIBLE"]
        \\segment_count = 2
        \\segment1 {{
        \\start_extent = 0
        \\extent_count = 4
        \\type = "striped"
        \\stripe_count = 1
        \\stripes = ["pv0", 10]
        \\}}
        \\segment2 {{
        \\start_extent = 4
        \\extent_count = 6
        \\type = "striped"
        \\stripe_count = 1
        \\stripes = ["pv0", {d}]
        \\}}
        \\}}
    , .{ &dashed(test_lv_id), @as(u64, 14) });
    const joined_text = try vgText(allocator, .{ .physical_volumes = pv, .logical_volumes = adjacent });
    var joined = try parseVolumeGroup(allocator, joined_text);
    joined.physical_volumes[0].region = wholeDisk(8 * 1024 * 1024 * 1024);
    const joined_lv = joined.findLogicalVolume("root").?;

    const extent_bytes: u64 = 4 * 1024 * 1024;
    const range = try contiguousRange(&joined, joined_lv);
    try testing.expectEqual(test_pe_start * sector_size + 10 * extent_bytes, range.offset);
    try testing.expectEqual(10 * extent_bytes, range.length);

    // The same volume with its second run somewhere else has no single byte
    // range, and answering with the first run would silently truncate it.
    const split = try std.fmt.allocPrint(allocator,
        \\root {{
        \\id = "{s}"
        \\status = ["READ", "WRITE", "VISIBLE"]
        \\segment_count = 2
        \\segment1 {{
        \\start_extent = 0
        \\extent_count = 4
        \\type = "striped"
        \\stripe_count = 1
        \\stripes = ["pv0", 10]
        \\}}
        \\segment2 {{
        \\start_extent = 4
        \\extent_count = 6
        \\type = "striped"
        \\stripe_count = 1
        \\stripes = ["pv0", 100]
        \\}}
        \\}}
    , .{&dashed(test_lv_id)});
    const split_text = try vgText(allocator, .{ .physical_volumes = pv, .logical_volumes = split });
    var split_group = try parseVolumeGroup(allocator, split_text);
    split_group.physical_volumes[0].region = wholeDisk(8 * 1024 * 1024 * 1024);
    const split_lv = split_group.findLogicalVolume("root").?;
    try testing.expectError(
        error.LogicalVolumeNotContiguous,
        contiguousRange(&split_group, split_lv),
    );
}

test "mapExtent reports a volume group whose other disk was not supplied" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const pv0 = try pvText(allocator, "pv0", test_pv0, 1024);
    const pv1 = try pvText(allocator, "pv1", test_pv1, 1024);
    const both = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ pv0, pv1 });
    const lv = try linearLvText(allocator, "root", "pv1", 0, 4);
    const text = try vgText(allocator, .{ .physical_volumes = both, .logical_volumes = lv });

    var group = try parseVolumeGroup(allocator, text);
    try testing.expectEqual(@as(usize, 2), group.physical_volumes.len);
    group.physical_volumes[0].region = wholeDisk(8 * 1024 * 1024 * 1024);
    try testing.expect(!group.complete());

    const volume = group.findLogicalVolume("root").?;
    try testing.expectError(error.LvmPhysicalVolumeMissing, mapExtent(&group, volume, 0));

    group.physical_volumes[1].region = wholeDisk(8 * 1024 * 1024 * 1024);
    try testing.expect(group.complete());
    _ = try mapExtent(&group, volume, 0);
}

test "scan finds a volume group inside a GPT partition" {
    const io = testing.io;
    const path = "test-lvm-scan-gpt.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const disk_size: u64 = 256 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const specs = [_]gpt.PartitionSpec{
        .{
            .type_guid = guid.esp,
            .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111"),
            .size_sectors = (16 * 1024 * 1024) / 512,
        },
        .{
            .type_guid = guid.linux_lvm,
            .unique_guid = guid.parse("22222222-2222-2222-2222-222222222222"),
            .size_sectors = (128 * 1024 * 1024) / 512,
        },
    };
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(
        &img,
        io,
        guid.parse("33333333-3333-3333-3333-333333333333"),
        &specs,
        &placements,
    );

    const text = try simpleVgText(allocator, 5, 8, 1);
    defer allocator.free(text);
    const pv_bytes = try buildPv(allocator, 64 * 1024 * 1024, test_pv0, .{
        .start = test_mda_offset,
        .size = test_mda_size,
        .text = text,
    });
    defer allocator.free(pv_bytes);

    const pv_offset = placements[1].first_lba * 512;
    try img.pwrite(io, pv_bytes, pv_offset);

    var result = try scan(allocator, img, io);
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.groups.len);
    const group = try result.findVolumeGroup("");
    try testing.expectEqualStrings("vg", group.name);
    try testing.expectEqual(@as(u64, 5), group.seqno);
    try testing.expect(group.complete());
    try testing.expectEqual(
        Location{ .gpt_partition = 2 },
        group.physical_volumes[0].region.?.location,
    );

    const selected = try result.findLogicalVolume("vg", "root");
    const extent_bytes: u64 = 4 * 1024 * 1024;
    const range = try contiguousRange(selected.group, selected.volume);
    try testing.expectEqual(
        pv_offset + test_pe_start * sector_size + extent_bytes,
        range.offset,
    );
    try testing.expectEqual(8 * extent_bytes, range.length);

    try testing.expectError(error.LogicalVolumeNotFound, result.findLogicalVolume("vg", "swap"));
    try testing.expectError(error.LvmVolumeGroupNotFound, result.findVolumeGroup("other"));
}

/// Lays out an MBR disk with `count` equal Linux partitions, returning their
/// byte offsets. Used to give a scan more than one physical volume.
fn writeTestMbr(img: *Image, io: Io, count: u8, part_bytes: u64, offsets: []u64) !void {
    var table = mbr.Mbr{};
    var lba: u32 = 2048;
    const sectors: u32 = @intCast(part_bytes / 512);
    var index: u8 = 0;
    while (index < count) : (index += 1) {
        table.entries[index] = .{
            .partition_type = .linux,
            .first_lba = lba,
            .sector_count = sectors,
        };
        offsets[index] = @as(u64, lba) * 512;
        lba += sectors;
    }
    const sector = table.encode();
    try img.pwrite(io, &sector, 0);
}

test "scan prefers the metadata copy with the highest sequence number" {
    const io = testing.io;
    const path = "test-lvm-scan-seqno.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const part_bytes: u64 = 16 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, 64 * 1024 * 1024, .{});
    defer img.close(io);

    var offsets: [2]u64 = undefined;
    try writeTestMbr(&img, io, 2, part_bytes, &offsets);

    // The same volume group, seen through two physical volumes whose copies
    // disagree: one was written before the volume was grown. Both orderings
    // are tried so a rule of "whichever came last" cannot pass.
    const seqnos = [_][2]u64{ .{ 4, 9 }, .{ 9, 4 } };
    for (seqnos) |pair| {
        const uuids = [_][32]u8{ test_pv0, test_pv1 };
        for (pair, uuids, offsets) |seqno, uuid, offset| {
            const pv0 = try pvText(allocator, "pv0", test_pv0, 1024);
            defer allocator.free(pv0);
            const extents: u64 = if (seqno == 9) 6 else 2;
            const lv = try linearLvText(allocator, "root", "pv0", 0, extents);
            defer allocator.free(lv);
            const text = try vgText(allocator, .{
                .seqno = seqno,
                .physical_volumes = pv0,
                .logical_volumes = lv,
            });
            defer allocator.free(text);
            const bytes = try buildPv(allocator, part_bytes, uuid, .{
                .start = test_mda_offset,
                .size = test_mda_size,
                .text = text,
            });
            defer allocator.free(bytes);
            try img.pwrite(io, bytes, offset);
        }

        var result = try scan(allocator, img, io);
        defer result.deinit();

        try testing.expectEqual(@as(usize, 1), result.groups.len);
        try testing.expectEqual(@as(u64, 9), result.groups[0].seqno);
        const lv = result.groups[0].findLogicalVolume("root").?;
        try testing.expectEqual(@as(u64, 6), lv.extent_count);
    }
}

test "scan refuses two volume groups that share a name" {
    const io = testing.io;
    const path = "test-lvm-scan-dupe.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const part_bytes: u64 = 16 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, 64 * 1024 * 1024, .{});
    defer img.close(io);

    var offsets: [2]u64 = undefined;
    try writeTestMbr(&img, io, 2, part_bytes, &offsets);

    const ids = [_][32]u8{ test_vg_id, "VG111111111111111111111111111111".* };
    const uuids = [_][32]u8{ test_pv0, test_pv1 };
    for (ids, uuids, offsets) |vg_id, uuid, offset| {
        const pv = try pvText(allocator, "pv0", uuid, 1024);
        defer allocator.free(pv);
        const lv = try linearLvText(allocator, "root", "pv0", 0, 2);
        defer allocator.free(lv);
        const text = try vgText(allocator, .{
            .vg_id = vg_id,
            .physical_volumes = pv,
            .logical_volumes = lv,
        });
        defer allocator.free(text);
        const bytes = try buildPv(allocator, part_bytes, uuid, .{
            .start = test_mda_offset,
            .size = test_mda_size,
            .text = text,
        });
        defer allocator.free(bytes);
        try img.pwrite(io, bytes, offset);
    }

    try testing.expectError(error.DuplicateLvmVolumeGroup, scan(allocator, img, io));
}

test "scan reports nothing for a disk with no physical volume" {
    const io = testing.io;
    const path = "test-lvm-scan-empty.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var img = try Image.create(io, path, .raw, 4 * 1024 * 1024, .{});
    defer img.close(io);

    var result = try scan(testing.allocator, img, io);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 0), result.groups.len);
    try testing.expectError(error.LvmVolumeGroupNotFound, result.findVolumeGroup(""));
    try testing.expectError(error.LvmVolumeGroupNotFound, result.findVolumeGroup("vg"));
}

test "an empty volume group name is ambiguous when the disk holds two" {
    const io = testing.io;
    const path = "test-lvm-scan-two.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const part_bytes: u64 = 16 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, 64 * 1024 * 1024, .{});
    defer img.close(io);

    var offsets: [2]u64 = undefined;
    try writeTestMbr(&img, io, 2, part_bytes, &offsets);

    const names = [_][]const u8{ "alpha", "beta" };
    const ids = [_][32]u8{ test_vg_id, "VG111111111111111111111111111111".* };
    const uuids = [_][32]u8{ test_pv0, test_pv1 };
    for (names, ids, uuids, offsets) |name, vg_id, uuid, offset| {
        const pv = try pvText(allocator, "pv0", uuid, 1024);
        defer allocator.free(pv);
        const lv = try linearLvText(allocator, "root", "pv0", 0, 2);
        defer allocator.free(lv);
        const text = try vgText(allocator, .{
            .vg_name = name,
            .vg_id = vg_id,
            .physical_volumes = pv,
            .logical_volumes = lv,
        });
        defer allocator.free(text);
        const bytes = try buildPv(allocator, part_bytes, uuid, .{
            .start = test_mda_offset,
            .size = test_mda_size,
            .text = text,
        });
        defer allocator.free(bytes);
        try img.pwrite(io, bytes, offset);
    }

    var result = try scan(allocator, img, io);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 2), result.groups.len);
    try testing.expectError(error.AmbiguousLvmVolumeGroup, result.findVolumeGroup(""));
    try testing.expectEqualStrings("beta", (try result.findVolumeGroup("beta")).name);
}

test "scan reports a physical volume whose metadata area is corrupt" {
    const io = testing.io;
    const path = "test-lvm-scan-corrupt.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const allocator = testing.allocator;
    const text = try simpleVgText(allocator, 1, 4, 0);
    defer allocator.free(text);
    const bytes = try buildPv(allocator, 1 << 20, test_pv0, .{
        .start = test_mda_offset,
        .size = test_mda_size,
        .text = text,
    });
    defer allocator.free(bytes);
    // A byte flipped inside the committed copy. A physical volume that says
    // it is one, and then does not parse, is corruption worth reporting
    // rather than a disk with no volume groups.
    bytes[test_mda_offset + metadata_area_header_size + 30] +%= 1;

    var img = try writeTestImage(io, path, bytes);
    defer img.close(io);

    try testing.expectError(error.BadLvmMetadataChecksum, scan(allocator, img, io));
}
