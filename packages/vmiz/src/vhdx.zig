//! VHDX (Hyper-V's successor format to VHD) support for standalone,
//! non-differencing images.
//!
//! Every struct layout, offset, well-known GUID, the CRC-32C checksum
//! algorithm, and -- critically -- the BAT chunk-ratio interleaving math are
//! transcribed directly from QEMU's `block/vhdx.h`/`block/vhdx.c` (based on
//! Microsoft's "VHDX Format Specification v1.00"), the de-facto
//! interoperability reference for this format. All multi-byte fields are
//! little-endian.
//!
//! Scope / limitations:
//!  - Differencing (parent/backing-file) VHDX images are not supported
//!    (`error.DifferencingNotSupported`).
//!  - Only 512-byte logical sectors are supported (matches QEMU's own
//!    restriction; virtually all real-world VHDX files use 512).
//!  - The optional journal/log region is created for new images but is not
//!    replayed on open and is not used to journal metadata updates during
//!    writes/resizes. Files written by tools that flush and cleanly close the
//!    image remain readable; crash recovery semantics remain out of scope.

const std = @import("std");
const Io = std.Io;
const guid = @import("guid.zig");

pub const header_block_size: usize = 64 * 1024;
pub const file_id_offset: u64 = 0;
pub const header1_offset: u64 = header_block_size * 1;
pub const header2_offset: u64 = header_block_size * 2;
pub const region_table_offset: u64 = header_block_size * 3;
pub const region_table2_offset: u64 = header_block_size * 4;
pub const header_section_end: u64 = 1 * 1024 * 1024;

pub const header_size: usize = 4 * 1024;
pub const header_signature: [4]u8 = "head".*;
pub const region_signature: [4]u8 = "regi".*;
pub const metadata_signature: [8]u8 = "metadata".*;
pub const file_signature: [8]u8 = "vhdxfile".*;

pub const default_log_size: u32 = 1 * 1024 * 1024;
pub const metadata_region_length: u64 = 1 * 1024 * 1024;
pub const metadata_item_base_offset: u32 = 64 * 1024;
pub const default_block_size: u32 = 1 * 1024 * 1024;
pub const min_block_size: u32 = 1 * 1024 * 1024;
pub const max_block_size: u32 = 256 * 1024 * 1024;
pub const max_image_size: u64 = 64 * 1024 * 1024 * 1024 * 1024;
pub const default_logical_sector_size: u32 = 512;
pub const default_physical_sector_size: u32 = 512;

pub const metadata_flag_is_user: u32 = 0x01;
pub const metadata_flag_is_virtual_disk: u32 = 0x02;
pub const metadata_flag_is_required: u32 = 0x04;
pub const region_entry_required: u32 = 0x01;
pub const file_params_leave_blocks_allocated: u32 = 0x01;
pub const file_params_has_parent: u32 = 0x02;

/// Sector-bitmap-block interleaving granularity: for every `chunk_ratio`
/// payload block entries in the BAT, there is one extra (here, ignored)
/// sector-bitmap-block entry -- see `batIndexForBlock`.
pub const max_sectors_per_block: u64 = 1 << 23;

/// upper 44 bits = file offset in 1 MiB units (conveniently, masking
/// without shifting already yields the byte offset, since 1 MiB == 2^20 and
/// the mask starts at bit 20); lower 3 bits = block state.
pub const bat_state_mask: u64 = 0x7;
pub const bat_file_off_mask: u64 = 0xFFFF_FFFF_FFF0_0000;

pub const BlockState = enum(u3) {
    not_present = 0,
    undefined_state = 1,
    zero = 2,
    unmapped = 3,
    unmapped_v095 = 5,
    fully_present = 6,
    partially_present = 7,
    _,
};

// ---- Well-known region table entry GUIDs ----
pub const bat_region_guid: guid.Guid = guid.parse("2DC27766-F623-4200-9D64-115E9BFD4A08");
pub const metadata_region_guid: guid.Guid = guid.parse("8B7CA206-4790-4B9A-B8FE-575F050F886E");

// ---- Well-known metadata item GUIDs ----
pub const file_parameters_guid: guid.Guid = guid.parse("CAA16737-FA36-4D43-B3B6-33F0AA44E76B");
pub const virtual_disk_size_guid: guid.Guid = guid.parse("2FA54224-CD1B-4876-B211-5DBED83BF4B8");
pub const page83_data_guid: guid.Guid = guid.parse("BECA12AB-B2E6-4523-93EF-C309E000C746");
pub const logical_sector_size_guid: guid.Guid = guid.parse("8141BF1D-A96F-4709-BA47-F233A8FAAB5F");
pub const physical_sector_size_guid: guid.Guid = guid.parse("CDA348C7-445D-4471-9CC9-E9885251C556");
pub const parent_locator_guid: guid.Guid = guid.parse("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C");

const Crc32c = std.hash.crc.Crc32Iscsi;

pub const OpenError = error{
    BadFileSignature,
    NoValidHeader,
    BadRegionTableChecksum,
    BadRegionSignature,
    MissingBatRegion,
    MissingMetadataRegion,
    MissingFileParameters,
    MissingVirtualDiskSize,
    MissingLogicalSectorSize,
    InvalidMetadataTable,
    UnsupportedLogicalSectorSize,
    DifferencingNotSupported,
    InvalidBlockSize,
} || Io.File.ReadPositionalError;

pub const CreateError = error{
    SizeNotSectorAligned,
    ImageTooLarge,
    HeaderSequenceOverflow,
} || Io.File.WritePositionalError || Io.File.SetLengthError;

pub const PreadError = error{
    UnsupportedBlockState,
    InvalidBatEntry,
} || Io.File.ReadPositionalError;

pub const PwriteError = error{
    WritePastEndOfImage,
    UnsupportedBlockState,
    InvalidBatEntry,
    HeaderSequenceOverflow,
} || Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError || Io.File.StatError;

pub const ResizeError = error{
    ShrinkNotSupported,
    ImageTooLarge,
    MissingVirtualDiskSize,
    HeaderSequenceOverflow,
} || OpenError || Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError || Io.File.StatError;

/// Everything `Image` and the direct VHDX read/write helpers need to translate
/// guest-visible byte offsets into file offsets and to update the redundant
/// header / region-table metadata on write.
pub const Info = struct {
    virtual_size: u64,
    block_size: u32,
    /// `(2^23 * logical_sector_size) / block_size`, always a power of two.
    chunk_ratio: u64,
    bat_offset: u64,
    bat_length: u64,
    metadata_offset: u64,
    log_offset: u64,
    log_length: u32,
    header_sequence_number: u64,
    file_write_guid: guid.Guid,
    data_write_guid: guid.Guid,
    page83_guid: guid.Guid,
    deterministic_write_guid_seed: ?[32]u8 = null,
    deterministic_write_index: u64 = 0,
};

pub const CreateOptions = struct {
    header_sequence_base: ?u64 = null,
    file_write_guid: ?guid.Guid = null,
    data_write_guid: ?guid.Guid = null,
    page83_guid: ?guid.Guid = null,
    write_guid_seed: ?[32]u8 = null,
};

/// Parses the file signature, active header, region table, and metadata table,
/// returning enough information to read and write guest data. `file` must be
/// positioned/seekable via positional reads (no seek state is assumed).
pub fn open(io: Io, file: Io.File) OpenError!Info {
    var sig: [8]u8 = undefined;
    _ = try file.readPositionalAll(io, &sig, file_id_offset);
    if (!std.mem.eql(u8, &sig, &file_signature)) return error.BadFileSignature;

    const header = try readValidHeader(io, file);
    const region = try readRegionTable(io, file);

    const params = try readFileParameters(io, file, region.metadata_offset);
    if (params.data_bits & file_params_has_parent != 0) return error.DifferencingNotSupported;
    if (!std.math.isPowerOfTwo(params.block_size) or params.block_size < min_block_size or params.block_size > max_block_size) {
        return error.InvalidBlockSize;
    }

    const virtual_size = try readVirtualDiskSize(io, file, region.metadata_offset);
    const logical_sector_size = try readLogicalSectorSize(io, file, region.metadata_offset);
    if (logical_sector_size != default_logical_sector_size) return error.UnsupportedLogicalSectorSize;
    const page83_guid = try readMetadataGuid(io, file, region.metadata_offset, page83_data_guid);

    const chunk_ratio = max_sectors_per_block * logical_sector_size / params.block_size;

    return .{
        .virtual_size = virtual_size,
        .block_size = params.block_size,
        .chunk_ratio = chunk_ratio,
        .bat_offset = region.bat_offset,
        .bat_length = region.bat_length,
        .metadata_offset = region.metadata_offset,
        .log_offset = header.log_offset,
        .log_length = header.log_length,
        .header_sequence_number = header.sequence_number,
        .file_write_guid = header.file_write_guid,
        .data_write_guid = header.data_write_guid,
        .page83_guid = page83_guid,
    };
}

/// Creates a new sparse, standalone VHDX image with a 1 MiB log region,
/// redundant headers/region tables, a metadata region, and an all-not-present
/// BAT sized for `size`.
pub fn create(io: Io, file: Io.File, size: u64) CreateError!Info {
    return createWithOptions(io, file, size, .{});
}

pub fn validateCreateOptions(size: u64, options: CreateOptions) CreateError!void {
    if (size % default_logical_sector_size != 0) return error.SizeNotSectorAligned;
    if (size > max_image_size) return error.ImageTooLarge;
    if (options.header_sequence_base) |base| {
        if (base > std.math.maxInt(u64) - 3) return error.HeaderSequenceOverflow;
    }
}

pub fn createWithOptions(io: Io, file: Io.File, size: u64, options: CreateOptions) CreateError!Info {
    try validateCreateOptions(size, options);
    const header_sequence_base = options.header_sequence_base orelse randomHeaderSequenceBase(io);

    const block_size = default_block_size;
    const chunk_ratio = max_sectors_per_block * default_logical_sector_size / block_size;
    const bat_entries = batEntryCount(size, block_size, chunk_ratio);
    const bat_length = batRegionLengthForEntries(bat_entries);
    const bat_offset = alignUp(header_section_end + default_log_size, header_section_end);
    const metadata_offset = alignUp(bat_offset + bat_length, header_section_end);
    const initial_file_size = metadata_offset + metadata_region_length;

    try file.setLength(io, initial_file_size);
    try writeFileIdentifier(file, io);

    const file_write_guid = options.file_write_guid orelse randomGuid(io);
    const data_write_guid = options.data_write_guid orelse randomGuid(io);
    const page83_guid = options.page83_guid orelse randomGuid(io);
    try writeHeaders(file, io, .{
        .sequence_base = header_sequence_base,
        .log_offset = header_section_end,
        .log_length = default_log_size,
        .file_write_guid = file_write_guid,
        .data_write_guid = data_write_guid,
        .log_guid = guid.nil,
    });
    try writeRegionTables(file, io, bat_offset, bat_length, metadata_offset);
    try writeMetadataRegion(file, io, size, block_size, metadata_offset, page83_guid);

    return .{
        .virtual_size = size,
        .block_size = block_size,
        .chunk_ratio = chunk_ratio,
        .bat_offset = bat_offset,
        .bat_length = bat_length,
        .metadata_offset = metadata_offset,
        .log_offset = header_section_end,
        .log_length = default_log_size,
        .header_sequence_number = header_sequence_base + 1,
        .file_write_guid = file_write_guid,
        .data_write_guid = data_write_guid,
        .page83_guid = page83_guid,
        .deterministic_write_guid_seed = options.write_guid_seed,
    };
}

pub fn pread(file: Io.File, io: Io, info: Info, buffer: []u8, offset: u64) PreadError!usize {
    if (offset >= info.virtual_size) return 0;

    var total: usize = 0;
    var off = offset;
    var remaining = @min(buffer.len, info.virtual_size - offset);
    while (remaining > 0) {
        const block_index = off / info.block_size;
        const in_block_offset: u32 = @intCast(off % info.block_size);
        const chunk: usize = @intCast(@min(@as(u64, remaining), info.block_size - in_block_offset));

        const entry = try readBatEntry(file, io, info.bat_offset, batIndexForBlock(block_index, info.chunk_ratio));
        const state: BlockState = @enumFromInt(entry & bat_state_mask);

        switch (state) {
            .fully_present => {
                const file_offset = entry & bat_file_off_mask;
                if (!isValidBlockFileOffset(file_offset)) return error.InvalidBatEntry;
                const got = try file.readPositionalAll(io, buffer[total..][0..chunk], file_offset + in_block_offset);
                if (got < chunk) @memset(buffer[total + got ..][0 .. chunk - got], 0);
            },
            .not_present, .undefined_state, .zero, .unmapped, .unmapped_v095 => {
                @memset(buffer[total..][0..chunk], 0);
            },
            else => return error.UnsupportedBlockState,
        }

        total += chunk;
        off += chunk;
        remaining -= chunk;
    }
    return total;
}

/// Writes guest-visible bytes, allocating payload blocks on demand and marking
/// their BAT entries `fully_present`. The optional VHDX log is not used;
/// headers and BAT updates are written in place.
pub fn pwrite(file: Io.File, io: Io, info: *Info, buffer: []const u8, offset: u64) PwriteError!void {
    const write_end = std.math.add(u64, offset, buffer.len) catch return error.WritePastEndOfImage;
    if (write_end > info.virtual_size) return error.WritePastEndOfImage;
    if (buffer.len == 0) return;
    try ensureHeaderSequenceAvailable(info.*);

    try ensureBatCapacityForSize(file, io, info, info.virtual_size);

    var off = offset;
    var remaining = buffer.len;
    var src: usize = 0;
    while (remaining > 0) {
        const block_index = off / info.block_size;
        const in_block_offset: u32 = @intCast(off % info.block_size);
        const chunk: usize = @intCast(@min(@as(u64, remaining), info.block_size - in_block_offset));
        const bat_index = batIndexForBlock(block_index, info.chunk_ratio);

        var entry = try readBatEntry(file, io, info.bat_offset, bat_index);
        const state: BlockState = @enumFromInt(entry & bat_state_mask);
        var file_offset = entry & bat_file_off_mask;

        switch (state) {
            .fully_present => {
                if (!isValidBlockFileOffset(file_offset)) return error.InvalidBatEntry;
            },
            .not_present, .undefined_state, .zero, .unmapped, .unmapped_v095 => {
                file_offset = try allocatePayloadBlock(file, io, info.*);
                entry = file_offset | @intFromEnum(BlockState.fully_present);
                try writeBatEntry(file, io, info.bat_offset, bat_index, entry);
            },
            else => return error.UnsupportedBlockState,
        }

        try file.writePositionalAll(io, buffer[src..][0..chunk], file_offset + in_block_offset);

        src += chunk;
        off += chunk;
        remaining -= chunk;
    }

    try updateHeaders(file, io, info, true);
}

/// Grows the guest-visible virtual size, relocating/expanding the BAT region
/// if necessary and updating the virtual-size metadata item in place.
pub fn resize(file: Io.File, io: Io, info: *Info, new_size: u64) ResizeError!void {
    if (new_size < info.virtual_size) return error.ShrinkNotSupported;
    if (new_size == info.virtual_size) return;
    if (new_size > max_image_size) return error.ImageTooLarge;
    try ensureHeaderSequenceAvailable(info.*);

    try ensureBatCapacityForSize(file, io, info, new_size);

    const item = (try findMetadataItem(io, file, info.metadata_offset, virtual_disk_size_guid)) orelse
        return error.MissingVirtualDiskSize;
    try writeU64(file, io, item.file_offset, new_size);

    info.virtual_size = new_size;
    try updateHeaders(file, io, info, true);
}

/// Index into the BAT array for payload block `block_index`, accounting for
/// the interleaved (here, unused/skipped) sector-bitmap-block entries: one
/// extra slot after every `chunk_ratio` payload entries. Matches QEMU's
/// `vhdx_block_translate`: `bat_idx += bat_idx >> chunk_ratio_bits`, i.e.
/// `bat_idx += bat_idx / chunk_ratio` since chunk_ratio is a power of two.
pub fn batIndexForBlock(block_index: u64, chunk_ratio: u64) u64 {
    return block_index + block_index / chunk_ratio;
}

fn readValidHeader(io: Io, file: Io.File) OpenError!HeaderInfo {
    const h1 = readOneHeader(io, file, header1_offset);
    const h2 = readOneHeader(io, file, header2_offset);

    if (h1 != null and h2 == null) return h1.?;
    if (h1 == null and h2 != null) return h2.?;
    if (h1 == null and h2 == null) return error.NoValidHeader;

    if (h1.?.sequence_number >= h2.?.sequence_number) return h1.?;
    return h2.?;
}

const HeaderInfo = struct {
    sequence_number: u64,
    log_offset: u64,
    log_length: u32,
    file_write_guid: guid.Guid,
    data_write_guid: guid.Guid,
};

fn readOneHeader(io: Io, file: Io.File, offset: u64) ?HeaderInfo {
    var buf: [header_size]u8 = undefined;
    const n = file.readPositionalAll(io, &buf, offset) catch return null;
    if (n != header_size) return null;
    if (!std.mem.eql(u8, buf[0..4], &header_signature)) return null;

    var checked = buf;
    checked[4..8].* = .{ 0, 0, 0, 0 };
    const stored_crc = std.mem.readInt(u32, buf[4..8], .little);
    if (Crc32c.hash(&checked) != stored_crc) return null;

    const version = std.mem.readInt(u16, buf[66..68], .little);
    if (version != 1) return null;

    return .{
        .sequence_number = std.mem.readInt(u64, buf[8..16], .little),
        .file_write_guid = buf[16..32].*,
        .data_write_guid = buf[32..48].*,
        .log_length = std.mem.readInt(u32, buf[68..72], .little),
        .log_offset = std.mem.readInt(u64, buf[72..80], .little),
    };
}

const RegionInfo = struct {
    bat_offset: u64,
    bat_length: u64,
    metadata_offset: u64,
};

fn readRegionTable(io: Io, file: Io.File) OpenError!RegionInfo {
    var buf: [header_block_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, region_table_offset);

    var checked = buf;
    checked[4..8].* = .{ 0, 0, 0, 0 };
    const stored_crc = std.mem.readInt(u32, buf[4..8], .little);
    if (Crc32c.hash(&checked) != stored_crc) return error.BadRegionTableChecksum;

    if (!std.mem.eql(u8, buf[0..4], &region_signature)) return error.BadRegionSignature;
    const entry_count = std.mem.readInt(u32, buf[8..12], .little);

    var bat_offset: ?u64 = null;
    var bat_length: ?u64 = null;
    var metadata_offset: ?u64 = null;

    var i: u32 = 0;
    while (i < entry_count) : (i += 1) {
        const off = 16 + i * 32;
        const entry_guid: guid.Guid = buf[off..][0..16].*;
        const file_offset = std.mem.readInt(u64, buf[off + 16 ..][0..8], .little);
        const length = std.mem.readInt(u32, buf[off + 24 ..][0..4], .little);

        if (std.mem.eql(u8, &entry_guid, &bat_region_guid)) {
            bat_offset = file_offset;
            bat_length = length;
        } else if (std.mem.eql(u8, &entry_guid, &metadata_region_guid)) {
            metadata_offset = file_offset;
        }
    }

    return .{
        .bat_offset = bat_offset orelse return error.MissingBatRegion,
        .bat_length = bat_length orelse return error.MissingBatRegion,
        .metadata_offset = metadata_offset orelse return error.MissingMetadataRegion,
    };
}

/// Finds a metadata item by GUID, returning its absolute file offset and
/// length, or `null` if not present. `metadata_region_offset` is the file
/// offset of the metadata region (from the region table).
fn findMetadataItem(io: Io, file: Io.File, metadata_region_offset: u64, item_guid: guid.Guid) OpenError!?struct { file_offset: u64, length: u32 } {
    var header_buf: [32]u8 = undefined;
    _ = try file.readPositionalAll(io, &header_buf, metadata_region_offset);
    if (!std.mem.eql(u8, header_buf[0..8], &metadata_signature)) return null;

    const entry_count = std.mem.readInt(u16, header_buf[10..12], .little);

    var i: u16 = 0;
    while (i < entry_count) : (i += 1) {
        var entry_buf: [32]u8 = undefined;
        _ = try file.readPositionalAll(io, &entry_buf, metadata_region_offset + 32 + @as(u64, i) * 32);

        const entry_guid: guid.Guid = entry_buf[0..16].*;
        if (std.mem.eql(u8, &entry_guid, &item_guid)) {
            const item_offset = std.mem.readInt(u32, entry_buf[16..20], .little);
            const item_length = std.mem.readInt(u32, entry_buf[20..24], .little);
            return .{ .file_offset = metadata_region_offset + item_offset, .length = item_length };
        }
    }
    return null;
}

fn readFileParameters(io: Io, file: Io.File, metadata_region_offset: u64) OpenError!struct { block_size: u32, data_bits: u32 } {
    const item = (try findMetadataItem(io, file, metadata_region_offset, file_parameters_guid)) orelse
        return error.MissingFileParameters;
    var buf: [8]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, item.file_offset);
    return .{
        .block_size = std.mem.readInt(u32, buf[0..4], .little),
        .data_bits = std.mem.readInt(u32, buf[4..8], .little),
    };
}

fn readVirtualDiskSize(io: Io, file: Io.File, metadata_region_offset: u64) OpenError!u64 {
    const item = (try findMetadataItem(io, file, metadata_region_offset, virtual_disk_size_guid)) orelse
        return error.MissingVirtualDiskSize;
    var buf: [8]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, item.file_offset);
    return std.mem.readInt(u64, &buf, .little);
}

fn readLogicalSectorSize(io: Io, file: Io.File, metadata_region_offset: u64) OpenError!u32 {
    const item = (try findMetadataItem(io, file, metadata_region_offset, logical_sector_size_guid)) orelse
        return error.MissingLogicalSectorSize;
    var buf: [4]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, item.file_offset);
    return std.mem.readInt(u32, &buf, .little);
}

fn readMetadataGuid(io: Io, file: Io.File, metadata_region_offset: u64, item_guid: guid.Guid) OpenError!guid.Guid {
    const item = (try findMetadataItem(io, file, metadata_region_offset, item_guid)) orelse
        return error.MissingMetadataRegion;
    if (item.length != 16) return error.InvalidMetadataTable;
    var value: guid.Guid = undefined;
    _ = try file.readPositionalAll(io, &value, item.file_offset);
    return value;
}

const HeaderWriteInfo = struct {
    sequence_base: u64,
    log_offset: u64,
    log_length: u32,
    file_write_guid: guid.Guid,
    data_write_guid: guid.Guid,
    log_guid: guid.Guid,
};

fn writeFileIdentifier(file: Io.File, io: Io) Io.File.WritePositionalError!void {
    var buf: [header_block_size]u8 = [_]u8{0} ** header_block_size;
    buf[0..8].* = file_signature;
    try file.writePositionalAll(io, &buf, file_id_offset);
}

fn writeHeaders(file: Io.File, io: Io, info: HeaderWriteInfo) Io.File.WritePositionalError!void {
    try writeOneHeader(file, io, header1_offset, info.sequence_base, info.log_offset, info.log_length, info.file_write_guid, info.data_write_guid, info.log_guid);
    try writeOneHeader(file, io, header2_offset, info.sequence_base + 1, info.log_offset, info.log_length, info.file_write_guid, info.data_write_guid, info.log_guid);
}

fn writeOneHeader(
    file: Io.File,
    io: Io,
    offset: u64,
    sequence_number: u64,
    log_offset: u64,
    log_length: u32,
    file_write_guid: guid.Guid,
    data_write_guid: guid.Guid,
    log_guid: guid.Guid,
) Io.File.WritePositionalError!void {
    var buf: [header_size]u8 = [_]u8{0} ** header_size;
    buf[0..4].* = header_signature;
    std.mem.writeInt(u64, buf[8..16], sequence_number, .little);
    buf[16..32].* = file_write_guid;
    buf[32..48].* = data_write_guid;
    buf[48..64].* = log_guid;
    std.mem.writeInt(u16, buf[64..66], 0, .little); // log_version
    std.mem.writeInt(u16, buf[66..68], 1, .little); // version
    std.mem.writeInt(u32, buf[68..72], log_length, .little);
    std.mem.writeInt(u64, buf[72..80], log_offset, .little);
    std.mem.writeInt(u32, buf[4..8], Crc32c.hash(&buf), .little);
    try file.writePositionalAll(io, &buf, offset);
}

fn ensureHeaderSequenceAvailable(info: Info) error{HeaderSequenceOverflow}!void {
    if (info.header_sequence_number > std.math.maxInt(u64) - 2) return error.HeaderSequenceOverflow;
}

fn updateHeaders(
    file: Io.File,
    io: Io,
    info: *Info,
    generate_data_write_guid: bool,
) (Io.File.WritePositionalError || error{HeaderSequenceOverflow})!void {
    try ensureHeaderSequenceAvailable(info.*);
    const file_write_guid = if (info.deterministic_write_guid_seed) |seed|
        derivedWriteGuid(seed, "file", info.deterministic_write_index)
    else
        randomGuid(io);
    const data_write_guid = if (!generate_data_write_guid)
        guid.nil
    else if (info.deterministic_write_guid_seed) |seed|
        derivedWriteGuid(seed, "data", info.deterministic_write_index)
    else
        randomGuid(io);
    try writeHeaders(file, io, .{
        .sequence_base = info.header_sequence_number + 1,
        .log_offset = info.log_offset,
        .log_length = info.log_length,
        .file_write_guid = file_write_guid,
        .data_write_guid = data_write_guid,
        .log_guid = guid.nil,
    });
    info.header_sequence_number += 2;
    info.file_write_guid = file_write_guid;
    info.data_write_guid = data_write_guid;
    info.deterministic_write_index += 1;
}

fn writeRegionTables(file: Io.File, io: Io, bat_offset: u64, bat_length: u64, metadata_offset: u64) Io.File.WritePositionalError!void {
    var buf: [header_block_size]u8 = [_]u8{0} ** header_block_size;
    buf[0..4].* = region_signature;
    std.mem.writeInt(u32, buf[8..12], 2, .little);

    buf[16..32].* = bat_region_guid;
    std.mem.writeInt(u64, buf[32..40], bat_offset, .little);
    std.mem.writeInt(u32, buf[40..44], @intCast(bat_length), .little);
    std.mem.writeInt(u32, buf[44..48], region_entry_required, .little);

    buf[48..64].* = metadata_region_guid;
    std.mem.writeInt(u64, buf[64..72], metadata_offset, .little);
    std.mem.writeInt(u32, buf[72..76], @intCast(metadata_region_length), .little);
    std.mem.writeInt(u32, buf[76..80], region_entry_required, .little);

    std.mem.writeInt(u32, buf[4..8], Crc32c.hash(&buf), .little);
    try file.writePositionalAll(io, &buf, region_table_offset);
    try file.writePositionalAll(io, &buf, region_table2_offset);
}

fn writeMetadataRegion(
    file: Io.File,
    io: Io,
    virtual_size: u64,
    block_size: u32,
    metadata_offset: u64,
    page83_guid: guid.Guid,
) Io.File.WritePositionalError!void {
    var table: [header_block_size]u8 = [_]u8{0} ** header_block_size;
    table[0..8].* = metadata_signature;
    std.mem.writeInt(u16, table[10..12], 5, .little);

    writeMetadataTableEntry(table[32..64], file_parameters_guid, metadata_item_base_offset, 8, metadata_flag_is_required);
    writeMetadataTableEntry(table[64..96], virtual_disk_size_guid, metadata_item_base_offset + 8, 8, metadata_flag_is_required | metadata_flag_is_virtual_disk);
    writeMetadataTableEntry(table[96..128], page83_data_guid, metadata_item_base_offset + 16, 16, metadata_flag_is_required | metadata_flag_is_virtual_disk);
    writeMetadataTableEntry(table[128..160], logical_sector_size_guid, metadata_item_base_offset + 32, 4, metadata_flag_is_required | metadata_flag_is_virtual_disk);
    writeMetadataTableEntry(table[160..192], physical_sector_size_guid, metadata_item_base_offset + 36, 4, metadata_flag_is_required | metadata_flag_is_virtual_disk);
    try file.writePositionalAll(io, &table, metadata_offset);

    var items: [40]u8 = [_]u8{0} ** 40;
    std.mem.writeInt(u32, items[0..4], block_size, .little);
    std.mem.writeInt(u32, items[4..8], 0, .little);
    std.mem.writeInt(u64, items[8..16], virtual_size, .little);
    items[16..32].* = page83_guid;
    std.mem.writeInt(u32, items[32..36], default_logical_sector_size, .little);
    std.mem.writeInt(u32, items[36..40], default_physical_sector_size, .little);
    try file.writePositionalAll(io, &items, metadata_offset + metadata_item_base_offset);
}

fn writeMetadataTableEntry(entry_buf: []u8, item_guid: guid.Guid, offset: u32, length: u32, flags: u32) void {
    entry_buf[0..16].* = item_guid;
    std.mem.writeInt(u32, entry_buf[16..20], offset, .little);
    std.mem.writeInt(u32, entry_buf[20..24], length, .little);
    std.mem.writeInt(u32, entry_buf[24..28], flags, .little);
    std.mem.writeInt(u32, entry_buf[28..32], 0, .little);
}

fn batEntryCount(virtual_size: u64, block_size: u32, chunk_ratio: u64) u64 {
    const data_blocks = divCeil(virtual_size, block_size);
    if (data_blocks == 0) return 0;
    return data_blocks + ((data_blocks - 1) / chunk_ratio);
}

fn batRegionLengthForEntries(entry_count: u64) u64 {
    const entry_bytes = std.math.mul(u64, entry_count, 8) catch unreachable;
    return @max(header_section_end, alignUp(entry_bytes, header_section_end));
}

fn ensureBatCapacityForSize(file: Io.File, io: Io, info: *Info, virtual_size: u64) (Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError || Io.File.StatError)!void {
    const needed_entries = batEntryCount(virtual_size, info.block_size, info.chunk_ratio);
    const needed_length = batRegionLengthForEntries(needed_entries);
    if (needed_length <= info.bat_length) return;

    const file_size = (try file.stat(io)).size;
    const new_bat_offset = alignUp(file_size, header_section_end);
    const new_end = new_bat_offset + needed_length;
    try file.setLength(io, new_end);
    try copyRange(file, io, info.bat_offset, new_bat_offset, info.bat_length);
    try writeRegionTables(file, io, new_bat_offset, needed_length, info.metadata_offset);

    info.bat_offset = new_bat_offset;
    info.bat_length = needed_length;
}

fn allocatePayloadBlock(file: Io.File, io: Io, info: Info) (Io.File.SetLengthError || Io.File.StatError)!u64 {
    const file_size = (try file.stat(io)).size;
    const block_offset = alignUp(file_size, header_section_end);
    try file.setLength(io, block_offset + info.block_size);
    return block_offset;
}

fn isValidBlockFileOffset(file_offset: u64) bool {
    return file_offset >= header_section_end and file_offset % header_section_end == 0;
}

fn readBatEntry(file: Io.File, io: Io, bat_offset: u64, index: u64) Io.File.ReadPositionalError!u64 {
    var buf: [8]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, bat_offset + index * 8);
    return std.mem.readInt(u64, &buf, .little);
}

fn writeBatEntry(file: Io.File, io: Io, bat_offset: u64, index: u64, value: u64) Io.File.WritePositionalError!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try file.writePositionalAll(io, &buf, bat_offset + index * 8);
}

fn copyRange(file: Io.File, io: Io, src_offset: u64, dst_offset: u64, byte_length: u64) (Io.File.ReadPositionalError || Io.File.WritePositionalError)!void {
    var buf: [4096]u8 = undefined;
    var copied: u64 = 0;
    while (copied < byte_length) {
        const n: usize = @intCast(@min(byte_length - copied, buf.len));
        _ = try file.readPositionalAll(io, buf[0..n], src_offset + copied);
        try file.writePositionalAll(io, buf[0..n], dst_offset + copied);
        copied += n;
    }
}

fn writeU64(file: Io.File, io: Io, offset: u64, value: u64) Io.File.WritePositionalError!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    try file.writePositionalAll(io, &buf, offset);
}

fn alignUp(value: u64, alignment: u64) u64 {
    if (alignment == 0) return value;
    return std.mem.alignForward(u64, value, alignment);
}

fn divCeil(numerator: u64, denominator: u64) u64 {
    if (numerator == 0) return 0;
    return std.math.divCeil(u64, numerator, denominator) catch unreachable;
}

fn randomHeaderSequenceBase(io: Io) u64 {
    while (true) {
        var buf: [8]u8 = undefined;
        Io.random(io, &buf);
        const value = std.mem.readInt(u64, &buf, .little);
        if (value <= std.math.maxInt(u64) - 3) return value;
    }
}

fn randomGuid(io: Io) guid.Guid {
    var bytes: guid.Guid = undefined;
    Io.random(io, &bytes);
    bytes[7] = (bytes[7] & 0x0F) | 0x40; // version 4 in mixed-endian GUID layout
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 10
    return bytes;
}

fn derivedWriteGuid(seed: [32]u8, kind: []const u8, index: u64) guid.Guid {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("vmiz-vhdx-write-guid-v1\x00");
    hash.update(kind);
    var index_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &index_bytes, index, .big);
    hash.update(&index_bytes);
    hash.update(&seed);
    var digest: [32]u8 = undefined;
    hash.final(&digest);

    var value: guid.Guid = digest[0..16].*;
    value[7] = (value[7] & 0x0F) | 0x40;
    value[8] = (value[8] & 0x3F) | 0x80;
    return value;
}

test "batIndexForBlock matches QEMU's vhdx_block_translate interleaving" {
    // chunk_ratio=4: blocks 0-3 map directly, block 4 gets +1 (one sector
    // bitmap slot inserted after every 4 payload entries), block 8 gets +2.
    try std.testing.expectEqual(@as(u64, 0), batIndexForBlock(0, 4));
    try std.testing.expectEqual(@as(u64, 3), batIndexForBlock(3, 4));
    try std.testing.expectEqual(@as(u64, 5), batIndexForBlock(4, 4));
    try std.testing.expectEqual(@as(u64, 8), batIndexForBlock(7, 4));
    try std.testing.expectEqual(@as(u64, 10), batIndexForBlock(8, 4));
}

test "guid constants match known VHDX region/metadata GUIDs" {
    // Cross-checked against QEMU's block/vhdx.c static MSGUID literals
    // (bat_guid, metadata_guid, file_param_guid, ...).
    const expected_bat: guid.Guid = .{
        0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42,
        0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
    };
    try std.testing.expectEqualSlices(u8, &expected_bat, &bat_region_guid);
}

test "create, write, resize, and reopen vhdx images" {
    const io = std.testing.io;
    const path = "test-vhdx-write.vhdx";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const gib: u64 = 1024 * 1024 * 1024;
    const initial_size: u64 = 120 * gib;
    const grown_size: u64 = 132 * gib;
    const sparse_offset: u64 = 3 * @as(u64, default_block_size) + 41;
    const cross_boundary_offset: u64 = 4 * @as(u64, default_block_size) - 96;
    const distant_offset: u64 = 130 * gib + 123;
    const payload0 = "vhdx-direct-0";
    const payload1 = "vhdx-direct-1";
    const payload2 = [_]u8{0x3C} ** 256;

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    var info = try createWithOptions(io, file, initial_size, .{});
    const initial_bat_length = info.bat_length;
    try std.testing.expectEqual(initial_size, info.virtual_size);
    try std.testing.expectEqual(default_block_size, info.block_size);

    try pwrite(file, io, &info, payload0, sparse_offset);
    try pwrite(file, io, &info, &payload2, cross_boundary_offset);
    try resize(file, io, &info, grown_size);
    try std.testing.expect(info.bat_length > initial_bat_length);
    try pwrite(file, io, &info, payload1, distant_offset);

    const reopened = try open(io, file);
    try std.testing.expectEqual(grown_size, reopened.virtual_size);
    try std.testing.expect(reopened.bat_length >= info.bat_length);

    var buf0: [payload0.len]u8 = undefined;
    _ = try pread(file, io, reopened, &buf0, sparse_offset);
    try std.testing.expectEqualSlices(u8, payload0, &buf0);

    var buf1: [payload1.len]u8 = undefined;
    _ = try pread(file, io, reopened, &buf1, distant_offset);
    try std.testing.expectEqualSlices(u8, payload1, &buf1);

    var buf2: [payload2.len]u8 = undefined;
    _ = try pread(file, io, reopened, &buf2, cross_boundary_offset);
    try std.testing.expectEqualSlices(u8, &payload2, &buf2);

    var zero_buf: [64]u8 = undefined;
    _ = try pread(file, io, reopened, &zero_buf, @as(u64, default_block_size));
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &zero_buf);
}

test "create rejects an overflowing header sequence before modifying the file" {
    const io = std.testing.io;
    const path = "test-vhdx-sequence-overflow.vhdx";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true });
    defer file.close(io);

    try std.testing.expectError(
        error.HeaderSequenceOverflow,
        createWithOptions(io, file, default_logical_sector_size, .{
            .header_sequence_base = std.math.maxInt(u64),
        }),
    );
    try std.testing.expectEqual(@as(u64, 0), (try file.stat(io)).size);

    var info = try createWithOptions(io, file, default_logical_sector_size, .{
        .header_sequence_base = 0,
    });
    const initial_file_size = (try file.stat(io)).size;
    info.header_sequence_number = std.math.maxInt(u64) - 1;
    try std.testing.expectError(error.HeaderSequenceOverflow, pwrite(file, io, &info, "x", 0));
    try std.testing.expectError(error.HeaderSequenceOverflow, resize(file, io, &info, 2 * default_logical_sector_size));
    try std.testing.expectEqual(initial_file_size, (try file.stat(io)).size);
    try std.testing.expectEqual(@as(u64, default_logical_sector_size), info.virtual_size);
}
