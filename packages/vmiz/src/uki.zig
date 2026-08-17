//! Unified Kernel Image (UKI) assembly helpers. This module keeps the PE/COFF
//! section-layout work separate from `bootconfig.zig`, which remains focused on
//! ESP/source-tree discovery and FAT32 population.

const std = @import("std");

pub const GenerateOptions = struct {
    /// Prebuilt PE/EFI systemd-stub-style loader binary.
    stub: []const u8,
    /// Raw kernel payload placed into the `.linux` section.
    linux: []const u8,
    /// Optional initrd payload placed into `.initrd`.
    initrd: ?[]const u8 = null,
    /// Kernel command line placed into `.cmdline`.
    cmdline: []const u8,
    /// `os-release(5)` contents placed into `.osrel`.
    os_release: []const u8,
    /// Kernel release string placed into `.uname`.
    uname: []const u8,
    /// Optional splash image placed into `.splash`.
    splash: ?[]const u8 = null,
};

pub const GenerateError = std.mem.Allocator.Error || error{
    BadDosSignature,
    BadPeSignature,
    InvalidAlignment,
    InvalidOptionalHeader,
    InvalidSecurityDirectory,
    InvalidSectionTable,
    SectionNameTooLong,
    TooManySections,
    TruncatedStub,
    UnsupportedOptionalHeader,
};

const image_scn_cnt_code = 0x0000_0020;
const image_scn_cnt_initialized_data = 0x0000_0040;
const image_scn_cnt_uninitialized_data = 0x0000_0080;
const image_scn_mem_execute = 0x2000_0000;
const image_scn_mem_read = 0x4000_0000;
const image_scn_mem_write = 0x8000_0000;

const pe_signature = "PE\x00\x00";
const optional_header_magic_pe32_plus: u16 = 0x20B;
const section_header_size: usize = 40;
const file_header_size: usize = 20;
const optional_header_fixed_size_pe32_plus: usize = 112;
const data_directory_entry_size: usize = 8;
const security_directory_index: usize = 4;

const file_header_machine_offset: usize = 0;
const file_header_section_count_offset: usize = 2;
const file_header_size_of_optional_header_offset: usize = 16;

const optional_header_size_of_code_offset: usize = 4;
const optional_header_size_of_initialized_data_offset: usize = 8;
const optional_header_size_of_uninitialized_data_offset: usize = 12;
const optional_header_section_alignment_offset: usize = 32;
const optional_header_file_alignment_offset: usize = 36;
const optional_header_size_of_image_offset: usize = 56;
const optional_header_size_of_headers_offset: usize = 60;
const optional_header_checksum_offset: usize = 64;
const optional_header_subsystem_offset: usize = 68;
const optional_header_number_of_rva_and_sizes_offset: usize = 108;
const optional_header_data_directories_offset: usize = 112;

const efi_subsystem_application: u16 = 10;

const PeSection = struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
    source: []const u8,
};

const ParsedStub = struct {
    pe_offset: usize,
    file_header_offset: usize,
    optional_header_offset: usize,
    section_table_offset: usize,
    section_alignment: u32,
    file_alignment: u32,
    machine: u16,
    subsystem: u16,
    optional_header_size: usize,
    section_count: usize,
    sections: []const PeSection,
    security_directory: ?FileRange,
};

pub const FileRange = struct {
    offset: u32,
    size: u32,
};

const SectionSpec = struct {
    name: []const u8,
    contents: []const u8,
    characteristics: u32 = image_scn_cnt_initialized_data | image_scn_mem_read,
};

pub fn generate(allocator: std.mem.Allocator, options: GenerateOptions) GenerateError![]u8 {
    const extra_sections = [_]SectionSpec{
        .{ .name = ".linux", .contents = options.linux },
        .{ .name = ".initrd", .contents = options.initrd orelse "" },
        .{ .name = ".cmdline", .contents = options.cmdline },
        .{ .name = ".osrel", .contents = options.os_release },
        .{ .name = ".uname", .contents = options.uname },
        .{ .name = ".splash", .contents = options.splash orelse "" },
    };

    var filtered = std.array_list.Managed(SectionSpec).init(allocator);
    defer filtered.deinit();

    for (extra_sections) |section| {
        if (section.contents.len == 0 and
            (std.mem.eql(u8, section.name, ".initrd") or std.mem.eql(u8, section.name, ".splash")))
        {
            continue;
        }
        try filtered.append(section);
    }

    return appendSections(allocator, options.stub, filtered.items);
}

fn appendSections(
    allocator: std.mem.Allocator,
    stub: []const u8,
    extra_sections: []const SectionSpec,
) GenerateError![]u8 {
    const parsed = try parseStub(allocator, stub);
    defer allocator.free(parsed.sections);

    const new_section_count = parsed.section_count + extra_sections.len;
    if (new_section_count > std.math.maxInt(u16)) return error.TooManySections;

    const section_table_end = parsed.section_table_offset + new_section_count * section_header_size;
    const size_of_headers = try alignForwardU32(section_table_end, parsed.file_alignment);

    const final_sections = try allocator.alloc(PeSection, new_section_count);
    defer allocator.free(final_sections);

    var next_virtual_address: u32 = 0;
    var next_raw_offset = size_of_headers;

    for (parsed.sections, 0..) |section, index| {
        const raw_size = if (section.raw_size == 0) 0 else try alignForwardU32(section.raw_size, parsed.file_alignment);
        const virtual_size = if (section.virtual_size == 0) section.raw_size else section.virtual_size;
        const raw_offset = if (raw_size == 0) 0 else next_raw_offset;
        final_sections[index] = .{
            .name = section.name,
            .virtual_size = virtual_size,
            .virtual_address = section.virtual_address,
            .raw_size = raw_size,
            .raw_offset = raw_offset,
            .characteristics = section.characteristics,
            .source = section.source,
        };
        if (raw_size != 0) next_raw_offset = try addAligned(next_raw_offset, raw_size, parsed.file_alignment);
        next_virtual_address = @max(next_virtual_address, section.virtual_address + try sectionExtent(section));
    }

    next_virtual_address = try alignForwardU32(next_virtual_address, parsed.section_alignment);

    for (extra_sections, parsed.section_count..) |section, index| {
        const raw_size = if (section.contents.len == 0) 0 else try alignForwardU32(section.contents.len, parsed.file_alignment);
        const virtual_size = std.math.cast(u32, section.contents.len) orelse return error.InvalidSectionTable;
        final_sections[index] = .{
            .name = try encodeSectionName(section.name),
            .virtual_size = virtual_size,
            .virtual_address = next_virtual_address,
            .raw_size = raw_size,
            .raw_offset = if (raw_size == 0) 0 else next_raw_offset,
            .characteristics = section.characteristics,
            .source = section.contents,
        };
        if (raw_size != 0) next_raw_offset = try addAligned(next_raw_offset, raw_size, parsed.file_alignment);
        next_virtual_address = try alignForwardU32(next_virtual_address + @max(virtual_size, raw_size), parsed.section_alignment);
    }

    const size_of_image = if (new_section_count == 0)
        size_of_headers
    else
        try alignForwardU32(final_sections[new_section_count - 1].virtual_address + @max(final_sections[new_section_count - 1].virtual_size, final_sections[new_section_count - 1].raw_size), parsed.section_alignment);

    const output_len = std.math.cast(usize, next_raw_offset) orelse return error.InvalidSectionTable;
    var output = try allocator.alloc(u8, output_len);
    errdefer allocator.free(output);
    @memset(output, 0);

    std.mem.copyForwards(u8, output[0..parsed.section_table_offset], stub[0..parsed.section_table_offset]);
    std.mem.writeInt(u16, output[parsed.file_header_offset + file_header_machine_offset ..][0..2], parsed.machine, .little);
    std.mem.writeInt(u16, output[parsed.file_header_offset + file_header_section_count_offset ..][0..2], @intCast(new_section_count), .little);
    std.mem.writeInt(u16, output[parsed.file_header_offset + file_header_size_of_optional_header_offset ..][0..2], @intCast(parsed.optional_header_size), .little);

    std.mem.writeInt(u16, output[parsed.optional_header_offset..][0..2], optional_header_magic_pe32_plus, .little);
    std.mem.writeInt(u32, output[parsed.optional_header_offset + optional_header_size_of_code_offset ..][0..4], sumSectionSize(final_sections, image_scn_cnt_code), .little);
    std.mem.writeInt(u32, output[parsed.optional_header_offset + optional_header_size_of_initialized_data_offset ..][0..4], sumSectionSize(final_sections, image_scn_cnt_initialized_data), .little);
    std.mem.writeInt(u32, output[parsed.optional_header_offset + optional_header_size_of_uninitialized_data_offset ..][0..4], sumUninitializedDataSize(final_sections), .little);
    std.mem.writeInt(u32, output[parsed.optional_header_offset + optional_header_section_alignment_offset ..][0..4], parsed.section_alignment, .little);
    std.mem.writeInt(u32, output[parsed.optional_header_offset + optional_header_file_alignment_offset ..][0..4], parsed.file_alignment, .little);
    std.mem.writeInt(u32, output[parsed.optional_header_offset + optional_header_size_of_image_offset ..][0..4], size_of_image, .little);
    std.mem.writeInt(u32, output[parsed.optional_header_offset + optional_header_size_of_headers_offset ..][0..4], size_of_headers, .little);
    std.mem.writeInt(u32, output[parsed.optional_header_offset + optional_header_checksum_offset ..][0..4], 0, .little);
    std.mem.writeInt(u16, output[parsed.optional_header_offset + optional_header_subsystem_offset ..][0..2], parsed.subsystem, .little);

    const number_of_rva_and_sizes = std.mem.readInt(u32, output[parsed.optional_header_offset + optional_header_number_of_rva_and_sizes_offset ..][0..4], .little);
    if (number_of_rva_and_sizes > security_directory_index and
        parsed.optional_header_size >= optional_header_data_directories_offset + (security_directory_index + 1) * data_directory_entry_size)
    {
        const security_directory_offset = parsed.optional_header_offset + optional_header_data_directories_offset + security_directory_index * data_directory_entry_size;
        @memset(output[security_directory_offset .. security_directory_offset + data_directory_entry_size], 0);
    }

    const section_table = output[parsed.section_table_offset .. parsed.section_table_offset + new_section_count * section_header_size];
    @memset(section_table, 0);
    for (final_sections, 0..) |section, index| {
        const header = section_table[index * section_header_size ..][0..section_header_size];
        std.mem.copyForwards(u8, header[0..8], &section.name);
        std.mem.writeInt(u32, header[8..12], section.virtual_size, .little);
        std.mem.writeInt(u32, header[12..16], section.virtual_address, .little);
        std.mem.writeInt(u32, header[16..20], section.raw_size, .little);
        std.mem.writeInt(u32, header[20..24], section.raw_offset, .little);
        std.mem.writeInt(u32, header[24..28], 0, .little);
        std.mem.writeInt(u32, header[28..32], 0, .little);
        std.mem.writeInt(u16, header[32..34], 0, .little);
        std.mem.writeInt(u16, header[34..36], 0, .little);
        std.mem.writeInt(u32, header[36..40], section.characteristics, .little);

        if (section.raw_size == 0) continue;
        std.mem.copyForwards(u8, output[section.raw_offset .. section.raw_offset + section.source.len], section.source);
    }

    return output;
}

fn parseStub(allocator: std.mem.Allocator, stub: []const u8) GenerateError!ParsedStub {
    if (stub.len < 64) return error.TruncatedStub;
    if (!std.mem.eql(u8, stub[0..2], "MZ")) return error.BadDosSignature;

    const pe_offset = std.mem.readInt(u32, stub[0x3C..0x40], .little);
    const file_header_offset = pe_offset + pe_signature.len;
    if (file_header_offset + file_header_size > stub.len) return error.TruncatedStub;
    if (!std.mem.eql(u8, stub[pe_offset .. pe_offset + pe_signature.len], pe_signature)) return error.BadPeSignature;

    const section_count = std.mem.readInt(u16, stub[file_header_offset + file_header_section_count_offset ..][0..2], .little);
    const optional_header_size = std.mem.readInt(u16, stub[file_header_offset + file_header_size_of_optional_header_offset ..][0..2], .little);
    const optional_header_offset = file_header_offset + file_header_size;
    const optional_header_end = optional_header_offset + optional_header_size;
    if (optional_header_end > stub.len or optional_header_size < optional_header_fixed_size_pe32_plus) return error.InvalidOptionalHeader;

    const magic = std.mem.readInt(u16, stub[optional_header_offset..][0..2], .little);
    if (magic != optional_header_magic_pe32_plus) return error.UnsupportedOptionalHeader;

    const section_alignment = std.mem.readInt(u32, stub[optional_header_offset + optional_header_section_alignment_offset ..][0..4], .little);
    const file_alignment = std.mem.readInt(u32, stub[optional_header_offset + optional_header_file_alignment_offset ..][0..4], .little);
    if (!isValidAlignment(section_alignment) or !isValidAlignment(file_alignment)) return error.InvalidAlignment;

    const section_table_offset = optional_header_end;
    const section_table_end = section_table_offset + @as(usize, section_count) * section_header_size;
    if (section_table_end > stub.len) return error.InvalidSectionTable;

    const sections = try allocator.alloc(PeSection, section_count);
    errdefer allocator.free(sections);

    for (sections, 0..) |*section, index| {
        const header = stub[section_table_offset + index * section_header_size ..][0..section_header_size];
        const raw_size = std.mem.readInt(u32, header[16..20], .little);
        const raw_offset = std.mem.readInt(u32, header[20..24], .little);
        const raw_end = std.math.add(u32, raw_offset, raw_size) catch return error.InvalidSectionTable;
        if (raw_size != 0 and raw_end > stub.len) return error.InvalidSectionTable;

        section.* = .{
            .name = header[0..8].*,
            .virtual_size = std.mem.readInt(u32, header[8..12], .little),
            .virtual_address = std.mem.readInt(u32, header[12..16], .little),
            .raw_size = raw_size,
            .raw_offset = raw_offset,
            .characteristics = std.mem.readInt(u32, header[36..40], .little),
            .source = if (raw_size == 0) "" else stub[raw_offset..raw_end],
        };
    }

    const number_of_rva_and_sizes = std.mem.readInt(
        u32,
        stub[optional_header_offset + optional_header_number_of_rva_and_sizes_offset ..][0..4],
        .little,
    );
    const security_directory = if (number_of_rva_and_sizes > security_directory_index and
        optional_header_size >= optional_header_data_directories_offset +
            (security_directory_index + 1) * data_directory_entry_size)
    blk: {
        const entry_offset = optional_header_offset + optional_header_data_directories_offset +
            security_directory_index * data_directory_entry_size;
        const file_offset = std.mem.readInt(u32, stub[entry_offset..][0..4], .little);
        const size = std.mem.readInt(u32, stub[entry_offset + 4 ..][0..4], .little);
        if (file_offset == 0 and size == 0) break :blk null;
        if (file_offset == 0 or size == 0 or file_offset % 8 != 0)
            return error.InvalidSecurityDirectory;
        const end = std.math.add(u32, file_offset, size) catch
            return error.InvalidSecurityDirectory;
        if (end > stub.len) return error.InvalidSecurityDirectory;
        break :blk FileRange{ .offset = file_offset, .size = size };
    } else null;

    return .{
        .pe_offset = pe_offset,
        .file_header_offset = file_header_offset,
        .optional_header_offset = optional_header_offset,
        .section_table_offset = section_table_offset,
        .section_alignment = section_alignment,
        .file_alignment = file_alignment,
        .machine = std.mem.readInt(u16, stub[file_header_offset + file_header_machine_offset ..][0..2], .little),
        .subsystem = std.mem.readInt(u16, stub[optional_header_offset + optional_header_subsystem_offset ..][0..2], .little),
        .optional_header_size = optional_header_size,
        .section_count = section_count,
        .sections = sections,
        .security_directory = security_directory,
    };
}

fn encodeSectionName(name: []const u8) GenerateError![8]u8 {
    if (name.len == 0 or name.len > 8) return error.SectionNameTooLong;
    var encoded = [_]u8{0} ** 8;
    std.mem.copyForwards(u8, encoded[0..name.len], name);
    return encoded;
}

fn sectionExtent(section: PeSection) GenerateError!u32 {
    const extent = @max(section.virtual_size, section.raw_size);
    if (section.virtual_address > std.math.maxInt(u32) - extent) return error.InvalidSectionTable;
    return extent;
}

fn addAligned(base: u32, amount: u32, alignment: u32) GenerateError!u32 {
    if (base > std.math.maxInt(u32) - amount) return error.InvalidSectionTable;
    return try alignForwardU32(base + amount, alignment);
}

fn alignForwardU32(value: anytype, alignment: u32) GenerateError!u32 {
    if (!isValidAlignment(alignment)) return error.InvalidAlignment;
    const promoted = std.math.cast(u64, value) orelse return error.InvalidSectionTable;
    const aligned = std.mem.alignForward(u64, promoted, alignment);
    return std.math.cast(u32, aligned) orelse return error.InvalidSectionTable;
}

fn isValidAlignment(alignment: u32) bool {
    return alignment != 0 and std.math.isPowerOfTwo(alignment);
}

fn sumSectionSize(sections: []const PeSection, mask: u32) u32 {
    var total: u32 = 0;
    for (sections) |section| {
        if (section.characteristics & mask == 0) continue;
        total +|= section.raw_size;
    }
    return total;
}

fn sumUninitializedDataSize(sections: []const PeSection) u32 {
    var total: u32 = 0;
    for (sections) |section| {
        if (section.characteristics & image_scn_cnt_uninitialized_data == 0) continue;
        total +|= section.virtual_size;
    }
    return total;
}

/// A PE section view whose contents borrow the image passed to `inspect`.
pub const SectionView = struct {
    name: [8]u8,
    contents: []const u8,
    raw_offset: u32,
    raw_size: u32,
    virtual_size: u32,

    pub fn nameSlice(self: *const SectionView) []const u8 {
        return trimSectionName(&self.name);
    }

    /// File padding covered by Authenticode but ignored by the PE loader.
    pub fn paddingRange(self: *const SectionView) ?FileRange {
        if (self.raw_size <= self.virtual_size) return null;
        return .{
            .offset = self.raw_offset + self.virtual_size,
            .size = self.raw_size - self.virtual_size,
        };
    }
};

/// Read-only PE/COFF details and section contents from a UKI or stub image.
/// Call `deinit` with the allocator used by `inspect`; section contents borrow
/// the inspected image and must not outlive it.
pub const Inspection = struct {
    machine: u16,
    subsystem: u16,
    sections: []SectionView,
    security_directory: ?FileRange,

    pub fn deinit(self: *Inspection, allocator: std.mem.Allocator) void {
        allocator.free(self.sections);
        self.* = undefined;
    }

    pub fn findSection(self: *const Inspection, name: []const u8) ?SectionView {
        for (self.sections) |section| {
            if (std.mem.eql(u8, section.nameSlice(), name)) return section;
        }
        return null;
    }
};

/// Inspects a PE32+ UKI without copying its section payloads.
pub fn inspect(allocator: std.mem.Allocator, image: []const u8) GenerateError!Inspection {
    const parsed = try parseStub(allocator, image);
    defer allocator.free(parsed.sections);

    var sections = try allocator.alloc(SectionView, parsed.sections.len);
    for (parsed.sections, 0..) |section, index| {
        sections[index] = .{
            .name = section.name,
            .contents = section.source[0..@min(section.source.len, section.virtual_size)],
            .raw_offset = section.raw_offset,
            .raw_size = section.raw_size,
            .virtual_size = section.virtual_size,
        };
    }
    return .{
        .machine = parsed.machine,
        .subsystem = parsed.subsystem,
        .sections = sections,
        .security_directory = parsed.security_directory,
    };
}

fn trimSectionName(name: *const [8]u8) []const u8 {
    const slice = name[0..];
    const end = std.mem.indexOfScalar(u8, slice, 0) orelse slice.len;
    return slice[0..end];
}

test "generate builds a structurally valid UKI with systemd-stub sections" {
    const stub = try syntheticStubPe(std.testing.allocator, 0x8664);
    defer std.testing.allocator.free(stub);

    const linux = "linux payload";
    const initrd = "initrd payload";
    const cmdline = "root=PARTUUID=11111111-1111-1111-1111-111111111111 quiet";
    const os_release = "ID=vmiz\nNAME=\"vmiz\"\n";
    const uname = "6.8.12-test";
    const splash = "BMPDATA";

    const image = try generate(std.testing.allocator, .{
        .stub = stub,
        .linux = linux,
        .initrd = initrd,
        .cmdline = cmdline,
        .os_release = os_release,
        .uname = uname,
        .splash = splash,
    });
    defer std.testing.allocator.free(image);

    try std.testing.expectEqualStrings("MZ", image[0..2]);
    const pe_offset = std.mem.readInt(u32, image[0x3C..0x40], .little);
    try std.testing.expectEqualStrings(pe_signature, image[pe_offset .. pe_offset + pe_signature.len]);

    var inspection = try inspect(std.testing.allocator, image);
    defer inspection.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 0x8664), inspection.machine);
    try std.testing.expectEqual(efi_subsystem_application, inspection.subsystem);
    try std.testing.expect(inspection.security_directory == null);
    try expectSectionContents(&inspection, ".text", "\xC3");
    try expectSectionContents(&inspection, ".linux", linux);
    try expectSectionContents(&inspection, ".initrd", initrd);
    try expectSectionContents(&inspection, ".cmdline", cmdline);
    try expectSectionContents(&inspection, ".osrel", os_release);
    try expectSectionContents(&inspection, ".uname", uname);
    try expectSectionContents(&inspection, ".splash", splash);
    const cmdline_section = inspection.findSection(".cmdline").?;
    const cmdline_padding = cmdline_section.paddingRange().?;
    try std.testing.expect(cmdline_padding.size > 0);
    try std.testing.expect(cmdline_padding.offset >= cmdline_section.raw_offset + cmdline.len);

    const parsed = try parseStub(std.testing.allocator, image);
    defer std.testing.allocator.free(parsed.sections);
    try std.testing.expect(parsed.section_count >= 7);
    try std.testing.expectEqual(efi_subsystem_application, parsed.subsystem);

    const size_of_headers = std.mem.readInt(u32, image[parsed.optional_header_offset + optional_header_size_of_headers_offset ..][0..4], .little);
    const size_of_image = std.mem.readInt(u32, image[parsed.optional_header_offset + optional_header_size_of_image_offset ..][0..4], .little);
    try std.testing.expectEqual(@as(u32, 0), size_of_headers % parsed.file_alignment);
    try std.testing.expectEqual(@as(u32, 0), size_of_image % parsed.section_alignment);

    const security_directory_offset = parsed.optional_header_offset + optional_header_data_directories_offset + security_directory_index * data_directory_entry_size;
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, image[security_directory_offset..][0..4], .little));
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, image[security_directory_offset + 4 ..][0..4], .little));
}

test "inspect rejects overflowing PE section bounds" {
    const image = try syntheticStubPe(std.testing.allocator, 0x8664);
    defer std.testing.allocator.free(image);

    const pe_offset = std.mem.readInt(u32, image[0x3C..0x40], .little);
    const file_header_offset = pe_offset + pe_signature.len;
    const optional_header_size = std.mem.readInt(
        u16,
        image[file_header_offset + file_header_size_of_optional_header_offset ..][0..2],
        .little,
    );
    const section_table_offset = file_header_offset + file_header_size + optional_header_size;
    const section = image[section_table_offset..][0..section_header_size];
    std.mem.writeInt(u32, section[16..20], 1, .little);
    std.mem.writeInt(u32, section[20..24], std.math.maxInt(u32), .little);

    try std.testing.expectError(
        error.InvalidSectionTable,
        inspect(std.testing.allocator, image),
    );
}

fn expectSectionContents(inspection: *const Inspection, name: []const u8, expected: []const u8) !void {
    const section = inspection.findSection(name) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, expected, section.contents);
}

/// Builds a minimal, synthetic systemd-stub-shaped PE32+ image. Exposed so
/// other modules can construct UKI fixtures without shipping a real stub.
pub fn syntheticStubPe(allocator: std.mem.Allocator, machine: u16) ![]u8 {
    const file_alignment: u32 = 0x200;
    const section_alignment: u32 = 0x1000;
    const pe_offset: usize = 0x80;
    const optional_header_size: usize = 240;
    const section_count: usize = 1;
    const size_of_headers = std.mem.alignForward(u32, pe_offset + pe_signature.len + file_header_size + optional_header_size + section_count * section_header_size, file_alignment);
    const file_len = size_of_headers + file_alignment;

    var buffer = try allocator.alloc(u8, file_len);
    @memset(buffer, 0);

    std.mem.copyForwards(u8, buffer[0..2], "MZ");
    std.mem.writeInt(u32, buffer[0x3C..0x40], pe_offset, .little);
    std.mem.copyForwards(u8, buffer[pe_offset .. pe_offset + pe_signature.len], pe_signature);

    const file_header_offset = pe_offset + pe_signature.len;
    std.mem.writeInt(u16, buffer[file_header_offset + file_header_machine_offset ..][0..2], machine, .little);
    std.mem.writeInt(u16, buffer[file_header_offset + file_header_section_count_offset ..][0..2], section_count, .little);
    std.mem.writeInt(u16, buffer[file_header_offset + file_header_size_of_optional_header_offset ..][0..2], optional_header_size, .little);
    std.mem.writeInt(u16, buffer[file_header_offset + 18 ..][0..2], 0x202, .little);

    const optional_header_offset = file_header_offset + file_header_size;
    std.mem.writeInt(u16, buffer[optional_header_offset..][0..2], optional_header_magic_pe32_plus, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_size_of_code_offset ..][0..4], file_alignment, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_size_of_initialized_data_offset ..][0..4], 0, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_size_of_uninitialized_data_offset ..][0..4], 0, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 16 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 20 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 24 ..][0..8], 0x400000, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_section_alignment_offset ..][0..4], section_alignment, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_file_alignment_offset ..][0..4], file_alignment, .little);
    std.mem.writeInt(u16, buffer[optional_header_offset + 40 ..][0..2], 6, .little);
    std.mem.writeInt(u16, buffer[optional_header_offset + 48 ..][0..2], 6, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_size_of_image_offset ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_size_of_headers_offset ..][0..4], size_of_headers, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_checksum_offset ..][0..4], 0, .little);
    std.mem.writeInt(u16, buffer[optional_header_offset + optional_header_subsystem_offset ..][0..2], efi_subsystem_application, .little);
    std.mem.writeInt(u16, buffer[optional_header_offset + 70 ..][0..2], 0x160, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 72 ..][0..8], 0x100000, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 80 ..][0..8], 0x1000, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 88 ..][0..8], 0x100000, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 96 ..][0..8], 0x1000, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 104 ..][0..4], 0, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + optional_header_number_of_rva_and_sizes_offset ..][0..4], 16, .little);

    const section_header_offset = optional_header_offset + optional_header_size;
    const header = buffer[section_header_offset .. section_header_offset + section_header_size];
    std.mem.copyForwards(u8, header[0..5], ".text");
    std.mem.writeInt(u32, header[8..12], 1, .little);
    std.mem.writeInt(u32, header[12..16], 0x1000, .little);
    std.mem.writeInt(u32, header[16..20], file_alignment, .little);
    std.mem.writeInt(u32, header[20..24], size_of_headers, .little);
    std.mem.writeInt(u32, header[36..40], image_scn_cnt_code | image_scn_mem_execute | image_scn_mem_read, .little);

    buffer[size_of_headers] = 0xC3;
    return buffer;
}
