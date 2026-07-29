//! COSI (Composable OS Image) writer.
//!
//! Partition payloads are emitted as real `.raw.zst` members using
//! `zstd.zig`'s small built-in encoder, so repetitive GPT/filesystem regions
//! shrink while
//! remaining decodable by standard zstd tooling.
//!
//! The emitted `metadata.json` schema is verified against Azure Linux Image
//! Tools' real implementation:
//! - `toolkit/tools/pkg/imagecustomizerlib/cosimetadata.go`
//! - `toolkit/tools/pkg/imagecustomizerlib/cosicommon.go`
//! - `toolkit/tools/pkg/imagecustomizerlib/extractgpt.go`
//! - `toolkit/tools/pkg/imagecustomizerlib/extractpartitions.go`
//!
//! Standalone `zvmi cosi` can derive only a subset of that metadata from a raw
//! disk image, so `writeWithOptions` accepts caller-supplied values for fields
//! like bootloader details and the OS package list. When no override is
//! supplied, `osRelease` is best-effort populated by reading `/etc/os-release`
//! from an ext4 root filesystem inside the image.

const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const ext4 = @import("ext4.zig");
const guid = @import("guid.zig");
const gpt = @import("gpt.zig");
const image_mod = @import("image.zig");
const tar = @import("tar.zig");
const verity = @import("verity.zig");
const zstd = @import("zstd.zig");

const Image = image_mod.Image;

const root_partition_x86_64 = guid.parse("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");
const root_partition_arm64 = guid.parse("B921B045-1DF0-41C3-AF44-4C6F280D3FAE");

pub const WriteError = std.mem.Allocator.Error || gpt.ReadError || Image.PreadError ||
    Io.File.OpenError || std.Io.Writer.Error || tar.Error || zstd.Error || error{
    ShortRead,
};

const GptImageName = "images/image_gpt.raw.zst";
const metadata_version = "1.2";
const file_mode = 0o400;

pub fn write(img: Image, io: Io, allocator: std.mem.Allocator, output_path: []const u8) WriteError!void {
    try writeWithOptions(img, io, allocator, output_path, .{});
}

pub const SystemdBootEntry = struct {
    type: []const u8,
    path: []const u8,
    cmdline: []const u8,
    kernel: []const u8,
};

pub const SystemdBoot = struct {
    entries: []const SystemdBootEntry,
};

pub const CosiBootloader = struct {
    type: []const u8 = "",
    systemdBoot: ?SystemdBoot = null,
};

pub const Compression = struct {
    maxWindowLog: u32 = 0,
};

pub const OsPackage = struct {
    name: []const u8,
    version: []const u8,
    release: []const u8,
    arch: []const u8,
};

pub const WriteOptions = struct {
    os_arch: ?[]const u8 = null,
    os_release: ?[]const u8 = null,
    bootloader: CosiBootloader = .{},
    root_verity: ?verity.Info = null,
    os_packages: []const OsPackage = &.{},
    compression: Compression = .{},
};

pub fn writeWithOptions(
    img: Image,
    io: Io,
    allocator: std.mem.Allocator,
    output_path: []const u8,
    options: WriteOptions,
) WriteError!void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = try gpt.readGpt(img, io, arena);
    const image_id = parsed.header.disk_guid;

    const disk_guid_storage = try arena.create([36]u8);
    const disk_guid_text = guid.formatLower(disk_guid_storage, parsed.header.disk_guid);

    const gpt_region = try buildGptRegion(arena, img, io, parsed.header, image_id);
    const partitions = try arena.alloc(PartitionArtifact, parsed.partitions.len);
    for (parsed.partitions, 0..) |entry, i| {
        partitions[i] = try buildPartitionArtifact(arena, img, io, entry, @intCast(i + 1), image_id);
    }

    const os_release = try detectOsRelease(arena, img, io, partitions, options.os_release);
    const metadata_json = try buildMetadataJson(arena, img.virtual_size, disk_guid_text, gpt_region, partitions, os_release, options);

    const output_file = try Io.Dir.cwd().createFile(io, output_path, .{ .truncate = true });
    defer output_file.close(io);

    var file_buffer: [16 * 1024]u8 = undefined;
    var file_writer = output_file.writer(io, &file_buffer);
    var tar_writer = tar.Writer.init(&file_writer.interface);

    try tar_writer.writeFile("cosi-marker", file_mode, "");
    try tar_writer.writeFile("metadata.json", file_mode, metadata_json);

    var entry_buffer: [8 * 1024]u8 = undefined;

    try tar_writer.beginFile(GptImageName, file_mode, gpt_region.image.compressedSize);
    {
        var entry_writer = tar_writer.entryWriter(&entry_buffer);
        try streamCompressedRegionWriter(&entry_writer.interface, img, io, 0, gpt_region.uncompressed_size, image_id);
        try entry_writer.interface.flush();
    }
    try tar_writer.endFile();

    for (partitions) |part| {
        try tar_writer.beginFile(part.image.path, file_mode, part.image.compressedSize);
        var entry_writer = tar_writer.entryWriter(&entry_buffer);
        try streamCompressedRegionWriter(&entry_writer.interface, img, io, part.offset_bytes, part.uncompressed_size, image_id);
        try entry_writer.interface.flush();
        try tar_writer.endFile();
    }

    try tar_writer.finish();
}

const ArtifactImage = struct {
    path: []const u8,
    compressedSize: u64,
    uncompressedSize: u64,
    sha384: []const u8,
};

const GptArtifact = struct {
    image: ArtifactImage,
    uncompressed_size: u64,
};

const PartitionArtifact = struct {
    number: u32,
    offset_bytes: u64,
    uncompressed_size: u64,
    image: ArtifactImage,
    mount_point: []const u8,
    fs_type: []const u8,
    fs_uuid: []const u8,
    part_type: []const u8,
    part_type_guid: guid.Guid,
};

fn buildGptRegion(arena: std.mem.Allocator, img: Image, io: Io, header: gpt.Header, image_id: [16]u8) WriteError!GptArtifact {
    const gpt_size = primaryGptSize(header);
    const meta = try hashCompressedRegion(arena, img, io, 0, gpt_size, image_id);
    return .{
        .image = .{
            .path = GptImageName,
            .compressedSize = meta.compressed_size,
            .uncompressedSize = gpt_size,
            .sha384 = meta.sha384,
        },
        .uncompressed_size = gpt_size,
    };
}

fn buildPartitionArtifact(
    arena: std.mem.Allocator,
    img: Image,
    io: Io,
    entry: gpt.PartitionEntry,
    number: u32,
    image_id: [16]u8,
) WriteError!PartitionArtifact {
    const offset_bytes = entry.first_lba * gpt.sector_size;
    const uncompressed_size = (entry.last_lba - entry.first_lba + 1) * gpt.sector_size;
    const image_path = try std.fmt.allocPrint(arena, "images/image_{d}.raw.zst", .{number});

    const part_type = try dupeGuidText(arena, entry.partition_type_guid);
    const part_name = try decodePartitionNameAlloc(arena, &entry.name_utf16le);
    const fs_probe = try probeFilesystem(arena, img, io, offset_bytes, uncompressed_size);
    const meta = try hashCompressedRegion(arena, img, io, offset_bytes, uncompressed_size, image_id);

    return .{
        .number = number,
        .offset_bytes = offset_bytes,
        .uncompressed_size = uncompressed_size,
        .image = .{
            .path = image_path,
            .compressedSize = meta.compressed_size,
            .uncompressedSize = uncompressed_size,
            .sha384 = meta.sha384,
        },
        .mount_point = inferMountPoint(entry.partition_type_guid, part_name),
        .fs_type = fs_probe.fs_type,
        .fs_uuid = fs_probe.fs_uuid,
        .part_type = part_type,
        .part_type_guid = entry.partition_type_guid,
    };
}

const HashedArtifact = struct {
    compressed_size: u64,
    sha384: []const u8,
};

fn hashCompressedRegion(
    arena: std.mem.Allocator,
    img: Image,
    io: Io,
    offset_bytes: u64,
    length: u64,
    image_id: [16]u8,
) WriteError!HashedArtifact {
    var discard_buffer: [1024]u8 = undefined;
    var hash_buffer: [1024]u8 = undefined;
    var discard = std.Io.Writer.Discarding.init(&discard_buffer);
    var hashed = discard.writer.hashed(std.crypto.hash.sha2.Sha384.init(.{}), &hash_buffer);

    try streamCompressedRegionWriter(&hashed.writer, img, io, offset_bytes, length, image_id);
    try hashed.writer.flush();

    var digest: [std.crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
    hashed.hasher.final(&digest);
    const digest_hex = std.fmt.bytesToHex(digest, .lower);

    return .{
        .compressed_size = discard.fullCount(),
        .sha384 = try arena.dupe(u8, &digest_hex),
    };
}

fn primaryGptSize(header: gpt.Header) u64 {
    return header.partition_entry_lba * gpt.sector_size +
        @as(u64, header.num_partition_entries) * header.partition_entry_size;
}

fn streamCompressedRegionWriter(writer: *std.Io.Writer, img: Image, io: Io, offset_bytes: u64, length: u64, image_id: [16]u8) WriteError!void {
    try zstd.writeSkippableFrame(writer, image_id);
    try zstd.writeFrameHeader(writer, length);
    if (length == 0) {
        try zstd.writeRawBlock(writer, &.{}, true);
        return;
    }

    var buffer: [zstd.max_block_size]u8 = undefined;
    var done: u64 = 0;
    while (done < length) {
        const remaining = length - done;
        const chunk_len: usize = @intCast(@min(remaining, buffer.len));
        const got = try img.pread(io, buffer[0..chunk_len], offset_bytes + done);
        if (got != chunk_len) return error.ShortRead;
        done += chunk_len;
        try zstd.writeBlocksForSlice(writer, buffer[0..chunk_len], done == length);
    }
}

const FsProbe = struct {
    fs_type: []const u8,
    fs_uuid: []const u8,
};

fn probeFilesystem(arena: std.mem.Allocator, img: Image, io: Io, offset_bytes: u64, length: u64) WriteError!FsProbe {
    var boot_sector: [512]u8 = [_]u8{0} ** 512;
    if (length >= boot_sector.len) {
        const got = try img.pread(io, &boot_sector, offset_bytes);
        if (got == boot_sector.len and isFatBootSector(&boot_sector)) {
            const serial_offset: usize = if (std.mem.eql(u8, boot_sector[82..90], "FAT32   ")) 67 else 39;
            const serial = readU32Le(boot_sector[serial_offset .. serial_offset + 4]);
            const fs_uuid = try std.fmt.allocPrint(arena, "{X:0>4}-{X:0>4}", .{ serial >> 16, serial & 0xFFFF });
            return .{ .fs_type = "vfat", .fs_uuid = fs_uuid };
        }
        if (got >= 96 and std.mem.eql(u8, boot_sector[0..4], "XFSB")) {
            const fs_uuid = try dupeUuidBytesText(arena, boot_sector[32..48]);
            return .{ .fs_type = "xfs", .fs_uuid = fs_uuid };
        }
    }

    var superblock: [2048]u8 = [_]u8{0} ** 2048;
    if (length >= superblock.len) {
        const got = try img.pread(io, &superblock, offset_bytes);
        if (got == superblock.len and std.mem.readInt(u16, superblock[1024 + 0x38 .. 1024 + 0x3A], .little) == 0xEF53) {
            const fs_uuid = try dupeUuidBytesText(arena, superblock[1024 + 0x68 .. 1024 + 0x78]);
            return .{ .fs_type = "ext4", .fs_uuid = fs_uuid };
        }
    }

    return .{ .fs_type = "", .fs_uuid = "" };
}

fn isFatBootSector(sector: *const [512]u8) bool {
    if (!std.mem.eql(u8, sector[510..512], "\x55\xAA")) return false;
    return std.mem.eql(u8, sector[54..62], "FAT12   ") or
        std.mem.eql(u8, sector[54..62], "FAT16   ") or
        std.mem.eql(u8, sector[82..90], "FAT32   ");
}

fn formatUuidBytes(buf: *[36]u8, bytes: []const u8) []const u8 {
    std.debug.assert(bytes.len == 16);
    _ = std.fmt.bufPrint(
        buf,
        "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
        .{
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        },
    ) catch unreachable;
    return buf;
}

fn dupeUuidBytesText(arena: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]const u8 {
    var buf: [36]u8 = undefined;
    return arena.dupe(u8, formatUuidBytes(&buf, bytes));
}

fn inferMountPoint(partition_type_guid: guid.Guid, part_name: []const u8) []const u8 {
    if (std.mem.eql(u8, &partition_type_guid, &guid.esp)) return "/boot/efi";
    if (std.mem.eql(u8, &partition_type_guid, &root_partition_x86_64) or
        std.mem.eql(u8, &partition_type_guid, &root_partition_arm64))
    {
        return "/";
    }
    if (containsIgnoreCase(part_name, "root")) return "/";
    if (containsIgnoreCase(part_name, "efi") or containsIgnoreCase(part_name, "esp")) return "/boot/efi";
    if (containsIgnoreCase(part_name, "boot")) return "/boot";
    return "";
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var matched = true;
        for (needle, 0..) |c, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(c)) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
}

fn decodePartitionNameAlloc(arena: std.mem.Allocator, name_utf16le: *const [36]u16) std.mem.Allocator.Error![]const u8 {
    var len: usize = 0;
    while (len < name_utf16le.len and name_utf16le[len] != 0) : (len += 1) {}

    var buf = try arena.alloc(u8, len);
    for (name_utf16le[0..len], 0..) |code_unit, i| {
        buf[i] = if (code_unit <= 0x7F) @truncate(code_unit) else '?';
    }
    return buf;
}

fn dupeGuidText(arena: std.mem.Allocator, value: guid.Guid) std.mem.Allocator.Error![]const u8 {
    var buf: [36]u8 = undefined;
    return arena.dupe(u8, guid.formatLower(&buf, value));
}

fn detectOsRelease(
    arena: std.mem.Allocator,
    img: Image,
    io: Io,
    partitions: []const PartitionArtifact,
    os_release_override: ?[]const u8,
) WriteError![]const u8 {
    if (os_release_override) |value| return value;

    for (partitions) |part| {
        if (!std.mem.eql(u8, part.mount_point, "/") or !std.mem.eql(u8, part.fs_type, "ext4")) continue;

        var reader = ext4.Reader.open(io, img.file, arena, .{ .offset = part.offset_bytes }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
        defer reader.deinit();

        return reader.readFileAlloc(io, arena, "etc/os-release") catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
    }

    return "";
}

fn readU32Le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len >= 4);
    return @as(u32, bytes[0]) | (@as(u32, bytes[1]) << 8) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 24);
}

const MetadataImage = struct {
    path: []const u8,
    compressedSize: u64,
    uncompressedSize: u64,
    sha384: []const u8,
};

const MetadataVerity = struct {
    image: MetadataImage,
    roothash: []const u8,
    hashAlgorithm: []const u8,
    salt: []const u8,
    dataBlockSize: u32,
    hashBlockSize: u32,
    dataBlocks: u64,
    format: u32,
    hashOffset: ?u64 = null,
};

const MetadataFs = struct {
    image: MetadataImage,
    mountPoint: []const u8,
    fsType: []const u8,
    fsUuid: []const u8,
    partType: []const u8,
    verity: ?MetadataVerity = null,
};

const MetadataDiskRegion = struct {
    image: MetadataImage,
    type: []const u8,
    number: ?u32 = null,
};

const MetadataDisk = struct {
    size: u64,
    type: []const u8,
    lbaSize: u32,
    gptRegions: []MetadataDiskRegion,
};

const MetadataRoot = struct {
    version: []const u8,
    osArch: []const u8,
    disk: MetadataDisk,
    images: []MetadataFs,
    osRelease: []const u8,
    id: []const u8,
    bootloader: CosiBootloader,
    osPackages: []const OsPackage,
    compression: Compression,
};

fn buildMetadataJson(
    arena: std.mem.Allocator,
    disk_size: u64,
    disk_guid_text: []const u8,
    gpt_region: GptArtifact,
    partitions: []const PartitionArtifact,
    os_release: []const u8,
    options: WriteOptions,
) WriteError![]u8 {
    const fs_entries = try arena.alloc(MetadataFs, partitions.len);
    const gpt_regions = try arena.alloc(MetadataDiskRegion, partitions.len + 1);

    gpt_regions[0] = .{
        .image = .{ .path = gpt_region.image.path, .compressedSize = gpt_region.image.compressedSize, .uncompressedSize = gpt_region.image.uncompressedSize, .sha384 = gpt_region.image.sha384 },
        .type = "primary-gpt",
    };
    for (partitions, 0..) |part, i| {
        const part_image: MetadataImage = .{
            .path = part.image.path,
            .compressedSize = part.image.compressedSize,
            .uncompressedSize = part.image.uncompressedSize,
            .sha384 = part.image.sha384,
        };
        fs_entries[i] = .{
            .image = part_image,
            .mountPoint = part.mount_point,
            .fsType = part.fs_type,
            .fsUuid = part.fs_uuid,
            .partType = part.part_type,
            .verity = try buildVerityMetadata(arena, part.mount_point, part_image, options.root_verity),
        };
        gpt_regions[i + 1] = .{
            .image = part_image,
            .type = "partition",
            .number = part.number,
        };
    }

    const metadata = MetadataRoot{
        .version = metadata_version,
        .osArch = options.os_arch orelse detectOsArch(partitions),
        .disk = .{
            .size = disk_size,
            .type = "gpt",
            .lbaSize = gpt.sector_size,
            .gptRegions = gpt_regions,
        },
        .images = fs_entries,
        .osRelease = os_release,
        .id = disk_guid_text,
        .bootloader = options.bootloader,
        .osPackages = options.os_packages,
        .compression = options.compression,
    };

    return try std.json.Stringify.valueAlloc(arena, metadata, .{});
}

fn buildVerityMetadata(
    arena: std.mem.Allocator,
    mount_point: []const u8,
    image: MetadataImage,
    info: ?verity.Info,
) std.mem.Allocator.Error!?MetadataVerity {
    if (info == null or !std.mem.eql(u8, mount_point, "/")) return null;

    var root_hash_buf: [verity.digest_size * 2]u8 = undefined;
    var salt_buf: [verity.salt_size * 2]u8 = undefined;
    const value = info.?;

    return .{
        .image = image,
        .roothash = try arena.dupe(u8, value.formatRootHash(&root_hash_buf)),
        .hashAlgorithm = value.hashAlgorithm,
        .salt = try arena.dupe(u8, value.formatSalt(&salt_buf)),
        .dataBlockSize = value.dataBlockSize,
        .hashBlockSize = value.hashBlockSize,
        .dataBlocks = value.dataBlocks,
        .format = value.format,
        .hashOffset = value.hashOffset,
    };
}

fn detectOsArch(partitions: []const PartitionArtifact) []const u8 {
    for (partitions) |part| {
        if (std.mem.eql(u8, &part.part_type_guid, &root_partition_x86_64)) return "x86_64";
        if (std.mem.eql(u8, &part.part_type_guid, &root_partition_arm64)) return "arm64";
    }
    return switch (builtin.target.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "arm64",
        else => @tagName(builtin.target.cpu.arch),
    };
}

const ParsedTarEntry = struct {
    path: []const u8,
    bytes: []const u8,
};

const InMemoryEntry = struct {
    path: []const u8,
    kind: ext4.Kind,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64 = 0,
    bytes: []const u8 = "",
};

const InMemoryTree = struct {
    entries: []const InMemoryEntry,
    index: usize = 0,
    view: ext4.FileTreeView,

    fn init(entries: []const InMemoryEntry) InMemoryTree {
        return .{
            .entries = entries,
            .view = .{
                .ctx = undefined,
                .next_fn = next,
                .reset_fn = reset,
            },
        };
    }

    fn bind(self: *InMemoryTree) void {
        self.view = .{
            .ctx = self,
            .next_fn = next,
            .reset_fn = reset,
        };
    }

    fn reset(ctx: *anyopaque) void {
        const self: *InMemoryTree = @ptrCast(@alignCast(ctx));
        self.index = 0;
    }

    fn next(ctx: *anyopaque) ext4.FileTreeView.IteratorError!?ext4.FileTreeView.Entry {
        const self: *InMemoryTree = @ptrCast(@alignCast(ctx));
        if (self.index >= self.entries.len) return null;
        const entry = self.entries[self.index];
        self.index += 1;
        return .{
            .path = entry.path,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = switch (entry.kind) {
                .file, .symlink => .{
                    .ctx = &self.entries[self.index - 1],
                    .read_at_fn = readContent,
                },
                else => null,
            },
        };
    }

    fn readContent(ctx: *const anyopaque, buffer: []u8, offset: u64) ext4.FileTreeView.ContentError!usize {
        const entry: *const InMemoryEntry = @ptrCast(@alignCast(ctx));
        const off = std.math.cast(usize, offset) orelse return error.UnexpectedEndOfStream;
        if (off > entry.bytes.len) return error.UnexpectedEndOfStream;
        const n = @min(buffer.len, entry.bytes.len - off);
        std.mem.copyForwards(u8, buffer[0..n], entry.bytes[off .. off + n]);
        return n;
    }
};

fn parseTarEntries(allocator: std.mem.Allocator, archive: []const u8) ![]ParsedTarEntry {
    var entries = std.array_list.Managed(ParsedTarEntry).init(allocator);
    errdefer entries.deinit();

    var offset: usize = 0;
    while (offset + tar.block_size <= archive.len) {
        const header = archive[offset .. offset + tar.block_size];
        offset += tar.block_size;
        if (std.mem.allEqual(u8, header, 0)) break;

        const name = std.mem.sliceTo(header[0..100], 0);
        const size_text = std.mem.sliceTo(header[124..136], 0);
        const size = if (std.mem.trim(u8, size_text, " \x00").len == 0)
            0
        else
            try std.fmt.parseInt(usize, std.mem.trim(u8, size_text, " \x00"), 8);
        try entries.append(.{ .path = try allocator.dupe(u8, name), .bytes = archive[offset .. offset + size] });
        offset += size;
        if (size % tar.block_size != 0) offset += tar.block_size - (size % tar.block_size);
    }

    return entries.toOwnedSlice();
}

fn findTarEntry(entries: []const ParsedTarEntry, path: []const u8) ?ParsedTarEntry {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.path, path)) return entry;
    }
    return null;
}

test "write builds a COSI tarball with GPT metadata and compressed zstd partitions" {
    const io = std.testing.io;
    const disk_path = "test-cosi.img";
    const cosi_path = "test-cosi.cosi";
    defer Io.Dir.cwd().deleteFile(io, disk_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, cosi_path) catch {};

    const disk_size: u64 = 32 * 1024 * 1024;
    var img = try Image.create(io, disk_path, .raw, disk_size, .{});
    defer img.close(io);

    const specs = [_]gpt.PartitionSpec{
        .{
            .type_guid = guid.esp,
            .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111"),
            .size_sectors = 2048,
            .name_utf16le = gpt.asciiName("EFI System"),
        },
        .{
            .type_guid = root_partition_x86_64,
            .unique_guid = guid.parse("22222222-2222-2222-2222-222222222222"),
            .size_sectors = 16384,
            .name_utf16le = gpt.asciiName("root"),
        },
    };
    var placements: [specs.len]gpt.Placement = undefined;
    const disk_guid = guid.parse("33333333-3333-3333-3333-333333333333");
    try gpt.writeGpt(&img, io, disk_guid, &specs, &placements);

    const esp_size = (placements[0].last_lba - placements[0].first_lba + 1) * gpt.sector_size;
    const root_size = (placements[1].last_lba - placements[1].first_lba + 1) * gpt.sector_size;
    const esp_bytes = try std.testing.allocator.alloc(u8, esp_size);
    defer std.testing.allocator.free(esp_bytes);
    const os_release = "NAME=zvmi\nID=zvmi\nVERSION_ID=1\n";
    const root_fs_uuid = [_]u8{ 0x88, 0xD2, 0xFA, 0x9B, 0x7A, 0x32, 0x45, 0x0A, 0xA9, 0xF8, 0xAA, 0x9C, 0x3D, 0xE7, 0x92, 0x98 };
    var root_tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .uid = 0, .gid = 0, .size = os_release.len, .bytes = os_release },
    });
    root_tree.bind();

    @memset(esp_bytes, 0xEE);
    esp_bytes[3] = 0x90;
    @memcpy(esp_bytes[82..90], "FAT32   ");
    esp_bytes[510] = 0x55;
    esp_bytes[511] = 0xAA;
    std.mem.writeInt(u32, esp_bytes[67..71], 0xC3D4250D, .little);

    try img.pwrite(io, esp_bytes, placements[0].first_lba * gpt.sector_size);
    _ = try ext4.populate(io, img.file, std.testing.allocator, &root_tree.view, .{
        .offset = placements[1].first_lba * gpt.sector_size,
        .length = root_size,
        .uuid = root_fs_uuid,
        .label = "rootfs",
    });

    const packages = [_]OsPackage{
        .{ .name = "bash", .version = "5.1.8", .release = "1", .arch = "x86_64" },
        .{ .name = "coreutils", .version = "9.5", .release = "2", .arch = "x86_64" },
    };
    var verity_salt: [verity.salt_size]u8 = undefined;
    var verity_root_hash: [verity.digest_size]u8 = undefined;
    for (&verity_salt, 0..) |*byte, index| byte.* = @intCast(index);
    for (&verity_root_hash, 0..) |*byte, index| byte.* = @intCast(index + 1);
    try writeWithOptions(img, io, std.testing.allocator, cosi_path, .{
        .bootloader = .{
            .type = "systemd-boot",
            .systemdBoot = .{
                .entries = &.{
                    .{
                        .type = "uki-standalone",
                        .path = "/boot/efi/EFI/Linux/zvmi.efi",
                        .cmdline = "root=UUID=88d2fa9b-7a32-450a-a9f8-aa9c3de79298 ro",
                        .kernel = "6.8.0-zvmi",
                    },
                },
            },
        },
        .root_verity = .{
            .dataBlockSize = 4096,
            .hashBlockSize = 4096,
            .dataBlocks = 2048,
            .hashOffset = 8 * 1024 * 1024,
            .hashTreeSize = 4096,
            .salt = verity_salt,
            .rootHash = verity_root_hash,
        },
        .os_packages = &packages,
        .compression = .{ .maxWindowLog = 23 },
    });

    const cosi_file = try Io.Dir.cwd().openFile(io, cosi_path, .{});
    defer cosi_file.close(io);
    const cosi_size = (try cosi_file.stat(io)).size;
    const cosi_bytes = try std.testing.allocator.alloc(u8, cosi_size);
    defer std.testing.allocator.free(cosi_bytes);
    _ = try cosi_file.readPositionalAll(io, cosi_bytes, 0);

    const entries = try parseTarEntries(std.testing.allocator, cosi_bytes);
    defer {
        for (entries) |entry| std.testing.allocator.free(entry.path);
        std.testing.allocator.free(entries);
    }

    try std.testing.expect(findTarEntry(entries, "cosi-marker") != null);
    const metadata_entry = findTarEntry(entries, "metadata.json").?;
    const gpt_entry = findTarEntry(entries, GptImageName).?;
    const esp_entry = findTarEntry(entries, "images/image_1.raw.zst").?;
    const root_entry = findTarEntry(entries, "images/image_2.raw.zst").?;

    const decoded_gpt = try zstd.decodeAlloc(std.testing.allocator, gpt_entry.bytes);
    defer std.testing.allocator.free(decoded_gpt.bytes);
    const decoded_esp = try zstd.decodeAlloc(std.testing.allocator, esp_entry.bytes);
    defer std.testing.allocator.free(decoded_esp.bytes);
    const decoded_root = try zstd.decodeAlloc(std.testing.allocator, root_entry.bytes);
    defer std.testing.allocator.free(decoded_root.bytes);

    try std.testing.expectEqualSlices(u8, esp_bytes, decoded_esp.bytes);
    var root_reader = try ext4.open(io, img.file, std.testing.allocator, .{ .offset = placements[1].first_lba * gpt.sector_size });
    defer root_reader.deinit();
    const expected_root_os_release = try root_reader.readFileAlloc(io, std.testing.allocator, "etc/os-release");
    defer std.testing.allocator.free(expected_root_os_release);
    try std.testing.expectEqualSlices(u8, os_release, expected_root_os_release);
    const decoded_root_reader_file = try Io.Dir.cwd().createFile(io, "test-cosi-rootfs.img", .{ .read = true, .truncate = true });
    defer {
        decoded_root_reader_file.close(io);
        Io.Dir.cwd().deleteFile(io, "test-cosi-rootfs.img") catch {};
    }
    try decoded_root_reader_file.writePositionalAll(io, decoded_root.bytes, 0);
    var decoded_root_reader = try ext4.open(io, decoded_root_reader_file, std.testing.allocator, .{});
    defer decoded_root_reader.deinit();
    const decoded_os_release = try decoded_root_reader.readFileAlloc(io, std.testing.allocator, "etc/os-release");
    defer std.testing.allocator.free(decoded_os_release);
    try std.testing.expectEqualSlices(u8, os_release, decoded_os_release);
    const parsed_gpt = try gpt.readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(parsed_gpt.partitions);
    try std.testing.expectEqual(primaryGptSize(parsed_gpt.header), decoded_gpt.bytes.len);

    try std.testing.expect(std.mem.indexOf(u8, metadata_entry.bytes, "\"guid\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, metadata_entry.bytes, "\"partUuid\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, metadata_entry.bytes, "\"partitionNumber\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, metadata_entry.bytes, "\"partitionName\"") == null);

    const MetadataForTest = struct {
        version: []const u8,
        osArch: []const u8,
        disk: struct {
            size: u64,
            type: []const u8,
            lbaSize: u32,
            gptRegions: []struct {
                image: struct {
                    path: []const u8,
                    compressedSize: u64,
                    uncompressedSize: u64,
                    sha384: []const u8,
                },
                type: []const u8,
                number: ?u32 = null,
            },
        },
        images: []struct {
            image: struct {
                path: []const u8,
                compressedSize: u64,
                uncompressedSize: u64,
                sha384: []const u8,
            },
            mountPoint: []const u8,
            fsType: []const u8,
            fsUuid: []const u8,
            partType: []const u8,
            verity: ?struct {
                image: struct {
                    path: []const u8,
                    compressedSize: u64,
                    uncompressedSize: u64,
                    sha384: []const u8,
                },
                roothash: []const u8,
                hashAlgorithm: []const u8,
                salt: []const u8,
                dataBlockSize: u32,
                hashBlockSize: u32,
                dataBlocks: u64,
                format: u32,
                hashOffset: ?u64 = null,
            } = null,
        },
        osRelease: []const u8,
        id: []const u8,
        bootloader: struct {
            type: []const u8,
            systemdBoot: ?struct {
                entries: []struct {
                    type: []const u8,
                    path: []const u8,
                    cmdline: []const u8,
                    kernel: []const u8,
                },
            } = null,
        },
        osPackages: []struct {
            name: []const u8,
            version: []const u8,
            release: []const u8,
            arch: []const u8,
        },
        compression: struct {
            maxWindowLog: u32,
        },
    };

    var parsed_json = try std.json.parseFromSlice(MetadataForTest, std.testing.allocator, metadata_entry.bytes, .{ .ignore_unknown_fields = true });
    defer parsed_json.deinit();

    try std.testing.expectEqualStrings(metadata_version, parsed_json.value.version);
    try std.testing.expectEqualStrings("33333333-3333-3333-3333-333333333333", parsed_json.value.id);
    try std.testing.expectEqualStrings("gpt", parsed_json.value.disk.type);
    try std.testing.expectEqual(@as(usize, 3), parsed_json.value.disk.gptRegions.len);
    try std.testing.expectEqualStrings(GptImageName, parsed_json.value.disk.gptRegions[0].image.path);
    try std.testing.expectEqualStrings("primary-gpt", parsed_json.value.disk.gptRegions[0].type);
    try std.testing.expectEqual(@as(usize, 2), parsed_json.value.images.len);
    try std.testing.expectEqualStrings("/boot/efi", parsed_json.value.images[0].mountPoint);
    try std.testing.expectEqualStrings("vfat", parsed_json.value.images[0].fsType);
    try std.testing.expectEqualStrings("C3D4-250D", parsed_json.value.images[0].fsUuid);
    try std.testing.expectEqualStrings("/", parsed_json.value.images[1].mountPoint);
    try std.testing.expectEqualStrings("ext4", parsed_json.value.images[1].fsType);
    try std.testing.expectEqualStrings("88d2fa9b-7a32-450a-a9f8-aa9c3de79298", parsed_json.value.images[1].fsUuid);
    try std.testing.expect(parsed_json.value.images[0].verity == null);
    try std.testing.expect(parsed_json.value.images[1].verity != null);
    try std.testing.expectEqualStrings("sha256", parsed_json.value.images[1].verity.?.hashAlgorithm);
    try std.testing.expectEqual(@as(u32, 4096), parsed_json.value.images[1].verity.?.dataBlockSize);
    try std.testing.expectEqual(@as(u32, 4096), parsed_json.value.images[1].verity.?.hashBlockSize);
    try std.testing.expectEqual(@as(u64, 2048), parsed_json.value.images[1].verity.?.dataBlocks);
    try std.testing.expectEqual(@as(u32, 1), parsed_json.value.images[1].verity.?.format);
    try std.testing.expectEqual(@as(?u64, 8 * 1024 * 1024), parsed_json.value.images[1].verity.?.hashOffset);
    try std.testing.expectEqualStrings(os_release, parsed_json.value.osRelease);
    try std.testing.expectEqualStrings("x86_64", parsed_json.value.osArch);
    try std.testing.expectEqualStrings("systemd-boot", parsed_json.value.bootloader.type);
    try std.testing.expect(parsed_json.value.bootloader.systemdBoot != null);
    try std.testing.expectEqual(@as(usize, 1), parsed_json.value.bootloader.systemdBoot.?.entries.len);
    try std.testing.expectEqualStrings("/boot/efi/EFI/Linux/zvmi.efi", parsed_json.value.bootloader.systemdBoot.?.entries[0].path);
    try std.testing.expectEqual(@as(usize, 2), parsed_json.value.osPackages.len);
    try std.testing.expectEqualStrings("bash", parsed_json.value.osPackages[0].name);
    try std.testing.expectEqual(@as(u32, 23), parsed_json.value.compression.maxWindowLog);
}
