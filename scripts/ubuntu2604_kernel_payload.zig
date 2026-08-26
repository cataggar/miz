const std = @import("std");

const Allocator = std.mem.Allocator;
const arm64_linux_magic_offset = 0x38;
const arm64_linux_magic = "ARM\x64";
const gzip_magic: u16 = 0x8b1f;

pub const Architecture = enum {
    x86_64,
    aarch64,

    pub fn parse(value: []const u8) ?Architecture {
        if (std.mem.eql(u8, value, "x86_64") or std.mem.eql(u8, value, "amd64"))
            return .x86_64;
        if (std.mem.eql(u8, value, "aarch64") or std.mem.eql(u8, value, "arm64"))
            return .aarch64;
        return null;
    }
};

pub const Payload = struct {
    bytes: []const u8,
    owned: ?[]u8 = null,

    pub fn deinit(self: *Payload, allocator: Allocator) void {
        if (self.owned) |bytes| allocator.free(bytes);
        self.* = undefined;
    }
};

pub fn peMachine(bytes: []const u8) !u16 {
    if (bytes.len < 0x40 or !std.mem.eql(u8, bytes[0..2], "MZ"))
        return error.InvalidPeImage;
    const pe_offset = std.mem.readInt(u32, bytes[0x3c..0x40], .little);
    if (pe_offset > bytes.len -| 6) return error.InvalidPeImage;
    const offset: usize = @intCast(pe_offset);
    if (!std.mem.eql(u8, bytes[offset .. offset + 4], "PE\x00\x00"))
        return error.InvalidPeImage;
    const machine: *const [2]u8 = @ptrCast(bytes[offset + 4 ..].ptr);
    return std.mem.readInt(u16, machine, .little);
}

fn validateArm64EfiKernel(bytes: []const u8) !void {
    if (try peMachine(bytes) != 0xaa64) return error.WrongKernelArchitecture;
    const magic_end = arm64_linux_magic_offset + arm64_linux_magic.len;
    if (bytes.len < magic_end or
        !std.mem.eql(u8, bytes[arm64_linux_magic_offset..magic_end], arm64_linux_magic))
    {
        return error.InvalidArm64LinuxImage;
    }
}

pub fn normalize(
    allocator: Allocator,
    architecture: Architecture,
    kernel: []const u8,
    max_linux_size: usize,
) !Payload {
    if (architecture == .x86_64) return .{ .bytes = kernel };
    if (kernel.len > max_linux_size) return error.Arm64KernelTooLarge;

    if (validateArm64EfiKernel(kernel)) |_| {
        return .{ .bytes = kernel };
    } else |err| switch (err) {
        error.InvalidPeImage => {},
        else => return err,
    }

    if (kernel.len < 2 or std.mem.readInt(u16, kernel[0..2], .little) != gzip_magic)
        return error.InvalidArm64KernelCompression;

    var input: std.Io.Reader = .fixed(kernel);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(&input, .gzip, &window);
    const bytes = decompress.reader.allocRemaining(
        allocator,
        .limited(max_linux_size + 1),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.Arm64KernelTooLarge,
        else => return error.UnreadableArm64Kernel,
    };
    errdefer allocator.free(bytes);
    if (bytes.len > max_linux_size) return error.Arm64KernelTooLarge;
    if (input.seek != input.end) return error.TrailingArm64KernelData;
    const metadata = switch (decompress.container_metadata) {
        .gzip => |gzip_metadata| gzip_metadata,
        else => unreachable,
    };
    if (metadata.count != @as(u32, @intCast(bytes.len)) or
        metadata.crc != std.hash.Crc32.hash(bytes))
    {
        return error.InvalidArm64KernelChecksum;
    }
    try validateArm64EfiKernel(bytes);
    return .{ .bytes = bytes, .owned = bytes };
}

fn arm64EfiKernel() [0x86]u8 {
    var bytes: [0x86]u8 = @splat(0);
    @memcpy(bytes[0..2], "MZ");
    @memcpy(
        bytes[arm64_linux_magic_offset .. arm64_linux_magic_offset + arm64_linux_magic.len],
        arm64_linux_magic,
    );
    std.mem.writeInt(u32, bytes[0x3c..0x40], 0x80, .little);
    @memcpy(bytes[0x80..0x84], "PE\x00\x00");
    std.mem.writeInt(u16, bytes[0x84..0x86], 0xaa64, .little);
    return bytes;
}

fn gzip(allocator: Allocator, bytes: []const u8) ![]u8 {
    var output = try std.Io.Writer.Allocating.initCapacity(allocator, 4096);
    errdefer output.deinit();
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(
        &output.writer,
        &history,
        .gzip,
        .default,
    );
    try compressor.writer.writeAll(bytes);
    try compressor.finish();
    return output.toOwnedSlice();
}

test "Arm64 gzip kernel becomes an EFI payload" {
    const allocator = std.testing.allocator;
    const arm64 = arm64EfiKernel();
    const compressed = try gzip(allocator, &arm64);
    defer allocator.free(compressed);

    var payload = try normalize(allocator, .aarch64, compressed, 512 * 1024 * 1024);
    defer payload.deinit(allocator);
    try std.testing.expect(payload.owned != null);
    try std.testing.expectEqualSlices(u8, &arm64, payload.bytes);
}

test "uncompressed Arm64 EFI kernel is borrowed" {
    const allocator = std.testing.allocator;
    const arm64 = arm64EfiKernel();
    var payload = try normalize(allocator, .aarch64, &arm64, arm64.len);
    defer payload.deinit(allocator);
    try std.testing.expect(payload.owned == null);
    try std.testing.expectEqualSlices(u8, &arm64, payload.bytes);
}

test "x86 kernel remains byte-for-byte unchanged" {
    const bytes = "Ubuntu compressed x86 kernel payload";
    var payload = try normalize(std.testing.allocator, .x86_64, bytes, 1);
    defer payload.deinit(std.testing.allocator);
    try std.testing.expect(payload.owned == null);
    try std.testing.expect(payload.bytes.ptr == bytes.ptr);
    try std.testing.expectEqualSlices(u8, bytes, payload.bytes);
}

test "Arm64 kernel validation fails closed" {
    const allocator = std.testing.allocator;
    const arm64 = arm64EfiKernel();

    var wrong_arch = arm64;
    std.mem.writeInt(u16, wrong_arch[0x84..0x86], 0x8664, .little);
    try std.testing.expectError(
        error.WrongKernelArchitecture,
        normalize(allocator, .aarch64, &wrong_arch, wrong_arch.len),
    );

    var missing_magic = arm64;
    missing_magic[arm64_linux_magic_offset] = 0;
    try std.testing.expectError(
        error.InvalidArm64LinuxImage,
        normalize(allocator, .aarch64, &missing_magic, missing_magic.len),
    );
    try std.testing.expectError(
        error.InvalidArm64KernelCompression,
        normalize(allocator, .aarch64, "not a kernel", 1024),
    );

    const compressed = try gzip(allocator, &arm64);
    defer allocator.free(compressed);
    try std.testing.expectError(
        error.UnreadableArm64Kernel,
        normalize(allocator, .aarch64, compressed[0 .. compressed.len - 4], arm64.len),
    );

    const corrupted = try allocator.dupe(u8, compressed);
    defer allocator.free(corrupted);
    corrupted[corrupted.len - 8] ^= 1;
    try std.testing.expectError(
        error.InvalidArm64KernelChecksum,
        normalize(allocator, .aarch64, corrupted, arm64.len),
    );

    var trailing = try allocator.alloc(u8, compressed.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..compressed.len], compressed);
    trailing[compressed.len] = 0;
    try std.testing.expectError(
        error.TrailingArm64KernelData,
        normalize(allocator, .aarch64, trailing, arm64.len),
    );
    try std.testing.expectError(
        error.Arm64KernelTooLarge,
        normalize(allocator, .aarch64, compressed, arm64.len - 1),
    );
}
