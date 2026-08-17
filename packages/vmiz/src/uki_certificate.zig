//! Extracts the Authenticode signer shared by the fallback and named UKIs in
//! a disk image. Certificate extraction identifies a CMS claim; it does not
//! establish image, signature, or certificate-chain trust.

const std = @import("std");
const artifact_pipeline = @import("artifact_pipeline.zig");
const authenticode = @import("authenticode.zig");
const fat32 = @import("fat32.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;

const Allocator = std.mem.Allocator;
const Io = std.Io;

const machine_x86_64: u16 = 0x8664;
const machine_aarch64: u16 = 0xaa64;
const max_uki_directory_entries = 4096;

pub const Options = struct {
    expected_sha256: ?artifact_pipeline.Digest = null,
    max_partition_array_bytes: u64 = 16 * 1024 * 1024,
    max_uki_bytes: usize = 512 * 1024 * 1024,
};

pub const Result = struct {
    certificate_der: []u8,
    certificate_sha256: artifact_pipeline.Digest,
    subject_der: []u8,
    issuer_der: []u8,
    serial_number: []u8,
    uki_paths: [][]u8,

    pub fn deinit(self: *Result, allocator: Allocator) void {
        allocator.free(self.certificate_der);
        allocator.free(self.subject_der);
        allocator.free(self.issuer_der);
        allocator.free(self.serial_number);
        for (self.uki_paths) |path| allocator.free(path);
        allocator.free(self.uki_paths);
        self.* = undefined;
    }
};

const Candidate = struct {
    path: []u8,
    size: u32,
    fallback_machine: ?u16 = null,
};

pub fn extractAlloc(
    allocator: Allocator,
    io: Io,
    image: *Image,
    options: Options,
) !Result {
    const dependencies = try image.sourceDependencyPaths(allocator);
    defer {
        for (dependencies) |path| allocator.free(path);
        allocator.free(dependencies);
    }
    if (dependencies.len != 0) return error.Qcow2BackingUnsupported;

    var verified = try gpt.readVerifiedGpt(
        image.*,
        io,
        allocator,
        options.max_partition_array_bytes,
    );
    defer verified.deinit(allocator);

    var esp_partition: ?gpt.PartitionEntry = null;
    for (verified.partitions) |partition| {
        if (!std.mem.eql(
            u8,
            &partition.partition_type_guid,
            &guid.esp,
        )) continue;
        if (esp_partition != null) return error.MultipleEspPartitions;
        esp_partition = partition;
    }
    const esp = esp_partition orelse return error.MissingEspPartition;
    const first_byte = std.math.mul(
        u64,
        esp.first_lba,
        gpt.sector_size,
    ) catch return error.InvalidEspBounds;
    const sector_count = std.math.add(
        u64,
        esp.last_lba - esp.first_lba,
        1,
    ) catch return error.InvalidEspBounds;
    const byte_length = std.math.mul(
        u64,
        sector_count,
        gpt.sector_size,
    ) catch return error.InvalidEspBounds;
    var filesystem = try fat32.open(image, io, .{
        .offset = first_byte,
        .length = byte_length,
    });

    var candidates = std.array_list.Managed(Candidate).init(allocator);
    defer {
        for (candidates.items) |candidate| allocator.free(candidate.path);
        candidates.deinit();
    }

    const boot_entries = filesystem.listDirAllocLimited(
        io,
        allocator,
        "EFI/BOOT",
        max_uki_directory_entries,
    ) catch |err| switch (err) {
        error.PathNotFound => return error.MissingFallbackUki,
        else => return err,
    };
    defer fat32.freeDirEntries(allocator, boot_entries);
    for (boot_entries) |entry| {
        if (entry.kind != .file) continue;
        const fallback_machine: ?u16 =
            if (std.ascii.eqlIgnoreCase(entry.name, "BOOTX64.EFI"))
                machine_x86_64
            else if (std.ascii.eqlIgnoreCase(entry.name, "BOOTAA64.EFI"))
                machine_aarch64
            else
                null;
        if (fallback_machine == null) continue;
        if (candidates.items.len != 0) return error.MultipleFallbackUkis;
        if (entry.size > options.max_uki_bytes) return error.UkiTooLarge;
        try candidates.append(.{
            .path = try std.fmt.allocPrint(
                allocator,
                "EFI/BOOT/{s}",
                .{entry.name},
            ),
            .size = entry.size,
            .fallback_machine = fallback_machine,
        });
    }
    if (candidates.items.len == 0) return error.MissingFallbackUki;

    const linux_entries = filesystem.listDirAllocLimited(
        io,
        allocator,
        "EFI/Linux",
        max_uki_directory_entries,
    ) catch |err| switch (err) {
        error.PathNotFound => return error.MissingNamedUki,
        else => return err,
    };
    defer fat32.freeDirEntries(allocator, linux_entries);
    var named_count: usize = 0;
    for (linux_entries) |entry| {
        if (entry.kind != .file or entry.name.len <= 4 or
            !std.ascii.eqlIgnoreCase(entry.name[entry.name.len - 4 ..], ".efi"))
        {
            continue;
        }
        if (entry.size > options.max_uki_bytes) return error.UkiTooLarge;
        try candidates.append(.{
            .path = try std.fmt.allocPrint(
                allocator,
                "EFI/Linux/{s}",
                .{entry.name},
            ),
            .size = entry.size,
        });
        named_count += 1;
    }
    if (named_count == 0) return error.MissingNamedUki;
    std.mem.sort(Candidate, candidates.items, {}, lessCandidate);

    var certificate_der: ?[]u8 = null;
    errdefer if (certificate_der) |bytes| allocator.free(bytes);
    var subject_der: ?[]u8 = null;
    errdefer if (subject_der) |bytes| allocator.free(bytes);
    var issuer_der: ?[]u8 = null;
    errdefer if (issuer_der) |bytes| allocator.free(bytes);
    var serial_number: ?[]u8 = null;
    errdefer if (serial_number) |bytes| allocator.free(bytes);
    var machine: ?u16 = null;

    for (candidates.items) |candidate| {
        if (candidate.size > options.max_uki_bytes) return error.UkiTooLarge;
        const bytes = try filesystem.readFileAlloc(
            io,
            allocator,
            candidate.path,
        );
        defer allocator.free(bytes);
        const signer = try authenticode.embeddedSigner(bytes);
        if (candidate.fallback_machine) |expected_machine| {
            if (signer.machine != expected_machine)
                return error.FallbackArchitectureMismatch;
        }
        if (machine) |expected_machine| {
            if (signer.machine != expected_machine)
                return error.MixedUkiArchitectures;
        } else {
            machine = signer.machine;
        }
        if (certificate_der) |expected_certificate| {
            if (!std.mem.eql(
                u8,
                expected_certificate,
                signer.certificate_der,
            )) {
                return error.MixedUkiSigners;
            }
        } else {
            certificate_der = try allocator.dupe(
                u8,
                signer.certificate_der,
            );
            subject_der = try allocator.dupe(u8, signer.subject_der);
            issuer_der = try allocator.dupe(u8, signer.issuer_der);
            serial_number = try allocator.dupe(u8, signer.serial_number);
        }
    }

    const certificate = certificate_der orelse return error.MissingNamedUki;
    const digest = artifact_pipeline.sha256Bytes(certificate);
    if (options.expected_sha256) |expected| {
        if (!std.mem.eql(u8, &digest, &expected))
            return error.CertificateFingerprintMismatch;
    }

    const paths = try allocator.alloc([]u8, candidates.items.len);
    var path_count: usize = 0;
    errdefer {
        for (paths[0..path_count]) |path| allocator.free(path);
        allocator.free(paths);
    }
    for (candidates.items) |candidate| {
        paths[path_count] = try allocator.dupe(u8, candidate.path);
        path_count += 1;
    }

    const result: Result = .{
        .certificate_der = certificate,
        .certificate_sha256 = digest,
        .subject_der = subject_der.?,
        .issuer_der = issuer_der.?,
        .serial_number = serial_number.?,
        .uki_paths = paths,
    };
    certificate_der = null;
    subject_der = null;
    issuer_der = null;
    serial_number = null;
    return result;
}

fn lessCandidate(_: void, left: Candidate, right: Candidate) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

test "extracts one signer through every supported image format" {
    const io = std.testing.io;
    const cases = [_]struct {
        path: []const u8,
        format: image_mod.Format,
        options: image_mod.CreateOptions = .{},
    }{
        .{ .path = "test-uki-certificate.raw", .format = .raw },
        .{
            .path = "test-uki-certificate-fixed.vhd",
            .format = .vhd,
            .options = .{ .vhd_subformat = .fixed },
        },
        .{
            .path = "test-uki-certificate-dynamic.vhd",
            .format = .vhd,
            .options = .{ .vhd_subformat = .dynamic },
        },
        .{ .path = "test-uki-certificate.vhdx", .format = .vhdx },
        .{ .path = "test-uki-certificate.qcow2", .format = .qcow2 },
    };

    for (cases) |case| {
        defer Io.Dir.cwd().deleteFile(io, case.path) catch {};
        var image = try makeTestImage(
            io,
            case.path,
            case.format,
            case.options,
            machine_x86_64,
            testCertificateOne(),
            testCertificateOne(),
        );
        defer image.close(io);
        const expected = artifact_pipeline.sha256Bytes(testCertificateOne());
        var result = try extractAlloc(
            std.testing.allocator,
            io,
            &image,
            .{ .expected_sha256 = expected },
        );
        defer result.deinit(std.testing.allocator);
        try std.testing.expectEqualSlices(
            u8,
            testCertificateOne(),
            result.certificate_der,
        );
        try std.testing.expectEqualSlices(
            u8,
            &expected,
            &result.certificate_sha256,
        );
        try std.testing.expectEqual(@as(usize, 3), result.uki_paths.len);
        try std.testing.expectEqualStrings(
            "EFI/BOOT/BOOTX64.EFI",
            result.uki_paths[0],
        );
        try std.testing.expectEqualStrings(
            "EFI/Linux/vmlinuz-a.efi",
            result.uki_paths[1],
        );
        try std.testing.expectEqualStrings(
            "EFI/Linux/vmlinuz-b.EFI",
            result.uki_paths[2],
        );
    }
}

test "supports AArch64 and rejects fingerprint or mixed signer" {
    const io = std.testing.io;
    const path = "test-uki-certificate-aarch64.raw";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    var image = try makeTestImage(
        io,
        path,
        .raw,
        .{},
        machine_aarch64,
        testCertificateOne(),
        testCertificateOne(),
    );
    defer image.close(io);

    var result = try extractAlloc(std.testing.allocator, io, &image, .{});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "EFI/BOOT/BOOTAA64.EFI",
        result.uki_paths[0],
    );

    const wrong_digest = artifact_pipeline.sha256Bytes(testCertificateTwo());
    try std.testing.expectError(
        error.CertificateFingerprintMismatch,
        extractAlloc(
            std.testing.allocator,
            io,
            &image,
            .{ .expected_sha256 = wrong_digest },
        ),
    );
    image.close(io);

    try Io.Dir.cwd().deleteFile(io, path);
    image = try makeTestImage(
        io,
        path,
        .raw,
        .{},
        machine_aarch64,
        testCertificateOne(),
        testCertificateTwo(),
    );
    try std.testing.expectError(
        error.MixedUkiSigners,
        extractAlloc(std.testing.allocator, io, &image, .{}),
    );
}

fn makeTestImage(
    io: Io,
    path: []const u8,
    format: image_mod.Format,
    create_options: image_mod.CreateOptions,
    machine: u16,
    fallback_certificate: []const u8,
    named_certificate: []const u8,
) !Image {
    const disk_size: u64 = 72 * 1024 * 1024;
    const esp_size: u64 = 64 * 1024 * 1024;
    var image = try Image.create(io, path, format, disk_size, create_options);
    errdefer image.close(io);
    var placements: [1]gpt.Placement = undefined;
    try gpt.writeGpt(
        &image,
        io,
        guid.parse("11111111-1111-1111-1111-111111111111"),
        &.{
            .{
                .type_guid = guid.esp,
                .unique_guid = guid.parse(
                    "22222222-2222-2222-2222-222222222222",
                ),
                .size_sectors = esp_size / gpt.sector_size,
                .name_utf16le = gpt.asciiName("EFI System"),
            },
        },
        &placements,
    );
    const placement = placements[0];
    const region = fat32.Region{
        .offset = placement.first_lba * gpt.sector_size,
        .length = (placement.last_lba - placement.first_lba + 1) *
            gpt.sector_size,
    };
    try fat32.format(&image, io, .{
        .partition_offset = region.offset,
        .partition_len = region.length,
    });
    var filesystem = try fat32.open(&image, io, region);
    try filesystem.createDir(io, "EFI/BOOT");
    try filesystem.createDir(io, "EFI/Linux");

    const fallback = try makeSignedTestPe(
        std.testing.allocator,
        machine,
        fallback_certificate,
    );
    defer std.testing.allocator.free(fallback);
    const named = try makeSignedTestPe(
        std.testing.allocator,
        machine,
        named_certificate,
    );
    defer std.testing.allocator.free(named);
    try filesystem.writeFile(
        io,
        if (machine == machine_aarch64)
            "EFI/BOOT/BOOTAA64.EFI"
        else
            "EFI/BOOT/BOOTX64.EFI",
        fallback,
    );
    try filesystem.writeFile(io, "EFI/Linux/vmlinuz-b.EFI", named);
    try filesystem.writeFile(io, "EFI/Linux/vmlinuz-a.efi", named);
    return image;
}

fn makeSignedTestPe(
    allocator: Allocator,
    machine: u16,
    certificate: []const u8,
) ![]u8 {
    const unsigned = try allocator.alloc(u8, 512);
    defer allocator.free(unsigned);
    @memset(unsigned, 0);
    unsigned[0..2].* = "MZ".*;
    std.mem.writeInt(u32, unsigned[0x3c..0x40], 0x80, .little);
    unsigned[0x80..0x84].* = "PE\x00\x00".*;
    std.mem.writeInt(u16, unsigned[0x84..0x86], machine, .little);
    std.mem.writeInt(u16, unsigned[0x94..0x96], 0xf0, .little);
    std.mem.writeInt(u16, unsigned[0x98..0x9a], 0x20b, .little);
    std.mem.writeInt(u32, unsigned[0x104..0x108], 16, .little);

    var prepared = try authenticode.prepareRsaSha256Alloc(
        allocator,
        unsigned,
    );
    defer prepared.deinit(allocator);
    const signature = [_]u8{0x5a} ** 256;
    return authenticode.finishRsaSha256Alloc(
        allocator,
        prepared,
        certificate,
        &signature,
    );
}

fn testCertificateOne() []const u8 {
    return testCertificateSerial(1);
}

fn testCertificateTwo() []const u8 {
    return testCertificateSerial(2);
}

fn testCertificateSerial(comptime serial: u8) []const u8 {
    return "\x30\x81\x92\x30\x7d\xa0\x03\x02\x01\x02\x02\x01" ++
        [_]u8{serial} ++
        "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00" ++
        "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
        "Test Signer" ++
        "\x30\x1e\x17\x0d\x32\x36\x30\x31\x30\x31\x30\x30\x30\x30" ++
        "\x30\x30\x5a\x17\x0d\x32\x37\x30\x31\x30\x31\x30\x30\x30" ++
        "\x30\x30\x30\x5a" ++
        "\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x0c\x0b" ++
        "Test Signer" ++
        "\x30\x14\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01" ++
        "\x01\x05\x00\x03\x03\x00\x30\x00" ++
        "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05" ++
        "\x00\x03\x02\x00\x00";
}
