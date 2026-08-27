//! Validate fixed VHD geometry for Azure uploads.
//!
//! Native port of `scripts/azure_vhd.py`. Azure only accepts a **fixed** VHD
//! whose virtual size is a whole number of MiB, and it derives the disk size
//! from the footer rather than from the file length, so a footer that
//! disagrees with the file produces an image that boots differently from the
//! one that was tested. This module re-derives every footer field, the legacy
//! CHS geometry, and the size `qemu-img` reports, and refuses anything that
//! does not agree.
//!
//! The command interface is stable and matches the Python it replaces:
//!
//!     azure_vhd verify --info <qemu-img-info.json> --vhd <path>
//!
//! On success it prints the footer's current size and the file size, one per
//! line, which is what the Azure acceptance shell reads. On a validation
//! failure it prints the failure line to stderr and exits 1; on a usage error
//! it exits 2, matching `argparse`.

const std = @import("std");
const miz = @import("miz");
const release = @import("release/root.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const contract = release.contract;
const file_support = release.file;
const json_document = release.json_document;
const vhd = miz.vhd;

/// Azure requires the virtual size of an uploaded VHD to be a whole number of
/// MiB.
pub const alignment: u64 = 1024 * 1024;
pub const footer_bytes: usize = 512;
/// The largest disk the legacy CHS triple can address. At and above this size
/// the geometry saturates, so it stops being a usable cross-check of the size.
pub const max_chs_sectors: u64 = 65535 * 16 * 255;
/// Creator application recorded by `miz azure derive`. Anything else means the
/// artifact under test was not produced by this repository's pipeline.
pub const creator_application: [4]u8 = "miz ".*;

const fixed_data_offset: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const expected_features: u32 = 2;
const expected_format_version: u32 = 0x0001_0000;
const expected_creator_version: u32 = 0x0001_0000;

/// Upper bound on `qemu-img info --output=json` output. The document is a
/// handful of fields; a megabyte is generous and finite.
pub const info_max_bytes: u64 = 1024 * 1024;

pub const Geometry = struct {
    cylinders: u16,
    heads: u8,
    sectors_per_track: u8,

    pub fn totalSectors(self: Geometry) u64 {
        return @as(u64, self.cylinders) * self.heads * self.sectors_per_track;
    }

    pub fn eql(self: Geometry, other: Geometry) bool {
        return self.cylinders == other.cylinders and
            self.heads == other.heads and
            self.sectors_per_track == other.sectors_per_track;
    }
};

pub const FooterValidation = struct {
    current_size: u64,
    /// Size `qemu-img` reports for this footer. Readers that trust the legacy
    /// CHS triple round down to whole cylinders, so the reported size is
    /// allowed to be either the footer's current size or that rounded size.
    qemu_virtual_size: u64,
};

pub const Inspection = struct {
    current_size: u64,
    file_size: u64,
    qemu_virtual_size: u64,
};

pub const ValidationError = error{
    TruncatedFooter,
    InvalidCookie,
    InvalidChecksum,
    InvalidVersion,
    InvalidCreatorIdentity,
    NotFixed,
    SizeMismatch,
    InvalidFooterState,
    UnalignedCurrentSize,
    FileSizeMismatch,
    InvalidGeometry,
    NotVpcFormat,
    InvalidReportedVirtualSize,
    IncompatibleVirtualSize,
};

pub const InspectError = ValidationError || json_document.ReadError || error{
    MissingVhd,
    CannotReadFooter,
};

/// Carries the operator-facing failure line plus whatever sizes were learned
/// before the failure, so a caller can print a size note next to it.
pub const Context = struct {
    diagnostic: contract.Diagnostic = .{},
    file_size: ?u64 = null,
    footer_current_size: ?u64 = null,
    reported_virtual_size: ?i64 = null,

    pub fn message(self: *const Context) []const u8 {
        return self.diagnostic.message();
    }

    /// Writes the size context behind a failure. Sizes are the whole subject
    /// of these failures, and byte counts alone are hard to compare by eye.
    pub fn writeNote(self: *const Context, writer: *std.Io.Writer) !void {
        if (self.file_size) |size| {
            try writer.print("note: derived VHD file size is {d} bytes ({s})\n", .{
                size,
                contract.formatMib(size).slice(),
            });
        }
        if (self.footer_current_size) |size| {
            try writer.print(
                "note: footer current size is {d} bytes ({s})\n",
                .{ size, contract.formatMib(size).slice() },
            );
        }
        if (self.reported_virtual_size) |size| {
            try writer.print("note: qemu-img reported virtual size {d}\n", .{size});
        }
    }
};

/// Legacy CHS geometry a fixed VHD of `current_size` must record. This is
/// QEMU's `calculate_geometry`, which the VHD writer in `miz` already
/// implements; validation re-derives it from the same source so a writer bug
/// cannot agree with a validator bug.
pub fn fixedVhdGeometry(current_size: u64) Geometry {
    const computed = vhd.calculateGeometry(current_size / vhd.sector_size);
    return .{
        .cylinders = computed.cylinders,
        .heads = computed.heads,
        .sectors_per_track = computed.sectors_per_track,
    };
}

/// Validates the 512-byte trailer of a derived upload VHD against the file it
/// was read from.
pub fn validateFooter(
    file_size: u64,
    footer: []const u8,
    context: *Context,
) ValidationError!FooterValidation {
    context.file_size = file_size;
    if (footer.len != footer_bytes) return context.diagnostic.fail(
        error.TruncatedFooter,
        "derived upload VHD is truncated before its complete footer",
        .{},
    );
    const raw: *const [footer_bytes]u8 = footer[0..footer_bytes];

    const decoded = vhd.Footer.decode(raw) catch |err| switch (err) {
        error.BadCookie => return context.diagnostic.fail(
            error.InvalidCookie,
            "derived upload VHD footer cookie is invalid",
            .{},
        ),
        error.BadChecksum => return context.diagnostic.fail(
            error.InvalidChecksum,
            "derived upload VHD footer checksum is invalid",
            .{},
        ),
    };

    if (decoded.features != expected_features or
        decoded.file_format_version != expected_format_version)
    {
        return context.diagnostic.fail(
            error.InvalidVersion,
            "derived upload VHD footer version is invalid",
            .{},
        );
    }
    if (!std.mem.eql(u8, &decoded.creator_application, &creator_application) or
        decoded.creator_version != expected_creator_version or
        !std.mem.eql(u8, &decoded.creator_host_os, &[_]u8{ 0, 0, 0, 0 }))
    {
        return context.diagnostic.fail(
            error.InvalidCreatorIdentity,
            "derived upload VHD creator identity is invalid",
            .{},
        );
    }
    if (decoded.data_offset != fixed_data_offset or decoded.disk_type != .fixed) {
        return context.diagnostic.fail(
            error.NotFixed,
            "derived upload VHD is not fixed",
            .{},
        );
    }
    if (decoded.original_size != decoded.current_size) {
        return context.diagnostic.fail(
            error.SizeMismatch,
            "derived upload VHD original and current sizes differ",
            .{},
        );
    }
    if (decoded.saved_state != 0 or !allZero(raw[85..])) {
        return context.diagnostic.fail(
            error.InvalidFooterState,
            "derived upload VHD footer state or reserved bytes are invalid",
            .{},
        );
    }

    const current_size = decoded.current_size;
    context.footer_current_size = current_size;
    if (current_size == 0 or current_size % alignment != 0) {
        return context.diagnostic.fail(
            error.UnalignedCurrentSize,
            "derived upload VHD current size is not 1 MiB aligned",
            .{},
        );
    }
    const expected_file_size = std.math.add(u64, current_size, footer_bytes) catch
        return context.diagnostic.fail(
            error.FileSizeMismatch,
            "derived upload VHD file size does not equal current size plus footer",
            .{},
        );
    if (file_size != expected_file_size) return context.diagnostic.fail(
        error.FileSizeMismatch,
        "derived upload VHD file size does not equal current size plus footer",
        .{},
    );

    const recorded: Geometry = .{
        .cylinders = decoded.geometry.cylinders,
        .heads = decoded.geometry.heads,
        .sectors_per_track = decoded.geometry.sectors_per_track,
    };
    if (!recorded.eql(fixedVhdGeometry(current_size))) {
        return context.diagnostic.fail(
            error.InvalidGeometry,
            "derived upload VHD CHS geometry is invalid",
            .{},
        );
    }

    const geometry_sectors = recorded.totalSectors();
    return .{
        .current_size = current_size,
        .qemu_virtual_size = if (geometry_sectors == max_chs_sectors)
            current_size
        else
            geometry_sectors * vhd.sector_size,
    };
}

/// Validates a `qemu-img info --output=json` document against the footer of
/// the file it describes, and returns the footer's current size.
pub fn validateInfo(
    info: *const std.json.ObjectMap,
    file_size: u64,
    footer: []const u8,
    context: *Context,
) ValidationError!u64 {
    if (!isVpc(info.get("format"))) return context.diagnostic.fail(
        error.NotVpcFormat,
        "derived upload image is not VHD/VPC",
        .{},
    );
    const reported = reportedVirtualSize(info.get("virtual-size")) orelse
        return context.diagnostic.fail(
            error.InvalidReportedVirtualSize,
            "derived upload VHD reported virtual size is invalid",
            .{},
        );
    context.reported_virtual_size = reported;

    const validated = try validateFooter(file_size, footer, context);
    const reported_unsigned: u64 = @intCast(reported);
    if (reported_unsigned != validated.current_size and
        reported_unsigned != validated.qemu_virtual_size)
    {
        const lower = @min(validated.current_size, validated.qemu_virtual_size);
        const upper = @max(validated.current_size, validated.qemu_virtual_size);
        if (lower == upper) {
            context.diagnostic.set(
                "derived upload VHD qemu virtual size is incompatible with " ++
                    "footer current size and legacy CHS rounding: " ++
                    "reported={d} current={d} allowed=[{d}]",
                .{ reported, validated.current_size, lower },
            );
        } else {
            context.diagnostic.set(
                "derived upload VHD qemu virtual size is incompatible with " ++
                    "footer current size and legacy CHS rounding: " ++
                    "reported={d} current={d} allowed=[{d}, {d}]",
                .{ reported, validated.current_size, lower, upper },
            );
        }
        return error.IncompatibleVirtualSize;
    }
    return validated.current_size;
}

/// Reads the footer of `vhd_path` and the `qemu-img` document at `info_path`,
/// validates them against each other, and reports the sizes.
pub fn inspect(
    allocator: Allocator,
    io: Io,
    info_path: []const u8,
    vhd_path: []const u8,
    context: *Context,
) InspectError!Inspection {
    const file_size = file_support.regularFileSize(io, vhd_path) catch {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        return context.diagnostic.fail(
            error.MissingVhd,
            "derived VHD is missing: {s}",
            .{resolveForDisplay(io, vhd_path, &buffer)},
        );
    };
    context.file_size = file_size;
    if (file_size < footer_bytes) return context.diagnostic.fail(
        error.TruncatedFooter,
        "derived upload VHD is truncated before its complete footer",
        .{},
    );

    var footer: [footer_bytes]u8 = undefined;
    _ = file_support.readTrailer(io, vhd_path, &footer) catch |err| {
        return context.diagnostic.fail(
            error.CannotReadFooter,
            "cannot read derived VHD footer: {s}",
            .{@errorName(err)},
        );
    };

    var document = try json_document.readObject(
        allocator,
        io,
        info_path,
        info_max_bytes,
        &context.diagnostic,
    );
    defer document.deinit();

    const current_size = try validateInfo(
        document.object(),
        file_size,
        &footer,
        context,
    );
    // Python reports `info["virtual-size"]` here rather than the derived
    // expectation, and `validateInfo` has already proven the two agree.
    const reported: u64 = @intCast(context.reported_virtual_size.?);
    return .{
        .current_size = current_size,
        .file_size = file_size,
        .qemu_virtual_size = reported,
    };
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn isVpc(value: ?std.json.Value) bool {
    const present = value orelse return false;
    return switch (present) {
        .string => |text| std.mem.eql(u8, text, "vpc"),
        else => false,
    };
}

/// `type(reported_size) is not int or reported_size <= 0` in the Python. JSON
/// booleans and floats are separate variants here, and an integer too large
/// for `i64` arrives as `.number_string`; all of them are rejected, which is
/// the same answer for any real disk.
fn reportedVirtualSize(value: ?std.json.Value) ?i64 {
    const present = value orelse return null;
    return switch (present) {
        .integer => |number| if (number > 0) number else null,
        else => null,
    };
}

/// Best-effort absolute spelling of `path` for the "missing" diagnostic, in
/// the spirit of the Python's `Path.resolve()`. Symlinks are not followed,
/// because the path may not exist at all.
fn resolveForDisplay(io: Io, path: []const u8, buffer: []u8) []const u8 {
    if (std.fs.path.isAbsolute(path)) return path;
    const length = Dir.cwd().realPathFile(io, ".", buffer) catch return path;
    const cwd = buffer[0..length];
    if (cwd.len + 1 + path.len > buffer.len) return path;
    const separator_index = cwd.len;
    buffer[separator_index] = '/';
    @memcpy(buffer[separator_index + 1 ..][0..path.len], path);
    return buffer[0 .. separator_index + 1 + path.len];
}

const usage_text =
    \\usage: azure_vhd verify --info INFO --vhd VHD
    \\
    \\Validate fixed VHD geometry for Azure uploads.
    \\
    \\commands:
    \\  verify    validate a derived upload VHD against its qemu-img document
    \\            and print its footer current size and file size
    \\
;

const usage_exit_code = 2;
const failure_exit_code = 1;

const Arguments = struct {
    info: []const u8,
    vhd: []const u8,
};

const ArgumentError = error{
    Usage,
    HelpRequested,
};

fn parseArguments(argv: []const []const u8) ArgumentError!Arguments {
    var info: ?[]const u8 = null;
    var vhd_path: ?[]const u8 = null;
    var index: usize = 0;

    for (argv) |argument| {
        if (std.mem.eql(u8, argument, "-h") or
            std.mem.eql(u8, argument, "--help")) return error.HelpRequested;
    }
    if (argv.len == 0) return error.Usage;
    if (!std.mem.eql(u8, argv[0], "verify")) return error.Usage;
    index = 1;

    while (index < argv.len) : (index += 1) {
        const argument = argv[index];
        if (optionValue(argv, &index, argument, "--info")) |value| {
            info = value;
        } else if (optionValue(argv, &index, argument, "--vhd")) |value| {
            vhd_path = value;
        } else return error.Usage;
    }

    return .{
        .info = info orelse return error.Usage,
        .vhd = vhd_path orelse return error.Usage,
    };
}

/// Accepts both `--name value` and `--name=value`, like `argparse`.
fn optionValue(
    argv: []const []const u8,
    index: *usize,
    argument: []const u8,
    name: []const u8,
) ?[]const u8 {
    if (std.mem.eql(u8, argument, name)) {
        if (index.* + 1 >= argv.len) return null;
        index.* += 1;
        return argv[index.*];
    }
    if (argument.len > name.len + 1 and
        std.mem.startsWith(u8, argument, name) and
        argument[name.len] == '=')
    {
        return argument[name.len + 1 ..];
    }
    return null;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    const arguments = parseArguments(argv[1..]) catch |err| switch (err) {
        error.HelpRequested => {
            try out.writeAll(usage_text);
            try out.flush();
            return;
        },
        error.Usage => {
            try err_out.writeAll(usage_text);
            try err_out.flush();
            std.process.exit(usage_exit_code);
        },
    };

    var context: Context = .{};
    const inspection = inspect(
        allocator,
        io,
        arguments.info,
        arguments.vhd,
        &context,
    ) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            try err_out.print("{s}\n", .{context.message()});
            try context.writeNote(err_out);
            try err_out.flush();
            std.process.exit(failure_exit_code);
        },
    };

    try out.print("{d}\n{d}\n", .{ inspection.current_size, inspection.file_size });
    try out.flush();
}

const testing_unique_id: [16]u8 = .{
    0x8d, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f,
    0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
};

fn testFooter(current_size: u64) [footer_bytes]u8 {
    return vhd.Footer.forFixedDisk(current_size, testing_unique_id, 1_700_000_000)
        .encode();
}

/// Recomputes the footer checksum after a test mutated a field, so each test
/// exercises the check it names rather than tripping the checksum first.
fn reseal(footer: *[footer_bytes]u8) void {
    footer[64..68].* = .{ 0, 0, 0, 0 };
    var sum: u32 = 0;
    for (footer) |byte| sum +%= byte;
    std.mem.writeInt(u32, footer[64..68], ~sum, .big);
}

fn expectFooterFailure(
    footer: []const u8,
    file_size: u64,
    expected_error: anyerror,
    expected_message: []const u8,
) !void {
    var context: Context = .{};
    try std.testing.expectError(
        expected_error,
        validateFooter(file_size, footer, &context),
    );
    try std.testing.expectEqualStrings(expected_message, context.message());
}

test "fixedVhdGeometry matches the legacy CHS reference for each branch" {
    // Small disk: 17 sectors per track, head count grown to at least 4.
    try std.testing.expect(fixedVhdGeometry(1024 * 1024).eql(.{
        .cylinders = 30,
        .heads = 4,
        .sectors_per_track = 17,
    }));
    // 30 GiB: still in the 17-sectors-per-track branch is impossible, this is
    // the 63-sector branch used by every published image size.
    const thirty_gib = 30 * 1024 * 1024 * 1024;
    const thirty = fixedVhdGeometry(thirty_gib);
    try std.testing.expectEqual(@as(u8, 16), thirty.heads);
    try std.testing.expectEqual(@as(u8, 63), thirty.sectors_per_track);
    try std.testing.expectEqual(@as(u16, 62415), thirty.cylinders);
    // Above the CHS ceiling the triple saturates and stops tracking the size.
    const saturated = fixedVhdGeometry(2 * 1024 * 1024 * 1024 * 1024);
    try std.testing.expectEqual(max_chs_sectors, saturated.totalSectors());
    try std.testing.expect(saturated.eql(fixedVhdGeometry(3 * 1024 * 1024 * 1024 * 1024)));
}

test "a footer written by the pipeline validates" {
    const current_size = 30 * 1024 * 1024 * 1024;
    const footer = testFooter(current_size);
    var context: Context = .{};
    const validated = try validateFooter(
        current_size + footer_bytes,
        &footer,
        &context,
    );
    try std.testing.expectEqual(current_size, validated.current_size);
    // 62415 * 16 * 63 sectors is just under the 30 GiB current size, so the
    // legacy rounding is the smaller of the two allowed reported sizes.
    try std.testing.expectEqual(
        @as(u64, 62415) * 16 * 63 * 512,
        validated.qemu_virtual_size,
    );
    try std.testing.expectEqual(@as(usize, 0), context.message().len);
}

test "a saturated CHS geometry reports the footer current size" {
    const current_size: u64 = 2 * 1024 * 1024 * 1024 * 1024;
    const footer = testFooter(current_size);
    var context: Context = .{};
    const validated = try validateFooter(
        current_size + footer_bytes,
        &footer,
        &context,
    );
    try std.testing.expectEqual(current_size, validated.qemu_virtual_size);
}

test "every footer rejection keeps its exact operator-facing text" {
    const current_size = 1024 * 1024 * 1024;
    const file_size = current_size + footer_bytes;
    const valid = testFooter(current_size);

    try expectFooterFailure(
        valid[0 .. footer_bytes - 1],
        file_size,
        error.TruncatedFooter,
        "derived upload VHD is truncated before its complete footer",
    );

    var cookie = valid;
    cookie[0] = 'C';
    reseal(&cookie);
    try expectFooterFailure(
        &cookie,
        file_size,
        error.InvalidCookie,
        "derived upload VHD footer cookie is invalid",
    );

    var checksum = valid;
    checksum[64] +%= 1;
    try expectFooterFailure(
        &checksum,
        file_size,
        error.InvalidChecksum,
        "derived upload VHD footer checksum is invalid",
    );

    var features = valid;
    std.mem.writeInt(u32, features[8..12], 3, .big);
    reseal(&features);
    try expectFooterFailure(
        &features,
        file_size,
        error.InvalidVersion,
        "derived upload VHD footer version is invalid",
    );

    var version = valid;
    std.mem.writeInt(u32, version[12..16], 0x0002_0000, .big);
    reseal(&version);
    try expectFooterFailure(
        &version,
        file_size,
        error.InvalidVersion,
        "derived upload VHD footer version is invalid",
    );

    var creator = valid;
    creator[28..32].* = "qemu".*;
    reseal(&creator);
    try expectFooterFailure(
        &creator,
        file_size,
        error.InvalidCreatorIdentity,
        "derived upload VHD creator identity is invalid",
    );

    var creator_version = valid;
    std.mem.writeInt(u32, creator_version[32..36], 0x0005_0003, .big);
    reseal(&creator_version);
    try expectFooterFailure(
        &creator_version,
        file_size,
        error.InvalidCreatorIdentity,
        "derived upload VHD creator identity is invalid",
    );

    var host_os = valid;
    host_os[36..40].* = "Wi2k".*;
    reseal(&host_os);
    try expectFooterFailure(
        &host_os,
        file_size,
        error.InvalidCreatorIdentity,
        "derived upload VHD creator identity is invalid",
    );

    var data_offset = valid;
    std.mem.writeInt(u64, data_offset[16..24], 512, .big);
    reseal(&data_offset);
    try expectFooterFailure(
        &data_offset,
        file_size,
        error.NotFixed,
        "derived upload VHD is not fixed",
    );

    var disk_type = valid;
    std.mem.writeInt(u32, disk_type[60..64], 3, .big);
    reseal(&disk_type);
    try expectFooterFailure(
        &disk_type,
        file_size,
        error.NotFixed,
        "derived upload VHD is not fixed",
    );

    var original = valid;
    std.mem.writeInt(u64, original[40..48], current_size - alignment, .big);
    reseal(&original);
    try expectFooterFailure(
        &original,
        file_size,
        error.SizeMismatch,
        "derived upload VHD original and current sizes differ",
    );

    var saved_state = valid;
    saved_state[84] = 1;
    reseal(&saved_state);
    try expectFooterFailure(
        &saved_state,
        file_size,
        error.InvalidFooterState,
        "derived upload VHD footer state or reserved bytes are invalid",
    );

    var reserved = valid;
    reserved[footer_bytes - 1] = 0x5a;
    reseal(&reserved);
    try expectFooterFailure(
        &reserved,
        file_size,
        error.InvalidFooterState,
        "derived upload VHD footer state or reserved bytes are invalid",
    );

    const unaligned_size = current_size + 512;
    var unaligned = testFooter(unaligned_size);
    try expectFooterFailure(
        &unaligned,
        unaligned_size + footer_bytes,
        error.UnalignedCurrentSize,
        "derived upload VHD current size is not 1 MiB aligned",
    );

    var empty = testFooter(0);
    try expectFooterFailure(
        &empty,
        footer_bytes,
        error.UnalignedCurrentSize,
        "derived upload VHD current size is not 1 MiB aligned",
    );

    try expectFooterFailure(
        &valid,
        file_size + 1,
        error.FileSizeMismatch,
        "derived upload VHD file size does not equal current size plus footer",
    );

    var geometry = valid;
    std.mem.writeInt(u16, geometry[56..58], 1, .big);
    reseal(&geometry);
    try expectFooterFailure(
        &geometry,
        file_size,
        error.InvalidGeometry,
        "derived upload VHD CHS geometry is invalid",
    );
}

test "a footer failure carries the sizes it managed to learn" {
    const current_size = 1024 * 1024 * 1024;
    const valid = testFooter(current_size);
    var context: Context = .{};
    try std.testing.expectError(
        error.FileSizeMismatch,
        validateFooter(current_size, &valid, &context),
    );

    var note: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer note.deinit();
    try context.writeNote(&note.writer);
    try std.testing.expectEqualStrings(
        "note: derived VHD file size is 1073741824 bytes (1024.0 MiB)\n" ++
            "note: footer current size is 1073741824 bytes (1024.0 MiB)\n",
        note.written(),
    );
}

fn parseInfo(text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        text,
        .{},
    );
}

test "qemu-img document validation accepts both allowed reported sizes" {
    const current_size = 30 * 1024 * 1024 * 1024;
    const footer = testFooter(current_size);
    const file_size = current_size + footer_bytes;
    const rounded: u64 = @as(u64, 62415) * 16 * 63 * 512;

    for ([_]u64{ current_size, rounded }) |reported| {
        const text = try std.fmt.allocPrint(
            std.testing.allocator,
            "{{\"format\": \"vpc\", \"virtual-size\": {d}}}",
            .{reported},
        );
        defer std.testing.allocator.free(text);
        var parsed = try parseInfo(text);
        defer parsed.deinit();
        var context: Context = .{};
        try std.testing.expectEqual(current_size, try validateInfo(
            &parsed.value.object,
            file_size,
            &footer,
            &context,
        ));
    }
}

test "qemu-img document validation rejects the wrong format and size shapes" {
    const current_size = 1024 * 1024 * 1024;
    const footer = testFooter(current_size);
    const file_size = current_size + footer_bytes;

    const Case = struct {
        document: []const u8,
        expected_error: anyerror,
        message: []const u8,
    };
    const cases = [_]Case{
        .{
            .document =
            \\{"format": "qcow2", "virtual-size": 1073741824}
            ,
            .expected_error = error.NotVpcFormat,
            .message = "derived upload image is not VHD/VPC",
        },
        .{
            .document =
            \\{"virtual-size": 1073741824}
            ,
            .expected_error = error.NotVpcFormat,
            .message = "derived upload image is not VHD/VPC",
        },
        .{
            .document =
            \\{"format": "vpc"}
            ,
            .expected_error = error.InvalidReportedVirtualSize,
            .message = "derived upload VHD reported virtual size is invalid",
        },
        .{
            .document =
            \\{"format": "vpc", "virtual-size": 0}
            ,
            .expected_error = error.InvalidReportedVirtualSize,
            .message = "derived upload VHD reported virtual size is invalid",
        },
        .{
            .document =
            \\{"format": "vpc", "virtual-size": -1}
            ,
            .expected_error = error.InvalidReportedVirtualSize,
            .message = "derived upload VHD reported virtual size is invalid",
        },
        .{
            .document =
            \\{"format": "vpc", "virtual-size": true}
            ,
            .expected_error = error.InvalidReportedVirtualSize,
            .message = "derived upload VHD reported virtual size is invalid",
        },
        .{
            .document =
            \\{"format": "vpc", "virtual-size": 1073741824.0}
            ,
            .expected_error = error.InvalidReportedVirtualSize,
            .message = "derived upload VHD reported virtual size is invalid",
        },
        .{
            .document =
            \\{"format": "vpc", "virtual-size": "1073741824"}
            ,
            .expected_error = error.InvalidReportedVirtualSize,
            .message = "derived upload VHD reported virtual size is invalid",
        },
    };

    for (cases) |case| {
        var parsed = try parseInfo(case.document);
        defer parsed.deinit();
        var context: Context = .{};
        try std.testing.expectError(case.expected_error, validateInfo(
            &parsed.value.object,
            file_size,
            &footer,
            &context,
        ));
        try std.testing.expectEqualStrings(case.message, context.message());
    }
}

test "an incompatible reported size names both allowed values" {
    const current_size = 30 * 1024 * 1024 * 1024;
    const footer = testFooter(current_size);
    const file_size = current_size + footer_bytes;
    var parsed = try parseInfo(
        \\{"format": "vpc", "virtual-size": 1073741824}
    );
    defer parsed.deinit();
    var context: Context = .{};
    try std.testing.expectError(error.IncompatibleVirtualSize, validateInfo(
        &parsed.value.object,
        file_size,
        &footer,
        &context,
    ));
    try std.testing.expectEqualStrings(
        "derived upload VHD qemu virtual size is incompatible with footer " ++
            "current size and legacy CHS rounding: reported=1073741824 " ++
            "current=32212254720 allowed=[32212131840, 32212254720]",
        context.message(),
    );
}

test "an incompatible reported size collapses one allowed value" {
    // At and above the CHS ceiling both allowed sizes are the current size.
    const current_size: u64 = 2 * 1024 * 1024 * 1024 * 1024;
    const footer = testFooter(current_size);
    const file_size = current_size + footer_bytes;
    var parsed = try parseInfo(
        \\{"format": "vpc", "virtual-size": 1073741824}
    );
    defer parsed.deinit();
    var context: Context = .{};
    try std.testing.expectError(error.IncompatibleVirtualSize, validateInfo(
        &parsed.value.object,
        file_size,
        &footer,
        &context,
    ));
    try std.testing.expectEqualStrings(
        "derived upload VHD qemu virtual size is incompatible with footer " ++
            "current size and legacy CHS rounding: reported=1073741824 " ++
            "current=2199023255552 allowed=[2199023255552]",
        context.message(),
    );
}

test "inspect validates a real file pair and reports its sizes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const current_size = 4 * 1024 * 1024;
    const vhd_path = "test-azure-vhd-inspect.vhd";
    const info_path = "test-azure-vhd-inspect.json";
    defer Dir.cwd().deleteFile(io, vhd_path) catch {};
    defer Dir.cwd().deleteFile(io, info_path) catch {};

    const payload = try allocator.alloc(u8, current_size + footer_bytes);
    defer allocator.free(payload);
    @memset(payload, 0);
    const footer = testFooter(current_size);
    @memcpy(payload[current_size..], &footer);
    try Dir.cwd().writeFile(io, .{ .sub_path = vhd_path, .data = payload });

    const geometry = fixedVhdGeometry(current_size);
    const info = try std.fmt.allocPrint(
        allocator,
        "{{\"format\": \"vpc\", \"virtual-size\": {d}}}",
        .{geometry.totalSectors() * 512},
    );
    defer allocator.free(info);
    try Dir.cwd().writeFile(io, .{ .sub_path = info_path, .data = info });

    var context: Context = .{};
    const inspection = try inspect(allocator, io, info_path, vhd_path, &context);
    try std.testing.expectEqual(@as(u64, current_size), inspection.current_size);
    try std.testing.expectEqual(
        @as(u64, current_size + footer_bytes),
        inspection.file_size,
    );
    try std.testing.expectEqual(
        geometry.totalSectors() * 512,
        inspection.qemu_virtual_size,
    );
}

test "inspect reports missing, truncated, and unreadable inputs" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const vhd_path = "test-azure-vhd-missing.vhd";
    const info_path = "test-azure-vhd-missing.json";
    defer Dir.cwd().deleteFile(io, vhd_path) catch {};
    defer Dir.cwd().deleteFile(io, info_path) catch {};
    Dir.cwd().deleteFile(io, vhd_path) catch {};

    var context: Context = .{};
    try std.testing.expectError(
        error.MissingVhd,
        inspect(allocator, io, info_path, vhd_path, &context),
    );
    try std.testing.expect(std.mem.startsWith(
        u8,
        context.message(),
        "derived VHD is missing: ",
    ));
    try std.testing.expect(std.mem.endsWith(u8, context.message(), vhd_path));

    try Dir.cwd().writeFile(io, .{ .sub_path = vhd_path, .data = "short" });
    context = .{};
    try std.testing.expectError(
        error.TruncatedFooter,
        inspect(allocator, io, info_path, vhd_path, &context),
    );
    try std.testing.expectEqualStrings(
        "derived upload VHD is truncated before its complete footer",
        context.message(),
    );

    const payload = try allocator.alloc(u8, 2 * 1024 * 1024 + footer_bytes);
    defer allocator.free(payload);
    @memset(payload, 0);
    const footer = testFooter(2 * 1024 * 1024);
    @memcpy(payload[2 * 1024 * 1024 ..], &footer);
    try Dir.cwd().writeFile(io, .{ .sub_path = vhd_path, .data = payload });

    context = .{};
    try std.testing.expectError(
        error.CannotRead,
        inspect(allocator, io, info_path, vhd_path, &context),
    );
    try std.testing.expectEqualStrings(
        "cannot read " ++ info_path ++ ": FileNotFound",
        context.message(),
    );

    try Dir.cwd().writeFile(io, .{ .sub_path = info_path, .data = "[]" });
    context = .{};
    try std.testing.expectError(
        error.NotAnObject,
        inspect(allocator, io, info_path, vhd_path, &context),
    );
    try std.testing.expectEqualStrings(
        info_path ++ " must contain a JSON object",
        context.message(),
    );
}

test "argument parsing mirrors the Python command line" {
    const parsed = try parseArguments(&.{
        "verify",
        "--info",
        "info.json",
        "--vhd",
        "disk.vhd",
    });
    try std.testing.expectEqualStrings("info.json", parsed.info);
    try std.testing.expectEqualStrings("disk.vhd", parsed.vhd);

    const joined = try parseArguments(&.{
        "verify",
        "--info=info.json",
        "--vhd=disk.vhd",
    });
    try std.testing.expectEqualStrings("info.json", joined.info);
    try std.testing.expectEqualStrings("disk.vhd", joined.vhd);

    try std.testing.expectError(error.Usage, parseArguments(&.{}));
    try std.testing.expectError(error.Usage, parseArguments(&.{"inspect"}));
    try std.testing.expectError(
        error.Usage,
        parseArguments(&.{ "verify", "--info", "info.json" }),
    );
    try std.testing.expectError(
        error.Usage,
        parseArguments(&.{ "verify", "--vhd", "disk.vhd" }),
    );
    try std.testing.expectError(
        error.Usage,
        parseArguments(&.{ "verify", "--info", "info.json", "--vhd" }),
    );
    try std.testing.expectError(
        error.Usage,
        parseArguments(&.{ "verify", "--info", "info.json", "--vhd", "disk.vhd", "extra" }),
    );
    try std.testing.expectError(
        error.HelpRequested,
        parseArguments(&.{"--help"}),
    );
    try std.testing.expectError(
        error.HelpRequested,
        parseArguments(&.{ "verify", "-h" }),
    );
}
