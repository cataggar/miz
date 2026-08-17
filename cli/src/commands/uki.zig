//! `vmiz uki certificate <disk-image> --output <certificate.pem>`
//! `vmiz uki certificate <disk-image> --output=json`

const std = @import("std");
const vmiz = @import("vmiz");
const atomic_output = @import("../atomic_output.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const usage =
    "usage: vmiz uki certificate <disk-image> --output <certificate.pem> " ++
    "[--expected-sha256 <hex>]\n" ++
    "       vmiz uki certificate <disk-image> --output=json " ++
    "[--expected-sha256 <hex>]";

const Output = union(enum) {
    pem: []const u8,
    json,
};

const ParsedArgs = struct {
    image_path: []const u8,
    output: Output,
    expected_sha256: ?vmiz.artifact_pipeline.Digest,
};

const ParseError = error{
    MissingSubcommand,
    UnknownSubcommand,
    MissingImage,
    MultipleImages,
    MissingOutput,
    DuplicateOutput,
    MissingOptionValue,
    InvalidSha256,
    DuplicateExpectedSha256,
    UnexpectedArgument,
};

pub fn run(allocator: Allocator, io: Io, args: []const []const u8) u8 {
    const parsed = parseArgs(args) catch |err| {
        std.debug.print(
            "vmiz uki: {s}\n{s}\n",
            .{ @errorName(err), usage },
        );
        return 1;
    };

    var image = vmiz.Image.openPathReadOnlyStandalone(
        io,
        parsed.image_path,
    ) catch |err|
        return fail(
            "failed to open '{s}': {s}",
            .{ parsed.image_path, @errorName(err) },
        );
    defer image.close(io);
    var result = vmiz.uki_certificate.extractAlloc(
        allocator,
        io,
        &image,
        .{ .expected_sha256 = parsed.expected_sha256 },
    ) catch |err| return fail(
        "failed to inspect '{s}': {s}",
        .{ parsed.image_path, @errorName(err) },
    );
    defer result.deinit(allocator);

    const pem = vmiz.authenticode.encodePemCertificateAlloc(
        allocator,
        result.certificate_der,
    ) catch |err| return fail(
        "failed to encode signer certificate: {s}",
        .{@errorName(err)},
    );
    defer allocator.free(pem);

    switch (parsed.output) {
        .pem => |path| {
            if (sameResolvedPath(allocator, parsed.image_path, path) catch |err|
                return fail(
                    "failed to validate output path: {s}",
                    .{@errorName(err)},
                ))
            {
                return fail(
                    "output path must differ from the disk image",
                    .{},
                );
            }
            atomic_output.writeAtomicProtected(
                io,
                allocator,
                path,
                pem,
                image.file,
            ) catch |err| return fail(
                "failed to write '{s}': {s}",
                .{ path, @errorName(err) },
            );
            writeHuman(io, path, result) catch |err| return fail(
                "failed to report certificate: {s}",
                .{@errorName(err)},
            );
        },
        .json => {
            const json = jsonAlloc(allocator, result, pem) catch |err|
                return fail(
                    "failed to format JSON: {s}",
                    .{@errorName(err)},
                );
            defer allocator.free(json);
            writeStdout(io, json) catch |err| return fail(
                "failed to write JSON: {s}",
                .{@errorName(err)},
            );
        },
    }
    return 0;
}

fn parseArgs(args: []const []const u8) ParseError!ParsedArgs {
    if (args.len == 0) return error.MissingSubcommand;
    if (!std.mem.eql(u8, args[0], "certificate"))
        return error.UnknownSubcommand;

    var image_path: ?[]const u8 = null;
    var output: ?Output = null;
    var expected_sha256: ?vmiz.artifact_pipeline.Digest = null;
    var expected_sha256_set = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const argument = args[i];
        if (std.mem.eql(u8, argument, "--output=json")) {
            if (output != null) return error.DuplicateOutput;
            output = .json;
        } else if (std.mem.eql(u8, argument, "--output")) {
            if (output != null) return error.DuplicateOutput;
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            output = .{ .pem = args[i] };
        } else if (std.mem.eql(u8, argument, "--expected-sha256")) {
            if (expected_sha256_set)
                return error.DuplicateExpectedSha256;
            expected_sha256_set = true;
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            expected_sha256 = vmiz.artifact_pipeline.parseSha256(
                args[i],
            ) catch return error.InvalidSha256;
        } else if (std.mem.startsWith(u8, argument, "-")) {
            return error.UnexpectedArgument;
        } else if (image_path == null) {
            image_path = argument;
        } else {
            return error.MultipleImages;
        }
    }
    return .{
        .image_path = image_path orelse return error.MissingImage,
        .output = output orelse return error.MissingOutput,
        .expected_sha256 = expected_sha256,
    };
}

fn jsonAlloc(
    allocator: Allocator,
    result: vmiz.uki_certificate.Result,
    pem: []const u8,
) ![]u8 {
    const fingerprint = vmiz.artifact_pipeline.formatSha256(
        result.certificate_sha256,
    );
    const subject = try base64Alloc(allocator, result.subject_der);
    defer allocator.free(subject);
    const issuer = try base64Alloc(allocator, result.issuer_der);
    defer allocator.free(issuer);
    const serial = try hexLowerAlloc(allocator, result.serial_number);
    defer allocator.free(serial);
    return std.json.Stringify.valueAlloc(
        allocator,
        .{
            .schema = @as(u32, 1),
            .certificate_sha256 = &fingerprint,
            .certificate_pem = pem,
            .signer = .{
                .subject_der_base64 = subject,
                .issuer_der_base64 = issuer,
                .serial_number_hex = serial,
            },
            .uki_paths = result.uki_paths,
        },
        .{},
    );
}

fn base64Alloc(allocator: Allocator, bytes: []const u8) ![]u8 {
    const encoded = try allocator.alloc(
        u8,
        std.base64.standard.Encoder.calcSize(bytes.len),
    );
    _ = std.base64.standard.Encoder.encode(encoded, bytes);
    return encoded;
}

fn hexLowerAlloc(allocator: Allocator, bytes: []const u8) ![]u8 {
    const output = try allocator.alloc(u8, bytes.len * 2);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

fn writeStdout(io: Io, bytes: []const u8) !void {
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try writer.writeAll(bytes);
    try writer.writeByte('\n');
    try writer.flush();
}

fn writeHuman(
    io: Io,
    output_path: []const u8,
    result: vmiz.uki_certificate.Result,
) !void {
    const fingerprint = vmiz.artifact_pipeline.formatSha256(
        result.certificate_sha256,
    );
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try writer.print(
        "certificate: {s}\ncertificate sha256: {s}\n",
        .{ output_path, &fingerprint },
    );
    for (result.uki_paths) |path| {
        try writer.print("uki: {s}\n", .{path});
    }
    try writer.flush();
}

fn sameResolvedPath(
    allocator: Allocator,
    left: []const u8,
    right: []const u8,
) !bool {
    const resolved_left = try std.fs.path.resolve(allocator, &.{left});
    defer allocator.free(resolved_left);
    const resolved_right = try std.fs.path.resolve(allocator, &.{right});
    defer allocator.free(resolved_right);
    return std.mem.eql(u8, resolved_left, resolved_right);
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print("vmiz uki certificate: " ++ format ++ "\n", args);
    return 1;
}

test "certificate arguments select PEM or JSON output" {
    const digest_text =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const pem = try parseArgs(&.{
        "certificate",
        "image.qcow2",
        "--output",
        "release.pem",
        "--expected-sha256",
        digest_text,
    });
    try std.testing.expectEqualStrings("image.qcow2", pem.image_path);
    try std.testing.expectEqualStrings("release.pem", pem.output.pem);
    try std.testing.expect(pem.expected_sha256 != null);

    const json = try parseArgs(&.{
        "certificate",
        "--output=json",
        "image.raw",
    });
    try std.testing.expectEqual(Output.json, json.output);
    try std.testing.expectError(
        error.DuplicateOutput,
        parseArgs(&.{
            "certificate",
            "image.raw",
            "--output=json",
            "--output",
            "out.pem",
        }),
    );
    try std.testing.expectError(
        error.MissingOutput,
        parseArgs(&.{ "certificate", "image.raw" }),
    );
}

test "JSON output exposes canonical signer fields" {
    var certificate = [_]u8{ 1, 2, 3 };
    var subject = [_]u8{ 0x30, 0x00 };
    var issuer = [_]u8{ 0x30, 0x01, 0x00 };
    var serial = [_]u8{ 0x00, 0xaf };
    var path = "EFI/BOOT/BOOTX64.EFI".*;
    var paths = [_][]u8{&path};
    const digest = vmiz.artifact_pipeline.sha256Bytes(&certificate);
    const result = vmiz.uki_certificate.Result{
        .certificate_der = &certificate,
        .certificate_sha256 = digest,
        .subject_der = &subject,
        .issuer_der = &issuer,
        .serial_number = &serial,
        .uki_paths = &paths,
    };
    const json = try jsonAlloc(
        std.testing.allocator,
        result,
        "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
    );
    defer std.testing.allocator.free(json);
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        json,
        .{},
    );
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(
        @as(i64, 1),
        root.get("schema").?.integer,
    );
    try std.testing.expectEqualStrings(
        "00af",
        root.get("signer").?.object.get("serial_number_hex").?.string,
    );
    try std.testing.expectEqualStrings(
        "EFI/BOOT/BOOTX64.EFI",
        root.get("uki_paths").?.array.items[0].string,
    );
}
