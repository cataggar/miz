//! Builds the from-scratch OCI image layouts the boot-smoke workflow feeds to
//! `miz build-image` as `--container` / `MIZ_BOOT_TEST_*_OCI` fixtures,
//! replacing `scripts/ci/make-*-oci-fixture.py`.
//!
//! Each subcommand produces a single-layer layout; see `oci_fixture.zig` for
//! the layout itself and `doc/image-building.md` for why each fixture exists.

const std = @import("std");
const oci_fixture = @import("oci_fixture.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

pub const help_text =
    \\usage: make-oci-fixture <command> [options]
    \\
    \\commands:
    \\  minimal <output-dir>
    \\      A tiny layer holding just `hello.txt` -- enough for `miz
    \\      build-image` to merge a valid container over the ISO rootfs.
    \\  uki-stub <output-dir> <path-to-linuxx64.efi.stub>
    \\      Overlays a systemd EFI stub so `--boot-mode uki` can find one.
    \\      The stub comes from the host's systemd-boot-efi package; it is a
    \\      real PE/COFF binary, not something worth synthesizing.
    \\  verity-initramfs <output-dir> <path-to-initramfs> <kernel-version>
    \\      Overlays a verity-capable initramfs at the exact
    \\      `boot/initramfs-<kernel-version>.img` path the ISO uses, so it
    \\      replaces the stock copy with no extra `miz` flag.
    \\
    \\options:
    \\  --architecture <name>   OCI config architecture (default: amd64)
    \\
;

pub const ParseError = error{
    MissingCommand,
    UnknownCommand,
    UnknownOption,
    MissingOptionValue,
    MissingArgument,
    UnexpectedArgument,
};

pub const Command = union(enum) {
    minimal: struct {
        output: []const u8,
    },
    uki_stub: struct {
        output: []const u8,
        stub_path: []const u8,
    },
    verity_initramfs: struct {
        output: []const u8,
        initramfs_path: []const u8,
        kernel_version: []const u8,
    },

    pub fn output(self: Command) []const u8 {
        return switch (self) {
            .minimal => |value| value.output,
            .uki_stub => |value| value.output,
            .verity_initramfs => |value| value.output,
        };
    }
};

pub const Args = struct {
    command: Command,
    architecture: []const u8 = oci_fixture.default_architecture,
};

pub fn parseArgs(argv: []const []const u8) ParseError!Args {
    var architecture: []const u8 = oci_fixture.default_architecture;
    var positional: [4][]const u8 = undefined;
    var positional_count: usize = 0;

    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const argument = argv[index];
        if (std.mem.startsWith(u8, argument, "--")) {
            const body = argument[2..];
            const separator = std.mem.indexOfScalar(u8, body, '=');
            const name = if (separator) |at| body[0..at] else body;
            if (!std.mem.eql(u8, name, "architecture")) return error.UnknownOption;
            if (separator) |at| {
                architecture = body[at + 1 ..];
                if (architecture.len == 0) return error.MissingOptionValue;
            } else {
                index += 1;
                if (index >= argv.len) return error.MissingOptionValue;
                architecture = argv[index];
            }
            continue;
        }
        if (positional_count == positional.len) return error.UnexpectedArgument;
        positional[positional_count] = argument;
        positional_count += 1;
    }

    if (positional_count == 0) return error.MissingCommand;
    const name = positional[0];
    const rest = positional[1..positional_count];
    const command: Command = if (std.mem.eql(u8, name, "minimal")) blk: {
        if (rest.len < 1) return error.MissingArgument;
        if (rest.len > 1) return error.UnexpectedArgument;
        break :blk .{ .minimal = .{ .output = rest[0] } };
    } else if (std.mem.eql(u8, name, "uki-stub")) blk: {
        if (rest.len < 2) return error.MissingArgument;
        if (rest.len > 2) return error.UnexpectedArgument;
        break :blk .{ .uki_stub = .{ .output = rest[0], .stub_path = rest[1] } };
    } else if (std.mem.eql(u8, name, "verity-initramfs")) blk: {
        if (rest.len < 3) return error.MissingArgument;
        if (rest.len > 3) return error.UnexpectedArgument;
        break :blk .{ .verity_initramfs = .{
            .output = rest[0],
            .initramfs_path = rest[1],
            .kernel_version = rest[2],
        } };
    } else return error.UnknownCommand;

    return .{ .command = command, .architecture = architecture };
}

pub const PayloadError = error{EmptyPayload};

/// Reads a fixture input. An empty payload is refused: a zero-byte stub or
/// initramfs would produce a layout that overlays nothing and a boot test
/// that fails much later, for a reason far from its cause.
fn readPayload(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    const bytes = try Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(oci_fixture.max_payload_size),
    );
    errdefer allocator.free(bytes);
    if (bytes.len == 0) return PayloadError.EmptyPayload;
    return bytes;
}

fn writeLine(io: Io, comptime format: []const u8, arguments: anytype) !void {
    var buffer: [4096]u8 = undefined;
    var file_writer: Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try writer.print(format ++ "\n", arguments);
    try writer.flush();
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());
    const args = parseArgs(argv[1..]) catch |err| {
        std.debug.print("error: {s}\n{s}", .{ @errorName(err), help_text });
        std.process.exit(2);
    };
    const options: oci_fixture.Options = .{ .architecture = args.architecture };
    const output = args.command.output();

    switch (args.command) {
        .minimal => {
            _ = try oci_fixture.buildSingleLayerLayout(allocator, io, output, &.{.{
                .path = oci_fixture.minimal_archive_path,
                .content = oci_fixture.minimal_content,
            }}, options);
            try writeLine(io, "built minimal OCI layout at {s}", .{output});
        },
        .uki_stub => |uki| {
            const stub = try readPayload(allocator, io, uki.stub_path);
            defer allocator.free(stub);
            if (!std.mem.startsWith(u8, stub, oci_fixture.pe_magic)) {
                std.debug.print(
                    "warning: {s} doesn't look like a PE/COFF EFI binary (missing 'MZ' header)\n",
                    .{uki.stub_path},
                );
            }
            _ = try oci_fixture.buildSingleLayerLayout(allocator, io, output, &.{.{
                .path = oci_fixture.uki_stub_archive_path,
                .content = stub,
            }}, options);
            try writeLine(
                io,
                "built UKI-stub OCI layout at {s} (stub: {d} bytes from {s})",
                .{ output, stub.len, uki.stub_path },
            );
        },
        .verity_initramfs => |verity| {
            const archive_path = try oci_fixture.verityArchivePath(
                allocator,
                verity.kernel_version,
            );
            defer allocator.free(archive_path);
            const initramfs = try readPayload(allocator, io, verity.initramfs_path);
            defer allocator.free(initramfs);
            _ = try oci_fixture.buildSingleLayerLayout(allocator, io, output, &.{.{
                .path = archive_path,
                .content = initramfs,
            }}, options);
            try writeLine(
                io,
                "built verity-initramfs OCI layout at {s} ({s}: {d} bytes)",
                .{ output, archive_path, initramfs.len },
            );
        },
    }
}

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(oci_fixture);
}

test "each fixture command parses its own arguments" {
    const minimal = try parseArgs(&.{ "minimal", "fixtures/oci-minimal" });
    try std.testing.expectEqualStrings("fixtures/oci-minimal", minimal.command.minimal.output);
    try std.testing.expectEqualStrings("amd64", minimal.architecture);

    const uki = try parseArgs(&.{ "uki-stub", "out", "/usr/lib/systemd/boot/efi/linuxx64.efi.stub" });
    try std.testing.expectEqualStrings("out", uki.command.uki_stub.output);
    try std.testing.expectEqualStrings(
        "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
        uki.command.uki_stub.stub_path,
    );

    const verity = try parseArgs(&.{ "verity-initramfs", "out", "initramfs.img", "6.6.0-1" });
    try std.testing.expectEqualStrings("initramfs.img", verity.command.verity_initramfs.initramfs_path);
    try std.testing.expectEqualStrings("6.6.0-1", verity.command.verity_initramfs.kernel_version);
}

test "architecture is selectable in either spelling" {
    const spaced = try parseArgs(&.{ "--architecture", "arm64", "minimal", "out" });
    try std.testing.expectEqualStrings("arm64", spaced.architecture);
    const joined = try parseArgs(&.{ "minimal", "out", "--architecture=arm64" });
    try std.testing.expectEqualStrings("arm64", joined.architecture);
}

test "malformed invocations are refused instead of guessed at" {
    try std.testing.expectError(error.MissingCommand, parseArgs(&.{}));
    try std.testing.expectError(error.UnknownCommand, parseArgs(&.{ "tiny", "out" }));
    try std.testing.expectError(error.MissingArgument, parseArgs(&.{"minimal"}));
    try std.testing.expectError(error.UnexpectedArgument, parseArgs(&.{ "minimal", "a", "b" }));
    try std.testing.expectError(error.MissingArgument, parseArgs(&.{ "uki-stub", "out" }));
    try std.testing.expectError(
        error.MissingArgument,
        parseArgs(&.{ "verity-initramfs", "out", "initramfs.img" }),
    );
    try std.testing.expectError(error.UnknownOption, parseArgs(&.{ "--arch", "arm64", "minimal", "out" }));
    try std.testing.expectError(error.MissingOptionValue, parseArgs(&.{ "minimal", "out", "--architecture" }));
    try std.testing.expectError(error.MissingOptionValue, parseArgs(&.{ "minimal", "out", "--architecture=" }));
}
