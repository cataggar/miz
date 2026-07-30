//! Architecture-matched EDK2 resolution for the `vm` backend's firmware boot.
//!
//! The search itself is not restated here: it is `qemu_host`, the same module
//! `zvmi qemu` resolves its own firmware through, so a firmware boot of a
//! customization run and a hand-driven `zvmi qemu` run of the same image find
//! the same files in the same order. What this module adds is the part that is
//! specific to a customization: the resolved pair has to be raw (the backend
//! hands paths to an emulator, not a decompressor) and it has to live at a
//! path that is a function of the plan, because the plan hash covers it.

const std = @import("std");
const qemu_host = @import("qemu_host");
const zvmi = @import("zvmi");

pub const ResolveError = Error || std.mem.Allocator.Error;

pub const Error = error{
    /// No architecture-matched firmware was found anywhere the search looks.
    VmFirmwareNotFound,
    /// A Secure Boot firmware was asked for and the only pair found is not one.
    VmFirmwareNotSecureBootCapable,
    /// An explicit pair was named and at least one half is not readable.
    VmFirmwareNotReadable,
    /// One half of an explicit pair was named without the other.
    VmFirmwareOverrideIncomplete,
    /// The pair was found but could not be placed at its deterministic path.
    VmFirmwareNotMaterialized,
};

pub const Resolved = struct {
    code_path: []const u8,
    vars_path: []const u8,
    /// True when the pair came out of the emulator's own `share/` directory or
    /// a system location rather than from explicit plan paths. Only useful for
    /// diagnostics; the plan records the resolved paths either way.
    automatic: bool,
};

pub const Options = struct {
    architecture: zvmi.customize.Architecture,
    /// The `qemu-system-<arch>` binary the plan names. Its directory is the
    /// first place the search looks, which is what makes one `ghr` install of
    /// `cataggar/qemu` cover both guest architectures.
    emulator_command: []const u8,
    secure_boot: bool = false,
    explicit_code_path: ?[]const u8 = null,
    explicit_vars_path: ?[]const u8 = null,
    /// Directory a compressed firmware is decompressed into. Must be stable
    /// across runs of the same plan: the resolved paths are hashed into the
    /// plan, so a per-run temporary directory would give every run a different
    /// plan hash for the same inputs.
    materialize_directory: []const u8,
};

fn guestArchitecture(architecture: zvmi.customize.Architecture) qemu_host.GuestArchitecture {
    return switch (architecture) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
    };
}

/// Resolves the firmware pair, decompressing into `materialize_directory` when
/// the only pair found ships compressed, and returns absolute-or-as-named
/// paths the backend can hand to the emulator.
pub fn resolveAlloc(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
) ResolveError!Resolved {
    const automatic = options.explicit_code_path == null and
        options.explicit_vars_path == null;

    var sources = (qemu_host.findFirmwareSourcePairAlloc(allocator, io, .{
        .architecture = guestArchitecture(options.architecture),
        .secure_boot = options.secure_boot,
        .explicit_code_path = options.explicit_code_path,
        .explicit_vars_path = options.explicit_vars_path,
        .qemu_path = options.emulator_command,
    }) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.IncompleteFirmwareOverride => error.VmFirmwareOverrideIncomplete,
        error.FirmwareNotReadable => error.VmFirmwareNotReadable,
        error.FirmwareNotSecureBootCapable => error.VmFirmwareNotSecureBootCapable,
        else => error.VmFirmwareNotFound,
    }) orelse return error.VmFirmwareNotFound;
    defer sources.deinit(allocator);

    if (sources.code.encoding == .raw and sources.vars.encoding == .raw) {
        const code_path = try allocator.dupe(u8, sources.code.path);
        errdefer allocator.free(code_path);
        return .{
            .code_path = code_path,
            .vars_path = try allocator.dupe(u8, sources.vars.path),
            .automatic = automatic,
        };
    }

    std.Io.Dir.cwd().createDirPath(io, options.materialize_directory) catch
        return error.VmFirmwareNotMaterialized;
    const code_path = try std.fs.path.join(
        allocator,
        &.{ options.materialize_directory, "code.fd" },
    );
    errdefer allocator.free(code_path);
    const vars_path = try std.fs.path.join(
        allocator,
        &.{ options.materialize_directory, "vars.fd" },
    );
    errdefer allocator.free(vars_path);

    var pair = qemu_host.materializeFirmwarePairAlloc(
        allocator,
        io,
        sources,
        code_path,
        vars_path,
        .{},
    ) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.VmFirmwareNotMaterialized,
    };
    pair.deinit(allocator);

    return .{ .code_path = code_path, .vars_path = vars_path, .automatic = automatic };
}

/// One line naming what was looked for and where, for the preflight
/// diagnostic. A refusal that does not say which firmware for which
/// architecture is not actionable.
pub fn describeAlloc(
    allocator: std.mem.Allocator,
    options: Options,
    err: ResolveError,
) std.mem.Allocator.Error![]u8 {
    return switch (err) {
        error.OutOfMemory => std.fmt.allocPrint(
            allocator,
            "the builder ran out of memory resolving {t} EDK2 firmware",
            .{options.architecture},
        ),
        error.VmFirmwareOverrideIncomplete => std.fmt.allocPrint(
            allocator,
            "the firmware boot names one of code_path and vars_path without the other",
            .{},
        ),
        error.VmFirmwareNotReadable => std.fmt.allocPrint(
            allocator,
            "the firmware boot names EDK2 files that are not readable regular files",
            .{},
        ),
        error.VmFirmwareNotSecureBootCapable => std.fmt.allocPrint(
            allocator,
            "no Secure Boot capable {t} EDK2 firmware was found near '{s}'",
            .{ options.architecture, options.emulator_command },
        ),
        error.VmFirmwareNotMaterialized => std.fmt.allocPrint(
            allocator,
            "{t} EDK2 firmware was found but could not be prepared under '{s}'",
            .{ options.architecture, options.materialize_directory },
        ),
        error.VmFirmwareNotFound => std.fmt.allocPrint(
            allocator,
            "no {t} EDK2 firmware was found in the share directory beside '{s}' or in the system locations",
            .{ options.architecture, options.emulator_command },
        ),
    };
}

test "an explicit firmware pair resolves to exactly the named files" {
    const allocator = std.testing.allocator;
    const io = std.testing.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    const code_path = try std.fs.path.join(allocator, &.{ root, "code.fd" });
    defer allocator.free(code_path);
    const vars_path = try std.fs.path.join(allocator, &.{ root, "vars.fd" });
    defer allocator.free(vars_path);
    try tmp.dir.writeFile(.{ .sub_path = "code.fd", .data = "code" });
    try tmp.dir.writeFile(.{ .sub_path = "vars.fd", .data = "vars" });

    const resolved = try resolveAlloc(allocator, io, .{
        .architecture = .x86_64,
        .emulator_command = "/nonexistent/qemu-system-x86_64",
        .explicit_code_path = code_path,
        .explicit_vars_path = vars_path,
        .materialize_directory = root,
    });
    defer allocator.free(resolved.code_path);
    defer allocator.free(resolved.vars_path);

    try std.testing.expectEqualStrings(code_path, resolved.code_path);
    try std.testing.expectEqualStrings(vars_path, resolved.vars_path);
    try std.testing.expect(!resolved.automatic);
}

test "half a firmware override is refused rather than half-resolved" {
    const allocator = std.testing.allocator;
    const io = std.testing.io();
    try std.testing.expectError(error.VmFirmwareOverrideIncomplete, resolveAlloc(
        allocator,
        io,
        .{
            .architecture = .x86_64,
            .emulator_command = "/nonexistent/qemu-system-x86_64",
            .explicit_code_path = "/nonexistent/code.fd",
            .materialize_directory = "/nonexistent",
        },
    ));
}

test "a missing firmware names the architecture and where it looked" {
    const allocator = std.testing.allocator;
    const io = std.testing.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const emulator = try std.fs.path.join(allocator, &.{ root, "bin", "qemu-system-aarch64" });
    defer allocator.free(emulator);

    const options: Options = .{
        .architecture = .aarch64,
        .emulator_command = emulator,
        .materialize_directory = root,
    };
    // The system candidate list is absolute, so a host that happens to have
    // AAVMF installed would resolve here. The description is what this test
    // is about, and it is produced from the options, not from the search.
    const description = try describeAlloc(allocator, options, error.VmFirmwareNotFound);
    defer allocator.free(description);
    try std.testing.expect(std.mem.indexOf(u8, description, "aarch64") != null);
    try std.testing.expect(std.mem.indexOf(u8, description, emulator) != null);
    _ = resolveAlloc(allocator, io, options) catch {};
}

test "a bzip2 firmware pair is decompressed to a path that is a function of the plan" {
    const allocator = std.testing.allocator;
    const io = std.testing.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);

    try tmp.dir.makePath("prefix/bin");
    try tmp.dir.makePath("prefix/share");
    const emulator = try std.fs.path.join(
        allocator,
        &.{ root, "prefix", "bin", "qemu-system-aarch64" },
    );
    defer allocator.free(emulator);
    try tmp.dir.writeFile(.{ .sub_path = "prefix/bin/qemu-system-aarch64", .data = "" });

    // A bzip2 stream of "firmware", written literally so the test needs no
    // fixture blob and no compressor on the host.
    const compressed = "\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\x29\x69\x3c\xeb\x00\x00\x01\x01\x80\x23\x22\x10\x80\x20\x00\x22\x1a\x63\x50\x86\x00\x1c\xe9\x4f\x17\x72\x45\x38\x50\x90\x29\x69\x3c\xeb";
    try tmp.dir.writeFile(.{
        .sub_path = "prefix/share/edk2-aarch64-code.fd.bz2",
        .data = compressed,
    });
    try tmp.dir.writeFile(.{
        .sub_path = "prefix/share/edk2-arm-vars.fd.bz2",
        .data = compressed,
    });

    const materialize = try std.fs.path.join(allocator, &.{ root, "firmware" });
    defer allocator.free(materialize);

    const first = try resolveAlloc(allocator, io, .{
        .architecture = .aarch64,
        .emulator_command = emulator,
        .materialize_directory = materialize,
    });
    defer allocator.free(first.code_path);
    defer allocator.free(first.vars_path);
    try std.testing.expect(first.automatic);
    try std.testing.expect(std.mem.endsWith(u8, first.code_path, "/firmware/code.fd"));

    // Resolution has to be idempotent: a second run of the same plan must land
    // on the same paths or the plan hash would move for unchanged inputs.
    const second = try resolveAlloc(allocator, io, .{
        .architecture = .aarch64,
        .emulator_command = emulator,
        .materialize_directory = materialize,
    });
    defer allocator.free(second.code_path);
    defer allocator.free(second.vars_path);
    try std.testing.expectEqualStrings(first.code_path, second.code_path);
    try std.testing.expectEqualStrings(first.vars_path, second.vars_path);

    const materialized = try std.Io.Dir.cwd().readFileAlloc(
        io,
        first.code_path,
        allocator,
        .limited(4096),
    );
    defer allocator.free(materialized);
    try std.testing.expectEqualStrings("firmware", materialized);
}
